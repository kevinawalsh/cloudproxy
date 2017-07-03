// Copyright (c) 2014, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tao

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A CoreOSLinuxhostConfig contains the details needed to start a new CoreOS VM.
type CoreOSLinuxhostConfig struct {
	Name       string
	ImageFile  string
	Memory     int
	RulesPath  string
	SSHKeysCfg string
	SocketPath string
}

// A KvmCoreOSHostContainer represents a linux host running on a CoreOS image on
// Qemu/KVM. It uses os/exec.Cmd to send commands to QEMU/KVM to start CoreOS
// then uses SSH to connect to CoreOS to start the LinuxHost there with a
// virtio-serial connection for its communication with the Tao running on Linux
// in the guest. This use of os/exec is to avoid having to rewrite or hook into
// libvirt for now. An ssh port is open allowing for further communication into
// the guest, e.g. to start hosted programs under the hosted linux host.
type KvmCoreOSHostContainer struct {

	// TODO(kwalsh) A secured, private copy of the image.
	// Temppath string

	// TODO(kwalsh) A temporary directory for the config drive.
	Tempdir string

	// The factory responsible for the vm.
	Factory *LinuxKVMCoreOSHostFactory

	// Configuration details for CoreOS, mostly obtained from the factory.
	// TODO(kwalsh) what is a good description for this?
	Cfg *CoreOSLinuxhostConfig

	// Hash of coreos image and linux host program
	CoreOSHash, LHHash []byte

	// The underlying vm process.
	QCmd *exec.Cmd

	// Path to linux host.
	// TODO(kwalsh) is this description correct?
	LHPath string

	HostedProgramInfo
}

// Kill sends a SIGKILL signal to a QEMU instance.
func (kcc *KvmCoreOSHostContainer) Kill() error {
	// Kill the qemu command directly.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGKILL is definitely not the right way to do this.
	return kcc.QCmd.Process.Kill()
}

// Start starts a QEMU/KVM CoreOS container using the command line.
func (kcc *KvmCoreOSHostContainer) startVM() error {
	// Create a temporary directory for the config drive.
	td, err := ioutil.TempDir("", "coreos")
	kcc.Tempdir = td
	if err != nil {
		return err
	}

	// Create a temporary directory for the linux_host image. Note that the
	// args were validated in Start before this call.
	kcc.LHPath = kcc.spec.Args[1]

	// Expand the host file into the directory.
	linuxHostFile, err := os.Open(kcc.spec.Path)
	if err != nil {
		return err
	}

	zipReader, err := gzip.NewReader(linuxHostFile)
	if err != nil {
		return err
	}
	defer zipReader.Close()

	unzippedImage, err := ioutil.ReadAll(zipReader)
	if err != nil {
		return err
	}
	unzippedReader := bytes.NewReader(unzippedImage)
	tarReader := tar.NewReader(unzippedReader)
	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		fi := hdr.FileInfo()
		outputName := path.Join(kcc.LHPath, hdr.Name)
		if fi.IsDir() {
			if err := os.Mkdir(outputName, fi.Mode()); err != nil {
				return err
			}
		} else {

			outputFile, err := os.OpenFile(outputName, os.O_CREATE|os.O_TRUNC|os.O_RDWR, fi.Mode())
			if err != nil {
				return err
			}

			if _, err := io.Copy(outputFile, tarReader); err != nil {
				outputFile.Close()
				return err
			}
			outputFile.Close()
		}
	}

	latestDir := path.Join(td, "openstack/latest")
	if err := util.MkdirAll(latestDir, 0700); err != nil {
		return err
	}

	cfg := kcc.Cfg
	userData := path.Join(latestDir, "user_data")
	if err := ioutil.WriteFile(userData, []byte(cfg.SSHKeysCfg), 0700); err != nil {
		return err
	}

	// Copy the rules into the mirrored filesystem for use by the Linux host
	// on CoreOS.
	if cfg.RulesPath != "" {
		rules, err := ioutil.ReadFile(cfg.RulesPath)
		if err != nil {
			return err
		}
		rulesFile := path.Join(kcc.LHPath, path.Base(cfg.RulesPath))
		if err := ioutil.WriteFile(rulesFile, []byte(rules), 0700); err != nil {
			return err
		}
	}

	qemuProg := "qemu-system-x86_64"
	qemuArgs := []string{"-name", cfg.Name,
		"-m", strconv.Itoa(cfg.Memory),
		"-machine", "accel=kvm:tcg",
		// Networking.
		"-net", "nic,vlan=0,model=virtio",
		"-net", "user,vlan=0,hostfwd=tcp::" + kcc.spec.Args[2] + "-:22,hostname=" + cfg.Name,
		// Tao communications through virtio-serial. With this
		// configuration, QEMU waits for a server on cfg.SocketPath,
		// then connects to it.
		"-chardev", "socket,path=" + cfg.SocketPath + ",id=port0-char",
		"-device", "virtio-serial",
		"-device", "virtserialport,id=port1,name=tao,chardev=port0-char",
		// The CoreOS image to boot from.
		"-drive", "if=virtio,file=" + cfg.ImageFile,
		// A Plan9P filesystem for SSH configuration (and our rules).
		"-fsdev", "local,id=conf,security_model=none,readonly,path=" + td,
		"-device", "virtio-9p-pci,fsdev=conf,mount_tag=config-2",
		// Another Plan9P filesystem for the linux_host files.
		"-fsdev", "local,id=tao,security_model=none,path=" + kcc.LHPath,
		"-device", "virtio-9p-pci,fsdev=tao,mount_tag=tao",
		// Machine config.
		"-cpu", "host",
		"-smp", "4",
		"-nographic"} // for now, we add -nographic explicitly.
	// TODO(tmroeder): append args later.
	//qemuArgs = append(qemuArgs, kcc.spec.Args...)

	glog.Info("Launching qemu/coreos")
	kcc.QCmd = exec.Command(qemuProg, qemuArgs...)
	// Don't connect QEMU/KVM to any of the current input/output channels,
	// since we'll connect over SSH.
	//kcc.QCmd.Stdin = os.Stdin
	//kcc.QCmd.Stdout = os.Stdout
	//kcc.QCmd.Stderr = os.Stderr
	// TODO(kwalsh) set up env, dir, and uid/gid.
	return kcc.QCmd.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (kcc *KvmCoreOSHostContainer) Stop() error {
	// Stop the QEMU/KVM process with SIGSTOP.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGSTOP is definitely not the right way to do this.
	return kcc.QCmd.Process.Signal(syscall.SIGSTOP)
}

// Pid returns a numeric ID for this container.
func (kcc *KvmCoreOSHostContainer) Pid() int {
	return kcc.QCmd.Process.Pid
}

// ExitStatus returns an exit code for the container.
func (kcc *KvmCoreOSHostContainer) ExitStatus() (int, error) {
	s := kcc.QCmd.ProcessState
	if s == nil {
		return -1, fmt.Errorf("Child has not exited")
	}
	if code, ok := (*s).Sys().(syscall.WaitStatus); ok {
		return int(code), nil
	}
	return -1, fmt.Errorf("Couldn't get exit status\n")
}

// A LinuxKVMCoreOSHostFactory manages hosted programs started as QEMU/KVM
// instances over a given CoreOS image.
type LinuxKVMCoreOSHostFactory struct {
	Cfg        *CoreOSLinuxhostConfig
	SocketPath string
	PublicKey  string
	PrivateKey ssh.Signer
}

// NewLinuxKVMCoreOSFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
// TODO(kwalsh) fix comment.
func NewLinuxKVMCoreOSHostFactory(sockPath string, cfg *CoreOSLinuxhostConfig) (HostedProgramFactory, error) {

	// Create a key to use to connect to the instance and set up LinuxHost
	// there.
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	sshpk, err := ssh.NewPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pkstr := "ssh-rsa " + base64.StdEncoding.EncodeToString(sshpk.Marshal()) + " linux_host"

	sshpriv, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, err
	}

	return &LinuxKVMCoreOSHostFactory{
		Cfg:        cfg,
		SocketPath: sockPath,
		PublicKey:  pkstr,
		PrivateKey: sshpriv,
	}, nil
}

func (lkcf *LinuxKVMCoreOSHostFactory) Cleanup() error {
	return nil
}

// CloudConfigFromSSHKeys converts an ssh authorized-keys file into a format
// that can be used by CoreOS to authorize incoming SSH connections over the
// Plan9P-mounted filesystem it uses. This also adds the SSH key used by the
// factory to configure the virtual machine.
func CloudConfigFromSSHKeys(keysFile string) (string, error) {
	sshKeys := "#cloud-config\nssh_authorized_keys:"
	sshFile, err := os.Open(keysFile)
	if err != nil {
		return "", err
	}
	scanner := bufio.NewScanner(sshFile)
	for scanner.Scan() {
		sshKeys += "\n - " + scanner.Text()
	}

	return sshKeys, nil
}

// MakeSubprin computes the hash of a QEMU/KVM CoreOS image to get a
// subprincipal for authorization purposes.
func (lkcf *LinuxKVMCoreOSHostFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {
	// (id uint, image string, uid, gid int) (auth.SubPrin, string, error)

	// The args must contain the directory to write the linux_host into, as
	// well as the port to use for SSH.
	if len(spec.Args) != 3 {
		glog.Errorf("Expected %d args, but got %d", 3, len(spec.Args))
		for i, a := range spec.Args {
			glog.Errorf("Arg %d: %s", i, a)
		}
		err = errors.New("KVM/CoreOS guest Tao requires args: <linux_host image> <temp directory for linux_host> <SSH port>")
		return
	}

	// TODO(tmroeder): the combination of TeeReader and ReadAll doesn't seem
	// to copy the entire image, so we're going to hash in place for now.
	// This needs to be fixed to copy the image so we can avoid a TOCTTOU
	// attack.
	// TODO(kwalsh) why is this recomputed for each hosted program?
	// TODO(kwalsh) Move this hash to LinuxKVMCoreOSHostFactory?
	b, err := ioutil.ReadFile(lkcf.Cfg.ImageFile)
	if err != nil {
		return
	}
	h := sha256.Sum256(b)

	bb, err := ioutil.ReadFile(spec.Path)
	if err != nil {
		return
	}
	hh := sha256.Sum256(bb)

	sockName := randName() + ".sock"
	sockPath := path.Join(lkcf.SocketPath, sockName)
	sshCfg := lkcf.Cfg.SSHKeysCfg + "\n - " + string(lkcf.PublicKey)

	cfg := &CoreOSLinuxhostConfig{
		Name:       randName(),
		ImageFile:  lkcf.Cfg.ImageFile, // the VM image
		Memory:     lkcf.Cfg.Memory,
		RulesPath:  lkcf.Cfg.RulesPath,
		SSHKeysCfg: sshCfg,
		SocketPath: sockPath,
	}

	child = &KvmCoreOSHostContainer{
		HostedProgramInfo: HostedProgramInfo{
			spec: spec,
			// TODO(kwalsh) why does Id appear twice in subprin?
			subprin: append(FormatCoreOSLinuxhostSubprin(spec.Id, h[:]), FormatLinuxHostSubprin(spec.Id, hh[:])...),
			Done:    make(chan bool, 1),
		},
		Cfg:        cfg,
		CoreOSHash: h[:],
		LHHash:     hh[:],
		Factory:    lkcf,
	}

	return
}

func (kcc *KvmCoreOSHostContainer) Manifest() Manifest {
	m := kcc.spec.Manifest()
	vm := Manifest{}
	vm["Linux Host Path"] = kcc.LHPath
	vm["Linux Host Hash"] = kcc.LHHash
	vm["CoreOS Image Path"] = kcc.Cfg.ImageFile
	vm["CoreOS Image Hash"] = kcc.CoreOSHash
	vm["Name"] = kcc.Cfg.Name
	vm["Memory"] = kcc.Cfg.Memory
	if kcc.Cfg.RulesPath != "" {
		vm["Rules Path"] = kcc.Cfg.RulesPath
	}
	if kcc.Cfg.SSHKeysCfg != "" {
		vm["SSH Keys Configuration"] = kcc.Cfg.SSHKeysCfg
	}
	m["Kernel Virtual Machine with Tao Linux Host"] = vm
	return m
}

// FormatLinuxHostSubprin produces a string that represents a subprincipal with
// the given ID and hash.
func FormatLinuxHostSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "LinuxHost", Arg: args}}
}

// FormatCoreOSLinuxhostSubprin produces a string that represents a subprincipal with the
// given ID and hash.
func FormatCoreOSLinuxhostSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "CoreOS", Arg: args}}
}

// TODO(kwalsh) move this elsewhere
func randName() string {
	b := make([]byte, 10)
	rand.Read(b) // ignore errors
	return hex.EncodeToString(b)
}

// Start launches a QEMU/KVM CoreOS instance, connects to it with SSH to start
// the LinuxHost on it, and returns the socket connection to that host.
func (kcc *KvmCoreOSHostContainer) Start() (err error) {
	// Create the listening server before starting the connection. This lets
	// QEMU start right away. See the comments in Start, above, for why this
	// is.
	kcc.TaoChannel = util.NewUnixSingleReadWriteCloser(kcc.Cfg.SocketPath)
	defer func() {
		if err != nil {
			kcc.TaoChannel.Close()
			kcc.TaoChannel = nil
		}
	}()
	if err = kcc.startVM(); err != nil {
		return
	}
	// TODO(kwalsh) reap and clenaup when vm dies; see linux_process_factory.go
	// Reap the child when the process dies.
	// sc := make(chan os.Signal, 1)
	// signal.Notify(sc, syscall.SIGCHLD)
	go func() {
		// <-sc
		kcc.QCmd.Wait()
		kcc.Cleanup()
		// signal.Stop(sc)
		kcc.Done <- true
		close(kcc.Done) // prevent any more blocking
	}()

	// We need some way to wait for the socket to open before we can connect
	// to it and return the ReadWriteCloser for communication. Also we need
	// to connect by SSH to the instance once it comes up properly. For now,
	// we just wait for a timeout before trying to connect and listen.
	tc := time.After(10 * time.Second)

	// Set up an ssh client config to use to connect to CoreOS.
	conf := &ssh.ClientConfig{
		// The CoreOS user for the SSH keys is currently always 'core'
		// on the virtual machine.
		User:            "core",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(kcc.Factory.PrivateKey)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // FIXME: put coreos host key here
	}

	glog.Info("Waiting about 10 seconds for qemu/coreos to start")
	<-tc

	hostPort := net.JoinHostPort("localhost", kcc.spec.Args[2])
	glog.Info("Connecting to " + hostPort)
	client, err := ssh.Dial("tcp", hostPort, conf)
	if err != nil {
		err = fmt.Errorf("couldn't dial '%s': %s", hostPort, err)
		return
	}

	cmds := []string{
		"sudo mkdir /media/tao",
		"sudo mount -t 9p -o trans=virtio,version=9p2000.L tao /media/tao",
		"sudo chmod -R 755 /media/tao",
		"sudo rm -rf /etc/tao",
		"sudo cp -r /media/tao /etc/tao",
		"& sudo /etc/tao/linux_host start -foreground -alsologtostderr -verbose -v 4 -stacked -parent_type file -parent_spec 'tao::RPC+tao::FileMessageChannel(/dev/virtio-ports/tao)' -tao_domain /etc/tao",
	}

	glog.Info("Initializing tao host on the guest")
	for i, cmd := range cmds {
		// glog.Infof("Running init command %d of %d: %s\n", i+1, len(cmds), cmd)
		init, err := client.NewSession()
		if err != nil {
			return fmt.Errorf("couldn't establish init session %d of %d over SSH: %s", i+1, len(cmds), err)
		}
		init.Stdin = kcc.spec.Stdin
		init.Stdout = kcc.spec.Stdout
		init.Stderr = kcc.spec.Stderr
		if cmd[0] == '&' {
			glog.Infof("Starting init command %d of %d: %s\n", i+1, len(cmds), cmd)
			if err = init.Start(cmd[2:]); err != nil {
				init.Close()
				return fmt.Errorf("error starting init command %d of %d (%s): %s", i+1, len(cmds), cmd[2:], err)
			}
		} else {
			glog.Infof("Running init command %d of %d: %s\n", i+1, len(cmds), cmd)
			if err = init.Run(cmd); err != nil {
				init.Close()
				return fmt.Errorf("error running init command %d of %d (%s): %s", i+1, len(cmds), cmd, err)
			}
		}
		go func() {
			time.Sleep(20 * time.Second)
			init.Close()
		}()
	}

	glog.Info("Hosted qemu/coreos/linux_host is ready")
	return
}

func (kcc *KvmCoreOSHostContainer) Cleanup() error {
	// TODO(kwalsh) need to kill vm if still running?
	if kcc.TaoChannel != nil {
		kcc.TaoChannel.Close()
	}
	os.RemoveAll(kcc.Tempdir)
	os.RemoveAll(kcc.LHPath)
	return nil
}
