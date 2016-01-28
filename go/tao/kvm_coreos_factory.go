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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A KvmCoreOSContainer represents a hosted program running on a CoreOS image on
// Qemu/KVM. It uses cloud-config to set up the environment and launch the
// command. A virtio-serial connection into the guest is also created to provide
// Tao services to the hosted program, and the necessary environment variables
// are set as part of the cloud-config.
//
// The user can (optionally) specify any command to run, e.g. a nested
// linux_host, demo_server, or even just bash. The command is run using systemd,
// and an attempt is made to connect stdio to the command using char devices,
// 'bash -c' and redirection. If the SSHCommand option is is set, then a
// temporary ssh key is created and ssh is used to start the command rather than
// systemd. In either case, when the command dies, the guest will be shut down.
// If no command is given, a temporary ssh key is not created, stdio is ignored,
// and the guest will run indefinitely.
//
// The user can (optionally) specify ssh coreos/systemd mount points and units,
// authorization keys for coreos, a port to be forewarded to coreos sshd, and
// other parameters for configuring qemu, kvm, and coreos.
//
// For now, this factory implementation uses os/exec and the qemu command-line
// interface to avoid having to hook into libvirt.
type KvmCoreOSContainer struct {

	// VMName provides a name for the Qemu virtual machine.
	VMName string

	// Hostname provides a name for the CoreOS guest.
	Hostname string

	// Memory is the amount of memory to use for Qemu/KVM guest.
	Memory int

	// SSHAuthorizedKeys is a list of ssh keys authorized to ssh into the guest.
	SSHAuthorizedKeys []string

	// SSHForwardingPort is a port to forward to ssh in the guest. This is only
	// useful if SSHAuthorizedKeys is not empty.
	SSHForwardingPort int

	// Setting SSHCommand causes the command to be run using an ssh session into
	// the guest. Otherwise, systemd units are used instead.
	SSHCommand bool

	// MountFrom lists directories to mount within the guest, e.g. "~/my/data".
	MountFrom []string

	// MountTo lists locations within the guest for mounts, e.g. "/media/data".
	MountTo []string

	// SocketPath is the host path to socket for providing tao api to guest.
	SocketPath string

	// StdioPath is the host path to socket for providing stdio to guest.
	StdioPath string

	// A socket for providing stdio to guest.
	StdioChannel io.ReadWriteCloser

	// A private copy-on-write qemu image backed by the factory's CoreOSImage.
	PrivateImage string

	// A temporary directory for CoreOS config-2 drive.
	CoreOSConfigPath string

	// The factory responsible for the vm.
	Factory *KVMCoreOSFactory

	// The underlying qemu process.
	QCmd *exec.Cmd

	// LogPath is the host path to log qemu output.
	LogPath string

	// The underlying ssh process, if SSHCommand is set.
	SCmd *ssh.Session

	HostedProgramInfo
}

// Kill sends a SIGKILL signal to a QEMU instance.
func (kcc *KvmCoreOSContainer) Kill() error {
	// Kill the qemu command directly.
	// TODO(tmroeder): rewrite this using qemu's communication/management
	// system; sending SIGKILL is definitely not the right way to do this.
	if kcc.QCmd == nil || kcc.QCmd.Process == nil {
		return nil
	}
	return kcc.QCmd.Process.Kill()
}

func isAlnum(r byte) bool {
	return '0' <= r && r <= '9' || 'a' <= r && r <= 'z' || 'A' <= r && r <= 'Z'
}

func systemdEscape(s string) string {
	// [from http://www.freedesktop.org/software/systemd/man/systemd.unit.html]
	// ... given a path, "/" is replaced by "-" and all other characters which
	// are not ASCII alphanumerics are replaced by C-style "\x2d" escapes
	// (except that "_" is never replaced and "." is only replaced when it would
	// be the first character in the escaped path). The root directory "/" is
	// encoded as single dash, while otherwise the initial and ending "/" are
	// removed from all paths during transformation.
	s = strings.TrimPrefix(s, "/")
	if s == "" {
		return "-"
	}
	b := make([]byte, len(s), 0)
	for i, r := range []byte(s) {
		if isAlnum(r) {
			b = append(b, byte(r))
		} else if r == '_' {
			b = append(b, '_')
		} else if r == '.' && i != 0 {
			b = append(b, '.')
		} else {
			b = append(b, []byte(fmt.Sprintf("\\x02x", r))...)
		}
	}
	return string(b)
}

func systemdQuote(s string) string {
	// TODO(kwalsh) Verify proper quoting for systemd command arguments
	return fmt.Sprintf("%q", s)
}

func sshQuote(s string) string {
	// TODO(kwalsh) Verify proper quoting for ssh command arguments
	return fmt.Sprintf("%q", s)
}

// Start starts a QEMU/KVM CoreOS container using the command line.
func (kcc *KvmCoreOSContainer) startVM() error {
	// CoreOS gets cloud-config data from openstack/latest/user_data on the
	// config-2 drive. Create a temporary directory for this file. The file
	// format is:
	//
	// #cloud-config
	// ssh_authorized_keys:
	// - ssh-rsa AAAAB3N...
	// - ssh-dss AAAAB3N...
	// hostname: mycontainer
	// coreos:
	//   units:
	//     - name: media-tao.mount
	//       command: start
	//       content: |
	//         [Mount]
	//         What=shared
	//         Where=/media/shared
	//         Type=9p
	//         Options=trans=virtio,version=9p2000.L
	//     - name: docker-redis.service
	//       command: start
	//       content: |
	//         [Service]
	//         ExecStart=bash -c 'echo "$0" "$1" <stdin >stdout 2>stderr' "hello "world"
	//         ExecStopPost=/usr/bin/shutdown -P now
	//
	// Note: The unusual "$0" "$1" ... notation is an attempt to avoid quoting
	// issues for Args.
	// TODO(kwalsh) ExecStopPost does not have the desired effect. Why not? For
	// now, put the shutdown into ExecStart.

	s := "#cloud-config\n"
	s += "hostname: " + kcc.Hostname + "\n"

	s += "ssh_authorized_keys:\n"
	s += "- " + kcc.Factory.PublicKey + "\n"
	for _, k := range kcc.SSHAuthorizedKeys {
		s += "- " + k + "\n"
	}

	s += "coreos:\n"
	s += "  units:\n"

	for i, from := range kcc.MountFrom {
		to := kcc.MountTo[i]
		// TODO(kwalsh) Security check: make sure from is owned by UID.
		s += fmt.Sprintf(""+
			"    - name: %s.mount\n"+
			"      command: start\n"+
			"      content: |\n"+
			"        [Mount]\n"+
			"        What=%s\n"+
			"        Where=%s\n"+
			"        Options=trans=virtio,version=9p2000.L\n",
			systemdEscape(to),
			systemdEscape(from), to)
	}

	s += fmt.Sprintf("" +
		"    - name: tao-perms.service\n" +
		"      command: start\n" +
		"      content: |\n" +
		"        [Service]\n" +
		"        Type=oneshot\n" +
		"        ExecStart=/bin/chmod a+rw /dev/virtio-ports/tao\n" +
		"        ExecStart=/bin/chmod a+rw /dev/virtio-ports/stdio\n")

	if !kcc.SSHCommand {
		// Use bash -c '...' so that we can redirect stdio to our socket
		// TODO(kwalsh) perhaps we can use systemd's "TTYPath=" option instead?
		cmd := kcc.spec.Path
		args := ""
		for i, arg := range kcc.spec.Args {
			cmd += fmt.Sprintf(" \"$%d\"", i)
			args += " " + systemdQuote(arg)
		}
		cmd += " <>/dev/virtio-ports/stdio 1>&0 2>&0"
		ctype := "file"
		cspec := "tao::RPC+tao::FileMessageChannel(/dev/virtio-ports/tao)"
		s += fmt.Sprintf(""+
			"    - name: tao-launch.service\n"+
			"      command: start\n"+
			"      content: |\n"+
			"        [Service]\n"+
			"        Type=oneshot\n"+
			"        Requires=tao-perms.service\n"+
			"        After=tao-perms.service\n"+
			"        Environment='%s=%s' '%s=%s'\n"+
			"        User=core\n"+
			"        ExecStart=/bin/bash -c '%s'%s\n"+
			"        ExecStopPost=/bin/bash -c '/bin/sudo /sbin/shutdown -P now'\n",
			HostChannelTypeEnvVar, ctype,
			HostSpecEnvVar, cspec,
			cmd, args)
		// TODO(kwalsh) shutting down the system in this way is apparently very
		// slow, with a 90 second delay. Not sure why... the last line of the
		// log before the 90 second pause is:
		// [   93.152540] random: nonblocking pool is initialized
	}

	cloudConfig := path.Join(kcc.CoreOSConfigPath, "openstack/latest/user_data")
	if err := util.WritePath(cloudConfig, []byte(s), 0400, 0644); err != nil {
		return err
	}

	userNet := "user,vlan=0"
	if kcc.Hostname != "" {
		userNet += ",hostname=" + kcc.Hostname
	}
	// TODO(kwalsh) remove hack
	if kcc.SSHCommand || true {
		userNet += fmt.Sprintf(",hostfwd=tcp::%d-:22", kcc.SSHForwardingPort)
	}

	// Most all of these options can be overridden by options in ContainerArgs.
	qemuProg := "qemu-system-x86_64"
	qemuArgs := []string{"-name", kcc.VMName,
		// Machine config.
		"-m", strconv.Itoa(kcc.Memory),
		"-machine", "accel=kvm:tcg",
		"-cpu", "host",
		"-smp", "4",
		"-nographic",
		// Networking.
		"-net", "nic,vlan=0,model=virtio",
		"-net", userNet,
		// Tao communications through virtio-serial. With this
		// configuration, QEMU waits for a server on kcc.SocketPath,
		// then connects to it.
		"-device", "virtio-serial",
		"-chardev", "socket,path=" + kcc.SocketPath + ",id=port0-char",
		"-device", "virtserialport,id=port1,name=tao,chardev=port0-char",
		// The CoreOS image to boot from.
		"-drive", "if=virtio,file=" + kcc.PrivateImage,
		// A Plan9P filesystem for cloud-config.
		"-fsdev", "local,id=conf,security_model=none,readonly,path=" + kcc.CoreOSConfigPath,
		"-device", "virtio-9p-pci,fsdev=conf,mount_tag=config-2",
	}
	if !kcc.SSHCommand {
		qemuArgs = append(qemuArgs,
			"-chardev", "socket,path="+kcc.StdioPath+",id=port1-char",
			"-device", "virtserialport,id=port2,name=stdio,chardev=port1-char")
	}
	// TODO(kwalsh) check above virtserialport usage. Do we need two of them to
	// handle stdout,stderr properly?

	for _, from := range kcc.MountFrom {
		tag := systemdEscape(from)
		// Another Plan9P filesystem for the user mount
		// TODO(kwalsh) should this really be security_model=none ?
		qemuArgs = append(qemuArgs,
			"-fsdev", "local,id=tao,security_model=none,path="+from,
			"-device", "virtio-9p-pci,fsdev="+tag+",mount_tag="+tag)
	}
	// TODO(kwalsh) sanity check user-supplied args, many can violate security
	qemuArgs = append(qemuArgs, kcc.spec.ContainerArgs...)

	// Log qemu output to file
	qout, err := os.Create(kcc.LogPath)
	if err != nil {
		return err
	}

	glog.Infof("Launching qemu/coreos prog=%s args=%q", qemuProg, qemuArgs)
	kcc.QCmd = exec.Command(qemuProg, qemuArgs...)
	kcc.QCmd.Stdout = qout
	kcc.QCmd.Stderr = qout

	return kcc.QCmd.Start()
}

// Stop sends a SIGSTOP signal to a docker container.
func (kcc *KvmCoreOSContainer) Stop() error {
	if kcc.SCmd != nil {
		return kcc.SCmd.Signal(ssh.SIGINT)
	} else {
		// Stop the QEMU/KVM process with SIGSTOP.
		// TODO(tmroeder): rewrite this using qemu's communication/management
		// system; sending SIGSTOP is definitely not the right way to do this.
		return kcc.QCmd.Process.Signal(syscall.SIGSTOP)
	}
}

// Pid returns a numeric ID for this container.
func (kcc *KvmCoreOSContainer) Pid() int {
	return kcc.QCmd.Process.Pid
}

// ExitStatus returns an exit code for the container.
func (kcc *KvmCoreOSContainer) ExitStatus() (int, error) {
	s := kcc.QCmd.ProcessState
	if s == nil {
		return -1, fmt.Errorf("QEMU/CoreOS has not exited")
	}
	if code, ok := (*s).Sys().(syscall.WaitStatus); ok {
		return int(code), nil
	}
	return -1, fmt.Errorf("Couldn't get QEMU/CoreOS exit status\n")
}

// A KVMCoreOSFactory manages hosted programs started as QEMU/KVM
// instances over a given CoreOS image.
type KVMCoreOSFactory struct {
	// CoreOSImage is the absolute host path to CoreOS image. It is specified as
	// part of the factory, rather than per-child, simply because it is very
	// large and we want to copy and hash it only once.
	CoreOSImage string

	// TempDir is a temporary directory for the factory.
	TempDir string

	// CoreOSHash is the hash of the TempCoreOSImage file.
	CoreOSHash []byte

	// PublicKey and PrivateKey are temporary keys used to ssh into guests.
	// These are only used if SSHCommand is set for a guest.
	PublicKey  string
	PrivateKey ssh.Signer
}

// NewKVMCoreOSFactory returns a new HostedProgramFactory that can create
// qemu-kvm/coreos virtual machines to run hosted programs.
func NewKVMCoreOSFactory(coreOSImage string, hashKvm bool) (factory HostedProgramFactory, err error) {

	// TODO(kwalsh) consoladate factory temp files into a single temp dir
	tempdir, err := ioutil.TempDir("", "cloudproxy_linux_host")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			os.RemoveAll(tempdir)
		}
	}()
	if err = os.Chmod(tempdir, 0755); err != nil {
		return
	}

	var hash []byte
	if hashKvm {
		// Copy and hash the coreos image. This is expensive. Also, it doesn't
		// account for kvm images that have a backing image, so it isn't really
		// complete anyway. Hence, the coping and hashing is optional.
		temppath := path.Join(tempdir, "coreos.img")
		var tf *os.File
		tf, err = os.OpenFile(temppath, os.O_CREATE|os.O_RDWR, 0700)
		defer tf.Close()
		if err != nil {
			return
		}
		if err = tf.Chmod(0755); err != nil {
			return
		}

		var inf *os.File
		inf, err = os.Open(coreOSImage)
		defer inf.Close()
		if err != nil {
			return
		}

		// Read from the input file and write to the temp file.
		hasher := sha256.New()
		if _, err = io.Copy(hasher, io.TeeReader(inf, tf)); err != nil {
			return
		}
		hash = hasher.Sum(nil)
		coreOSImage = temppath
	} else {
		hash = []byte{0}
	}

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

	return &KVMCoreOSFactory{
		CoreOSImage: coreOSImage,
		TempDir:     tempdir,
		CoreOSHash:  hash[:],
		PublicKey:   pkstr,
		PrivateKey:  sshpriv,
	}, nil
}

func (lkcf *KVMCoreOSFactory) Cleanup() error {
	return os.RemoveAll(lkcf.TempDir)
}

// MakeSubprin computes the hash of a QEMU/KVM CoreOS image to get a
// subprincipal for authorization purposes.
func (lkcf *KVMCoreOSFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {
	// TODO(kwalsh) We should really hash a bunch of other stuff here, including
	// mount points, ssh auth keys, other configuration parameters for qemu, and
	// perhaps the entire coreos cloud-config file. We probably also need to
	// hash the contents of directories in MountFrom[], since that is where the
	// program we are running is likely going to be stored.

	child = &KvmCoreOSContainer{
		HostedProgramInfo: HostedProgramInfo{
			spec:    spec,
			subprin: append(FormatCoreOSSubprin(spec.Id, lkcf.CoreOSHash), FormatCoreOSCommandSubprin(spec.Path)...),
			Done:    make(chan bool, 1),
		},
		Factory: lkcf,
	}
	return
}

// FormatCoreOSCommandSubprin produces a string that represents a subprincipal
// with the given ID and hash.
func FormatCoreOSCommandSubprin(cmd string) auth.SubPrin {
	args := []auth.Term{auth.Str(cmd)}
	return auth.SubPrin{auth.PrinExt{Name: "Command", Arg: args}}
}

// FormatCoreOSSubprin produces a string that represents a subprincipal with the
// given ID and hash.
func FormatCoreOSSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "CoreOS", Arg: args}}
}

// Start launches a QEMU/KVM CoreOS instance, connects to it with SSH to start
// the LinuxHost on it, and returns the socket connection to that host.
func (kcc *KvmCoreOSContainer) Start() (err error) {

	// TODO(kwalsh) make ContainerArgs in HostedProgram spec be a map to
	// facilitate things like hostname, memory, ssh rules, etc.

	// Use random name to avoid conflicts with other virtual machines.
	kcc.VMName = randName()
	kcc.Memory = 1024
	kcc.SSHAuthorizedKeys = []string{
		"ssh-dss AAAAB3NzaC1kc3MAAACBAI3+32jaz6TR+CGCxsz/ggd6+W9zfCFmWHrWy7BfvtI8sW70752eJVlH806tkv8pvI8q+xbGjDpDkzYUBLS8ilfgPoGqzxg7DYB/1TQzUWPoncKqlUiX96xgvqwiL1MsT/rVn9MMRj7iixRrU+DJgOMw/RBoJ6xApNBybLy4SzQ9AAAAFQChgDI8sBoxAwCr4tBDGyrZSlO3VwAAAIEAjDo8AYlMoByOvjQzZZnElw7juxe14qT4eac++x+jEEnpjtefFRqZuN4FJq2oplcXpi1Z8D2CSsq0fFUGH9ej6Mv9gOE2uQUyg4DsfBvyOdNP8IKo0CuUDnRd4tWjGT8UvmDrAN+XcXnm/61+2gMkwmisyfYyGoSi85gXcU7BWGIAAACAP+wM/IpBfI8egYIXT596I1eJLLaLcWODYhym0GRoNnovLZUH6XS9dIU29RnD69NPjROkBOvux9X7PIxseFfA4TDKaKZbu6U3hdC0XJt2QK6ItnUdfN4l+PvHX/KcINTpA4wtsdPxOlDhpttErO+WnypkYM46Illml3DvOcXeQoI= kwalsh@oakham",
		"ssh-dss AAAAB3NzaC1kc3MAAACBAPlRunaTbzhvZ/zF/PFpdDSbSZgl/bJi35hSS8v/EVx/nXQJhfSEOMt0NDKajDdpryCywU7RnWiMGBaaGo36inIQPnxxrCLfO0fot9Cj9HMoSQTCvJ4P2GW7VR0VkoGNv2notOwJSabTOh7K8cUxxVZwd52bYeSH75y8w7/w6gcnAAAAFQDXJ4RQf9pC00ARgbE0y8L2p8ow9wAAAIBKXrzjr4QIeITPpZYu/x/3s4ecjQ02Wa6LoYOi+BMb/6HHJEGqyZ6pCP2UBXNPxZn+bf5WTUBiL+b5t22NwWoKFPVJE+glKhMjkfXqyYpnwugRJGnu1PEgjSZjL+6wRGBbBdkMWnrJfN11Zefiuzt+ebRSano6zQeqvzQo5ocBxAAAAIBiuEpiCp71X6uo78sTawOWyWJHHDBrBQN06cO7jDsVSYBgv5fxqNCAVctLmzYKye6Ptu5zgNiDUMt7ZjfVZaf8kFfWIxntVXZEaWibRFm1nOuSiSaobrMOd5usGRmmNNVMk6+CeBwRurob81xhpo6OwTa4kntEiyk7XdCqo75YPQ== family@oakham",
	}
	kcc.SSHForwardingPort = 2222 // TODO(kwalsh) remove hack
	kcc.SSHCommand = false
	kcc.MountFrom = nil
	kcc.MountTo = nil

	t := randName()
	kcc.SocketPath = path.Join(kcc.Factory.TempDir, t+".sock")
	kcc.LogPath = path.Join(kcc.Factory.TempDir, t+".log")
	kcc.CoreOSConfigPath = path.Join(kcc.Factory.TempDir, t+".config")
	kcc.PrivateImage = path.Join(kcc.Factory.TempDir, t+".img")

	// Copy the image
	cp := exec.Command("qemu-img", "create", "-f", "qcow2", "-o", "backing_file="+kcc.Factory.CoreOSImage, kcc.PrivateImage)
	if err := cp.Run(); err != nil {
		glog.Errorf("qemu-img error creating copy-on-write image: %s\n", err)
		return err
	}

	// Create the listening server before starting the connection. This lets
	// QEMU start right away. See the comments in Start, above, for why this
	// is.
	kcc.TaoChannel = util.NewUnixSingleReadWriteCloser(kcc.SocketPath)
	defer func() {
		if err != nil {
			kcc.TaoChannel.Close()
			kcc.TaoChannel = nil
		}
	}()
	kcc.StdioPath = path.Join(kcc.Factory.TempDir, t+".stdio")
	if !kcc.SSHCommand {
		kcc.StdioChannel = util.NewUnixSingleReadWriteCloser(kcc.StdioPath)
		defer func() {
			if err != nil {
				kcc.StdioChannel.Close()
				kcc.StdioChannel = nil
			}
		}()
	}
	if err = kcc.startVM(); err != nil {
		glog.Infof("Failed to start qemu: %s", err)
		return
	}
	// Reap the child when the process dies.
	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGCHLD)
	go func() {
		<-sc
		kcc.QCmd.Wait()
		kcc.Cleanup()
		signal.Stop(sc)
		kcc.Done <- true
		close(kcc.Done) // prevent any more blocking
	}()

	if !kcc.SSHCommand {
		// Proxy stdio
		go io.Copy(kcc.spec.Stdout, kcc.StdioChannel)
		go io.Copy(kcc.StdioChannel, kcc.spec.Stdin)
	} else {
		// We need some way to wait for the socket to open before we can connect
		// to it and return the ReadWriteCloser for communication. Also we need
		// to connect by SSH to the instance once it comes up properly. For now,
		// we just wait for a timeout before trying to connect and listen.
		glog.Info("Waiting about 10 seconds for qemu/coreos to start")
		<-time.After(10 * time.Second)

		dest := net.JoinHostPort("localhost", strconv.Itoa(kcc.SSHForwardingPort))
		glog.Info("Connecting to " + dest)
		conf := &ssh.ClientConfig{
			User: "core",
			Auth: []ssh.AuthMethod{ssh.PublicKeys(kcc.Factory.PrivateKey)},
		}
		var client *ssh.Client
		client, err = ssh.Dial("tcp", dest, conf)
		if err != nil {
			err = fmt.Errorf("couldn't dial '%s': %s", dest, err)
			return
		}

		glog.Info("Executing user command on the guest")
		kcc.SCmd, err = client.NewSession()
		if err != nil {
			err = fmt.Errorf("couldn't establish a start session on SSH: %s", err)
			return
		}
		kcc.SCmd.Stdin = kcc.spec.Stdin
		kcc.SCmd.Stdout = kcc.spec.Stdout
		kcc.SCmd.Stderr = kcc.spec.Stderr
		ctype := "file"
		cspec := "tao::RPC+tao::FileMessageChannel(/dev/virtio-ports/tao)"
		env := fmt.Sprintf("%s=%s %s=%s",
			HostChannelTypeEnvVar, ctype,
			HostSpecEnvVar, cspec)
		cmd := kcc.spec.Path
		args := ""
		for _, arg := range kcc.spec.Args {
			args += " " + sshQuote(arg)
		}
		shutdown := "/sbin/shutdown -h now"
		if err = kcc.SCmd.Start(env + " " + cmd + args + " ; " + shutdown); err != nil {
			err = fmt.Errorf("couldn't start user command on the guest: %s", err)
			return
		}
		// Reap the child when the ssh session dies.
		sc := make(chan os.Signal, 1)
		go func() {
			kcc.SCmd.Wait()
			// Give the guest a moment to shutdown cleanly.
			<-time.After(3 * time.Second)
			kcc.Cleanup()
			signal.Stop(sc)
			kcc.Done <- true
			close(kcc.Done) // prevent any more blocking
		}()
	}

	return
}

func (kcc *KvmCoreOSContainer) Cleanup() error {
	kcc.Kill()
	if kcc.TaoChannel != nil {
		kcc.TaoChannel.Close()
	}
	if kcc.StdioChannel != nil {
		kcc.StdioChannel.Close()
	}
	os.RemoveAll(kcc.CoreOSConfigPath)
	// Don't do os.RemoveAll(kcc.LogPath), as the log file helps with debugging
	os.RemoveAll(kcc.SocketPath)
	os.RemoveAll(kcc.PrivateImage)
	os.RemoveAll(kcc.StdioPath)
	return nil
}
