// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

// Package host exposes the functionality of a linux_host implementation as a
// library.
package host

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"syscall"
	"text/tabwriter"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
)

var emptylist []string

var opts = []options.Option{
	// Flags for all/most commands
	{"tao_domain", "", "<dir>", "Tao domain configuration directory", "all"},
	{"host", "", "<dir>", "Host configuration, relative to domain directory or absolute", "all"},

	// Flags for init (and start) command
	{"root", false, "", "Create a root host, not backed by any parent Tao", "init,start"},
	{"stacked", false, "", "Create a stacked host, backed by a parent Tao", "init,start"},
	{"hosting", emptylist, "<type>[,<type>...]", "Hosted program type: process, docker, kvm_coreos, or kvm_coreos_linuxhost", "init"},
	{"socket_dir", "", "<dir>", "Hosted program socket directory, relative to host directory or absolute", "init"},

	// Flags for start command
	{"foreground", false, "", "Run in the foreground", "start"},
	// Using setsid (1) and shell redirection is an alternative -daemon:
	//    sh$ setsid tao host start ... </dev/null >/dev/null 2>&1
	//    sh$ setsid linux_host start ... </dev/null >/dev/null 2>&1
	{"daemon", false, "", "Detach from tty, close stdio, and run as a daemon", "start"},
	{"delegation", "", "<file>", "Delegation for keys from an attestation authority", "start"},

	// Flags for root
	{"pass", "", "<password>", "Host password for root hosts (for testing only!)", "root"},

	// Flags for stacked
	{"parent_type", "", "<type>", "Type of channel to parent Tao: TPM, pipe, file, or unix", "stacked"},
	{"parent_spec", "", "<spec>", "Spec for channel to parent Tao", "stacked"},
	{"signing_key", true, "", "Use a signing key for attestations to avoid calling parent", "stacked"},
	{"crypting_key", true, "", "Use a crypting key for sealing to avoid calling parent", "stacked"},
	{"deriving_key", true, "", "Use a deriving key to avoid calling parent", "stacked"},

	// Flags for QEMU/KVM CoreOS init
	{"kvm_coreos_img", "", "<path>", "Path to CoreOS.img file, relative to domain or absolute", "kvm"},
	{"kvm_coreos_vm_memory", 0, "SIZE", "The amount of RAM (in KB) to give VM", "kvm"},
	{"kvm_coreos_ssh_auth_keys", "", "<path>", "An authorized_keys file for SSH to CoreOS guest, relative to domain or absolute", "kvm"},
}

func init() {
	options.Add(opts...)
}

func help() {
	w := new(tabwriter.Writer)
	w.Init(os.Stderr, 4, 0, 2, ' ', 0)
	av0 := path.Base(os.Args[0])

	fmt.Fprintf(w, "Linux Tao Host\n")
	fmt.Fprintf(w, "Usage:\n")
	fmt.Fprintf(w, "  %s init [options]\t Initialize a new host\n", av0)
	fmt.Fprintf(w, "  %s show [options]\t Show host principal name\n", av0)
	fmt.Fprintf(w, "  %s start [options]\t Start the host\n", av0)
	fmt.Fprintf(w, "  %s stop [options]\t Request the host stop\n", av0)
	fmt.Fprintf(w, "\n")

	categories := []options.Category{
		{"all", "Basic options for most commands"},
		{"init", "Options for 'init' command"},
		{"start", "Options for 'start' command"},
		{"root", "Options for root hosts"},
		{"stacked", "Options for stacked hosts"},
		{"kvm", "Options for hosting QEMU/KVM CoreOS"},
		{"logging", "Options to control log output"},
	}
	options.ShowRelevant(w, categories...)

	w.Flush()
}

func Main() {
	flag.Usage = help
	verbose.Set(true)
	glog.Errorf("still here\n")
	glog.Flush()

	glog.Errorf("checkpoint init %d\n", 1)
	glog.Flush()

	// Get options before the command verb
	flag.Parse()
	glog.Errorf("checkpoint after flag parse%d\n", 2)
	glog.Flush()
	// Get command verb
	cmd := "help"
	if flag.NArg() > 0 {
		cmd = flag.Arg(0)
	}
	glog.Errorf("checkpoint after narg%d\n", 3)
	glog.Flush()
	// Get options after the command verb
	if flag.NArg() > 1 {
		flag.CommandLine.Parse(flag.Args()[1:])
	}
	glog.Errorf("checkpoint after narg again %d\n", 4)
	glog.Flush()

	// Load the domain.
	glog.Errorf("checkpoint loading domain%d\n", 5)
	glog.Flush()
	cpath := path.Join(apps.TaoDomainPath(), "tao.config")
	glog.Errorf("checkpoint after join %d\n", 6)
	glog.Flush()
	domain, err := tao.LoadDomain(cpath, nil)
	glog.Errorf("checkpoint loaded domain%d\n", 7)
	glog.Flush()
	options.FailIf(err, "Can't load domain")
	glog.Errorf("checkpoint err %d\n", 8)
	glog.Flush()

	// Set $TAO_DOMAIN so it will be inherited by hosted programs
	glog.Errorf("checkpoint setting domain %d\n", 9)
	glog.Flush()
	os.Unsetenv("TAO_DOMAIN")
	glog.Errorf("checkpoint unsetted %d\n", 10)
	glog.Flush()
	err = os.Setenv("TAO_DOMAIN", apps.TaoDomainPath())
	glog.Errorf("checkpoint setenv %d\n", 11)
	glog.Flush()
	options.FailIf(err, "Can't set $TAO_DOMAIN")
	glog.Errorf("checkpoint err check %d\n", 12)
	glog.Flush()

	switch cmd {
	case "help":
		help()
	case "init":
		initHost(domain)
	case "show":
		showHost(domain)
	case "start":
		glog.Errorf("checkpoint about to start %d\n", 13)
		glog.Flush()
		startHost(domain)
		glog.Errorf("checkpoint after start %d\n", 14)
		glog.Flush()
	case "stop", "shutdown":
		stopHost(domain)
	default:
		options.Usage("Unrecognized command: %s", cmd)
	}
}

func hostPath() string {
	hostPath := *options.String["host"]
	if hostPath == "" {
		// options.Usage("Must supply a -host path")
		hostPath = "linux_tao_host"
	}
	if !path.IsAbs(hostPath) {
		hostPath = path.Join(apps.TaoDomainPath(), hostPath)
	}
	return hostPath
}

func hostConfigPath() string {
	return path.Join(hostPath(), "host.config")
}

// Update configuration based on command-line options. Does very little sanity checking.
func configureFromOptions(cfg *tao.LinuxHostConfig) {
	if *options.Bool["root"] && *options.Bool["stacked"] {
		options.Usage("Can supply only one of -root and -stacked")
	} else if *options.Bool["root"] {
		cfg.Type = proto.String("root")
	} else if *options.Bool["stacked"] {
		cfg.Type = proto.String("stacked")
	}
	cfg.Hosting = append(cfg.Hosting, options.Strings["hosting"]...)
	if s := *options.String["parent_type"]; s != "" {
		cfg.ParentType = proto.String(s)
	}
	if s := *options.String["parent_spec"]; s != "" {
		cfg.ParentSpec = proto.String(s)
	}
	if s := *options.String["socket_dir"]; s != "" {
		cfg.SocketDir = proto.String(s)
	}
	if s := *options.String["kvm_coreos_img"]; s != "" {
		cfg.KvmCoreosImg = proto.String(s)
	}
	if i := *options.Int["kvm_coreos_vm_memory"]; i != 0 {
		cfg.KvmCoreosVmMemory = proto.Int32(int32(i))
	}
	if s := *options.String["kvm_coreos_ssh_auth_keys"]; s != "" {
		cfg.KvmCoreosSshAuthKeys = proto.String(s)
	}
	var keys []string
	if *options.Bool["signing_key"] {
		keys = append(keys, "signing")
	}
	if *options.Bool["crypting_key"] {
		keys = append(keys, "signing")
	}
	if *options.Bool["signing_key"] {
		keys = append(keys, "signing")
	}
	cfg.Keys = keys
}

func configureFromFile() *tao.LinuxHostConfig {
	d, err := ioutil.ReadFile(hostConfigPath())
	if err != nil {
		options.Fail(err, "Can't read linux host configuration")
	}
	var cfg tao.LinuxHostConfig
	if err := proto.UnmarshalText(string(d), &cfg); err != nil {
		options.Fail(err, "Can't parse linux host configuration")
	}
	return &cfg
}

func loadHost(domain *tao.Domain, cfg *tao.LinuxHostConfig) (*tao.LinuxHost, error) {
	var tc tao.Config

	// Sanity check host type
	var stacked bool
	switch cfg.GetType() {
	case "root":
		stacked = false
	case "stacked":
		stacked = true
	case "":
		options.Usage("Must supply -root or -stacked flag")
	default:
		options.Usage("Invalid host type: %s", cfg.GetType())
	}

	// Sanity check hosting type
	hosting := make(map[string]bool)
	for _, h := range cfg.GetHosting() {
		switch h {
		case "process", "docker", "kvm_coreos", "kvm_coreos_linuxhost":
			hosting[h] = true
		default:
			options.Usage("Invalid hosting type: %s", cfg.GetHosting())
		}
	}
	if len(hosting) == 0 {
		options.Usage("Must supply -hosting flag")
	}

	// For stacked hosts, figure out the channel type: TPM, pipe, file, or unix
	if stacked {
		switch cfg.GetParentType() {
		case "TPM":
			tc.HostChannelType = "tpm"
		case "pipe":
			tc.HostChannelType = "pipe"
		case "file":
			tc.HostChannelType = "file"
		case "unix":
			tc.HostChannelType = "unix"
		case "":
			// leave channel type blank, tao may find it in env vars
			tc.HostChannelType = ""
		default:
			options.Usage("Invalid parent type: %s", cfg.GetParentType())
		}

		// For stacked hosts, we may also have a parent spec from command line
		tc.HostSpec = cfg.GetParentSpec()

		// For stacked hosts on a TPM, we may also have tpm info from domain config
		if domain.Config.TpmInfo != nil {
			tc.TPMAIKPath = path.Join(apps.TaoDomainPath(), domain.Config.TpmInfo.GetAikPath())
			tc.TPMPCRs = domain.Config.TpmInfo.GetPcrs()
			tc.TPMDevice = domain.Config.TpmInfo.GetTpmPath()
		}
	}

	rulesPath := ""
	if p := domain.RulesPath(); p != "" {
		rulesPath = path.Join(apps.TaoDomainPath(), p)
	}

	// Create the hosted program factory
	socketPath := hostPath()
	if subPath := cfg.GetSocketDir(); subPath != "" {
		if path.IsAbs(subPath) {
			socketPath = subPath
		} else {
			socketPath = path.Join(socketPath, subPath)
		}
	}

	// TODO(cjpatton) How do the NewLinuxDockerContainterFactory and the
	// NewLinuxKVMCoreOSHostFactory need to be modified to support the new
	// CachedGuard? They probably don't.
	childFactory := make(map[string]tao.HostedProgramFactory)
	if hosting["process"] {
		childFactory["process"] = tao.NewLinuxProcessFactory("pipe", socketPath)
	}
	if hosting["docker"] {
		childFactory["docker"] = tao.NewLinuxDockerContainerFactory(socketPath, rulesPath)
	}
	if hosting["kvm_coreos"] {
		// TODO(kwalsh) re-enable this code path in new kvm factory
		// sshFile := cfg.GetKvmCoreosSshAuthKeys()
		// if sshFile != "" {
		// if !path.IsAbs(sshFile) {
		// 	sshFile = path.Join(apps.TaoDomainPath(), sshFile)
		// }
		// sshKeysCfg, err := io.ReadFile(sshFile)
		// options.FailIf(err, "Can't read ssh authorized keys")
		// ... }

		coreOSImage := cfg.GetKvmCoreosImg()
		if coreOSImage == "" {
			options.Usage("Must specify -kvm_coreos_image for hosting QEMU/KVM CoreOS")
		}
		if !path.IsAbs(coreOSImage) {
			coreOSImage = path.Join(apps.TaoDomainPath(), coreOSImage)
		}

		// TODO(kwalsh) re-enable this code path in new kvm factory
		// vmMemory := cfg.GetKvmCoreosVmMemory()
		// if vmMemory == 0 {
		// 	vmMemory = 1024
		// }

		var err error
		childFactory["kvm_coreos"], err = tao.NewKVMCoreOSFactory(coreOSImage, false)
		options.FailIf(err, "Can't create KVM CoreOS factory")
	}
	if hosting["kvm_coreos_linuxhost"] {
		sshFile := cfg.GetKvmCoreosSshAuthKeys()
		if sshFile == "" {
			options.Usage("Must specify -kvm_coreos_ssh_auth_keys for hosting QEMU/KVM CoreOS")
		}
		if !path.IsAbs(sshFile) {
			sshFile = path.Join(apps.TaoDomainPath(), sshFile)
		}
		sshKeysCfg, err := tao.CloudConfigFromSSHKeys(sshFile)
		options.FailIf(err, "Can't read ssh keys")

		coreOSImage := cfg.GetKvmCoreosImg()
		if coreOSImage == "" {
			options.Usage("Must specify -kvm_coreos_image for hosting QEMU/KVM CoreOS")
		}
		if !path.IsAbs(coreOSImage) {
			coreOSImage = path.Join(apps.TaoDomainPath(), coreOSImage)
		}

		vmMemory := cfg.GetKvmCoreosVmMemory()
		if vmMemory == 0 {
			vmMemory = 1024
		}

		kvmCfg := &tao.CoreOSLinuxhostConfig{
			ImageFile:  coreOSImage,
			Memory:     int(vmMemory),
			RulesPath:  rulesPath,
			SSHKeysCfg: sshKeysCfg,
		}

		childFactory["kvm_coreos_linuxhost"], err = tao.NewLinuxKVMCoreOSHostFactory(socketPath, kvmCfg)
		options.FailIf(err, "Can't create KVM CoreOS LinuxHost factory")
	}

	if !stacked {
		pwd := options.Password("root host key password", "pass")
		return tao.NewRootLinuxHost(hostPath(), domain.Guard, pwd, childFactory)
	} else {
		parent := tao.ParentFromConfig(tc)
		if parent == nil {
			options.Usage("No host tao available, verify -parent_type (or $%s) and associated variables\n", tao.HostChannelTypeEnvVar)
		}
		keyTypes := keyTypesFromConfig(cfg)
		return tao.NewStackedLinuxHost(hostPath(), keyTypes, domain.Guard, parent, childFactory)
	}
}

func keyTypesFromConfig(cfg *tao.LinuxHostConfig) (keyTypes tao.KeyType) {
	for _, s := range cfg.Keys {
		switch s {
		case "signing":
			keyTypes |= tao.Signing
		case "crypting":
			keyTypes |= tao.Crypting
		case "deriving":
			keyTypes |= tao.Deriving
		}
	}
	return
}

func initHost(domain *tao.Domain) {
	var cfg tao.LinuxHostConfig

	configureFromOptions(&cfg)
	_, err := loadHost(domain, &cfg)
	options.FailIf(err, "Can't create host")

	// If we get here, keys were created and flags must be ok.

	file, err := util.CreatePath(hostConfigPath(), 0777, 0666)
	options.FailIf(err, "Can't create host configuration")
	cs := proto.MarshalTextString(&cfg)
	fmt.Fprint(file, cs)
	file.Close()
}

func showHost(domain *tao.Domain) {
	cfg := configureFromFile()
	configureFromOptions(cfg)
	host, err := loadHost(domain, cfg)
	options.FailIf(err, "Can't create host")
	fmt.Printf("%v\n", host.HostName())
}

func isBoolFlagSet(name string) bool {
	f := flag.Lookup(name)
	if f == nil {
		return false
	}
	v, ok := f.Value.(flag.Getter).Get().(bool)
	return ok && v
}

func daemonize() {
	// For our purposes, "daemon" means being a session leader.
	sid, _, errno := syscall.Syscall(syscall.SYS_GETSID, 0, 0, 0)
	var err error
	if errno != 0 {
		err = errno
	}
	options.FailIf(err, "Can't get process SID")
	if int(sid) != syscall.Getpid() {
		// Go does not support daemonize(), and we can't simply call setsid
		// because PID may be equal to GID. Using exec.Cmd with the Setsid=true
		// will fork, ensuring that PID differs from GID, then call setsid, then
		// exec ourself again in the new session.
		path, err := os.Readlink("/proc/self/exe")
		options.FailIf(err, "Can't get path to self executable")
		// special case: keep stderr if -logtostderr or -alsologtostderr
		stderr := os.Stderr
		if !isBoolFlagSet("logtostderr") && !isBoolFlagSet("alsologtostderr") {
			stderr = nil
		}
		spa := &syscall.SysProcAttr{
			Setsid: true, // Create session.
		}
		daemon := exec.Cmd{
			Path:        path,
			Args:        os.Args,
			Stderr:      stderr,
			SysProcAttr: spa,
		}
		err = daemon.Start()
		options.FailIf(err, "Can't become daemon")
		glog.Errorf("Linux Tao Host running as daemon\n")
		glog.Flush()
		os.Exit(0)
	} else {
		glog.Errorf("Already a session leader?\n")
		glog.Flush()
	}
}

func startHost(domain *tao.Domain) {

	glog.Errorf("checkpoint in start *** %d\n", 15)
	glog.Flush()
	if *options.Bool["daemon"] && *options.Bool["foreground"] {
		options.Usage("Can supply only one of -daemon and -foreground")
		glog.Errorf("checkpoint in daemon check %d\n", 16)
		glog.Flush()
	}
	glog.Errorf("checkpoint before bool %d\n", 17)
	glog.Flush()
	if *options.Bool["daemon"] {
		glog.Errorf("checkpoint in daemon %d\n", 18)
		glog.Flush()
		glog.Errorf("** Going to daemon\n")
		glog.Flush()
		glog.Errorf("checkpoint going %d\n", 19)
		glog.Flush()
		fmt.Printf("Going to daemon\n")
		glog.Errorf("checkpoint again %d\n", 20)
		glog.Flush()
		daemonize()
		glog.Errorf("checkpoint dmz %d\n", 21)
		glog.Flush()
	}
	glog.Errorf("checkpoint after dmz%d\n", 22)
	glog.Flush()

	cfg := configureFromFile()
	glog.Errorf("checkpoint configed %d\n", 23)
	glog.Flush()
	configureFromOptions(cfg)
	glog.Errorf("checkpoint optioned %d\n", 24)
	glog.Flush()
	host, err := loadHost(domain, cfg)
	glog.Errorf("checkpoint loaded %d\n", 25)
	glog.Flush()
	options.FailIf(err, "Can't create host")
	glog.Errorf("checkpoint not failed %d\n", 26)
	glog.Flush()

	if *options.String["delegation"] != "" {
		// dPath := path.Join(hostPath(), *options.String["delegation"])
		glog.Errorf("checkpoint in delegation %d\n", 27)
		glog.Flush()
		dPath := *options.String["delegation"]
		glog.Errorf("checkpoint after path %d\n", 28)
		glog.Flush()
		buf, err := ioutil.ReadFile(dPath)
		glog.Errorf("checkpoint after readfile %d\n", 29)
		glog.Flush()
		options.FailIf(err, "Can't read delegation: %s", dPath)
		glog.Errorf("checkpoint after err read %d\n", 30)
		glog.Flush()
		var delegation tao.Attestation
		glog.Errorf("checkpoint after att %d\n", 31)
		glog.Flush()
		err = proto.Unmarshal(buf, &delegation)
		glog.Errorf("checkpoint unmar %d\n", 32)
		glog.Flush()
		options.FailIf(err, "Can't unmarshal delegation: %s", dPath)
		glog.Errorf("checkpoint cant unmar %d\n", 33)
		glog.Flush()
		host.Host.SetDelegation(&delegation)
		glog.Errorf("checkpoint set del %d\n", 34)
		glog.Flush()
	}
	glog.Errorf("checkpoint after delegation %d\n", 35)
	glog.Flush()

	glog.Errorf("checkpoint before admin socket %d\n", 36)
	glog.Flush()
	sockPath := path.Join(hostPath(), "admin_socket")
	glog.Errorf("** Creating admin socket: %s\n", sockPath)
	glog.Flush()
	fmt.Printf("Creating admin socket: %s\n", sockPath)
	// Set the socketPath directory go+rx so tao_launch can access sockPath and
	// connect to this linux host, even when tao_launch is run as non-root.
	err = os.Chmod(path.Dir(sockPath), 0755)
	options.FailIf(err, "Can't change permissions")
	uaddr, err := net.ResolveUnixAddr("unix", sockPath)
	options.FailIf(err, "Can't resolve unix socket")
	sock, err := net.ListenUnix("unix", uaddr)
	if err != nil {
		fmt.Printf("Problem listening at %v\n", sockPath)
		// can we make a file instead?
		err2 := ioutil.WriteFile(sockPath, []byte("hello world"), 0755)
		err3 := ioutil.WriteFile(sockPath+"2", []byte("hello again"), 0755)
		if err2 != nil {
			fmt.Printf("Can't make a file either\n")
		} else {
			fmt.Printf("But we can make a file there\n")
			// os.Remove(sockPath)
		}
		if err3 != nil {
			fmt.Printf("Can't make another file\n")
		} else {
			fmt.Printf("We can make another file there\n")
			// os.Remove(sockPath)
		}
	}
	options.FailIf(err, "Can't create admin socket")
	defer sock.Close()
	err = os.Chmod(sockPath, 0666)
	if err != nil {
		sock.Close()
		options.Fail(err, "Can't change permissions on admin socket")
	}

	go func() {
		verbose.Printf("Linux Tao Service started and waiting for requests\n  HostName: %s\n  SignName: %s\n", host.HostName(), host.SignName())
		glog.Errorf("Linux Tao Service started and waiting for requests\n  HostName: %s\n  SignName: %s\n", host.HostName(), host.SignName())
		glog.Flush()
		err = tao.NewLinuxHostAdminServer(host).Serve(sock)
		verbose.Printf("Linux Tao Service finished\n")
		glog.Errorf("Linux Tao Service finished\n")
		glog.Flush()
		sock.Close()
		options.FailIf(err, "Error serving admin requests")
		os.Exit(0)
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill, syscall.SIGTERM)
	<-c
	verbose.Printf("Linux Tao Service shutting down\n")
	glog.Errorf("Linux Tao Service shutting down\n")
	glog.Flush()
	err = shutdown()
	if err != nil {
		sock.Close()
		options.Fail(err, "Can't shut down admin socket")
	}

	// The above goroutine will normally end by calling os.Exit(), so we
	// can block here indefinitely. But if we get a second kill signal,
	// let's abort.
	verbose.Printf("Waiting for shutdown....\n")
	glog.Errorf("Waiting for shutdown....\n")
	glog.Flush()
	<-c
	options.Fail(nil, "Could not shut down linux_host")
}

func stopHost(domain *tao.Domain) {
	err := shutdown()
	if err != nil {
		options.Usage("Couldn't connect to linux_host: %s", err)
	}
}

func shutdown() error {
	sockPath := path.Join(hostPath(), "admin_socket")
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sockPath, Net: "unix"})
	if err != nil {
		return err
	}
	defer conn.Close()
	return tao.NewLinuxHostAdminClient(conn).Shutdown()
}
