// Copyright (c) 2014, Google, Inc.  All rights reserved.
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
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	// "os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A DockerContainer represents a hosted program running as a Docker container.
// It uses os/exec.Cmd and the `docker` program to send commands to the Docker
// daemon rather than using the docker client API directly. This is so that this
// code doesn't depend on the docker code for now.
type DockerContainer struct {

	// The factory responsible for the hosted process.
	Factory *LinuxDockerContainerFactory

	Hash        []byte
	ImageName   string
	SocketPath  string
	CidfilePath string
	RulesPath   string

	// The underlying docker process.
	Cmd *exec.Cmd

	HostedProgramInfo
}

// Kill sends a SIGKILL signal to a docker container.
func (dc *DockerContainer) Kill() error {
	dc.TaoChannel.Close()
	cid, err := dc.ContainerName()
	if err != nil {
		return err
	}
	return docker(nil, "kill", cid)
}

func (dc *DockerContainer) ContainerName() (string, error) {
	b, err := ioutil.ReadFile(dc.CidfilePath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func docker(stdin io.Reader, cmd string, args ...string) error {
	c := exec.Command("docker", append([]string{cmd}, args...)...)
	var b bytes.Buffer
	c.Stdin = stdin
	c.Stdout = &b
	c.Stderr = &b
	err := c.Run()
	if err != nil {
		glog.Errorf("Docker error %v: cmd=%v args=%v\n"+
			"begin docker output\n"+
			"%v\n"+
			"end docker output\n", err, cmd, args, b.String())
	}
	return err
}

// Stop sends a SIGSTOP signal to a docker container.
func (dc *DockerContainer) Stop() error {
	cid, err := dc.ContainerName()
	if err != nil {
		return err
	}
	return docker(nil, "kill", "-s", "STOP", cid)
}

// Pid returns a numeric ID for this docker container.
func (dc *DockerContainer) Pid() int {
	return dc.Cmd.Process.Pid
}

// ExitStatus returns an exit code for the container.
func (dc *DockerContainer) ExitStatus() (int, error) {
	s := dc.Cmd.ProcessState
	if s == nil {
		return -1, fmt.Errorf("Child has not exited")
	}
	if code, ok := (*s).Sys().(syscall.WaitStatus); ok {
		return int(code), nil
	}
	return -1, fmt.Errorf("Couldn't get exit status\n")
}

// A LinuxDockerContainerFactory manages hosted programs started as docker
// containers over a given docker image.
type LinuxDockerContainerFactory struct {
	SocketDir string
	RulesPath string
}

// NewLinuxDockerContainerFactory returns a new HostedProgramFactory that can
// create docker containers to wrap programs.
func NewLinuxDockerContainerFactory(sockDir, rulesPath string) HostedProgramFactory {
	return &LinuxDockerContainerFactory{
		SocketDir: sockDir,
		RulesPath: rulesPath,
	}
}

func (ldcf *LinuxDockerContainerFactory) Cleanup() error {
	return nil
}

// NewHostedProgram initializes, but does not start, a hosted docker container.
func (ldcf *LinuxDockerContainerFactory) NewHostedProgram(spec HostedProgramSpec) (child HostedProgram, err error) {

	// The imagename for the child is given by spec.ContainerArgs[0]
	argv0 := "cloudproxy"
	if len(spec.ContainerArgs) >= 1 {
		argv0 = spec.ContainerArgs[0]
	}
	img := argv0 + ":" + randName()

	inf, err := os.Open(spec.Path)
	defer inf.Close()
	if err != nil {
		return
	}

	// Build the docker image, and hash the image as it is sent.
	hasher := sha256.New()
	err = docker(io.TeeReader(inf, hasher), "build", "-t", img, "-q", "-")
	if err != nil {
		return
	}

	hash := hasher.Sum(nil)

	// TODO(kwalsh) We should probably hash the configuration used to run the
	// docker container, including custom arguments for the docker container.

	child = &DockerContainer{
		HostedProgramInfo: HostedProgramInfo{
			spec:    spec,
			subprin: FormatDockerSubprin(spec.Id, hash),
			Done:    make(chan bool, 1),
		},
		Hash:      hash,
		ImageName: img,
		Factory:   ldcf,
	}

	return
}

func (dc *DockerContainer) Manifest() Manifest {
	m := dc.spec.Manifest()
	m["Program Hash"] = dc.Hash
	m["Docker Image Name"] = dc.ImageName
	m["Docker Rules Path"] = dc.Factory.RulesPath
	return m
}

// FormatDockerSubprin produces a string that represents a subprincipal with the
// given ID and hash.
func FormatDockerSubprin(id uint, hash []byte) auth.SubPrin {
	var args []auth.Term
	if id != 0 {
		args = append(args, auth.Int(id))
	}
	args = append(args, auth.Bytes(hash))
	return auth.SubPrin{auth.PrinExt{Name: "Container", Arg: args}}
}

// Start builds the docker container from the tar file and launches it.
func (dc *DockerContainer) Start() (err error) {

	s := path.Join(dc.Factory.SocketDir, randName())
	dc.SocketPath = s + ".sock"
	dc.CidfilePath = s + ".cid"

	dc.RulesPath = dc.Factory.RulesPath

	dc.TaoChannel = util.NewUnixSingleReadWriteCloser(dc.SocketPath)
	defer func() {
		if err != nil {
			dc.TaoChannel.Close()
			dc.TaoChannel = nil
		}
	}()

	args := []string{"run", "--rm=true", "-v", dc.SocketPath + ":/tao"}
	args = append(args, "--cidfile", dc.CidfilePath)
	args = append(args, "--env", HostChannelTypeEnvVar+"="+"unix")
	args = append(args, "--env", HostSpecEnvVar+"="+"/tao")
	if dc.RulesPath != "" {
		args = append(args, "-v", dc.RulesPath+":/"+path.Base(dc.RulesPath))
	}
	// ContainerArgs has a name plus args passed directly to docker, i.e. before
	// image name. Args are passed to the ENTRYPOINT within the Docker image,
	// i.e. after image name.
	// Note: Uid, Gid, Dir, and Env do not apply to docker hosted programs.
	if len(dc.spec.ContainerArgs) > 1 {
		args = append(args, dc.spec.ContainerArgs[1:]...)
	}
	args = append(args, dc.ImageName)
	args = append(args, dc.spec.Args...)
	dc.Cmd = exec.Command("docker", args...)
	dc.Cmd.Stdin = dc.spec.Stdin
	dc.Cmd.Stdout = dc.spec.Stdout
	dc.Cmd.Stderr = dc.spec.Stderr

	err = dc.Cmd.Start()
	if err != nil {
		return
	}
	// Reap the child when the process dies.
	go func() {
		// sc := make(chan os.Signal, 1)
		// signal.Notify(sc, syscall.SIGCHLD)
		// <-sc
		dc.Cmd.Wait()
		// signal.Stop(sc)

		time.Sleep(1 * time.Second)
		docker(nil, "rmi", dc.ImageName)
		dc.Done <- true
		os.Remove(dc.CidfilePath)
		close(dc.Done) // prevent any more blocking
	}()

	return
}

func (dc *DockerContainer) Cleanup() error {
	// TODO(kwalsh) need to kill docker container if still running?
	if dc.TaoChannel != nil {
		dc.TaoChannel.Close()
	}
	dc.spec.Cleanup()
	return nil
}
