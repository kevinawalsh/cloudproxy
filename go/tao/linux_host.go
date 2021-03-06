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
	"path"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A LinuxHost is a Tao host environment in which hosted programs are Linux
// processes. A Unix domain socket accepts administrative commands for
// controlling the host, e.g., for starting hosted processes, stopping hosted
// processes, or shutting down the host. A LinuxTao can be run in stacked mode
// (on top of a host Tao) or in root mode (without an underlying host Tao).
type LinuxHost struct {
	Host           Host
	path           string
	guard          Guard
	childFactory   map[string]HostedProgramFactory
	hostedPrograms []HostedProgram
	hpm            sync.RWMutex
	nextChildID    uint
	idm            sync.Mutex
}

// NewStackedLinuxHost creates a new LinuxHost as a hosted program of an existing
// host Tao.
func NewStackedLinuxHost(path string, keyTypes KeyType, guard Guard, hostTao Tao, childFactory map[string]HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		path:         path,
		guard:        guard,
		childFactory: childFactory,
	}

	if err := hostTao.ExtendTaoName(guard.Subprincipal()); err != nil {
		return nil, err
	}

	var k *Keys
	var err error
	if keyTypes != 0 {
		k, err = NewOnDiskTaoSealedKeys(keyTypes, nil, hostTao, path, SealPolicyDefault)
		if err != nil {
			return nil, err
		}
	}

	lh.Host, err = NewTaoStackedHostFromKeys(k, hostTao)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

// NewRootLinuxHost creates a new LinuxHost as a standalone Host that can
// provide the Tao to hosted Linux processes.
func NewRootLinuxHost(path string, guard Guard, password []byte, childFactory map[string]HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		guard:        guard,
		childFactory: childFactory,
	}
	k, err := NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path, nil)
	if err != nil {
		return nil, err
	}

	rootHost, err := NewTaoRootHostFromKeys(k)
	if err != nil {
		return nil, err
	}
	rootHost.taoHostName = rootHost.taoHostName.MakeSubprincipal(guard.Subprincipal())

	lh.Host = rootHost

	return lh, nil
}

// GetTaoName returns the Tao name for the child.
func (lh *LinuxHost) GetTaoName(child HostedProgram) auth.Prin {
	return lh.Host.HostName().MakeSubprincipal(child.Subprin())
}

// ExtendTaoName irreversibly extends the Tao principal name of the child.
func (lh *LinuxHost) ExtendTaoName(child HostedProgram, ext auth.SubPrin) error {
	child.Extend(ext)
	return nil
}

// GetRandomBytes returns a slice of n random bytes for the child.
func (lh *LinuxHost) GetRandomBytes(child HostedProgram, n int) ([]byte, error) {
	return lh.Host.GetRandomBytes(child.Subprin(), n)
}

// GetSharedSecret returns a slice of n secret bytes for the child.
func (lh *LinuxHost) GetSharedSecret(child HostedProgram, requester *auth.Prin, n int, policy string, level int) ([]byte, error) {
	// Compute a tag based on the policy identifier and the child's subprin.
	if level < 0 {
		return nil, newError("invalid level %d for shared secret", level)
	}
	childName := lh.GetTaoName(child)
	if requester == nil {
		requester = &childName
	} else if !auth.SubprinOrIdentical(requester, childName) {
		return nil, newError("requester is not identical to or subprincipal of hosted child")
	}
	var tag string
	switch policy {
	case SharedSecretPolicyDefault, SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		// TODO(kwalsh) conservative policy could include PID or other
		// child info.
		if level != 0 {
			return nil, newError("default and conservative policy are only sensible with level 0 shared secrets")
		}
		tag = policy + "|" + requester.SubprinSuffix(len(requester.Ext)-len(lh.Host.HostName().Ext)).String()
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance.
		tag = policy
	default:
		var guard Guard
		var err error
		if strings.HasPrefix(policy, PolicyTagACL) {
			// Unserialize the acl guard and use that policy
			ser := []byte(policy[len(PolicyTagACL):])
			guard, err = NewMarshalledACLGuard(ser)
			if err != nil {
				return nil, newError("failed to unmarshal ACL policy in GetSharedSecret")
			}
		} else if strings.HasPrefix(policy, PolicyTagDatalog) {
			ser := []byte(policy[len(PolicyTagDatalog):])
			guard, err = NewMarshalledDatalogGuard(ser)
			if err != nil {
				return nil, newError("failed to unmarshal Datalog policy in GetSharedSecret")
			}
		} else {
			return nil, newError("policy not supported for GetSharedSecret: " + policy)
		}
		// TODO(kwalsh) support named secrets
		if !guard.IsAuthorized(*requester, "GetSharedSecret", nil) {
			glog.Errorf("Requester not authorized under given policy...\n Requester: %v\n Policy: %v\n",
				requester, guard)
			return nil, newError("denied")
		}
		tag = policy
	}
	return lh.Host.GetSharedSecret(requester, policy, tag, n, level)
}

// SetFederatedSharedSecret returns a slice of n secret bytes for the child.
func (lh *LinuxHost) SetFederatedSharedSecret(bytes []byte, level int) error {
	return lh.Host.SetFederatedSharedSecret(bytes, level)
}

// Seal encrypts data for the child. This call also zeroes the data parameter.
func (lh *LinuxHost) Seal(child HostedProgram, data []byte, policy string) ([]byte, error) {
	defer ZeroBytes(data)
	lhsb := &LinuxHostSealedBundle{
		Policy: proto.String(policy),
		Data:   data,
	}

	switch policy {
	case SealPolicyDefault, SealPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		lhsb.PolicyInfo = proto.String(child.Subprin().String())
	case SealPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance. So, we don't set
		// any policy info.
	default:
		// Try to parse this statement as a tao/auth policy. If it
		// parses, then use it as the policy statement.
		return nil, newError("policy not supported for Seal: " + policy)
	}

	m, err := proto.Marshal(lhsb)
	if err != nil {
		return nil, err
	}
	defer ZeroBytes(m)

	return lh.Host.Encrypt(m)
}

// Unseal decrypts data for the child, but only if the policy is satisfied.
func (lh *LinuxHost) Unseal(child HostedProgram, sealed []byte) ([]byte, string, error) {
	decrypted, err := lh.Host.Decrypt(sealed)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(decrypted)

	var lhsb LinuxHostSealedBundle
	if err := proto.Unmarshal(decrypted, &lhsb); err != nil {
		return nil, "", err
	}

	if lhsb.Policy == nil {
		return nil, "", newError("invalid policy in sealed data")
	}

	policy := *lhsb.Policy
	switch policy {
	case SealPolicyConservative, SealPolicyDefault:
		if lhsb.PolicyInfo == nil {
			return nil, "", newError("principal not authorized for unseal: sealed bundle is missing policy info")
		}
		if child.Subprin().String() != *lhsb.PolicyInfo {
			return nil, "", newError("principal not authorized for unseal:\n  principal is: %v\n but owner is: %v\n", child.Subprin().String(), *lhsb.PolicyInfo)
		}
	case SealPolicyLiberal:
		// Allow all
		break
	default:
		return nil, "", newError("policy not supported for Unseal: " + policy)
	}
	return lhsb.Data, policy, nil
}

// Attest signs a statement on behalf of a child.
func (lh *LinuxHost) Attest(child HostedProgram, issuer *auth.Prin, time, expiration *int64, stmt auth.Form) (*Attestation, error) {
	return lh.Host.Attest(child.Subprin(), issuer, time, expiration, stmt)
}

// StartHostedProgram starts a new hosted program.
func (lh *LinuxHost) StartHostedProgram(spec HostedProgramSpec) (auth.SubPrin, int, error) {
	if !path.IsAbs(spec.Path) {
		return auth.SubPrin{}, 0, newError("%s: Path must be absolute", spec.Path)
	}
	if spec.Dir != "" && !path.IsAbs(spec.Dir) {
		return auth.SubPrin{}, 0, newError("%s: Dir must be absolute", spec.Dir)
	}
	lh.idm.Lock()
	id := lh.nextChildID
	if lh.nextChildID != 0 {
		lh.nextChildID++
	}
	lh.idm.Unlock()

	spec.Id = id

	factory := lh.childFactory[spec.ContainerType]
	if factory == nil {
		return auth.SubPrin{}, 0, newError("No suitable factory for starting container type %s", spec.ContainerType)
	}
	prog, err := factory.NewHostedProgram(spec)
	if err != nil {
		return auth.SubPrin{}, 0, err
	}

	// We allow multiple hosted programs with the same subprincipal name,
	// so we don't check here to make sure that there isn't another program
	// with the same subprincipal.

	// TODO(tmroeder): do we want to support concurrent updates to policy?
	// Then we need a lock here, too.
	hostName := lh.Host.HostName()
	subprin := prog.Subprin()
	childName := hostName.MakeSubprincipal(subprin)
	if !lh.guard.IsAuthorized(childName, "Execute", []string{}) {
		return auth.SubPrin{}, 0, newError("Hosted program %s denied authorization to execute on host %s", subprin, hostName)
	}

	m := prog.Manifest()
	m.Publish(lh.Host, subprin)

	if err = prog.Start(); err != nil {
		prog.Cleanup()
		return auth.SubPrin{}, 0, err
	}
	glog.Infof("Started hosted program with pid %d ...\n  path: %s\n  subprincipal: %s\n", prog.Pid(), spec.Path, subprin)

	go NewLinuxHostTaoServer(lh, prog).Serve(prog.Channel())

	lh.hpm.Lock()
	lh.hostedPrograms = append(lh.hostedPrograms, prog)
	lh.hpm.Unlock()

	go func() {
		<-prog.WaitChan()
		status, err := prog.ExitStatus()
		glog.Infof("Hosted program with pid %d exited with status %d (err=%s)", prog.Pid(), status, err)
		lh.hpm.Lock()
		for i, lph := range lh.hostedPrograms {
			if prog == lph {
				var empty []HostedProgram
				lh.hostedPrograms = append(append(empty, lh.hostedPrograms[:i]...), lh.hostedPrograms[i+1:]...)
				break
			}
		}
		lh.hpm.Unlock()
	}()

	return subprin, prog.Pid(), nil
}

// StopHostedProgram stops a running hosted program.
func (lh *LinuxHost) StopHostedProgram(subprin auth.SubPrin) error {
	var err error
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	for _, lph := range lh.hostedPrograms {
		if lph.Subprin().Identical(subprin) {
			err = lph.Stop()
			if err != nil {
				glog.Errorf("Couldn't stop hosted program %d, subprincipal %s: %s\n", lph.Pid(), subprin, err)
			}
		}
	}
	return err
}

// ListHostedPrograms returns a list of running hosted programs.
func (lh *LinuxHost) ListHostedPrograms() ([]auth.SubPrin, []int, error) {
	lh.hpm.RLock()
	subprins := make([]auth.SubPrin, len(lh.hostedPrograms))
	pids := make([]int, len(lh.hostedPrograms))
	for i, v := range lh.hostedPrograms {
		subprins[i] = v.Subprin()
		pids[i] = v.Pid()
	}
	lh.hpm.RUnlock()
	return subprins, pids, nil
}

// WaitHostedProgram waits for a running hosted program to exit.
func (lh *LinuxHost) WaitHostedProgram(pid int, subprin auth.SubPrin) (int, error) {
	lh.hpm.Lock()
	var p HostedProgram
	for _, lph := range lh.hostedPrograms {
		if lph.Pid() == pid && subprin.PrefixOf(lph.Subprin()) {
			p = lph
			break
		}
	}
	lh.hpm.Unlock()
	if p == nil {
		return -1, newError("no such hosted program")
	}
	<-p.WaitChan()
	return p.ExitStatus()
}

// KillHostedProgram kills a running hosted program.
func (lh *LinuxHost) KillHostedProgram(subprin auth.SubPrin) error {
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	for _, lph := range lh.hostedPrograms {
		if lph.Subprin().Identical(subprin) {
			if err := lph.Kill(); err != nil {
				glog.Errorf("Couldn't kill hosted program %d, subprincipal %s: %s\n", lph.Pid(), subprin, err)
			}
		}
	}
	return nil
}

// HostName returns the name of the Host used by the LinuxHost.
func (lh *LinuxHost) HostName() auth.Prin {
	return lh.Host.HostName()
}

// SignName returns the name of the Host used for signing by the LinuxHost.
func (lh *LinuxHost) SignName() auth.Prin {
	return lh.Host.SignName()
}

// Shutdown stops all hosted programs. If any remain after 10 seconds, they are
// killed. Cleans up factories and temp directories.
func (lh *LinuxHost) Shutdown() error {
	glog.Infof("Stopping all hosted programs")
	lh.hpm.Lock()
	// Request each child stop
	for _, lph := range lh.hostedPrograms {
		glog.Infof("Stopping hosted program %d\n", lph.Pid())
		if err := lph.Stop(); err != nil {
			glog.Errorf("Couldn't stop hosted program %d, subprincipal %s: %s\n", lph.Pid(), lph.Subprin(), err)
		}
	}
	timeout := make(chan bool, 1)
	waiting := make(chan bool, 1)
	go func() {
		time.Sleep(1 * time.Second)
		waiting <- true
		time.Sleep(9 * time.Second)
		timeout <- true
		close(timeout)
	}()
	// If timeout expires before child is done, kill child
	for _, lph := range lh.hostedPrograms {
		glog.Infof("Waiting for hosted program %d to stop\n", lph.Pid())
	childWaitLoop:
		for {
			select {
			case <-lph.WaitChan():
				glog.Infof("Hosted program %d stopped\n", lph.Pid())
				break childWaitLoop
			default:
				// fall into next select loop
			}
			select {
			case <-lph.WaitChan():
				glog.Infof("Hosted program %d stopped\n", lph.Pid())
				break childWaitLoop
			case <-waiting:
				glog.Infof("Still waiting for hosted program %d to stop\n", lph.Pid())
				glog.Infof("Waiting for hosted programs to stop")
			case <-timeout:
				glog.Infof("Hosted program %d is taking too long to stop\n", lph.Pid())
				glog.Infof("Killing hosted program %d, subprincipal %s\n", lph.Pid(), lph.Subprin())
				if err := lph.Kill(); err != nil {
					glog.Errorf("Couldn't kill hosted program %d, subprincipal %s: %s\n", lph.Pid(), lph.Subprin(), err)
				}
				glog.Infof("Hosted program %d killed, subprincipal %s\n", lph.Pid(), lph.Subprin())
				break childWaitLoop
			}
		}
	}
	glog.Infof("Reaping all hosted programs\n")
	// Reap all children
	for _, lph := range lh.hostedPrograms {
		glog.Infof("Reaping hosted program %d\n", lph.Pid())
		<-lph.WaitChan()
		glog.Infof("Hosted program %d reaped\n", lph.Pid())
	}
	lh.hostedPrograms = nil
	lh.hpm.Unlock()

	for _, factory := range lh.childFactory {
		glog.Infof("Cleaning up child factory %v\n", factory)
		factory.Cleanup()
	}

	glog.Infof("Shutdown tasks completed\n")

	return nil
}
