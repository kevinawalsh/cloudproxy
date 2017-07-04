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

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A RootHost is a standalone implementation of Host.
type RootHost struct {
	keys        *Keys
	taoHostName auth.Prin
	taoSignName auth.Prin
}

// NewTaoRootHostFromKeys returns a RootHost that uses these keys.
func NewTaoRootHostFromKeys(k *Keys) (*RootHost, error) {
	if k.SigningKey == nil || k.CryptingKey == nil || k.VerifyingKey == nil {
		return nil, newError("missing required key for RootHost")
	}

	p := k.SigningKey.ToPrincipal()
	s := p
	var err error
	if k.Delegation != nil {
		s, err = k.Delegation.ValidateDelegationFrom(k.SigningKey.ToPrincipal())
		if err != nil {
			return nil, err
		}
	}
	t := &RootHost{
		keys:        k,
		taoHostName: p,
		taoSignName: s,
	}

	return t, nil
}

// NewTaoRootHost generates a new RootHost with a fresh set of temporary
// keys.
func NewTaoRootHost() (*RootHost, error) {
	k, err := NewTemporaryKeys(Signing | Crypting)
	if err != nil {
		return nil, err
	}

	return NewTaoRootHostFromKeys(k)
}

// GetRandomBytes returns a slice of n random bytes.
func (t *RootHost) GetRandomBytes(childSubprin auth.SubPrin, n int) (bytes []byte, err error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *RootHost) GetSharedSecret(requester *auth.Prin, policy, tag string, n, level int) (bytes []byte, err error) {
	if level > 0 {
		return nil, newError("RootHost can't generate level %d shared secrets", level)
	}

	if t.keys.DerivingKey == nil {
		return nil, newError("this RootHost does not implement shared secrets")
	}

	// For now, all our key deriving with keys.DerivingKey uses a fixed 0-length salt.
	var salt []byte
	material := make([]byte, n)
	if err := t.keys.DerivingKey.Derive(salt, []byte(tag), material); err != nil {
		return nil, err
	}

	return material, nil
}

// SetFederatedSharedSecret sets the deriving key material.
func (t *RootHost) SetFederatedSharedSecret(bytes []byte, level int) error {
	if level > 0 {
		return newError("RootHost can't federate level %d shared secrets", level)
	}

	if t.keys.DerivingKey == nil {
		return newError("this RootHost does not implement shared secrets")
	}

	t.keys.DerivingKey.secret = bytes
	return nil
}

// Attest requests the Tao host sign a statement on behalf of a child.
func (t *RootHost) Attest(childSubprin auth.SubPrin, issuer *auth.Prin,
	time, expiration *int64, message auth.Form) (*Attestation, error) {

	child := t.taoHostName.MakeSubprincipal(childSubprin)
	if issuer != nil {
		if !auth.SubprinOrIdentical(*issuer, child) {
			return nil, newError("invalid issuer in statement")
		}
	} else {
		issuer = &child
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

	return GenerateAttestation(t.keys.SigningKey, nil /* delegation */, stmt)
}

func (t *RootHost) Say(stmt auth.Says) (*Attestation, error) {
	var d []byte
	if t.keys.Delegation != nil {
		var err error
		d, err = proto.Marshal(t.keys.Delegation)
		if err != nil {
			return nil, err
		}
	}
	return GenerateAttestation(t.keys.SigningKey, d, stmt)
}

func (t *RootHost) SetDelegation(delegation *Attestation) (err error) {
	delegator, err := delegation.ValidateDelegationFrom(t.taoHostName)
	if err != nil {
		return err
	}
	t.taoSignName = delegator
	t.keys.Delegation = delegation
	return nil
}

// Encrypt data so that only this host can access it.
func (t *RootHost) Encrypt(data []byte) (encrypted []byte, err error) {
	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *RootHost) Decrypt(encrypted []byte) (data []byte, err error) {
	return t.keys.CryptingKey.Decrypt(encrypted)
}

// AddedHostedProgram notifies this Host that a new hosted program has been
// created.
func (t *RootHost) AddedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// RemovedHostedProgram notifies this Host that a hosted program has been
// killed.
func (t *RootHost) RemovedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// HostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *RootHost) HostName() auth.Prin {
	return t.taoHostName
}

// SignName gets the Tao principal name this hosted Tao host uses for signing.
// This will either the same as HostName(), or it will be extracted from the
// delegation set previously.
func (t *RootHost) SignName() auth.Prin {
	return t.taoSignName
}
