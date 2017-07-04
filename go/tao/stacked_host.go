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
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A StackedHost implements Host over an existing host Tao, optionally using a
// set of keys to avoid calling the underlying host Tao in some situations.
// If keys is nil, all calls will pass through to the underlying host Tao.
// Otherwise:
// - if keys has a SigningKey, it will be used for attestions.
// - if keys has a CryptingKey, it will be used for sealing and unsealing.
// - if keys has a DerivingKey, it will be used for deriving keys.
type StackedHost struct {
	taoHostName auth.Prin
	taoSignName auth.Prin
	hostTao     Tao
	keys        *Keys
}

// NewTaoStackedHostFromKeys takes ownership of an existing set of keys and
// returns a StackedHost that uses these keys over an existing host Tao.
func NewTaoStackedHostFromKeys(k *Keys, t Tao) (Host, error) {
	n, err := t.GetTaoName()
	if err != nil {
		return nil, err
	}
	s := n
	if k != nil && k.Delegation != nil {
		s, err = k.Delegation.ValidateDelegationFrom(k.SigningKey.ToPrincipal())
		if err != nil {
			return nil, err
		}
	}
	tsh := &StackedHost{
		keys:        k,
		taoHostName: n,
		taoSignName: s,
		hostTao:     t,
	}

	return tsh, nil
}

// NewTaoStackedHost generates a new StackedHost, optionally with a fresh set of
// temporary keys.
func NewTaoStackedHost(t Tao, keyTypes KeyType) (Host, error) {
	if keyTypes == 0 {
		return NewTaoStackedHostFromKeys(nil, t)
	}

	k, err := NewTemporaryKeys(keyTypes)
	if err != nil {
		return nil, err
	}

	return NewTaoStackedHostFromKeys(k, t)
}

// GetRandomBytes returns a slice of n random bytes.
func (t *StackedHost) GetRandomBytes(childSubprin auth.SubPrin, n int) (bytes []byte, err error) {
	return t.hostTao.GetRandomBytes(n)
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *StackedHost) GetSharedSecret(requester *auth.Prin, policy, tag string, n, level int) (bytes []byte, err error) {
	if level > 0 {
		return t.hostTao.GetSharedSecret(requester, n, policy, level-1)
	}

	if level == 0 && (t.keys == nil || t.keys.DerivingKey == nil) {
		// TODO(tmroeder): this should be implemented using the underlying host
		return nil, newError("this StackedHost does not yet implement shared secrets")
	}

	// TODO(tmroeder): for now, we're using a fixed zero salt and counting on
	// the strength of HKDF with a strong key.
	salt := make([]byte, 8)
	material := make([]byte, n)
	// fmt.Printf("Deriving %d-byte secret with salt %02x\n", n, salt)
	if err := t.keys.DerivingKey.Derive(salt, []byte(tag), material); err != nil {
		return nil, err
	}
	// fmt.Printf("Secret is %02x\n", material)

	return material, nil
}

// Attest requests the Tao host sign a statement on behalf of a child.
func (t *StackedHost) Attest(childSubprin auth.SubPrin, issuer *auth.Prin,
	time, expiration *int64, message auth.Form) (*Attestation, error) {

	child := t.taoHostName.MakeSubprincipal(childSubprin)
	if issuer != nil {
		if !auth.SubprinOrIdentical(*issuer, child) {
			return nil, newError("invalid issuer in statement")
		}
	} else {
		issuer = &child
	}

	if t.keys == nil || t.keys.SigningKey == nil {
		return t.hostTao.Attest(issuer, time, expiration, message)
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

	return t.Say(stmt)
}

func (t *StackedHost) Say(stmt auth.Says) (*Attestation, error) {
	if t.keys == nil || t.keys.SigningKey == nil {
		return nil, newError("Say is not yet implemented for keyless stacked hosts")
	}
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

func (t *StackedHost) SetDelegation(delegation *Attestation) (err error) {
	if t.keys == nil || t.keys.SigningKey == nil {
		return newError("SetDelegation requires a signing key")
	}
	delegator, err := delegation.ValidateDelegationFrom(t.keys.SigningKey.ToPrincipal())
	if err != nil {
		return err
	}
	t.taoSignName = delegator
	t.keys.Delegation = delegation
	return nil
}

// Encrypt data so that only this host can access it.
func (t *StackedHost) Encrypt(data []byte) (encrypted []byte, err error) {
	if t.keys == nil || t.keys.CryptingKey == nil {
		// TODO(tmroeder) (from TODO(kwalsh) in tao_stacked_host.cc):
		// where should the policy come from here?
		return t.hostTao.Seal(data, SealPolicyDefault)
	}

	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *StackedHost) Decrypt(encrypted []byte) (data []byte, err error) {
	if t.keys != nil && t.keys.CryptingKey != nil {
		return t.keys.CryptingKey.Decrypt(encrypted)
	}

	// TODO(tmroeder) (from TODO(kwalsh) in tao_stacked_host.cc):
	// where should the policy come from here?
	var policy string
	data, policy, err = t.hostTao.Unseal(encrypted)
	if err != nil {
		return nil, err
	}

	if policy != SealPolicyDefault {
		return nil, newError("unsealed data with uncertain provenance")
	}

	return data, nil
}

// AddedHostedProgram notifies this Host that a new hosted program has been
// created.
func (t *StackedHost) AddedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// RemovedHostedProgram notifies this Host that a hosted program has been
// killed.
func (t *StackedHost) RemovedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// HostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *StackedHost) HostName() auth.Prin {
	return t.taoHostName
}

// SignName gets the Tao principal name this hosted Tao host uses for signing.
// This will either the same as HostName(), or it will be extracted from the
// delegation set previously.
func (t *StackedHost) SignName() auth.Prin {
	return t.taoSignName
}
