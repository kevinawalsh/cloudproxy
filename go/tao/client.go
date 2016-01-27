// Copyright (c) 2014, Google, Inc. All rights reserved.
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
	"crypto/tls"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// TLS mode client/server

const (
	x509duration = 24 * time.Hour
	x509keySize  = 2048
)

// Dial connects to a Tao TLS server, performs a TLS handshake. If guard is nil,
// it verifies the Attestation value of the server, checking that the server is
// authorized to execute. If keys are provided (keys!=nil), then it sends an
// attestation of its identity to the peer. If config is nil, one will be
// created.
func Dial(network, addr string, guard Guard, v *Verifier, keys *Keys, conf *tls.Config) (*Conn, error) {
	// Set up certificate for two-way authentication.
	if conf == nil {
		var err error
		conf, err = keys.TLSClientConfig(nil)
		if err != nil {
			return nil, err
		}
	}
	conn, err := tls.Dial(network, addr, conf)
	if err != nil {
		return nil, err
	}
	var del *Attestation
	if keys != nil {
		del = keys.Delegation
	}
	c := &Conn{
		isServer: false,
		ConnAuth: ConnAuth{
			Authenticate:     keys != nil,
			delegation:       del,
			AuthenticatePeer: guard != nil,
			guard:            guard,
			verifier:         v,
		},
		Conn: conn,
	}
	c.FramedStream = util.FramedStream{util.MessageFraming{}, c}
	// Handshake now, since it seems better to fail early on client.
	err = c.Handshake()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// AddEndorsements reads the SerializedEndorsements in an attestation and adds
// the ones that are predicates signed by the policy key.
func AddEndorsements(guard Guard, a *Attestation, v *Verifier) error {
	// Before validating against the guard, check to see if there are any
	// predicates endorsed by the policy key. This allows truncated principals
	// to get the Tao CA to sign a statement of the form
	// TrustedHash(ext.Program(...)).
	for _, e := range a.SerializedEndorsements {
		var ea Attestation
		if err := proto.Unmarshal(e, &ea); err != nil {
			return err
		}

		f, err := auth.UnmarshalForm(ea.SerializedStatement)
		if err != nil {
			return err
		}

		says, ok := f.(auth.Says)
		if !ok {
			return fmt.Errorf("a serialized endorsement must be an auth.Says")
		}

		// TODO(tmroeder): check that this endorsement hasn't expired.
		pred, ok := says.Message.(auth.Pred)
		if !ok {
			return fmt.Errorf("the message in an endorsement must be a predicate")
		}

		signerPrin, err := auth.UnmarshalPrin(ea.Signer)
		if err != nil {
			return err
		}

		if !signerPrin.Identical(says.Speaker) {
			return fmt.Errorf("the speaker of an endorsement must be the signer")
		}
		if !v.ToPrincipal().Identical(signerPrin) {
			return fmt.Errorf("the signer of an endorsement must be the policy key")
		}
		if ok, err := v.Verify(ea.SerializedStatement, AttestationSigningContext, ea.Signature); (err != nil) || !ok {
			return fmt.Errorf("the signature on an endorsement didn't pass verification")
		}

		return guard.AddRule(pred.String())
	}

	return nil
}

// TruncateAttestation cuts off a delegation chain at its "Program" subprincipal
// extension and replaces its prefix with the given key principal. It also
// returns the PrinExt that represents exactly the program hash.
func TruncateAttestation(kprin auth.Prin, a *Attestation) (auth.Says, auth.PrinExt, error) {
	// This attestation must have a top-level delegation to a key. Return an
	// authorization for this program rooted in the policy key. I don't like
	// this, since it seems like it's much riskier, since this doesn't say
	// anything about the context in which the program is running. Fortunately,
	// local policy rules: if a peer won't accept this cert, then the other
	// program will have to fall back on the longer attestation.
	stmt, err := auth.UnmarshalForm(a.SerializedStatement)
	if err != nil {
		return auth.Says{}, auth.PrinExt{}, err
	}

	says, ok := stmt.(auth.Says)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the serialized statement must be a says")
	}
	// Replace the message with one that uses the new principal, taking the last
	// Program subprinicpal, and all its following elements. It should say:
	// policyKey.Program(...)... says key(...) speaksfor
	// policyKey.Program(...)..., signed policyKey.
	sf, ok := says.Message.(auth.Speaksfor)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the message in the statement must be a speaksfor")
	}

	delegator, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return auth.Says{}, auth.PrinExt{}, fmt.Errorf("the delegator must be a principal")
	}

	var prog auth.PrinExt
	found := false
	for _, sprin := range delegator.Ext {
		if !found && (sprin.Name == "Program") {
			found = true
			prog = sprin
		}

		if found {
			kprin.Ext = append(kprin.Ext, sprin)
		}
	}

	// TODO(tmroeder): make sure that the delegate is a key and is not, e.g.,
	// the policy key.
	truncSpeaksfor := auth.Speaksfor{
		Delegate:  sf.Delegate,
		Delegator: kprin,
	}
	truncSays := auth.Says{
		Speaker:    kprin,
		Time:       says.Time,
		Expiration: says.Expiration,
		Message:    truncSpeaksfor,
	}

	return truncSays, prog, nil
}

// IdenticalDelegations checks to see if two Form values are Says and are
// identical delegations (i.e., the Message must be an auth.Speaksfor).  This
// function is not in the auth package, since it's specific to a particular
// pattern.
func IdenticalDelegations(s, t auth.Form) bool {
	ss, ok := s.(auth.Says)
	if !ok {
		return false
	}
	st, ok := t.(auth.Says)
	if !ok {
		return false
	}
	if !ss.Speaker.Identical(st.Speaker) {
		return false
	}

	if (ss.Time == nil) != (st.Time == nil) {
		return false
	}
	if (ss.Time != nil) && (*ss.Time != *st.Time) {
		return false
	}
	if (ss.Expiration == nil) != (st.Expiration == nil) {
		return false
	}
	if (ss.Expiration != nil) && (*ss.Expiration != *st.Expiration) {
		return false
	}

	sfs, ok := ss.Message.(auth.Speaksfor)
	if !ok {
		return false
	}
	sft, ok := ss.Message.(auth.Speaksfor)
	if !ok {
		return false
	}

	if !sfs.Delegate.Identical(sft.Delegate) || !sfs.Delegator.Identical(sft.Delegator) {
		return false
	}

	return true
}
