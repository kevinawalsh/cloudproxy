// Copyright (c) 2017, Kevin Walsh.  All rights reserved.
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

package guard

import (
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

var localTpmAttestation = flag.String("local_tpm_attestation", "", "File containing tpm attestation for this platform")
var peerSubprin = flag.String("peer_subprin", "", "Subprincipal extension for peer")

type AttestationGuard struct {
	LocalSerializedTpmAttestation []byte
	LocalTpmAttestation           tao.Attestation
	LocalSubprin                  auth.SubPrin
	PeerSubprin                   auth.SubPrin
	PeerTpm                       auth.Prin
	tao.TrivialGuard
}

func NewAttestationGuard() *AttestationGuard {
	options.FailWhen(*localTpmAttestation == "", "-local_tpm_attestation is required")
	options.FailWhen(*peerSubprin == "", "-peer_subprin is required")

	localName, err := tao.Parent().GetTaoName() // get last part of our name
	options.FailIf(err, "can't get name")
	localSubprin := localName.Ext[len(localName.Ext)-1:]

	s, err := ioutil.ReadFile(*localTpmAttestation)
	options.FailIf(err, "can't read peer tpm attestation")
	var a tao.Attestation
	err = proto.Unmarshal(s, &a)
	options.FailIf(err, "can't unmarshal peer tpm attestation")

	var peer auth.PrinTail
	_, err = fmt.Sscanf(*peerSubprin, "%v", &peer)
	options.FailIf(err, "can't parse peer subprin")

	// extend our name
	err = tao.Parent().ExtendTaoName([]auth.PrinExt{auth.MakePrinExt("PeeredWith", peer)})
	options.FailIf(err, "can't extend name")

	return &AttestationGuard{
		LocalSerializedTpmAttestation: s,
		LocalTpmAttestation:           a,
		LocalSubprin:                  localSubprin,
		PeerSubprin:                   peer.Ext,
		TrivialGuard:                  tao.ConservativeGuard, // default for most methods
	}
}

func (t *AttestationGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	// name should be tpm.pcrs.guard.prog.config, where
	// - tpm.pcrs.guard matches attestation from AddRule, which was signed by aa/domain key
	// - prog matches peer subprin
	// - config matches our subprin
	fmt.Printf("checking peer: %v\n", name)
	prin := t.PeerTpm.MakeSubprincipal(t.PeerSubprin).MakeSubprincipal(auth.SubPrin{auth.MakePrinExt("PeeredWith", auth.PrinTail{t.LocalSubprin})})
	fmt.Printf("want: %v\n", prin)
	ok := prin.Identical(name)
	if ok {
		fmt.Printf("authorized\n")
	} else {
		fmt.Printf("denied, expecting: %v\n", prin)
	}
	return ok
}

func (t *AttestationGuard) AddRule(rule string) error {
	// should get attestation about peers tpm key, of the form:
	//  TrustedTpm(prin)
	fmt.Printf("add rule: %s\n", rule)
	var pred auth.Pred
	_, err := fmt.Sscanf(rule, "%v", &pred)
	options.FailIf(err, "can't parse endorsement")
	options.FailWhen(pred.Name != "TrustedTPM" || len(pred.Arg) != 1, "bad endorsement")
	prin, ok := pred.Arg[0].(auth.Prin)
	options.FailWhen(!ok, "bad endorsement principal")
	t.PeerTpm = prin
	return nil
}
