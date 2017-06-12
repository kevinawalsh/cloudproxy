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
	Subprin                       auth.SubPrin
	tao.TrivialGuard
}

func NewAttestationGuard() *AttestationGuard {
	s, err := ioutil.ReadFile(*localTpmAttestation)
	options.FailIf(err, "can't read peer tpm attestation")
	var a tao.Attestation
	err = proto.Unmarshal(s, &a)
	options.FailIf(err, "can't unmarshal peer tpm attestation")

	var subprin auth.SubPrin
	_, err = fmt.Sscanf(*peerSubprin, "%v", &subprin)
	options.FailIf(err, "can't parse peer subprin")

	return &AttestationGuard{
		LocalSerializedTpmAttestation: s,
		LocalTpmAttestation:           a,
		Subprin:                       subprin,
		TrivialGuard:                  tao.ConservativeGuard,
	}
}

func (t AttestationGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	// name should be tpm.pcrs.guard.prog.config, where
	// - tpm.pcrs.guard matches attestation from AddRule, which was signed by aa/domain key
	// - prog matches peer subprin
	// - config matches our subprin
	ok := true
	if ok {
		fmt.Printf("authorized peer: %v\n", name)
	} else {
		fmt.Printf("denied peer: %v\n", name)
	}
	return ok
}

func (t AttestationGuard) AddRule(rule string) error {
	// should get attestation about peers tpm key
	fmt.Printf("add rule: %s\n", rule)
	return nil
}
