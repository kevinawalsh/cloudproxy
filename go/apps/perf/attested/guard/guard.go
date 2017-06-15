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
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

type prinTailFlags []auth.PrinTail

func (f *prinTailFlags) String() string {
	var s []string
	for _, p := range *f {
		s = append(s, fmt.Sprintf("%v", p))
	}
	return strings.Join(s, ",")
}

func (f *prinTailFlags) Set(value string) error {
	buf := bytes.NewBufferString(value)
	for buf.Len() > 0 {
		var p auth.PrinTail
		_, err := fmt.Fscan(buf, &p)
		if err != nil {
			return err
		}
		*f = append(*f, p)
	}
	return nil
}

var localTpmAttestation = flag.String("local_tpm_attestation", "", "File containing tpm attestation for this platform")
var peerTails prinTailFlags

func init() {
	flag.Var(&peerTails, "peer_subprin", "Subprincipal extension(s) for peer")
}

type AttestationGuard struct {
	LocalSerializedTpmAttestation []byte
	LocalTpmAttestation           tao.Attestation
	LocalSubprin                  auth.SubPrin
	PeerSubprins                  []auth.SubPrin
	PeerGroup                     auth.PrinExt
	PeerTpm                       auth.Prin
	tao.TrivialGuard
}

var Guard *AttestationGuard

func NewAttestationGuard() *AttestationGuard {
	if Guard != nil {
		return Guard
	}
	options.FailWhen(*localTpmAttestation == "", "-local_tpm_attestation is required")
	options.FailWhen(len(peerTails) == 0, "-peer_subprin is required")

	localName, err := tao.Parent().GetTaoName() // get last part of our name
	options.FailIf(err, "can't get name")
	localSubprin := localName.Ext[len(localName.Ext)-1:]

	s, err := ioutil.ReadFile(*localTpmAttestation)
	options.FailIf(err, "can't read peer tpm attestation")
	var a tao.Attestation
	err = proto.Unmarshal(s, &a)
	options.FailIf(err, "can't unmarshal peer tpm attestation")

	args := make([]interface{}, len(peerTails))
	peerExts := make([]auth.SubPrin, len(peerTails))
	for i, p := range peerTails {
		args[i] = p
		peerExts[i] = p.Ext
	}
	peerGroup := auth.MakePrinExt("PeeredWith", args...)
	err = tao.Parent().ExtendTaoName([]auth.PrinExt{peerGroup})
	options.FailIf(err, "can't extend name")

	Guard = &AttestationGuard{
		LocalSerializedTpmAttestation: s,
		LocalTpmAttestation:           a,
		LocalSubprin:                  localSubprin,
		PeerSubprins:                  peerExts,
		PeerGroup:                     peerGroup,
		TrivialGuard:                  tao.ConservativeGuard, // default for most methods
	}
	return Guard
}

func (t *AttestationGuard) IsAuthorized(name auth.Prin, op string, args []string) bool {
	// name should be tpm.pcrs.guard.prog.config, where
	// - tpm.pcrs.guard matches attestation from AddRule, which was signed by aa/domain key
	// - prog matches peer subprin
	// - config matches our subprin
	// fmt.Printf("checking peer: %v\n", name)
	for _, peerSubprin := range t.PeerSubprins {
		prin := t.PeerTpm.MakeSubprincipal(peerSubprin).MakeSubprincipal(auth.SubPrin{t.PeerGroup})
		// fmt.Printf("want: %v\n", prin)
		if prin.Identical(name) {
			// fmt.Printf("authorized\n")
			return true
		}
	}
	//fmt.Printf("denied\n")
	return false
}

func (t *AttestationGuard) AddRule(rule string) error {
	// should get attestation about peers tpm key, of the form:
	//  TrustedTpm(prin)
	// fmt.Printf("add rule: %s\n", rule)
	var pred auth.Pred
	_, err := fmt.Sscanf(rule, "%v", &pred)
	options.FailIf(err, "can't parse endorsement")
	options.FailWhen(pred.Name != "TrustedTPM" || len(pred.Arg) != 1, "bad endorsement")
	prin, ok := pred.Arg[0].(auth.Prin)
	options.FailWhen(!ok, "bad endorsement principal")
	t.PeerTpm = prin
	return nil
}
