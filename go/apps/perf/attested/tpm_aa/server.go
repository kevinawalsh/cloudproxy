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

// standalone_ca acts as very simple CA to provide HTTPS/x509 certificates to
// any principal that asks for one.
//
// Requests:
//   CSR <name, is_ca, expiration, etc.>
//   Signature
// Responses:
//   OK <x509cert>
//   ERROR <msg>

package main

import (
	"crypto/x509/pkix"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
)

var opts = []options.Option{
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all"},
	{"attestation", "", "<file>", "File for storing signed tpm attestation", "all"},
	{"id", 0, "", "Sequence number / ID for attestation", "all"},
	{"delegation", false, "", "Use a speaksfor delegation instead of a predicate", "all"},
}

func init() {
	options.Add(opts...)
}

var aaName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Root Certificate Authority",
}

func main() {
	options.Parse()

	id := *options.Int["id"]
	options.FailWhen(id == 0, "-id is required")

	kdir := *options.String["keys"]
	options.FailWhen(kdir == "", "-keys is required")

	afile := *options.String["attestation"]
	options.FailWhen(afile == "", "-attestation is required")

	parent := tao.Parent()
	options.FailWhen(parent == nil, "This must run on tao")

	pwd := []byte("BogusPass")
	aaKeys, err := tao.NewOnDiskPBEKeys(tao.Signing, pwd, kdir, aaName)
	options.FailIf(err, "Can't get or initialize root AA signing key (or domain signing key)")

	name, err := parent.GetTaoName()
	options.FailIf(err, "Can't get Tao principal name")

	aa := aaKeys.SigningKey.ToPrincipal()
	aasub := aa.MakeSubprincipal(auth.SubPrin([]auth.PrinExt{auth.MakePrinExt("tpm", id)}))
	tpm := name.Parent()

	verbose.Printf("TPM-Tao:\n%v\n\n", tpm)
	verbose.Printf("Root keys for attestation authority:\n%v\n\n", aa)
	verbose.Printf("Delegate:\n%v\n\n", aasub)

	var stmt auth.Says
	if *options.Bool["delegation"] {
		delegation := auth.Speaksfor{
			Delegate:  tpm,
			Delegator: aasub,
		}
		stmt = auth.Says{
			Speaker: aa,
			Message: delegation,
		}
	} else {
		pred := auth.MakePredicate("TrustedTPM", tpm)
		stmt = auth.Says{
			Speaker: aa,
			Message: pred,
		}
	}

	verbose.Printf("Statement:\n%v\n\n", stmt)

	attestation, err := tao.GenerateAttestation(aaKeys.SigningKey, nil, stmt)
	verbose.Printf("Attestation:\n%v\n\n", attestation)

	ser, err := proto.Marshal(attestation)
	options.FailIf(err, "Can't serialize attestation")
	err = util.WritePath(afile, ser, 0777, 0644)
	options.FailIf(err, "Can't write attestation")

	verbose.Printf("Attestation written to: %s\n", afile)

}
