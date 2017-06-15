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

package ping

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca"
)

func doError(ms util.MessageStream, err error, status taoca.ResponseStatus, detail string) {
	if err != nil {
		fmt.Printf("error handling request: %s\n", err)
	}
	fmt.Printf("sending error response: status=%s detail=%q\n", status, detail)
	resp := &taoca.Response{
		Status:      &status,
		ErrorDetail: proto.String(detail),
	}
	sendResponse(ms, resp)
}

func sendResponse(ms util.MessageStream, resp *taoca.Response) {
	_, err := ms.WriteMessage(resp)
	if err != nil {
		fmt.Printf("error writing response: %s\n", err)
	}
}

var legalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890,:.()_/ "

func sanitize(s *string, fieldName string, errmsg *string) string {
	if *errmsg != "" {
		return ""
	}
	if s == nil {
		*errmsg = "missing name." + fieldName
		return ""
	}
	if *s == "" {
		*errmsg = "empty name." + fieldName
		return ""
	}
	for i := 0; i < len(*s); i++ {
		if !strings.ContainsRune(legalChars, rune((*s)[i])) {
			*errmsg = "invalid characters in name." + fieldName
			return ""
		}
	}
	if *s != strings.TrimSpace(*s) {
		*errmsg = "invalid whitespace in name." + fieldName
		return ""
	}
	return *s
}

func publish(doc []byte) string {
	docurl := "http://www.example.com"
	h := sha256.Sum256(doc)
	url := fmt.Sprintf("%s/%x.txt", docurl, h)
	return url
}

// NewX509Name returns a new pkix.Name.
func NewX509Name(p *taoca.X509Details) *pkix.Name {
	return &pkix.Name{
		Country:            []string{p.GetCountry()},
		Organization:       []string{p.GetOrganization()},
		OrganizationalUnit: []string{p.GetOrganizationalUnit()},
		Province:           []string{p.GetState()},
		Locality:           []string{p.GetCity()},
		CommonName:         string(p.GetCommonName()),
	}
}

func InitCA() {
	// generate new standalone root keys for ca
	var err error
	caKeys, err = tao.NewTemporaryNamedKeys(tao.Signing, CertName)
	options.FailIf(err, "generating keys")
	// Print some stats on exit
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for _ = range c {
			fmt.Printf("CA issued %d certificates\n", CertificatesIssued)
			os.Exit(0)
		}
	}()
}

var CertificatesIssued int

func HandleCSR(conn util.MessageStream) {
	defer conn.Close()
	var req taoca.Request
	if err := conn.ReadMessage(&req); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "failed to read request")
		return
	}

	// Check whether the CSR is well-formed
	var errmsg string
	name := req.CSR.Name
	sanitize(name.Country, "Country", &errmsg)
	sanitize(name.State, "State/Province", &errmsg)
	sanitize(name.City, "City/Locality", &errmsg)
	sanitize(name.Organization, "Organization", &errmsg)
	ou := sanitize(name.OrganizationalUnit, "OrganizationalUnit", &errmsg)
	cn := sanitize(name.CommonName, "CommonName", &errmsg)
	years := *req.CSR.Years
	verbose.Printf("Request for OU=%s CN=%s\n", ou, cn)
	if years <= 0 {
		errmsg = "invalid validity period"
	}
	if errmsg != "" {
		doError(conn, nil, taoca.ResponseStatus_TAOCA_BAD_REQUEST, errmsg)
		return
	}

	var ck tao.CryptoKey
	if err := proto.Unmarshal(req.CSR.PublicKey, &ck); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return
	}
	subjectKey, err := tao.UnmarshalVerifierProto(&ck)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return
	}
	// check signature on CSR
	scsr, err := proto.Marshal(req.CSR)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't marshal csr")
		return
	}
	ok, err := subjectKey.Verify(scsr, "csr", req.Signature)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't verify csr signature")
		return
	}
	if !ok {
		doError(conn, nil, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "csr signature mismatch")
		return
	}

	var serial int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &serial); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "could not generate random serial number")
	}
	if serial < 0 {
		serial = ^serial
	}

	cps := cpsTemplate + cpsManual
	unotice := fmt.Sprintf(unoticeTemplate + "* The certificate was requested anonymously.\n")
	cpsUrl := publish([]byte(cps))
	unoticeUrl := publish([]byte(unotice))

	ext, err := taoca.NewCertficationPolicy(cpsUrl, unoticeUrl)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate policy extension")
		return
	}

	template := caKeys.SigningKey.X509Template(NewX509Name(name), ext)
	template.IsCA = *req.CSR.IsCa
	template.SerialNumber.SetInt64(serial)
	cert, err := caKeys.CreateSignedX509(subjectKey, template, "default")
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate")
		return
	}

	status := taoca.ResponseStatus_TAOCA_OK
	resp := &taoca.Response{
		Status: &status,
		Cert:   []*taoca.Cert{&taoca.Cert{X509Cert: cert.Raw}},
	}
	for _, parent := range caKeys.CertChain("default") {
		resp.Cert = append(resp.Cert, &taoca.Cert{X509Cert: parent.Raw})
	}

	sendResponse(conn, resp)
	CertificatesIssued++
}

var cpsTemplate = `Experimental Cloudproxy HTTPS Certificate Authority
** Certification Practices Statement **

This document specifies the practices and policies under which certificate
signing requests are approved by some instance of the Experimental Cloudproxy
HTTPS Certificate Authority.

Document Integrity
------------------

This document should be hosted as a file with name <hhh>.txt where <hhh> is the
sha256 hash of this document. If the document hash does not match the file name,
then the contents of this document should not be trusted.

Policies
--------

* Certificates issued will include extended validation (EV) information,
  including links to this document and a user notice document under the
  id-qt-cps and id-qt-unotice extensions. The user notice document will include
  details about the circumstances under which the certificate was issued.
`

var cpsManual = `
* Certificate signing requests are vetted and approved manually by the holder of
  the certficiate authority private signing key.
`

var unoticeTemplate = `Experimental Cloudproxy HTTPS Certificate Authority
** User Notice **

This document details the circumstances under which some certificate was issued
by some instance of the Experimental Cloudproxy HTTPS Certificate Authority.

Document Integrity
------------------

This document should be hosted as a file with name <hhh>.txt where <hhh> is the
sha256 hash of this document. If the document hash does not match the file name,
then the contents of this document should not be trusted.

Issuance Details
----------------

`

var caKeys *tao.Keys
