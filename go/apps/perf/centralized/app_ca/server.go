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

// app_ca acts as very tao-based CA to provide HTTPS/x509 certificates to
// a specific list of principals
//
// Requests:
//   CSR <name, is_ca, expiration, etc.>
//   Signature
// Responses:
//   OK <x509cert>
//   ERROR <msg>

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/perf/attested/guard"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/profiling"
	"github.com/kevinawalsh/taoca"
)

var serverHost = flag.String("host", "0.0.0.0", "address for app ca")
var serverPort = flag.String("port", "8127", "port for app ca")
var serverAddr string // see main()
var domainPathFlag = flag.String("tao_domain", "", "The Tao domain directory")
var showName = flag.Bool("show_name", false, "Show local principal name instead of running test")
var showSubprin = flag.Bool("show_subprin", false, "Show only local subprincipal extension name")

var caName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Root App Certificate Authority",
}

func main() {
	flag.Parse()

	options.FailWhen(tao.Parent() == nil, "No host Tao available")

	if *showName || *showSubprin {
		name, err := tao.Parent().GetTaoName()
		options.FailIf(err, "can't get name")
		if *showName {
			fmt.Printf("%s\n", name)
		} else {
			ext := name.Ext[2:]
			fmt.Printf("%s\n", auth.PrinTail{ext})
		}
		return
	}

	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "error: couldn't load the tao domain from %s\n", configPath())

	// generate new keys
	caKeys, err = tao.NewTemporaryNamedKeys(tao.Signing, caName)
	options.FailIf(err, "can't generate keys")

	serverAddr = net.JoinHostPort(*serverHost, *serverPort)

	g := guard.NewAttestationGuard()
	// Generate a private/public key for this hosted program (hp) and
	// request attestation from the host of the statement "hp speaksFor
	// host". The resulting certificate, keys.Delegation, is a chain of
	// "says" statements extending to the policy key. The policy is
	// checked by the host before this program is executed.
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
	options.FailIf(err, "server: failed to generate delegated keys")

	keys.Delegation.SerializedEndorsements = append(keys.Delegation.SerializedEndorsements, g.LocalSerializedTpmAttestation)
	sock, err := tao.Listen("tcp", serverAddr, keys, g, domain.Keys.VerifyingKey, nil)
	options.FailIf(err, "sever: couldn't create a taonet listener")

	defer sock.Close()

	fmt.Printf("Listening at %s using Tao-authenticated TLS channels\n", serverAddr)

	for {
		conn, err := sock.Accept()
		options.FailIf(err, "error accepting connection")
		// op := profiling.NewOp()
		ok, T := doResponse(util.NewMessageStream(conn))
		// stats.Done(&op, ok)
		if ok && T != nil {
			fmt.Println(T)
		}
	}
}

func domainPath() string {
	if *domainPathFlag != "" {
		return *domainPathFlag
	}
	if path := os.Getenv("TAO_DOMAIN"); path != "" {
		return path
	}
	options.Usage("Must supply -tao_domain or set $TAO_DOMAIN")
	return ""
}

func configPath() string {
	return path.Join(domainPath(), "tao.config")
}

func printRequest(req *taoca.Request, subjectKey *tao.Verifier, serial int64, peer string) {
	t := "Server (can't sign certificates)"
	if *req.CSR.IsCa {
		t = "Certificate Authority (can sign certificates)"
	}
	name := req.CSR.Name
	fmt.Printf("\n"+
		"A new Certificate Signing Request has been received:\n"+
		"  Country: %s\n"+
		"  Province: %s\n"+
		"  Locality: %s\n"+
		"  Organization: %s\n"+
		"  Organizational Unit: %s\n"+
		"  Common Name: %s\n"+
		"  Validity Period: %d years\n"+
		"  Type: %s\n"+
		"  Serial: %d\n"+
		"  Public Key Principal: %s\n"+
		"  Requesting Principal: %s\n"+
		"\n",
		*name.Country, *name.State, *name.City,
		*name.Organization, *name.OrganizationalUnit, *name.CommonName,
		*req.CSR.Years, t, serial, subjectKey.ToPrincipal(), peer)
}

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

func doResponse(conn util.MessageStream) (bool, *profiling.Trace) {
	T := profiling.NewTrace(10, 1)
	T.Start()
	defer conn.Close()

	var req taoca.Request

	if err := conn.ReadMessage(&req); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "failed to read request")
		return false, T
	}
	T.Sample("got msg") // 1

	peer := "anonymous"
	// if conn.Peer() != nil {
	// 	peer = conn.Peer().String()
	// }
	T.Sample("got peer") // 2

	var errmsg string

	// Check whether the CSR is well-formed
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
		return false, T
	}
	T.Sample("sanitized") // 3

	var ck tao.CryptoKey
	if err := proto.Unmarshal(req.CSR.PublicKey, &ck); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return false, T
	}
	subjectKey, err := tao.UnmarshalVerifierProto(&ck)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't unmarshal key")
		return false, T
	}
	// check signature on CSR
	scsr, err := proto.Marshal(req.CSR)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't marshal csr")
		return false, T
	}
	ok, err := subjectKey.Verify(scsr, "csr", req.Signature)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "can't verify csr signature")
		return false, T
	}
	if !ok {
		doError(conn, nil, taoca.ResponseStatus_TAOCA_BAD_REQUEST, "csr signature mismatch")
		return false, T
	}

	T.Sample("got subject") // 4

	// TODO(kwalsh) more robust generation of serial numbers?
	var serial int64
	if err := binary.Read(rand.Reader, binary.LittleEndian, &serial); err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "could not generate random serial number")
	}
	if serial < 0 {
		serial = ^serial
	}
	T.Sample("made serial") // 5

	if verbose.Enabled {
		printRequest(&req, subjectKey, serial, peer)
	}

	T.Sample("approved") // 6

	cps := cpsTemplate + cpsManual
	unotice := fmt.Sprintf(unoticeTemplate + "* The certificate was requested anonymously.\n")
	cpsUrl := publish([]byte(cps))
	unoticeUrl := publish([]byte(unotice))

	// ext, err := taoca.NewUserNotice("Hello user, how are you?")
	ext, err := taoca.NewCertficationPolicy(cpsUrl, unoticeUrl)
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate policy extension")
		return false, T
	}
	T.Sample("made cps") // 7

	template := caKeys.SigningKey.X509Template(NewX509Name(name), ext)
	template.IsCA = *req.CSR.IsCa
	template.SerialNumber.SetInt64(serial)
	cert, err := caKeys.CreateSignedX509(subjectKey, template, "default")
	if err != nil {
		doError(conn, err, taoca.ResponseStatus_TAOCA_ERROR, "failed to generate certificate")
		return false, T
	}
	T.Sample("signed cert") // 8

	status := taoca.ResponseStatus_TAOCA_OK
	resp := &taoca.Response{
		Status: &status,
		Cert:   []*taoca.Cert{&taoca.Cert{X509Cert: cert.Raw}},
	}
	for _, parent := range caKeys.CertChain("default") {
		resp.Cert = append(resp.Cert, &taoca.Cert{X509Cert: parent.Raw})
	}
	T.Sample("built response") // 9

	sendResponse(conn, resp)
	T.Sample("sent response") // 10
	fmt.Println(T)
	return true, T
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
