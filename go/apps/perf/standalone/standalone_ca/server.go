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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/profiling"
	"github.com/kevinawalsh/taoca"
)

var opts = []options.Option{
	{"host", "0.0.0.0", "<address>", "Address for listening", "all"},
	{"port", "8124", "<port>", "Port for listening", "all"},
	{"init", false, "", "Initialize fresh signing keys", "all"},
	{"level", 0, "", "Number of certificate levels (0 for root CA, 1 for subsidiary, etc.)", "all"},
	{"keys", "", "<dir>", "Directory for storing keys and associated certificates", "all,persistent"},
	{"pass", "", "<password>", "Signing key password for manual mode (for testing only!)", "all"},
	{"config", "/etc/tao/https_ca/ca.config", "<file>", "Location for storing configuration", "all"},
	{"stats", "", "", "rate to print status updates", "all,persistent"},
	{"profile", "", "", "filename to capture cpu profile", "all,persistent"},
}

func init() {
	options.Add(opts...)
}

var stats profiling.Stats

var caKeys *tao.Keys
var caRootName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Root Certificate Authority",
}
var caSubsidiaryName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"Google"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "Experimental Google CloudProxy HTTPS/TLS Subsidiary Certificate Authority",
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

func main() {
	verbose.Set(true)
	options.Parse()

	profiling.ProfilePath = *options.String["profile"]

	if !verbose.Enabled {
		taoca.ConfirmNames = false
	}

	if *options.String["config"] != "" && !*options.Bool["init"] {
		err := options.Load(*options.String["config"])
		options.FailIf(err, "Can't load configuration")
	}

	fmt.Println("https/tls Certificate Authority")

	host := *options.String["host"]
	port := *options.String["port"]
	addr := net.JoinHostPort(host, port)

	// TODO(kwalsh) extend tao name with operating mode and policy

	cpath := *options.String["config"]
	kdir := *options.String["keys"]
	if kdir == "" && cpath != "" {
		kdir = path.Dir(cpath)
	} else if kdir == "" {
		options.Fail(nil, "Option -keys or -config is required")
	}

	var err error

	if *options.Bool["init"] {
		if cpath != "" {
			err := options.Save(cpath, "HTTPS/TLS certificate authority configuration", "persistent")
			options.FailIf(err, "Can't save configuration")
		}
		fmt.Println("" +
			"Initializing fresh HTTP/TLS CA signing key. Provide the following information,\n" +
			"to be include in the CA's own x509 certificate. Leave the response blank to\n" +
			"accept the default value.\n" +
			"\n" +
			"Configuration file: " + cpath + "\n" +
			"Keys directory: " + kdir + "\n")

		var caName *pkix.Name
		if taoca.ConfirmNames {
			if *options.Int["level"] == 0 {
				caName = taoca.ConfirmName(caRootName)
			} else {
				caName = taoca.ConfirmName(caSubsidiaryName)
			}
		} else {
			if *options.Int["level"] == 0 {
				caName = caRootName
			} else {
				caName = caSubsidiaryName
			}
		}

		pwd := options.Password("Choose an HTTPS/TLS CA signing key password", "pass")
		caKeys, err = tao.InitOnDiskPBEKeys(tao.Signing, pwd, kdir, caName)
		tao.ZeroBytes(pwd)

		options.FailIf(err, "Can't initialize fresh HTTPS/TLS CA signing key")
		if *options.Int["level"] == 0 {
			fmt.Printf(""+
				"Note: To install this CA's key in the Chrome browser, go to\n"+
				"  'Settings', 'Show advanced settings...', 'Manage Certificates...', 'Authorities'\n"+
				"  then import the following file:\n"+
				"     %s\n"+
				"  Select 'Trust this certificate for identifying websites' and/or other\n"+
				"  options, then click 'OK'\n", caKeys.X509Path("default"))
		} else {
			csr := taoca.NewCertificateSigningRequest(caKeys.VerifyingKey, caName)
			*csr.IsCa = true
			srv := fmt.Sprintf("Level %d Subsidiary", *options.Int["level"])
			taoca.DefaultServerName = srv
			//taoca.SubmitAndInstall(caKeys, csr)
			options.Fail(nil, "todo")
		}

	} else {
		pwd := options.Password("HTTPS/TLS CA signing key password", "pass")
		caKeys, err = tao.LoadOnDiskPBEKeys(tao.Signing, pwd, kdir)
		tao.ZeroBytes(pwd)
		options.FailIf(err, "Can't load HTTP/TLS CA signing key")
	}

	statsdelay := *options.String["stats"]
	if statsdelay != "" {
		go profiling.ShowStats(&stats, statsdelay, "sign certificates")
	}

	sock, err := net.Listen("tcp", addr)
	options.FailIf(err, "Can't listen")
	defer sock.Close()

	// srv.Keys = caKeys
	fmt.Printf("Listening at %s using Non-authenticated TCP channels\n", addr)
	// err = srv.ListenAndServe(addr)
	for {
		conn, err := sock.Accept()
		options.FailIf(err, "error accepting connection")
		op := profiling.NewOp()
		ok, T := doResponse(util.NewMessageStream(conn))
		stats.Done(&op, ok)
		if ok && T != nil {
			fmt.Println(T)
		}
	}
}

// There is room for two two URLs in each issued certificate. The first, the CPS
// or Certification Practices Statement, links to a statement of the approval
// practices under which this CA is operating. The second links to a User Notice
// statement about this specific certificate request, containing e.g. the full,
// verified Tao principal name of the subject. The integrity of these documents
// matters, so we hash them and embed the hash in the URL.

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
