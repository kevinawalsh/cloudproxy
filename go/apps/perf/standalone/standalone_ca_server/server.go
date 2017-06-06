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

package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/util/x509txt"
)

var host = flag.String("host", "0.0.0.0", "server host")
var port = flag.String("port", "8123", "server port")
var count = flag.Int("n", 1, "Number of trials, negative for indefinite")

var cahost = flag.String("cahost", "localhost", "ca server host")
var caport = flag.String("caport", "8124", "ca server port")

var name = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"kwalsh"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "localhost",
}

func main() {
	flag.Parse()

	// generate ecdsa key pair
	keys := generateKeysAndCertify(name)

	// listen
	addr := net.JoinHostPort(*host, *port)
	conf, err := keys.TLSServerConfig(keys.Cert["root"])
	options.FailIf(err, "error generating tls config")
	sock, err := tls.Listen("tcp", addr, conf)

	options.FailIf(err, "error listening at %s", addr)
	defer sock.Close()
	fmt.Printf("listening at %s.\n", addr)

	for i := 0; i < *count || *count < 0; i++ { // negative means forever
		// accept connection
		conn, err := sock.Accept()
		options.FailIf(err, "error accepting connection")

		// recv ping
		buf := []byte{1}
		_, err = conn.Read(buf)
		options.FailIf(err, "can't read")
		buf[0]++

		// send pong
		_, err = conn.Write(buf)
		options.FailIf(err, "can't write")

		conn.Close()

		verbose.Printf("done one\n")
	}
}

func generateKeysAndCertify(name *pkix.Name) *tao.Keys {
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	options.FailIf(err, "can't generate key")

	csr := taoca.NewCertificateSigningRequest(keys.VerifyingKey, name)
	caaddr := net.JoinHostPort(*cahost, *caport)
	conn, err := net.Dial("tcp", caaddr)
	options.FailIf(err, "error connecting to ca %s", caaddr)
	defer conn.Close()

	ms := util.NewMessageStream(conn)
	req := &taoca.Request{CSR: csr}
	_, err = ms.WriteMessage(req)
	options.FailIf(err, "error writing message")

	var resp taoca.Response
	err = ms.ReadMessage(&resp)
	options.FailIf(err, "error reading message")

	if *resp.Status != taoca.ResponseStatus_TAOCA_OK {
		options.Fail(nil, "ca response not OK")
	}
	if len(resp.Cert) == 0 {
		options.Fail(nil, "no cert in ca response")
	}
	certs := make([]*x509.Certificate, len(resp.Cert))
	for i, c := range resp.Cert {
		cert, err := x509.ParseCertificate(c.X509Cert)
		options.FailIf(err, "bad cert in ca response")
		certs[i] = cert
	}
	keys.Cert["default"] = certs[0]
	for i, c := range certs {
		name := "ca"
		if i > 0 {
			name = fmt.Sprintf("ca-%d", i)
		}
		keys.Cert[name] = c
	}

	chain := keys.CertChain("default")
	verbose.Printf("Obtained certfificate chain of length %d:\n", len(chain))
	for i, cert := range chain {
		verbose.Printf("  Cert[%d] Subject: %s\n", i, x509txt.RDNString(cert.Subject))
	}
	keys.Cert["root"] = chain[len(chain)-1]
	verbose.Println("Note: You may need to install root CA's key into the browser.")
	return keys
}
