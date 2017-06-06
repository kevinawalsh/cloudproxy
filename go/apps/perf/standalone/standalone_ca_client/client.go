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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"

	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/kevinawalsh/profiling"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/util/x509txt"
)

var host = flag.String("host", "localhost", "server host")
var port = flag.String("port", "8123", "server port")
var count = flag.Int("n", 1, "Number of trials")

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

	T := profiling.NewTrace(6, *count)

	for i := 0; i < *count; i++ {

		T.Start()

		_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		options.FailIf(err, "error generating extra key")
		_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		options.FailIf(err, "error generating extra key")
		_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		options.FailIf(err, "error generating extra key")
		_, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		options.FailIf(err, "error generating extra key")
		T.Sample("extrakey")

		// generate ecdsa key pair
		keys := generateKeysAndCertify(name, T)

		// open tls connection
		addr := net.JoinHostPort(*host, *port)
		conf, err := keys.TLSClientConfig(keys.Cert["root"])
		options.FailIf(err, "error generating tls config")
		conn, err := tls.Dial("tcp", addr, conf)
		options.FailIf(err, "error connecting to %s", addr)
		defer conn.Close()
		T.Sample("connect")

		// send ping
		buf := []byte{1}
		_, err = conn.Write(buf)
		options.FailIf(err, "can't write")

		// recv pong
		n, err := conn.Read(buf)
		options.FailWhen(n != 1, "bad pong: len=%d\n", n)
		options.FailWhen(buf[0] != 2, "bad pong: %d\n", buf[0])
		T.Sample("rtt")

		// close tls connection
		err = conn.Close()
		options.FailIf(err, "can't close")

		verbose.Printf("done one\n")
	}

	fmt.Println(T)
}

func generateKeysAndCertify(name *pkix.Name, T *profiling.Trace) *tao.Keys {
	keys, err := tao.NewTemporaryKeys(tao.Signing)
	options.FailIf(err, "can't generate key")
	T.Sample("genkey")

	csr := taoca.NewCertificateSigningRequest(keys.VerifyingKey, name)
	scsr, err := proto.Marshal(csr)
	options.FailIf(err, "error serializing csr")
	sig, err := keys.SigningKey.Sign(scsr, "csr")
	caaddr := net.JoinHostPort(*cahost, *caport)
	conn, err := net.Dial("tcp", caaddr)
	options.FailIf(err, "error connecting to ca %s", caaddr)
	defer conn.Close()
	T.Sample("gencsr")

	ms := util.NewMessageStream(conn)
	req := &taoca.Request{CSR: csr, Signature: sig}
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
	T.Sample("certify")
	return keys
}
