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
	"os"
	"path"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/perf/attested/guard"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
	"github.com/kevinawalsh/taoca"
	"github.com/kevinawalsh/taoca/util/x509txt"
)

var serverHost = flag.String("host", "0.0.0.0", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var domainPathFlag = flag.String("tao_domain", "", "The Tao domain directory")
var showName = flag.Bool("show_name", false, "Show local principal name instead of running test")
var showSubprin = flag.Bool("show_subprin", false, "Show only local subprincipal extension name")

var caHost = flag.String("cahost", "localhost", "ca server host")
var caPort = flag.String("caport", "8127", "app ca server port")

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

	fmt.Println("Go Tao Demo Server")

	serverAddr = net.JoinHostPort(*serverHost, *serverPort)

	// generate ecdsa key pair
	keys := generateKeysAndCertify(name)

	// listen
	conf, err := keys.TLSServerConfig(keys.Cert["approot"])
	options.FailIf(err, "error generating tls config")
	sock, err := tls.Listen("tcp", serverAddr, conf)

	options.FailIf(err, "error listening at %s", serverAddr)
	defer sock.Close()
	fmt.Printf("listening at %s.\n", serverAddr)

	for i := 0; i < *pingCount || *pingCount < 0; i++ { // negative means forever
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

	caAddr := net.JoinHostPort(*caHost, *caPort)
	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "error: couldn't load the tao domain from %s\n", configPath())

	g := guard.NewAttestationGuard()
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
	options.FailIf(err, "server: failed to generate delegated keys")
	keys.Delegation.SerializedEndorsements = append(keys.Delegation.SerializedEndorsements, g.LocalSerializedTpmAttestation)

	csr := taoca.NewCertificateSigningRequest(keys.VerifyingKey, name)
	scsr, err := proto.Marshal(csr)
	options.FailIf(err, "error serializing csr")
	sig, err := keys.SigningKey.Sign(scsr, "csr")

	fmt.Printf("server: connecting to app ca %s using tao authentication.\n", caAddr)
	conn, err := tao.Dial("tcp", caAddr, g, domain.Keys.VerifyingKey, keys, nil)
	options.FailIf(err, "error connecting to app ca %s", caAddr)
	defer conn.Close()

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
			name = fmt.Sprintf("appca-%d", i)
		}
		keys.Cert[name] = c
	}

	chain := keys.CertChain("default")
	verbose.Printf("Obtained certfificate chain of length %d:\n", len(chain))
	for i, cert := range chain {
		verbose.Printf("  Cert[%d] Subject: %s\n", i, x509txt.RDNString(cert.Subject))
	}
	keys.Cert["approot"] = chain[len(chain)-1]
	return keys
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
