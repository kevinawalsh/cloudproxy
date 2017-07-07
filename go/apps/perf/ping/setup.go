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
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"path"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/perf/attested/guard"
	psk "github.com/jlmucb/cloudproxy/go/apps/perf/central_psk"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/profiling"
	"github.com/kevinawalsh/taoca"
)

// Common setup code for ping-pong performance tests.

var ServerHost = flag.String("host", "localhost", "address for ping server")
var ServerPort = flag.String("port", "8123", "port for ping server")
var ServerAddr string

var Count = flag.Int("n", 5, "Number of repeat measurements")

var SharedSecretLevel = flag.Int("level", 0, "Levels for GetSharedSecret")
var Federated = flag.Bool("federated", false, "Use federated shared secrets")

var DomainPathFlag = flag.String("tao_domain", "", "The Tao domain directory")
var DomainPath string
var ConfigPath string
var Domain *tao.Domain
var Parent tao.Tao
var TaoName auth.Prin

var NameBase = flag.Int("name_base", 1, "Use 1 for soft tao, 2 for tpm, etc.")
var ShowName = flag.Bool("show_name", false, "Show local principal name, no tests")
var ShowSubprin = flag.Bool("show_subprin", false, "Show local subprincipal extension name, no tests")

var SaveName = flag.String("save_name", "", "Save local principal name to file, no tests")
var SaveSubprin = flag.String("save_subprin", "", "Show local subprincipal extension name, no tests")

var AppCAHost = flag.String("appcahost", "localhost", "Attested App CA server host")
var AppCAPort = flag.String("appcaport", "8127", "Attested App CA server port")
var AppCAAddr string

var StandaloneAppCAHost = flag.String("sappcahost", "localhost", "Standalone App CA server host")
var StandaloneAppCAPort = flag.String("sappcaport", "8127", "Standalone App CA server port")
var StandaloneAppCAAddr string

var AppKAHost = flag.String("appkahost", "localhost", "Attested App KA server host")
var AppKAPort = flag.String("appkaport", "8127", "Attested App KA server port")
var AppKAAddr string

var ResumeTLSSessions = flag.Bool("tls_resume", false, "Use TLS session resumption")

var PingBufSize = flag.Int("buf", 24, "Ping Buffer Size")

var Dump = flag.String("dump", "", "file for saving trace")

type PrinFlags []auth.Prin

func (f *PrinFlags) String() string {
	var s []string
	for _, p := range *f {
		s = append(s, fmt.Sprintf("%v", p))
	}
	return strings.Join(s, ",")
}

func (f *PrinFlags) Set(value string) error {
	buf := bytes.NewBufferString(value)
	for buf.Len() > 0 {
		var p auth.Prin
		_, err := fmt.Fscan(buf, &p)
		if err != nil {
			return err
		}
		*f = append(*f, p)
	}
	return nil
}

var PeerNames PrinFlags

func init() {
	flag.Var(&PeerNames, "peer_prins", "Principal names for shared secret ACL")
}

var CertName = &pkix.Name{
	Country:            []string{"US"},
	Province:           []string{"MA"},
	Locality:           []string{"Oakham"},
	Organization:       []string{"kwalsh"},
	OrganizationalUnit: []string{"CloudProxy"},
	CommonName:         "localhost",
}

var T *profiling.Trace

func EnableTracing() *profiling.Trace {
	T = &profiling.Trace{}
	return T
}

func ParseFlags(requiresTao bool) {
	flag.Parse()

	ServerAddr = net.JoinHostPort(*ServerHost, *ServerPort)
	AppCAAddr = net.JoinHostPort(*AppCAHost, *AppCAPort)
	StandaloneAppCAAddr = net.JoinHostPort(*StandaloneAppCAHost, *StandaloneAppCAPort)
	AppKAAddr = net.JoinHostPort(*AppKAHost, *AppKAPort)

	if !requiresTao {
		return
	}

	Parent = tao.Parent()
	options.FailWhen(Parent == nil, "Requires host Tao, but no parent available")

	var err error
	TaoName, err = Parent.GetTaoName()
	options.FailIf(err, "can't get Tao name")
	TaoTail := auth.PrinTail{TaoName.Ext[*NameBase:]}

	exit := false
	if *ShowName {
		fmt.Printf("%s\n", TaoName)
		exit = true
	}
	if *ShowSubprin {
		fmt.Printf("%s\n", TaoTail)
		exit = true
	}
	if SaveName != nil && *SaveName != "" {
		err := ioutil.WriteFile(*SaveName, []byte(fmt.Sprintf("%s\n", TaoName)), 0666)
		options.FailIf(err, "can't write file")
		exit = true
	}
	if SaveSubprin != nil && *SaveSubprin != "" {
		err := ioutil.WriteFile(*SaveSubprin, []byte(fmt.Sprintf("%s\n", TaoTail)), 0666)
		options.FailIf(err, "can't write file")
		exit = true
	}
	if exit {
		os.Exit(0)
	}

	if *DomainPathFlag != "" {
		DomainPath = *DomainPathFlag
	} else if path := os.Getenv("TAO_DOMAIN"); path != "" {
		DomainPath = path
	} else {
		options.Fail(nil, "must supply -tao_domain or set $TAO_DOMAIN")
	}

	ConfigPath = path.Join(DomainPath, "tao.config")

	Domain, err = tao.LoadDomain(ConfigPath, nil)
	options.FailIf(err, "can't load Tao domain")

	if *Federated {
		err = Parent.SetFederatedSharedSecret([]byte("todoTODOtodoTODOtodoTODO"), *SharedSecretLevel)
		options.FailIf(err, "can't federate at given level")
	}
}

func AttestedListen(addr string) *tao.Listener {
	keys, g := GenerateKeysWithAttestationGuard()
	sock, err := tao.Listen("tcp", addr, keys, g, Domain.Keys.VerifyingKey, nil)
	options.FailIf(err, "listening")
	fmt.Printf("Listening at %s using Tao-attested channels\n", addr)
	return sock
}

func GenerateKeysAndCertifyWithStandaloneAppCA(name *pkix.Name) *tao.Keys {

	keys, err := tao.NewTemporaryKeys(tao.Signing)
	options.FailIf(err, "can't generate key")
	T.Sample("genkey")

	csr := taoca.NewCertificateSigningRequest(keys.VerifyingKey, name)
	scsr, err := proto.Marshal(csr)
	options.FailIf(err, "serializing csr")
	sig, err := keys.SigningKey.Sign(scsr, "csr")
	T.Sample("gen csr")

	conn, err := net.Dial("tcp", StandaloneAppCAAddr)
	options.FailIf(err, "connecting to standalone app ca")
	defer conn.Close()

	ObtainCertFromCA(conn, keys, csr, sig, "ca", "root")
	return keys
}

func GenerateKeysWithAttestationGuard() (*tao.Keys, tao.Guard) {
	g := guard.NewAttestationGuard()
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, Parent)
	options.FailIf(err, "generating keys")
	keys.Delegation.SerializedEndorsements = append(keys.Delegation.SerializedEndorsements, g.LocalSerializedTpmAttestation)
	T.Sample("genkey")
	return keys, g
}

func GenerateKeysAndCertifyWithAppCA(name *pkix.Name) *tao.Keys {

	keys1, g := GenerateKeysWithAttestationGuard()
	appCAKey = keys1
	appCAGuard = g

	keys2, err := tao.NewTemporaryKeys(tao.Signing) // alternative: use keys1 for both connections
	options.FailIf(err, "can't generate key")
	T.Sample("genkey")
	csr := taoca.NewCertificateSigningRequest(keys2.VerifyingKey, name)
	scsr, err := proto.Marshal(csr)
	options.FailIf(err, "serializing csr")
	sig, err := keys2.SigningKey.Sign(scsr, "csr")
	T.Sample("gen csr")

	conf, err := keys1.TLSClientConfig(nil)
	options.FailIf(err, "tls config")
	conf.SessionTicketsDisabled = !*ResumeTLSSessions
	if *ResumeTLSSessions {
		conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	appCAConf = conf
	conn, err := tao.Dial("tcp", AppCAAddr, g, Domain.Keys.VerifyingKey, keys1, conf)
	options.FailIf(err, "connecting to attested app ca")
	defer conn.Close()
	T.Sample("connect ca")

	ObtainCertFromCA(conn, keys2, csr, sig, "appca", "approot")
	return keys2
}

var appCAKey *tao.Keys    // also used for PSK_KA
var appCAGuard tao.Guard  // also used for PSK_KA
var appCAConf *tls.Config // also used for PSK_KA

func GenerateKeysAndRecertifyWithAppCA(name *pkix.Name) *tao.Keys {
	keys2, err := tao.NewTemporaryKeys(tao.Signing) // alternative: use keys1 for yet another connection
	options.FailIf(err, "can't generate key")
	T.Sample("regenkey")
	csr := taoca.NewCertificateSigningRequest(keys2.VerifyingKey, name)
	scsr, err := proto.Marshal(csr)
	options.FailIf(err, "serializing csr")
	sig, err := keys2.SigningKey.Sign(scsr, "csr")
	T.Sample("regen csr")

	conn, err := tao.Dial("tcp", AppCAAddr, appCAGuard, Domain.Keys.VerifyingKey, appCAKey, appCAConf)
	options.FailIf(err, "connecting to attested app ca")
	defer conn.Close()
	T.Sample("reconnect ca")

	ObtainCertFromCA(conn, keys2, csr, sig, "appca", "approot")
	return keys2
}

func ObtainCertFromCA(conn net.Conn, keys *tao.Keys, csr *taoca.CSR, sig []byte, ca, root string) {
	ms := util.NewMessageStream(conn)
	req := &taoca.Request{CSR: csr, Signature: sig}
	_, err := ms.WriteMessage(req)
	options.FailIf(err, "sending csr")

	var resp taoca.Response
	err = ms.ReadMessage(&resp)
	options.FailIf(err, "reading ca response")

	if *resp.Status != taoca.ResponseStatus_TAOCA_OK {
		options.Fail(nil, "bad app ca response")
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
			name = fmt.Sprintf("%s-%d", ca, i)
		}
		keys.Cert[name] = c
	}

	chain := keys.CertChain("default")
	// verbose.Printf("Obtained certfificate chain of length %d:\n", len(chain))
	// for i, cert := range chain {
	// 	verbose.Printf("  Cert[%d] Subject: %s\n", i, x509txt.RDNString(cert.Subject))
	// }
	keys.Cert[root] = chain[len(chain)-1]

	T.Sample("getcert")
}

func ObtainPreSharedKeyFromKA() []byte {
	// generate keys
	keys1, g := GenerateKeysWithAttestationGuard()
	appCAKey = keys1
	appCAGuard = g

	// open connection
	conf, err := keys1.TLSClientConfig(nil)
	options.FailIf(err, "tls config")
	conf.SessionTicketsDisabled = !*ResumeTLSSessions
	if *ResumeTLSSessions {
		conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
	}
	appCAConf = conf
	conn, err := tao.Dial("tcp", AppKAAddr, g, Domain.Keys.VerifyingKey, keys1, conf)
	options.FailIf(err, "connecting to attested psk ka")
	T.Sample("connect psk ka")

	peerGroup := g.(*guard.AttestationGuard).PeerGroup
	req := &psk.KGRequest{
		PeerGroup: auth.Marshal(auth.PrinTail{auth.SubPrin{peerGroup}}),
	}

	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(req)
	options.FailIf(err, "sending kgr")

	var resp psk.KGResponse
	err = ms.ReadMessage(&resp)
	options.FailIf(err, "reading ka response")
	ms.Close()

	if resp.ErrorDetail != nil && len(*resp.ErrorDetail) != 0 {
		options.Fail(nil, *resp.ErrorDetail)
	}
	T.Sample("obtain psk")
	return resp.KeyMaterial
}

func ObtainAnotherPreSharedKeyFromKA() []byte {
	// generate keys
	keys1 := appCAKey
	g := appCAGuard

	// open connection
	conf := appCAConf
	conn, err := tao.Dial("tcp", AppKAAddr, g, Domain.Keys.VerifyingKey, keys1, conf)
	options.FailIf(err, "connecting to attested psk ka")
	T.Sample("reconnect psk ka")

	peerGroup := g.(*guard.AttestationGuard).PeerGroup
	req := &psk.KGRequest{
		PeerGroup: auth.Marshal(auth.PrinTail{auth.SubPrin{peerGroup}}),
	}

	ms := util.NewMessageStream(conn)
	_, err = ms.WriteMessage(req)
	options.FailIf(err, "sending kgr")

	var resp psk.KGResponse
	err = ms.ReadMessage(&resp)
	options.FailIf(err, "reading ka response")
	ms.Close()

	if resp.ErrorDetail != nil && len(*resp.ErrorDetail) != 0 {
		options.Fail(nil, *resp.ErrorDetail)
	}
	T.Sample("reobtain psk")
	return resp.KeyMaterial
}

func WriteReadClose(conn io.ReadWriteCloser) (x int64, y int64, z int64) {
	// send ping
	buf := make([]byte, *PingBufSize)

	_, err := conn.Write(buf[:])
	options.FailIf(err, "writing")

	// recv pong
	n, err := conn.Read(buf[:])
	options.FailWhen(n != *PingBufSize, "bad pong: len=%d\n", n)
	// options.FailWhen(buf[0] != 2, "bad pong: %d\n", buf[0])
	T.Sample("rtt")

	// close tls connection
	err = conn.Close()
	options.FailIf(err, "closing")

	x = int64(binary.LittleEndian.Uint64(buf[0:8]))
	y = int64(binary.LittleEndian.Uint64(buf[8:16]))
	z = int64(binary.LittleEndian.Uint64(buf[16:24]))
	return x, y, z
}

func ReadWriteClose(conn io.ReadWriteCloser, getData func() (int64, int64, int64)) {
	// recv ping
	buf := make([]byte, *PingBufSize)
	n, err := conn.Read(buf[:])
	options.FailWhen(n != *PingBufSize, "bad ping: len=%d\n", n)

	// send pong
	var x, y, z int64
	if getData != nil {
		x, y, z = getData()
	}
	binary.LittleEndian.PutUint64(buf[0:8], uint64(x))
	binary.LittleEndian.PutUint64(buf[8:16], uint64(y))
	binary.LittleEndian.PutUint64(buf[16:24], uint64(z))
	_, err = conn.Write(buf[:])
	options.FailIf(err, "writing")

	err = conn.Close()
	options.FailIf(err, "closing")
}

func GetLocalTaoSharedSecret() []byte {
	options.FailWhen(len(PeerNames) == 0, "-peer_prins is required")

	g := tao.NewACLGuard()

	for _, peer := range PeerNames {
		g.Authorize(peer, "GetSharedSecret", nil)
	}

	sharedSecret, err := Parent.GetSharedSecret(nil, 30, g, *SharedSecretLevel)
	options.FailIf(err, "obtaining psk")
	// fmt.Printf("shared secret is %v\n", sharedSecret)
	T.Sample("get psk")
	return sharedSecret
}
