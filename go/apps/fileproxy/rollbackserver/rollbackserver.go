// Copyright (c) 2014, Google, Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: rollbackserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/fileproxy"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

func serve(serverAddr string, prin string, policyCert []byte, signingKey *tao.Keys, policy *fileproxy.ProgramPolicy, m *fileproxy.RollbackMaster) error {
	pc, err := x509.ParseCertificate(policyCert)
	if err != nil {
		return err
	}
	conf, err := signingKey.TLSServerConfig(pc)
	if err != nil {
		return err
	}
	log.Println("Rollback server listening")
	sock, err := tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		return err
	}

	for {
		conn, err := sock.Accept()
		if err != nil {
			return err
		}
		var clientName string
		if err = conn.(*tls.Conn).Handshake(); err != nil {
			log.Println("TLS handshake failed")
			continue
		}

		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Println("rollbackserver: can't get peer list")
			continue
		}

		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert.Raw == nil {
			log.Println("rollbackserver: can't get peer name")
			continue
		}

		if peerCert.Subject.OrganizationalUnit == nil {
			log.Println("No OrganizationalUnit name in the peer certificate. Refusing the connection")
			continue
		}

		clientName = peerCert.Subject.OrganizationalUnit[0]
		ms := util.NewMessageStream(conn)
		// TODO(tmroeder): support multiple simultaneous clients.
		// Add this program as a rollback program.
		log.Printf("Adding a program with name '%s'\n", clientName)
		_ = m.AddRollbackProgram(clientName)
		if err := m.RunMessageLoop(ms, policy, clientName); err != nil {
			log.Printf("rollbackserver: failed to run message loop: %s\n", err)
		}
	}
}

func main() {
	caAddr := flag.String("caAddr", "localhost:8124", "The address of the CA for setting up a certificate signed by the policy key")
	hostcfg := flag.String("hostconfig", "tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8129", "port for client/server")
	rollbackServerPath := flag.String("rollbackserver_files", "rollbackserver_files", "rollbackserver directory")
	country := flag.String("country", "US", "The country for the fileclient certificate")
	org := flag.String("organization", "Google", "The organization for the fileclient certificate")

	flag.Parse()
	serverAddr := net.JoinHostPort(*serverHost, *serverPort)

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("rollbackserver: can't load domain:", err)
	}
	var policyCert []byte
	if hostDomain.Keys.Cert["default"] != nil {
		policyCert = hostDomain.Keys.Cert["default"].Raw
	}
	if policyCert == nil {
		log.Fatalln("rollbackserver: can't retrieve policy cert")
	}

	parentTao := tao.Parent()
	if err := hostDomain.ExtendTaoName(parentTao); err != nil {
		log.Fatalln("fileserver: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "rollbackserver_version_1"}
	if err = parentTao.ExtendTaoName(auth.SubPrin{e}); err != nil {
		log.Fatalln("rollbackserver: can't extend name")
	}

	taoName, err := parentTao.GetTaoName()
	if err != nil {
		return
	}

	// Create or read the keys for rollbackserver.
	// Set up a temporary cert for communication with keyNegoServer.
	// TODO(kwalsh) This may no longer be needed. Is there a significance to
	// this cert?
	name := tao.NewX509Name(&tao.X509Details{
		Country:      proto.String(*country),
		Organization: proto.String(*org),
		CommonName:   proto.String(taoName.String()),
	})
	rbKeys, err := tao.NewOnDiskTaoSealedKeys(tao.Signing|tao.Crypting, name, parentTao, *rollbackServerPath, tao.SealPolicyDefault)
	if err != nil {
		log.Fatalln("rollbackserver: couldn't set up the Tao-sealed keys:", err)
	}

	if err != nil {
		log.Fatalln("rollbackserver: couldn't create a self-signed cert for rollbackserver keys:", err)
	}

	// Contact keyNegoServer for the certificate.
	if err := fileproxy.EstablishCert("tcp", *caAddr, rbKeys, hostDomain.Keys.VerifyingKey); err != nil {
		log.Fatalf("rollbackserver: couldn't establish a cert signed by the policy key: %s", err)
	}

	// The symmetric keys aren't used by the rollback server.
	progPolicy := fileproxy.NewProgramPolicy(policyCert, taoName.String(), rbKeys, nil, rbKeys.Cert["default"].Raw)
	m := fileproxy.NewRollbackMaster(taoName.String())

	if err := serve(serverAddr, taoName.String(), policyCert, rbKeys, progPolicy, m); err != nil {
		log.Fatalf("rollbackserver: server error: %s\n", err)
	}
	log.Println("rollbackserver: done")
}
