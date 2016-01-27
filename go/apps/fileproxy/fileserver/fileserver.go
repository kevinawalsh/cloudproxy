// Copyright (c) 2014, Google, Inc. All rights reserved.
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
//
// File: fileserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"
	"os"
	"path"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/fileproxy"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

func serve(addr, fp string, cert []byte, signingKey *tao.Keys, policy *fileproxy.ProgramPolicy) error {
	m := fileproxy.NewResourceMaster(fp)

	policyCert, err := x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	conf, err := signingKey.TLSServerConfig(policyCert)
	if err != nil {
		return err
	}
	log.Println("fileserver listening")
	sock, err := tls.Listen("tcp", addr, conf)
	if err != nil {
		return err
	}

	for {
		// Accept and handle client connections one at a time.
		conn, err := sock.Accept()
		if err != nil {
			return err
		}

		var clientName string
		if err = conn.(*tls.Conn).Handshake(); err != nil {
			log.Printf("fileserver: couldn't perform handshake: %s\n", err)
			continue
		}

		peerCerts := conn.(*tls.Conn).ConnectionState().PeerCertificates
		if peerCerts == nil {
			log.Println("fileserver: couldn't get peer list")
			continue
		}

		peerCert := conn.(*tls.Conn).ConnectionState().PeerCertificates[0]
		if peerCert.Raw == nil {
			log.Println("fileserver: couldn't get peer name")
			continue
		}

		if peerCert.Subject.OrganizationalUnit != nil {
			clientName = peerCert.Subject.OrganizationalUnit[0]
		}
		log.Printf("fileserver: peer name: '%s'\n", clientName)
		ms := util.NewMessageStream(conn)

		// TODO(tmroeder): support multiple simultaneous clients. This
		// requires, e.g., adding locking to the ResourceMaster.
		if err := m.RunMessageLoop(ms, policy); err != nil {
			log.Printf("fileserver: failed to run message loop: %s\n", err)
			continue
		}

		log.Println("Finished handling the client messages")
	}
}

func main() {
	caAddr := flag.String("caAddr", "localhost:8124", "The address of the CA for setting up a certificate signed by the policy key")
	hostcfg := flag.String("hostconfig", "tao.config", "path to host tao configuration")
	serverHost := flag.String("host", "localhost", "address for client/server")
	serverPort := flag.String("port", "8123", "port for client/server")
	fileServerPath := flag.String("fileserver_files", "fileserver_files/", "fileserver directory")
	fileServerFilePath := flag.String("stored_files", "fileserver_files/stored_files/", "fileserver directory")
	country := flag.String("country", "US", "The country for the fileclient certificate")
	org := flag.String("organization", "Google", "The organization for the fileclient certificate")

	flag.Parse()

	serverAddr := net.JoinHostPort(*serverHost, *serverPort)
	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		log.Fatalln("fileserver: can't LoadDomain")
	}

	var policyCert []byte
	if hostDomain.Keys.Cert["default"] != nil {
		policyCert = hostDomain.Keys.Cert["default"].Raw
	}
	if policyCert == nil {
		log.Fatalln("fileserver: can't retrieve policy cert")
	}

	parentTao := tao.Parent()
	if err := hostDomain.ExtendTaoName(parentTao); err != nil {
		log.Fatalln("fileserver: can't extend the Tao with the policy key")
	}
	e := auth.PrinExt{Name: "fileserver_version_1"}
	if err = parentTao.ExtendTaoName(auth.SubPrin{e}); err != nil {
		log.Fatalln("fileserver: couldn't extend the Tao name")
	}

	taoName, err := parentTao.GetTaoName()
	if err != nil {
		log.Fatalln("fileserver: couldn't get tao name")
	}

	// Create or read the keys for fileclient.
	// Set up a temporary cert for communication with keyNegoServer.
	// TODO(kwalsh) This may no longer be needed. Is there a significance to
	// this cert?
	name := tao.NewX509Name(&tao.X509Details{
		Country:      proto.String(*country),
		Organization: proto.String(*org),
		CommonName:   proto.String(taoName.String()),
	})
	fsKeys, err := tao.NewOnDiskTaoSealedKeys(tao.Signing|tao.Crypting, name, parentTao, *fileServerPath, tao.SealPolicyDefault)
	if err != nil {
		log.Fatalln("fileserver: couldn't set up the Tao-sealed keys:", err)
	}

	// Contact keyNegoServer for the certificate.
	if err := fileproxy.EstablishCert("tcp", *caAddr, fsKeys, hostDomain.Keys.VerifyingKey); err != nil {
		log.Fatalf("fileserver: couldn't establish a cert signed by the policy key: %s", err)
	}

	symKeysPath := path.Join(*fileServerPath, "sealedEncKeys")
	symKeys, err := fsKeys.NewSecret(symKeysPath, fileproxy.SymmetricKeySize)
	if err != nil {
		log.Fatalln("fileserver: couldn't get the file encryption keys")
	}
	tao.ZeroBytes(symKeys)

	progPolicy := fileproxy.NewProgramPolicy(policyCert, taoName.String(), fsKeys, symKeys, fsKeys.Cert["default"].Raw)

	// Set up the file storage path if it doesn't exist.
	if _, err := os.Stat(*fileServerFilePath); err != nil {
		if err := os.MkdirAll(*fileServerFilePath, 0700); err != nil {
			log.Fatalln("fileserver: couldn't create a file storage directory:", err)
		}
	}

	if err := serve(serverAddr, *fileServerFilePath, policyCert, fsKeys, progPolicy); err != nil {
		log.Fatalln("fileserver: couldn't serve connections:", err)
	}

	log.Printf("fileserver: done\n")
}
