// Copyright (c) 2014, Google Corporation.  All rights reserved.
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
// File: fileserver.go

package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"log"
	"net"

	"github.com/jlmucb/cloudproxy/apps/fileproxy"
	tao "github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var hostcfg = flag.String("../hostdomain/tao.config", "../hostdomain/tao.config", "path to host tao configuration")
var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var fileserverPath = flag.String("fileserver_files/", "fileserver_files/", "fileserver directory")
var fileserverFilePath = flag.String("fileserver_files/stored_files/", "fileserver_files/stored_files/",
	"fileserver directory")
var serverAddr string
var testFile = flag.String("originalTestFile", "originalTestFile", "test file")

var fileServerResourceMaster fileproxy.ResourceMaster
var FileServerResourceMaster *fileproxy.ResourceMaster
var fileServerProgramPolicy fileproxy.ProgramPolicy
var FileServerProgramPolicy *fileproxy.ProgramPolicy

func clientServiceThead(ms *util.MessageStream, fileGuard tao.Guard) {
	log.Printf("fileserver: clientServiceThead\n")
	var clientProgramName string

	// TODO: get program name of principal that established channel

	// How do I know if the connection terminates?
	for {
		log.Printf("clientServiceThead: ReadString\n")
		strbytes, err := ms.ReadString()
		if err != nil {
			return
		}
		terminate, err := FileServerResourceMaster.HandleServiceRequest(ms, *FileServerProgramPolicy, clientProgramName, []byte(strbytes))
		if terminate {
			break
		}
	}
	log.Printf("fileserver: client thread terminating\n")
}

func server(serverAddr string, prin string, derPolicyCert []byte, signingKey *tao.Keys) {
	var sock net.Listener
	log.Printf("fileserver: server\n")

	FileServerResourceMaster = new(fileproxy.ResourceMaster)
	err := FileServerResourceMaster.InitMaster(*fileserverFilePath, *fileserverPath, prin)
	if err != nil {
		log.Printf("fileserver: can't InitMaster\n")
		return
	}

	policyCert, err := x509.ParseCertificate(derPolicyCert)
	if err != nil {
		log.Printf("fileserver: can't ParseCertificate\n")
		return
	}
	pool := x509.NewCertPool()
	pool.AddCert(policyCert)
	tlsc, err := taonet.EncodeTLSCert(signingKey)
	if err != nil {
		log.Printf("fileserver, encode error: ", err)
		log.Printf("\n")
		return
	}
	conf := &tls.Config{
		RootCAs:            pool,
		Certificates:       []tls.Certificate{*tlsc},
		InsecureSkipVerify: false,
		ClientAuth:         tls.RequireAnyClientCert,
	}
	log.Printf("Listening\n")
	sock, err = tls.Listen("tcp", serverAddr, conf)
	if err != nil {
		log.Printf("fileserver, listen error: ", err)
		log.Printf("\n")
		return
	}
	for {
		log.Printf("fileserver: at Accept\n")
		conn, err := sock.Accept()
		if err != nil {
			log.Printf("fileserver: can't accept connection: %s\n", err.Error())
		} else {
			ms := util.NewMessageStream(conn)
			go clientServiceThead(ms, FileServerResourceMaster.Guard)
		}
	}
}

func main() {
	flag.Parse()
	serverAddr = *serverHost + ":" + *serverPort

	hostDomain, err := tao.LoadDomain(*hostcfg, nil)
	if err != nil {
		return
	}
	log.Printf("fileserver: Domain name: %s\n", hostDomain.ConfigPath)
	var derPolicyCert []byte
	if hostDomain.Keys.Cert != nil {
		derPolicyCert = hostDomain.Keys.Cert.Raw
	}
	if derPolicyCert == nil {
		log.Printf("fileserver: can't retrieve policy cert\n")
		return
	}

	e := auth.PrinExt{Name: "fileserver_version_1"}
	err = tao.Parent().ExtendTaoName(auth.SubPrin{e})
	if err != nil {
		return
	}

	taoName, err := tao.Parent().GetTaoName()
	if err != nil {
		log.Printf("fileserver: cant get tao name\n")
		return
	}
	log.Printf("fileserver: my name is %s\n", taoName)

	FileServerResourceMaster = &fileServerResourceMaster
	FileServerProgramPolicy = &fileServerProgramPolicy

	var programCert []byte
	sealedSymmetricKey, sealedSigningKey, programCert, delegation, err := fileproxy.LoadProgramKeys(*fileserverPath)
	if err != nil {
		log.Printf("fileserver: cant retrieve key material\n")
	}
	if sealedSymmetricKey == nil || sealedSigningKey == nil || delegation == nil || programCert == nil {
		log.Printf("fileserver: No key material present\n")
	}

	var symKeys []byte
	defer fileproxy.ZeroBytes(symKeys)
	if sealedSymmetricKey != nil {
		symKeys, policy, err := tao.Parent().Unseal(sealedSymmetricKey)
		if err != nil {
			return
		}
		if policy != tao.SealPolicyDefault {
			log.Printf("fileserver: unexpected policy on unseal\n")
		}
		log.Printf("fileserver: Unsealed symKeys: % x\n", symKeys)
	} else {
		symKeys, err = fileproxy.InitializeSealedSymmetricKeys(*fileserverPath, tao.Parent(), fileproxy.SizeofSymmetricKeys)
		if err != nil {
			log.Printf("fileserver: InitializeSealedSymmetricKeys error: %s\n", err)
		}
		log.Printf("fileserver: InitilizedsymKeys: % x\n", symKeys)
	}

	var signingKey *tao.Keys
	if sealedSigningKey != nil {
		log.Printf("retrieving signing key\n")
		signingKey, err = fileproxy.SigningKeyFromBlob(tao.Parent(),
			sealedSigningKey, programCert, delegation)
		if err != nil {
			log.Printf("fileserver: SigningKeyFromBlob error: %s\n", err)
		}
		log.Printf("fileserver: Retrieved Signing key: % x\n", *signingKey)
	} else {
		log.Printf("fileserver: initializing signing key\n")
		signingKey, err = fileproxy.InitializeSealedSigningKey(*fileserverPath,
			tao.Parent(), *hostDomain)
		if err != nil {
			log.Printf("fileserver: InitializeSealedSigningKey error: %s\n", err)
		}
		log.Printf("fileserver: Initialized signingKey: % x\n", *signingKey)
		programCert = signingKey.Cert.Raw
	}
	taoNameStr := taoName.String()
	_ = FileServerProgramPolicy.InitProgramPolicy(derPolicyCert, taoNameStr, *signingKey, symKeys, programCert)

	server(serverAddr, taoNameStr, derPolicyCert, signingKey)
	if err != nil {
		log.Printf("fileserver: server error\n")
	}
	log.Printf("fileserver: done\n")
}
