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
// File: fileproxy.go

package fileproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"code.google.com/p/goprotobuf/proto"

	"github.com/jlmucb/cloudproxy/tao"
	"github.com/jlmucb/cloudproxy/tao/auth"
	taonet "github.com/jlmucb/cloudproxy/tao/net"
	"github.com/jlmucb/cloudproxy/util"
)

var caAddr = flag.String("caAddr", "localhost:8124", "The address to listen on")
var taoChannelAddr = flag.String("taoChannelAddr", "localhost:8124", "The address to listen on")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

const SizeofSymmetricKeys = 64

// RequestTruncatedAttestation connects to a CA instance, sends the attestation
// for an X.509 certificate, and gets back a truncated attestation with a new
// principal name based on the policy key.
func RequestKeyNegoAttestation(network, addr string, keys *tao.Keys, v *tao.Verifier) (*tao.Attestation, error) {
	if keys.Cert == nil {
		return nil, errors.New("client: can't dial with an empty client certificate\n")
	}
	tlsCert, err := taonet.EncodeTLSCert(keys)
	if err != nil {
		return nil, err
	}
	conn, err := tls.Dial(network, addr, &tls.Config{
		RootCAs:            x509.NewCertPool(),
		Certificates:       []tls.Certificate{*tlsCert},
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// Tao handshake: send client delegation.
	ms := util.NewMessageStream(conn)
	if _, err = ms.WriteMessage(keys.Delegation); err != nil {
		return nil, err
	}

	// Read the truncated attestation and check it.
	var a tao.Attestation
	if err := ms.ReadMessage(&a); err != nil {
		return nil, err
	}

	ok, err := v.Verify(a.SerializedStatement, tao.AttestationSigningContext, a.Signature)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("invalid attestation signature from Tao CA")
	}

	return &a, nil
}

func ZeroBytes(buf []byte) {
	n := len(buf)
	for i := 0; i < n; i++ {
		buf[i] = 0
	}
}

// returns sealed symmetric key, sealed signing key, DER encoded cert, delegation, error
func LoadProgramKeys(path string) ([]byte, []byte, []byte, []byte, error) {
	fileinfo, err := os.Stat(path + "sealedsymmetrickey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Size of %s is %d\n", path+"sealedsymmetricKey", fileinfo.Size())
	fileinfo, err = os.Stat(path + "sealedsigningKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Size of %s is %d\n", path+"sealedsigningKey", fileinfo.Size())
	fileinfo, err = os.Stat(path + "signerCert")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Size of %s is %d\n", path+"signerCert", fileinfo.Size())

	sealedSymmetricKey, err := ioutil.ReadFile(path + "sealedsymmetricKey")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got sealedSymmetricKey\n")
	sealedSigningKey, err := ioutil.ReadFile(path + "sealedsigningKey")
	log.Printf("sealedSigningKey: ", sealedSigningKey)
	log.Printf("\n")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got sealedSigningKey\n")
	derCert, err := ioutil.ReadFile(path + "signerCert")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("fileproxy: Got signerCert\n")
	ds, err := ioutil.ReadFile(path + "delegationBlob")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	log.Printf("LoadProgramKeys succeeded\n")
	return sealedSymmetricKey, sealedSigningKey, derCert, ds, nil
}

func CreateSigningKey(t tao.Tao) (*tao.Keys, []byte, error) {
	self, err := t.GetTaoName()
	k, err := tao.NewTemporaryKeys(tao.Signing)
	if k == nil || err != nil {
		return nil, nil, errors.New("Cant generate signing key")
	}
	publicString := strings.Replace(self.String(), "(", "", -1)
	publicString = strings.Replace(publicString, ")", "", -1)
	log.Printf("fileclient, publicString: %s\n", publicString)
	details := tao.X509Details{
		Country:      "US",
		Organization: "Google",
		CommonName:   publicString}
	subjectname := tao.NewX509Name(details)
	derCert, err := k.SigningKey.CreateSelfSignedDER(subjectname)
	if err != nil {
		return nil, nil, errors.New("Can't self sign cert\n")
	}
	log.Printf("fileproxy: derCert: %x\n", derCert)
	log.Printf("\n")
	cert, err := x509.ParseCertificate(derCert)
	if err != nil {
		return nil, nil, err
	}
	k.Cert = cert
	s := &auth.Speaksfor{
		Delegate:  k.SigningKey.ToPrincipal(),
		Delegator: self}
	if s == nil {
		return nil, nil, errors.New("Cant produce speaksfor")
	}
	if k.Delegation, err = t.Attest(&self, nil, nil, s); err != nil {
		return nil, nil, err
	}
	if err == nil {
		temp, _ := auth.UnmarshalForm(k.Delegation.SerializedStatement)
		log.Printf("fileproxy: deserialized statement: %s\n", temp.String())
	}
	return k, derCert, nil
}

func InitializeSealedSymmetricKeys(path string, t tao.Tao, keysize int) ([]byte, error) {
	unsealed, err := tao.Parent().GetRandomBytes(keysize)
	if err != nil {
		return nil, errors.New("Cant get random bytes")
	}
	sealed, err := tao.Parent().Seal(unsealed, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Cant seal random bytes")
	}
	ioutil.WriteFile(path+"sealedsymmetrickey", sealed, os.ModePerm)
	return unsealed, nil
}

func InitializeSealedSigningKey(path string, t tao.Tao, domain tao.Domain) (*tao.Keys, error) {
	k, derCert, err := CreateSigningKey(t)
	if err != nil {
		log.Printf("fileproxy: CreateSigningKey failed with error %s\n", err)
		return nil, err
	}
	if derCert == nil {
		log.Printf("fileproxy: CreateSigningKey failed, no dercert\n")
		return nil, errors.New("No DER cert")
	}
	na, err := RequestKeyNegoAttestation("tcp", *caAddr, k, domain.Keys.VerifyingKey)
	if err != nil {
		log.Printf("fileproxy: error from taonet.RequestTruncatedAttestation\n")
		return nil, err
	}
	if na == nil {
		return nil, errors.New("tao returned nil attestation")
	}
	k.Delegation = na
	log.Printf("\n")
	pa, _ := auth.UnmarshalForm(na.SerializedStatement)
	log.Printf("returned attestation: %s", pa.String())
	log.Printf("\n")
	var saysStatement *auth.Says
	if ptr, ok := pa.(*auth.Says); ok {
		saysStatement = ptr
	} else if val, ok := pa.(auth.Says); ok {
		saysStatement = &val
	}
	sf, ok := saysStatement.Message.(auth.Speaksfor)
	if ok != true {
		return nil, errors.New("says doesnt have speaksfor message")
	}
	kprin, ok := sf.Delegate.(auth.Term)
	if ok != true {
		return nil, errors.New("speaksfor message doesnt have Delegate")
	}
	newCert := auth.Bytes(kprin.(auth.Bytes))
	k.Cert, err = x509.ParseCertificate(newCert)
	if err != nil {
		log.Printf("cant parse returned certificate", err)
		log.Printf("\n")
		return nil, err
	}
	signingKeyBlob, err := tao.MarshalSignerDER(k.SigningKey)
	if err != nil {
		return nil, errors.New("Cant produce signing key blob")
	}
	sealedSigningKey, err := t.Seal(signingKeyBlob, tao.SealPolicyDefault)
	if err != nil {
		return nil, errors.New("Cant seal signing key")
	}
	err = ioutil.WriteFile(path+"sealedsigningKey", sealedSigningKey, os.ModePerm)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(path+"signerCert", newCert, os.ModePerm)
	if err != nil {
		return nil, err
	}
	delegateBlob, err := proto.Marshal(k.Delegation)
	if err != nil {
		return nil, errors.New("Cant seal random bytes")
	}
	err = ioutil.WriteFile(path+"delegationBlob", delegateBlob, os.ModePerm)
	if err != nil {
		return nil, err
	}
	return k, nil
}

func SigningKeyFromBlob(t tao.Tao, sealedKeyBlob []byte, certBlob []byte, delegateBlob []byte) (*tao.Keys, error) {
	k := &tao.Keys{}

	log.Printf("SigningKeyFromBlob, certBlob % x\n", certBlob)
	log.Printf("\n")
	cert, err := x509.ParseCertificate(certBlob)
	if err != nil {
		return nil, err
	}
	log.Printf("SigningKeyFromBlob: got cert\n")
	k.Cert = cert
	k.Delegation = new(tao.Attestation)
	err = proto.Unmarshal(delegateBlob, k.Delegation)
	if err != nil {
		return nil, err
	}
	log.Printf("SigningKeyFromBlob: unmarshaled\n")
	signingKeyBlob, policy, err := tao.Parent().Unseal(sealedKeyBlob)
	if err != nil {
		log.Printf("fileproxy: signingkey unsealing error: %s\n", err)
	}
	if policy != tao.SealPolicyDefault {
		log.Printf("fileproxy: unexpected policy on unseal\n")
	}
	log.Printf("fileproxy: Unsealed Signing Key blob: %x\n", signingKeyBlob)
	k.SigningKey, err = tao.UnmarshalSignerDER(signingKeyBlob)
	k.Cert = cert
	return k, err
}

func SendFile(ms *util.MessageStream, path string, filename string, keys []byte) error {
	log.Printf("SendFile %s%s\n", path, filename)
	// TODO: later read incrementally and send multiple blocks
	contents, err := ioutil.ReadFile(path + filename)
	if err != nil {
		log.Printf("SendFile error reading file %s, ", path+filename, err)
		log.Printf("\n")
		return errors.New("fileproxy: SendFile no such file")
	}
	n := len(contents)
	size := n
	log.Printf("SendFile contents % x\n", contents)
	out, err := EncodeMessage(int(MessageType_FILE_LAST), nil, nil, &filename, nil,
		nil, nil, &size, contents)
	if err != nil {
		log.Printf("SendFile cant encode message\n")
		return errors.New("transmission error")
	}
	_, _ = ms.WriteString(string(out))
	return nil
}

func GetFile(ms *util.MessageStream, path string, filename string, keys []byte) error {
	log.Printf("GetFile %s%s\n", path, filename)
	in, err := ms.ReadString()
	if err != nil {
		log.Printf("GetFile cant readstring ", err)
		log.Printf("\n")
		return errors.New("reception error")
	}
	theType, _, _, _, _, _, _, size_buf, buf,
		err := DecodeMessage([]byte(in))
	log.Printf("GetFile buffer size: %d\n", *size_buf)
	if err != nil {
		log.Printf("GetFile cant decode message ", err)
		log.Printf("\n")
		return errors.New("reception error")
	}
	if theType == nil {
		log.Printf("GetFile bad type\n")
		return errors.New("reception error")
	}
	if *theType != int(MessageType_FILE_LAST) {
		log.Printf("GetFile expecting message last\n")
		return errors.New("reception error")
	}
	log.Printf("GetFile writing %d bytes to %s\n", len(buf), path+filename)
	return ioutil.WriteFile(path+filename, buf, os.ModePerm)
}

func SendSendFile(ms *util.MessageStream, subjectCert []byte, filename string) error {
	log.Printf("SendSendFile, filename: %s\n", filename)
	subjectName := string(subjectCert)
	action := "sendfile"
	message, err := EncodeMessage(1, &subjectName, &action, &filename, nil,
		nil, nil, nil, nil)
	if err != nil {
		log.Printf("SendSendFile couldnt build request\n")
		return errors.New("SendSendFile can't build request")
	}
	log.Printf("SendSendrequest %d, ", len(message))
	log.Printf("\n")
	written, _ := ms.WriteString(string(message))
	log.Printf("Bytes written %d\n", written)
	return nil
}

func SendGetFile(ms *util.MessageStream, subjectCert []byte, filename string) error {
	log.Printf("SendGetFile, filename: %s\n", filename)
	subjectName := string(subjectCert)
	action := "getfile"
	message, err := EncodeMessage(int(MessageType_REQUEST), &subjectName, &action, &filename, nil,
		nil, nil, nil, nil)
	if err != nil {
		log.Printf("SendGetFile couldnt build request\n")
		return errors.New("SendGetFile can't build request")
	}
	log.Printf("SendGetrequest %d, ", len(message))
	log.Printf("\n")
	written, _ := ms.WriteString(string(message))
	log.Printf("Bytes written %d\n", written)
	return nil
}

func SendCreateFile(ms *util.MessageStream, subjectCert []byte, filename string) error {
	log.Printf("SendCreateFile, filename: %s\n", filename)
	subject := string(subjectCert)
	action := "create"
	message, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &filename, &subject,
		nil, nil, nil, nil)
	if err != nil {
		log.Printf("SendCreateFile couldnt build request\n")
		return errors.New("SendCreateFile can't build request")
	}
	log.Printf("SendCreateFile request %d, ", len(message))
	log.Printf("\n")
	written, _ := ms.WriteString(string(message))
	log.Printf("Bytes written %d\n", written)
	return nil
}

func SendRule(ms *util.MessageStream, rule string, signerCert []byte) error {
	log.Printf("SendRule, rule: %s\n", rule)
	subject := string(signerCert)
	action := "sendrule"
	message, err := EncodeMessage(int(MessageType_REQUEST), &subject, &action, &rule, &subject,
		nil, nil, nil, nil)
	if err != nil {
		log.Printf("SendRule couldnt build request\n")
		return errors.New("SendRule can't build request")
	}
	log.Printf("SendRule request %d, ", len(message))
	log.Printf("\n")
	written, _ := ms.WriteString(string(message))
	log.Printf("Bytes written %d\n", written)
	return nil
}

func SendDeleteFile(ms *util.MessageStream, creds []byte, filename string) error {
	return errors.New("CreateFile request not implemented")
}

func SendAddFilePermissions(ms *util.MessageStream, creds []byte, filename string) error {
	return errors.New("AddFilePermissions request not implemented")
}
