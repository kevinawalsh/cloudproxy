// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
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

package tao

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"time"
)

func (pool CertificatePool) certForIssuer(cert *x509.Certificate) *x509.Certificate {
	s := string(cert.RawIssuer)
	if string(cert.RawSubject) == s {
		if err := cert.CheckSignatureFrom(cert); err == nil {
			return cert
		}
	}
	for _, other := range pool.Cert {
		if string(other.RawSubject) == s {
			if err := cert.CheckSignatureFrom(other); err == nil {
				return other
			}
		}
	}
	return nil
}

func (pool CertificatePool) CertChain(name string) []*x509.Certificate {
	// TODO(kwalsh) use system or std lib to construct a chain
	// This code assumes there is a single chain upwards towards a root,
	// but there is no need to actually reach a root to be considered ok.
	var certs []*x509.Certificate
	cert := pool.Cert[name]
	if cert == nil {
		return nil
	}
	certs = append(certs, cert)
	parent := pool.certForIssuer(cert)
	for parent != nil && parent != cert {
		cert = parent
		certs = append(certs, cert)
		parent = pool.certForIssuer(cert)
	}
	return certs
}

// TLSCert combines a signing key and a certificate in a single tls
// certificate suitable for a TLS config.
func (keys *Keys) TLSCert() (*tls.Certificate, error) {
	certs := keys.CertChain("default")
	if len(certs) == 0 {
		return nil, fmt.Errorf("can't use TLS without a certificate")
	}
	var certPem []byte
	for _, cert := range certs {
		s := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
		certPem = append(certPem, s...)
	}
	keyBytes, err := MarshalSignerDER(keys.SigningKey)
	if err != nil {
		return nil, err
	}
	keyPem := pem.EncodeToMemory(&pem.Block{Type: "ECDSA PRIVATE KEY", Bytes: keyBytes})

	tlsCert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		return nil, fmt.Errorf("can't parse cert: %s", err.Error())
	}
	return &tlsCert, nil
}

// TLSServerConfig creates a tls server configuration using the signing key and
// its cert. If ca is not nil, then a client cert will be required and verified
// against that ca. Otherwise a client cert will be requested but not verified.
func (keys *Keys) TLSServerConfig(ca *x509.Certificate, protos ...string) (*tls.Config, error) {
	cert, err := keys.TLSCert()
	if err != nil {
		return nil, err
	}
	conf := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		ClientCAs:    x509.NewCertPool(),
		ClientAuth:   tls.RequestClientCert,
		NextProtos:   protos,
	}
	if ca != nil {
		conf.ClientCAs.AddCert(ca)
		conf.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return conf, nil
}

// TLSClientConfig creates a tls client configuration using the signing key and
// its cert. The keys may be nil, in which case the client will not authenticate
// to the server. If ca is not nil, then the server cert will be verified
// against that ca. otherwise, the server cert will not be verified at all.
func (keys *Keys) TLSClientConfig(ca *x509.Certificate) (*tls.Config, error) {
	conf := &tls.Config{
		RootCAs:            x509.NewCertPool(),
		InsecureSkipVerify: ca == nil,
	}
	if keys != nil {
		cert, err := keys.TLSCert()
		if err != nil {
			return nil, err
		}
		conf.Certificates = append(conf.Certificates, *cert)
	}
	if ca != nil {
		conf.RootCAs.AddCert(ca)
	}
	return conf, nil
}

// ListenAndServeTLS acts like http.ListenAndServeTLS, except that it takes an
// in-memory key and its parsed x509 cert, rather than key and cert files.
func ListenAndServeTLS(addr string, key *Keys) error {
	conf, err := key.TLSServerConfig(nil, "http/1.1")
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: addr, Handler: nil, TLSConfig: conf}
	tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, conf)
	return srv.Serve(tlsListener)
}

// tcpKeepAliveListener sets TCP keep-alive timeouts on accepted connections.
// It's used by ListenAndServeTLS so dead TCP connections (e.g. closing laptop
// mid-download) eventually go away.
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	tc.SetKeepAlive(true)
	tc.SetKeepAlivePeriod(3 * time.Minute)
	return tc, nil
}
