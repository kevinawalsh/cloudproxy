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

package tao

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/kevinawalsh/profiling"
)

// ConnAuth controls authentication and authorization options for connections.
type ConnAuth struct {
	// Authenticate controls whether local host authenticates to remote using a
	// Tao delegation. If true, keys must be provided in Dial or Listen.
	Authenticate bool

	// delegation is used by remote to authenticate local side
	delegation *Attestation

	// AuthenticatePeer controls whether local requires remote to authenticate
	// using a Tao delegation. If false, guard is ignored.
	AuthenticatePeer bool

	// guard and verifier are used by local to authenticate remote side
	guard    Guard
	verifier *Verifier
}

// A Listener implements net.Listener for Tao connections. Each time it accepts
// a connection, it exchanges Tao attestation chains and checks the attestation
// for the certificate of the client against its Guard. The guard in this
// case should be the guard of the Tao domain. This listener allows connections
// from any program that is authorized under the Tao to execute.
type Listener struct {
	// ConnAuth controls authentication and authorization options for accepted
	// connections.
	ConnAuth

	net.Listener
}

// Conn implements net.Conn but performs a Tao (and TLS) handshake before the
// first read or write.
type Conn struct {
	peer *auth.Prin

	isServer bool

	handshakeComplete bool
	handshakeErr      error

	// ConnAuth reports authentication and authorization options for this
	// connection.
	ConnAuth

	// The underlying tls connection. Use this only for querying properties. In
	// particular, don't use the read and write functions, since they don't
	// ensure the proper handshaking has been done.
	*tls.Conn

	//util.MessageFraming
	util.FramedStream

	T *profiling.Trace
}

/*
func (c *Conn) WriteString(s string) (int, error) {
	return util.WriteString(c, s)
}

func (c *Conn) ReadString() (string, error) {
	return util.ReadString(c)
}

func (c *Conn) WriteMessage(m proto.Message) (int, error) {
	return util.WriteMessage(c, m)
}

func (c *Conn) ReadMessage(m proto.Message) error {
	return util.ReadMessage(c, m)
}
*/

// Handshake performs a Tao (and TLS) handshake. This occurs only once, before
// the first read or write. Users don't usually need to call this directly,
// since other functions call this as necessary.
func (conn *Conn) Handshake() error {
	// Tao handshake protocol:
	// 0. TLS handshake (executed automatically on first message)
	// 1. Client -> Server: "delgation", Tao delegation for X.509 certificate.
	// 2. Server: checks for a Tao-authorized program.
	// 3. Server -> Client: "delgation", Tao delegation for X.509 certificate.
	// 4. Client: checks for a Tao-authorized program.
	//
	// Alternate steps 1 and 2 if client authentication is not needed:
	// 1'. Client -> Server: "anonymous"
	// 2'. Server: checks if policy allows anonymous connections
	//
	// Alternate steps 3 and 4 if server authentication is not needed:
	// 3'. Server -> Client: "anonymous"
	// 4'. Client: checks if policy allows anonymous connections
	if !conn.handshakeComplete {
		if conn.T != nil {
			conn.T.Start()
		}
		// Use a new framing stream on the underlying tls to avoid recursing.
		ms := util.NewMessageStream(conn.Conn)
		if conn.isServer {
			conn.sendCredentials(ms)
			if conn.T != nil {
				conn.T.Sample("sent tao creds")
			}
			conn.recvCredentials(ms)
		} else {
			conn.sendCredentials(ms)
			if conn.T != nil {
				conn.T.Sample("sent tao creds")
			}
			conn.recvCredentials(ms)
		}
		conn.handshakeComplete = true
		conn.handshakeErr = ms.Err()
		if conn.handshakeErr != nil {
			conn.Close()
			conn.SetErr(conn.handshakeErr)
		}
		if conn.T != nil {
			conn.T.Sample("done tao handshake")
		}
	}
	return conn.handshakeErr
}

func (conn *Conn) sendCredentials(ms util.MessageStream) {
	if conn.Authenticate && conn.delegation != nil {
		ms.WriteString("delegation")
		ms.WriteMessage(conn.delegation)
	} else if conn.Authenticate {
		ms.WriteString("key")
	} else {
		ms.WriteString("anonymous")
	}
}

func (conn *Conn) recvCredentials(ms util.MessageStream) {
	m, err := ms.ReadString()
	if err != nil {
		return
	}
	if m == "delegation" {
		var a Attestation
		if err = ms.ReadMessage(&a); err != nil {
			return
		}
		// Validate the peer certificate
		peerCert := conn.ConnectionState().PeerCertificates[0]
		p, err := ValidatePeerAttestation(&a, peerCert)
		if err != nil {
			ms.SetErr(err)
			return
		}
		if conn.guard != nil {
			if conn.verifier != nil {
				if err = AddEndorsements(conn.guard, &a, conn.verifier); err != nil {
					ms.SetErr(err)
					return
				}
			}
			if !conn.guard.IsAuthorized(p, "Connect", nil) {
				ms.SetErr(errors.New("principal delegator in client attestation is not authorized to connect"))
				return
			}
		}
		conn.peer = &p
	} else if m == "key" {
		peerCert := conn.ConnectionState().PeerCertificates[0]
		v, err := FromX509(peerCert)
		if err != nil {
			ms.SetErr(errors.New("can't decode key from peer certificate"))
			return
		}
		p := v.ToPrincipal()
		conn.peer = &p
	} else if m == "anonymous" {
		if conn.guard != nil {
			err = errors.New("peer did not provide tao delegation")
			ms.SetErr(err)
			return
		}
	} else {
		err = errors.New("unrecognized authentication handshake: " + m)
		ms.SetErr(err)
		return
	}
}

func (conn *Conn) Peer() *auth.Prin {
	if err := conn.Handshake(); err != nil {
		return nil
	}
	return conn.peer
}

func (conn *Conn) Read(b []byte) (n int, err error) {
	if err := conn.Handshake(); err != nil {
		return 0, err
	}
	return conn.Conn.Read(b)
}

func (conn *Conn) Write(b []byte) (n int, err error) {
	if err := conn.Handshake(); err != nil {
		return 0, err
	}
	return conn.Conn.Write(b)
}

// Listen returns a new Tao-based Listener that uses an underlying crypto/tls
// net.Listener to authenticate connections. If keys are not nil, then the
// server will authenticate to clients using the keys. If guard is nil, clients
// need not provide authentication. If guard is not nil, clients must
// authenticate to the server and the guard must authorize the connection. If a
// Verifier key is also provided, attestations provided by clients and signed by
// that verifier will be added to the guard rule set. If conf is nil, a tls
// configuration will be created.
func Listen(network, laddr string, keys *Keys, g Guard, v *Verifier, conf *tls.Config) (*Listener, error) {
	if conf == nil {
		var err error
		conf, err = keys.TLSServerConfig(nil)
		if err != nil {
			return nil, err
		}
	}
	var del *Attestation
	if keys != nil {
		del = keys.Delegation
	}
	l, err := tls.Listen(network, laddr, conf)
	if err != nil {
		return nil, err
	}
	return &Listener{
		Listener: l,
		ConnAuth: ConnAuth{
			Authenticate:     keys != nil,
			delegation:       del,
			AuthenticatePeer: g != nil,
			guard:            g,
			verifier:         v,
		},
	}, nil
}

// ValidatePeerAttestation checks a Attestation for a given Listener against
// an X.509 certificate from a TLS channel.
func ValidatePeerAttestation(a *Attestation, cert *x509.Certificate) (auth.Prin, error) {
	stmt, err := a.Validate()
	if err != nil {
		return auth.Prin{}, err
	}

	// Insist that the message of the statement be a SpeaksFor and that the
	// initial term be an auth.Prin of type key. Note that Validate has already
	// checked the expirations and the times and the general well-formedness of
	// the attestation.
	sf, ok := stmt.Message.(auth.Speaksfor)
	if !ok {
		return auth.Prin{}, errors.New("a peer attestation must have an auth.Speaksfor as a message")
	}

	// This key must contain the serialized X.509 certificate.
	kprin, ok := sf.Delegate.(auth.Prin)
	if !ok {
		return auth.Prin{}, errors.New("a peer attestation must have an auth.Prin as its delegate")
	}

	if kprin.Type != "key" {
		return auth.Prin{}, errors.New("a peer attestation must have an auth.Prin of type 'key' as its delegate")
	}

	if _, ok := kprin.KeyHash.(auth.Bytes); !ok {
		return auth.Prin{}, errors.New("a peer attestation must have a KeyHash of type auth.Bytes")
	}

	prin, ok := sf.Delegator.(auth.Prin)
	if !ok {
		return auth.Prin{}, errors.New("a peer attestation must have an auth.Prin as its delegator")
	}

	// The bytes of the delegate are the result of ToPrincipal on
	// Keys.SigningKey. Check that this represents the same key as the one
	// in the certificate.
	verifier, err := FromX509(cert)
	if err != nil {
		return auth.Prin{}, err
	}
	if !verifier.ToPrincipal().Identical(kprin) {
		return auth.Prin{}, errors.New("a peer attestation must have an auth.Prin.KeyHash of type auth.Bytes where the bytes match the auth.Prin hash representation of the X.509 certificate")
	}

	return prin, nil
}

// Accept waits for a connect, accepts it using the underlying Conn and checks
// the attestations and the statement. The resulting net.Conn implements
// tao.Conn, which implements util.MessageStream and embeds tls.Conn.
func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	c := &Conn{
		isServer: true,
		ConnAuth: l.ConnAuth,
		Conn:     conn.(*tls.Conn),
	}
	c.FramedStream = util.FramedStream{util.MessageFraming{}, c}
	// Handshake later so we don't block the accept loop
	return c, nil
}
