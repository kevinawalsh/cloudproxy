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
	"fmt"
	"net"
	"time"

	// "github.com/jlmucb/cloudproxy/go/util/verbose"
)

// ConnHandler serves a single connection.
type ConnHandler interface {
	ServeConn(conn *Conn)
	Logf(msg string, arg ...interface{})
}

type ConnHandlerFunc func(conn *Conn)

func (f ConnHandlerFunc) ServeConn(conn *Conn) {
	f(conn)
}

func (f ConnHandlerFunc) Logf(msg string, arg ...interface{}) {
	// verbose.Printf(msg, arg...)
	fmt.Printf(msg, arg...)
}

type Server struct {
	Handler  ConnHandler
	Guard    Guard
	Verifier *Verifier
	Keys     *Keys
}

func (srv *Server) Logf(msg string, arg ...interface{}) {
	srv.Handler.Logf(msg, arg)
}

func NewOpenServer(handler ConnHandler) *Server {
	return &Server{Handler: handler}
}

func NewProtectedServer(handler ConnHandler, g Guard, v *Verifier) *Server {
	return &Server{Handler: handler, Guard: g, Verifier: v}
}

// ListenAndServe accepts connections, optionally authenticates the peer,
// optionally performs a check for authorization to connect, then invokes a
// handler for the connection. The server will authenticate to clients using the
// server's keys. If those are nil and a host Tao is available, temporary keys
// will be used instead.
func (srv *Server) ListenAndServe(addr string) error {
	var sock net.Listener
	var err error

	var keys *Keys
	if srv.Keys != nil {
		keys = srv.Keys
	} else if Parent() != nil {
		keys, err = NewTemporaryTaoDelegatedKeys(Signing, nil, Parent())
		if err != nil {
			return err
		}
	}

	srv.Logf("server: listening at %s using tao authentication.\n", addr)
	sock, err = Listen("tcp", addr, keys, srv.Guard, srv.Verifier, nil)
	if err != nil {
		return err
	}
	defer sock.Close()

	// The following is mostly from go's net/http/server.go
	var tempDelay time.Duration // how long to sleep on accept failure
	for {
		conn, e := sock.Accept()
		if e != nil {
			if ne, ok := e.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				srv.Logf("server: accept error: %v; retrying in %v", e, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return e
		}
		tempDelay = 0
		go srv.Handler.ServeConn(conn.(*Conn))
	}
	srv.Logf("server: done")
	return nil
}
