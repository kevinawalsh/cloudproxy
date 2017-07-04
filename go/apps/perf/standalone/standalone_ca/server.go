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

// standalone_ca acts as very simple CA to provide HTTPS/x509 certificates to
// any principal that asks for one.
//
// Requests:
//   CSR <name, is_ca, expiration, etc.>
//   Signature
// Responses:
//   OK <x509cert>
//   ERROR <msg>

package main

import (
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

func main() {
	ping.ParseFlags(false)

	ping.InitCA()

	sock, err := net.Listen("tcp", ping.StandaloneAppCAAddr)
	options.FailIf(err, "listening")
	defer sock.Close()
	fmt.Printf("Listening at %s using unauthenticated TCP channels\n", ping.StandaloneAppCAAddr)

	for i := 0; i < *ping.Count || *ping.Count < 0; i++ { // negative means forever
		conn, err := sock.Accept()
		options.FailIf(err, "accepting connection")
		ip := conn.RemoteAddr().String()
		ping.HandleCSR(util.NewMessageStream(conn), ip)
	}
}
