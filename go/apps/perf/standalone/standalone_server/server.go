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
	"flag"
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"
)

var host = flag.String("host", "0.0.0.0", "server host")
var port = flag.String("port", "8123", "server port")
var count = flag.Int("n", 1, "Number of trials, negative for indefinite")

func main() {
	flag.Parse()

	// listen
	addr := net.JoinHostPort(*host, *port)
	sock, err := net.Listen("tcp", addr)
	options.FailIf(err, "error listening at %s", addr)
	defer sock.Close()
	fmt.Printf("listening at %s.\n", addr)

	for i := 0; i < *count || *count < 0; i++ { // negative means forever
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
