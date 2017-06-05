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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	// "crypto/tls"
	"flag"
	"fmt"
	"net"

	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/jlmucb/cloudproxy/go/util/verbose"

	"github.com/kevinawalsh/profiling"
)

var host = flag.String("host", "localhost", "server host")
var port = flag.String("port", "8123", "server port")
var count = flag.Int("n", 1, "Number of trials")

func main() {
	flag.Parse()

	T := profiling.NewTrace(3, *count)

	for i := 0; i < *count; i++ {

		T.Start()

		// generate ecdsa key pair
		// ec
		_, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		options.FailIf(err, "can't generate key pair")
		T.Sample("genkey")

		// generate self-signed certificate

		// open tls connection
		addr := net.JoinHostPort(*host, *port)
		conn, err := net.Dial("tcp", addr)
		options.FailIf(err, "error connecting to %s", addr)
		defer conn.Close()
		T.Sample("connect")

		// send ping
		buf := []byte{1}
		_, err = conn.Write(buf)
		options.FailIf(err, "can't write")

		// recv pong
		_, err = conn.Read(buf)
		options.FailIf(err, "can't read")
		options.FailWhen(buf[0] != 2, "bad pong: %d\n", buf[0])
		T.Sample("rtt")

		// close tls connection
		err = conn.Close()
		options.FailIf(err, "can't close")

		verbose.Printf("done one\n")
	}

	fmt.Println(T)
}
