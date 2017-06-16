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
	"fmt"

	// "github.com/raff/tls-ext"
	// "github.com/raff/tls-psk"
	tls "github.com/mordyovits/golang-crypto-tls"

	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

func getIdentityHint() ([]byte, error) {
	return []byte("hint5678901234567890123456789"), nil
	// return nil, nil
}

func getIdentity(identityHint []byte) (string, error) {
	return "clientid901234567890123456789", nil
}

// hard-coded pre-shared key
var sharedKey = []byte{0x6c, 0x56, 0x2e, 0x2e, 0xbc, 0xe0, 0x66, 0xad, 0x75, 0x2b, 0x75, 0x17, 0x9c, 0x51, 0x3b, 0x7a, 0xb8, 0x67, 0x5a, 0x7b, 0x5d, 0x94, 0xb2, 0x0d, 0x3a, 0x36, 0xcb, 0xb6, 0xbb, 0x60}

func getKey(id string) ([]byte, error) {
	return sharedKey, nil
}

func main() {
	ping.ParseFlags(false)

	conf := &tls.Config{
		CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		// Certificates:   []tls.Certificate{tls.Certificate{}},
		GetPSKIdentityHint: getIdentityHint,
		GetPSKIdentity:     getIdentity,
		GetPSKKey:          getKey,
	}

	// listen
	conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
	sock, err := tls.Listen("tcp", ping.ServerAddr, conf)
	options.FailIf(err, "listening")
	fmt.Printf("Listening at %s using TLS-PSK.\n", ping.ServerAddr)
	defer sock.Close()

	for i := 0; i < *ping.Count || *ping.Count < 0; i++ { // negative means forever
		// accept connection
		conn, err := sock.Accept()
		options.FailIf(err, "accepting connection")

		// recv ping, send pong, close conn
		ping.ReadWriteClose(conn)
	}
}
