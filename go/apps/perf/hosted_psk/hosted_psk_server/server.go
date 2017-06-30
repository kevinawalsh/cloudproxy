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
	"time"

	// "github.com/raff/tls-ext"
	// "github.com/raff/tls-psk"
	tls "github.com/mordyovits/golang-crypto-tls"

	// "github.com/davecheney/junk/clock"
	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/profiling"
)

// var tHandshake time.Time

func getIdentityHint() ([]byte, error) {
	// tHandshake = clock.Monotonic.Now()
	return []byte("hint5678901234567890123456789"), nil
	// return nil, nil
}

var sharedKey []byte

// var durationGetKey time.Duration

// var durationHandshake time.Duration

var T *profiling.Trace

func getKey(id string) ([]byte, error) {
	T.N = 0
	T.Repeats = 0
	T.Start()
	//	tStart := clock.Monotonic.Now()
	// durationHandshake = tStart.Sub(tHandshake)
	if id == "clientidFreshKey7890123456789" {
		sharedKey = ping.GetLocalTaoSharedSecret()
	} else if id == "clientidSameKey67890123456789" {
		options.FailWhen(sharedKey == nil, "no shared key yet")
	} else {
		options.Fail(nil, "no such shared key")
	}
	//	tEnd := clock.Monotonic.Now()
	//	durationGetKey = tEnd.Sub(tStart)
	return sharedKey, nil
}

func main() {
	ping.ParseFlags(true)
	T = ping.EnableTracing()

	conf := &tls.Config{
		CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
		// Certificates:   []tls.Certificate{tls.Certificate{}},
		GetPSKIdentityHint: getIdentityHint,
		GetPSKIdentity:     nil, // only for client
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
		// ping.ReadWriteClose(conn, func() (int64, int64) { return int64(durationGetKey), 0 })
		ping.ReadWriteClose(conn, func() (int64, int64, int64) {
			// fmt.Printf("Trace has %d samples, %d columns, %d repeats\n", T.N, T.Points, T.Repeats)
			var w, x time.Time
			if T.N == 2 {
				w = T.Samples[T.N-2]
				x = T.Samples[T.N-1]
			}
			return int64(x.Sub(w)), 0, 0
		})
	}
}
