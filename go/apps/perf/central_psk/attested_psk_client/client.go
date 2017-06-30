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
	"time"

	// "github.com/raff/tls-ext"
	// "github.com/raff/tls-psk"
	tls "github.com/mordyovits/golang-crypto-tls"

	// "github.com/davecheney/junk/clock"
	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util/options"
	"github.com/kevinawalsh/profiling"
)

var reconnect = flag.Bool("reconnect", false, "ping, then ping again, using same tls config")
var halfReconnect = flag.Bool("half_reconnect", false, "ping, then ping again, using new tls config from same ka")

var sharedKey []byte

func getIdentity(identityHint []byte) (string, error) {
	T.Sample("handshake")
	if sharedKey == nil {
		// first connection
		return "clientidFreshKey7890123456789", nil
	} else if *halfReconnect {
		// second connection, but use same ca to get new key
		return "clientidFastFreshKey123456789", nil
	} else {
		// second connection, re-use existing
		return "clientidSameKey67890123456789", nil
	}
}

func getKey(id string) ([]byte, error) {
	if sharedKey == nil {
		// obtain shared key from fresh psk ka
		sharedKey = ping.ObtainPreSharedKeyFromKA()
	} else if *halfReconnect {
		// re-obtain shared key from same psk ka
		sharedKey = ping.ObtainAnotherPreSharedKeyFromKA()
	}
	options.FailWhen(sharedKey == nil, "missing key")
	return sharedKey, nil
}

var T *profiling.Trace

func main() {
	ping.ParseFlags(true)

	T = ping.EnableTracing()

	for i := 0; i < *ping.Count || *ping.Count < 0; i++ { // negative means forever
		sharedKey = nil

		T.Start()

		// open connection
		conf := &tls.Config{
			CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
			// Certificates: []tls.Certificate{tls.Certificate{}},
			GetPSKIdentityHint: nil, // only for server
			GetPSKIdentity:     getIdentity,
			GetPSKKey:          getKey,
		}
		conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
		if *ping.ResumeTLSSessions {
			conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}
		conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
		options.FailIf(err, "connecting")
		t3 := T.Skip("srv_getkey")
		T.Sample("connect")

		// send ping, recv pong, close conn
		x, _ := ping.WriteReadClose(conn, 0, 0)
		*t3 = t3.Add(time.Duration(x))

		if *halfReconnect {

			// open connection
			conf := &tls.Config{
				CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
				// Certificates: []tls.Certificate{tls.Certificate{}},
				GetPSKIdentityHint: nil, // only for server
				GetPSKIdentity:     getIdentity,
				GetPSKKey:          getKey,
			}
			conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
			if *ping.ResumeTLSSessions {
				conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
			}
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			t3 := T.Skip("srv_getkey")
			T.Sample("connect")

			// send ping, recv pong, close conn
			x, _ := ping.WriteReadClose(conn, 0, 0)
			*t3 = t3.Add(time.Duration(x))

		} else if *reconnect {
			// re-open connection
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			t3 := T.Skip("srv_getkey")
			T.Sample("reconnect")

			// re-send ping, recv pong, close conn
			x, _ := ping.WriteReadClose(conn, 0, 0)
			*t3 = t3.Add(time.Duration(x))
		}
	}

	fmt.Println(T)
}
