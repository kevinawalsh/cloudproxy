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

	// "github.com/raff/tls-ext"
	// "github.com/raff/tls-psk"
	tls "github.com/mordyovits/golang-crypto-tls"

	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

var reconnect = flag.Bool("reconnect", false, "ping, then ping again, using same tls config")
var halfReconnect = flag.Bool("half_reconnect", false, "ping, then ping again, using new tls config from same ka")

func getIdentityHint() ([]byte, error) {
	return []byte("hint5678901234567890123456789"), nil
}

func getIdentity(identityHint []byte) (string, error) {
	return "clientid901234567890123456789", nil
}

var sharedKey []byte

func getKey(id string) ([]byte, error) {
	return sharedKey, nil
}

func main() {
	ping.ParseFlags(true)

	T := ping.EnableTracing()

	for i := 0; i < *ping.Count || *ping.Count < 0; i++ { // negative means forever
		T.Start()

		// obtain shared key from psk ka
		sharedKey = ping.ObtainPreSharedKeyFromKA()

		// open connection
		conf := &tls.Config{
			CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
			// Certificates: []tls.Certificate{tls.Certificate{}},
			GetPSKIdentityHint: getIdentityHint,
			GetPSKIdentity:     getIdentity,
			GetPSKKey:          getKey,
		}
		conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
		if *ping.ResumeTLSSessions {
			conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}
		conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
		options.FailIf(err, "connecting")
		T.Sample("connect")

		// send ping, recv pong, close conn
		ping.WriteReadClose(conn)

		if *halfReconnect {
			// obtain shared key from psk ka
			sharedKey = ping.ObtainAnotherPreSharedKeyFromKA()

			// open connection
			conf := &tls.Config{
				CipherSuites: []uint16{tls.TLS_PSK_WITH_AES_128_GCM_SHA256},
				// Certificates: []tls.Certificate{tls.Certificate{}},
				GetPSKIdentityHint: getIdentityHint,
				GetPSKIdentity:     getIdentity,
				GetPSKKey:          getKey,
			}
			conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
			if *ping.ResumeTLSSessions {
				conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
			}
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			T.Sample("connect")

			// send ping, recv pong, close conn
			ping.WriteReadClose(conn)

		} else if *reconnect {
			// re-open connection
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			T.Sample("reconnect")

			// re-send ping, recv pong, close conn
			ping.WriteReadClose(conn)
		}
	}

	fmt.Println(T)
}
