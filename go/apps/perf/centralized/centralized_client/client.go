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
	"crypto/tls"
	"flag"
	"fmt"

	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

var reconnect = flag.Bool("reconnect", false, "ping, then ping again, using new tls config from fresh ca")
var halfReconnect = flag.Bool("half_reconnect", false, "ping, then ping again, using new tls config from same ca")

func main() {
	ping.ParseFlags(true)

	T := ping.EnableTracing()

	for i := 0; i < *ping.Count || *ping.Count < 0; i++ { // negative means forever
		T.Start()

		// generate keys
		keys := ping.GenerateKeysAndCertifyWithAppCA(ping.CertName)

		// open connection
		conf, err := keys.TLSClientConfig(keys.Cert["approot"])
		options.FailIf(err, "tls config")
		conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
		if *ping.ResumeTLSSessions {
			conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
		}
		conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
		options.FailIf(err, "connecting")
		T.Sample("connect")

		// send ping, recv pong, close conn
		ping.WriteReadClose(conn, 0, 0)

		if *halfReconnect {
			// generate keys
			keys = ping.GenerateKeysAndRecertifyWithAppCA(ping.CertName)

			// open connection
			conf, err := keys.TLSClientConfig(keys.Cert["approot"])
			options.FailIf(err, "tls config")
			conf.SessionTicketsDisabled = !*ping.ResumeTLSSessions
			if *ping.ResumeTLSSessions {
				conf.ClientSessionCache = tls.NewLRUClientSessionCache(0)
			}
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			T.Sample("reconnect")

			// send ping, recv pong, close conn
			ping.WriteReadClose(conn, 0, 0)
		} else if *reconnect {
			// open connection
			conn, err := tls.Dial("tcp", ping.ServerAddr, conf)
			options.FailIf(err, "connecting")
			T.Sample("reconnect")

			// send ping, recv pong, close conn
			ping.WriteReadClose(conn, 0, 0)
		}
	}

	fmt.Println(T)
}
