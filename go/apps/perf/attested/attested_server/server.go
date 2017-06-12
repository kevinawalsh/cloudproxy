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
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"path"
	"strings"

	"github.com/jlmucb/cloudproxy/go/apps/perf/attested/guard"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

var serverHost = flag.String("host", "0.0.0.0", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")
var domainPathFlag = flag.String("tao_domain", "", "The Tao domain directory")

func doResponse(conn net.Conn, responseOk chan<- bool) {
	defer conn.Close()

	// Both the TLS and the Tao/TLS connections and listeners handle
	// authorization during the Accept operation. So, no extra authorization is
	// needed here.
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: can't read: %s\n", err)
		responseOk <- false
		return
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("server: got message: %s\n", msg)
	responseOk <- true
	fmt.Fprintf(conn, "echo(%s)\n", msg)
}

func doServer() {
	var sock net.Listener
	var err error
	var keys *tao.Keys
	network := "tcp"
	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "error: couldn't load the tao domain from %s\n", configPath())

	switch *demoAuth {
	case "tcp":
		sock, err = net.Listen(network, serverAddr)
		options.FailIf(err, "server: couldn't listen to the network")

	case "tls", "tao":
		// Generate a private/public key for this hosted program (hp) and
		// request attestation from the host of the statement "hp speaksFor
		// host". The resulting certificate, keys.Delegation, is a chain of
		// "says" statements extending to the policy key. The policy is
		// checked by the host before this program is executed.
		keys, err = tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
		options.FailIf(err, "server: failed to generate delegated keys")

		if *demoAuth == "tao" {
			g := &guard.newAttestationGuard()
			append(keys.Delegation.SerializedEndorsements, g.localSerializedTpmAttestation)
			sock, err = tao.Listen(network, serverAddr, keys, g, domain.Keys.VerifyingKey, nil)
			options.FailIf(err, "sever: couldn't create a taonet listener")
		} else {
			conf, err := keys.TLSServerConfig(nil)
			options.FailIf(err, "server: couldn't encode TLS certificate")
			sock, err = tls.Listen(network, serverAddr, conf)
			options.FailIf(err, "server: couldn't create a tls listener")
		}
	}

	fmt.Printf("server: listening at %s using %s authentication.\n", serverAddr, *demoAuth)
	defer sock.Close()

	pings := make(chan bool, 5)
	connCount := 0

	go func() {
		for connCount = 0; connCount < *pingCount || *pingCount < 0; connCount++ { // negative means forever
			conn, err := sock.Accept()
			options.FailIf(err, "server: can't accept connection")
			go doResponse(conn, pings)
		}
	}()

	pingGood := 0
	pingFail := 0

	for {
		select {
		case ok := <-pings:
			if ok {
				pingGood++
			} else {
				pingFail++
			}
		}
	}
}

func main() {
	flag.Parse()
	serverAddr = net.JoinHostPort(*serverHost, *serverPort)
	switch *demoAuth {
	case "tcp", "tls", "tao":
	default:
		options.Usage("unrecognized authentication mode: %s\n", *demoAuth)
		return
	}

	fmt.Println("Go Tao Demo Server")

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: No host Tao available")
	}

	doServer()
	fmt.Println("Server Done")
}

func domainPath() string {
	if *domainPathFlag != "" {
		return *domainPathFlag
	}
	if path := os.Getenv("TAO_DOMAIN"); path != "" {
		return path
	}
	options.Usage("Must supply -tao_domain or set $TAO_DOMAIN")
	return ""
}

func configPath() string {
	return path.Join(domainPath(), "tao.config")
}
