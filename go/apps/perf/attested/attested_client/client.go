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

var serverHost = flag.String("host", "localhost", "address for client/server")
var serverPort = flag.String("port", "8123", "port for client/server")
var serverAddr string // see main()
var pingCount = flag.Int("n", 5, "Number of client/server pings")
var demoAuth = flag.String("auth", "tao", "\"tcp\", \"tls\", or \"tao\"")
var domainPathFlag = flag.String("tao_domain", "", "The Tao domain directory")
var showName = flag.Bool("show_name", false, "Show local principal name instead of running test")
var showSubprin = flag.Bool("show_subprin", false, "Show only local subprincipal extension name")

func doRequest(domain *tao.Domain, keys *tao.Keys) bool {
	fmt.Printf("client: connecting to %s using %s authentication.\n", serverAddr, *demoAuth)
	var conn net.Conn
	var err error
	network := "tcp"

	switch *demoAuth {
	case "tcp":
		conn, err = net.Dial(network, serverAddr)
	case "tls":
		conf, err := keys.TLSClientConfig(nil)
		options.FailIf(err, "client: couldn't encode TLS keys")
		conn, err = tls.Dial(network, serverAddr, conf)
	case "tao":
		g := guard.NewAttestationGuard()
		keys.Delegation.SerializedEndorsements = append(keys.Delegation.SerializedEndorsements, g.LocalSerializedTpmAttestation)
		conn, err = tao.Dial(network, serverAddr, g, domain.Keys.VerifyingKey, keys, nil)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: error connecting to %s: %s\n", serverAddr, err.Error())
		return false
	}
	defer conn.Close()

	_, err = fmt.Fprintf(conn, "Hello\n")
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: can't write: %s\n", err.Error())
		return false
	}
	msg, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "client: can't read: %s\n", err.Error())
		return false
	}
	msg = strings.TrimSpace(msg)
	fmt.Printf("client: got reply: %s\n", msg)
	return true
}

func doClient(domain *tao.Domain) {
	keys, err := tao.NewTemporaryTaoDelegatedKeys(tao.Signing, nil, tao.Parent())
	options.FailIf(err, "client: couldn't generate temporary Tao keys")

	pingGood := 0
	pingFail := 0
	for i := 0; i < *pingCount || *pingCount < 0; i++ { // negative means forever
		if doRequest(domain, keys) {
			pingGood++
		} else {
			pingFail++
		}
		fmt.Printf("client: made %d connections, finished %d ok, %d bad pings\n", i+1, pingGood, pingFail)
	}
}

func main() {
	flag.Parse()

	// Check to see if we are running in Docker mode with linked containers.
	// If so, then there will be an environment variable SERVER_PORT that
	// will contain a value of the form tcp://<ip>:<port>
	serverEnvVar := os.Getenv("SERVER_PORT")
	if serverEnvVar == "" {
		serverAddr = net.JoinHostPort(*serverHost, *serverPort)
	} else {
		serverAddr = strings.TrimPrefix(serverEnvVar, "tcp://")
		if serverAddr == serverEnvVar {
			options.Usage("client: invalid SERVER_PORT environment variable value '%s'\n", serverEnvVar)
		}
	}

	switch *demoAuth {
	case "tcp", "tls", "tao":
	default:
		options.Usage("unrecognized authentication mode: %s\n", *demoAuth)
	}

	if tao.Parent() == nil {
		options.Fail(nil, "can't continue: No host Tao available")
	}

	if *showName || *showSubprin {
		name, err := tao.Parent().GetTaoName()
		options.FailIf(err, "can't get name")
		if *showName {
			fmt.Printf("%s\n", name)
		} else {
			ext := name.Ext[1:]
			fmt.Printf("%s\n", ext)
		}
		return
	}

	fmt.Println("Go Tao Demo Client")

	domain, err := tao.LoadDomain(configPath(), nil)
	options.FailIf(err, "error: couldn't load the tao domain from %s\n", configPath())

	doClient(domain)
	fmt.Println("Client Done")
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
