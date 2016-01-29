// Copyright (c) 2014, Google Inc. All rights reserved.
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

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao"
)

var network = flag.String("network", "tcp", "The network to use for connections")
var addr = flag.String("addr", "localhost:8124", "The address to listen on")
var domainPass = flag.String("password", "BogusPass", "The domain password for the policy key")
var configPath = flag.String("config", "tao.config", "The Tao domain config")

func main() {
	flag.Parse()
	domain, err := tao.LoadDomain(*configPath, []byte(*domainPass))
	if err != nil {
		glog.Exitf("Couldn't load the config path %s: %s\n", *configPath, err)
		return
	}

	sock, err := net.Listen(*network, *addr)
	if err != nil {
		glog.Exit("Couldn't bind socket to address:", err)
		return
	}

	fmt.Println("tcca: accepting connections")
	for {
		conn, err := sock.Accept()
		if err != nil {
			glog.Exitf("Couldn't accept a connection on %s: %s", *addr, err)
			return
		}

		go tao.HandleCARequest(conn, domain.Keys.SigningKey, domain.Guard)
	}
}
