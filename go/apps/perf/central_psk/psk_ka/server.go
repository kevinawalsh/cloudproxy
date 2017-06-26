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

// psk_ka acts as simple tao-based key server to provide PSK secrets to
// a specific list of principals
//
// Requests:
//   Peer group
// Responses:
//   OK PSK

package main

import (
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/apps/perf/attested/guard"
	psk "github.com/jlmucb/cloudproxy/go/apps/perf/central_psk"
	"github.com/jlmucb/cloudproxy/go/apps/perf/ping"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
	"github.com/jlmucb/cloudproxy/go/util/options"
)

func main() {
	ping.ParseFlags(true)

	keys, err := tao.NewTemporaryKeys(tao.Deriving)
	options.FailIf(err, "generating keys")

	sock := ping.AttestedListen(ping.AppKAAddr)

	for {
		conn, err := sock.Accept()
		options.FailIf(err, "accepting connection")
		peer := conn.(*tao.Conn).Peer()
		tpm := sock.Guard.(*guard.AttestationGuard).PeerTpm
		HandleKGR(keys, util.NewMessageStream(conn), &tpm, peer)
	}
}

func HandleKGR(keys *tao.Keys, conn util.MessageStream, tpm, peer *auth.Prin) {
	defer conn.Close()
	var req psk.KGRequest
	if err := conn.ReadMessage(&req); err != nil {
		doError(conn, err, "failed to read request")
		return
	}
	// todo: ensure peer is part of req.PeerGroup
	f, err := auth.UnmarshalTerm(req.PeerGroup)
	// fmt.Printf("peer group is %v\n", f)
	if err != nil {
		doError(conn, err, "failed to unmarshal peergroup term")
		return
	}
	peerGroup, ok := f.(auth.PrinTail)
	if !ok {
		doError(conn, nil, "failed to unmarshal peergroup tail")
		return
	}
	if len(peerGroup.Ext) != 1 || peerGroup.Ext[0].Name != "PeeredWith" {
		doError(conn, nil, "failed to unmarshal peergroup ext")
		return
	}
	member := false
	for _, a := range peerGroup.Ext[0].Arg {
		tail, ok := a.(auth.PrinTail)
		if !ok {
			continue
		}
		prin := tpm.MakeSubprincipal(tail.Ext).MakeSubprincipal(peerGroup.Ext)
		if prin.Identical(peer) {
			member = true
			break
		}
	}
	if !member {
		doError(conn, nil, "denied")
		return
	}
	salt := append(append(req.PeerGroup, []byte("||")...), ping.Domain.Keys.VerifyingKey.MarshalKey()...)

	var material [40]byte
	err = keys.DerivingKey.Derive(salt, []byte("central psk"), material[:])
	if err != nil {
		doError(conn, nil, "failed to derive key")
		return
	}

	resp := &psk.KGResponse{
		KeyMaterial: material[:],
	}
	sendResponse(conn, resp)
}

func doError(ms util.MessageStream, err error, detail string) {
	if err != nil {
		fmt.Printf("error handling request: %s\n", err)
	}
	fmt.Printf("sending error response: detail=%q\n", detail)
	resp := &psk.KGResponse{
		ErrorDetail: proto.String(detail),
	}
	sendResponse(ms, resp)
}

func sendResponse(ms util.MessageStream, resp *psk.KGResponse) {
	_, err := ms.WriteMessage(resp)
	if err != nil {
		fmt.Printf("error writing response: %s\n", err)
	}
}
