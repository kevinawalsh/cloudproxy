// Copyright (c) 2015, Kevin Walsh.  All rights reserved.
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

package tao

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"path"
	"sort"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/util"
)

// A manifest is a template for a human-readable version of a principal name.
// For example, the tpm manifest would change principal
// tpm(...).Program(...).Sub(...)
// Linux Host with TPM-based root of trust:
//   TPM Public Key:
//     Algorithm: RSA
//     Key: (2048 bits)
//      ...
//   TPM PCR Values:
//     PCR[17]: ...
//     PCR[17]: ...
// Linux Host, stacked:
//   Domain Policy Public Key:
//     Algorithm: ECDSA
//     Key: (256 bits)
//       ...
// Linux Process:
//   Process ID: unspecified
//   Program Hash: ....
//   Unverified Details:
//     Program Path: /home/kwalsh/src/go/bin/https_ca_server
// HTTPS Certificate Authority Configuration:
//   Port: 8143
//   Policy Hash: ...
//   Policy Type: datalog
//   Datalog Rules:
//     ...
//
// Some of this info can be extracted from the principal names, but typically
// principal names include only hashes in order to keep the principal names
// short. To get back the original information, there needs to be a mechanisms
// to invert the hashes. Some options:
// * Carry complete auxiliary info along with the principal names. This defeats
//   the purpose of having short principal names. We don't want the full binary
//   contents of a program being stored, for example.
// * Carry partial auxiliary info along with the principal names, then later
//   try to reconstruct the full info on a best-effort basis.
// * Invent a protocol for hosted programs to get manifests from their Tao
//   parent or other hosted programs.
// * Build an online hash inversion service. Auxiliary data can be published
//   when the names are first created, then stored with best-effort. Later
//   when formatting names we can look up these details, and verify signatures
//   to make sure the auxiliary data is valid.
// The last option is what is implemented here.

// Manifest holds info about a principal, encoded as a key:value map, where the
// keys are strings and the values can be strings, byte sequences, integers,
// principals, and other auth.Term values. Since we need to sign these, and
// since we might want do use them for auth, etc., we encode the key:value pairs
// as auth predicates. For example:
//   Manfest(prin, "file path", "/usr/bin/http_server")
//   Manfest(prin, "prog hash", [01345...])
//   Manfest(prin, "prog hash", [abcd013456...])
//   Manfest(prin, "prog id", 42)
//   Manfest(prin, "prog id", 42)
//   Manfest(prin, "compiler info", "name", "gcc")
//   Manfest(prin, "compiler info", "version", "4.8.4-2 (ubuntu)")
type Manifest map[string]interface{}

// type Str auth.Str
// type Bytes auth.Bytes
// type Int auth.Int

// type Str string
// type Bytes []byte
// type Int int

// type Hash []byte
// type Bits struct {
//  	N     int
//  	Value []byte
// }

func (m Manifest) Formula(p *auth.Prin, prefix ...string) auth.Form {
	if len(m) == 0 {
		return nil
	}
	keys := m.Keys()
	f := make([]auth.Form, len(keys))
	for i := 0; i < len(keys); i++ {
		k := keys[i]
		v := m[k]
		f[i] = formula(v, p, k, prefix...)
	}
	if len(f) == 1 {
		return f[0]
	} else {
		return &auth.And{f}
	}
}

func formula(v interface{}, p *auth.Prin, key string, prefix ...string) auth.Form {
	if m, ok := v.(Manifest); ok {
		return m.Formula(p, append([]string{key}, prefix...)...)
	}
	var args []interface{}
	// Manifest(p, prefix1, prefix2, prefix3, ..., key, v)
	args = append(args, p)
	for _, s := range prefix {
		args = append(args, s)
	}
	args = append(args, key)
	args = append(args, v)
	return auth.MakePredicate("Manifest", args...)
}

func (m Manifest) Keys() []string {
	keys := make([]string, len(m))
	i := 0
	for k := range m {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	return keys
}

var Directory = "/etc/tao/manifests"

var ecdsaCurveName = map[elliptic.Curve]string{
	elliptic.P224(): "P-224",
	elliptic.P256(): "P-256",
	elliptic.P384(): "P-384",
	elliptic.P521(): "P-521",
}

// Derive returns a manifest for a principal based on previously published info
// and/or the principal name itself.
func DeriveManifest(p *auth.Prin) Manifest {
	m := Manifest{}
	parent := p.Parent()
	if parent == nil {
		if p.Type == "tpm" {

			pcr := Manifest{}
			nums, vals, err := ExtractPCRs(*p)
			if err != nil {
				pcr["Status"] = "Unknown"
			} else {
				for i := 0; i < len(nums) && i < len(vals); i++ {
					pcr[fmt.Sprintf("PCR %d", nums[i])] = vals[i]
				}
			}

			aik := Manifest{}
			k, err := ExtractAIK(*p)
			if err != nil {
				aik["Status"] = "Unknown"
			} else {
				aik["Type"] = "RSA"
				aik["Size"] = k.N.BitLen()
				aik["Exponent"] = k.E
				aik["Modulus"] = k.N.Bytes()
			}
			m["Type"] = "Trusted Platform Module"
			m["TPM"] = Manifest{
				"Platform Configuration Registers": pcr,
				"Public Attestation Identity Key":  aik,
			}

		} else if p.Type == "key" {
			key := Manifest{}
			v, err := FromPrincipal(*p)
			if err != nil {
				key["Status"] = "Unknown"
			} else {
				switch v := v.PublicKey().(type) {
				case *ecdsa.PublicKey:
					key["Algorithm"] = "ECDSA"
					key["Curve"] = ecdsaCurveName[v.Curve]
					key["X"] = v.X.Bytes()
					key["Y"] = v.Y.Bytes()
				}
			}
			m["Type"] = "Public Key Principal"
			m["Key"] = key
		} else {
			m["Type"] = "Unrecognized"
		}
		return m
	} else {
		m["Subprincipal Extension"] = p.Ext.String()
	}
	for _, f := range filenames(p) {
		b, err := ioutil.ReadFile(f)
		// TODO(kwalsh) reap expired and malformed files
		if err != nil {
			continue
		}
		var a Attestation
		if err = proto.Unmarshal(b, &a); err != nil {
			glog.Errorf("Ignoring malformed manifest %s\n", f)
			continue
		}
		says, err := a.Validate()
		if err != nil {
			glog.Errorf("Ignoring invalid manifest %s\n", f)
			continue
		}
		if !says.Speaker.Identical(parent) {
			glog.Errorf("Ignoring misplaced manifest %s\n", f)
			continue
		}
		if !says.Active(time.Now().UnixNano()) {
			glog.Errorf("Ignoring expired manifest %s\n", f)
			continue
		}
		m.Extend(p, says.Message)
	}
	m["Parent"] = DeriveManifest(parent)
	return m
}

func (m Manifest) Extend(p *auth.Prin, stmt auth.Form) {
	switch stmt := stmt.(type) {
	case auth.And:
		for _, f := range stmt.Conjunct {
			m.Extend(p, f)
		}
	case auth.Pred:
		if stmt.Name != "Manifest" || len(stmt.Arg) < 3 {
			return
		}
		if !p.Identical(stmt.Arg[0]) {
			return
		}
		s, ok := stmt.Arg[1].(auth.Str)
		if !ok {
			glog.Errorf("Ignoring manifest key of non-string type %T\n", stmt.Arg[1])
			return
		}
		for i := 2; i < len(stmt.Arg)-1; i++ {
			if m[string(s)] == nil {
				m2 := Manifest{}
				m, m[string(s)] = m2, m2
			} else {
				m2, ok := m[string(s)].(Manifest)
				if !ok {
					// Name clash with existing key, ignore new data.
					return
				}
				m = m2
			}
			s, ok = stmt.Arg[i].(auth.Str)
			if !ok {
				glog.Errorf("Ignoring manifest key of non-string type %T\n", stmt.Arg[i])
				return
			}
		}
		m[string(s)] = stmt.Arg[len(stmt.Arg)-1]
	}
}

func filenames(p *auth.Prin) []string {
	hash := fmt.Sprintf("%02x", sha256.Sum256([]byte(p.String())))
	dir := path.Join(Directory, hash)
	fi, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil
	}
	var names []string
	for _, f := range fi {
		if f.IsDir() {
			continue
		}
		names = append(names, path.Join(dir, f.Name()))
	}
	return names
}

// Publish signs and caches a manifest about a child for later use by Derive.
func (m Manifest) Publish(h Host, childSubprin auth.SubPrin) error {
	self := h.HostName()
	child := self.MakeSubprincipal(childSubprin)
	stmt := auth.Says{
		Speaker: &self,
		Message: m.Formula(&child),
	}
	a, err := h.Say(stmt)
	if err != nil {
		return err
	}
	buf, err := proto.Marshal(a)
	if err != nil {
		return err
	}
	hash := fmt.Sprintf("%02x", sha256.Sum256([]byte(child.String())))
	b := make([]byte, 10)
	rand.Read(b) // ignore errors
	f := path.Join(Directory, fmt.Sprintf("%s/%02x", hash, b))
	return util.WritePath(f, buf, 0755, 0644)
}
