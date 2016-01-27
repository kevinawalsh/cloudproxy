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

// Package verbose provides print functions which can be disabled using a -quiet
// flag or enabled using a -verbose flag. By default, the print functions are
// disabled.
package verbose

import (
	"fmt"
	"io/ioutil"
	"os"
	"strconv"

	"github.com/jlmucb/cloudproxy/go/util/options"
)

// Out is set to ioutil.Discard or os.Stdout as appropriate.
var Out = ioutil.Discard

// Enabled is set by flag -verbose, and it is unset by flag -quiet.
var Enabled = false

// Set controls whether output is enabled or disabled.
func Set(verbose bool) {
	Enabled = verbose
	if Enabled {
		Out = os.Stdout
	} else {
		Out = ioutil.Discard
	}
}

type qflag bool

func (f qflag) String() string {
	return strconv.FormatBool(bool(f) == Enabled)
}

func (f qflag) IsBoolFlag() bool {
	return true
}

func (f qflag) Set(s string) error {
	b, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	Set(bool(f) == b)
	return nil
}

func init() {
	q := options.Option{"quiet", qflag(false), "", "Be more quiet", "all"}
	v := options.Option{"verbose", qflag(true), "", "Be more verbose", "all"}
	options.Add(q, v)
}

func Print(a ...interface{}) (n int, err error) {
	return fmt.Fprint(Out, a...)
}

func Printf(format string, a ...interface{}) (n int, err error) {
	return fmt.Fprintf(Out, format, a...)
}

func Println(a ...interface{}) (n int, err error) {
	return fmt.Fprintln(Out, a...)
}
