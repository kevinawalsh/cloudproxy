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

package options

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Confirm prompts the user to confirm a default value or input a different
// string.
func Confirm(msg, def string) string {
	if def == "" {
		fmt.Printf("%s: ", msg)
	} else {
		fmt.Printf("%s [%s]: ", msg, def)
	}
	line, hasMoreInLine, err := bufio.NewReader(os.Stdin).ReadLine()
	FailIf(err, "Bad input")
	if hasMoreInLine {
		Fail(nil, "Buffer overflow: Bad input")
	}
	s := strings.TrimSpace(string(line))
	if s == "" {
		s = def
	}
	return s
}

// ConfirmN prompts the user to confirm a list of default values or input a
// different list of strings.
func ConfirmN(msg string, def []string) []string {
	s := Confirm(msg, strings.Join(def, ";"))
	return strings.Split(s, ";")
}
