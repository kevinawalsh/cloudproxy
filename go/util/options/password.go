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
	"fmt"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

func Password(prompt, name string) []byte {
	if input := *String[name]; input != "" {
		fmt.Fprintf(os.Stderr, "Warning: Passwords on the command line are not secure. Use -%s option only for testing.\n", name)
		return []byte(input)
	} else {
		// Get the password from the user.
		fmt.Print(prompt + ": ")
		pwd, err := terminal.ReadPassword(syscall.Stdin)
		FailIf(err, "Can't get password")
		fmt.Println()
		return pwd
	}
}
