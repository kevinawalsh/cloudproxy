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

package main

// This is a simple shell interpreter to allow multiple commands in docker.

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

type line struct {
	arg []string
	bg  bool
	cmd *exec.Cmd
}

func main() {
	var cmds []line
	var c line

	if os.Args[len(os.Args)-1] != ";" && os.Args[len(os.Args)-1] != "&" {
		os.Args = append(os.Args, ";")
	}
	for i := 1; i < len(os.Args); i++ {
		arg := os.Args[i]
		if arg == ";" || arg == "&" {
			c.bg = (arg == "&")
			cmds = append(cmds, c)
			c = line{}
		} else {
			c.arg = append(c.arg, arg)
		}
	}

	for i, c := range cmds {
		var err error
		if c.bg {
			fmt.Printf("%d> % s &\n", i, c.arg)
		} else {
			fmt.Printf("%d> % s ;\n", i, c.arg)
		}
		c.cmd = exec.Command(c.arg[0], c.arg[1:]...)
		c.cmd.Stdout = os.Stdout
		c.cmd.Stderr = os.Stderr
		if c.arg[0] == "sleep" {
			if c.bg {
				// do nothing
			} else {
				var d time.Duration
				d, err = time.ParseDuration(c.arg[1])
				if err == nil {
					time.Sleep(d)
				}
			}
		} else if c.bg {
			err = c.cmd.Start()
		} else {
			err = c.cmd.Run()
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	for _, c := range cmds {
		if c.bg {
			err := c.cmd.Wait()
			if err != nil {
				log.Fatal(err)
			}
		}
	}
	fmt.Printf("*> done\n")
}
