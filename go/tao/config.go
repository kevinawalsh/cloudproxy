// Copyright (c) 2015, Google, Inc.  All rights reserved.
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
	"os"
)

// A Config stores the information needed to talk to establish a channel
// with a host tao.
type Config struct {
	HostChannelType string
	HostSpec        string

	// Variables for the TPM configuration
	TPMAIKPath string
	TPMPCRs    string
	TPMDevice  string
}

// NewConfigFromEnv creates a Config using values drawn from environment
// variables.
func NewConfigFromEnv() Config {

	tc := Config{}

	tc.HostChannelType = os.Getenv(HostChannelTypeEnvVar)
	if tc.HostChannelType == "tpm" {
		tc.TPMAIKPath = os.Getenv(TaoTPMAIKEnvVar)
		tc.TPMPCRs = os.Getenv(TaoTPMPCRsEnvVar)
		tc.TPMDevice = os.Getenv(TaoTPMDeviceEnvVar)
	}

	tc.HostSpec = os.Getenv(HostSpecEnvVar)

	return tc
}

// Merge combines two Config values into one. The parameter value take
// precendence over the existing values. This is used to merge a config taken
// from the environment with a config specified explicitly on the command line.
// The latter takes precedence where it is explicitly given.
func (tc *Config) Merge(c Config) {

	if tc.HostChannelType == "" || c.HostChannelType != "" {
		tc.HostChannelType = c.HostChannelType
	}

	if tc.HostSpec == "" || c.HostSpec != "" {
		tc.HostSpec = c.HostSpec
	}

	if tc.TPMAIKPath == "" || c.TPMAIKPath != "" {
		tc.TPMAIKPath = c.TPMAIKPath
	}

	if tc.TPMPCRs == "" || c.TPMPCRs != "" {
		tc.TPMPCRs = c.TPMPCRs
	}

	if tc.TPMDevice == "" || c.TPMDevice != "" {
		tc.TPMDevice = c.TPMDevice
	}
}
