// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

package util

import (
	"io"

	"github.com/golang/protobuf/proto"
)

// A MessageReader is a stream from which protobuf messages can be read.
type MessageReader interface {
	ReadMessage(m proto.Message) error
}

// A MessageWriter is a stream to which protobuf messages can be written.
type MessageWriter interface {
	WriteMessage(m proto.Message) (n int, err error)
}

// A StringReader is a stream from which strings can be read.
type StringReader interface {
	ReadString() (string, error)
}

// A StringWriter is a stream to which strings can be written.
type StringWriter interface {
	WriteString(s string) (n int, err error)
}

// A IntReader is a stream from which strings can be read.
type IntReader interface {
	ReadInt() (int, error)
}

// A IntWriter is a stream to which strings can be written.
type IntWriter interface {
	WriteInt(i int) (n int, err error)
}

// A MessageStream is an io.ReadWriteCloser that can also read and write strings
// and protobuf messages. Boundaries are preserved for strings and protobuf
// messages using a 32-bit (network byte order) length prefix before the
// contents of the string or marshalled protobuf message. MessageStream can also
// enforce an upper-limit on the size of received messages. The new operations
// accumulate errors in Err and are no-ops if Err is not nil.
type MessageStream interface {
	io.ReadWriteCloser
	MessageReader
	MessageWriter
	StringReader
	StringWriter
	IntReader
	IntWriter
	// Err returns recent errors from the string and protobuf functions.
	Err() error
	// ClearErr discards recent errors for this stream.
	ClearErr()
	// SetErr sets the recent error for this stream.
	SetErr(err error)
	// SetMaxMessageSize sets the maximum allowed message or string size.
	// Negative means unlimited, zero means use the default.
	SetMaxMessageSize(i int)
	// MaxmessageSize gets the maximum allowed message or string size. Negative
	// means unlimited, zero means use the default.
	MaxMessageSize() int
}
