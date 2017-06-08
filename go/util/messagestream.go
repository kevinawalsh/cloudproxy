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
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/golang/protobuf/proto"
)

// MessageFraming is a partial implementation of MessageStream.
type MessageFraming struct {
	max int // Negative means unlimited, zero means default
	err error
}

func (f *MessageFraming) Err() error {
	return f.err
}

func (f *MessageFraming) ClearErr() {
	f.err = nil
}

func (f *MessageFraming) SetErr(err error) {
	f.err = err
}

func (f *MessageFraming) SetMaxMessageSize(i int) {
	f.max = i
}

func (f *MessageFraming) MaxMessageSize() int {
	return f.max
}

// FramedStream combines an io.ReadWriteCloser with message framing to implement
// MessageStream.
type FramedStream struct {
	MessageFraming
	io.ReadWriteCloser
}

func (f *FramedStream) WriteInt(i int) (int, error) {
	return WriteInt(f, i)
}

func (f *FramedStream) ReadInt() (int, error) {
	return ReadInt(f)
}

func (f *FramedStream) WriteString(s string) (int, error) {
	return WriteString(f, s)
}

func (f *FramedStream) ReadString() (string, error) {
	return ReadString(f)
}

func (f *FramedStream) WriteMessage(m proto.Message) (int, error) {
	return WriteMessage(f, m)
}

func (f *FramedStream) ReadMessage(m proto.Message) error {
	return ReadMessage(f, m)
}

// NewMessageStream creates a MessageStream for the given pipe with a reception
// limit of DefaultMaxMessageSize.
func NewMessageStream(pipe io.ReadWriteCloser) MessageStream {
	return &FramedStream{MessageFraming{}, pipe}
}

// DefaultMaxMessageSize gives the default max for messages sent on a
// MessageStream.
const DefaultMaxMessageSize = 20 * 1024 * 1024

// ErrMessageTooLarge is the error message returned when a message larger than
// DefaultMaxMessageSize is sent on a MessageStream.
var ErrMessageTooLarge = errors.New("messagestream: message is too large")

// WriteInt writes a 64-bit integer.
func WriteInt(ms MessageStream, i int) (int, error) {
	err := ms.Err()
	if err != nil {
		return 0, err
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(i))
	n, err := ms.Write(b[:])
	if err != nil {
		ms.SetErr(err)
		return n, Logged(err)
	}
	return n, nil
}

// ReadInt reads a 64-bit integer and converts it to an int.
func ReadInt(ms MessageStream) (int, error) {
	err := ms.Err()
	if err != nil {
		return 0, err
	}
	defer func() {
		if err != nil {
			ms.SetErr(err)
		}
	}()
	var b [8]byte
	_, err = io.ReadFull(ms, b[:])
	if err == io.EOF {
		return 0, err
	} else if neterr, ok := err.(*net.OpError); ok && neterr.Err == io.EOF {
		return 0, err
	} else if err != nil {
		return 0, Logged(err)
	}
	i := int64(binary.BigEndian.Uint64(b[:]))
	const maxUint = ^uint(0)
	const maxInt = int64(maxUint >> 1)
	const minInt = -maxInt - 1
	// Check for int(n) to overflow so allocation below doesn't fail.
	if i < minInt || i > maxInt {
		err = ErrMessageTooLarge
		return 0, Logged(err)
	}
	return int(i), nil
}

// WriteString writes a 32-bit length followed by the string.
func WriteString(ms MessageStream, s string) (int, error) {
	err := ms.Err()
	if err != nil {
		return 0, err
	}
	n, err := WriteInt(ms, len(s))
	if err != nil {
		ms.SetErr(err)
		return n, Logged(err)
	}
	m, err := ms.Write([]byte(s))
	if err != nil {
		ms.SetErr(err)
		return n, Logged(err)
	}
	return n + m, nil
}

// ReadString reads a 32-bit length followed by a string.
func ReadString(ms MessageStream) (string, error) {
	err := ms.Err()
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			ms.SetErr(err)
		}
	}()
	n, err := ReadInt(ms)
	if err == io.EOF {
		return "", err
	} else if neterr, ok := err.(*net.OpError); ok && neterr.Err == io.EOF {
		return "", err
	} else if err != nil {
		return "", Logged(err)
	}
	max := ms.MaxMessageSize()
	if max == 0 {
		max = DefaultMaxMessageSize
	}
	if n < 0 || (max > 0 && n > max) {
		err = ErrMessageTooLarge
		return "", Logged(err)
	}
	strbytes := make([]byte, int(n))
	_, err = io.ReadFull(ms, strbytes)
	if err != nil {
		return "", Logged(err)
	}
	return string(strbytes), nil
}

// WriteMessage writes 32-bit length followed by a protobuf message. If m is
// nil, a blank message is written instead.
func WriteMessage(ms MessageStream, m proto.Message) (int, error) {
	err := ms.Err()
	if err != nil {
		return 0, err
	}
	if m == nil {
		return WriteString(ms, "")
	}
	bytes, err := proto.Marshal(m)
	if err != nil {
		ms.SetErr(err)
		return 0, Logged(err)
	}
	return WriteString(ms, string(bytes))
}

// ReadMessage reads a 32-bit length followed by a protobuf message. If m is
// nil, the incoming message is discarded.
func ReadMessage(ms MessageStream, m proto.Message) error {
	err := ms.Err()
	if err != nil {
		return err
	}
	s, err := ReadString(ms)
	if err != nil {
		return err
	}
	if m != nil {
		err = proto.Unmarshal([]byte(s), m)
		if err != nil {
			ms.SetErr(err)
			return Logged(err)
		}
	}
	return nil
}
