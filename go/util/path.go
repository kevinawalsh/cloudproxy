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
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/golang/glog"
)

// WritePath writes data to a file after creating any necessary directories. The
// permission bits are used to overwrite the permission bits for the file and
// any directories created, ignoring umask.
func WritePath(path string, data []byte, dirPerm, filePerm os.FileMode) error {
	dir := filepath.Dir(path)
	err := MkdirAll(dir, dirPerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path, data, filePerm)
	if err != nil {
		return err
	}
	return os.Chmod(path, filePerm)
}

// CreatePath creates a file after creating any necessary directories. The
// permission bits are used to overwrite the permission bits for the file and
// any directories created, ignoring umask.
func CreatePath(path string, dirPerm, filePerm os.FileMode) (*os.File, error) {
	dir := filepath.Dir(path)
	err := MkdirAll(dir, dirPerm)
	if err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, filePerm)
	if err != nil {
		return nil, err
	}
	return f, os.Chmod(path, filePerm)
}

// MkdirAll creates a directory named path, along with any necessary parents,
// and returns nil, or else returns an error. The permission bits perm are used
// for all directories that MkdirAll creates, ignoring umask. If path is already
// a directory, MkdirAll does nothing and returns nil.
// Borrowed nearly verbatim from
// https://golang.org/src/os/path.go?s=488:535#L9
// which carries the following notice:
//   Copyright 2009 The Go Authors. All rights reserved.
//   Use of this source code is governed by a BSD-style
//   license that can be found in the LICENSE file.
func MkdirAll(path string, perm os.FileMode) error {
	// Fast path: if we can tell whether path is a directory or file, stop with success or error.
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{"mkdir", path, syscall.ENOTDIR}
	}

	// Slow path: make sure parent exists and then call Mkdir for path.
	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent
		err = MkdirAll(path[0:j-1], perm)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke Mkdir and use its result.
	err = os.Mkdir(path, perm)
	if err != nil {
		// Handle arguments like "foo/." by
		// double-checking that directory doesn't exist.
		dir, err1 := os.Lstat(path)
		if err1 == nil && dir.IsDir() {
			return nil
		}
		return err
	}
	return os.Chmod(path, perm)
}

// FindExecutable searches for an executable in a path. If the name contains a
// slash, the search path is ignored. If the search fails, emptystring is
// returned.
func FindExecutable(name string, dirs []string) string {
	if strings.ContainsRune(name, '/') {
		// For name containing a slash, the file need not be executable.
		return name
	}
	for _, dir := range dirs {
		path := filepath.Join(dir, name)
		if IsExecutable(path) {
			return path
		}
	}
	return ""
}

// SystemPath returns the elements of $PATH
func SystemPath() []string {
	var dirs []string
	if pathenv := os.Getenv("PATH"); pathenv != "" {
		for _, dir := range strings.Split(pathenv, ":") {
			if dir == "" {
				dir = "." // Unix shell semantics: "" in $PATH means "."
			}
			dirs = append(dirs, dir)
		}
	}
	return dirs
}

// GoBinPath returns dir/bin for each dir in $GOPATH
func GoBinPath() []string {
	var dirs []string
	gopath := os.Getenv("GOPATH")
	if gopath != "" {
		for _, dir := range strings.Split(gopath, ":") {
			dirs = append(dirs, dir+"/bin")
		}
	}
	return dirs
}

// LocalPath returns the directory of the current executable
func LocalPath() []string {
	path, err := filepath.Abs(os.Args[0])
	if err != nil {
		glog.Errorf("%v: Can't get path of '%s'", err, os.Args[0])
		return nil
	} else {
		return []string{filepath.Dir(path)}
	}
}

// LiberalSearchPath returns LocalPath, GoBinPath, and SystemPath together, in
// that order.
func LiberalSearchPath() []string {
	var dirs []string
	dirs = append(dirs, LocalPath()...)
	dirs = append(dirs, GoBinPath()...)
	dirs = append(dirs, SystemPath()...)
	return dirs
}

// IsExecutable checks whether the file has an executable bits set.
func IsExecutable(file string) bool {
	d, err := os.Stat(file)
	return err == nil && !d.Mode().IsDir() && d.Mode()&0111 != 0
}

// IsDir checks whether the path is a directory.
func IsDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}
