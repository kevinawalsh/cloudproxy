package util

import (
	"io"
	"io/ioutil"
	"os"
	"testing"
)

func PairHelper(t *testing.T, closeA, closeB bool, msg string) {
	a, _ := ioutil.TempFile(os.TempDir(), "tempA")
	defer os.Remove(a.Name())
	b, _ := ioutil.TempFile(os.TempDir(), "tempB")
	defer os.Remove(b.Name())

	var p *PairReadWriteCloser
	var c1,c2 io.Closer
	if closeA {
		c1 = a
	} else {
		c1 = nil
	}
	if closeB {
		c2 = b
	} else {
		c2 = nil
	}

	p = NewPairReadWriteCloser(a, b, c1, c2)
	_, err := io.WriteString(p, "hello")
	if err != nil {
		t.Error(err.Error)
		return
	}
	err = p.Close()
	if err != nil {
		t.Error(err.Error)
		return
	}
	if p.Close() == nil && (closeA || closeB){
		t.Error("pair did not detect double close for " + msg)
	}
	if (a.Close() != nil) != (closeA) {
		t.Error("tempA close was not handled properly for " + msg)
	}
	if (b.Close() != nil) != (closeB) {
		t.Error("tempB close was not handled properly for " + msg)
	}

	a, _ = os.Open(a.Name())
	b, _ = os.Open(b.Name())

	p = NewPairReadWriteCloser(b, a, b, a)
	buf := make([]byte, 100)
	n, err := io.ReadFull(p, buf)
	if err != io.ErrUnexpectedEOF {
		t.Error(err.Error())
		return
	}
	if n != len("hello") {
		t.Error("wrong number of chars")
	}
	p.Close()
}

func TestPairReadWriteCloser(t *testing.T) {
	PairHelper(t, true, true, "double close")
	PairHelper(t, true, false, "close only A")
	PairHelper(t, false, true, "close only B")
	PairHelper(t, false, false, "close neither")
}
