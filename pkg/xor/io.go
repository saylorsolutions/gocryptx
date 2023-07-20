package xor

import (
	"bytes"
	"io"
)

// Reader extends io.Reader, but also provides a way to reuse a key with a different source.
type Reader interface {
	io.Reader
	// Reset will use the provided io.Reader and reset the offset position within the key to its initial value.
	Reset(source io.Reader)
}

// Writer extends io.Writer, but also provides a way to reuse a key with a different target.
type Writer interface {
	io.Writer
	// Reset will use the provided io.Writer and reset the offset position within the key to its initial value.
	Reset(target io.Writer)
}

var _ Reader = (*reader)(nil)

type reader struct {
	source io.Reader
	scr    *xorScreen
}

func (r *reader) Read(out []byte) (n int, err error) {
	n, err = r.source.Read(out)
	for i := 0; i < n; i++ {
		out[i] = r.scr.screen(out[i])
	}
	return n, err
}

func (r *reader) Reset(source io.Reader) {
	r.source = source
	r.scr.reset()
}

// NewReader constructs a new Reader that will perform XOR operations on all bytes read, using the provided key, starting at offset.
func NewReader(r io.Reader, key []byte, offset ...int) (Reader, error) {
	scr, err := newXorScreen(key, offset...)
	if err != nil {
		return nil, err
	}
	xReader := &reader{
		source: r,
		scr:    scr,
	}
	return xReader, nil
}

var _ Writer = (*writer)(nil)

type writer struct {
	target io.Writer
	scr    *xorScreen
}

func NewWriter(target io.Writer, key []byte, offset ...int) (Writer, error) {
	scr, err := newXorScreen(key, offset...)
	if err != nil {
		return nil, err
	}
	xWriter := &writer{
		target: target,
		scr:    scr,
	}
	return xWriter, nil
}

func (w *writer) Write(in []byte) (n int, err error) {
	var buf bytes.Buffer
	for i := 0; i < len(in); i++ {
		buf.WriteByte(w.scr.screen(in[i]))
	}
	return w.target.Write(buf.Bytes())
}

func (w *writer) Reset(target io.Writer) {
	w.target = target
	w.scr.reset()
}
