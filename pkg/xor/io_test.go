package xor

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"io"
	"strings"
	"testing"
)

func TestReadWrite(t *testing.T) {
	data := "A string with some text"
	key := []byte{0xde, 0xad, 0xbe, 0xef}
	var output strings.Builder

	in, err := NewReader(strings.NewReader(data), key)
	assert.NoError(t, err)
	assert.NotNil(t, in)

	out, err := NewWriter(&output, key)
	assert.NoError(t, err)
	assert.NotNil(t, out)

	expectedLen := int64(len(data))
	n, err := io.Copy(out, in)
	assert.NoError(t, err)
	assert.Equal(t, expectedLen, n)
	assert.Equal(t, "A string with some text", output.String())
}

func TestWriter_Reset(t *testing.T) {
	var (
		outA bytes.Buffer
		outB bytes.Buffer
		in   = []byte{0x0, 0x1}
		key  = []byte{0x0, 0x1, 0x1, 0x2}
	)
	w, err := NewWriter(&outA, key, 1)
	assert.NoError(t, err)
	n, err := w.Write(in)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{0x1, 0x0}, outA.Bytes())

	w.Reset(&outB)
	n, err = w.Write(in)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{0x1, 0x0}, outA.Bytes())
}

func TestReader_Reset(t *testing.T) {
	var (
		outA = make([]byte, 2)
		outB = make([]byte, 2)
		in   = []byte{0x0, 0x1}
		key  = []byte{0x0, 0x1, 0x1, 0x2}
	)
	r, err := NewReader(bytes.NewReader(in), key, 1)
	assert.NoError(t, err)
	n, err := r.Read(outA)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{0x1, 0x0}, outA)

	r.Reset(bytes.NewReader(in))
	n, err = r.Read(outB)
	assert.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, []byte{0x1, 0x0}, outB)
}
