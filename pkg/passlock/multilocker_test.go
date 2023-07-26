package passlock

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMultikey_AddKey(t *testing.T) {
	var (
		plaintext = "A secret message"
		basePass  = "passphrase"
		buf       bytes.Buffer
	)
	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	mk := NewMultiLocker(gen)
	assert.NoError(t, mk.Lock([]byte(basePass), []byte(plaintext)))

	assert.NoError(t, mk.AddPass("developer", []byte("s3cre+")))
	assert.NoError(t, mk.AddPass("other", []byte("some other secret")))
	assert.NoError(t, mk.Write(&buf))

	mkdata := buf.Bytes()
	buf.Reset()
	buf.Write(mkdata)

	mk = NewMultiLocker(gen)
	assert.NoError(t, mk.Read(&buf))
	assert.Len(t, mk.surKeys, 2)
	data, err := mk.Unlock("developer", []byte("s3cre+"))
	assert.NoError(t, err)
	assert.Equal(t, plaintext, string(data))
}

func TestMultiLocker_RemovePass(t *testing.T) {
	var (
		plaintext = "A secret message"
		basePass  = "passphrase"
	)
	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	mk := NewMultiLocker(gen)
	assert.NoError(t, mk.Lock([]byte(basePass), []byte(plaintext)))

	assert.NoError(t, mk.AddPass("developer", []byte("s3cre+")))
	assert.NoError(t, mk.AddPass("other", []byte("some other secret")))

	mk.DisableUpdate()
	assert.Error(t, mk.RemovePass("other"), "Should return an error when update is not enabled.")

	assert.NoError(t, mk.EnableUpdate([]byte(basePass)))
	assert.NoError(t, mk.RemovePass("other"), "Should be okay to update.")
}

func TestMultiLocker_ReLock(t *testing.T) {
	var (
		plaintext    = "A secret message"
		newPlaintext = "Another secret message"
		basePass     = "passphrase"
	)
	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	mk := NewMultiLocker(gen)
	assert.NoError(t, mk.Lock([]byte(basePass), []byte(plaintext)))

	assert.NoError(t, mk.AddPass("developer", []byte("s3cre+")))
	assert.NoError(t, mk.AddPass("other", []byte("some other secret")))

	mk.DisableUpdate()
	assert.Error(t, mk.Lock([]byte(basePass), []byte(newPlaintext)))

	assert.NoError(t, mk.EnableUpdate([]byte(basePass)))
	assert.NoError(t, mk.Lock([]byte(basePass), []byte(newPlaintext)))

	got, err := mk.Unlock("developer", []byte("s3cre+"))
	assert.NoError(t, err)
	assert.Equal(t, newPlaintext, string(got))
}
