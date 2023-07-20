package xor

import (
	"bytes"
	"crypto/rand"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGenKeyAndOffset(t *testing.T) {
	key, offset, err := GenKeyAndOffset(32)
	assert.NoError(t, err)
	assert.Len(t, key, 32)
	assert.Less(t, offset, 32)
}

func TestGenKeyAndOffset_Neg(t *testing.T) {
	_, _, err := GenKeyAndOffset(0)
	assert.Error(t, err)

	orig := rand.Reader
	defer func() {
		rand.Reader = orig
	}()
	rand.Reader = bytes.NewBuffer(nil)

	_, _, err = GenKeyAndOffset(10)
	assert.Error(t, err)
}
