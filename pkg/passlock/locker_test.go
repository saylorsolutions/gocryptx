package passlock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestLockUnlock(t *testing.T) {
	const password = "password"
	const data = "How wonderful life is while you're in the world"
	dataBytes := []byte(data)

	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	key, salt, err := gen.GenerateKey([]byte(password))
	assert.NoError(t, err)

	encrypted, err := Lock(key, salt, dataBytes)
	t.Log(string(encrypted))
	assert.NoError(t, err)
	assert.NotEqual(t, dataBytes, encrypted)

	key2, err := gen.DeriveKey([]byte(password), encrypted)
	assert.NoError(t, err)
	assert.Equal(t, key, key2)

	unencrypted, err := Unlock(key2, encrypted)
	t.Log(string(unencrypted))
	assert.NoError(t, err)
	assert.NotEqual(t, encrypted, unencrypted)
	assert.Equal(t, data, string(unencrypted))
}
