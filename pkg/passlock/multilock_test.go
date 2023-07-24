package passlock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMultikey_AddKey(t *testing.T) {
	mk, err := NewMultiLocker()
	assert.NoError(t, err)
	mk.AddKey("Test", []byte("test value"))
	assert.Equal(t, 1, mk.numKeys)
	assert.Len(t, mk.id, 1)
	assert.Len(t, mk.id[0], 32)

	for i := len("Test"); i < 32; i++ {
		assert.Equal(t, uint8(0), mk.id[0][i])
	}

	assert.Len(t, mk.len, 1)
	assert.Len(t, mk.encryptedKey, 1)
	assert.Equal(t, len("test value"), mk.len[0])
	assert.Equal(t, []byte("test value"), mk.encryptedKey[0])
}
