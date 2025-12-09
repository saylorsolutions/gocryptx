package xor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenKeyAndOffset(t *testing.T) {
	key, offset, err := GenKeyAndOffset(32)
	assert.NoError(t, err)
	assert.Len(t, key, 32)
	assert.Less(t, offset, 32)
}
