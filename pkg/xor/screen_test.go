package xor

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewXorScreenNeg(t *testing.T) {
	_, err := newXorScreen(nil)
	assert.Error(t, err)
	_, err = newXorScreen([]byte{0}, -1)
	assert.Error(t, err)
	_, err = newXorScreen([]byte{0}, 1)
	assert.Error(t, err)
	_, err = newXorScreen([]byte{0}, 2)
	assert.Error(t, err)
}
