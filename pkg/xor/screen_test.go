package xor

import (
	"github.com/stretchr/testify/assert"
	"testing"
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
