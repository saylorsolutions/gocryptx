package passlock

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewKeyGenerator(t *testing.T) {
	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, DefaultInteractiveIterations, gen.iterations)
	assert.Equal(t, DefaultCpuCost, gen.cpuCost)
	assert.Equal(t, AES256KeySize, gen.aesKeySize)
	assert.Equal(t, DefaultRelBlockSize, gen.relativeBlockSize)

	key, salt, err := gen.GenerateKey([]byte("a test password"))
	assert.NoError(t, err)
	assert.Len(t, key, gen.aesKeySize)
	assert.Len(t, salt, gen.aesKeySize)
}

func TestNewKeyGenerator_Custom(t *testing.T) {
	gen, err := NewKeyGenerator(
		SetIterations(2),
		SetLongDelayIterations(),
		SetShortDelayIterations(),
		SetCPUCost(DefaultCpuCost),
		SetRelativeBlockSize(DefaultRelBlockSize),
		SetAES512KeySize(),
		SetAES256KeySize(),
	)
	assert.NoError(t, err)
	assert.NotNil(t, gen)
	assert.Equal(t, DefaultInteractiveIterations, gen.iterations)
	assert.Equal(t, DefaultCpuCost, gen.cpuCost)
	assert.Equal(t, AES256KeySize, gen.aesKeySize)
	assert.Equal(t, DefaultRelBlockSize, gen.relativeBlockSize)

	key, salt, err := gen.GenerateKey([]byte("a test password"))
	assert.NoError(t, err)
	assert.Len(t, key, gen.aesKeySize)
	assert.Len(t, salt, gen.aesKeySize)
}
