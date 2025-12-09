package passlock

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
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
	assert.Len(t, key, int(gen.aesKeySize))
	assert.Len(t, salt, int(gen.aesKeySize))
}

func TestNewKeyGenerator_Custom(t *testing.T) {
	gen, err := NewKeyGenerator(
		SetIterations(2),
		SetLongDelayIterations(),
		SetShortDelayIterations(),
		SetCPUCost(DefaultCpuCost),
		SetRelativeBlockSize(DefaultRelBlockSize),
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
	assert.Len(t, key, int(gen.aesKeySize))
	assert.Len(t, salt, int(gen.aesKeySize))
}

func TestKeyGenerator_mapper(t *testing.T) {
	var (
		buf bytes.Buffer
	)
	gen, err := NewKeyGenerator(SetShortDelayIterations())
	assert.NoError(t, err)
	assert.NotNil(t, gen)

	assert.NoError(t, gen.mapper().Write(&buf, binary.BigEndian))
	updated, err := NewKeyGenerator(
		SetIterations(1<<4),
		SetCPUCost(4),
		SetRelativeBlockSize(128),
		SetAES128KeySize(),
	)
	assert.NoError(t, err)
	assert.NoError(t, updated.mapper().Read(&buf, binary.BigEndian))
	assert.Equal(t, DefaultInteractiveIterations, updated.iterations)
	assert.Equal(t, DefaultCpuCost, updated.cpuCost)
	assert.Equal(t, DefaultRelBlockSize, updated.relativeBlockSize)
	assert.Equal(t, AES256KeySize, updated.aesKeySize)
}
