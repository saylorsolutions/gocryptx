package passlock

import (
	"crypto/rand"
	"errors"
	"fmt"
	"golang.org/x/crypto/scrypt"
)

const (
	DefaultLargeIterations       = 1_048_576
	DefaultInteractiveIterations = 131_072
	DefaultRelBlockSize          = 8
	DefaultCpuCost               = 1
	AES256KeySize                = 256 / 8
	AES512KeySize                = 512 / 8
)

var (
	ErrEmptyPassPhrase = errors.New("cannot use an empty passphrase")
	ErrInvalidData     = errors.New("unable to use input data")
)

type KeyGenerator struct {
	iterations        int
	relativeBlockSize int
	cpuCost           int
	aesKeySize        int
}

type GeneratorOpt = func(*KeyGenerator) error

func SetAES256KeySize() GeneratorOpt {
	return func(gen *KeyGenerator) error {
		gen.aesKeySize = AES256KeySize
		return nil
	}
}

func SetAES512KeySize() GeneratorOpt {
	return func(gen *KeyGenerator) error {
		gen.aesKeySize = AES512KeySize
		return nil
	}
}

// SetLongDelayIterations sets a higher iteration count. This is sufficient for infrequent key derivation, or cases where the key will be cached for long periods of time.
// This option is much more resistant to password cracking, and is the default.
func SetLongDelayIterations() GeneratorOpt {
	return func(gen *KeyGenerator) error {
		gen.iterations = DefaultLargeIterations
		return nil
	}
}

// SetShortDelayIterations sets a lower iteration count. This is appropriate for situations where a shorter delay is desired because of frequent key derivations.
// This option balances speed with password cracking resistance. It's recommended to use longer passwords with this approach.
func SetShortDelayIterations() GeneratorOpt {
	return func(gen *KeyGenerator) error {
		gen.iterations = DefaultInteractiveIterations
		return nil
	}
}

// SetIterations allows the caller to customize the iteration count.
// Only use this option if you know what you're doing.
func SetIterations(iterations int) GeneratorOpt {
	return func(gen *KeyGenerator) error {
		if iterations <= 1 {
			return errors.New("iterations cannot be <= 1")
		}
		if iterations%2 != 0 {
			return errors.New("iterations must be a power of 2")
		}
		gen.iterations = iterations
		return nil
	}
}

// SetCPUCost sets the parallelism factor for key generation from the default of 1.
// Only use this option if you know what you're doing.
func SetCPUCost(cost int) GeneratorOpt {
	return func(gen *KeyGenerator) error {
		if cost < DefaultCpuCost {
			return errors.New("cpu cost must be at least 1")
		}
		gen.cpuCost = cost
		return nil
	}
}

// SetRelativeBlockSize sets the relative block size.
// Only use this option if you know what you're doing.
func SetRelativeBlockSize(size int) GeneratorOpt {
	return func(gen *KeyGenerator) error {
		if size < DefaultRelBlockSize {
			return errors.New("relative block size must be at least 8")
		}
		gen.relativeBlockSize = size
		return nil
	}
}

// NewKeyGenerator creates a new KeyGenerator using the options provided as zero or more GeneratorOpt.
// By default, the generator generates a key for AES256KeySize using DefaultLargeIterations.
func NewKeyGenerator(opts ...GeneratorOpt) (*KeyGenerator, error) {
	gen := &KeyGenerator{
		iterations:        DefaultLargeIterations,
		relativeBlockSize: DefaultRelBlockSize,
		cpuCost:           DefaultCpuCost,
		aesKeySize:        AES256KeySize,
	}

	for _, opt := range opts {
		if err := opt(gen); err != nil {
			return nil, err
		}
	}
	return gen, nil
}

// GenerateKey will generate an AES key and salt using the configuration of the KeyGenerator.
func (g *KeyGenerator) GenerateKey(pass []byte) (key, salt []byte, err error) {
	if len(pass) == 0 {
		return nil, nil, ErrEmptyPassPhrase
	}
	salt = make([]byte, g.aesKeySize)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, err
	}
	key, err = scrypt.Key(pass, salt, g.iterations, g.relativeBlockSize, g.cpuCost, g.aesKeySize)
	return key, salt, err
}

func (g *KeyGenerator) DeriveKey(pass, data []byte) (key []byte, err error) {
	if len(pass) == 0 {
		return nil, ErrEmptyPassPhrase
	}
	if len(data) <= g.aesKeySize {
		return nil, fmt.Errorf("%w: input data isn't long enough to contain a key salt", ErrInvalidData)
	}
	salt := data[len(data)-g.aesKeySize:]
	return scrypt.Key(pass, salt, g.iterations, g.relativeBlockSize, g.cpuCost, g.aesKeySize)
}
