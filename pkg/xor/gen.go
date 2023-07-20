package xor

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
)

// GenKey will generate an XOR key with the given length.
func GenKey(length int) ([]byte, error) {
	if length == 0 {
		return nil, errors.New("asked to generate a 0-length key")
	}
	buf := make([]byte, length)
	n, err := rand.Read(buf)
	if n < length {
		return nil, fmt.Errorf("failed to read requested bytes: %v", err)
	}
	return buf, nil
}

func GenKeyAndOffset(length int) ([]byte, int, error) {
	key, err := GenKey(length)
	if err != nil {
		return nil, 0, err
	}
	buf := make([]byte, 4)
	_, err = rand.Read(buf)
	if err != nil {
		return nil, 0, err
	}
	return key, int(binary.BigEndian.Uint32(buf)) % length, nil
}
