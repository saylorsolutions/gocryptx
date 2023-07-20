package xor

import (
	"errors"
	"fmt"
)

type xorScreen struct {
	key  []byte
	init int
	cur  int
}

func newXorScreen(key []byte, offset ...int) (*xorScreen, error) {
	if len(key) == 0 {
		return nil, errors.New("cannot use empty key")
	}
	s := &xorScreen{
		key: key,
	}
	if len(offset) > 0 {
		if offset[0] < 0 || offset[0] >= len(key) {
			return nil, fmt.Errorf("offset %d out of range for provided key of len %d", offset, len(key))
		}
		s.init = offset[0]
		s.cur = s.init
	}
	return s, nil
}

func (s *xorScreen) screen(b byte) byte {
	b ^= s.key[s.cur]
	s.cur = (s.cur + 1) % len(s.key)
	return b
}

func (s *xorScreen) reset() {
	s.cur = s.init
}
