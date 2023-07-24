package passlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrInvalidHeader = errors.New("invalid MultiLock header")
)

// MultiLock is used to allow multiple distinct passphrases to decrypt an encrypted payload.
type MultiLock struct {
	numKeys      int
	id           [][idFieldLen]byte
	len          []int
	encryptedKey [][]byte
	gen          *KeyGenerator
}

func NewMultiLocker() (*MultiLock, error) {
	mk := new(MultiLock)
	var err error
	mk.gen, err = NewKeyGenerator(SetShortDelayIterations())
	if err != nil {
		return nil, err
	}
	return mk, nil
}

func (m *MultiLock) AddPassphrase(id string, pass []byte, realPass []byte) error {
	genkey, salt, err := m.gen.GenerateKey(pass)
	if err != nil {
		return err
	}
	_id := [idFieldLen]byte{}
	for i := 0; i < len(id) && i < idFieldLen; i++ {
		_id[i] = id[i]
	}
	m.id = append(m.id, _id)
	m.len = append(m.len, len(pass))
	m.encryptedKey = append(m.encryptedKey, encryptedKey)
	m.numKeys++
}

func (m *MultiLock) validate() error {
	if m == nil {
		return fmt.Errorf("%w: nil MultiLock", ErrInvalidHeader)
	}
	if m.numKeys <= 0 {
		return fmt.Errorf("%w: no keys loaded in this MultiLock", ErrInvalidHeader)
	}
	if len(m.id) != m.numKeys {
		return fmt.Errorf("%w: mismatched number of IDs", ErrInvalidHeader)
	}
	if len(m.len) != m.numKeys {
		return fmt.Errorf("%w: mismatched number of key lengths", ErrInvalidHeader)
	}
	if len(m.encryptedKey) != m.numKeys {
		return fmt.Errorf("%w: mismatched number of encrypted keys", ErrInvalidHeader)
	}
	return nil
}

func (m *MultiLock) MarshalBinary() ([]byte, error) {
	if err := m.validate(); err != nil {
		return nil, err
	}
	var (
		buf    bytes.Buffer
		endian = binary.BigEndian
	)

	if err := binary.Write(&buf, endian, magicBytes); err != nil {
		return nil, err
	}
	for i := 0; i < m.numKeys; i++ {
		if err := binary.Write(&buf, endian, m.id[i]); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, endian, m.len[i]); err != nil {
			return nil, err
		}
		if err := binary.Write(&buf, endian, m.encryptedKey[i]); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func (m *MultiLock) UnmarshalBinary(data []byte) error {
	var (
		magic  uint16
		num    uint16
		endian binary.ByteOrder = binary.BigEndian
	)
	r := bytes.NewReader(data)
	if err := binary.Read(r, endian, &magic); err != nil {
		return err
	}
	if magic == magicBytesInverse {
		endian = binary.LittleEndian
	}
	if err := binary.Read(r, endian, &num); err != nil {
		return err
	}
	m.numKeys = int(num)
	m.id = make([][idFieldLen]byte, m.numKeys)
	m.len = make([]int, m.numKeys)
	m.encryptedKey = make([][]byte, m.numKeys)

	for i := 0; i < m.numKeys; i++ {
		var (
			id     [idFieldLen]byte
			keyLen uint16
			key    []byte
		)
		if err := binary.Read(r, endian, &id); err != nil {
			return err
		}
		if err := binary.Read(r, endian, &keyLen); err != nil {
			return err
		}
		key = make([]byte, int(keyLen))
		if err := binary.Read(r, endian, &key); err != nil {
			return err
		}
		m.id[i] = id
		m.len[i] = int(keyLen)
		m.encryptedKey[i] = key
	}
	return nil
}
