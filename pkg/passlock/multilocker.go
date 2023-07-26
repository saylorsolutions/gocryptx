package passlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	bin "github.com/saylorsolutions/binmap"
	"io"
	"sort"
)

const (
	idFieldLen = 32
)

var (
	ErrInvalidHeader   = errors.New("invalid MultiLocker header")
	ErrInvalidPassword = errors.New("invalid password")
)

type MultiKey struct {
	id           string
	encryptedKey []byte
}

func (k *MultiKey) mapper() bin.Mapper {
	return bin.MapSequence(
		bin.FixedString(&k.id, idFieldLen),
		bin.DynamicSlice(&k.encryptedKey, bin.Byte),
	)
}

type MultiLocker struct {
	mkeys   []MultiKey
	payload []byte

	baseKey []byte
	keyGen  *KeyGenerator
}

func NewMultiLocker(gen *KeyGenerator) *MultiLocker {
	return &MultiLocker{
		keyGen: gen,
	}
}

func (l *MultiLocker) validateInitialized() error {
	if len(l.payload) == 0 {
		return errors.New("no payload set for update")
	}
	if l.keyGen == nil {
		return errors.New("no generator set")
	}
	return nil
}

func (l *MultiLocker) validateForUpdate() error {
	if err := l.validateInitialized(); err != nil {
		return err
	}
	if len(l.baseKey) == 0 {
		return errors.New("payload baseKey is not populated, enable update on this MultiLocker first")
	}
	return nil
}

func (l *MultiLocker) mapper() bin.Mapper {
	return bin.MapSequence(bin.DynamicSlice(&l.mkeys, func(k *MultiKey) bin.Mapper {
		return k.mapper()
	}), bin.Any(&l.payload, func(r io.Reader, endian binary.ByteOrder) error {
		payload, err := io.ReadAll(r)
		if err != nil {
			return err
		}
		l.payload = payload
		return nil
	}, func(w io.Writer, endian binary.ByteOrder) error {
		_, err := io.Copy(w, bytes.NewReader(l.payload))
		return err
	}))
}

func (l *MultiLocker) Read(r io.Reader) error {
	if err := l.mapper().Read(r, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	return nil
}

func (l *MultiLocker) Write(w io.Writer) error {
	if len(l.mkeys) == 0 {
		return errors.New("refusing to write MultiLocker without keys, data will be unrecoverable")
	}
	return l.mapper().Write(w, binary.BigEndian)
}

// EnableUpdate validates the MultiLocker and ensures that it's in a suitable state for updating.
// The original payload password must be used (not MultiKey passwords) to validate that the correct key is populated.
// The first validation error will be returned.
func (l *MultiLocker) EnableUpdate(pass []byte) error {
	err := l.validateInitialized()
	if err != nil {
		return err
	}
	derivedKey, err := l.keyGen.DeriveKey(pass, l.payload)
	if err != nil {
		return fmt.Errorf("failed to derive baseKey from payload: %w", err)
	}
	_, err = Unlock(derivedKey, l.payload)
	if err != nil {
		return fmt.Errorf("%w: invalid base pass", ErrInvalidPassword)
	}
	l.baseKey = derivedKey
	return nil
}

func (l *MultiLocker) DisableUpdate() {
	l.baseKey = nil
}

func (l *MultiLocker) ListKeyIDs() []string {
	ids := make([]string, len(l.mkeys))
	for i, mk := range l.mkeys {
		ids[i] = mk.id
	}
	sort.Strings(ids)
	return ids
}

func (l *MultiLocker) AddPass(id string, pass []byte) error {
	if len(id) > idFieldLen || len(id) == 0 {
		return fmt.Errorf("id value is not within the valid range of 1-%d bytes", idFieldLen)
	}
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	newPassKey, salt, err := l.keyGen.GenerateKey(pass)
	if err != nil {
		return err
	}
	encryptedKey, err := Lock(newPassKey, salt, l.baseKey)
	if err != nil {
		return err
	}
	newKey := MultiKey{
		id:           id,
		encryptedKey: encryptedKey,
	}
	l.mkeys = append(l.mkeys, newKey)
	return nil
}

func (l *MultiLocker) RemovePass(id string) error {
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	for i := 0; i < len(l.mkeys); i++ {
		if l.mkeys[i].id == id {
			l.mkeys = append(l.mkeys[:i], l.mkeys[i+1:]...)
			return nil
		}
	}
	return nil
}

func (l *MultiLocker) UpdatePass(id string, pass []byte) error {
	if len(id) > idFieldLen {
		return fmt.Errorf("id value is greater than the maximum field width of %d", idFieldLen)
	}
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	newPassKey, salt, err := l.keyGen.GenerateKey(pass)
	if err != nil {
		return err
	}
	encryptedKey, err := Lock(newPassKey, salt, l.baseKey)
	if err != nil {
		return err
	}
	for _, mk := range l.mkeys {
		if mk.id == id {
			mk.encryptedKey = encryptedKey
			return nil
		}
	}
	return errors.New("given ID is not present in this MultiLocker")
}

func (l *MultiLocker) Lock(pass []byte, unencrypted []byte) error {
	if l.keyGen == nil {
		return errors.New("missing key generator")
	}
	if len(l.mkeys) > 0 {
		return errors.New("locking a new payload will invalidate all existing MultiKeys")
	}
	key, salt, err := l.keyGen.GenerateKey(pass)
	if err != nil {
		return err
	}
	encrypted, err := Lock(key, salt, unencrypted)
	if err != nil {
		return err
	}
	l.payload = encrypted
	l.baseKey = key
	return nil
}

func (l *MultiLocker) Unlock(id string, pass []byte) ([]byte, error) {
	if err := l.validateInitialized(); err != nil {
		return nil, err
	}
	for _, mk := range l.mkeys {
		if mk.id == id {
			passKey, err := l.keyGen.DeriveKey(pass, mk.encryptedKey)
			if err != nil {
				return nil, err
			}
			baseKey, err := Unlock(passKey, mk.encryptedKey)
			if err != nil {
				return nil, ErrInvalidPassword
			}
			data, err := Unlock(baseKey, l.payload)
			baseKey = nil
			if err != nil {
				return nil, fmt.Errorf("%w: invalid base pass", ErrInvalidPassword)
			}
			return data, nil
		}
	}
	return nil, errors.New("multikey ID not found")
}
