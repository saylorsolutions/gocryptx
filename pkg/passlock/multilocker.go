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

type surrogateKey struct {
	encryptedKey Encrypted
}

type MultiLocker struct {
	surKeys map[string]surrogateKey
	payload Encrypted

	baseKey Key
	keyGen  *KeyGenerator
}

func NewMultiLocker(gen *KeyGenerator) *MultiLocker {
	return &MultiLocker{
		keyGen:  gen,
		surKeys: map[string]surrogateKey{},
	}
}

func (l *MultiLocker) validateInitialized() error {
	if len(l.payload) == 0 {
		return errors.New("no payload set")
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
	return bin.MapSequence(
		bin.Map(&l.surKeys, func(key *string) bin.Mapper {
			return bin.FixedString(key, idFieldLen)
		}, func(val *surrogateKey) bin.Mapper {
			return bin.DynamicSlice((*[]byte)(&val.encryptedKey), func(e *byte) bin.Mapper {
				return bin.Byte(e)
			})
		}),
		l.keyGen.mapper(),
		bin.Any(
			func(r io.Reader, endian binary.ByteOrder) error {
				payload, err := io.ReadAll(r)
				if err != nil {
					return err
				}
				l.payload = payload
				return nil
			},
			func(w io.Writer, endian binary.ByteOrder) error {
				_, err := io.Copy(w, bytes.NewReader(l.payload))
				return err
			},
		),
	)
}

func (l *MultiLocker) Read(r io.Reader) error {
	if err := l.mapper().Read(r, binary.BigEndian); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	return nil
}

func (l *MultiLocker) Write(w io.Writer) error {
	return l.mapper().Write(w, binary.BigEndian)
}

// EnableUpdate validates the MultiLocker and ensures that it's in a suitable state for updating by setting the base key.
// The original payload passphrase must be used, not a surrogate passphrase, to validate that the correct key is populated.
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
	ids := make([]string, len(l.surKeys))
	for id := range l.surKeys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (l *MultiLocker) AddSurrogatePass(id string, pass Passphrase) error {
	if len(id) > idFieldLen || len(id) == 0 {
		return fmt.Errorf("id value is not within the valid range of 1-%d bytes", idFieldLen)
	}
	if _, ok := l.surKeys[id]; ok {
		return fmt.Errorf("surrogate key ID already exists")
	}
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	newPassKey, salt, err := l.keyGen.GenerateKey(pass)
	if err != nil {
		return err
	}
	plainKey := Plaintext(l.baseKey)
	encryptedKey, err := Lock(newPassKey, salt, plainKey)
	if err != nil {
		return err
	}
	newKey := surrogateKey{
		encryptedKey: encryptedKey,
	}
	l.surKeys[id] = newKey
	return nil
}

func (l *MultiLocker) RemoveSurrogatePass(id string) error {
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	_, ok := l.surKeys[id]
	if !ok {
		return nil
	}
	delete(l.surKeys, id)
	return nil
}

func (l *MultiLocker) UpdateSurrogatePass(id string, newPass Passphrase) error {
	if len(id) > idFieldLen {
		return fmt.Errorf("id value is greater than the maximum field width of %d", idFieldLen)
	}
	sur, ok := l.surKeys[id]
	if !ok {
		return errors.New("given ID is not present in this MultiLocker")
	}
	if err := l.validateForUpdate(); err != nil {
		return err
	}
	newPassKey, salt, err := l.keyGen.GenerateKey(newPass)
	if err != nil {
		return err
	}
	plainKey := Plaintext(l.baseKey)
	encryptedKey, err := Lock(newPassKey, salt, plainKey)
	if err != nil {
		return err
	}
	sur.encryptedKey = encryptedKey
	return nil
}

func (l *MultiLocker) Lock(pass []byte, unencrypted []byte) error {
	if l.keyGen == nil {
		return errors.New("missing key generator")
	}
	if len(l.surKeys) > 0 {
		if err := l.validateInitialized(); err != nil {
			return fmt.Errorf("cannot Lock a new payload with surrogate keys until update is enabled: %w", err)
		}
		key, salt, err := l.keyGen.DeriveKeySalt(pass, l.payload)
		if err != nil {
			return err
		}
		_, err = Unlock(key, l.payload)
		if err != nil {
			return ErrInvalidPassword
		}
		newPayload, err := Lock(key, salt, unencrypted)
		if err != nil {
			return err
		}
		l.payload = newPayload
		return nil
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
	sur, ok := l.surKeys[id]
	if !ok {
		return nil, errors.New("surrogate key ID not found")
	}
	passKey, err := l.keyGen.DeriveKey(pass, sur.encryptedKey)
	if err != nil {
		return nil, err
	}
	unencKey, err := Unlock(passKey, sur.encryptedKey)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	baseKey := Key(unencKey)
	data, err := Unlock(baseKey, l.payload)
	baseKey = nil
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base key", ErrInvalidPassword)
	}
	return data, nil
}

// WriteMultiLocker is the same as MultiLocker, except that the logical constraint that surrogate keys cannot write a new payload is lifted.
type WriteMultiLocker struct {
	*MultiLocker
}

func NewWriteMultiLocker(gen *KeyGenerator) *WriteMultiLocker {
	return &WriteMultiLocker{
		MultiLocker: NewMultiLocker(gen),
	}
}

func (l *WriteMultiLocker) SurrogateLock(id string, pass Passphrase, unencrypted Plaintext) error {
	if err := l.validateInitialized(); err != nil {
		return err
	}
	sur, ok := l.surKeys[id]
	if !ok {
		return errors.New("surrogate key ID not found")
	}
	passKey, err := l.keyGen.DeriveKey(pass, sur.encryptedKey)
	if err != nil {
		return err
	}
	unencKey, err := Unlock(passKey, sur.encryptedKey)
	if err != nil {
		return ErrInvalidPassword
	}
	baseKey := Key(unencKey)
	_, err = Unlock(baseKey, l.payload)
	if err != nil {
		return fmt.Errorf("%w: invalid base key", ErrInvalidPassword)
	}
	salt, err := l.keyGen.DeriveSalt(l.payload)
	if err != nil {
		return err
	}
	l.payload, err = Lock(baseKey, salt, unencrypted)
	baseKey = nil
	return err
}
