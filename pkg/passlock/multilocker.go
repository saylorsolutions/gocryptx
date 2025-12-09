package passlock

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"

	bin "github.com/saylorsolutions/binmap"
)

const (
	idFieldLen = 32
)

var (
	ErrInvalidHeader   = errors.New("invalid MultiLocker header")
	ErrInvalidPassword = errors.New("invalid password")
)

type surrogateKey struct {
	encryptedPass Encrypted
}

// MultiLocker allows using surrogate keys - in addition to a base key - for reading an encrypted payload.
// If surrogate key writes are desired, then use the WriteMultiLocker instead.
type MultiLocker struct {
	surKeys map[string]surrogateKey
	payload Encrypted

	basePass Passphrase
	keyGen   *KeyGenerator
}

func NewMultiLocker(gen *KeyGenerator) *MultiLocker {
	return &MultiLocker{
		keyGen:  gen,
		surKeys: map[string]surrogateKey{},
	}
}

func (l *MultiLocker) validateHasGenerator() error {
	if l.keyGen == nil {
		return errors.New("no generator set")
	}
	return nil
}

func (l *MultiLocker) validateInitialized() error {
	if len(l.payload) == 0 {
		return errors.New("no payload set")
	}
	if err := l.validateHasGenerator(); err != nil {
		return err
	}
	return nil
}

func (l *MultiLocker) validateForUpdate() error {
	if err := l.validateInitialized(); err != nil {
		return err
	}
	if len(l.basePass) == 0 {
		return errors.New("payload basePass is not populated, enable update on this MultiLocker first")
	}
	return nil
}

func (l *MultiLocker) mapper() bin.Mapper {
	return bin.MapSequence(
		bin.Map(&l.surKeys, func(key *string) bin.Mapper {
			return bin.FixedString(key, idFieldLen)
		}, func(val *surrogateKey) bin.Mapper {
			return bin.DynamicSlice((*[]byte)(&val.encryptedPass), func(e *byte) bin.Mapper {
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

// ReadMultiLocker will read a MultiLocker as a binary payload from the io.Reader.
func ReadMultiLocker(r io.Reader) (*MultiLocker, error) {
	l := &MultiLocker{
		keyGen: new(KeyGenerator),
	}
	if err := l.mapper().Read(r, binary.BigEndian); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidHeader, err)
	}
	return l, nil
}

// Write will write the MultiLocker as a binary payload to the io.Writer.
func (l *MultiLocker) Write(w io.Writer) error {
	return l.mapper().Write(w, binary.BigEndian)
}

// EnableUpdate validates the MultiLocker and ensures that it's in a suitable state for updating by setting the base key.
// The original base passphrase must be used, not a surrogate passphrase, to validate that the correct key is populated.
func (l *MultiLocker) EnableUpdate(pass Passphrase) error {
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
	l.basePass = pass
	return nil
}

// DisableUpdate will disable updates to this MultiLocker.
func (l *MultiLocker) DisableUpdate() {
	l.basePass = nil
}

// ListKeyIDs lists all surrogate key IDs in this MultiLocker.
func (l *MultiLocker) ListKeyIDs() []string {
	ids := make([]string, len(l.surKeys))
	i := 0
	for id := range l.surKeys {
		ids[i] = id
		i++
	}
	sort.Strings(ids)
	return ids
}

// AddSurrogatePass will add a new surrogate key to this MultiLocker.
// Update must be enabled in this MultiLocker before this can be done.
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
	encryptedPass, err := Lock(newPassKey, salt, Plaintext(l.basePass))
	if err != nil {
		return err
	}
	newKey := surrogateKey{
		encryptedPass: encryptedPass,
	}
	l.surKeys[id] = newKey
	return nil
}

// RemoveSurrogatePass will remove a surrogate key.
// Update must be enabled in this MultiLocker before this can be done.
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

// UpdateSurrogatePass will update the passphrase of an existing surrogate key by ID.
// Update must be enabled in this MultiLocker before this can be done.
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
	encryptedPass, err := Lock(newPassKey, salt, Plaintext(l.basePass))
	if err != nil {
		return err
	}
	sur.encryptedPass = encryptedPass
	return nil
}

// InvalidateLock will encrypt a new payload and remove all surrogate keys.
// This is done by generating a new base key for the payload with a new salt that renders the existing surrogate keys invalid.
func (l *MultiLocker) InvalidateLock(pass Passphrase, unencrypted Plaintext) error {
	if err := l.validateHasGenerator(); err != nil {
		return err
	}
	key, salt, err := l.keyGen.GenerateKey(pass)
	if err != nil {
		return err
	}
	l.payload, err = Lock(key, salt, unencrypted)
	if err != nil {
		return err
	}
	l.surKeys = map[string]surrogateKey{}
	return nil
}

// Lock will lock a payload with the base key.
// If surrogate keys are present, or if a payload is set, then the same pass phrase must be used to ensure that surrogate keys are not invalidated.
// This also helps prevent someone else from tampering with the store.
func (l *MultiLocker) Lock(basePass Passphrase, unencrypted Plaintext) error {
	if err := l.validateHasGenerator(); err != nil {
		return err
	}
	if len(l.surKeys) > 0 || len(l.payload) > 0 {
		// Implies that there is a set payload.
		// Must use the same pass phrase to avoid invalidating surrogate keys
		key, _, err := l.keyGen.DeriveKeySalt(basePass, l.payload)
		if err != nil {
			return err
		}
		// Check that the key is valid
		_, err = Unlock(key, l.payload)
		if err != nil {
			return ErrInvalidPassword
		}
	}
	key, salt, err := l.keyGen.GenerateKey(basePass)
	if err != nil {
		return err
	}
	encrypted, err := Lock(key, salt, unencrypted)
	if err != nil {
		return err
	}
	l.payload = encrypted
	l.basePass = basePass
	return nil
}

// Unlock will unlock the [MultiLocker]'s payload with the base pass phrase.
func (l *MultiLocker) Unlock(basePass Passphrase) (Plaintext, error) {
	if err := l.validateInitialized(); err != nil {
		return nil, err
	}
	baseKey, err := l.keyGen.DeriveKey(basePass, l.payload)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	data, err := Unlock(baseKey, l.payload)
	baseKey = nil
	if err != nil {
		return nil, fmt.Errorf("%w: invalid base key", ErrInvalidPassword)
	}
	return data, nil
}

// SurrogateUnlock will unlock the payload with a surrogate key.
func (l *MultiLocker) SurrogateUnlock(id string, pass Passphrase) (Plaintext, error) {
	if err := l.validateInitialized(); err != nil {
		return nil, err
	}
	sur, ok := l.surKeys[id]
	if !ok {
		return nil, errors.New("surrogate key ID not found")
	}
	passKey, err := l.keyGen.DeriveKey(pass, sur.encryptedPass)
	if err != nil {
		return nil, err
	}
	basePass, err := Unlock(passKey, sur.encryptedPass)
	if err != nil {
		return nil, ErrInvalidPassword
	}
	baseKey, err := l.keyGen.DeriveKey(Passphrase(basePass), l.payload)
	if err != nil {
		return nil, err
	}
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

// SurrogateLock will Lock a new payload in the MultiLocker using a surrogate key.
func (l *WriteMultiLocker) SurrogateLock(id string, pass Passphrase, unencrypted Plaintext) error {
	if err := l.validateInitialized(); err != nil {
		return err
	}
	sur, ok := l.surKeys[id]
	if !ok {
		return errors.New("surrogate key ID not found")
	}
	passKey, err := l.keyGen.DeriveKey(pass, sur.encryptedPass)
	if err != nil {
		return err
	}
	unencKey, err := Unlock(passKey, sur.encryptedPass)
	if err != nil {
		return ErrInvalidPassword
	}
	basePass := Passphrase(unencKey)
	baseKey, salt, err := l.keyGen.DeriveKeySalt(basePass, l.payload)
	// Ensure the baseKey is valid
	_, err = Unlock(baseKey, l.payload)
	if err != nil {
		return fmt.Errorf("%w: invalid base key", ErrInvalidPassword)
	}
	l.payload, err = Lock(baseKey, salt, unencrypted)
	baseKey = nil
	return err
}
