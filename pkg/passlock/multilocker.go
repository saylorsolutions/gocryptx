package passlock

const (
	magicBytes        uint16 = 0x1ff1
	magicBytesInverse uint16 = 0xf11f
	idFieldLen               = 32
)

type MultiLocker struct {
	numKeys      int
	id           [][idFieldLen]byte
	len          []int
	encryptedKey [][]byte
	payload      []byte

	key         []byte
	multiKeyGen *KeyGenerator
	keyGen      *KeyGenerator
}
