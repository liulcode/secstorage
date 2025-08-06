package secstorage

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/argon2"
)

const (
	keyLength   = 32 // 32 bytes for AES-256
	saltLength  = 16 // 16 bytes for salt
	nonceLength = 12 // 12 bytes for GCM nonce
	tagLength   = 16 // 16 bytes for GCM tag
)

// deriveKey uses Argon2id to derive a key from a password and salt.
func deriveKey(password []byte, salt []byte, time, memory uint32, threads uint8) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes(argon2.IDKey(password, salt, time, memory, threads, keyLength))
}

// generateSalt creates a new random salt.
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// encrypt data using AES-256-GCM.
// The output is [nonce || ciphertext || tag].
func encrypt(plaintext []byte, key *memguard.LockedBuffer) ([]byte, error) {
	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Seal will append the output to the first argument; we pass nil to allocate a new buffer.
	encrypted := gcm.Seal(nil, nonce, plaintext, nil)
	memguard.WipeBytes(plaintext)
	return append(nonce, encrypted...), nil
}

// decrypt data using AES-256-GCM.
// The input must be [nonce || ciphertext || tag].
func decrypt(ciphertext []byte, key *memguard.LockedBuffer) ([]byte, error) {
	block, err := aes.NewCipher(key.Bytes())
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, actualCiphertext := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]

	// Open will append the output to the first argument; we pass nil to allocate a new buffer.
	decrypted, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	memguard.WipeBytes(ciphertext)
	return decrypted, err
}

// sign data using HMAC-SHA256
func sign(data []byte, key *memguard.LockedBuffer) []byte {
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write(data)
	return mac.Sum(nil)
}

// verify HMAC-SHA256 signature
func verify(data, signature []byte, key *memguard.LockedBuffer) bool {
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(signature, expectedMAC)
}
