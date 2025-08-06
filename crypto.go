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
	// keyLength 定义了 AES-256 加密所需的密钥长度（32字节）。
	keyLength = 32
	// saltLength 定义了生成盐值的长度（16字节）。
	saltLength = 16
)

// deriveKey 使用 Argon2id 从密码和盐值派生出加密密钥。
// 为了增强安全性，返回的密钥存储在 memguard 的 LockedBuffer 中，以防止内存泄漏。
func deriveKey(password []byte, salt []byte, time, memory uint32, threads uint8) *memguard.LockedBuffer {
	return memguard.NewBufferFromBytes(argon2.IDKey(password, salt, time, memory, threads, keyLength))
}

// generateDataKey 生成一个用于数据加密的随机密钥。
func generateDataKey() (*memguard.LockedBuffer, error) {
	key := make([]byte, keyLength)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return memguard.NewBufferFromBytes(key), nil
}

// generateSalt 生成一个用于密钥派生的随机盐值。
func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}



// encrypt 使用 AES-256-GCM 算法加密数据。
// GCM 提供认证加密，无需额外的填充（如 PKCS#7）。
// 输出格式为：[nonce || ciphertext || tag]。
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

	encrypted := gcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, encrypted...), nil
}

// decrypt 使用 AES-256-GCM 算法解密数据。
// GCM 会自动处理认证和解密，无需手动移除填充。
// 输入格式必须为：[nonce || ciphertext || tag]。
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

	return gcm.Open(nil, nonce, actualCiphertext, nil)
}

// sign 使用 HMAC-SHA256 算法为数据生成签名。
// 这用于验证数据的完整性和来源，例如在 manifest 文件上签名。
// 注意：AES-GCM 已经为其加密的数据提供了认证，因此对于加密块本身，此签名是多余的。
func sign(data []byte, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// verify 验证 HMAC-SHA256 签名。
// 如果签名有效，则返回 true。
func verify(data, signature []byte, key []byte) bool {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(signature, expectedMAC)
}
