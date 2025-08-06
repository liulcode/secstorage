package secstorage

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	_ "github.com/awnumar/memguard"
)

// SecureSyncer defines the interface for the secure file syncer.
type SecureSyncer interface {
	EncryptFile(localPath, password string, chunkSizeKB int, argon2Time, argon2Memory uint32, argon2Threads uint8) (string, error)
	DecryptFile(manifestID, outputPath, password string) error
}

// Syncer implements the SecureSyncer interface.
type Syncer struct {
	StorageDir string
}

// NewSyncer creates a new Syncer.
func NewSyncer(storageDir string) *Syncer {
	return &Syncer{StorageDir: storageDir}
}

// Manifest stores metadata about an encrypted file.
type Manifest struct {
	Salt                  []byte   `json:"salt"`
	ChunkPaths            []string `json:"chunk_paths"`
	ChunkSize             int      `json:"chunk_size"`
	EncryptedOrigFilename []byte   `json:"encrypted_orig_filename"`
	Argon2Time            uint32   `json:"argon2_time"`
	Argon2Memory          uint32   `json:"argon2_memory"`
	Argon2Threads         uint8    `json:"argon2_threads"`
	Signature             []byte   `json:"signature,omitempty"`
}

// EncryptFile encrypts a file, splits it into chunks, and stores it.
func (s *Syncer) EncryptFile(localPath, password string, chunkSizeKB int, argon2Time, argon2Memory uint32, argon2Threads uint8) (string, error) {
	// 1. Generate a unique manifest ID
	manifestID, err := randomHex(16)
	if err != nil {
		return "", fmt.Errorf("failed to generate manifest ID: %w", err)
	}

	outputDir := filepath.Join(s.StorageDir, manifestID)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// 2. Generate salt and derive key
	salt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	key := deriveKey([]byte(password), salt, argon2Time, argon2Memory, argon2Threads)
	defer key.Destroy()

	// 3. Split the file into chunks
	chunker, err := NewFileChunker(chunkSizeKB)
	if err != nil {
		return "", err
	}

	file, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %w", err)
	}
	if fileInfo.Size() == 0 {
		return "", fmt.Errorf("input file is empty")
	}

	var encryptedChunkPaths []string
	buffer := make([]byte, chunker.ChunkSize)
	for i := 0; ; i++ {
		n, err := file.Read(buffer)
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		if n == 0 {
			break
		}

		// 4. Encrypt each chunk
		encryptedData, err := encrypt(buffer[:n], key)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt chunk %d for file '%s': %w", i, localPath, err)
		}

		randomSuffix, err := randomHex(4)
		if err != nil {
			return "", err
		}

		chunkFileName := fmt.Sprintf("chunk_%d_%s.dat", i, randomSuffix)
		chunkPath := filepath.Join(outputDir, chunkFileName)

		if err := os.WriteFile(chunkPath, encryptedData, 0644); err != nil {
			return "", fmt.Errorf("failed to write chunk %d: %w", i, err)
		}
		encryptedChunkPaths = append(encryptedChunkPaths, chunkFileName)
	}

	// 5. Encrypt original filename
	origFilename := filepath.Base(localPath)
	encryptedOrigFilename, err := encrypt([]byte(origFilename), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt original filename for file '%s': %w", localPath, err)
	}

	// 6. Create and save the manifest
	manifest := Manifest{
		Salt:                  salt,
		ChunkPaths:            encryptedChunkPaths,
		ChunkSize:             chunker.ChunkSize,
		EncryptedOrigFilename: encryptedOrigFilename,
		Argon2Time:            argon2Time,
		Argon2Memory:          argon2Memory,
		Argon2Threads:         argon2Threads,
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal manifest: %w", err)
	}

	// 7. Sign the manifest
	manifest.Signature = sign(manifestData, key)
	manifestData, err = json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to re-marshal manifest with signature: %w", err)
	}

	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := os.WriteFile(manifestPath, manifestData, 0644); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	return manifestID, nil
}

// DecryptFile decrypts a file from chunks.
func (s *Syncer) DecryptFile(manifestID, outputPath, password string) error {
	outputDir := filepath.Join(s.StorageDir, manifestID)
	manifestPath := filepath.Join(outputDir, "manifest.json")

	// 1. Read the manifest
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// 2. Derive the key
	key := deriveKey([]byte(password), manifest.Salt, manifest.Argon2Time, manifest.Argon2Memory, manifest.Argon2Threads)
	defer key.Destroy()

	// 3. Verify the signature
	signature := manifest.Signature
	manifest.Signature = nil // Clear signature for verification
	unsignedManifestData, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal manifest for verification: %w", err)
	}
	if !verify(unsignedManifestData, signature, key) {
		return fmt.Errorf("manifest signature verification failed: data may be tampered or password may be incorrect")
	}

	if len(manifest.ChunkPaths) == 0 {
		return fmt.Errorf("manifest contains no chunks to decrypt")
	}

	// 4. Determine output path
	finalOutputPath := outputPath
	if len(finalOutputPath) == 0 {
		decryptedOrigFilename, err := decrypt(manifest.EncryptedOrigFilename, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt original filename (likely due to incorrect password): %w", err)
		}
		finalOutputPath = string(decryptedOrigFilename)
	}

	// 5. Create the output file
	outputFile, err := os.Create(finalOutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// 6. Decrypt and write each chunk
	for i, chunkFileName := range manifest.ChunkPaths {
		chunkPath := filepath.Join(outputDir, chunkFileName)
		encryptedData, err := os.ReadFile(chunkPath)
		if err != nil {
			return fmt.Errorf("failed to read chunk %d (%s): %w", i, chunkPath, err)
		}

		decryptedData, err := decrypt(encryptedData, key)
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d (%s): %w", i, chunkPath, err)
		}

		if _, err := outputFile.Write(decryptedData); err != nil {
			return fmt.Errorf("failed to write chunk %d to output file: %w", i, err)
		}
	}

	return nil
}
