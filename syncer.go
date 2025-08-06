package secstorage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/awnumar/memguard"
	"github.com/klauspost/reedsolomon"
)

// EncryptionOptions 封装了加密操作所需的所有参数。
type EncryptionOptions struct {
	Password      string
	DataShards    int
	ParityShards  int
	ChunkSizeKB   int
	Argon2Time    uint32
	Argon2Memory  uint32
	Argon2Threads uint8
}

// SecureSyncer 定义了安全文件同步器的接口，提供了加密和解密文件的核心功能。
type SecureSyncer interface {
	EncryptFile(localPath string, opts EncryptionOptions) (string, error)
	DecryptFile(manifestID, outputPath, password string) error
}

const (
	// defaultDirPerm 定义了创建目录时使用的默认权限。
	defaultDirPerm = 0755
	// defaultFilePerm 定义了创建文件时使用的默认权限。
	defaultFilePerm = 0644
)

// Syncer 是 SecureSyncer 接口的具体实现。
type Syncer struct {
	StorageDir string
}

// NewSyncer 创建一个新的 Syncer 实例。
func NewSyncer(storageDir string) *Syncer {
	return &Syncer{StorageDir: storageDir}
}

// getManifestPath 根据 manifestID 生成并返回 manifest.json 文件的完整路径。
func (s *Syncer) getManifestPath(manifestID string) string {
	return filepath.Join(s.StorageDir, manifestID, "manifest.json")
}

// Manifest 结构体定义了加密文件的元数据，这些元数据以 JSON 格式存储在 manifest.json 文件中。
// 它包含了重建和解密文件所需的所有信息。
type Manifest struct {
	Salt                     []byte     `json:"salt"`
	ChunkPaths               []string   `json:"chunk_paths"`
	EncryptedOrigFilename    []byte     `json:"encrypted_orig_filename"`
	EncryptedDataKeys        [][]byte   `json:"encrypted_data_keys"`
	Argon2Time               uint32     `json:"argon2_time"`
	Argon2Memory             uint32     `json:"argon2_memory"`
	Argon2Threads            uint8      `json:"argon2_threads"`
	Signature                []byte     `json:"signature,omitempty"`
	DataShards               int        `json:"data_shards"`
	ParityShards             int        `json:"parity_shards"`
	ErasureCodeChunkSuffixes [][]string `json:"erasure_code_chunk_suffixes"`
	EncryptedChunkSizes      []int      `json:"encrypted_chunk_sizes"`
}

// EncryptFile 负责加密单个文件，并将其安全地存储到指定的目录中。
func (s *Syncer) EncryptFile(localPath string, opts EncryptionOptions) (manifestID string, err error) {
	// 1. Generate a unique manifest ID
	manifestID, err = generateManifestID()
	if err != nil {
		return "", fmt.Errorf("failed to generate manifest ID: %w", err)
	}

	outputDir := filepath.Join(s.StorageDir, manifestID)
	if err := os.MkdirAll(outputDir, defaultDirPerm); err != nil {
		return "", fmt.Errorf("failed to create output directory: %w", err)
	}

	// 2. Generate salt and derive key
	salt, err := generateSalt()
	if err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	key := deriveKey([]byte(opts.Password), salt, opts.Argon2Time, opts.Argon2Memory, opts.Argon2Threads)
	defer key.Destroy()

	// 3. Handle file chunking and encryption
	file, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	var encryptedChunkPaths []string
	var erasureCodeChunkSuffixes [][]string
	var encryptedChunkSizes []int
	var encryptedDataKeys [][]byte

	chunker := newCDCChunker(file, opts.ChunkSizeKB)
	var chunkNumber int
	for {
		chunk, err := chunker.Next(nil)
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", fmt.Errorf("failed to read chunk: %w", err)
		}

		dataKey, err := generateDataKey()
		if err != nil {
			return "", fmt.Errorf("failed to generate data key for chunk %d: %w", chunkNumber, err)
		}

		encryptedData, err := encrypt(chunk.Data, dataKey)
		if err != nil {
			dataKey.Destroy()
			return "", fmt.Errorf("failed to encrypt chunk %d for file '%s': %w", chunkNumber, localPath, err)
		}

		encryptedKey, err := encrypt(dataKey.Bytes(), key)
		dataKey.Destroy() // Destroy key immediately after use
		if err != nil {
			return "", fmt.Errorf("failed to encrypt data key for chunk %d: %w", chunkNumber, err)
		}
		encryptedDataKeys = append(encryptedDataKeys, encryptedKey)
		encryptedChunkSizes = append(encryptedChunkSizes, len(encryptedData))

		// Erasure code
		enc, err := reedsolomon.New(opts.DataShards, opts.ParityShards)
		if err != nil {
			return "", fmt.Errorf("failed to create erasure code encoder: %w", err)
		}

		shards, err := enc.Split(encryptedData)
		if err != nil {
			return "", fmt.Errorf("failed to split data into shards: %w", err)
		}

		if err := enc.Encode(shards); err != nil {
			return "", fmt.Errorf("failed to encode data shards: %w", err)
		}

		var currentChunkSuffixes []string
		for i, shard := range shards {
			suffix := fmt.Sprintf("_shard_%d.dat", i)
			shardPath := filepath.Join(outputDir, fmt.Sprintf("chunk_%d%s", chunkNumber, suffix))
			if err := os.WriteFile(shardPath, shard, defaultFilePerm); err != nil {
				return "", fmt.Errorf("failed to write shard %d of chunk %d: %w", i, chunkNumber, err)
			}
			currentChunkSuffixes = append(currentChunkSuffixes, suffix)
		}

		chunkBaseName := fmt.Sprintf("chunk_%d", chunkNumber)
		encryptedChunkPaths = append(encryptedChunkPaths, chunkBaseName)
		erasureCodeChunkSuffixes = append(erasureCodeChunkSuffixes, currentChunkSuffixes)
		chunkNumber++
	}

	// 4. Encrypt original filename
	origFilename := filepath.Base(localPath)
	encryptedOrigFilename, err := encrypt([]byte(origFilename), key)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt original filename for file '%s': %w", localPath, err)
	}

	// 5. Create and sign the manifest
	manifest := Manifest{
		Salt:                     salt,
		ChunkPaths:               encryptedChunkPaths,
		EncryptedOrigFilename:    encryptedOrigFilename,
		EncryptedDataKeys:        encryptedDataKeys,
		Argon2Time:               opts.Argon2Time,
		Argon2Memory:             opts.Argon2Memory,
		Argon2Threads:            opts.Argon2Threads,
		DataShards:               opts.DataShards,
		ParityShards:             opts.ParityShards,
		ErasureCodeChunkSuffixes: erasureCodeChunkSuffixes,
		EncryptedChunkSizes:      encryptedChunkSizes,
	}

	manifestData, err := json.Marshal(manifest)
	if err != nil {
		return "", fmt.Errorf("failed to marshal manifest for signing: %w", err)
	}

	manifest.Signature = sign(manifestData, key.Bytes())

	finalManifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal final manifest: %w", err)
	}

	// 7. Save the manifest
	if err := os.WriteFile(s.getManifestPath(manifestID), finalManifestData, defaultFilePerm); err != nil {
		return "", fmt.Errorf("failed to write manifest: %w", err)
	}

	return manifestID, nil
}

// DecryptFile 负责从存储中解密文件。
func (s *Syncer) DecryptFile(manifestID, outputPath, password string) (err error) {
	// Ensure the output directory exists
	if err := os.MkdirAll(filepath.Dir(outputPath), defaultDirPerm); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	// 1. Read and validate the manifest
	manifestPath := s.getManifestPath(manifestID)
	manifestData, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("failed to read manifest from %s: %w", manifestPath, err)
	}

	var manifest Manifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// Temporarily remove signature for verification
	signature := manifest.Signature
	manifest.Signature = nil
	unsignedManifestData, err := json.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("failed to marshal unsigned manifest for verification: %w", err)
	}

	// 2. Derive key from password
	pass := memguard.NewBufferFromBytes([]byte(password))
	defer pass.Destroy()
	key := deriveKey(pass.Bytes(), manifest.Salt, manifest.Argon2Time, manifest.Argon2Memory, manifest.Argon2Threads)
	defer key.Destroy()

	if !verify(unsignedManifestData, signature, key.Bytes()) {
		return fmt.Errorf("manifest signature verification failed")
	}



	// 4. Decrypt original filename
	decryptedOrigFilename, err := decrypt(manifest.EncryptedOrigFilename, key)
	if err != nil {
		return fmt.Errorf("failed to decrypt original filename: %w", err)
	}



	finalOutputPath := filepath.Join(outputPath, string(decryptedOrigFilename))
	outputFile, err := os.Create(finalOutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outputFile.Close()

	// 5. Reconstruct and decrypt chunks
	enc, err := reedsolomon.New(manifest.DataShards, manifest.ParityShards)
	if err != nil {
		return fmt.Errorf("failed to create erasure code decoder: %w", err)
	}

	for i, chunkBaseName := range manifest.ChunkPaths {
		shards := make([][]byte, manifest.DataShards+manifest.ParityShards)
		shardPresentCount := 0

		for j, suffix := range manifest.ErasureCodeChunkSuffixes[i] {
			shardPath := filepath.Join(s.StorageDir, manifestID, fmt.Sprintf("%s%s", chunkBaseName, suffix))
			data, err := os.ReadFile(shardPath)
			if err != nil {
				if !os.IsNotExist(err) {
					return fmt.Errorf("failed to read shard %s: %w", shardPath, err)
				}
				shards[j] = nil // Mark missing shard as nil
			} else {
				shards[j] = data
				shardPresentCount++
			}
		}

		if shardPresentCount < manifest.DataShards {
			return fmt.Errorf("not enough shards to reconstruct chunk %d: have %d, need %d", i, shardPresentCount, manifest.DataShards)
		}

		// Verify the shards, and reconstruct if necessary.
		ok, err := enc.Verify(shards)
		if !ok {
			if err != nil { // Log the verification error
				fmt.Printf("Shard verification failed for chunk %d: %v. Attempting reconstruction.\n", i, err)
			}
			if err := enc.Reconstruct(shards); err != nil {
				return fmt.Errorf("failed to reconstruct chunk %d after verification failure: %w", i, err)
			}
		}

		var encryptedData bytes.Buffer
		if err := enc.Join(&encryptedData, shards, manifest.EncryptedChunkSizes[i]); err != nil {
			return fmt.Errorf("failed to join shards for chunk %d: %w", i, err)
		}

		// Decrypt data key
		dataKeyBytes, err := decrypt(manifest.EncryptedDataKeys[i], key)
		if err != nil {
			return fmt.Errorf("failed to decrypt data key for chunk %d: %w", i, err)
		}
		dataKey := memguard.NewBufferFromBytes(dataKeyBytes)

		// Decrypt chunk data
		decryptedData, err := decrypt(encryptedData.Bytes(), dataKey)
		dataKey.Destroy() // Destroy key immediately after use
		if err != nil {
			return fmt.Errorf("failed to decrypt chunk %d: %w", i, err)
		}

		if _, err := outputFile.Write(decryptedData); err != nil {
			return fmt.Errorf("failed to write decrypted chunk %d to file: %w", i, err)
		}
	}

	return nil
}
