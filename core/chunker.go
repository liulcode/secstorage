package secstorage

import (
	"crypto/rand"
	"fmt"
)

const (
	// DefaultChunkSize is the default size for file chunks (4MB).
	DefaultChunkSize = 4 * 1024 * 1024  // 4MB
	MinChunkSize     = 64 * 1024        // 64KB
	MaxChunkSize     = 16 * 1024 * 1024 // 16MB
)

// FileChunker is responsible for splitting files into chunks and reassembling them.

type FileChunker struct {
	ChunkSize int
}

// NewFileChunker creates a new FileChunker with a given chunk size.
func NewFileChunker(chunkSizeKB int) (*FileChunker, error) {
	chunkSize := chunkSizeKB * 1024
	if chunkSize < MinChunkSize || chunkSize > MaxChunkSize {
		return nil, fmt.Errorf("chunk size must be between %dKB and %dKB", MinChunkSize/1024, MaxChunkSize/1024)
	}
	return &FileChunker{ChunkSize: chunkSize}, nil
}

// randomHex generates a random hex string of n bytes.
func randomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}
