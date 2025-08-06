package secstorage

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ChunkSizeKB int          `yaml:"chunk_size_kb"`
	Argon2      Argon2Config `yaml:"argon2"`
	StoragePath string       `yaml:"storage_path"`
}

type Argon2Config struct {
	Time     uint32 `yaml:"time"`
	MemoryKB uint32 `yaml:"memory_kb"`
	Threads  uint8  `yaml:"threads"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}
