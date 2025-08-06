package secstorage

import (
	"os"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Config 定义了应用程序的所有配置选项。
// 这些选项可以从一个 YAML 文件中加载。

type Config struct {
	// ChunkSizeKB 定义了内容分块的平均大小（以 KB 为单位）。
	ChunkSizeKB int `yaml:"chunk_size_kb"`
	// DataShards 定义了纠删码所需的数据分片数。
	DataShards int `yaml:"data_shards"`
	// ParityShards 定义了纠删码所需的奇偶校验分片数。
	ParityShards int `yaml:"parity_shards"`
	// Argon2 包含了用于密钥派生的 Argon2 算法的配置。
	Argon2 Argon2Config `yaml:"argon2"`
	// StoragePath 定义了加密文件存储的根目录。
	StoragePath string `yaml:"storage_path"`
}

// Argon2Config 定义了 Argon2 密钥派生函数的参数。

type Argon2Config struct {
	// Time 是 Argon2 算法的迭代次数。
	Time uint32 `yaml:"time"`
	// MemoryKB 是 Argon2 算法应使用的内存量（以 KB 为单位）。
	MemoryKB uint32 `yaml:"memory_kb"`
	// Threads 是 Argon2 算法可以使用的 CPU 线程数。
	Threads uint8 `yaml:"threads"`
}

// LoadConfig 从指定的路径加载 YAML 配置文件并解析它。
// 它返回一个包含配置的 Config 结构体指针，或者在出错时返回一个错误。
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file at %s: %w", path, err)
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config YAML: %w", err)
	}

	// Here you could add validation for the config values, e.g.:
	if config.ChunkSizeKB <= 0 {
		return nil, fmt.Errorf("chunk_size_kb must be positive")
	}
	if config.DataShards <= 0 || config.ParityShards <= 0 {
		return nil, fmt.Errorf("data_shards and parity_shards must be positive")
	}

	return &config, nil
}
