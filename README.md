# SecStorage
SecStorage 是一个基于 Go 语言的文件加密存储库，它提供了一种简单的方式来加密存储文件，同时确保数据的安全性。

这个项目的目标是将文件切割加密为多个块，这些块文件可以被自由且安全的放置在任何存储设备上，当然也包括云端存储。

## 使用
```go
package main

import (
	"fmt"
	"log"

	secstorage "github.com/liulcode/secstorage"
)

func main() {
	// config, err := secstorage.LoadConfig(*configPath)
	// if err != nil {
	// 	log.Fatalf("Failed to load config: %v", err)
	// }

	storageDir := "./storage"
	ChunkSizeKB := 1024
	argon2Time := 3
	argon2MemoryKB := 65536
	argon2Threads := 4

	password := "testpassword" //密码，加密解密均需要，建议实际使用时从用户输入读取

	/**
	 * 如果使用配置文件，可以通过config获取配置信息（当然也可以自己定义处理）
	 * var configPath = flag.String("config", "config.yaml", "Path to the configuration file")
	 * config, err := secstorage.LoadConfig(*configPath)
	 * storageDir := config.StoragePath
	 * ChunkSizeKB := config.ChunkSizeKB
	 * argon2Time := config.Argon2.Time
	 * argon2MemoryKB := config.Argon2.MemoryKB
	 * argon2Threads := config.Argon2.Threads
	 **/

	syncer := secstorage.NewSyncer(storageDir)

	options := secstorage.EncryptionOptions{
		Password:      password,
		DataShards:    10,
		ParityShards:  3,
		ChunkSizeKB:   ChunkSizeKB,
		Argon2Time:    uint32(argon2Time),
		Argon2Memory:  uint32(argon2MemoryKB),
		Argon2Threads: uint8(argon2Threads),
	}

	//加密文件
	manifestID, err := syncer.EncryptFile("./testfile.txt", options)
	//此处manifestID为加密后的文件目录，后续解密需要传递这个目录（可任意修改）
	if err != nil {
		log.Fatalf("加密文件失败: %v", err)
	}
	fmt.Printf("加密文件成功. 加密后的文件目录为: %s\n", manifestID)

	//解密还原文件
	if err := syncer.DecryptFile("manifestID", "", password); err != nil {
		log.Fatalf("还原文件失败: %v", err)
	}
	fmt.Println("还原文件成功")
}
```

## Thanks
这是一个 AI 生成项目，感谢科技的进步。

项目代码大部分由 AI 生成，魔法咒语在 prompt 目录中提供。
