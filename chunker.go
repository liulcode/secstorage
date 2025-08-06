package secstorage

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/restic/chunker"
)

// newCDCChunker 创建一个新的内容定义分块器 (Content-Defined Chunker)。
// CDC 是一种智能的分块算法，它根据文件内容本身来决定如何分块。
// 这意味着即使文件内容有小的改动，大部分分块的哈希值仍然保持不变，非常适合增量备份和去重场景。
func newCDCChunker(r io.Reader, chunkSizeKB int) *chunker.Chunker {
	// The polynomial is chosen based on the desired average chunk size.
	// See https://github.com/restic/chunker/blob/master/chunker_test.go#L24 for details.
	// We use NewWithBoundaries to enforce our own size limits based on the config.
	// This makes the chunker create chunks with sizes between chunkSizeKB/2 and chunkSizeKB*2.
	avgSize := uint(chunkSizeKB * 1024)
	minSize := avgSize / 2
	maxSize := avgSize * 2

	// 注意：下面的多项式是为 1MiB 平均块大小优化的。
	// 如果在配置中设置了显著不同于 1MiB 的 chunk_size_kb，
	// 分块效率可能会降低。为了获得最佳性能，
	// 应根据平均块大小动态生成或选择多项式。
	// 为简单起见，我们在这里使用一个固定的值。
	poly := chunker.Pol(0x3DA3358B4DC173) // Corresponds to 1MiB average

	return chunker.NewWithBoundaries(r, poly, minSize, maxSize)
}

// generateManifestID 为清单 (manifest) 生成一个唯一的16字节（32个十六进制字符）ID。
// 这个 ID 用于唯一标识一次加密操作产生的所有文件和元数据。
func generateManifestID() (string, error) {
	bytes := make([]byte, 16) // 16 bytes = 32 hex characters
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}
