**核心目标：**
开发一个安全的文件加解密系统，实现以下流程：
```
原始文件 → 分块处理 → 加密 → 存储到指定目录/上传公网 → 下载 → 解密 → 合并还原
```

**关键需求：**
1. **安全架构要求：**
   - 端到端加密（E2EE）设计
   - 使用AES-256-GCM认证加密模式
   - Argon2id密钥派生（参数：time=1, memory=64MB, threads=4）
   - 每个数据块必须使用唯一随机nonce
   - 主密码绝不存储/传输

2. **分块处理规范：**
   - 分块数据存储在元文件同名目录下
   - 动态分块大小：64-16384KB可配置，单位为KB
   - 文件名格式：`chunk_{index}_{8位随机十六进制}.dat`

3. **加密流程：**
   ```
   用户密码 + 随机盐 → Argon2id派生密钥 → 
   for 每个块:
       生成随机nonce → 
       AES-GCM加密 → 
       输出格式 [nonce(12B) || 密文 || 认证标签(16B)]
   ```

4. **解密验证：**
   - 严格验证GCM认证标签
   - 块完整性检查失败时中止并告警
   - 内存安全：密钥使用后立即清零

5. **其他要求：**
   - 传输层加密：强制HTTPS或者TLS+其他协议
   - 实现块级断点续传

**开发约束：**
- 语言：Go 1.20+
- 加密库：crypto/aes + golang.org/x/crypto/argon2
- 禁止：自行实现加密算法、ECB/CBC模式
- 内存安全：使用`memguard`保护敏感数据

**验收标准：**
1. 加密文件能抵抗已知明文攻击
2. 修改单个块不影响其他块解密
3. 10GB文件处理内存占用<100MB
4. 通过以下测试：
   ```go
   // 加密解密循环测试
   orig := randomData(1GB) 
   encrypted := encrypt(orig, password)
   decrypted := decrypt(encrypted, password)
   assert(sha256(orig) == sha256(decrypted))
   
   // 篡改检测测试
   tamperedChunk = modifyRandomByte(encryptedChunk)
   assert(decrypt(tamperedChunk) → error
   ```

**交付物要求：**
- API设计：
  ```go
  type SecureSyncer interface {
      EncryptFile(localPath string, password string) (manifestID string, error)
      DecryptFile(manifestID string, outputPath string, password string) error
  }
  ```
- 性能指标：
  - 加密吞吐量 ≥ 200MB/s
  - 密钥派生延迟：500-1000ms
- 文档：
  - 威胁模型分析文档
  - 密钥管理流程图

**参考实现提示：**
```go
// 关键安全操作示例：
func secureDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
    nonce := ciphertext[:12]
    actualCiphertext := ciphertext[12:]
    
    block, _ := aes.NewCipher(key)
    gcm, _ := cipher.NewGCM(block)
    
    // 自动验证认证标签
    plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
    runtime.Memzero(key) // 立即清除密钥
    
    return plaintext, err
}
```

**例外场景处理：**
1. 密码丢失：返回硬错误（无恢复后门）
2. 网络中断：实现块级重传
3. 存储损坏：提供块校验和验证