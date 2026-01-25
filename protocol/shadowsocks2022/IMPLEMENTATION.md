# Shadowsocks 2022 协议实现文档

## 概述

本文档记录了 Shadowsocks 2022 (SS2022) 协议在 outbound 库中的实现细节，包括协议规范、参考代码分析和实现要点。

## 参考实现

- **shadowsocks-go**: https://github.com/database64128/shadowsocks-go
  - 主要参考目录: `ss2022/`
  - 关键文件: `crypto.go`, `header.go`, `stream.go`, `udp.go`, `packet.go`

- **sing-shadowsocks2**: https://github.com/SagerNet/sing-shadowsocks2
  - 主要参考目录: `shadowaead_2022/`
  - 关键文件: `protocol.go`, `method.go`, `slidingwindow.go`

---

## 协议规范

### 支持的加密方法

| 方法 | 密钥长度 | Salt 长度 | 备注 |
|------|----------|-----------|------|
| `2022-blake3-aes-128-gcm` | 16 字节 | 16 字节 | 支持 EIH |
| `2022-blake3-aes-256-gcm` | 32 字节 | 32 字节 | 支持 EIH |
| `2022-blake3-chacha20-poly1305` | 32 字节 | 32 字节 | 不支持 EIH |

### 密钥派生

使用 BLAKE3 进行密钥派生：

```go
// 会话子密钥派生
// Context: "shadowsocks 2022 session subkey"
func DeriveSessionKey(psk, salt []byte, keyLen int) []byte {
    keyMaterial := append(psk, salt...)
    subkey := make([]byte, keyLen)
    blake3.DeriveKey(subkey, "shadowsocks 2022 session subkey", keyMaterial)
    return subkey
}

// 身份子密钥派生 (用于 TCP EIH)
// Context: "shadowsocks 2022 identity subkey"
func DeriveIdentitySubkeyWithSalt(iPSK, salt []byte, keyLen int) []byte {
    keyMaterial := append(iPSK, salt...)
    subkey := make([]byte, keyLen)
    blake3.DeriveKey(subkey, "shadowsocks 2022 identity subkey", keyMaterial)
    return subkey
}
```

### PSK 哈希

```go
// 用于 EIH 身份验证
func PSKHash(psk []byte) [16]byte {
    hash := blake3.Sum512(psk)
    var result [16]byte
    copy(result[:], hash[:16])
    return result
}
```

---

## TCP 协议

### 请求格式

```
+--------+------------------+---------------------+----------------------+
|  Salt  | Identity Headers |  Encrypted Fixed    | Encrypted Variable   |
|        |    (optional)    |       Header        |       Header         |
+--------+------------------+---------------------+----------------------+
| 16/32B |   N * 16B        | 11B + 16B tag       | variable + 16B tag   |
+--------+------------------+---------------------+----------------------+
```

#### 固定头 (11 字节)

```
+------+---------------+--------+
| Type |   Timestamp   | Length |
+------+---------------+--------+
|  1B  | 8B unix epoch |  u16be |
+------+---------------+--------+
```

- Type: 0 = 客户端请求, 1 = 服务端响应
- Timestamp: Unix 时间戳，允许 ±30 秒误差
- Length: 可变头长度

#### 可变头

```
+------+----------+-------+----------------+----------+-----------------+
| ATYP |  Address |  Port | Padding Length |  Padding | Initial Payload |
+------+----------+-------+----------------+----------+-----------------+
|  1B  | variable | u16be |     u16be      | variable |    variable     |
+------+----------+-------+----------------+----------+-----------------+
```

**注意**: Padding Length 在地址之后，Initial Payload 在最后。

### 响应格式

```
+--------+---------------------+----------------------+
|  Salt  |  Encrypted Response |  Encrypted Payload   |
|        |       Header        |       Chunk          |
+--------+---------------------+----------------------+
| 16/32B | (11+SaltLen)B + tag | variable + 16B tag   |
+--------+---------------------+----------------------+
```

#### 响应头

```
+------+---------------+----------------+--------+
| Type |   Timestamp   |  Request Salt  | Length |
+------+---------------+----------------+--------+
|  1B  | 8B unix epoch |    16/32B      |  u16be |
+------+---------------+----------------+--------+
```

- Request Salt: 客户端请求中的 salt，用于验证响应
- Length: 第一个 payload chunk 的长度

### 数据传输 (Chunk 格式)

```
+------------------------+---------------------------+
| Encrypted Length Chunk |  Encrypted Payload Chunk  |
+------------------------+---------------------------+
|   2B length + 16B tag  | variable length + 16B tag |
+------------------------+---------------------------+
```

### TCP 身份头 (EIH)

对于多用户模式，在 salt 之后添加身份头：

```go
// 派生身份子密钥
identitySubkey := DeriveIdentitySubkeyWithSalt(iPSK, salt, keyLen)

// 计算 uPSK 哈希
uPSKHash := PSKHash(uPSK)

// AES-ECB 加密
block, _ := aes.NewCipher(identitySubkey[:16])
identityHeader := make([]byte, 16)
block.Encrypt(identityHeader, uPSKHash[:])
```

---

## UDP 协议

### 包格式 (AES-GCM)

```
+-------------------+------------------+---------------------------+
| Encrypted Separate|  Identity Headers|     Encrypted Message     |
|      Header       |    (optional)    |                           |
+-------------------+------------------+---------------------------+
|       16B         |     N * 16B      |   variable + 16B tag      |
+-------------------+------------------+---------------------------+
```

### 分离头 (Separate Header)

```
+------------+-----------+
| Session ID | Packet ID |
+------------+-----------+
|     8B     |   u64be   |
+------------+-----------+
```

- 使用 AES-ECB 加密整个 16 字节
- **Nonce**: 分离头的后 12 字节 (偏移 4-16)，在加密前提取

### 会话密钥派生

```go
// 使用 session ID (前 8 字节) 作为 salt
sessionKey := DeriveSessionKey(psk, sessionID[:8], keyLen)
```

### 客户端消息

```
+------+---------------+----------------+----------+------+----------+-------+----------+
| Type |   Timestamp   | Padding Length |  Padding | ATYP |  Address |  Port |  Payload |
+------+---------------+----------------+----------+------+----------+-------+----------+
|  1B  | 8B unix epoch |     u16be      | variable |  1B  | variable | u16be | variable |
+------+---------------+----------------+----------+------+----------+-------+----------+
```

### 服务端消息

```
+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
| Type |   Timestamp   | Client Session ID | Padding Length |  Padding | ATYP |  Address |  Port |  Payload |
+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
|  1B  | 8B unix epoch |         8B        |     u16be      | variable |  1B  | variable | u16be | variable |
+------+---------------+-------------------+----------------+----------+------+----------+-------+----------+
```

### UDP 身份头 (EIH)

```go
// XOR uPSK 哈希与分离头
xored := make([]byte, 16)
subtle.XORBytes(xored, uPSKHash[:], separateHeader[:16])

// AES-ECB 加密 (使用 iPSK 直接)
block, _ := aes.NewCipher(iPSK[:16])
identityHeader := make([]byte, 16)
block.Encrypt(identityHeader, xored)
```

**关键区别**: UDP 身份头使用 `iPSK` 直接作为密钥，而 TCP 身份头使用派生的子密钥。

---

## 重放防护

### TCP

- 使用 salt 作为唯一标识
- 可选使用 bloom filter 检测重复 salt

### UDP

使用滑动窗口过滤器：

```go
type SlidingWindowFilter struct {
    lastID     uint64
    windowSize uint64
    bitmap     []uint64  // 每个 uint64 可跟踪 64 个 packet ID
}

// 检查 packet ID 是否有效 (非重放)
func (f *SlidingWindowFilter) Check(id uint64) bool {
    // 1. 如果 ID 太旧 (在窗口之前)，拒绝
    // 2. 如果 ID 更新，滑动窗口
    // 3. 如果 ID 在窗口内，检查是否已见过
}
```

### 服务端会话跟踪

客户端需要跟踪服务端会话变化：

```go
type serverSessionState struct {
    currentSessionID    uint64
    currentCipher       cipher.AEAD
    currentFilter       *SlidingWindowFilter

    oldSessionID        uint64
    oldCipher           cipher.AEAD
    oldFilter           *SlidingWindowFilter
    oldLastSeen         time.Time
}
```

- 保留当前会话和上一个会话
- 如果会话在 60 秒内变化超过一次，拒绝新会话

---

## URL 格式

### 单用户模式

```
ss://BASE64(method:BASE64_PSK)@server:port#name
```

示例:
```
ss://MjAyMi1ibGFrZTMtYWVzLTI1Ni1nY206QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE=@example.com:8388#MyServer
```

### 多用户模式 (EIH)

```
ss://BASE64(method:BASE64_iPSK:BASE64_uPSK)@server:port#name
```

---

## 实现文件结构

```
protocol/shadowsocks2022/
├── cipher.go       # BLAKE3 密钥派生和 cipher 配置
├── header.go       # 固定头/可变头编解码，时间戳验证，地址编解码
├── identity.go     # EIH 多用户身份头处理
├── tcp_conn.go     # TCP 连接实现
├── udp_conn.go     # UDP 连接实现
├── dialer.go       # 协议 dialer，注册 "shadowsocks2022"
├── replay.go       # 滑动窗口重放防护
└── *_test.go       # 单元测试
```

---

## 关键实现细节

### 1. Nonce 递增

使用小端序递增：

```go
func BytesIncLittleEndian(b []byte) {
    for i := 0; i < len(b); i++ {
        b[i]++
        if b[i] != 0 {
            break
        }
    }
}
```

### 2. AEAD 操作

```go
// 加密
ciphertext := aead.Seal(dst[:0], nonce, plaintext, nil)
increment(nonce)

// 解密
plaintext, err := aead.Open(dst[:0], nonce, ciphertext, nil)
if err == nil {
    increment(nonce)
}
```

### 3. 时间戳验证

```go
const MaxEpochDiff = 30 // 秒

func ValidateTimestamp(timestamp uint64) error {
    now := uint64(time.Now().Unix())
    diff := int64(timestamp) - int64(now)
    if diff < 0 {
        diff = -diff
    }
    if diff > MaxEpochDiff {
        return ErrBadTimestamp
    }
    return nil
}
```

---

## 与传统 Shadowsocks 的区别

| 特性 | 传统 SS | SS2022 |
|------|---------|--------|
| 密钥派生 | HKDF-SHA1 | BLAKE3 |
| 密码格式 | 明文密码 | Base64 编码的 PSK |
| TCP 头部 | Salt + 加密数据 | Salt + 固定头(时间戳) + 可变头 |
| 时间验证 | 无 | ±30秒 |
| 响应验证 | 无 | 响应包含请求 Salt |
| 多用户 | 不支持 | EIH (Encrypted Identity Header) |
| UDP 格式 | Salt + 加密数据 | 分离头 + 身份头(可选) + 加密消息 |

---

## 测试

```bash
# 运行单元测试
go test ./protocol/shadowsocks2022/... -v

# 运行构建
go build ./...

# 运行 dialer 测试
go test ./dialer/shadowsocks/... -v
```

---

## 参考资料

- [Shadowsocks 2022 Edition 规范](https://github.com/Shadowsocks-NET/shadowsocks-specs/blob/main/2022-1-shadowsocks-2022-edition.md)
- [shadowsocks-go 实现](https://github.com/database64128/shadowsocks-go)
- [sing-shadowsocks2 实现](https://github.com/SagerNet/sing-shadowsocks2)
