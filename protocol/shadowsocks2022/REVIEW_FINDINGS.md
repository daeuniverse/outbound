# Shadowsocks 2022 实现检查问题清单

按严重度排序，基于对照：
- 实现代码：`/Users/chulq/Code/outbound/protocol/shadowsocks2022`
- 参考实现：`/Users/chulq/Code/shadowsocks-go/ss2022` 与 `/Users/chulq/Code/sing-shadowsocks2/shadowaead_2022`

## 严重

1. **[已修复] TCP 首次写入会重复发送首段数据（协议层数据损坏）**
   `Write` 里 `initWrite(b)` 已把 `b` 当作 initial payload 写进可变头，随后 `Write` 又把同一份 `b` 作为 chunk 再写一次。
   - 位置：`protocol/shadowsocks2022/tcp_conn.go:67-99` 与 `protocol/shadowsocks2022/tcp_conn.go:103-156`
   - 修复：添加 `firstWriteDone` 标志，确保首次写入数据不会再作为 chunk 重发

2. **[已修复] TCP 可变头长度未限制，存在 u16 溢出与超大首包问题**
   `varHeaderLen` 含 `len(initialData)` 后被 `uint16(varHeaderLen)` 写入固定头，若首次写入超过 65535 会溢出导致解析错位。
   - 位置：`protocol/shadowsocks2022/tcp_conn.go:141-157`
   - 修复：添加 `MaxInitialPayloadLen` 常量限制首包大小，并在 `initWrite` 中检查溢出

## 高

1. **[已修复] UDP 多用户（EIH）时，client→server 的 separate header 加密 key 用错**
   当前 `headerBlockCipher` 使用 `psk`（uPSK）初始化并用于加解密。参考实现中，客户端发包时应使用 `iPSK` 加密 separate header（便于服务器先解 header 与 identity header）；服务端回包才用 `uPSK`，客户端用 `uPSK` 解密。
   - 位置：`protocol/shadowsocks2022/udp_conn.go:88-92`
   - 修复：分离 `clientHeaderBlockCipher`（使用 iPSK）和 `serverHeaderBlockCipher`（使用 uPSK）

2. **[已修复] UDP 的 chacha20-poly1305 路径不符合 SS2022 规范实现**
   目前所有方法都使用 16B separate header + AES-ECB，但参考实现对 chacha20 使用 24B nonce header（XChaCha20-Poly1305）且不支持 EIH。当前实现会与标准实现不互通。
   - 位置：`protocol/shadowsocks2022/cipher.go` 与 `protocol/shadowsocks2022/udp_conn.go:179-200`
   - 修复：
     - `cipher.go`：添加 `UDPCipherMode` 枚举区分 AES/ChaCha 模式，为 ChaCha20 配置 `NewUDPCipher: chacha20poly1305.NewX`
     - `udp_conn.go`：实现双模式 WriteTo/ReadFrom，ChaCha20 使用 24B nonce（SessionID+PacketID+Random）+ XChaCha20-Poly1305

3. **[已修复] AES-256 路径下 AES-ECB 使用了错误的密钥长度**
   `CreateECBEncryptor/CreateECBDecryptor` 与 UDP/TCP EIH 相关逻辑固定使用 `key[:16]`，导致 AES-256 方法被当成 AES-128 使用，和标准实现不兼容。
   - 位置：`protocol/shadowsocks2022/identity.go:96-128`
   - 修复：添加 `CreateECBEncryptorWithKeyLen` 和 `CreateECBDecryptorWithKeyLen` 函数，根据 keyLen 选择 AES-128 或 AES-256

4. **[已修复] UDP Packet ID 起始值应为 1**
   当前 `packetID` 从 0 开始（`Add(1)-1`），而参考实现明确"AEAD-2022 Packet ID starts from 1"。
   - 位置：`protocol/shadowsocks2022/udp_conn.go:138-139`
   - 修复：改为 `packetID := c.packetID.Add(1)`，首包使用 ID 1

## 中

1. **[已修复] 未阻止 chacha20 方法启用 EIH**
   规范与参考实现中 chacha20 不支持 EIH，但目前 dialer/初始化未做校验。
   - 位置：`protocol/shadowsocks2022/dialer.go`（PSK 解析）与 `protocol/shadowsocks2022/identity.go`（EIH 使用路径）
   - 修复：在 `NewDialer` 中检查 chacha20 + iPSK 组合并返回错误
## 验证对照（shadowsocks-rust / sslocal）

以下对照基于 `/Users/chulq/Code/shadowsocks-rust`：

1. **TCP 首次写入不重复发送首段数据（支持“重复发送”问题成立）**  
   sslocal 首次写入将 `addr + padding + payload` 拼成单个 buffer 发送，随后进入 Connected 状态，不会再把同一 payload 作为 chunk 重发。  
   - 位置：`crates/shadowsocks/src/relay/tcprelay/proxy_stream/client.rs:246-314`

2. **TCP 首包 payload 被限制到 u16::MAX（支持“u16 溢出”问题成立）**  
   AEAD2022 writer 会将 buf 截断到 `MAX_PACKET_SIZE = 0xFFFF` 并写入 u16 length。  
   - 位置：`crates/shadowsocks/src/relay/tcprelay/aead_2022.rs:81-82`、`crates/shadowsocks/src/relay/tcprelay/aead_2022.rs:637-675`

3. **UDP 多用户 EIH：client→server separate header 使用 iPSK 加密（支持“key 用错”问题成立）**  
   `encrypt_client_payload_aead_2022` 在有 EIH 时选择 `identity_keys[0]` 作为 `ipsk`，并在 `encrypt_message` 里用该 `ipsk` 进行 AES-ECB 加密 separate header。  
   - 位置：`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:510-515`、`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:175-236`

4. **chacha20-poly1305 UDP 头部使用 24B nonce；EIH 仅支持 AES（支持“chacha/EIH”问题成立）**  
   - nonce_len 对 AES 为 0、对 chacha 为 `method.nonce_len()`；并在包头 prepend nonce。  
     - 位置：`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:390-396`  
   - `method_support_eih` 仅匹配 AES 方法。  
     - 位置：`crates/shadowsocks/src/config.rs:487-491`

5. **AES-256 使用 AES-256 进行 AES-ECB（支持“密钥长度错误”问题成立）**  
   rust 在 AES-256 路径下用 `Aes256` 处理 separate header 与 EIH，而非截断为 16 字节。  
   - 位置：`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:208-235`

6. **UDP Packet ID 从 1 开始（支持“起始值错误”问题成立）**  
   rust 侧有明确注释并在发送前自增 packet_id。  
   - 位置：`crates/shadowsocks-service/src/local/dns/upstream.rs:114`  
   - 位置：`crates/shadowsocks-service/src/local/net/udp/association.rs:533-587`

## 再次对照结论（shadowsocks-go / shadowsocks-rust / sing-shadowsocks2）

以下结论基于同时对照三仓：

1. **可以确认成立（3 仓一致或 2 仓一致 + 1 仓不支持该功能）**  
   - TCP 首包只发送一次，不会把首段 payload 再作为 chunk 重发。  
     - rust：`crates/shadowsocks/src/relay/tcprelay/proxy_stream/client.rs:246-314`  
     - sing：`shadowaead_2022/method.go`（首包发送路径）  
     - go：`ss2022/stream.go`（首包与后续 chunk 分离）  
   - TCP 首包 payload 有 u16 上限（0xFFFF），避免溢出。  
     - rust：`crates/shadowsocks/src/relay/tcprelay/aead_2022.rs:81-82, 637-675`  
     - go：`ss2022/stream.go:18, 126-127`  
   - UDP 多用户 EIH 时，client→server separate header 使用 iPSK 加密。  
     - rust：`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:510-515, 175-236`  
     - sing：`shadowaead_2022/method.go:112, 340-390`  
     - go：`ss2022/crypto.go:90-111` 与 `ss2022/udp.go`（EIH 走 iPSK block）  
   - AES-256 路径下 AES-ECB 使用 32 字节密钥（不是截断为 16B）。  
     - rust：`crates/shadowsocks/src/relay/udprelay/aead_2022.rs:208-235`  
     - sing：`shadowaead_2022/method.go:61-110`  
     - go：`ss2022/crypto.go:24-60`

2. **不完全一致（不能用三仓一致性“确认”）**  
   - UDP Packet ID 起始值：  
     - rust：明确“从 1 开始”。  
       - `crates/shadowsocks-service/src/local/dns/upstream.rs:114`  
     - sing：通过 `packetId--` 使首包从 1 开始。  
       - `shadowaead_2022/method.go:366-386`  
     - go：实现里 `cpid++` 写入前值，首包从 0。  
       - `ss2022/packet.go:144-145`  

3. **部分一致（仅在支持该算法的实现里成立）**  
   - chacha20-poly1305 UDP 头部 nonce 格式与 EIH 支持：  
     - rust 与 sing：chacha 使用额外 nonce 头，且不支持 EIH。  
     - go：不支持 chacha2022。  
