# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 概述

Outbound 是一个 Go 库，提供统一的接口，从分享链接 URL 创建网络 dialer。属于 daeuniverse 组织，支持多种代理协议。

## 构建与测试命令

```bash
# 构建
go build ./...

# 运行所有测试
go test ./...

# 运行特定包的测试
go test ./protocol/hysteria2/...
go test ./common/...

# 运行单个测试
go test -run TestFunctionName ./path/to/package

# 详细输出
go test -v ./...
```

## 架构

### 核心抽象

**netproxy.Dialer** (`netproxy/dialer.go`) - 所有 dialer 实现的基础接口：
```go
type Dialer interface {
    DialContext(ctx context.Context, network, addr string) (Conn, error)
}
```

**dialer.FromLinkCreator** (`dialer/register.go`) - 从分享链接创建 dialer 的工厂函数类型。

### 分层 Dialer 模式

Dialer 可组合链式调用。典型的 Trojan over WebSocket over TLS 链：
```
direct -> tls -> ws -> trojanc
```

每层包装前一个 dialer（`nextDialer`），添加自己的协议处理。

### 包结构

- **dialer/** - 各协议的分享链接解析器和高层 dialer 工厂（ss, trojan, vmess, vless, hysteria2, tuic, juicity 等）
- **protocol/** - 底层协议实现，处理实际代理协议（shadowsocks, trojanc, vmess, vless 等）
- **transport/** - 传输层实现（tls, ws, grpc, simpleobfs, httpupgrade, meek, mux, shadowsocksr obfs/proto）
- **netproxy/** - 核心 Dialer/Conn 接口和包装器
- **ciphers/** - 加密实现（AEAD、流加密）
- **pool/** - 字节缓冲池，优化内存

### 添加新协议

1. 在 `protocol/yourproto/` 创建协议处理器，实现连接逻辑
2. 在 `protocol/dialer.go` 通过 `protocol.Register("yourproto", creator)` 注册
3. 在 `dialer/yourproto/` 创建分享链接解析器，包含 `ParseXxxURL()` 和 `ExportToURL()`
4. 在 `init()` 中通过 `dialer.FromLinkRegister("scheme", creator)` 注册

### 入口点

`dialer.NewNetproxyDialerFromLink()` 是主入口 - 解析分享链接 URL，识别协议 scheme，构建对应的 dialer 链。

### 支持的协议

- Shadowsocks (ss://)、ShadowsocksR (ssr://)
- VMess (vmess://)、VLESS (vless://) 含 REALITY 支持
- Trojan (trojan://)、Trojan-Go (trojan-go://)
- TUIC (tuic://)、Juicity (juicity://)
- Hysteria2 (hysteria2://, hy2://) 含 UDP 端口跳跃
- HTTP 代理、SOCKS5 代理
- AnyTLS (anytls://)

### 传输选项

协议可叠加多种传输层：
- TLS/uTLS（含指纹模拟）
- WebSocket
- gRPC
- HTTP/2
- HTTPUpgrade
- Meek
- Simple-obfs
- REALITY
