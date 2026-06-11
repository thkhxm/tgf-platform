# tgf-platform

[tgf v2](https://github.com/thkhxm/tgf)（Go 分布式游戏服务器框架）的**第三方平台 SDK 实现 monorepo**。

实现 `github.com/thkhxm/tgf/v2` 的 `tgf/platform` 合约层（设计定稿见 tgf 主仓
`doc/platform-sdk-design.md`）：每个平台一个**独立 go module**，按需实现合约接口子集
（`LoginProvider` / `PaymentProvider` / `ContentAuditProvider` / `WebhookVerifier`）。

## 仓库结构

```
tgf-platform/
├── go.work              # 本地开发工作区（聚合各 module）
├── core/                # module github.com/thkhxm/tgf-platform/core
│   ├── httpx/           #   带超时/重试/上下文的 HTTP client 封装 + JSON 解析 helper
│   ├── sign/            #   HMAC-SHA256 / RSA-SHA256 签验 / AES-GCM / AES-CBC-PKCS#7 / 常量时间比较
│   └── errs/            #   平台统一错误类型（错误码透传 + 可重试标记）
├── tiktok/              # module github.com/thkhxm/tgf-platform/tiktok
└── <platform>/          # 后续平台：wechat / apple / facebook / ...
```

## 设计原则

### 1. 每个平台独立 go module（依赖隔离，硬规则）

平台官方/社区 SDK 依赖树庞杂。独立 module 保证：**不接微信的项目，二进制里没有微信的
一行代码、`go.mod` 里没有它的任何依赖**。因此：

- 平台 module 之间**禁止互相 import**；
- 公共逻辑只能下沉到 `core`，而 **`core` 仅依赖 Go 标准库**——任何平台依赖 core
  都不会污染依赖树；
- 平台 module 允许的依赖：`github.com/thkhxm/tgf/v2`（合约层）、
  `github.com/thkhxm/tgf-platform/core`、该平台必需的第三方 SDK（能用 stdlib + core
  实现就不引 SDK）。

### 2. core 模块只放"平台无关"原语

core 提供 HTTP 调用、签名/验签/加解密、错误类型三类工具，**不预设任何平台的
endpoint / 鉴权头格式 / 签名串拼接规则**——这些协议细节必须由各平台 module 按
官方文档实现，并在代码注释附【官方文档链接 + 拉取日期】（见下"工程纪律"）。

### 3. 工程纪律（来自 tgf 主仓设计文档第四节，违反必被 review 打回）

1. **先查官网最新文档，不许凭记忆写**——endpoint / 鉴权头 / 参数单位以官方文档为准；
2. **每个 endpoint 在代码注释附官方文档链接 + 拉取日期**；
3. **接入完成必须用真凭据端到端验证一次**——`go build` 通过不等于接通；
4. 持续报 "data invalid" 类错误时，优先怀疑 endpoint 选错 / SKU 不匹配 / 参数单位错
   （实战教训：TikTok progress 0-1 被当 0-100、IAP 用错 token 类型），而不是反复调 payload。

## 版本与 tag 规则

monorepo 多 module 的 tag 必须带 module 子目录前缀（Go module 规范）：

| module | tag 形如 |
|---|---|
| core | `core/v0.1.0` |
| tiktok | `tiktok/v0.1.0` |
| wechat | `wechat/v0.1.0` |

- 各平台独立演进版本号，互不联动；core 的破坏性变更须 bump 所有依赖它的平台 module。
- v2+ 时按 Go 规范 module path 追加 `/v2`（如 `github.com/thkhxm/tgf-platform/tiktok/v2`，
  tag `tiktok/v2.0.0`）。

## 如何新增平台

以新增 `wechat` 为例：

1. 建目录与 module：
   ```bash
   mkdir wechat && cd wechat
   go mod init github.com/thkhxm/tgf-platform/wechat
   go mod edit -require=github.com/thkhxm/tgf/v2@v2.1.0
   go mod edit -require=github.com/thkhxm/tgf-platform/core@v0.1.0
   ```
2. 把 `./wechat` 加进根目录 `go.work` 的 `use` 块（本地开发即时联编，无需发版）。
   注：`core/v0.1.0` tag 发布前，`go.work` 里已有 `replace github.com/thkhxm/tgf-platform/core v0.1.0 => ./core`
   兜底（Go workspace 不会自动用本地模块满足 sibling require 的未发布版本）；tag 发布后可删。
   平台 module 的 `go.sum` 同理需等 core tag 发布后 `GOWORK=off go mod tidy` 生成。
3. 实现合约接口子集：`wechat.New(cfg)` 返回实现了
   `platform.LoginProvider` / `platform.PaymentProvider` / ... 的类型，
   用编译期断言锁定（参考 tgf 主仓 `platform/fake.go` 的写法）：
   ```go
   var (
       _ platform.LoginProvider   = (*Wechat)(nil)
       _ platform.PaymentProvider = (*Wechat)(nil)
   )
   ```
4. 每个 endpoint 按上面"工程纪律"执行：查官方文档 → 注释附链接+日期 → 单测
   （httptest mock 平台应答）→ 真凭据端到端验证。
5. 凭据（AppID / AppSecret / 商户密钥）从业务侧配置传入 `New(cfg)`，
   **绝不在本仓库硬编码、绝不入库**（`.gitignore` 已拦 `.env*` / `*.pem` / `*.key`）。
6. 业务接入：`rpc.NewRPCServer().WithPlatform(wechat.New(cfg))`，
   按平台名 + 能力取用：`lp, ok := platform.Login("wechat")`。

## 本地开发

```bash
# go.work 已聚合各 module，根目录直接构建/测试任意 module
cd core
go build ./...
go vet ./...
go test ./...
```

要求 Go ≥ 1.26.0（`go.work` 声明 toolchain go1.26.4）。

## License

与 tgf 主仓一致。
