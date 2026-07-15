# tgf-platform

[tgf v2](https://github.com/thkhxm/tgf)（Go 分布式游戏服务器框架）的**第三方平台 SDK 实现 monorepo**。

实现 `github.com/thkhxm/tgf/v2` 的 `tgf/platform` 合约层（设计定稿见 tgf 主仓
`doc/platform-sdk-design.md`）：每个平台一个**独立 go module**，按需实现合约接口子集
（`LoginProvider` / `PaymentProvider` / `ContentAuditProvider` / `WebhookVerifier`）。

## 仓库结构

```
tgf-platform/
├── README.md
├── STATUS.md            # 能力矩阵、验证等级与真凭据缺口
├── core/                # module github.com/thkhxm/tgf-platform/core
│   ├── httpx/           #   带超时/重试/上下文的 HTTP client 封装 + JSON 解析 helper
│   ├── sign/            #   HMAC-SHA256 / RSA-SHA256 签验 / AES-GCM / AES-CBC-PKCS#7 / 常量时间比较
│   └── errs/            #   平台统一错误类型（错误码透传 + 可重试标记）
└── <platform>/          # 13 个独立平台 module，详见 STATUS.md
```

仓库根目录本身**不是 Go module，也没有 `tgf-platform/go.work`**。当前 TGF 联合开发
checkout 由父级联合 workspace 的 `<workspace>/go.work` 聚合 `tgf`、`rpcx`、
`rpcx-consul` 与这里的 14 个 module；该文件的本机绝对路径只属于开发环境，不是公开
规范或本仓库发布物。独立 clone 或业务项目不能假定它存在，应按发布的 module tag
正常解析依赖。

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

- 当前公开基线是 14 个 module 各自的 `<module>/v0.1.0` tag。当前源码正在准备下一补丁：
  13 个平台 module 的 `go.mod` 统一声明
  `github.com/thkhxm/tgf-platform/core v0.1.1`，并继续依赖
  `github.com/thkhxm/tgf/v2 v2.1.0`。这只是**待发布依赖图**；合并或本地 CI 通过都不等于
  `core/v0.1.1` 或任何平台下一补丁 tag 已经推送、可从公网解析。
- 13 个平台 `go.mod` 还各自保留
  `replace github.com/thkhxm/tgf-platform/core => ../core`，供脱离 workspace、以该平台
  module 作为 main module 时联调 sibling core。它是 **module-local replace**，不是一个
  不存在的根 `go.work` replace。当前联合 checkout 的多 module 联编入口仍是上层
  `<workspace>/go.work`，其中只有 `use`、没有 `replace`。该 replace 会让本地构建读取
  工作树中的 core，因此不能用来证明 `require` 版本一致或远端 tag 存在；
  `.github/scripts/verify-module-graph.ps1` 会单独检查 13 份版本声明，并在临时副本和显式
  source-only consumer 中以 `GOWORK=off` 验证源码图。
- 各平台独立演进版本号，互不联动；core 的破坏性变更须 bump 所有依赖它的平台 module。
- v2+ 时按 Go 规范 module path 追加 `/v2`（如 `github.com/thkhxm/tgf-platform/tiktok/v2`，
  tag `tiktok/v2.0.0`）。
- `go get github.com/thkhxm/tgf-platform/wechat@v0.1.0` 精确解析 `wechat/v0.1.0`；
  `@latest` 则解析该 module 已发布的最高兼容语义版本。`@latest` 不会读取调用方机器上
  未发布的 sibling 工作树，也不会解析一个不存在的仓库根 module；需要可复现构建时应
  固定具体版本。
- Go 只采用 main module（或 workspace）的 `replace`；平台 module 作为业务依赖时，
  它自身 `go.mod` 中的 `../core` replace 不会改写业务依赖图，实际按该平台 tag 的
  `require github.com/thkhxm/tgf-platform/core <version>` 解析 core。业务项目不要复制
  仓库维护用的相对路径 replace。

## 业务接入规范

### 1. 只引入实际使用的平台 module

业务只接微信时只安装、import `wechat`，不要为了“全平台预留”把其它平台 module 一并
加入依赖：

```bash
go get github.com/thkhxm/tgf-platform/wechat@v0.1.0
# 主动跟随该 module 最新已发布 tag 时才使用：
go get github.com/thkhxm/tgf-platform/wechat@latest
```

`wechat` 自己的 `go.mod` 会带入当前所需的 `core` 与 `tgf/v2` 版本；业务无需添加
`replace`。业务若直接使用 `core/httpx` 等公共工具，才单独 import 对应 core 包。

### 2. 显式构造、注册，再按能力获取

所有平台的 `New(Config)` 都会校验必填配置并返回 `(provider, error)`。先处理构造错误，
再交给 `rpc.NewRPCServer().WithPlatform` 注册；不要把双返回值的 `New` 直接写进
`WithPlatform(...)`：

```go
import (
    "fmt"

    "github.com/thkhxm/tgf-platform/wechat"
    "github.com/thkhxm/tgf/v2/config"
    "github.com/thkhxm/tgf/v2/platform"
    "github.com/thkhxm/tgf/v2/rpc"
)

func newServer() (*rpc.Server, error) {
    pc := config.Current().Platform
    wx, err := wechat.New(wechat.Config{
        AppID:     pc.WechatAppID,
        AppSecret: pc.WechatAppSecret,
    })
    if err != nil {
        return nil, fmt.Errorf("初始化微信平台: %w", err)
    }

    server := rpc.NewRPCServer().WithPlatform(wx)

    // 平台存在不等于实现所有能力；调用前按平台名 + 能力切面获取。
    if _, ok := platform.Login("wechat"); !ok {
        return nil, fmt.Errorf("微信登录能力未注册")
    }
    if _, ok := platform.Payment("wechat"); !ok {
        return nil, fmt.Errorf("微信支付能力未注册")
    }
    return server, nil
}
```

运行期分别用 `platform.Login`、`platform.Payment`、`platform.Audit`、
`platform.Webhook` 获取能力；第二个返回值为 `false` 表示平台未注册或未实现该能力，
不得用类型断言失败后的零值继续调用。完整能力状态见 [STATUS.md](STATUS.md)。

### 3. 凭据与错误信息安全

- AppID 等标识和 Secret/私钥/支付密钥由业务配置或部署 Secret 注入对应平台的
  `New(Config)`；tgf 已登记的字段优先从 `config.Current().Platform` 读取。平台 module
  不自行读取环境变量，不硬编码凭据，也不把凭据写入仓库、镜像或测试夹具。
- 客户端 code、access token、session key、receipt、webhook body 与签名头都按凭据处理；
  错误和日志中不得记录它们，即使截断也不允许。
- 维护 HTTP 调用时，不得把 `core/httpx.Response.String()`、`Body` 或原始 webhook/JWT
  内容拼进错误；只用 `Response.SafeSummary()` 记录 HTTP status、有限 Content-Type
  类别（如 `json`/`html`/`text`/`xml`/`binary`/`other`/`invalid`）和 body 字节数，绝不
  回显远端提供的 type、subtype 或参数。没有 `Response` 元数据的载荷只用
  `httpx.SafeBodySummary(body)`。
- 平台公开错误码/公开消息可以用于诊断，但业务仍应防范上游把敏感值回显进 message，
  不要再附加 token、Header 或请求/响应原文。

### 4. 验证证据分级

1. **静态/编译证据**：`go build`、`go vet`、接口编译期断言通过，只证明代码和合约可编译。
2. **unit/mock 证据**：`go test` 使用 `httptest`、本地签名重算或固定 fixture，证明本地协议
   分支与错误路径；它不访问平台，不证明 endpoint、后台开关、SKU 或真应答形态正确。
3. **真实/沙箱凭据 E2E**：用平台真实或官方沙箱凭据完成登录、支付、回调等实际请求，
   才能把该能力标记为真凭据已验证。不得用 build 或 mock 测试冒充 E2E 证据。

当前各 module 的证据等级、`NEEDS-DOC` 与真实凭据缺口以 [STATUS.md](STATUS.md) 为准。

## 如何新增平台

以新增 `wechat` 为例：

1. 建目录与 module：
   ```bash
   mkdir wechat && cd wechat
   go mod init github.com/thkhxm/tgf-platform/wechat
   go mod edit -require=github.com/thkhxm/tgf/v2@v2.1.0
   go mod edit -require=github.com/thkhxm/tgf-platform/core@v0.1.1
   go mod edit -replace=github.com/thkhxm/tgf-platform/core=../core
   ```
2. 在当前联合开发 checkout 中，从父级 `<workspace>` 目录执行
   `go work use ./tgf-platform/wechat`，把它加入 `<workspace>/go.work`；不要在
   `tgf-platform` 根虚构 `go.work` 或把 module-local replace 误写成根 workspace 配置。
   Go workspace 会优先使用 `use` 中 module path 匹配的本地 module。独立 clone 若需要
   多 module 联编，可在仓库外自建个人 workspace；单 module 维护则使用上一步与现有
   平台一致的 `../core` replace，但不要把本地路径当作业务项目依赖。
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
6. 发布必须严格按依赖拓扑执行：先完成并推送 `core/v0.1.1`，再从仓库外、无
   `go.work`/`replace` 的空 consumer 验证该版本可公开解析；只有这一步成功后，才创建并
   推送各平台下一补丁 tag（如 `<platform>/v0.1.1`），最后再用同样的空 consumer 验证
   平台 tag。平台目录中的 module-local replace 会读取 `../core`，临时 source consumer
   也会显式 replace 到临时副本；二者都只证明源码图，不得被描述成远端 tag 已存在。
   业务接入遵循上面的“构造 → `WithPlatform` 注册 → 按能力获取”流程。

## 本地开发

```bash
# tgf-platform 根不是 module；进入需要验证的 module 再执行命令
cd core
go build ./...
go vet ./...
go test ./...

cd ../wechat
go build ./...
go vet ./...
go test ./...
```

每个 `go.mod` 均声明 Go 1.26.0。当前联合开发 checkout 从任意子 module 执行
`go env GOWORK` 应指向父级 `<workspace>/go.work`（该文件声明
`toolchain go1.26.4`）；独立消费者则以自身 module/workspace 与工具链为准。

发布图门禁可从仓库根运行：

```powershell
pwsh ./.github/scripts/verify-module-graph.ps1 -ExpectedCoreVersion v0.1.1
```

该门禁会检查 13 份 `core` require、保留的 module-local replace，并在系统临时目录复制
源码后以 `GOWORK=off` 验证每个平台及 consumer 形态。consumer 对 core 的 replace 是
明确的 source-only 测试装配；脚本不会查询、创建或伪装任何远端 tag。

## License

与 tgf 主仓一致。
