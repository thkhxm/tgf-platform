module github.com/thkhxm/tgf-platform/line

go 1.26.0

require (
	github.com/thkhxm/tgf-platform/core v0.1.0
	github.com/thkhxm/tgf/v2 v2.1.0
)

require (
	github.com/bwmarrin/snowflake v0.3.0 // indirect
	github.com/bytedance/gopkg v0.1.3 // indirect
	github.com/bytedance/sonic v1.15.0 // indirect
	github.com/bytedance/sonic/loader v0.5.0 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/joho/godotenv v1.5.1 // indirect
	github.com/klauspost/cpuid/v2 v2.2.9 // indirect
	github.com/panjf2000/ants/v2 v2.12.0 // indirect
	github.com/richardlehane/mscfb v1.0.6 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/tiendc/go-deepcopy v1.7.2 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/xuri/efp v0.0.1 // indirect
	github.com/xuri/excelize/v2 v2.10.1 // indirect
	github.com/xuri/nfp v0.0.2-0.20250530014748-2ddeb826f9a9 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	golang.org/x/arch v0.13.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20250106191152-7588d65b2ba8 // indirect
	golang.org/x/net v0.50.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

// 本地联编：core 尚未发布 core/v0.1.0 tag 前，对它的 require 在本 module 内 replace
// 到同仓库 ../core 目录（path replace 只在本主模块生效，依赖方忽略）。core 打 tag 后删除本行。
replace github.com/thkhxm/tgf-platform/core => ../core
