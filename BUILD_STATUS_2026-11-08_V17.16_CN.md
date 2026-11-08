# v17.16 构建与交付状态（2026-11-08）

- 基线：上传 v17.15，输入 ZIP CRC 与全部原 SHA-256 清单已核验。
- 工具链：Go 1.23.2 linux/amd64（与原构建记录一致），PowerShell 7.4.6 Linux。
- Go 工具链下载包 SHA-256 已按官方 go.dev 元数据核验；PowerShell 下载包按官方 release hashes.sha256 核验。
- 目标：GOOS=windows、GOARCH=amd64、CGO_ENABLED=0。
- gofmt：源码及测试文件已格式化。
- `go test GuardLauncher_v17.go`：Windows 编译检查通过，输出 `[no test files]`，没有执行 Windows 测试。
- `go vet GuardLauncher_v17.go GuardLauncher_v17_test.go GuardLauncher_windows_test.go`：通过。
- `go test -c` 同三份文件：Windows 测试套件编译通过，测试 EXE 未执行、未放入发布包。
- `go build -trimpath -ldflags='-s -w'`：两个不同输出文件分别构建，字节完全一致。
- EXE：PE32+ Windows x64 Console。
- Linux 上抽取当前可移植函数运行：7 个 Go 测试函数通过，其中端点语法另含 22 个子用例。
- PowerShell Parser/定义/函数模拟/原生枚举检查：107 项通过；包括 7 份导出模板及 build-local.ps1 解析，不等于 107 个 Windows 集成场景。
- 根目录只含当前一个 EXE；历史原件字节保留；三个未改配置字节一致。
- FILE_HASHES_SHA256 全部文件、ZIP CRC、ZIP 内清单与实际字节一致性已验证。

## 最终文件哈希

EXE SHA-256：`b69bafbc4cb3155094ddd8248611e512e441e3cc84531e0897935a5c89b21c50`

当前 Go 源码 SHA-256：`fc76cb30e26c4a2d1dd6a5d17235b7d7ec56c4448688ada6c9e1aa74e5bf3fe8`

原 v17.15 Go 源码 SHA-256：`0d38159ca47007192a797f06846039a5ee0fb22ce7c77b5101b09b8a4a06e4c5`

## 实机限制

本轮没有 Windows PowerShell 5.1、UAC、Windows 11、NTFS ACL、NetSecurity ActiveStore、Winmgmt/WMI 服务或 WFP 的实际执行证据。Linux PS7 Parser、模拟测试、.NET 枚举及 Go 交叉构建均不能替代这些实机测试。Windows 原生身份/Parser 测试已提供，但本轮只交叉编译。

完整待验收场景见 TEST_MATRIX_V17.16_CN.md；剩余架构/链接/首次连接边界见 00/02/03。包内结果日志保留原输出，所有模拟成功都限定于明确的测试替身与临时夹具。
