# GuardLauncher v17.16 更新记录

基线 v17.15 / Schema 11；当前仍为 Schema 11。

- 统一 Go/Helper/Watchdog 有效 ACL 判定，分开读取失败与无 Deny。
- 修复独立 Watchdog 缺 Get-GuardInheritanceFlags / Write-Notification 定义。
- Java 配置和扫描错误显式化；候选不自动授予规则；核验本次后代与 Minecraft 参数后持久化实际路径并同步原精确白名单。取消 PATH/JAVA_HOME 自动授权。
- CIM 错误后增加保守的独立进程枚举；Watchdog 身份用有限查询权限的原生句柄核验。长探针改走临时脚本文件，避免命令行长度回归。
- audit_policy.json 严格 UTF-8，未知原始状态保留恢复记录。
- QQ INI 覆盖隐藏/多于 50 项，明确编码和不完整错误；不跟随 reparse point。
- FQDN 动态 ID 清理失败保留重试；旧 Watchdog 身份查询不确定不再继续并发恢复。
- ProtectedPaths 读失败、ACL 基线缺项、无效 AllowedDomains 行和 CLI 非 EXE 目标明确报告。
- 通知 writer 无 BOM、共享注入，Go 增量读取，限制通知体积及尾行缓冲。
- 新增可复现测试、详细需求溯源总结、剩余边界和待确认架构建议。

没有新增端点/端口、放宽默认 BLOCK、扩展默认 Tencent 目录、改动 roots=0 决定或自动跟随链接。全局 BLOCK 与共享 Java 的副作用仍需下一轮专项设计。Windows 实机验证未完成。
