# HachimiGuard v17.16 重点改进方案与验收设计

**文件性质：待用户确认的技术方案，不是新版本发布或修复完成报告。**

编制日期：2026 年 11 月 8 日。审查基线：本次对话已交付的 v17.16 / Schema 11。

本轮仅阅读代码、查询权威资料、执行隔离的只读函数夹具并编写本文件。没有修改 v17.16 源码、配置、构建脚本、EXE、既有测试或发布 ZIP，没有运行 Helper Apply、实际 Watchdog、NTFS 权限变更或防火墙操作。后文所有“拟修改”“应当”“验收”都属于未来实施要求。

## 一、建议批准的范围

建议选择 **三项核心工作和一项配套改进**。优先解决保护结果可能误判和恢复资料可能失去作用的问题，然后改善 Java 兼容性；不重写全局网络架构。

| 顺序 | 工作 | 为什么优先 | 建议性质 | 完成标准 |
|---|---|---|---|---|
| A，P0 | ACL 实际权限核验与独立 Watchdog 恢复 | 统一判断标准仍可能统一地判断错；匹配的继承 Deny 不一定能阻止前面的显式 Allow | 先补 Windows 反例验证，确认后修正有效保护判定；新增独立进程验收 | 同一普通用户的实际访问结果与三方判断一致；真实非空 journal 经独立 Watchdog 恢复，外部 ACE 保留 |
| B，P0 | FQDN 重建与异常恢复顺序 | 正常退出基本正确，重建却仍有先删除对象、后清规则的分支；Windows 不会替程序维护引用依赖 | 收紧顺序、持久状态和故障恢复，补对象解析就绪验证 | 每个中断点都能识别旧/新对象及规则，删除失败不丢 ID，未核验不报告完成 |
| C，P1 | Java 入口识别与精确规则就绪 | 当前全命令行子串匹配可能误判辅助 Java；首连还受动态 DNS 更新和既有 Allow 影响 | 改成结构化、可解释判定；显式配置优先解决首连；运行后识别保留失败关闭 | 选定版本的原版/Fabric/Forge/NeoForge/Quilt/第三方包装启动可解释；辅助 Java 不自动授权；规则有效与路径登记分开 |
| D，P1，配套 | Java 候选扫描的时间和资源预算 | 当前根目录有限，但无总预算、进度或取消通道，候选扫描不应成为保护启动的长期阻塞 | 保留有限根目录，减少无必要扫描，加入预算、中断和不完整结果 | 到达预算或取消后结果明确；候选从不自动获得 Allow；没有遗留无限扫描任务 |

**本轮不建议实施：**全局 BLOCK 改 ALLOW、批量给无关程序补 Allow、自动跟随目录链接、进程注入/强制挂起/终止 Java、自动下载或切换用户 JRE、新增服务/计划任务、扫描全磁盘、处理已暂缓的 roots=0。

共享 Java 和全局 BLOCK 的冲突，继续作为单独架构课题。它们不能靠一次正则优化或路径识别被宣布解决。

## 二、证据范围与新发现

### 2.1 不能沿用“说明写得完整，所以运行已成功”的判断

此前 107 项检查包含脚本解析、函数存在性、模拟数据和替代接口。复核 `tests/verify_powershell.ps1` 可见：ACL 读取被 `Get-Acl` 模拟函数替代，非空 journal 恢复中的实际删除也使用了替代函数。这些检查有价值，但没有证明真实 NTFS 上的拒绝访问、完整独立 Watchdog 或 WFP 的结果。

本文件使用四种证据标签：

- **源码确认**：实际分支、参数、先后顺序可直接定位。
- **只读夹具确认**：从当前源码取出原函数，在隔离模拟输入上执行；不等于 Windows 系统功能复现。
- **依据官方语义推导的条件性风险**：官方规则和代码组合支持判断，仍需目标环境验证。
- **未实机验证**：本轮没有运行相关 Windows 场景；不能写成已经失败或已经通过。

### 2.2 本轮新增的关键复核结果

| 编号 | 实际观察 | 结论与证据等级 |
|---|---|---|
| F-A1 | `Test-GuardProtectionEffective` 遇到匹配 SID 的 FullControl Deny 就返回 true，没有按整个有序 DACL 与访问令牌求结果 | 源码确认；“存在匹配 Deny”不能直接充当“所有敏感访问均被拒绝”的证明 |
| F-A2 | 在“显式 FullControl Allow 在前、继承 FullControl Deny 在后”的模拟 ACE 列表中，原函数返回 true | 只读夹具确认；Windows AccessCheck 的实际文件访问反例仍需实测 |
| F-J1 | `java.exe -Dnote=net.minecraft.client.main.Main -jar helper.jar` 被原识别函数判为 true | 只读夹具确认；类名出现在 JVM 属性值中，也会触发当前强匹配 |
| F-J2 | `java.exe -cp C:/libs/net.neoforged.tools.jar example.Helper` 也被判为 true | 只读夹具确认；包名前缀在 classpath 字符串里并不是游戏入口证据 |
| F-J3 | `java.exe @C:/instance/args.txt` 被判为 false | 只读夹具确认；若真正入口仅位于参数文件中，原字符串函数看不到。没有据此宣称所有启动器都使用此形式 |
| F-F1 | Watchdog `Rebuild-FirewallRules` 在 `$exists` 不成立时，先尝试删除旧 ID，之后才执行本次 Guard 规则移除 | 源码确认；重建分支没有完全遵循用户提出的规则先删、对象后删的顺序 |
| F-F2 | `active_endpoints.json` 可在系统重建完成前写入拟采用的端点；`Sync-SessionJavaPaths` 先登记路径，最后调用的 Rebuild 主要以 PersistentStore 数量做结尾检查 | 源码确认；另有周期性 ActiveStore 语义检查，但登记成功/数量正确不应代替即时生效确认 |
| F-S1 | 自动扫描根有限，包含 ModeSymlink 检查；仍使用同步 WalkDir/Glob，没有总预算、进度或取消参数，Warnings 可持续增长 | 源码确认；“全磁盘无限扫描”不是当前代码事实，潜在卡顿取决于目录和存储 |

这些夹具是判断函数的边界输入，不是已运行的 Minecraft、真实 NTFS 或防火墙攻击实验。`ConfirmedJavaProcesses` 还要求后代关系，因此 F-J1/F-J2 只有在相应辅助进程也满足本次归属条件时，才可能进入后续自动路径同步；不能仅凭字符串命中就声称已经出现越权联网。

## 三、方案 A：将 ACL 存在性检查升级为真实效果核验

### A1 对应的原始要求

对应本次反馈第二部分第 4 项，以及上传 00 文档 P1-01、01 文档关于普通用户身份、Guard ACE 来源和三组件一致性的要求。

这里需要更正此前说明中的一个过强表述：**继承 Deny 可以适用于目标，但适用不等于它一定决定了本次访问结果。** Microsoft 说明访问检查按 ACE 顺序执行，所有所需权限获准时可以提前结束；规范顺序将显式 ACE 排在继承 ACE 前面。[S01][S02]

因此应重点验证如下组合：某子文件有显式 Read/FullControl Allow，后面继承了同用户 Deny；从已知文件路径直接读取时，不能只因看见后面的 Deny 就报告保护有效。父目录无法列出，也不能替代子文件按已知路径的读取测试。

### A2 拟修改内容

1. **保留共享实现，分开三个概念。**
   - 存在某种 ACE：用于描述和诊断。
   - 指定普通用户的某项访问能否获准：用于有效保护门禁。
   - 某条显式 ACE 是否属于 Guard：用于重新施加和恢复。
   有效权限计算不能改变 Guard 来源判定，也不能成为删除用户原有 ACE 的理由。
2. **优先使用 Windows 原生 AccessCheck 等系统能力，避免自行复制一套 DACL 算法。** 对同一安全描述符、经核验的普通用户令牌和文件/目录具体访问位求结果。AccessCheck 要求有效模拟令牌、正确的 GenericMapping，并且函数调用是否成功与 AccessStatus 是否允许是两回事。[S03]
3. **不能用管理员 Helper 的令牌替代受保护用户。** UAC 提权账号可能不同。拟先核对 ParentPID、创建时间和 Caller SID，再获取相应普通主体令牌；令牌句柄不可写入 JSON 当作可跨进程恢复凭据。Watchdog 重启后无法重新取得可靠主体时，应返回 Unknown，而不是仅凭 SID 字符串重建“相同用户”的假想权限。
4. **按敏感操作分别检验。** 文件读取数据、目录列举分别检查；属性、扩展属性等是否必须同时拒绝，应以现有 FullControl Deny 的产品目标明确列出。不能请求一次 FullControl、看到整体被拒绝，就认为其中的 ReadData 也一定被拒绝。分项核验不是把既有 FullControl Deny 缩减为只拒绝读取，也不扩大或放宽当前 ACL 策略。
5. **结果采用 Allow / Deny / Unknown，而不是一个真假值包办。** Allow 表示尚有必须关闭的访问；Deny 表示指定操作被拒绝；Unknown 包括令牌、描述符或 API 调用失败。Unknown 必须带操作和错误原因。
6. **只在确实需要时添加 Guard 显式 Deny。** 若继承记录存在、但实际检查仍允许敏感读取，应先写 Guard 来源 journal，再添加/核验所需显式 Deny；不无条件堆叠重复 ACE，不禁用全树继承，不覆盖整份 DACL 来“修好顺序”。若已有外部 ACL 已足够保护，不应据为 Guard 所有。
7. **三条路径共同调整。** Helper Apply、Watchdog 重施加与主程序最终门禁使用同一含义。主程序权限不足时不能将“读不到 ACL”转换成目标不存在。恢复阶段仍依据来源 journal 和退出证据，不应因为恢复主体令牌已不可得，就永远阻止移除可明确归属的 Guard ACE。

上述是接口和行为设计，不在本轮添加 API 封装。具体句柄交接、权限位集合、进程退出后的核验边界，须在实施前完成设计复查。

### A3 必须新增的真实 Windows 验收

| 场景 | 必须观察的结果 |
|---|---|
| 已有匹配 SID 的显式 Deny | 普通用户实际读取/列举失败；不新增重复 Guard ACE；恢复不删除原 Deny |
| 继承 Deny 且无更早授权覆盖 | 逐操作核验结果与实际访问一致；不能仅凭 IsInherited 统一拒绝或统一接受 |
| **显式 Allow 在前，继承 Deny 在后** | 记录真实访问结果；若仍能读取，必须判定未受完整保护，施加必要 Guard ACE 后再验证 |
| InheritOnly | 不能用于证明对象本身已经拒绝访问 |
| 其他 SID、组成员资格、deny-only SID | 按实际令牌和权限位核验；其他用户的 Deny 不当作当前用户的保护证据 |
| Get-Acl/AccessCheck/令牌读取失败 | 返回 Unknown 和明确错误，不报告“没有 Deny”或“已保护” |
| 目标用户与 UAC 管理员不是同一账号 | 主体仍为最初普通用户，不能以提权身份测试通过代替 |
| 普通文件、中文目录、关闭继承的子项 | 对真实内容访问作验证，逐项检查添加和恢复来源 |

### A4 独立 Watchdog 的验收必须另外做

在专用 Windows 测试账号/虚拟机中，使用真正的 GuardLauncher → UAC Helper → 独立 powershell.exe Watchdog 链路；先用仅 ACL 模式控制变量，测试根只存在于该测试账号中，不对日常 QQ 数据试验。

准备非空 Tencent 测试树，包含能实际产生 Guard 新增显式 ACE 的文件/目录和需要保留的外部 ACE；确认 journal 至少一条，不能 roots=0 通过。随后：

1. 记录主程序、Helper、Watchdog 的 PID/创建时间、实际生成脚本哈希及心跳/parent-ready；确认 Watchdog 为另一进程。
2. 普通用户测试进程在保护前可以读到固定测试内容，保护后不能读。只记录是否成功和错误码，不读取或记录真实 QQ 内容。
3. 结束受保护测试进程，等待真实 Watchdog 调用未替换的 Get-Acl、Set-Acl 和 Restore-GuardACLs。
4. 按每个来源记录验证 Guard ACE 已移除、原有 ACE 未删、固定测试内容重新可读，并检查最终 SDDL 和恢复摘要。
5. 在 ACL 添加后、parent-ready 前、监控中、部分恢复后分别中断相关进程；验证恢复资料保留与后续重试。中断实验只在可回滚测试环境执行。

只有这组证据齐全，才能把“独立 Watchdog 非空 ACL 恢复通过”写进发布说明。函数共享和模拟成功只是其前置条件。

## 四、方案 B：FQDN 重建与恢复采用可追溯阶段

### B1 对应要求与资料结论

对应本次反馈第二部分第 5 项，以及 00 文档动态对象 ID 和恢复顺序要求。

v17.16 的正常恢复已经先删规则、再检查动态对象。应保留这一方向，集中修正重建和异常分支。Windows 允许规则引用尚不存在的动态对象，也允许删除仍被规则引用的对象；这些依赖必须由 Guard 管理。[S04]

另一个边界是：**对象存在、规则存在和域名地址已填充是三个状态。** Microsoft 说明 FQDN 更新并非同步于应用得到 DNS 响应，可能造成额外的首次连接失败；重启后 AutoResolve 对象的已解析地址也需重新填充。[S04][S05]

### B2 拟修改原则

- ID 生成后先持久化“拟创建”记录，再调用系统创建；调用失败不能直接删除来源记录。
- 创建后核验 ID、精确 Keyword、AutoResolve 及必要的归属信息。不能把查询异常当成不存在后立即删除/替换。
- 重建时先计算期望规则；**在删除或替换旧对象前，先移除引用旧对象的本次 Guard 规则，并确认 PersistentStore/ActiveStore 状态**。若只能确认部分存储结果，保留状态并中止破坏性下一步。
- 新对象和规则建立后，检查实际程序、方向、协议、地址/动态 ID、端口、Profile、启用状态及是否存在冲突 Allow；数量只作为辅助。若策略合并或不可禁用的外部 Allow 导致无法满足限制，应明确报告隔离无法保证；不能仅因 Profile 显示 Block 就宣称安全。
- 将“期望配置”与“最后验证生效配置”区分。不能先写拟采用的 active_endpoints，就在崩溃重启后把它当作已经成功生效的事实。
- 规则成功移除之后才删除其 Guard 动态对象；查询确认不存在后，才将相应待清理记录退休。
- 对外部规则引用或对象身份不匹配，保留恢复资料并报告冲突，不能删除外部规则来满足清理目标。
- 删除动态对象失败时保留该 ID。若已经证明 Guard 规则完全移除，无引用的对象残留本身不能被描述成正在放行网络；用户 Profile/Allow 的恢复仍按既有独立分组和安全依赖推进，不能为了清一个无引用对象长期无条件维持全局 BLOCK。

### B3 建议的阶段与中断处理

以下是行为模型，不预先规定 JSON 字段名，也不承诺沿用旧 Schema 足够。如果需要新增结构化阶段记录，实施时应明确 Schema 升级、旧 Schema 11 兼容读取和降级拒绝策略。

| 阶段 | 已知事实 | 此刻异常退出后应如何处理 |
|---|---|---|
| ID 已记账 | 有拟使用 ID，不证明对象创建成功 | 按 ID 查询；不存在也只有在查询成功后才算无对象；查询失败保留 |
| 对象已核验 | 对象属性匹配，不证明关联规则存在 | 检查属于本会话的实际规则和旧/新 ID；不得直接宣告策略就绪 |
| 规则待生效核验 | 系统创建请求已执行，可能只有部分规则 | 核对实际状态，保持严格策略，完整重建或清理；不能只比数量 |
| 规则已核验 | 精确规则语义与活动存储符合预期 | 监控、按现有机制重施加；解析就绪单独记录 |
| Guard 规则已移除 | 无本会话活动规则，动态对象可能仍在 | 可清理对象；不要因为一次删除调用没报错就退休记录 |
| 动态对象已确认不存在 | 成功枚举/定向核验表明不存在 | 原子更新该 ID 的恢复进度，随后处理其余独立恢复分组 |
| 会话全部恢复 | 所有必要分组核验完成 | 才删除 session 目录；审计日志继续保留 |

### B4 首连就绪处理不增加网络允许范围

对已在 AllowedDomains 中的精确 FQDN，可评估在规则建立后执行**受时间预算约束的 DNS 预解析与对象地址读回**；只用当前策略已经允许的解析路径。不要复制文档示例就新增 nslookup 的 UDP 53 放行，也不修改系统 DNS、DoH、VPN 或 Defender 设置。[S05]

读回为空或不能核验时，区分“规则结构有效但地址未就绪”和“规则创建失败”。该状态继续受到默认策略限制；对必要目标可以终止本次启动并走既有恢复，或在已明确说明的降级模式中继续。是否把某个目标设成强制就绪条件，需要针对现有端点清单另行确认，不能凭研究自动新增 required 配置或新域名。

DNS 预解析只能减轻第二种首连延迟，不能消除 Java 尚未被识别的第一种延迟，也不能证明未来 DNS 地址永不变化。

### B5 必须实施的故障注入

每个持久化边界分别中断：ID 写完未创建、对象创建后未建规则、部分规则成功、拟采用端点写完、旧规则移除后、新规则完成前、对象删除后尚未更新 journal、部分 journal 退休后。

每个场景同时验证：

- Watchdog 重启和下一次启动的旧会话恢复；
- JSON 损坏、查询失败、命令不可用、删除失败和对象已经不存在；
- v17.16 旧字典格式导入，新格式不能被旧版本误接管；
- ID 是否还可追溯，实际规则是否仍引用它，是否有外部引用；
- 冷 DNS、热缓存、FQDN 未解析、IPv4/IPv6 和系统重启后的地址重填；
- 恢复顺序与日志事实是否相符，不用“清理函数调用过”代替系统状态读回。

## 五、方案 C：Java 入口判定与网络就绪分别设计

### C1 对应要求

对应本次反馈第二部分第 1、2 项，以及原始 P1-03 和“不要把所有 Java/IDE/Gradle 当 Minecraft”的要求。

应将首连问题拆成三个时序窗口：

| 窗口 | 原因 | 拟处理办法 | 不能声称解决的内容 |
|---|---|---|---|
| Java 出现到被识别 | Watchdog 轮询、归属链暂时不完整 | 用户已核实的准确 JavaPaths 在 Apply 前建精确规则；自动发现保持谨慎，记录时间线 | 不能声称每个未知 Java 首包必然被挡；既有程序专属 Allow 可能仍有效 |
| 路径登记到规则真正生效 | 写 journal、冲突规则处理、系统策略合并均需时间 | 增加“已登记/待核验/已生效”区分和可重试更新，即时检查 ActiveStore | 不能把 session.json 中有路径当作已保护或已联网 |
| FQDN 规则存在到地址填充 | DNS/Network Protection 异步更新 | 按方案 B 的精确预解析与读回、实际启动器重试测试 | 不能保证所有应用都会重试，也不能保证一次预解析消除竞态 |

官方防火墙资料说明显式 Allow 能优先于默认 Block，显式 Block 又会覆盖冲突 Allow。因此“临时给未知 Java 全封，再加几条允许”不能作为本轮的简易修补。[S06]

### C2 根据权威资料建立入口样本，不只加更多正则

| 启动方式 | 本轮取得的第一方证据 | 对设计的启示与限制 |
|---|---|---|
| Minecraft 原版 | Mojang 1.21.1 版本 JSON 中 mainClass 为 `net.minecraft.client.main.Main`，javaVersion majorVersion 为 21 | 可以作固定历史版本的正样本；这是一个版本的声明，不证明任何路径上的 Java 实际启动了它，也不建议用户因此升级 |
| Fabric | FabricMC 安装元数据生成源码分别声明客户端 KnotClient 和服务器 KnotServer，并有 LaunchWrapper 配置 | 根据准确的客户端入口/受支持兼容模式分类；服务器模式作为单独样本，不自动扩展当前客户端产品范围 |
| Forge | Forge 官方 Maven 的 1.20.1-47.2.0 安装器 version.json 使用 BootstrapLauncher，并声明 forgeclient 启动目标 | 通用 BootstrapLauncher 名称本身不足以授权，需要结合真实参数/该实例元数据 |
| NeoForge | 第一方 FancyModLoader 的固定提交具有 `net.neoforged.fml.startup.Client`，再调用 Minecraft 客户端入口 | 新入口可能变化，按固定版本采样；不能仅凭 `net.neoforged.` 包名前缀判定所有工具进程 |
| Quilt | QuiltMC 客户端 KnotClient 入口源码 | 支持客户端正样本；不同 bootstrap/旧版形式另行采样，不能宣称已覆盖全部版本 |
| 第三方启动器包装 | Prism 的 StandardLauncher 第一方源码能将 mainClassName 通过反射转发给实际入口 | 原始命令行未必直接展现最终游戏主类；要采集实际受支持版本，不能见陌生入口就放宽，也不能声称 Prism 必然失败 |
| Java 参数文件/模块/JAR | Java 21 官方手册区分 mainclass、-jar、-m/--module、@argfile | 需要结构化解析；参数文件路径和引用解析有自身语义，不能按整行字符串搜到类名就当入口 |

来源见 [S07]～[S13]。以上是正负样本的依据，不是所有版本/启动器已经通过的兼容声明。Minecraft 1.20.1、1.21.1 仅是可固定重现的起始样本，实际版本由用户当前使用情况决定。

### C3 拟修改的识别逻辑

1. **先验证进程身份和归属。** 记录 PID + 创建时间、映像路径、归属链证据；对 PID 重用和父进程早退保持保守。启动器辅助 Java 也可能是后代，所以后代关系不能单独授权。
2. **按 Windows/Java 启动语义解析，而非在整个字符串中搜索。** 提取真正的入口位置、JVM 选项和程序参数。`-Dnote=...`、classpath 的文件名、日志文本不能被提升为游戏入口。
3. **结合已知客户端入口、launchTarget 和实例元数据建立解释。** 元数据只是一种声明，用户可写；不能因为 JSON 写着某个类就当作安全身份签名。模组启动器与游戏本来就可能不可信，本项目识别的是需约束的运行链，而不是证明其代码良性。
4. **参数文件支持从有限形式做起。** 绝对路径、已确认实例范围、单次读取上限、引号/编码规则与内容摘要先明确。无法可靠取得进程当前目录时，不猜测相对 @file 的根目录。文件内容可能在进程读取后变化，所以新读到的内容不能充当完整执行证明；不执行参数文件、不加载 JAR、不调用目标 Java 来“验证”。Oracle 明确说明参数文件里的相对文件名以当前工作目录为基准，而非参数文件所在目录。[S12]
5. **保留 Unknown。** 未知包装器、无法取得参数、仅有通用 BootstrapLauncher 或参数中出现包名，均不得自动进入已确认集合。JavaPaths 是用户确认的路径授权通道，也不能被写成实例级隔离。
6. **将生命周期等待集合与网络授权集合分开。** 可能属于游戏的 Java 可以使恢复继续等待；不确定的信息不能因此授予 Allow。客户端、服务器、安装器、下载器、检测 Java 版本、Gradle/IDE 分别分类，避免为了兼容把范围越放越大。基线已有服务器入口匹配，不能在本轮以“新增安全规则”为由悄悄删除既有兼容；服务器是否属于要授权的运行方式应单列确认。辅助工具与无关 IDE/Gradle 则必须有明确负样本。
7. **路径已登记但策略未成功的更新必须可重试。** `Sync-SessionJavaPaths` 不能仅因路径已在 cfg.JavaPaths 中就永久跳过本次未完成的策略步骤；保留 pending 的实际含义，并即时执行 ActiveStore 完整核验。周期性修复继续保留，但不能作为首次成功的替代证据。

### C4 首连兼容的最小方案

优先使用现有 JavaPaths.txt，由用户核实真正运行时后，在启动前处理该路径的冲突 Allow、建立原有精确端点规则并验证。没有新域名、端口、Any Allow，也不自动把候选列表全部加入配置。

运行后自动确认作为兼容补充；未确认仍不授予新规则。对于只在运行后才能确定的布局，应明确告知可能需要重试认证或补充准确路径，不能对外承诺透明兼容。缩短轮询只能减少部分延迟，不能消除窗口；本轮不引入挂起/注入/终止进程来制造原子保证。

### C5 选定启动器的验收矩阵

至少覆盖：原版、Fabric、Forge、NeoForge、Quilt 五种加载方式；再用一种实际采用的第三方包装启动器做跨模式测试。固定 Minecraft、加载器、启动器和 Java 版本，不要求将五种模式与所有历史版本做无边界笛卡尔积。

每组分别测试：准确显式路径、纯自动识别、冷/热 DNS、已有/无程序专属 Allow、Launcher 早退、辅助 Java 先启动、WMI 暂时失败。已有宽泛程序 Allow 的边界实验只用隔离测试端点与测试机器，不在日常机器制造放行。

记录单调时钟下的时间线：

- t0 Launcher 实际启动；t1 Java 创建；t2 首次观察；t3 归属/入口确认；
- t4 元数据落盘；t5 冲突 Allow 核验完成；t6 ActiveStore 精确规则验证；
- t7 动态地址就绪；t8 首次连接成功/失败及是否重试。

不记录完整 accessToken、用户名、UUID 或全部命令行；只记录入口类别、必要的脱敏参数名、文件摘要和证据状态。首次请求时刻取不到，就标记不可观测，不能用第一条 5157 日志冒充网络请求的精确起点。

通过条件包括：辅助/IDE/Gradle 不被自动授权；必要精确目标可按已说明的配置方式连接；未允许目标在隔离实验中仍被阻断；未就绪/不确定状态不能显示成保护成功。若发现已有未知路径 Allow 在识别前允许通信，作为已知架构阻塞项记录，不能用本轮补丁宣称消除。

## 六、方案 D：候选扫描增加预算与可恢复中断

### D1 当前事实

`loadJavaPaths` 仅扫描 Launcher 邻近和若干 Minecraft 运行时根，未扫描全磁盘。该点无需“修成”另一个无依据的大扫描器。

但根路径有限不代表工作量有限；一个 runtime 根也可能有大量文件、访问失败或慢存储。WalkDir 需要读取目录内容才能继续，Glob 又会忽略部分文件系统 I/O 错误，因此仅检查 Glob 返回 error 不能证明包目录枚举完整。[S14]

Go 1.23.2 的 Windows 文件模式对部分重解析标签的处理也不同；当前显式日志只检查 ModeSymlink。不能直接断言它会递归跟随 junction——该工具链还可能通过非目录/ModeIrregular 阻止递归；但也不能把“有一个 symlink 判断”写成所有 reparse 情况都已有完整日志和测试。

### D2 建议改进

- 用户有有效显式 JavaPaths 时，默认省去无必要的递归候选提示扫描；这不等于证明实际启动器一定使用了该路径。
- 无显式路径时仍只扫描现有有限根；Store 包根采用有限枚举并保留访问错误，不继续扩展成 Packages 下全部目录搜索。
- 加总耗时、总条目、目录数和错误记录预算；控制警告样本数，另记被省略数量，避免大量错误撑满内存/日志。
- 用分批目录枚举和取消检查替代“整个目录读完后才看到预算”的假限时。普通文件扫描不打开全部内容、不执行 Java。
- 明确返回 Complete / BudgetExceeded / Cancelled / IOIncomplete / LinkSkipped 及已发现候选，不能把中断结果包装成“已找到所有实际 Java”。
- 扫描在 UAC/系统修改之前进行，显示简洁进度。取消仅终止候选发现；是否继续启动取决于已有明确授权和模式，不能因扫描被取消就批量授权，或让后台扫描继续无界运行。
- 下一次启动可重新扫描或使用用户核实后的显式路径；本轮不增加持久化扫描缓存或复杂磁盘断点记录。

拟用于测试的起始预算可设为 **总计 5 秒或 5 万条目，警告样本最多 50 条，约每 500 毫秒刷新一次进度**。这些是待验证参数，不是已批准默认值或性能保证。

普通 context 检查无法中断已经阻塞的单次 Windows 文件系统调用。如果实测有这种卡顿，才进一步评估受控只读扫描子进程，超时终止并回收；不能只把扫描放到 goroutine 中、主程序超时返回，就声称扫描已停止。该内部执行方式另行复查后决定，不默认增加常驻服务。

### D3 验收

在固定测试机器上记录空目录、小目录、深层运行时、十万级条目、访问拒绝、重复根、junction/symlink、慢盘及取消场景。报告实际耗时、峰值内存、扫描结束后是否仍有工作、候选数和不完整原因。

有限深度不再作为正确性的硬门槛；有限时间/资源才是可用性边界。到达预算不能扩大白名单，也不能削弱受保护目录扫描或 ACL journal 的完整性要求：Java 候选扫描与 ACL 保护遍历是不同任务，不能共用“扫不完就忽略”的策略。

## 七、继续保留的设计限制与暂缓项

| 事项 | 本轮方案立场 | 原因 |
|---|---|---|
| 同一 Java EXE 被 Minecraft 和 IDE 共用 | 保留明确限制，不声称识别后规则只属于游戏实例 | New-NetFirewallRule 的 Program 是应用文件完整路径；进程用途和父子关系不是该路径规则的匹配条件。[S15] |
| 全局默认出站 BLOCK | 保留现状，单列副作用 | 修改它需要网络架构方案；不能先改全局 ALLOW 或给无关应用补宽泛规则 |
| 专用 Minecraft 运行时 | 可作为降低共享影响的用户选择，当前不自动安装/复制/切换 | 不解决当前全局 BLOCK；额外磁盘、更新、可信来源和启动器配置均需确认 |
| WFP/隔离环境重设计 | 只保留为下一课题 | 仅按 WFP 应用路径过滤也不等于按进程实例隔离；子层仲裁、故障回收和系统政策交互须独立验证 |
| 自动跟随目录链接 | 不实施 | 现有最终路径/文件身份/竞态与恢复设计仍不足；本轮只把链接纳入扫描与验收边界 |
| roots=0 | 不修改 | 用户此前已明确暂缓，没有新的实际覆盖失败证据支持顺手修改 |
| 不完整状态伪装成功 | 继续禁止 | 未确认进程退出、未知 ACL 效果、未验证规则、未完成对象清理均应分别记录，保留必要恢复资料 |

共享 Java 的验收不能只测 IDE 被拦截：还应验证同路径 IDE 的 Java 可能获得相同精确目的地 Allow。两种方向都属于路径级隔离的副作用，不能将精确 IP:端口误描述成实例身份绑定。

## 八、实施批次与发布门槛

这是一份建议顺序，不是授权执行。用户确认后，仍先编写最小复现和 Windows 基线，再集中修改对应模块。

| 阶段 | 工作与预期产物 | 进入下一阶段的条件 |
|---|---|---|
| 0，先获取证据 | ACL 显式 Allow/继承 Deny 的 NTFS 反例；真实独立 Watchdog 非空恢复；FQDN 中断清单；选定启动器脱敏样本 | 版本、身份、SDDL、时间线与实际系统结果齐全；不能用 PS7 解析或已有 107 项模拟顶替 |
| 1，最小安全修正 | A 的实际效果门禁与来源保护；B 的重建顺序/查询失败处理；对应共享函数和迁移设计 | 三组件语义一致，真实规则/ACL 结果通过；新旧记录可恢复；无外部 ACE/规则误删 |
| 2，兼容和性能 | C 的结构化入口与策略 pending/verified；D 的扫描预算；精确 DNS 就绪诊断 | 已选启动器支持范围可列清，辅助 Java 负样本通过，扫描可终止，未授权流量测试没有新增放宽 |
| 3，发布审核 | Windows Go test/vet、PS5.1 完整脚本解析、双构建和哈希，真实 Apply/rollback/Watchdog/旧会话恢复 | 功能验收证据与编译证据分别记录；文档明示共享 Java/全局 BLOCK/动态发现窗口；用户批准发布 |

若阶段 0 证明某项无需改代码，只新增验收证据和说明，不为了“方案列了这一项”就强行改实现。若 A/B 的安全语义需要更大改造，先收敛范围和状态迁移方案，不将它混入一连串孤立补丁。

### 必须同时核对的入口

| 工作 | Go 主程序 | Helper | Watchdog | 恢复/迁移 |
|---|---|---|---|---|
| A | hasDenyForSID、主流程 ACL 门禁 | Test-GuardProtectionEffective、Protect-PathIfNeeded | 同一判定、Reapply-GuardACLs | Remove-GuardDeny 保留来源语义；Restore-GuardACLs/Restore-Files/旧 journal |
| B | 就绪与最终恢复报告 | Add-Firewall、Remove-Firewall | Rebuild-FirewallRules、Remove-UnavailableFqdnTargets、Remove-Fw | Save/Remove-PendingDynamicId(s)、Assert-DynamicCleanupComplete、旧会话动态清理 |
| C | queryMinecraftJavaProcess、启动检查、用户提示 | 同一进程识别和初始规则审计 | Get-SessionProcessState、Sync-SessionJavaPaths、周期核验 | ResumeWatchdog 从可信元数据恢复；待核验状态不可误判为就绪 |
| D | loadJavaPaths、发现结果及诊断 | 不扩大 cfg.JavaPaths | 不因候选/扫描未完自动授权 | 显式配置和已有恢复格式不受扫描取消破坏 |

## 九、需求溯源与本轮边界

| 需求来源 | 本文件响应 |
|---|---|
| 本次反馈：Java 首次连接、加载器参数和辅助 Java | 方案 C；三种时序窗口、入口样本、负样本和实际启动器时间线 |
| 本次反馈：共享 Java | 第七节；路径规则双向副作用，未把它包装成已解决 |
| 本次反馈：取消深度限制后的性能与可中断 | 方案 D；有限根、总预算、批量读取、明确不完整状态 |
| 本次反馈：真实 ACL 与独立 Watchdog | 方案 A；新增 DACL 顺序反例、正确令牌、逐访问位、真实独立进程恢复 |
| 本次反馈：FQDN 生命周期与 Watchdog 重启 | 方案 B；重建顺序、阶段记录、故障注入、对象未解析与不存在的区分 |
| 本次反馈：总体网络架构暂不擅改 | 第一、七节；不切换全局 ALLOW，不扩大白名单 |
| 原始文档：先审计、完整链路、可溯源总结、实机/模拟分开 | 第二、八、十节及源码定位表 |
| 本次明确要求：先输出方案，不落实修改 | 全文仅为提案；项目文件和原 ZIP 哈希核对不变 |

## 十、当前源码定位与可复核证据

本轮核对的 `GuardLauncher_v17.go` SHA-256：

`fc76cb30e26c4a2d1dd6a5d17235b7d7ec56c4448688ada6c9e1aa74e5bf3fe8`

原 v17.16 ZIP SHA-256：

`34fca4c420df54be24d3f8f604c4ed042359cd1479793b931ada9b74ba43c6bd`

行号只适用于上述源码；函数名与哈希共同用于定位，未来修改后行号会变化。

| 定位 | 审查内容 |
|---|---|
| 第 212 行起 Sync-SessionJavaPaths | 持久路径、跳过已登记路径、规则更新顺序 |
| 第 287 行起 Test-MinecraftJavaCommandLine；第 441 行附近 | 全字符串强匹配与 ConfirmedJavaProcesses 组合条件 |
| 第 463 行起 Test-GuardProtectionEffective | Deny 存在性与 InheritOnly 过滤 |
| 第 478～520 行附近 | 动态 ID 记账、删除失败保留、最终查询核验 |
| 第 2551 行起 Rebuild-FirewallRules | 旧对象删除分支、第 2599 行附近端点写入、第 2601 行后规则清除、第 2631 行后数量检查 |
| 第 2893 行起 Restore-GuardACLs | 非空 journal 和 Guard ACE 恢复 |
| 第 3020 行附近 | 自动 Java 同步与后续周期性实际策略核验 |
| 第 3877 行起 loadJavaPaths | 显式路径、候选根、Glob、WalkDir、警告收集 |
| tests/verify_powershell.ps1 第 27、125～135 行附近 | Get-Acl 与实际 ACE 删除的替代函数说明，不能代替独立 NTFS 验收 |

只读夹具的原函数输出：

| 输入 | v17.16 原函数输出 | 该输出能证明什么 |
|---|---|---|
| vanilla：明确 Minecraft 客户端主类 | true | 基本正样本可命中，不等于所有版本兼容 |
| 属性值包含客户端主类，真正入口为 helper.jar | true | 全行子串可以造成错误入口证据 |
| classpath 文件名包含 net.neoforged.tools，真正入口为 example.Helper | true | 包名前缀不等于游戏主类 |
| 只有 @args.txt | false | 该函数未读取/解析参数文件；具体启动器是否使用该形式需实测 |
| 显式 Allow 后继承 Deny 的模拟 ACL 列表 | reportedProtected=true | 当前函数不计算完整访问效果；不证明 NTFS 实机必现 |

本轮夹具只在独立研究目录运行，未写入或替换项目测试。没有产生新的程序版本。项目目录 115 个文件及原发布 ZIP 的哈希在方案交付前再次核对。

## 十一、权威资料与样本来源

检索/读取日期均为 2026 年 11 月 8 日。只采用厂商官方文档、官方发布元数据及项目第一方源码；未将论坛报错、第三方教程或搜索摘要作为加载器支持证据。

### Windows 权限和网络

- **[S01] Microsoft How AccessCheck Works**：DACL 按顺序与令牌核验，访问获准/拒绝可提前结束。用于 A 的语义依据，不证明本机 ACL 结构。https://learn.microsoft.com/en-us/windows/win32/secauthz/how-dacls-control-access-to-an-object
- **[S02] Microsoft Order of ACEs in a DACL**：显式与继承 ACE 的顺序。用于显式 Allow/继承 Deny 反例设计。https://learn.microsoft.com/en-us/windows/win32/secauthz/order-of-aces-in-a-dacl
- **[S03] Microsoft AccessCheck API**：主体令牌、GenericMapping、调用返回值与 AccessStatus。不是即插即用的 Guard 令牌设计。https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-accesscheck
- **[S04] Microsoft Firewall dynamic keywords API 概述**：动态对象的生命周期、引用关系和重启行为。用于恢复状态设计。https://learn.microsoft.com/en-us/windows/win32/ics/firewall-dynamic-keywords
- **[S05] Microsoft Windows Firewall dynamic keywords**：DNS 异步更新、前置条件和预解析。本文只考虑现有精确目标，不采用该页的通配符/额外解析器放行示例。https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/dynamic-keywords
- **[S06] Microsoft Windows Firewall rules**：默认 Block、显式 Allow/Block 优先级。不能据此保证未知路径的既有规则无效。https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/rules
- **[S15] Microsoft New-NetFirewallRule Program 参数**：按应用文件完整路径限定。https://learn.microsoft.com/en-us/powershell/module/netsecurity/new-netfirewallrule

### Minecraft 与加载器第一方样本

- **[S07] Mojang 官方 Minecraft 1.21.1 版本 JSON**：实际读取 mainClass、arguments 和 javaVersion；固定历史样本，不是“当前最新版”的建议。https://piston-meta.mojang.com/v1/packages/82ba6501da174a665c1787775f946487422f2432/1.21.1.json
- **[S08] FabricMC fabric-loader 安装元数据生成源码**：客户端、服务器和 LaunchWrapper 入口声明。https://github.com/FabricMC/fabric-loader/blob/master/gradle/installer-json.gradle
- **[S09] Forge 官方 Maven 安装器 1.20.1-47.2.0**：只读取 ZIP 内 version.json，未运行安装器；包含 BootstrapLauncher/forgeclient 的历史样本。https://maven.minecraftforge.net/net/minecraftforge/forge/1.20.1-47.2.0/forge-1.20.1-47.2.0-installer.jar
- **[S10] NeoForged FancyModLoader Client 固定提交**：客户端转发入口；提交为 e19b9b422939e18b6f56983067d8bd028c7d38f3。https://raw.githubusercontent.com/neoforged/fancymodloader/e19b9b422939e18b6f56983067d8bd028c7d38f3/loader/src/main/java/net/neoforged/fml/startup/Client.java
- **[S11] QuiltMC KnotClient 源码**：客户端入口样本。https://raw.githubusercontent.com/QuiltMC/quilt-loader/develop/src/main/java/org/quiltmc/loader/impl/launch/knot/KnotClient.java
- **[S12] Oracle Java 21 java 命令手册**：启动入口、JAR/模块和参数文件语义。https://docs.oracle.com/en/java/javase/21/docs/specs/man/java.html
- **[S13] PrismLauncher StandardLauncher 第一方源码**：接收 mainClassName 后反射执行。只支持“存在包装转发机制”的判断，不能替代具体 Prism 版本实测。https://raw.githubusercontent.com/PrismLauncher/PrismLauncher/develop/libraries/launcher/org/prismlauncher/launcher/impl/StandardLauncher.java

### Go 扫描行为

- **[S14] Go filepath 文档及当前工具链源码**：Glob 的错误处理、WalkDir 整目录读取/不跟随符号链接。当前基线工具链为 Go 1.23.2，另核对其 Windows file mode 实现，避免把所有 reparse tag 都当作 ModeSymlink。https://pkg.go.dev/path/filepath ；固定版本源码：https://raw.githubusercontent.com/golang/go/go1.23.2/src/path/filepath/path.go ；Windows 类型：https://raw.githubusercontent.com/golang/go/go1.23.2/src/os/types_windows.go

分支型上游来源将来可能更新。下表记录本轮实际下载内容摘要，便于与固定研究样本核对；实施时仍需固定到具体发布版本/提交，而非实时追随 master/develop。

| 样本 | 本轮读取内容 SHA-256 |
|---|---|
| Mojang 1.21.1 JSON | `3636c26c20f1f0b7472ebef1a624ba1a6a2c4b003858c13224929898b5321437` |
| Fabric 安装元数据源码 | `ba575e888b12d3697c0a87fc161953718f469cf8a6c0bc4b2c2e8974c4201a1a` |
| Quilt KnotClient 源码 | `d3abd4a2f19d022b28f5f01a26ba18a4d05c7825d79258e97dbbeff7c2490c7e` |
| NeoForge 固定提交 Client 源码 | `2722aae706f2ce94d08ffb544c67995340611d71d93b879efb63add1537059e6` |
| Prism StandardLauncher 源码 | `74e7901d3a95fe3b7c1db7a7f93bce16f26bc044b94e5369d93e2cc6cad0f5fd` |
| Go 1.23.2 filepath 源码 | `4ab76f2082841d2524f2bef6bab0d2502e70814e6e557deebde04f6fee67ec19` |
| Forge 官方安装器 JAR 整体 | `bc2a0f7b161a2d8284df3d603f7f2b22313b246f026ad77511cbd35bcd01caac` |

**建议用户确认的核心范围：A 与 B 的安全与恢复修正、C 的入口和就绪处理、D 的受控扫描。** 全局网络架构、共享 Java 实例隔离、自动链接跟随另行立项，不在这批改动中顺带实施。
