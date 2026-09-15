# UEBA 日志分类与最小 ECS 字段全量表

## 1. 这份文档怎么用

本文是**逐来源、逐事件的最小字段映射契约**。覆盖 Windows 报告全部 **32 个事件 ID**、Zeek **38 类日志**、Linux **22 类记录**。不是 ECS 所有字段全集，也不是宣称服务器已采集所有类型。

- 第 2 节：公共最小字段和条件规则。
- 第 3 节：92 类来源的分类/数据集索引目录。
- 第 4 节：32 个 Windows 事件逐项映射；每个有样本的事件引用报告中的真实字段值。4624 另有 11 种登录类型的条件映射、完整原始 XML 及清洗后业务投影。
- 第 5 节：38 类 Zeek 日志逐项映射，基于原始 JSON key；这是设计映射，不是本次实时 ES 样本。
- 第 6 节：22 类 Linux 日志逐项映射，标明文本提取和 audit 多记录关联条件。
- 第 7 节：部署/验证边界。
- 第 8 节：保留枚举字典，解释含义和选择条件。

**必要性约定：必备=本项目最低契约；条件=原始有值且语义明确时填写；可选=不影响首版核心统计；扩展=不是 ECS 标准字段，但可能是关联分析所必需。** 条件字段缺失时省略，不补空字符串、0、false、未知用户名或推测的来源 IP；原始真实的 0/false（如 auth_attempts=0、auth_success=false）必须保留，不按“假值”删除。字段不足时标记该分析能力受限，不能用默认值掩盖。

**event.action 为可选项。** Windows 可以依据 event.code 区分动作；Zeek 可依据 dataset 和协议字段。末尾动作字典供跨来源统一规则时采用，不要求强制维护/填满全部动作。

命名仍为 `<module>.<dataset>-<namespace>`：`module.dataset`（自定义）只是命名表达式，实际字段是 `event.module` 和 `event.dataset`，例如 zeek、zeek.ssh；生产目标为 zeek.ssh-prod。“（自定义）”和“-prod”都不写进 event.dataset 值。同一记录多类别只存一份。

Windows 实证依据为 [AD-UEBA关键事件真实日志模拟报告.md](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md>)。本次重新解析该报告的原始 XML：31 个事件有代表样本，4740 无样本，明确保留。没有重新连接服务器，也没有把清洗设计示例冒充 ES 已存数据。

## 2. 公共最小字段：每种日志都先执行这里

下表由各来源详细表继承；同一记录只生成一份公共字段。表中 keyword[]/ip[] 表示同类型多值，ES mapping 仍为 keyword/ip；不是独立的数组类型。条件字段有值且语义成立才写入，不能仅靠字段名相似复制。

| 原始字段或生成依据 | 目标 ECS 字段 | 类型 | 要求 | 规则与含义 |
|---|---|---|---|---|
| Windows System.TimeCreated/@SystemTime；Zeek ts；Linux 原文时间 | @timestamp | date；需纳秒查询精度时明确采用 date_nanos | 必备 | 事件发生时间，不是采集时间。date 的检索精度为毫秒；保留原文中的更高精度，不能宣称默认 date 可按纳秒聚合 |
| 固定并验证过的 schema 版本 | ecs.version | keyword | 必备/生成 | 上线配置注入，不能使用 ES/Beat 版本替代 |
| 采集来源配置 | event.module | keyword | 必备/生成 | windows、zeek、linux；不要求开启官方模块 |
| 来源和解析器配置 | event.dataset | keyword | 必备/生成 | 第 3 节的数据集，生产目标名称为该值加 -prod |
| 记录性质 | event.kind | keyword | 必备/生成 | 普通活动 event；探针测量 metric；明确外部检测 alert；失败处理可为 pipeline_error |
| 事件 ID、操作码、对象和协议语义 | event.category | keyword 数组 | 能分类时必备/生成 | 仅使用末尾标准类别，缺乏适用类别时省略 |
| 生命周期或操作语义 | event.type | keyword 数组 | 能分类时必备/生成 | start/end/change 等，成功失败不放这里 |
| Audit 标志、业务状态、明确结果 | event.outcome | keyword | 有结果语义时条件/生成 | success/failure/unknown；无结果概念的指标等省略 |
| 原始 ID/类型 | event.code | keyword | 有事件代码时条件/原始 | Windows Event ID、Linux audit type；不是 ES _id |
| 原始事件生产者 | event.provider | keyword | 可选/原始 | Windows Provider、sshd、sudo 等 |
| 原始一条 XML/JSON/文本或关联 audit 原文 | event.original | keyword，index=false、doc_values=false | 建议保留/原始 | 查询 _source 可回看；敏感凭据保护策略先落实。表格截断显示不代表可截断存储原文 |
| ES ingest 当前时间 | event.ingested | date | 建议/生成 | 入库延迟排查，不代替 @timestamp |
| 采集器首次读取时间 | event.created | date | 可选/生成 | 只有采集器实际提供时保留 |
| 解析错误信息 | error.message | match_only_text | 失败路径条件 | 原始证据保留并可监控；不能静默丢弃 |
| 可选统一动作映射 | event.action | keyword | 可选/生成 | ECS 不强制；未知时省略，不生成没有区分价值的固定字符串 |
| 真实采集实例与文件路径 | agent.id/type/version、log.file.path | keyword | 建议/原始或配置 | log.file.path 是被采集文件；file.path 是事件操作的业务文件，不互换 |

证据角色：Windows/Linux 主机事件用 host.name（可获稳定 ID 时加 host.id）；Zeek 探针用 observer.name/type。source.ip/destination.ip 表示通信双方，不能填成探针地址。ECS 字段定义依据：[Event](https://www.elastic.co/docs/reference/ecs/ecs-event)、[User 角色](https://www.elastic.co/docs/reference/ecs/ecs-user-usage)、[网络端点](https://www.elastic.co/docs/reference/ecs/ecs-source)。

### 2.1 身份、时间与原始证据

| 规则 | 最小实现 |
|---|---|
| 身份分工 | 登录事件的 user 是被认证身份；IAM 的 user 是操作者、user.target 是受影响用户；su/sudo 的请求者用 user，目标权限身份用 user.effective。Windows Subject、Target 的角色逐事件定义，不能统一批量复制 |
| 身份归一化 | 保留原 SID/UID；Windows DOMAIN\\name 或已确认的 UPN 按格式拆分。NetBIOS 域与 DNS 域的等价关系需受控目录映射，不仅靠小写转换。Linux UID 必须结合 host.id/name，不能与域 SID 或其他主机同 UID 合并 |
| 跨角色检索 | 有账号时建议生成 related.user（keyword[]，角色账号去重）；它只用于查找，不代替明确的账号角色。按用户基线统计应选择对应角色及稳定身份键 |
| 时间口径 | @timestamp 按来源含义：Windows 事件时间；Zeek conn/ssh 的连接开始时间；协议事务按各日志 ts；探针指标按测量记录时间。不能把连接起点当每次密码尝试时刻 |
| 稳定关联 | Windows 使用主机＋会话 ID＋时间/启动边界；Zeek 使用探针＋uid，再结合协议事务标识；audit 使用主机＋启动上下文＋审计时间及 serial。关联键不是文档唯一键 |
| 原始证据 | event.original 是 ECS 标准 keyword 字段，关闭 index/doc_values；只能从 _source 回看，不能替代用于筛选/聚合的必要扩展字段。JSON 对象不得直接塞入此字符串字段 |
| 解析版本 | 固定 ECS schema、Windows Provider/EventID/Version、Zeek 版本/脚本与 Linux 格式版本，分别做样本验收；ecs.version 不填写软件版本。没有实际部署版本证据时不标记已兼容 |
| 未知值 | 原字段缺失与 false/0 区分；占位符按字段语义处理。SystemTime 解析失败进入错误路径，不以当前时间伪装事件时间 |

## 3. 来源 → 类别 → module.dataset（自定义）：92 类目录

动作字段已从必备列移除。类型栏的斜杠/“按动作”等是条件说明，不是可直接写入的字符串。

| 日志来源 | event.category | module.dataset（自定义） | event.type |
|---|---|---|---|
| Windows 4624 登录成功 | authentication + session | windows.security | start；解锁 Type 7/13 为 info |
| Windows 4625 登录失败 | authentication | windows.security | start |
| Windows 4634 会话结束 | session | windows.security | end |
| Windows 4647 主动注销 | session | windows.security | end |
| Windows 4648 显式凭据 | authentication | windows.security | info |
| Windows 4740 账户锁定 | iam | windows.security | change + user |
| Windows 4768 请求 TGT | authentication | windows.security | info |
| Windows 4769 请求服务票据 | authentication | windows.security | info |
| Windows 4771 Kerberos 预认证失败 | authentication | windows.security | info |
| Windows 4776 NTLM 凭据验证 | authentication | windows.security | info |
| Windows 4720 创建用户 | iam | windows.security | creation + user |
| Windows 4722 启用用户 | iam | windows.security | change + user |
| Windows 4723 修改自身密码 | iam | windows.security | change + user |
| Windows 4724 重置他人密码 | iam | windows.security | change + user |
| Windows 4725 禁用用户 | iam | windows.security | change + user |
| Windows 4726 删除用户 | iam | windows.security | deletion + user |
| Windows 4738 用户属性修改 | iam | windows.security | change + user |
| Windows 4741 创建计算机账户 | iam | windows.security | creation |
| Windows 4742 修改计算机账户 | iam | windows.security | change |
| Windows 4743 删除计算机账户 | iam | windows.security | deletion |
| Windows 4728 全局组添加成员 | iam | windows.security | change + group |
| Windows 4729 全局组移除成员 | iam | windows.security | change + group |
| Windows 4732 本地域组添加成员 | iam | windows.security | change + group |
| Windows 4733 本地域组移除成员 | iam | windows.security | change + group |
| Windows 4756 通用组添加成员 | iam | windows.security | change + group |
| Windows 4757 通用组移除成员 | iam | windows.security | change + group |
| Windows 4661 SAM 对象句柄访问 | iam（报告样本） | windows.security | info |
| Windows 4662 目录服务对象操作 | iam | windows.security | info；明确修改时 change |
| Windows 4670 对象权限改变 | file / registry / iam，按对象类型选取 | windows.security | change |
| Windows 4673 调用特权服务 | api | windows.security | info |
| Windows 4688 进程创建 | process | windows.security | start |
| Windows 4689 进程结束 | process | windows.security | end |
| Zeek conn.log | network | zeek.conn | connection |
| Zeek dns.log | network | zeek.dns | protocol |
| Zeek ssh.log | network；有认证判定时可加 authentication | zeek.ssh | protocol |
| Zeek rdp.log | network | zeek.rdp | protocol |
| Zeek kerberos.log | network + authentication | zeek.kerberos | protocol |
| Zeek ntlm.log | network + authentication | zeek.ntlm | protocol |
| Zeek http.log | network + web | zeek.http | access |
| Zeek ssl.log | network | zeek.ssl | protocol |
| Zeek x509.log | network | zeek.x509 | info |
| Zeek ocsp.log | network | zeek.ocsp | info |
| Zeek files.log | file | zeek.files | info |
| Zeek smb_files.log | network + file | zeek.smb_files | access；明确动作时 creation/change/deletion |
| Zeek smb_mapping.log | network | zeek.smb_mapping | access |
| Zeek dce_rpc.log | network + api | zeek.dce_rpc | protocol |
| Zeek ftp.log | network；明确文件传输时可加 file | zeek.ftp | protocol |
| Zeek smtp.log | network + email | zeek.smtp | info |
| Zeek dhcp.log | network | zeek.dhcp | protocol |
| Zeek ntp.log | network | zeek.ntp | protocol |
| Zeek snmp.log | network | zeek.snmp | protocol |
| Zeek quic.log | network | zeek.quic | protocol |
| Zeek tunnel.log | network | zeek.tunnel | connection |
| Zeek ldap.log（版本/脚本支持时） | network；明确绑定认证时加 authentication | zeek.ldap | protocol |
| Zeek ldap_search.log（版本/脚本支持时） | network | zeek.ldap_search | access |
| Zeek radius.log（启用时） | network + authentication | zeek.radius | protocol |
| Zeek sip.log（启用时） | network | zeek.sip | protocol |
| Zeek irc.log（启用时） | network | zeek.irc | protocol |
| Zeek syslog.log（启用时） | network；消息可可靠解析时补语义类别 | zeek.syslog | info |
| Zeek weird.log | network | zeek.weird | info |
| Zeek notice.log | 按 note 分类；明确入侵检测为 intrusion_detection | zeek.notice | info |
| Zeek intel.log（启用情报框架时） | intrusion_detection（作为检测命中记录时） | zeek.intel | info |
| Zeek signatures.log（启用时） | intrusion_detection（检测签名命中） | zeek.signatures | info |
| Zeek software.log | package | zeek.software | info |
| Zeek known_hosts.log（启用时） | host | zeek.known_hosts | info |
| Zeek known_services.log（启用时） | network | zeek.known_services | info |
| Zeek stats.log | 省略 | zeek.sensor | info |
| Zeek capture_loss.log | 省略 | zeek.sensor | info |
| Zeek reporter.log | 省略或按明确内容分类 | zeek.sensor | info/error，按实际等级 |
| Zeek dpd.log / analyzer.log（按实际版本） | network | zeek.analyzer | info |
| Linux secure/auth.log：sshd/PAM 登录认证 | authentication | linux.auth | start |
| Linux secure/auth.log：su/sudo 认证检查 | authentication | linux.auth | info |
| Linux secure/auth.log：PAM 会话开始 | session | linux.auth | start |
| Linux secure/auth.log：PAM 会话结束 | session | linux.auth | end |
| Linux secure/auth.log：用户创建/变更/删除 | iam | linux.auth | creation/change/deletion + user |
| Linux secure/auth.log：组及成员管理 | iam | linux.auth | change + group；组创建/删除按动作 |
| Linux secure/auth.log：passwd、锁定/解锁 | iam | linux.auth | change + user |
| Linux secure/auth.log：sudo 命令记录 | process | linux.auth | info |
| Linux audit.log：USER_AUTH 等认证记录 | authentication | linux.audit | info |
| Linux audit.log：USER_START/USER_END | session | linux.audit | start/end |
| Linux audit.log：账号/组变更审计 | iam | linux.audit | creation/change/deletion，按操作 |
| Linux audit.log：execve/execveat 执行审计 | process | linux.audit | start（执行成功）；失败尝试用 info |
| Linux audit.log：文件访问/修改审计 | file | linux.audit | access/creation/change/deletion，按 syscall |
| Linux audit.log：sudoers/sshd 等配置修改 | configuration + file | linux.audit | change |
| Linux audit.log：审计规则/审计配置变更 | configuration | linux.audit | change |
| Linux audit.log：SELinux AVC 拒绝 | 按对象选 file/process/network 等 | linux.audit | file/process 常用 access；network 可用 denied |
| Linux messages/syslog/journal：主机启动/关闭 | host | linux.system | start/end |
| Linux messages/syslog/journal：服务生命周期 | process | linux.system | start/end/info，按事件 |
| Linux messages/syslog/journal：其他运行日志 | 可判断才设置，否则省略 | linux.system | info/error，按内容 |
| Linux dpkg.log/apt/history.log/dnf.log/yum.log：软件变更 | package | linux.package | installation/change/deletion，按动作 |
| Linux nginx/apache access.log（可选） | web | linux.web_access | access |
| Linux 应用运行日志（可选） | 按明确业务语义，不统一归 application | linux.application | info/error 或业务子类 |

## 4. Windows：32 个原始事件逐项映射

### 4.0 原始 XML 与采集器字段的对应规则

- 以下 System/EventData 路径指**原始 XML**，不是要求文档里真的建立 System 对象。若 Winlogbeat 已提供 @timestamp、host.name、winlog.event_id、winlog.event_data.*，按实际采集器字段读取，不能假定原始 XML 一定在 message 中。
- 原始 XML 中 UserSid/TargetSid 等名字存在差异，每张表按报告原值列出；无样本 4740 仅列拟支持规则。表内较长值显示截断时会明确标记，完整值从对应报告定位获取。
- winlog.channel、winlog.record_id、winlog.event_data.* 都是**源扩展，不是 ECS 核心字段**。保留最小事件定位字段；ECS user/process 等不适合承载的源细节放扩展或 event.original。
- 认证主体不等于日志生成主体；IAM 的操作人用 user.*，被管理者用 user.target.*；组的成员 DN 不直接存成短用户名。
- 审计成功/失败基于 System.Keywords 的 Audit Success/Failure 位及该事件业务 Status；4689 的 Status 是进程退出码，不能拿它判断审计失败。

所有 Windows 事件继承以下定位字段，不在后续 31 张表重复列行；**其实际值从各节样本定位段读取，映射仍是每条事件必备项**。4624 保留全展开示例。

| 原始 XML | 目标 | 类型 | 规则 |
|---|---|---|---|
| System.TimeCreated/@SystemTime | @timestamp | date | 原 UTC 事件时间 |
| System.Computer | host.name | keyword | 原事件主机，不是 WEF 收集器 |
| System.Channel | winlog.channel【扩展】 | keyword | Security |
| System.EventRecordID | winlog.record_id【扩展】 | keyword | 本项目新模板采用字符串；若沿用现有 Beat 模板为其它类型，先统一契约/新目标，不能直接改旧字段类型 |
| System.Version | winlog.version【扩展】 | long | 事件版本，用于选择分支 |
| System.Provider/@Name | event.provider | keyword | 原始提供者 |

按 Provider＋EventID＋Version 选择分支。表内“未提供（条件映射规则）”不是样本值，更不能写入 ES。

### 4.1 4624 — 登录成功

分类：`authentication + session`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`start`（Type 7/13 解锁为 `info`）。event.action 可选：`logon-success`（解锁可省略或另设动作）。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:7>)；主机 `win-169.test.local`，Security Record ID `20512`，时间 `2026-09-11T03:40:07.1228815Z`。以下是报告样本，不是本次 ES 查询结果。

完整原始 XML（来自报告，未改写）：

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-a5ba-3e3b0328c30d}'/><EventID>4624</EventID><Version>3</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8020000000000000</Keywords><TimeCreated SystemTime='2026-09-11T03:40:07.1228815Z'/><EventRecordID>20512</EventRecordID><Correlation ActivityID='{cb1ba9a2-3b55-0001-f7a9-1bcb553bdd01}'/><Execution ProcessID='908' ThreadID='1488'/><Channel>Security</Channel><Computer>win-169.test.local</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-5-21-425182487-128829183-2370913515-500</Data><Data Name='SubjectUserName'>Administrator</Data><Data Name='SubjectDomainName'>WIN-169</Data><Data Name='SubjectLogonId'>0xf1d4191</Data><Data Name='TargetUserSid'>S-1-5-21-4210831952-4165203136-4232524810-1122</Data><Data Name='TargetUserName'>UEBALOGON-11113950</Data><Data Name='TargetDomainName'>test</Data><Data Name='TargetLogonId'>0xf1d7b33</Data><Data Name='LogonType'>2</Data><Data Name='LogonProcessName'>Advapi  </Data><Data Name='AuthenticationPackageName'>Negotiate</Data><Data Name='WorkstationName'>WIN-169</Data><Data Name='LogonGuid'>{2bf09c60-5444-beb9-39ed-165696f615c1}</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x1b04</Data><Data Name='ProcessName'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='IpAddress'>-</Data><Data Name='IpPort'>-</Data><Data Name='ImpersonationLevel'>%%1833</Data><Data Name='RestrictedAdminMode'>-</Data><Data Name='RemoteCredentialGuard'>-</Data><Data Name='TargetOutboundUserName'>-</Data><Data Name='TargetOutboundDomainName'>-</Data><Data Name='VirtualAccount'>%%1843</Data><Data Name='TargetLinkedLogonId'>0x0</Data><Data Name='ElevatedToken'>%%1843</Data></EventData></Event>
```

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.TimeCreated/@SystemTime | 2026-09-11T03:40:07.1228815Z | @timestamp | date | 必备/转换 | 解析 UTC 时间；保持事件时间语义 |
| System.EventID | 4624 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Computer | win-169.test.local | host.name | keyword | 必备/原始 | 实际写入 Security 事件的主机，不是 WEF 收集器 |
| System.Channel | Security | winlog.channel【扩展】 | keyword | 必备/原始 | 与主机、Record ID 一起回查 |
| System.EventRecordID | 20512 | winlog.record_id【扩展】 | keyword | 必备/原始 | 不是全局唯一，不等于 ES _id |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.TargetUserSid | S-1-5-21-4210831952-4165203136-4232524810-1122 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOGON-11113950 | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x1b04 | process.pid | long | 条件/原始 | 十六进制转十进制 6916；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.IpAddress | - | source.ip | ip | 条件/原始 | 本样本不生成该目标值；合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | - | source.port | long | 条件/原始 | 本样本不生成该目标值；仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.LogonType | 2 | winlog.event_data.LogonType【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.TargetLogonId | 0xf1d7b33 | winlog.event_data.TargetLogonId【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.AuthenticationPackageName | Negotiate | winlog.event_data.AuthenticationPackageName【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.SubjectUserSid | S-1-5-21-425182487-128829183-2370913515-500 | winlog.event_data.SubjectUserSid【扩展】 | keyword | 条件/原始或转换 | 发起登录的上下文主体；不覆盖被认证的 user.* |
| EventData.SubjectUserName | Administrator | winlog.event_data.SubjectUserName【扩展】 | keyword | 条件/原始或转换 | 发起登录的上下文主体；不覆盖被认证的 user.* |
| EventData.SubjectDomainName | WIN-169 | winlog.event_data.SubjectDomainName【扩展】 | keyword | 条件/原始或转换 | 发起登录的上下文主体；不覆盖被认证的 user.* |
| EventData.SubjectLogonId | 0xf1d4191 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始或转换 | 发起登录的上下文主体；不覆盖被认证的 user.* |
| EventData.LogonGuid | {2bf09c60-5444-beb9-39ed-165696f615c1} | winlog.event_data.LogonGuid【扩展】 | keyword | 条件/原始或转换 | 会话关联；全零 GUID/0x0 不参与有效关联 |
| EventData.TargetLinkedLogonId | 0x0 | winlog.event_data.TargetLinkedLogonId【扩展】 | keyword | 条件/原始或转换 | 会话关联；全零 GUID/0x0 不参与有效关联 |
| EventData.TargetOutboundUserName | - | winlog.event_data.TargetOutboundUserName【扩展】 | keyword | 条件/原始或转换 | Type 9 对外凭据身份；与本地 Target 身份分开，不证明远端已认证 |
| EventData.TargetOutboundDomainName | - | winlog.event_data.TargetOutboundDomainName【扩展】 | keyword | 条件/原始或转换 | Type 9 对外凭据身份；与本地 Target 身份分开，不证明远端已认证 |
| EventData.WorkstationName | WIN-169 | winlog.event_data.WorkstationName【扩展】 | keyword | 条件/原始或转换 | 工作站/登录进程/NTLM 子类型；原始有值才保留，不从来源主机补造 |
| EventData.LogonProcessName | Advapi   | winlog.event_data.LogonProcessName【扩展】 | keyword | 条件/原始或转换 | 工作站/登录进程/NTLM 子类型；原始有值才保留，不从来源主机补造 |
| EventData.LmPackageName | - | winlog.event_data.LmPackageName【扩展】 | keyword | 条件/原始或转换 | 工作站/登录进程/NTLM 子类型；原始有值才保留，不从来源主机补造 |
| EventData.ElevatedToken | %%1843 | winlog.event_data.ElevatedToken【扩展】 | keyword | 条件/原始或转换 | 保留源标志/消息代码，不把 %%1842/%%1843 当布尔文本；按版本解释 |
| EventData.VirtualAccount | %%1843 | winlog.event_data.VirtualAccount【扩展】 | keyword | 条件/原始或转换 | 保留源标志/消息代码，不把 %%1842/%%1843 当布尔文本；按版本解释 |
| EventData.ImpersonationLevel | %%1833 | winlog.event_data.ImpersonationLevel【扩展】 | keyword | 条件/原始或转换 | 保留源标志/消息代码，不把 %%1842/%%1843 当布尔文本；按版本解释 |
| EventData.RestrictedAdminMode | - | winlog.event_data.RestrictedAdminMode【扩展】 | keyword | 条件/原始或转换 | 保留源标志/消息代码，不把 %%1842/%%1843 当布尔文本；按版本解释 |
| EventData.RemoteCredentialGuard | - | winlog.event_data.RemoteCredentialGuard【扩展】 | keyword | 条件/原始或转换 | 保留源标志/消息代码，不把 %%1842/%%1843 当布尔文本；按版本解释 |
| EventData.KeyLength | 0 | winlog.event_data.KeyLength【扩展】 | keyword | 条件/原始或转换 | 协商会话密钥长度原值；不是密码长度，按加密分析需要保留 |
| EventData.TransmittedServices | - | winlog.event_data.TransmittedServices【扩展】 | keyword | 条件/原始或转换 | 认证委派经过的服务；按场景保留 |
| 解析配置/事件规则 | windows / windows.security / authentication + session / start | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

对应的**最小业务投影示例**（由上面的真实 XML 映射生成，不是 ES 实时取样；为阅读省略 event.original、ecs.version 等公共证据/运行期字段，实际写入按第2节补齐；event.action 无需生成）：

```json
{
  "@timestamp": "2026-09-11T03:40:07.1228815Z",
  "event": {
    "code": "4624",
    "module": "windows",
    "dataset": "windows.security",
    "kind": "event",
    "category": [
      "authentication",
      "session"
    ],
    "type": [
      "start"
    ],
    "outcome": "success",
    "provider": "Microsoft-Windows-Security-Auditing"
  },
  "host": {
    "name": "win-169.test.local"
  },
  "user": {
    "id": "S-1-5-21-4210831952-4165203136-4232524810-1122",
    "name": "UEBALOGON-11113950",
    "domain": "test"
  },
  "process": {
    "pid": 6916,
    "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
  },
  "related": {
    "user": [
      "UEBALOGON-11113950",
      "Administrator"
    ]
  },
  "winlog": {
    "channel": "Security",
    "record_id": "20512",
    "version": 3,
    "event_data": {
      "LogonType": "2",
      "TargetLogonId": "0xf1d7b33",
      "AuthenticationPackageName": "Negotiate",
      "SubjectUserSid": "S-1-5-21-425182487-128829183-2370913515-500",
      "SubjectUserName": "Administrator",
      "SubjectDomainName": "WIN-169",
      "SubjectLogonId": "0xf1d4191",
      "LogonGuid": "{2bf09c60-5444-beb9-39ed-165696f615c1}",
      "TargetLinkedLogonId": "0x0",
      "WorkstationName": "WIN-169",
      "LogonProcessName": "Advapi  ",
      "ElevatedToken": "%%1843",
      "VirtualAccount": "%%1843",
      "ImpersonationLevel": "%%1833",
      "KeyLength": "0"
    }
  }
}
```

该样本 LogonType=2，IpAddress/IpPort 为 `-`，因此示例不生成 source.ip/source.port，也不假定远程登录。目标账号不是 SubjectUserName=Administrator；这正是必须逐字段映射的原因。

#### 4624：11 种登录类型的条件分支

所有类型共用前表；下表仅列条件补充及解释，不拆成 11 个 dataset。Type 0=System 另行保留，不计入这 11 种。

| LogonType | 场景 | 必要的条件上下文/限制 | 报告证据 |
|---|---|---|---|
| 2 | Interactive 本机交互式 | Subject、Target、进程、提升标志；不能把 API 创建会话当作人工桌面操作 | 有样本，LogonUser API 模拟 |
| 3 | Network 网络登录 | 源地址/端口、WorkstationName、认证包、LogonGuid；不能只凭类型判断 SMB | 有样本 |
| 4 | Batch 批处理 | TargetLogonId、Subject、登录进程；任务名称需任务日志关联，4624 不补造 | 有计划任务样本 |
| 5 | Service 服务登录 | TargetLogonId、VirtualAccount、ElevatedToken；具体服务名需服务日志 | 有服务样本 |
| 7 | Unlock 解锁 | 保留类型和会话上下文；按解锁单独统计，不能与首次登录相加 | 有 API 模拟样本，非人工锁屏实验 |
| 8 | NetworkCleartext | 认证包及登录进程；不等于密码在网络中明文传输 | 有 API 模拟样本 |
| 9 | NewCredentials 新凭据 | 本地身份用 user.*；TargetOutboundUserName/DomainName 独立保留 | 有样本，本地 Administrator，对外 UEBALOGON-11113950 |
| 10 | RemoteInteractive 远程桌面 | 源地址、工作站、RestrictedAdminMode、RemoteCredentialGuard、提升标志；不补端口 3389 | 有历史 RDP 样本 |
| 11 | CachedInteractive 缓存交互式 | 保留缓存类型；不表示域控在线认证成功 | 未捕获，未实证 |
| 12 | CachedRemoteInteractive | 微软内部审核类型，保留独立代码；不推断为“断网 RDP” | 报告未覆盖 |
| 13 | CachedUnlock 缓存解锁 | 保留独立代码及会话上下文 | 报告未覆盖 |

认证与会话分类：Type 7/13 的 event.type 采用 info，event.category 为 authentication、session；其他类型沿用 start，Type 9 的 start 指本地新凭据会话。各类型 outcome=success 只描述本事件成功，不证明后续远程资源访问成功。源代码字段保留，不要求再生成布尔副本。

依据：[Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624)。

### 4.2 4625 — 登录失败

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`start`。event.action 可选：`logon-failure`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:943>)；主机 `win-169.test.local`，Security Record ID `20562`，时间 `2026-09-11T03:44:55.6029627Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4625 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8010000000000000 | event.outcome | keyword | 条件/生成 | 本样本：failure；按该动作的来源结果解释 |
| EventData.TargetUserSid | S-1-0-0 | user.id | keyword | 条件/原始 | 本样本不生成该目标值；SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOGON-11113950 | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | TEST | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x2eec | process.pid | long | 条件/原始 | 十六进制转十进制 12012；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.IpAddress | - | source.ip | ip | 条件/原始 | 本样本不生成该目标值；合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | - | source.port | long | 条件/原始 | 本样本不生成该目标值；仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.LogonType | 2 | winlog.event_data.LogonType【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.AuthenticationPackageName | Negotiate | winlog.event_data.AuthenticationPackageName【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.Status | 0xc000006d | winlog.event_data.Status【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.SubStatus | 0xc000006a | winlog.event_data.SubStatus【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.FailureReason | %%2313 | winlog.event_data.FailureReason【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.SubjectUserSid | S-1-5-21-425182487-128829183-2370913515-500 | winlog.event_data.SubjectUserSid【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.SubjectUserName | Administrator | winlog.event_data.SubjectUserName【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.SubjectDomainName | WIN-169 | winlog.event_data.SubjectDomainName【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.SubjectLogonId | 0xf24fa95 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.WorkstationName | WIN-169 | winlog.event_data.WorkstationName【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.LogonProcessName | Advapi   | winlog.event_data.LogonProcessName【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| EventData.LmPackageName | - | winlog.event_data.LmPackageName【扩展】 | keyword | 条件/原始或转换 | 保留发起上下文/工作站/认证细节；失败目标身份仍在 user.* |
| 解析配置/事件规则 | windows / windows.security / authentication / start | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

失败原因同时保留 Status、SubStatus、FailureReason；按已验证状态表可生成 event.reason。非密码错误（账号不存在、禁用、锁定、策略拒绝等）不得统一解释为输错密码。

### 4.3 4634 — 登录会话结束

分类：`session`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`end`。event.action 可选：`logoff`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:1584>)；主机 `win-169.test.local`，Security Record ID `20523`，时间 `2026-09-11T03:40:07.2127420Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4634 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.TargetUserSid | S-1-5-21-4210831952-4165203136-4232524810-1122 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOGON-11113950 | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.LogonType | 2 | winlog.event_data.LogonType【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| EventData.TargetLogonId | 0xf1d7b33 | winlog.event_data.TargetLogonId【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| 解析配置/事件规则 | windows / windows.security / session / end | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

会话分析：4647 表示主动注销发起，4634 表示会话已结束；两者不相加计数。匹配 4624 时使用同一 host＋TargetLogonId＋有界时间/启动上下文；缺少配对记录不生成时长。

### 4.4 4647 — 用户主动注销

分类：`session`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`end`。event.action 可选：`user-initiated-logoff`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:1986>)；主机 `win-169.test.local`，Security Record ID `19975`，时间 `2026-09-09T08:06:29.5817899Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4647 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.TargetUserSid | S-1-5-21-425182487-128829183-2370913515-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | WIN-169 | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetLogonId | 0x6c8484e | winlog.event_data.TargetLogonId【扩展】 | keyword | 条件/原始 | 登录类型/会话或失败判定所需；没有值时不生成 |
| 解析配置/事件规则 | windows / windows.security / session / end | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

**修正：本报告 4647 原始 XML 使用 TargetUserSid/TargetUserName/TargetLogonId，不是 SubjectLogonId。** 对其他事件版本以实际 XML 或采集器字段为准。

会话分析：4647 表示主动注销发起，4634 表示会话已结束；两者不相加计数。匹配 4624 时使用同一 host＋TargetLogonId＋有界时间/启动上下文；缺少配对记录不生成时长。

### 4.5 4648 — 使用显式凭据

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`explicit-credentials-use`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2083>)；主机 `win-139.test.local`，Security Record ID `185326`，时间 `2026-09-11T02:58:07.3123507Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4648 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；只代表凭据使用审计，不代表目标登录成功 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetUserName | UEBAU-0911105806 | winlog.event_data.TargetUserName【扩展】 | keyword | 条件/原始 | 显式使用的凭据身份，非被管理账户；最小版保留扩展，不自动写 user.target/effective |
| EventData.TargetDomainName | TEST.LOCAL | winlog.event_data.TargetDomainName【扩展】 | keyword | 条件/原始 |  |
| EventData.IpAddress | fe80::abca:2c38:f3d7:44de | source.ip | ip | 条件/原始 | 合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | 49682 | source.port | long | 条件/原始 | 仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.ProcessId | 0x2044 | process.pid | long | 条件/原始 | 十六进制转十进制 8260；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.SubjectLogonId | 0x1700c693 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| EventData.TargetServerName | win-139.test.local | winlog.event_data.TargetServerName【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| EventData.TargetInfo | LDAP/win-139.test.local | winlog.event_data.TargetInfo【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| EventData.TargetLogonGuid | {00000000-0000-0000-0000-000000000000} | winlog.event_data.TargetLogonGuid【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| EventData.LogonGuid | {00000000-0000-0000-0000-000000000000} | winlog.event_data.LogonGuid【扩展】 | keyword | 条件/原始或转换 | 发起方登录关联 GUID；与 TargetLogonGuid 分开，零值不关联 |
| 解析配置/事件规则 | windows / windows.security / authentication / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

身份规则：Subject → user.*；Target 凭据保留上述扩展并可参与 related.user。只有额外证据能确定远程端点和身份角色时才增加 source.user/destination.user，不由 TargetServerName 推造 IP。

### 4.6 4740 — 域账户被锁定

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-lock`。

**无实际样本：报告未捕获 4740。** 以下为事件模板映射规则；无原始值列不得当作真实数据。上线需用实际事件验收。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4740 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 样本不存在 | event.outcome | keyword | 条件/生成 | 条件规则：按 4740 实际成功锁定事件解释；按该动作的来源结果解释 |
| EventData.SubjectUserSid | 样本不存在 | user.id | keyword | 条件/原始 | 本样本不生成该目标值；SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | 样本不存在 | user.name | keyword | 条件/原始 | 本样本不生成该目标值；账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | 样本不存在 | user.domain | keyword | 条件/原始 | 本样本不生成该目标值；原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | 样本不存在 | user.target.id | keyword | 条件/原始 | 本样本不生成该目标值；SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | 样本不存在 | user.target.name | keyword | 条件/原始 | 本样本不生成该目标值；账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | 样本不存在 | user.target.domain | keyword | 条件/原始 | 本样本不生成该目标值；原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 样本不存在 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；锁定事件上下文；CallerComputerName 是计算机名，不是 IP |
| EventData.CallerComputerName | 样本不存在 | winlog.event_data.CallerComputerName【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；锁定事件上下文；CallerComputerName 是计算机名，不是 IP |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.7 4768 — 请求 Kerberos TGT

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`kerberos-tgt-request`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2241>)；主机 `win-139.test.local`，Security Record ID `185329`，时间 `2026-09-11T02:58:07.3253988Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4768 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords + EventData.Status | 0x8020000000000000; Status=0x0 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1114 | user.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBAU-0911105806 | user.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test.local | user.domain | keyword | 条件/原始 |  |
| EventData.ServiceName | krbtgt | service.name | keyword | 条件/原始 |  |
| EventData.IpAddress | ::1 | source.ip | ip | 条件/原始 | 合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | 0 | source.port | long | 条件/原始 | 仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.Status | 0x0 | winlog.event_data.Status【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.PreAuthType | 2 | winlog.event_data.PreAuthType【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.TicketEncryptionType | 0x12 | winlog.event_data.TicketEncryptionType【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.TicketOptions | 0x40810010 | winlog.event_data.TicketOptions【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.ServiceSid | S-1-5-21-4210831952-4165203136-4232524810-502 | winlog.event_data.ServiceSid【扩展】 | keyword | 条件/原始或转换 | 票据服务身份，非请求用户 SID |
| EventData.SessionKeyEncryptionType | 0x12 | winlog.event_data.SessionKeyEncryptionType【扩展】 | keyword | 条件/原始或转换 | 会话密钥加密类型，与票据加密类型分开 |
| 解析配置/事件规则 | windows / windows.security / authentication / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

加密能力/票据哈希等新版字段是可选增强，不纳入首版强制字段；字段缺失不得推定弱加密。按 System.Version 及实际 schema 适配。ServiceName 保留服务账户/SPN 原始含义，不假定为目标 IP。成功只代表本阶段票据操作。

### 4.8 4769 — 请求 Kerberos Service Ticket

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`kerberos-service-ticket-request`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2399>)；主机 `win-139.test.local`，Security Record ID `185321`，时间 `2026-09-11T02:58:07.1528837Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4769 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords + EventData.Status | 0x8020000000000000; Status=0x0 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.TargetUserName | UEBAU-0911105806@TEST.LOCAL | user.name | keyword | 条件/原始 | 已确认 UPN 时拆分账号与域，完整原值保留原文；不把不同表示直接当不同用户 |
| EventData.TargetDomainName | TEST.LOCAL | user.domain | keyword | 条件/原始 |  |
| EventData.ServiceName | WIN-139$ | service.name | keyword | 条件/原始 |  |
| EventData.IpAddress | ::1 | source.ip | ip | 条件/原始 | 合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | 0 | source.port | long | 条件/原始 | 仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.Status | 0x0 | winlog.event_data.Status【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.TicketEncryptionType | 0x12 | winlog.event_data.TicketEncryptionType【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.TicketOptions | 0x40810000 | winlog.event_data.TicketOptions【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.LogonGuid | {d8a90667-2f23-c0a8-b365-fd34262a6d5e} | winlog.event_data.LogonGuid【扩展】 | keyword | 条件/原始或转换 | 关联登录/凭据使用；全零值不关联 |
| EventData.ServiceSid | S-1-5-21-4210831952-4165203136-4232524810-1000 | winlog.event_data.ServiceSid【扩展】 | keyword | 条件/原始或转换 | 服务账户 SID，不是客户端 user.id |
| EventData.SessionKeyEncryptionType | 0x12 | winlog.event_data.SessionKeyEncryptionType【扩展】 | keyword | 条件/原始或转换 | 会话密钥算法，与 TicketEncryptionType 分开 |
| 解析配置/事件规则 | windows / windows.security / authentication / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

加密能力/票据哈希等新版字段是可选增强，不纳入首版强制字段；字段缺失不得推定弱加密。按 System.Version 及实际 schema 适配。ServiceName 保留服务账户/SPN 原始含义，不假定为目标 IP。成功只代表本阶段票据操作。

### 4.9 4771 — Kerberos 预身份验证失败

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`kerberos-preauth-failure`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2549>)；主机 `win-139.test.local`，Security Record ID `185515`，时间 `2026-09-11T03:06:17.8697210Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4771 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords + EventData.Status | 0x8010000000000000; Status=0x12 | event.outcome | keyword | 条件/生成 | 本样本：failure；按该动作的来源结果解释 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1121 | user.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBALOCK-11110448 | user.name | keyword | 条件/原始 |  |
| EventData.ServiceName | krbtgt/TEST | service.name | keyword | 条件/原始 |  |
| EventData.IpAddress | ::ffff:10.6.6.169 | source.ip | ip | 条件/原始 | 合法 IP 才写入；明确规范化 IPv4-mapped IPv6，保留原地址可选 |
| EventData.IpPort | 56971 | source.port | long | 条件/原始 | 仅明确有效端口才写入；- 省略；记录未提供目的地址时不虚构 destination.ip |
| EventData.Status | 0x12 | winlog.event_data.Status【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.PreAuthType | 0 | winlog.event_data.PreAuthType【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.TicketOptions | 0x40810010 | winlog.event_data.TicketOptions【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| 解析配置/事件规则 | windows / windows.security / authentication / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

**修正：本报告 4771 的失败状态原始字段叫 Status；不要在 Pipeline 中只读取不存在的 FailureCode。**

### 4.10 4776 — 验证 NTLM 凭据

分类：`authentication`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`ntlm-credential-validation`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2664>)；主机 `win-139.test.local`，Security Record ID `185305`，时间 `2026-09-11T02:57:24.8512144Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4776 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords + EventData.Status | 0x8010000000000000; Status=0xc0000064 | event.outcome | keyword | 条件/生成 | 本样本：failure；按该动作的来源结果解释 |
| EventData.TargetUserName | UEBA-SIM-20260911-10 | user.name | keyword | 条件/原始 |  |
| EventData.Status | 0xc0000064 | winlog.event_data.Status【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.Workstation | WIN-139 | winlog.event_data.Workstation【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| EventData.PackageName | MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 | winlog.event_data.PackageName【扩展】 | keyword | 条件/原始 | 保留源认证状态/协议细节；按本事件定义解释 |
| 解析配置/事件规则 | windows / windows.security / authentication / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.11 4720 — 创建用户账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`creation + user`。event.action 可选：`user-create`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2758>)；主机 `win-139.test.local`，Security Record ID `185477`，时间 `2026-09-11T03:04:48.7729499Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4720 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1121 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOCK-11110448 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.OldUacValue | 0x0 | winlog.event_data.OldUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.NewUacValue | 0x11 | winlog.event_data.NewUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.UserAccountControl | <br>		%%2080<br>		%%2084 | winlog.event_data.UserAccountControl【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.SamAccountName | UEBALOCK-11110448 | winlog.event_data.SamAccountName【扩展】 | keyword | 条件/原始或转换 | 实际账号属性；改名有明确证据时才生成 user.changes.name，不覆盖旧身份 |
| EventData.UserPrincipalName | - | winlog.event_data.UserPrincipalName【扩展】 | keyword | 条件/原始或转换 | UPN 原值；不无条件映射 email |
| EventData.DisplayName | - | winlog.event_data.DisplayName【扩展】 | keyword | 条件/原始或转换 | 显示名；不当登录账号 |
| EventData.PrimaryGroupId | 513 | winlog.event_data.PrimaryGroupId【扩展】 | keyword | 条件/原始或转换 | 主组 RID，不是完整组 SID |
| EventData.AllowedToDelegateTo | - | winlog.event_data.AllowedToDelegateTo【扩展】 | keyword | 条件/原始或转换 | 委派服务列表，按原文字符串保留；多值拆分需固定规则 |
| EventData.SidHistory | - | winlog.event_data.SidHistory【扩展】 | keyword | 条件/原始或转换 | 历史 SID 原值；不覆盖当前 user.target.id |
| EventData.AccountExpires | %%1794 | winlog.event_data.AccountExpires【扩展】 | keyword | 条件/原始或转换 | 源有效期文本，含特殊值；未确定语言/时区不强转日期 |
| EventData.PasswordLastSet | %%1794 | winlog.event_data.PasswordLastSet【扩展】 | keyword | 条件/原始或转换 | 密码更新时间文本；不能推出密码内容 |
| EventData.UserWorkstations | - | winlog.event_data.UserWorkstations【扩展】 | keyword | 条件/原始或转换 | 允许登录工作站列表 |
| EventData.ScriptPath | - | winlog.event_data.ScriptPath【扩展】 | keyword | 条件/原始或转换 | 登录脚本属性，不代表脚本已执行 |
| 解析配置/事件规则 | windows / windows.security / iam / creation + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

属性规则：只索引本场景需要且原始有值的属性。'-' 不表示已清空；属性未出现不代表未变化。4738 的本地账号字段可能含当前值，不能把每个非空属性都当本次变更。未给旧值时不伪造 before/after。

### 4.12 4722 — 启用用户账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-enable`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:2920>)；主机 `win-139.test.local`，Security Record ID `185481`，时间 `2026-09-11T03:04:48.8100382Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4722 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1121 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOCK-11110448 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.13 4723 — 用户尝试修改自己的密码

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-password-change`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3023>)；主机 `win-139.test.local`，Security Record ID `185330`，时间 `2026-09-11T02:58:07.3269351Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4723 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8010000000000000 | event.outcome | keyword | 条件/生成 | 本样本：failure；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-1114 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | UEBAU-0911105806 | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1114 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBAU-0911105806 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x17013e5a | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.14 4724 — 尝试重置其他账户密码

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-password-reset`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3129>)；主机 `win-139.test.local`，Security Record ID `185479`，时间 `2026-09-11T03:04:48.8082563Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4724 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1121 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOCK-11110448 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x1705fd82 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.15 4725 — 禁用用户账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-disable`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3232>)；主机 `win-139.test.local`，Security Record ID `185336`，时间 `2026-09-11T02:58:07.4608629Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4725 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1114 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBAU-0911105806 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.16 4726 — 删除用户账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`deletion + user`。event.action 可选：`user-delete`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3335>)；主机 `win-139.test.local`，Security Record ID `185475`，时间 `2026-09-11T03:04:48.6705784Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4726 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1120 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBADEL-0911110447 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / deletion + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.17 4738 — 用户账户属性发生变化

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + user`。event.action 可选：`user-change`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3441>)；主机 `win-139.test.local`，Security Record ID `185480`，时间 `2026-09-11T03:04:48.8100198Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4738 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1121 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBALOCK-11110448 | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.OldUacValue | 0x11 | winlog.event_data.OldUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.NewUacValue | 0x10 | winlog.event_data.NewUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.UserAccountControl | <br>		%%2048 | winlog.event_data.UserAccountControl【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.SamAccountName | - | winlog.event_data.SamAccountName【扩展】 | keyword | 条件/原始或转换 | 实际账号属性；改名有明确证据时才生成 user.changes.name，不覆盖旧身份 |
| EventData.UserPrincipalName | - | winlog.event_data.UserPrincipalName【扩展】 | keyword | 条件/原始或转换 | UPN 原值；不无条件映射 email |
| EventData.DisplayName | - | winlog.event_data.DisplayName【扩展】 | keyword | 条件/原始或转换 | 显示名；不当登录账号 |
| EventData.PrimaryGroupId | - | winlog.event_data.PrimaryGroupId【扩展】 | keyword | 条件/原始或转换 | 主组 RID，不是完整组 SID |
| EventData.AllowedToDelegateTo | - | winlog.event_data.AllowedToDelegateTo【扩展】 | keyword | 条件/原始或转换 | 委派服务列表，按原文字符串保留；多值拆分需固定规则 |
| EventData.SidHistory | - | winlog.event_data.SidHistory【扩展】 | keyword | 条件/原始或转换 | 历史 SID 原值；不覆盖当前 user.target.id |
| EventData.AccountExpires | - | winlog.event_data.AccountExpires【扩展】 | keyword | 条件/原始或转换 | 源有效期文本，含特殊值；未确定语言/时区不强转日期 |
| EventData.PasswordLastSet | - | winlog.event_data.PasswordLastSet【扩展】 | keyword | 条件/原始或转换 | 密码更新时间文本；不能推出密码内容 |
| EventData.UserWorkstations | - | winlog.event_data.UserWorkstations【扩展】 | keyword | 条件/原始或转换 | 允许登录工作站列表 |
| EventData.ScriptPath | - | winlog.event_data.ScriptPath【扩展】 | keyword | 条件/原始或转换 | 登录脚本属性，不代表脚本已执行 |
| 解析配置/事件规则 | windows / windows.security / iam / change + user | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

属性规则：只索引本场景需要且原始有值的属性。'-' 不表示已清空；属性未出现不代表未变化。4738 的本地账号字段可能含当前值，不能把每个非空属性都当本次变更。未给旧值时不伪造 before/after。

### 4.18 4741 — 创建计算机账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`creation`。event.action 可选：`computer-account-create`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3605>)；主机 `win-139.test.local`，Security Record ID `185359`，时间 `2026-09-11T02:58:07.7441911Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4741 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1119 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBAPC-11105806$ | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.OldUacValue | 0x0 | winlog.event_data.OldUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.NewUacValue | 0x81 | winlog.event_data.NewUacValue【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.UserAccountControl | <br>		%%2080<br>		%%2087 | winlog.event_data.UserAccountControl【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.DnsHostName | - | winlog.event_data.DnsHostName【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.ServicePrincipalNames | - | winlog.event_data.ServicePrincipalNames【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.SamAccountName | UEBAPC-11105806$ | winlog.event_data.SamAccountName【扩展】 | keyword | 条件/原始或转换 | 实际账号属性；改名有明确证据时才生成 user.changes.name，不覆盖旧身份 |
| EventData.UserPrincipalName | - | winlog.event_data.UserPrincipalName【扩展】 | keyword | 条件/原始或转换 | UPN 原值；不无条件映射 email |
| EventData.DisplayName | - | winlog.event_data.DisplayName【扩展】 | keyword | 条件/原始或转换 | 显示名；不当登录账号 |
| EventData.PrimaryGroupId | 515 | winlog.event_data.PrimaryGroupId【扩展】 | keyword | 条件/原始或转换 | 主组 RID，不是完整组 SID |
| EventData.AllowedToDelegateTo | - | winlog.event_data.AllowedToDelegateTo【扩展】 | keyword | 条件/原始或转换 | 委派服务列表，按原文字符串保留；多值拆分需固定规则 |
| EventData.SidHistory | - | winlog.event_data.SidHistory【扩展】 | keyword | 条件/原始或转换 | 历史 SID 原值；不覆盖当前 user.target.id |
| EventData.AccountExpires | %%1794 | winlog.event_data.AccountExpires【扩展】 | keyword | 条件/原始或转换 | 源有效期文本，含特殊值；未确定语言/时区不强转日期 |
| EventData.PasswordLastSet | %%1794 | winlog.event_data.PasswordLastSet【扩展】 | keyword | 条件/原始或转换 | 密码更新时间文本；不能推出密码内容 |
| EventData.UserWorkstations | - | winlog.event_data.UserWorkstations【扩展】 | keyword | 条件/原始或转换 | 允许登录工作站列表 |
| EventData.ScriptPath | - | winlog.event_data.ScriptPath【扩展】 | keyword | 条件/原始或转换 | 登录脚本属性，不代表脚本已执行 |
| 解析配置/事件规则 | windows / windows.security / iam / creation | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

属性规则：只索引本场景需要且原始有值的属性。'-' 不表示已清空；属性未出现不代表未变化。4738 的本地账号字段可能含当前值，不能把每个非空属性都当本次变更。未给旧值时不伪造 before/after。

### 4.19 4742 — 计算机账户属性变化

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change`。event.action 可选：`computer-account-change`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3773>)；主机 `win-139.test.local`，Security Record ID `185364`，时间 `2026-09-11T02:58:07.8324473Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4742 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1119 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBAPC-11105806$ | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.OldUacValue | - | winlog.event_data.OldUacValue【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.NewUacValue | - | winlog.event_data.NewUacValue【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.UserAccountControl | - | winlog.event_data.UserAccountControl【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.DnsHostName | - | winlog.event_data.DnsHostName【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.ServicePrincipalNames | - | winlog.event_data.ServicePrincipalNames【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；账户管理属性；操作者和被管理账户分开，缺失值省略 |
| EventData.SamAccountName | - | winlog.event_data.SamAccountName【扩展】 | keyword | 条件/原始或转换 | 实际账号属性；改名有明确证据时才生成 user.changes.name，不覆盖旧身份 |
| EventData.UserPrincipalName | - | winlog.event_data.UserPrincipalName【扩展】 | keyword | 条件/原始或转换 | UPN 原值；不无条件映射 email |
| EventData.DisplayName | - | winlog.event_data.DisplayName【扩展】 | keyword | 条件/原始或转换 | 显示名；不当登录账号 |
| EventData.PrimaryGroupId | - | winlog.event_data.PrimaryGroupId【扩展】 | keyword | 条件/原始或转换 | 主组 RID，不是完整组 SID |
| EventData.AllowedToDelegateTo | - | winlog.event_data.AllowedToDelegateTo【扩展】 | keyword | 条件/原始或转换 | 委派服务列表，按原文字符串保留；多值拆分需固定规则 |
| EventData.SidHistory | - | winlog.event_data.SidHistory【扩展】 | keyword | 条件/原始或转换 | 历史 SID 原值；不覆盖当前 user.target.id |
| EventData.AccountExpires | - | winlog.event_data.AccountExpires【扩展】 | keyword | 条件/原始或转换 | 源有效期文本，含特殊值；未确定语言/时区不强转日期 |
| EventData.PasswordLastSet | - | winlog.event_data.PasswordLastSet【扩展】 | keyword | 条件/原始或转换 | 密码更新时间文本；不能推出密码内容 |
| EventData.UserWorkstations | - | winlog.event_data.UserWorkstations【扩展】 | keyword | 条件/原始或转换 | 允许登录工作站列表 |
| EventData.ScriptPath | - | winlog.event_data.ScriptPath【扩展】 | keyword | 条件/原始或转换 | 登录脚本属性，不代表脚本已执行 |
| 解析配置/事件规则 | windows / windows.security / iam / change | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

属性规则：只索引本场景需要且原始有值的属性。'-' 不表示已清空；属性未出现不代表未变化。4738 的本地账号字段可能含当前值，不能把每个非空属性都当本次变更。未给旧值时不伪造 before/after。

### 4.20 4743 — 删除计算机账户

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`deletion`。event.action 可选：`computer-account-delete`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:3942>)；主机 `win-139.test.local`，Security Record ID `185365`，时间 `2026-09-11T02:58:07.8520654Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4743 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1119 | user.target.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.TargetUserName | UEBAPC-11105806$ | user.target.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.TargetDomainName | test | user.target.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x16f9413f | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 账户管理属性；操作者和被管理账户分开，缺失值省略 |
| 解析配置/事件规则 | windows / windows.security / iam / deletion | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.21 4728 — 向全局安全组添加成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-add`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4048>)；主机 `win-139.test.local`，Security Record ID `216903`，时间 `2026-09-14T09:25:08.8183320Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4728 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1125 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBAGG-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.22 4729 — 从全局安全组删除成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-remove`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4160>)；主机 `win-139.test.local`，Security Record ID `216905`，时间 `2026-09-14T09:25:08.8526372Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4729 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1125 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBAGG-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.23 4732 — 向本地域安全组添加成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-add`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4272>)；主机 `win-139.test.local`，Security Record ID `216907`，时间 `2026-09-14T09:25:08.8899256Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4732 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1126 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBADL-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.24 4733 — 从本地域安全组删除成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-remove`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4384>)；主机 `win-139.test.local`，Security Record ID `216909`，时间 `2026-09-14T09:25:08.9189572Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4733 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1126 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBADL-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.25 4756 — 向通用安全组添加成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-add`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4496>)；主机 `win-139.test.local`，Security Record ID `216911`，时间 `2026-09-14T09:25:08.9437727Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4756 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1127 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBAUG-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.26 4757 — 从通用安全组删除成员

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change + group`。event.action 可选：`group-member-remove`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4608>)；主机 `win-139.test.local`，Security Record ID `216913`，时间 `2026-09-14T09:25:09.0033504Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4757 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.MemberSid | S-1-5-21-4210831952-4165203136-4232524810-1124 | winlog.event_data.MemberSid【扩展】 | keyword | 条件/原始 | 成员原始 SID；未知主体类型时不写 user.target.id |
| EventData.MemberName | CN=UEBAM-FIX-0914172508,OU=UEBA-XML-Refresh-0914172508,OU=IT部,OU=上海总部,DC=test,DC=local | winlog.event_data.MemberName【扩展】 | keyword | 条件/原始 | 可能为 DN；不得直接映射 user.target.name，除非可靠目录解析得到账号名 |
| EventData.TargetSid | S-1-5-21-4210831952-4165203136-4232524810-1127 | group.id | keyword | 条件/原始 |  |
| EventData.TargetUserName | UEBAUG-FIX-0914172508 | group.name | keyword | 条件/原始 |  |
| EventData.TargetDomainName | test | group.domain | keyword | 条件/原始 |  |
| EventData.SubjectLogonId | 0x1da76b8c | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / iam / change + group | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

成员角色：主表按“修改目标组成员集合”归为 change＋group，group.* 为目标组。MemberSid/MemberName 原始保留；可靠目录证据确认成员为用户/计算机账户时，可复制到 user.target.id，解析到账号名才填 user.target.name；成员为组或类型未知时只保留成员扩展，不能覆盖目标 group.*。这是本项目的组中心分类口径，不混用以用户成员关系为中心的另一套统计。

### 4.27 4661 — 请求访问对象句柄

分类：`iam（报告样本）`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`sam-handle-request`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4720>)；主机 `win-139.test.local`，Security Record ID `216632`，时间 `2026-09-14T08:53:20.0193889Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4661 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x3a4 | process.pid | long | 条件/原始 | 十六进制转十进制 932；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\lsass.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.SubjectLogonId | 0x1d8f46e0 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectServer | Security Account Manager | winlog.event_data.ObjectServer【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectType | SAM_USER | winlog.event_data.ObjectType【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectName | S-1-5-21-4210831952-4165203136-4232524810-1123 | winlog.event_data.ObjectName【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.AccessMask | 0xf01ff | winlog.event_data.AccessMask【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.AccessList | %%1537<br>				%%1538<br>				%%1539<br>				%%1540<br>				%%5440<br>				%%5441<br>				%%5442<br>				%%5443<br>				%%5444<br>				%%5445<br>				%%5446<br>				%%5447<br>				%%5448<br>	…（表内截断，原值见报告） | winlog.event_data.AccessList【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.Properties | ---<br>	{bf967aba-0de6-11d0-a285-00aa003049e2}<br>%%1537<br>%%1538<br>%%1539<br>%%1540<br>%%5440<br>%%5441<br>%%5442<br>%%5443<br>%%5444<br>%%5445<br>%%5446<br>%%5447<br>%%5448<br>		{59…（表内截断，原值见报告） | winlog.event_data.Properties【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.PrivilegeList | - | winlog.event_data.PrivilegeList【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.HandleId | 0x29c6af85920 | winlog.event_data.HandleId【扩展】 | keyword | 条件/原始或转换 | 对象句柄关联；只在同主机、进程及时间边界内使用 |
| EventData.TransactionId | {00000000-0000-0000-0000-000000000000} | winlog.event_data.TransactionId【扩展】 | keyword | 条件/原始或转换 | 事务关联 ID；零 GUID 不参与关联 |
| 解析配置/事件规则 | windows / windows.security / iam（报告样本） / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.28 4662 — 对目录服务对象执行操作

分类：`iam`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info；明确修改时 change`。event.action 可选：`directory-object-operation`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:4912>)；主机 `win-139.test.local`，Security Record ID `216561`，时间 `2026-09-14T08:45:11.5720681Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4662 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-4210831952-4165203136-4232524810-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.SubjectLogonId | 0x1d8a7375 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectServer | DS | winlog.event_data.ObjectServer【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectType | %{bf967aba-0de6-11d0-a285-00aa003049e2} | winlog.event_data.ObjectType【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectName | %{04540b73-d452-407f-9aa0-d8c932ce1a4e} | winlog.event_data.ObjectName【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.AccessMask | 0x10 | winlog.event_data.AccessMask【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.AccessList | %%7684<br>				 | winlog.event_data.AccessList【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.Properties | %%7684<br>	{bf967aba-0de6-11d0-a285-00aa003049e2}<br>		{e48d0154-bcf8-11d1-8702-00c04fb96050}<br>			{bf9679e5-0de6-11d0-a285-00aa003049e2}<br>			{bf967a…（表内截断，原值见报告） | winlog.event_data.Properties【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.OperationType | Object Access | winlog.event_data.OperationType【扩展】 | keyword | 条件/原始或转换 | 源操作代码/文本；与 AccessMask、Properties 一起解释，不等于所有操作都修改对象 |
| 解析配置/事件规则 | windows / windows.security / iam / info；明确修改时 change | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.29 4670 — 对象权限发生变化

分类：`file / registry / iam，按对象类型选取`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`change`。event.action 可选：`object-permissions-change`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:5055>)；主机 `win-169.test.local`，Security Record ID `22439`，时间 `2026-09-14T08:46:09.5746903Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4670 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-425182487-128829183-2370913515-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | WIN-169 | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x2180 | process.pid | long | 条件/原始 | 十六进制转十进制 8576；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.ObjectName | C:\Windows\Temp\UEBA-4670-0914164608.txt | file.path | keyword | 条件/原始 | File→file.path；注册表→registry.path；其他对象保留扩展再定义 |
| EventData.SubjectLogonId | 0x143b9c40 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectServer | Security | winlog.event_data.ObjectServer【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectType | File | winlog.event_data.ObjectType【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.OldSd | D:AI(A;ID;FA;;;BA)(A;ID;FA;;;SY) | winlog.event_data.OldSd【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.NewSd | D:ARAI(A;;FR;;;S-1-5-21-425182487-128829183-2370913515-500)(A;ID;FA;;;BA)(A;ID;FA;;;SY) | winlog.event_data.NewSd【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.HandleId | 0x900 | winlog.event_data.HandleId【扩展】 | keyword | 条件/原始或转换 | 同主机、进程内对象句柄关联；避免跨进程混用 |
| 解析配置/事件规则 | windows / windows.security / file / registry / iam，按对象类型选取 / change | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.30 4673 — 调用特权服务

分类：`api`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`info`。event.action 可选：`privileged-service-call`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:5173>)；主机 `win-169.test.local`，Security Record ID `22736`，时间 `2026-09-14T08:51:30.9657357Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4673 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-18 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | WIN-169$ | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | test | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x38c | process.pid | long | 条件/原始 | 十六进制转十进制 908；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\lsass.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.Service | LsaRegisterLogonProcess() | service.name | keyword | 条件/原始 | 特权调用服务/API 名称，不是任意进程名 |
| EventData.SubjectLogonId | 0x3e7 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.ObjectServer | NT Local Security Authority / Authentication Service | winlog.event_data.ObjectServer【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| EventData.PrivilegeList | SeTcbPrivilege | winlog.event_data.PrivilegeList【扩展】 | keyword | 条件/原始 | 对象权限或调用细节；原文 GUID/DN/SDDL 不套进用户名/文件路径 |
| 解析配置/事件规则 | windows / windows.security / api / info | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

### 4.31 4688 — 创建新进程

分类：`process`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`start`。event.action 可选：`process-start`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:5282>)；主机 `win-169.test.local`，Security Record ID `22449`，时间 `2026-09-14T08:46:09.5943965Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4688 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；按该动作的来源结果解释 |
| EventData.SubjectUserSid | S-1-5-21-425182487-128829183-2370913515-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | WIN-169 | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.NewProcessId | 0x24d8 | process.pid | long | 条件/原始 | 十六进制转十进制 9432；新进程 PID |
| EventData.NewProcessName | C:\Windows\System32\cmd.exe | process.executable | keyword | 条件/原始 |  |
| EventData.ProcessId | 0x2180 | process.parent.pid | long | 条件/原始 | 十六进制转十进制 8576；此事件的 ProcessId 是创建者/父进程 PID |
| EventData.ParentProcessName | C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe | process.parent.executable | keyword | 条件/原始 |  |
| EventData.CommandLine | 空字符串 | process.command_line | wildcard | 条件/原始 | 本样本不生成该目标值；原始命令行为空时省略，不能凭可执行文件补造 |
| EventData.SubjectLogonId | 0x143b9c40 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.TargetUserSid | S-1-0-0 | winlog.event_data.TargetUserSid【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.TargetUserName | - | winlog.event_data.TargetUserName【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.TargetDomainName | - | winlog.event_data.TargetDomainName【扩展】 | keyword | 条件/原始 | 本样本不生成该目标值；目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.TargetLogonId | 0x0 | winlog.event_data.TargetLogonId【扩展】 | keyword | 条件/原始 | 目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.TokenElevationType | %%1936 | winlog.event_data.TokenElevationType【扩展】 | keyword | 条件/原始 | 目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| EventData.MandatoryLabel | S-1-16-12288 | winlog.event_data.MandatoryLabel【扩展】 | keyword | 条件/原始 | 目标主体有有效值时可进一步映射进程运行身份；本样本目标主体为空占位 |
| 解析配置/事件规则 | windows / windows.security / process / start | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

运行身份分支：Subject → user.*（创建者）；有效 TargetUserSid/TargetUserName/TargetDomainName → process.user.id/name/domain（新进程运行身份）。目标字段缺失/占位时不伪造，保留已知创建者。TokenElevationType/MandatoryLabel 与目标身份独立保留，不因目标占位而删除。PID 与父 PID 会复用，关联 4689 需同主机、时间顺序及进程身份；没有可靠起点不构造 process.entity_id。

### 4.32 4689 — 进程结束

分类：`process`；dataset：`windows.security`（自定义）；目标：`windows.security-prod`；type：`end`。event.action 可选：`process-end`。

**报告真实样本定位**：[原始事件章节](<D:/Program Files/JetBrains/ELK/AD-UEBA关键事件真实日志模拟报告.md:5409>)；主机 `win-169.test.local`，Security Record ID `22452`，时间 `2026-09-14T08:46:09.6354855Z`。以下是报告样本，不是本次 ES 查询结果。

| 原始字段 | 报告原始值 | ECS 或来源扩展目标 | 类型 | 要求/来源 | 转换规则与字段含义 |
|---|---|---|---|---|---|
| System.EventID | 4689 | event.code | keyword | 必备/原始 | 以字符串保存事件代码 |
| System.Keywords | 0x8020000000000000 | event.outcome | keyword | 条件/生成 | 本样本：success；不要使用进程 Status 判断审计结果 |
| EventData.SubjectUserSid | S-1-5-21-425182487-128829183-2370913515-500 | user.id | keyword | 条件/原始 | SID；无效占位 SID 不进入身份基线 |
| EventData.SubjectUserName | Administrator | user.name | keyword | 条件/原始 | 账号名称；原文中有 UPN 时按明确规则拆分并保留原文 |
| EventData.SubjectDomainName | WIN-169 | user.domain | keyword | 条件/原始 | 原始域/本地账户域；缺失不推造 |
| EventData.ProcessId | 0x24d8 | process.pid | long | 条件/原始 | 十六进制转十进制 9432；业务进程，不使用 System.Execution.ProcessID |
| EventData.ProcessName | C:\Windows\System32\cmd.exe | process.executable | keyword | 条件/原始 | 业务进程，不使用 System.Execution.ProcessID |
| EventData.Status | 0x25 | process.exit_code | long | 条件/原始 | 十六进制转十进制 37；进程退出状态，本样本 0x25 = 37；不是 event.outcome |
| EventData.SubjectLogonId | 0x143b9c40 | winlog.event_data.SubjectLogonId【扩展】 | keyword | 条件/原始 | 必要时索引；其余留原文 |
| 解析配置/事件规则 | windows / windows.security / process / end | event.module、event.dataset、event.category、event.type、event.kind | keyword / keyword数组 | 必备/生成 | 按第2节与本节分类写入；不是原始 XML 的同名字段；kind=event |

## 5. Zeek：38 类原始 JSON 逐项映射

### 5.0 公共规则与适用边界

本节定义采集与映射，不代表本次服务器已启用。每类事件继承第 2 节＋下表＋本类专有字段。所有专有字段均为条件字段；标注可选/原文接入的能力不作为生产已验证功能。zeek.* 均为本项目来源扩展，未标注扩展的目标为 ECS 字段。“/”表示逐项对应，不是字段名。

| 原始字段/依据 | 目标 | 类型 | 规则 |
|---|---|---|---|
| ts | @timestamp | date | UNIX 秒转 UTC；conn/ssh 为连接起点，不能当每次认证时间 |
| 配置 | event.module / event.dataset | keyword / keyword | zeek 与目录中的 zeek.<类型>，目标名加 -prod |
| 探针配置 | observer.name / observer.type | keyword / keyword | name 为稳定探针标识，type=sensor；可提供时增加 observer.version |
| 日志类型配置 | zeek.log_type【扩展】 | keyword | 文件基本类型，如 conn、stats、capture_loss；共享 dataset 仍能区分，不依赖可选 action |
| id.orig_h / id.resp_h | source.ip / destination.ip | ip / ip | 原始发起/响应端点；signatures、DHCP 等按本类专用键 |
| id.orig_p / id.resp_p | source.port / destination.port | long / long | 只用于明确 TCP/UDP 的记录；ICMP type/code 不映射端口 |
| proto | network.transport | keyword | 原协议规范化；缺失时只有已验证的协议 schema 可提供固定传输类型，否则省略 |
| 解析器识别协议 | network.protocol | keyword | ssh/dns/http/tls 等；不能仅按端口识别协议，探针指标/证书不强制填写 |
| uid | zeek.uid【扩展】 | keyword | 连接关联 ID；不是所有日志都有，不当文档唯一 ID |
| 采集路径/完整 JSON 行 | log.file.path / event.original | keyword / keyword | 原始证据按第 2 节保留；密码、token、community 等在原文也执行保护 |

原 JSON 可能是字面带点键 id.orig_h，也可能来自旧链路的 id_orig_h。每个采集路径固定一种输入适配器，不同时猜测/混合。数字溢出、类型冲突、日期失败走错误路径，不静默转换成 0。内部网段未配置时不生成 network.direction；已配置时按第 8.8 节计算。

数组契约：keyword[]/double[] 在 _source 保留顺序，但检索聚合不应依赖 doc values 的原始位置；需要答案与 TTL 成对条件查询时采用明确的 nested 结构，而不是两个平行数组交叉匹配。

### 5.1 Zeek conn.log

分类：`network`；module.dataset：`zeek.conn`（自定义）；存储：`zeek.conn-prod`；type：`connection`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| orig_bytes | source.bytes | long | 发起方有效载荷字节 |
| resp_bytes | destination.bytes | long | 响应方有效载荷字节；两侧都存在时相加生成 network.bytes（long） |
| orig_pkts / resp_pkts | source.packets / destination.packets | long / long | 两侧均有值时相加生成 network.packets（long） |
| duration | event.duration | long | 秒乘 10^9，检查溢出并转整数；ts 可同时生成 event.start（date） |
| ts + duration | event.end | date | 两者有效时计算连接结束时间；不等于采集时间 |
| conn_state / history | zeek.conn.state / zeek.conn.history【扩展】 | keyword / keyword | 保留状态和观测历史；RST/S0 不等同于用户认证失败 |
| missed_bytes | zeek.conn.missed_bytes【扩展】 | long | 捕获完整性证据 |
| orig_ip_bytes / resp_ip_bytes | zeek.conn.orig_ip_bytes / zeek.conn.resp_ip_bytes【扩展】 | long / long | IP 层字节，不与 payload 相加 |
| service | zeek.conn.service【扩展】 | keyword[] | 保留识别协议集合；多个服务不拼成一个伪协议名 |

网络总量仅从 conn 汇总，不再叠加 http/files 的业务字节。跨窗口长连接按起点计数与按时间分摊是不同模型；本版默认连接起点，不声称每分钟流量精确分布。

### 5.2 Zeek dns.log

分类：`network`；module.dataset：`zeek.dns`（自定义）；存储：`zeek.dns-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| query | dns.question.name | keyword | 查询名；保留原文，规范化规则固定 |
| qtype_name / qclass_name | dns.question.type / dns.question.class | keyword / keyword | 原始协议类型和类 |
| rcode_name | dns.response_code | keyword | 响应码；缺失不补 NOERROR |
| answers 中的合法 IP | dns.resolved_ip | ip[] | CNAME、文本答案不强转 IP |
| answers / TTLs | zeek.dns.answers / zeek.dns.ttls【扩展】 | keyword[] / double[] | TTL 单位秒，保持 _source 数组对应关系；需要成对查询时另建 nested RR 结构 |
| trans_id | zeek.dns.trans_id【扩展】 | long | 结合 observer、uid、时间区分事务，重复 ID 不作为全局唯一键 |
| rtt | zeek.dns.rtt【扩展】 | double | 响应时延秒，只有源记录有值才保存 |

### 5.3 Zeek ssh.log

分类：`network；有认证判定时可加 authentication`；module.dataset：`zeek.ssh`（自定义）；存储：`zeek.ssh-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| auth_success | event.outcome | keyword | true→success、false→failure；未提供时省略，网络推断不是端点权威审计 |
| auth_success / auth_attempts | zeek.ssh.auth_success / zeek.ssh.auth_attempts【扩展】 | boolean / long | 真实 false/0 保留；auth_attempts 不是失败次数 |
| client / server | zeek.ssh.client / zeek.ssh.server【扩展】 | keyword / keyword | 软件 banner，不是用户 |
| version / compression_alg | zeek.ssh.version / zeek.ssh.compression_alg【扩展】 | long / keyword | SSH 大版本和压缩方式，支持解释推断限制 |
| host_key_fingerprint | zeek.ssh.host_key_fingerprint【扩展】 | keyword | 可选，分析服务端主机密钥变化；须源 schema 提供 |

标准 ssh.log 不提供可直接作为登录账号的字段。只能做连接/推断认证结果统计，不能据它精确计算“同一账号输错密码次数”；ts 是连接起点。需要账号及每次失败时间时关联目标主机 sshd/audit。

### 5.4 Zeek rdp.log

分类：`network`；module.dataset：`zeek.rdp`（自定义）；存储：`zeek.rdp-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| cookie / client_name | zeek.rdp.cookie / zeek.rdp.client_name【扩展】 | keyword / keyword | 客户端自报线索，不能当已验证账户/主机 |
| security_protocol | zeek.rdp.security_protocol【扩展】 | keyword | 会话安全协议 |

此最小集支持 RDP 活动观察，不证明用户已登录桌面；认证成功需要目标 Windows 事件。

### 5.5 Zeek kerberos.log

分类：`network + authentication`；module.dataset：`zeek.kerberos`（自定义）；存储：`zeek.kerberos-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| client | user.name / user.domain | keyword / keyword | 仅对已确认 principal 格式拆分，保留完整原值；无 realm 不补域 |
| client / service | zeek.kerberos.client / service.name【扩展仅前者】 | keyword / keyword | 服务 principal 不当作人工账号 |
| success | event.outcome | keyword | 显式布尔值映射；只代表本次 Kerberos 交换 |
| error_msg | event.reason | keyword | 原始错误原因 |
| request_type / cipher | zeek.kerberos.request_type / zeek.kerberos.cipher【扩展】 | keyword / keyword | 请求阶段、加密算法；票据有效期不是登录时长 |

### 5.6 Zeek ntlm.log

分类：`network + authentication`；module.dataset：`zeek.ntlm`（自定义）；存储：`zeek.ntlm-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| username / domainname | user.name / user.domain | keyword / keyword | 认证账号及域，domainname 是原始键 |
| success | event.outcome | keyword | 只有明确布尔结果才转换 |
| hostname | zeek.ntlm.hostname【扩展】 | keyword | 客户端自报工作站，不覆盖 observer/host 身份 |

### 5.7 Zeek http.log

分类：`network + web`；module.dataset：`zeek.http`（自定义）；存储：`zeek.http-prod`；type：`access`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| method | http.request.method | keyword | 请求方法 |
| host | url.domain | keyword | 解析 Host 主机部分；存在显式端口时写 url.port（long），不覆盖 host.name |
| uri | url.original / url.path / url.query | wildcard / wildcard / keyword | 保留 URI 并按形式解析；CONNECT、绝对 URI、* 分支处理，不猜 scheme |
| status_code / version | http.response.status_code / http.version | long / keyword | 响应码与 HTTP 版本 |
| user_agent | user_agent.original | keyword | 原始 UA，不要求富化 |
| trans_depth | zeek.http.trans_depth【扩展】 | long | 结合 uid 区分连接内事务 |
| request_body_len / response_body_len | http.request.body.bytes / http.response.body.bytes | long / long | 请求/响应正文长度，不等于整个连接字节 |
| orig_fuids / resp_fuids | zeek.http.orig_fuids / zeek.http.resp_fuids【扩展】 | keyword[] / keyword[] | 可选；关联 files 中实际可见文件 |

HTTP 状态码保留，不自动解释为登录成功/失败。URL、UA、正文原文须先做敏感信息保护。

### 5.8 Zeek ssl.log

分类：`network`；module.dataset：`zeek.ssl`（自定义）；存储：`zeek.ssl-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| version | tls.version / tls.version_protocol | keyword / keyword | 验证后将 TLSv12/TLSv1.2 等映射 1.2＋tls；SSL 使用对应版本及 ssl；未知仅留原文 |
| cipher / server_name | tls.cipher / tls.client.server_name | keyword / keyword | 密码套件、SNI；不反查补造 SNI |
| established | tls.established | boolean | TLS 握手结果，不是用户认证结果 |
| cert_chain_fuids | zeek.ssl.cert_chain_fuids【扩展】 | keyword[] | 仅实际提供此字段的版本启用，关联 FUID |
| cert_chain_fps | zeek.ssl.cert_chain_fps【扩展】 | keyword[] | 仅实际提供此字段的版本启用，与证书 fingerprint 关联，不能混装成 FUID |
| validation_status | zeek.ssl.validation_status【扩展】 | keyword | 实际证书验证结果；缺失不当有效 |

### 5.9 Zeek x509.log

分类：`network`；module.dataset：`zeek.x509`（自定义）；存储：`zeek.x509-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| id / fingerprint | zeek.x509.id / zeek.x509.fingerprint【扩展】 | keyword / keyword | 按源版本分别保存，不相互覆盖或当 uid |
| certificate.subject / certificate.issuer | zeek.x509.subject / zeek.x509.issuer【扩展】 | keyword / keyword | 独立证书不猜客户端/服务端角色 |
| certificate.serial | zeek.x509.serial【扩展】 | keyword | 证书序列号 |
| certificate.not_valid_before / certificate.not_valid_after | zeek.x509.not_valid_before / zeek.x509.not_valid_after【扩展】 | date / date | 明确为 UNIX 秒才转换；非法值进入字段错误路径 |

### 5.10 Zeek ocsp.log

分类：`network`；module.dataset：`zeek.ocsp`（自定义）；存储：`zeek.ocsp-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 已验证的 ts | @timestamp | date | 公共时间转换；未确认 schema 时不能猜测其它键 |
| 完整 JSON 行 | event.original | keyword，index=false、doc_values=false | 原文回查，不建立猜测的 certificate_id/status 字段 |

能力边界：本项只定义原文接入。没有部署版本及 OCSP 样本，专有状态和证书关联解析不启用；不能宣称已具备证书状态统计。

### 5.11 Zeek files.log

分类：`file`；module.dataset：`zeek.files`（自定义）；存储：`zeek.files-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| filename / mime_type | file.name / file.mime_type | keyword / keyword | 原始文件名和识别类型；探针提取路径不是远端文件路径 |
| total_bytes | file.size | long | 已知文件总大小才保存；seen_bytes 不能代替 |
| sha256 | file.hash.sha256 | keyword | 启用并实际生成哈希时保存 |
| fuid / conn_uids | zeek.fuid / zeek.conn_uids【扩展】 | keyword / keyword[] | 文件与连接关联 |
| seen_bytes / missing_bytes | zeek.files.seen_bytes / zeek.files.missing_bytes【扩展】 | long / long | 观测完整性，不完整文件也要保留证据 |

### 5.12 Zeek smb_files.log

分类：`network + file`；module.dataset：`zeek.smb_files`（自定义）；存储：`zeek.smb_files-prod`；type：`access；明确动作时 creation/change/deletion`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| path + name | file.path | keyword | 按实际路径语义组合，缺失部分不补造 |
| name | file.name | keyword | 真实文件名 |
| action | zeek.smb_files.action【扩展】 | keyword | 保留精确源动作，ECS event.action 可省略 |
| action | event.type | keyword[] | SMB::FILE_OPEN/SMB::FILE_READ→access；SMB::FILE_WRITE/SMB::FILE_RENAME/SMB::FILE_SET_ATTRIBUTE→change；SMB::FILE_DELETE→deletion；SMB::FILE_CLOSE→end；其它→info；不将 FILE_OPEN 推断为新建 |
| fuid | zeek.fuid【扩展】 | keyword | 文件关联；原动作或日志存在不证明操作已成功 |

上述动作分支只适用于部署版本实际输出的同名值；必须用该版日志/脚本验证动作含义，不用模糊包含匹配或臆造 success。

### 5.13 Zeek smb_mapping.log

分类：`network`；module.dataset：`zeek.smb_mapping`（自定义）；存储：`zeek.smb_mapping-prod`；type：`access`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| path | zeek.smb_mapping.path【扩展】 | keyword | 共享路径，不是本地 file.path |
| service / share_type | zeek.smb_mapping.service / zeek.smb_mapping.share_type【扩展】 | keyword / keyword | 原服务和共享类型；版本提供才写 |

共享映射不证明文件已下载。

### 5.14 Zeek dce_rpc.log

分类：`network + api`；module.dataset：`zeek.dce_rpc`（自定义）；存储：`zeek.dce_rpc-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| endpoint / operation / named_pipe | zeek.dce_rpc.endpoint / zeek.dce_rpc.operation / zeek.dce_rpc.named_pipe【扩展】 | keyword / keyword / keyword | 可见 RPC 接口、操作、管道；不推断授权结果 |

### 5.15 Zeek ftp.log

分类：`network；明确文件传输时可加 file`；module.dataset：`zeek.ftp`（自定义）；存储：`zeek.ftp-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| user | user.name | keyword | 可见 FTP 账号 |
| command / arg | zeek.ftp.command / zeek.ftp.arg【扩展】 | keyword / keyword | 原始命令及非敏感参数；PASS 等敏感参数不索引，event.original 同样处理 |
| reply_code / reply_msg | zeek.ftp.reply_code / zeek.ftp.reply_msg【扩展】 | long / keyword | 保留对应回复；1xx/3xx 中间阶段不能直接当最终成功 |

最小版以 command＋reply_code 区分行为，不强制 event.outcome；RETR/STOR 为传输操作，不能只凭命令出现声明文件完整传输。

### 5.16 Zeek smtp.log

分类：`network + email`；module.dataset：`zeek.smtp`（自定义）；存储：`zeek.smtp-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| from / to / cc | email.from.address / email.to.address / email.cc.address | keyword[] / keyword[] / keyword[] | 解析邮件头地址，不能与信封地址互换 |
| mailfrom / rcptto | zeek.smtp.mailfrom / zeek.smtp.rcptto【扩展】 | keyword / keyword[] | 信封发件人与收件人 |
| msg_id | email.message_id | keyword | 邮件头消息 ID，不保证全局唯一；不是连接 uid |
| trans_depth | zeek.smtp.trans_depth【扩展】 | long | 连接内邮件事务关联 |
| last_reply | zeek.smtp.last_reply【扩展】 | keyword | SMTP 最后回复，不能直接证明最终投递到用户邮箱 |
| fuids | zeek.smtp.fuids【扩展】 | keyword[] | 仅实际提供时，用于 files 关联 |

### 5.17 Zeek dhcp.log

分类：`network`；module.dataset：`zeek.dhcp`（自定义）；存储：`zeek.dhcp-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| client_addr / server_addr | source.ip / destination.ip | ip / ip | 客户端→服务器逻辑方向，不把分配地址当原始源 IP |
| mac | source.mac | keyword | 客户端 MAC 按固定格式规范化 |
| uids | zeek.uids【扩展】 | keyword[] | 多连接关联 |
| assigned_addr / requested_addr | zeek.dhcp.assigned_addr / zeek.dhcp.requested_addr【扩展】 | ip / ip | 分配与请求分开 |
| lease_time / msg_types / host_name | zeek.dhcp.lease_time / zeek.dhcp.msg_types / zeek.dhcp.host_name【扩展】 | double / keyword[] / keyword | 租约秒、消息类型集合及自报名称；租约不是 event.duration |

地址—主机归属仅在确认分配/租约消息及有效时段内使用，不能由单条请求建立永久身份关系。

### 5.18 Zeek ntp.log

分类：`network`；module.dataset：`zeek.ntp`（自定义）；存储：`zeek.ntp-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| version / mode / stratum | zeek.ntp.version / zeek.ntp.mode / zeek.ntp.stratum【扩展】 | long / long / long | 基础 NTP 活动观察，不包含用户认证 |

### 5.19 Zeek snmp.log

分类：`network`；module.dataset：`zeek.snmp`（自定义）；存储：`zeek.snmp-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| version | zeek.snmp.version【扩展】 | keyword | 规范为源版本字符串，未知不推断 |
| community | 不输出 | — | 明文 community 不入普通字段，原文亦脱敏 |

能力边界：首版为 SNMP 基础活动，不宣称能按 OID/管理操作建立完整基线。

### 5.20 Zeek quic.log

分类：`network`；module.dataset：`zeek.quic`（自定义）；存储：`zeek.quic-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| version | zeek.quic.version【扩展】 | keyword | QUIC 版本，不是 tls.version |
| client_initial_dcid / client_scid / server_scid | zeek.quic.client_initial_dcid / zeek.quic.client_scid / zeek.quic.server_scid【扩展】 | keyword / keyword / keyword | 区分各连接 ID，不能当 ES _id |
| server_name | tls.client.server_name | keyword | 实际从 ClientHello 获取的 SNI |
| client_protocol / history | zeek.quic.client_protocol / zeek.quic.history【扩展】 | keyword / keyword | 可见 ALPN 和观测历史，不推断加密应用业务结果 |

仅启用已验证包含这些键的版本；无对应键时只投影公共端点与原文。

### 5.21 Zeek tunnel.log

分类：`network`；module.dataset：`zeek.tunnel`（自定义）；存储：`zeek.tunnel-prod`；type：`connection`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| tunnel_type / action | zeek.tunnel.type / zeek.tunnel.action【扩展】 | keyword / keyword | 原始隧道类型及动作；观察到隧道不代表攻击 |

### 5.22 Zeek ldap.log（版本/脚本支持时）

分类：`network；明确绑定认证时加 authentication`；module.dataset：`zeek.ldap`（自定义）；存储：`zeek.ldap-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| message_id / opcode | zeek.ldap.message_id / zeek.ldap.opcode【扩展】 | long / keyword | 消息标识和操作码；与 observer、uid、时间关联 |
| result / diagnostic_message | zeek.ldap.result / event.reason【扩展仅前者】 | keyword / keyword | 保留 LDAP 原始结果与说明；无响应不补成功 |
| object / argument | zeek.ldap.object / zeek.ldap.argument【扩展】 | keyword / keyword | 可见对象及非敏感参数；按 opcode 保护凭据；DN 不直接当 user.name |

仅明确 Bind 操作可增加 authentication；Search/Modify 不当登录。最小版保留 opcode＋result，不强制统一 outcome；结果枚举适配经样本验证后才启用。

### 5.23 Zeek ldap_search.log（版本/脚本支持时）

分类：`network`；module.dataset：`zeek.ldap_search`（自定义）；存储：`zeek.ldap_search-prod`；type：`access`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| message_id | zeek.ldap_search.message_id【扩展】 | long | 与同 uid 的 LDAP 交换关联 |
| base_object / scope / filter | zeek.ldap_search.base_object / zeek.ldap_search.scope / zeek.ldap_search.filter【扩展】 | keyword / keyword / wildcard | 搜索根 DN、范围与过滤表达式 |
| attributes | zeek.ldap_search.attributes【扩展】 | keyword[] | 请求属性列表 |
| result_count / result | zeek.ldap_search.result_count / zeek.ldap_search.result【扩展】 | long / keyword | 返回计数及源结果 |
| diagnostic_message | event.reason | keyword | 来源诊断说明 |

字段契约依据官方 SearchInfo；生产启用前仍需核对本机版本。与 ldap.log 不叠加成两次独立目录访问。

### 5.24 Zeek radius.log（启用时）

分类：`network + authentication`；module.dataset：`zeek.radius`（自定义）；存储：`zeek.radius-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| username | user.name | keyword | 可见认证账号 |
| result | zeek.radius.result【扩展】 | keyword | 保留原枚举 |
| result | event.outcome | keyword | 已确认 success→success、failure→failure；challenge/未知值不当失败 |
| reply_msg | event.reason | keyword | 来源回复说明 |

### 5.25 Zeek sip.log（启用时）

分类：`network`；module.dataset：`zeek.sip`（自定义）；存储：`zeek.sip-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| method / uri | zeek.sip.method / zeek.sip.uri【扩展】 | keyword / keyword | 请求方法和对象 |
| call_id / seq | zeek.sip.call_id / zeek.sip.seq【扩展】 | keyword / keyword | 通话 ID 与 CSeq，不能单用 call_id 计算事务数 |
| request_from / request_to | zeek.sip.request_from / zeek.sip.request_to【扩展】 | keyword / keyword | 自报通信对象，不当企业已验证账号 |
| status_code / status_msg | zeek.sip.status_code / zeek.sip.status_msg【扩展】 | long / keyword | 原始响应；认证挑战不直接等同密码错误 |

### 5.26 Zeek irc.log（启用时）

分类：`network`；module.dataset：`zeek.irc`（自定义）；存储：`zeek.irc-prod`；type：`protocol`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| nick / command | zeek.irc.nick / zeek.irc.command【扩展】 | keyword / keyword | 昵称及协议命令，不视为企业已验证用户 |

### 5.27 Zeek syslog.log（启用时）

分类：`network；消息可可靠解析时补语义类别`；module.dataset：`zeek.syslog`（自定义）；存储：`zeek.syslog-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| message | message | match_only_text | 网络侧收到的 syslog 正文，不覆盖 event.original |
| facility / severity | zeek.syslog.facility / zeek.syslog.severity【扩展】 | keyword / keyword | 首版保留名称/原值字符串；不把 syslog 名称直接写数字严重度 |

### 5.28 Zeek weird.log

分类：`network`；module.dataset：`zeek.weird`（自定义）；存储：`zeek.weird-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| name | event.reason | keyword | 协议异常名称 |
| name / addl | zeek.weird.name / zeek.weird.addl【扩展】 | keyword / keyword | 源异常与附加说明；kind=event，不自动作为攻击 |

### 5.29 Zeek notice.log

分类：`按 note 分类；明确入侵检测为 intrusion_detection`；module.dataset：`zeek.notice`（自定义）；存储：`zeek.notice-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| note | zeek.notice.note【扩展】 | keyword | 所有通知保留类型 |
| note | rule.name | keyword | 仅明确检测规则通知复制；运维通知不填 |
| msg | event.reason | keyword | 通知原因 |
| sub / actions | zeek.notice.sub / zeek.notice.actions【扩展】 | keyword / keyword[] | 补充说明及处置集合，actions 不是 event.action |
| src / dst | source.ip / destination.ip | ip / ip | 仅公共 id 端点缺失且方向语义一致时回填，不能覆盖矛盾端点 |

### 5.30 Zeek intel.log（启用情报框架时）

分类：`intrusion_detection（作为检测命中记录时）`；module.dataset：`zeek.intel`（自定义）；存储：`zeek.intel-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| seen.indicator / seen.indicator_type / seen.where | zeek.intel.indicator / zeek.intel.indicator_type / zeek.intel.where【扩展】 | keyword / keyword / keyword | 命中值、类型及位置；支持字面带点键 |
| sources | zeek.intel.sources【扩展】 | keyword[] | 情报来源集合；不能把命中记录当原始 IOC 导入 |

### 5.31 Zeek signatures.log（启用时）

分类：`intrusion_detection（检测签名命中）`；module.dataset：`zeek.signatures`（自定义）；存储：`zeek.signatures-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| src_addr / dst_addr | source.ip / destination.ip | ip / ip | 使用本日志专用端点键，不读取不存在的 id.orig_h/id.resp_h |
| src_port / dst_port | source.port / destination.port | long / long | 原端口存在且传输语义明确时映射 |
| sig_id / event_msg | rule.id / event.reason | keyword / keyword | 签名 ID 及说明 |
| note / sub_msg | zeek.signatures.note / zeek.signatures.sub_msg【扩展】 | keyword / keyword | 通知类型及附加上下文 |
| sig_count / host_count | zeek.signatures.sig_count / zeek.signatures.host_count【扩展】 | long / long | 汇总计数；汇总记录不等于一次单独命中 |

明确检测告警时 kind=alert；协议识别/其它签名按实际用途为 event。

### 5.32 Zeek software.log

分类：`package`；module.dataset：`zeek.software`（自定义）；存储：`zeek.software-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| name | package.name | keyword | 被动观察到的软件，不是安装操作 |
| version.major/minor/minor2/minor3 | package.version | keyword | 仅连接从 major 开始连续存在的数字段，缺中间段不补 0；完整原值保留 |
| unparsed_version / software_type | zeek.software.unparsed_version / zeek.software.type【扩展】 | keyword / keyword | 原版本字符串和软件类型 |
| host / host_p | zeek.software.host / zeek.software.port【扩展】 | ip / long | 被观测资产及可用服务端口，不覆盖探针身份 |

### 5.33 Zeek known_hosts.log（启用时）

分类：`host`；module.dataset：`zeek.known_hosts`（自定义）；存储：`zeek.known_hosts-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| host | host.ip | ip | 被观测资产，observer 仍为探针 |

### 5.34 Zeek known_services.log（启用时）

分类：`network`；module.dataset：`zeek.known_services`（自定义）；存储：`zeek.known_services-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| host / port_num / port_proto | destination.ip / destination.port / network.transport | ip / long / keyword | 被观测服务端，未知客户端不补 source |
| service | zeek.known_services.service【扩展】 | keyword[] | 识别出的服务集合，不拼为单值 |

### 5.35 Zeek stats.log

分类：`省略`；module.dataset：`zeek.sensor`（自定义）；存储：`zeek.sensor-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| peer | zeek.sensor.peer【扩展】 | keyword | 区分集群实例 |
| mem | zeek.sensor.stats.mem【扩展】 | long | 源内存 MB，保留源单位 |
| pkts_proc / pkts_dropped / bytes_recv | zeek.sensor.stats.pkts_proc / zeek.sensor.stats.pkts_dropped / zeek.sensor.stats.bytes_recv【扩展】 | long / long / long | 官方当前 schema 为上个统计间隔以来计数；部署版本核对后使用 |
| pkt_lag | zeek.sensor.stats.pkt_lag【扩展】 | double | 秒 |

kind=metric；zeek.log_type=stats。不同 peer 不混算为同一实例，计数不再求差。其它版本先验证指标是否区间量。

### 5.36 Zeek capture_loss.log

分类：`省略`；module.dataset：`zeek.sensor`（自定义）；存储：`zeek.sensor-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| peer | zeek.sensor.peer【扩展】 | keyword | 测量节点，不能按收集文件所在主机合并所有 peer |
| ts_delta | zeek.sensor.capture_loss.ts_delta【扩展】 | double | 与上次测量间隔，秒 |
| percent_lost | zeek.sensor.capture_loss.percent_lost【扩展】 | double | 原日志百分数口径；不是配置阈值 too_much_loss 的 0～1 比例 |
| gaps / acks | zeek.sensor.capture_loss.gaps / zeek.sensor.capture_loss.acks【扩展】 | long / long | 保留区间计数 |

kind=metric；zeek.log_type=capture_loss。此估计可反映镜像链路损失，不是某条 SSH 登录失败的直接证据；合并百分比需依据分母加权，不能简单相加。

### 5.37 Zeek reporter.log

分类：`省略或按明确内容分类`；module.dataset：`zeek.sensor`（自定义）；存储：`zeek.sensor-prod`；type：`info/error，按实际等级`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| level | log.level | keyword | 保留或固定表规范化级别 |
| message | message / error.message | match_only_text / match_only_text | 普通正文用 message，明确错误才另外写 error.message |
| location | zeek.sensor.reporter.location【扩展】 | keyword | 原始诊断位置 |

kind=event；zeek.log_type=reporter，与同 dataset 的 metric 区分。

### 5.38 Zeek dpd.log / analyzer.log（按实际版本）

分类：`network`；module.dataset：`zeek.analyzer`（自定义）；存储：`zeek.analyzer-prod`；type：`info`。

| 原始 JSON key / 依据 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| analyzer / failure_reason（dpd schema） | zeek.analyzer.name / zeek.analyzer.failure_reason【扩展】 | keyword / keyword | 只用于实际提供这两个键的 dpd 版本 |
| 其它 analyzer schema 的完整行 | event.original | keyword，index=false、doc_values=false | 不假定 analyzer.log 与 dpd.log 同结构 |

能力边界：dpd 字段匹配时启用专有解析；新版 analyzer schema 未验证时仅原文接入，保留 zeek.log_type 区分来源。

字段参考：[Zeek Conn](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)、[SSH](https://docs.zeek.org/en/current/scripts/base/protocols/ssh/main.zeek.html)、[LDAP](https://docs.zeek.org/en/current/scripts/base/protocols/ldap/main.zeek.html)、[Signatures](https://docs.zeek.org/en/current/scripts/base/frameworks/signatures/main.zeek.html)、[QUIC](https://docs.zeek.org/en/current/scripts/base/protocols/quic/main.zeek.html)、[Stats](https://docs.zeek.org/en/current/scripts/policy/misc/stats.zeek.html)、[Capture loss](https://docs.zeek.org/en/current/scripts/policy/misc/capture-loss.zeek.html)。在线 current 不是部署版本凭证；契约字段必须与部署 schema 对照后启用。

## 6. Linux：22 类原始记录逐项映射

### 6.0 公共规则与前置处理

本节为映射设计，非现场样本。普通文本中的“for 后账号”等必须落实到已识别的具体消息模板；不将它作为 JSON 路径。linux.*、auditd.* 是本项目扩展字段，不是 ECS；下表全部专有字段均按条件写入，所有类型显式定义。

| 原始字段/依据 | 目标字段 | 类型 | 规则 |
|---|---|---|---|
| 原业务时间、audit(ts:serial) 的 ts | @timestamp | date | 明确时区和格式，audit 秒换算；旧 syslog 缺年份不能历史回灌一律取当前年 |
| Journal _SOURCE_REALTIME_TIMESTAMP / __REALTIME_TIMESTAMP | @timestamp | date | 可用的可信源时间优先，否则记录 Journal 接收时间；微秒换算。增加 linux.time_basis（keyword：source/journal_received），不把接收时间冒充精确业务发生时间 |
| 原主机/_HOSTNAME/可信采集配置 | host.name | keyword | 真实产生日志主机，不是转发收集器 |
| _MACHINE_ID / _BOOT_ID | host.id / linux.boot_id【扩展仅后者】 | keyword / keyword | 真实主机和启动上下文；普通文件无此值时不猜 |
| 来源配置 | event.module / event.dataset | keyword / keyword | linux 与目录数据集；不由不可信正文控制索引路由 |
| 模板识别 | linux.record_type【扩展】 | keyword | 本节定义的记录子类，区分同 dataset 内的认证/会话/请求；event.action 仍可选 |
| SYSLOG_IDENTIFIER/程序名 | event.provider | keyword | 认证、会话、服务解析器须尽可能保留，未知省略 |
| audit type | event.code | keyword | 聚合事件选主记录类型，全部类型保留 auditd.record_types（keyword[]） |
| audit(ts:serial) 的 serial | auditd.sequence【扩展】 | keyword | 字符串标识；关联必须同时用主机、审计时间和启动上下文 |
| 原始行/聚合后的同事件原文 | event.original | keyword，index=false、doc_values=false | 多记录按确定顺序以换行拼成字符串，不写成对象数组 |
| 实际文件路径 | log.file.path | keyword | 文件输入提供；Journal 输入无文件路径时省略 |

**audit 事件组装契约（在 Ingest 前完成）**：

1. 按 host.id（否则可信 host.name）＋启动上下文（有则必须使用）＋audit 时间戳＋serial 分组。允许记录交错，不能只用“相邻行多行合并”。
2. 以 EOE 或采集器可靠的事件完成判定结束；设置可配置超时、最大组大小和持久化策略。SYSCALL.items、EXECVE.argc 与已收齐记录核对；路径角色或参数不完整时标记 auditd.assembly_status=incomplete（keyword）。
3. 完整事件为 complete；迟到记录为 late，并保留原关联键。重启丢失、超时、截断均不补造完整操作；首版 incomplete/late 保留原文及可确定字段，排除“一次执行/文件操作”基线。
4. 聚合事件只生成一份业务文档；优先按 syscall/AVC/对象实际语义选择主分类。重放防重使用采集身份＋源事件定位生成确定性 ES _id（或等效幂等策略），不能简单依赖随机 _id。
5. PATH 全集保留到 auditd.paths（object，enabled=false）；选择主 file.path，rename/link 另存 source_path/target_path。若将来需要对子字段做成对查询，再单独定义 nested mapping，不直接依赖普通对象数组。
6. syscall 数字依 arch 解码，open 类操作还需 flags、nametype、success。解析不明时保留原文/状态，不宣称已发生写入或创建。ES Ingest 本身不承担跨文档组装。

统计边界：同机 sshd/PAM/audit、同事务 sudo 请求/execve、文件与配置分类可以描述同一行为，必须按目标分析选择一条主事实来源，不能按所有入库文档相加。过程阶段的去重不是删除原始证据。

### 6.1 Linux secure/auth.log：sshd/PAM 登录认证

分类：`authentication`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`start`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| Accepted/Failed password/publickey for [invalid user] <account> from <ip> port <port> | user.name / source.ip / source.port | keyword / ip / long | 按完整 sshd 模板定位，不用任意 for/from 全文匹配 |
| sshd[PID] | process.pid | long | 记录来源进程 |
| password/publickey 等认证方法 | linux.auth.method【扩展】 | keyword | 源认证方式；密钥指纹按需要另行保护，不保存密码 |
| Accepted / Failed | event.outcome | keyword | 已适配模板中分别 success/failure |
| pam_*(sshd:auth) 中 user/rhost 和 authentication failure | user.name / source.ip / event.outcome | keyword / ip / keyword | PAM 认证模板单独分支；无 rhost 省略，失败不猜密码错误 |

模板标签 linux.record_type 分别为 sshd_auth、pam_auth（keyword，扩展）。同机同时存在两种记录时，认证次数首版以已适配 sshd Accepted/Failed 为主；PAM 用作补充证据，不再相加。只有 PAM 的源须单独定义统计范围。

### 6.2 Linux secure/auth.log：su/sudo 认证检查

分类：`authentication`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`info`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 明确请求者（sudo 前缀用户名、su 模板的 by/ruser，或可解释的请求者 UID） | user.name / user.id | keyword / keyword | 根据模板选择，不把目标 PAM user= 当操作者 |
| 明确目标身份（su 的目标、sudo USER= 或对应 PAM user=） | user.effective.name | keyword | 同时知道请求者才用 effective；仅知目标则以 user.name 保存并标记角色 |
| 认证成功/失败模板 | event.outcome | keyword | 认证结果，不是目标命令退出码 |
| PAM rhost / tty / 原 uid | source.ip / linux.auth.tty / linux.auth.uid【扩展后两者】 | ip / keyword / keyword | 地址合法才写，保留 UID 原始上下文 |
| 模板识别 | linux.auth.identity_role【扩展】 | keyword | requester_and_target 或 target_only |

linux.record_type=su_auth 或 sudo_auth；失败时仍可保留请求的目标权限身份，不证明身份切换成功。

### 6.3 Linux secure/auth.log：PAM 会话开始

分类：`session`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`start`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| session opened for user <account> | user.name | keyword | 会话所属账号 |
| 与该账号对应的 uid | user.id | keyword | 不误用 by 后的调用者 UID |
| 程序及 PID | event.provider / process.pid | keyword / long | sshd、sudo、su、cron 等明确来源分别保留 |
| 终端及明确会话标识 | linux.auth.tty / linux.auth.session_id【扩展】 | keyword / keyword | 无值不构造 |
| session opened | event.type / linux.record_type【扩展仅后者】 | keyword[] / keyword | start / pam_session_start |

### 6.4 Linux secure/auth.log：PAM 会话结束

分类：`session`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`end`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| session closed for user <account> | user.name | keyword | 会话所属账号 |
| 程序及 PID | event.provider / process.pid | keyword / long | 不根据用户名跨服务配对 |
| 终端及明确会话标识 | linux.auth.tty / linux.auth.session_id【扩展】 | keyword / keyword | 来源实际存在才保存 |
| session closed | event.type / linux.record_type【扩展仅后者】 | keyword[] / keyword | end / pam_session_end |

配对优先同 host＋启动上下文＋来源服务＋显式 session_id；没有会话 ID 时，PID＋账号＋时间只能做有界候选关联，发现复用/多候选则不生成 event.duration。

### 6.5 Linux secure/auth.log：用户创建/变更/删除

分类：`iam`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`creation/change/deletion + user`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| useradd/usermod/userdel 模板目标 name/UID | user.target.name / user.target.id | keyword / keyword | 按目标字段读取；不能将程序运行 UID 当目标 UID |
| 明确的操作者 | user.name / user.id | keyword / keyword | 无操作者不补 root |
| 来源操作 | linux.operation【扩展】 | keyword | create/change/delete；不是 event.action |
| 实际变化属性 | linux.auth.changes【扩展】 | object，enabled=false | 保留结构回查，不把任意属性动态建字段 |

linux.record_type=account_management；type 分别为 [creation,user]/[change,user]/[deletion,user]；只有明确操作完成模板才写 outcome=success。

### 6.6 Linux secure/auth.log：组及成员管理

分类：`iam`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`change + group；组创建/删除按动作`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 目标组 name/GID | group.name / group.id | keyword / keyword | 被管理组 |
| 明确用户成员 name/UID | user.target.name / user.target.id | keyword / keyword | 只在成员明确为用户时填写 |
| 明确操作者 | user.name / user.id | keyword / keyword | 不猜操作者 |
| 源管理动作 | linux.operation【扩展】 | keyword | group_create/group_delete/member_add/member_remove/group_change |

linux.record_type=group_management；本项目以目标组为中心，成员增删 type=[change,group]，创建/删除组分别 [creation,group]/[deletion,group]。

### 6.7 Linux secure/auth.log：passwd、锁定/解锁

分类：`iam`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`change + user`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 明确目标账户 | user.target.name / user.target.id | keyword / keyword | 密码/锁定操作对象 |
| 明确操作者 | user.name / user.id | keyword / keyword | 自改密码时角色可以相同 |
| 原始具体操作 | linux.operation【扩展】 | keyword | password_change/password_reset/lock/unlock |
| 明确结果 | event.outcome | keyword | 实际管理结果，不凭 passwd 命令被请求就认为成功 |

linux.record_type=account_management；不读取或保存密码内容。

### 6.8 Linux secure/auth.log：sudo 命令记录

分类：`process`；module.dataset：`linux.auth`（自定义）；存储：`linux.auth-prod`；type：`info`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| sudo: 后、TTY=前的请求用户名 | user.name | keyword | 仅适用于该完整 sudo 日志模板 |
| USER= | user.effective.name | keyword | 请求运行目标身份 |
| COMMAND= | process.command_line | wildcard | 非敏感命令请求；不是已执行成功证明 |
| PWD= / TTY= | process.working_directory / linux.auth.tty【扩展仅后者】 | keyword / keyword | 工作目录和终端 |
| sudo 请求模板 | linux.record_type / linux.operation【扩展】 | keyword / keyword | sudo_command / command_request |

只有 COMMAND 的日志不生成子进程 PID、退出码或执行成功；与 audit execve 关联后才能判断实际执行，不重复计算为两次程序启动。

### 6.9 Linux audit.log：USER_AUTH 等认证记录

分类：`authentication`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`info`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| acct | user.name | keyword | 本次认证账号；生产记录的 uid 不是其 UID |
| addr | source.ip | ip | 合法地址，? 占位省略 |
| res | event.outcome | keyword | 已验证 success/failed 枚举分别映射；其它值保留扩展 |
| auid / uid / ses / op | auditd.auid / auditd.uid / auditd.session / auditd.operation【扩展】 | keyword / keyword / keyword / keyword | 原登录身份、记录生产身份、会话及源操作 |
| res / exe / terminal | auditd.result / process.executable / auditd.terminal【扩展首尾】 | keyword / keyword / keyword | 原结果、业务进程路径、终端上下文 |

linux.record_type=audit_auth；未提供有效 UID 时只填用户名，不能把记录生产进程 UID 配给认证账号。

### 6.10 Linux audit.log：USER_START/USER_END

分类：`session`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`start/end`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| type=USER_START/USER_END | event.type | keyword[] | 分别 start/end |
| acct / addr | user.name / source.ip | keyword / ip | 会话账号与真实来源 |
| ses / auid / res | auditd.session / auditd.auid / auditd.result【扩展】 | keyword / keyword / keyword | 源会话、原登录身份、结果 |
| res | event.outcome | keyword | 有明确结果时规范，未知不猜 |

linux.record_type=audit_session_start 或 audit_session_end；失败的 USER_START 不计为已建立会话。

### 6.11 Linux audit.log：账号/组变更审计

分类：`iam`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`creation/change/deletion，按操作`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 按具体 audit type 定义的目标 acct/账号 UID | user.target.name / user.target.id | keyword / keyword | ADD_USER/DEL_USER 等分别适配；记录 uid 不当目标 UID |
| 明确操作者 uid | user.id | keyword | 操作上下文 |
| 目标组/成员 | group.name / group.id / user.target.name | keyword / keyword / keyword | 仅角色明确时映射，不能将组名填 user |
| res | event.outcome | keyword | 已验证的管理操作结果 |
| op / auid / ses | auditd.operation / auditd.auid / auditd.session【扩展】 | keyword / keyword / keyword | 保留原始操作与身份 |
| 明确操作分支 | linux.operation【扩展】 | keyword | create/delete/change/group_create/group_delete/member_add/member_remove |

linux.record_type=audit_iam；源 type 未适配时仅保留 event.code 与原文，不从含糊消息推断目标账号。

### 6.12 Linux audit.log：execve/execveat 执行审计

分类：`process`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`start（执行成功）；失败尝试用 info`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| uid / auid / euid | user.id / auditd.auid / process.user.id【扩展仅中间】 | keyword / keyword / keyword | 实际身份、原登录身份、进程有效身份分开；auid 的 unset/-1/4294967295 不当 root |
| uid | process.real_user.id | keyword | 按固定 ECS schema 复用真实 UID |
| pid / ppid | process.pid / process.parent.pid | long / long | 业务进程、父进程，不使用采集器 PID |
| exe / comm | process.executable / process.name | keyword / keyword | 实际程序路径和名称 |
| ses / arch / syscall / key | auditd.session / auditd.arch / auditd.syscall / auditd.key【扩展】 | keyword / keyword / keyword / keyword[] | syscall 数字先结合 arch 解码；key 不是操作成功证明 |
| success / exit | event.outcome / auditd.syscall_exit【扩展仅后者】 | keyword / long | yes/no→success/failure；exit 是系统调用返回值，不写 process.exit_code |
| EXECVE.a0…aN / argc | process.args / process.args_count | keyword[] / long | 同 serial 关联后解码分段/十六进制；顺序和参数数量校验，不按空格盲分 |
| PROCTITLE.proctitle | process.command_line | wildcard | 解码 NUL 参数后按固定转义格式展示；原始字节保留原文 |
| CWD.cwd | process.working_directory | keyword | 同事件真实工作目录 |

linux.record_type=audit_exec；只有 syscall 解码为 execve/execveat 才进入此分支，成功 type=start、失败 info。exec 成功不等于程序最终正常退出。

### 6.13 Linux audit.log：文件访问/修改审计

分类：`file`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`access/creation/change/deletion，按 syscall`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| uid / auid / euid | user.id / auditd.auid / process.user.id【扩展仅中间】 | keyword / keyword / keyword | 实际身份、原登录身份、进程有效身份分开；auid 的 unset/-1/4294967295 不当 root |
| uid | process.real_user.id | keyword | 按固定 ECS schema 复用真实 UID |
| pid / ppid | process.pid / process.parent.pid | long / long | 业务进程、父进程，不使用采集器 PID |
| exe / comm | process.executable / process.name | keyword / keyword | 实际程序路径和名称 |
| ses / arch / syscall / key | auditd.session / auditd.arch / auditd.syscall / auditd.key【扩展】 | keyword / keyword / keyword / keyword[] | syscall 数字先结合 arch 解码；key 不是操作成功证明 |
| success / exit | event.outcome / auditd.syscall_exit【扩展仅后者】 | keyword / long | yes/no→success/failure；exit 是系统调用返回值，不写 process.exit_code |
| PATH.name + CWD.cwd | file.path | keyword | 主操作对象的规范化路径；仅在对象和相对路径基准明确时拼接 |
| PATH 全部记录 | auditd.paths【扩展】 | object[]，enabled=false | 保留 item/nametype/name/inode/mode 等来源结构及对象关系，不直接参与聚合 |
| rename/link 的来源和目标路径 | auditd.source_path / auditd.target_path【扩展】 | keyword / keyword | 操作角色明确时分别索引；不把多个 PATH 展开为多次独立操作 |
| SYSCALL 的 a0…a3 | auditd.args【扩展】 | object，enabled=false | 保存原参数；文件标志解码依 arch＋syscall，不能照搬 exec 参数解析 |

linux.record_type=audit_file；open/openat 必须结合 flags、PATH nametype 及 success 解释，不能只凭 syscall 名称认定创建/修改。rename 是 change，unlink 是 deletion；只读 access。文件内容差异不由 audit 自动提供。

### 6.14 Linux audit.log：sudoers/sshd 等配置修改

分类：`configuration + file`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`change`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| uid / auid / euid | user.id / auditd.auid / process.user.id【扩展仅中间】 | keyword / keyword / keyword | 实际身份、原登录身份、进程有效身份分开；auid 的 unset/-1/4294967295 不当 root |
| uid | process.real_user.id | keyword | 按固定 ECS schema 复用真实 UID |
| pid / ppid | process.pid / process.parent.pid | long / long | 业务进程、父进程，不使用采集器 PID |
| exe / comm | process.executable / process.name | keyword / keyword | 实际程序路径和名称 |
| ses / arch / syscall / key | auditd.session / auditd.arch / auditd.syscall / auditd.key【扩展】 | keyword / keyword / keyword / keyword[] | syscall 数字先结合 arch 解码；key 不是操作成功证明 |
| success / exit | event.outcome / auditd.syscall_exit【扩展仅后者】 | keyword / long | yes/no→success/failure；exit 是系统调用返回值，不写 process.exit_code |
| PATH.name + CWD.cwd | file.path | keyword | 主操作对象的规范化路径；仅在对象和相对路径基准明确时拼接 |
| PATH 全部记录 | auditd.paths【扩展】 | object[]，enabled=false | 保留 item/nametype/name/inode/mode 等来源结构及对象关系，不直接参与聚合 |
| rename/link 的来源和目标路径 | auditd.source_path / auditd.target_path【扩展】 | keyword / keyword | 操作角色明确时分别索引；不把多个 PATH 展开为多次独立操作 |
| SYSCALL 的 a0…a3 | auditd.args【扩展】 | object，enabled=false | 保存原参数；文件标志解码依 arch＋syscall，不能照搬 exec 参数解析 |
| 已证明的写入/权限变化＋受控配置路径清单 | event.category / event.type | keyword[] / keyword[] | configuration＋file 与 change；只读配置仍是 file/access |

linux.record_type=audit_configuration；audit key 命中不自动证明配置已改变。

### 6.15 Linux audit.log：审计规则/审计配置变更

分类：`configuration`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`change`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| audit type/op | event.code / auditd.operation【扩展仅后者】 | keyword / keyword | 原始配置事件类型和操作 |
| uid / auid / ses | user.id / auditd.auid / auditd.session【扩展后两者】 | keyword / keyword / keyword | 操作者、原登录身份及会话 |
| res | auditd.result / event.outcome【扩展仅前者】 | keyword / keyword | res 原值保留；按此类型的枚举转换，不复用其它类型规则 |
| key/list/rule 及相关字段 | auditd.config【扩展】 | object，enabled=false | 完整源配置细节，首版不展开索引 |

linux.record_type=audit_rules；仍保留 event.code 和 auditd.operation 供规则筛选。

### 6.16 Linux audit.log：SELinux AVC 拒绝

分类：`按对象选 file/process/network 等`；module.dataset：`linux.audit`（自定义）；存储：`linux.audit-prod`；type：`file/process 常用 access；network 可用 denied`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| uid / auid / euid | user.id / auditd.auid / process.user.id【扩展仅中间】 | keyword / keyword / keyword | 实际身份、原登录身份、进程有效身份分开；auid 的 unset/-1/4294967295 不当 root |
| uid | process.real_user.id | keyword | 按固定 ECS schema 复用真实 UID |
| pid / ppid | process.pid / process.parent.pid | long / long | 业务进程、父进程，不使用采集器 PID |
| exe / comm | process.executable / process.name | keyword / keyword | 实际程序路径和名称 |
| ses / arch / syscall / key | auditd.session / auditd.arch / auditd.syscall / auditd.key【扩展】 | keyword / keyword / keyword / keyword[] | syscall 数字先结合 arch 解码；key 不是操作成功证明 |
| success / exit | event.outcome / auditd.syscall_exit【扩展仅后者】 | keyword / long | yes/no→success/failure；exit 是系统调用返回值，不写 process.exit_code |
| AVC 权限集合 / tclass | auditd.selinux.permissions / auditd.selinux.tclass【扩展】 | keyword[] / keyword | 原策略权限及对象类型 |
| scontext / tcontext / permissive | auditd.selinux.scontext / auditd.selinux.tcontext / auditd.selinux.permissive【扩展】 | keyword / keyword / long | 保留源上下文和 0/1，类型不漂移 |
| 明确 path 或关联 PATH | file.path | keyword | name 仅为文件基名时不能冒充完整路径 |

linux.record_type=audit_avc；AVC denied 是策略判定，permissive=1 不等于实际阻断。最终 event.outcome 以同事件 syscall 结果优先；没有 syscall 且 enforcing 明确拒绝时可为 failure，未知则省略。审计多记录中 AVC 与文件主体只生成一个规范事件，保留 record_types，不另加一条重复文件操作。

### 6.17 Linux messages/syslog/journal：主机启动/关闭

分类：`host`；module.dataset：`linux.system`（自定义）；存储：`linux.system-prod`；type：`start/end`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 可信启动/关机模式 | event.type / linux.record_type【扩展仅后者】 | keyword[] / keyword | start/host_start 或 end/host_stop，不凭日志中断推断 |
| _BOOT_ID / 明确原因 | linux.boot_id / event.reason【扩展仅前者】 | keyword / keyword | 启动上下文与源原因 |
| _MACHINE_ID 或可信配置 | host.id | keyword | 来源稳定主机标识，不使用收集器标识 |

### 6.18 Linux messages/syslog/journal：服务生命周期

分类：`process`；module.dataset：`linux.system`（自定义）；存储：`linux.system-prod`；type：`start/end/info，按事件`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| systemd 管理器记录的 UNIT | service.name | keyword | 被管理服务优先；不被 _SYSTEMD_UNIT 覆盖 |
| _SYSTEMD_UNIT | linux.system.origin_unit【扩展】 | keyword | 产生日志的进程所属单元；仅明确它就是目标服务时才填 service.name |
| 明确目标服务 PID | process.pid | long | systemd 自身 PID 不当业务服务 PID |
| JOB_RESULT/明确状态 | linux.system.job_result / event.outcome【扩展仅前者】 | keyword / keyword | 原结果保留；done/明确成功→success，明确失败→failure，未决不填 |
| INVOCATION_ID 或 _SYSTEMD_INVOCATION_ID（角色已确认） | linux.system.invocation_id【扩展】 | keyword | 服务运行周期；管理器自己的调用上下文不当目标服务实例 |

linux.record_type=service_lifecycle；linux.operation=start/stop/state（keyword）。按消息区分请求、完成和状态，不能把 Starting 与 Started 当两次服务启动。

### 6.19 Linux messages/syslog/journal：其他运行日志

分类：`可判断才设置，否则省略`；module.dataset：`linux.system`（自定义）；存储：`linux.system-prod`；type：`info/error，按内容`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| SYSLOG_IDENTIFIER / 程序名 | event.provider | keyword | 实际生产者 |
| PRIORITY / 明确级别 | log.level | keyword | Journal 0..7→emerg/alert/crit/err/warning/notice/info/debug；原数值可留 linux.system.priority（long） |
| MESSAGE / 正文 | message | match_only_text | 可搜索正文，原文仍保留 |

linux.record_type=system_message；无法判断业务语义时省略 category，不将全部系统日志归 host。

### 6.20 Linux dpkg.log/apt/history.log/dnf.log/yum.log：软件变更

分类：`package`；module.dataset：`linux.package`（自定义）；存储：`linux.package-prod`；type：`installation/change/deletion，按动作`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 包名 | package.name | keyword | dpkg/apt/dnf/yum 分格式处理 |
| 实际版本 | package.version | keyword | 保留字符串，不转小数 |
| 旧版本/包架构/事务 ID | linux.package.old_version / package.architecture / linux.package.transaction_id【扩展首尾】 | keyword / keyword / keyword | 真实存在才保留 |
| 安装/升级/删除完成记录 | event.type / linux.operation【扩展仅后者】 | keyword[] / keyword | installation/install、change/upgrade、deletion/remove |

linux.record_type=package_change；多行 apt 事务先归并，下载/计划执行不当安装完成，同包同事务的状态行不重复计数。

### 6.21 Linux nginx/apache access.log（可选）

分类：`web`；module.dataset：`linux.web_access`（自定义）；存储：`linux.web_access-prod`；type：`access`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| remote_addr / %a | source.ip | ip | 按真实 LogFormat，代理环境只信任配置的代理链 |
| 请求方法 / URI | http.request.method / url.original | keyword / wildcard | 完整请求 URI 经敏感信息保护；再拆 url.path（wildcard）、url.query（keyword） |
| status / %>s | http.response.status_code | long | 实际响应码 |
| http_user_agent / User-Agent | user_agent.original | keyword | 原始 UA |
| remote_user | user.name | keyword | 明确已认证且非 - 的用户 |
| body_bytes_sent / Apache %B | http.response.body.bytes | long | 正文字节，不是完整网络包字节 |
| request_time（秒）/Apache %D（微秒） | event.duration | long | 分别乘 10^9 / 10^3 后转纳秒；未配置日志格式时不生成 |
| 可信虚拟主机/服务配置 | service.name | keyword | 区分被访问服务，不从任意 Host 头推导可信身份 |

linux.record_type=web_access；HTTP 错误码不自动当用户认证失败。与 Zeek HTTP 按不同观察来源使用，不简单叠加请求数。

### 6.22 Linux 应用运行日志（可选）

分类：`按明确业务语义，不统一归 application`；module.dataset：`linux.application`（自定义）；存储：`linux.application-prod`；type：`info/error 或业务子类`。

| 原始字段/具体模板位置 | 目标字段 | 类型 | 条件规则与含义 |
|---|---|---|---|
| 业务时间 / 日志等级 | @timestamp / log.level | date / keyword | 指定格式和时区；多行异常先合并 |
| 可信服务配置 | service.name | keyword | 稳定服务标识 |
| 正文 / 明确异常 | message / error.message | match_only_text / match_only_text | ERROR 等级不自动映射认证 failure |
| 明确业务账号 | user.name / user.id | keyword / keyword | 只有结构化语义明确时映射，不全文猜用户名 |
| 明确业务操作 | linux.operation【扩展】 | keyword | 仅已登记、已适配的动作；不存在则省略 |
| 尚未适配的完整原文 | event.original | keyword，index=false、doc_values=false | 回查用；不把任意 JSON key 动态建索引 |

linux.record_type=application；没有业务账号/操作字段时，只具备运行日志检索能力，不宣称已具备应用用户行为分析。

依据：[Red Hat Audit](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/8/html/security_hardening/auditing-the-system_security-hardening)、[ECS Process 身份复用](https://www.elastic.co/docs/reference/ecs/ecs-process)、[systemd Journal 字段](https://github.com/systemd/systemd/blob/main/man/systemd.journal-fields.xml)。这些定义不能替代对具体发行版、服务模板和已部署采集器的输入输出验收。

## 7. 最小实现与验收边界

### 7.1 只保留有分析价值的字段

1. **原始有值才映射**：缺失IP、SID、用户名、命令行不能补造。类型必须明确：IP用ip、分类与标识用keyword、端口/计数用long、category/type用字符串数组。
2. **来源扩展不是ECS**：winlog.*、zeek.*、auditd.*、linux.* 是本方案必要来源扩展字段。使用明确白名单；未用于检索的内容留event.original，或放入不展开索引的原始对象。不要把全部原始键动态建成索引字段。
3. **action可选**：Windows保留event.code，协议保留原操作字段，Linux 保留 linux.record_type 及适用的 linux.operation；只有跨来源统一业务规则需要时增加event.action。缺少action不拒绝入库。类别/数据集相同不表示业务动作相同。
4. **文档展示不等于全部必填**：每类的“公共字段+实际有值的条件字段”组成真实最小事件。正文里的组合名称仅表示分别映射，不要创建包含斜杠的字段名。
5. **不新增普通id**：ES _id是元数据，event.id不是首版强制字段。Zeek uid/FUID、Windows Record ID、audit序列号是源关联字段，不能因为ES有_id就删除；也不能仅用其中一个做跨记录幂等键。

### 7.2 最小链路

Windows事件由Winlogbeat采集；Zeek JSON由自定义Filebeat filestream采集，不要求官方Zeek模块；Linux文件由适配格式的采集器处理。普通解析和ECS映射可在ES Ingest完成，Linux audit跨记录关联需要采集器或前置关联层。

`<module>.<dataset>-<namespace>` 是本项目目标命名。每个目标需要匹配的mapping/template及受控写入路由。可使用稳定数据流或写入别名，按实际容量配置生命周期、分片与副本；不预创建所有协议空索引。本次没有改动旧logs-zeek.*-prod或当前服务。

最小落地原则：普通文本/JSON 只走采集器→ES Ingest 即可；audit 需要前置组装。当前是文档设计交付，不生成或更换线上 Pipeline。完成部署验收前，“覆盖该日志类型”只代表有字段契约，不代表该类型所有场景均已产生日志。

### 7.3 必须验收的项目

| 验收项目 | 判断标准 |
|---|---|
| Windows覆盖 | 32 个 ID 的映射齐全；31 个 ID 有报告代表样本。4624 的 11 类型逐分支验收；Type 11 未捕获、12/13 未覆盖、4740 无样本不得标成通过 |
| 缺失值 | 4624样本IpAddress=-不生成source.ip；4688样本CommandLine为空不虚构命令行；缺失auth_success不补false |
| 原始身份角色 | 登录目标/对外凭据/创建进程身份、IAM 操作者与目标、未知类型成员 SID、audit uid/euid/auid 均不互相覆盖 |
| 时间 | 原始事件时间与采集/入库时间分离；date默认毫秒检索精度，高精度方案另行确认 |
| 业务语义 | 4771读取实际Status；4689 Status转process.exit_code；SSHD/PAM重复阶段不能简单相加 |
| 解析与完整性 | 每个已启用解析器有真实输入与ES _source输出校验；版本相关协议没有样本不得宣称上线验证完成 |
| 故障路径 | JSON/日期/类型错误保留原文、error.message 并可监控；audit 不完整/迟到、模板拒绝、积压和镜像丢包分别监控 |
| 敏感数据 | 密码、token、community和敏感参数按策略不采集/脱敏，保留原文同样受该策略约束 |
| 数组与类型 | 同一目标跨来源类型一致；DNS 答案/TTL 和多 PATH 保持关系；不能将 long 数字、boolean 假值误删 |
| 计数与防重 | 同事件重放不增加独立动作数；同 uid 多事务不能互相覆盖；跨来源描述同一行为不简单相加 |
| 路由与兼容 | 每个 dataset 写入目标与模板匹配，未登记来源不能任意创建索引；既有字段改类型必须使用新目标或明确迁移 |

### 7.4 证据等级

- Windows 代表样本值来自报告 XML；新增条件行若该样本没有字段，明确写“未提供（条件映射规则）”，不冒充真实值。保留 API 模拟、历史样本与未捕获边界。
- 4624 JSON是由报告真实XML生成的**清洗设计投影**，没有宣称已存入ES。
- Zeek/Linux表是字段级映射契约，未进行本次服务器连接或端到端试写；版本相关未验证key已经标注。
- 生产级设计与部署完成是两件事；本次只重构本地文档，不重启/修改任何服务器服务。

## 8. 枚举值字典：含义与选择条件

本节作为可选分类/动作字典保留，实际原始字段映射以前文逐事件表为准。event.action 始终可选，不能因未填写而拒绝入库。本节用于指导编写分类规则。“满足条件”指有原始事件 ID、协议日志类型、操作码、对象类型或可信解析结果支撑，不是仅根据关键词猜测。

| 字段 | 枚举性质 | 使用约束 |
|---|---|---|
| `event.category` | ECS 标准枚举 | 数组，可多选；无合适类别时省略，不创建 authentication_failure、ssh、linux、application 等类别 |
| `module.dataset`（自定义） | 项目数据集枚举，实际写入 `event.dataset` | 单值，按来源和日志结构选取；“（自定义）”仅为文档标注，不能写进实际值 |
| `event.type` | ECS 标准枚举 | 数组，可多选；不是成功/失败，也不是日志级别 |
| `event.action` | ECS 字段、值由项目自定义 | 可选单值，本节给出可供采用的动作字典；不把主表的斜杠、多选说明、中文“等”写入值中 |
| `event.kind`、`event.outcome` | ECS 标准枚举 | 单值；普通原始事件不冒充告警或检测系统内部对象 |
| `event.module`、namespace | 项目约定值 | 来源/环境配置决定，不根据事件成功失败改变 |

以下 ECS 标准值按本次核对的官方文档列出；正式上线仍应固定实际采用的 ECS 版本。补充列出的类别不代表首版已具备相应采集源。

### 8.1 event.category：行为大类（ECS 标准）

| 枚举值 | 含义 | 满足什么条件时选择 / 本项目例子 |
|---|---|---|
| `api` | API/服务接口调用 | 有具体接口调用记录；如 4673 特权服务调用、DCE/RPC 调用，不因出现进程名就选 api |
| `authentication` | 身份凭据验证活动 | 4624/4625、Kerberos/NTLM 认证、PAM 认证，或 Zeek 明确观察到认证活动；不是所有 SSH 连接均有认证结论 |
| `configuration` | 系统或应用配置操作 | 明确修改 sshd/sudoers/审计规则等设置；读取配置文件不等于配置发生变化 |
| `database` | 数据库访问/操作 | 后续接入数据库审计，且记录描述查询、更新等数据库行为时使用；本期未单独配置数据库采集 |
| `driver` | 驱动活动 | 实际驱动/内核模块加载、卸载或变化记录；普通程序启动不适用，首版没有专用采集规则 |
| `email` | 邮件活动 | SMTP、邮件投递/访问等；本表 smtp.log 可以同时标 network |
| `file` | 文件/目录活动 | 文件访问、增删改、权限变化或网络文件观察；4670 必须先确认对象是 File |
| `host` | 主机本身的信息/生命周期 | 主机开关机或 known_hosts 资产观察；不能给全部主机日志都选 host |
| `iam` | 用户、组及身份权限管理 | 用户启停、密码管理、组成员变化、AD/SAM 对象操作；不是每次登录都归 iam |
| `intrusion_detection` | 入侵检测活动 | 明确检测规则/签名/情报命中记录；weird、丢包或登录失败本身不能直接套用 |
| `library` | 进程加载库 | 有 DLL/SO 等库加载记录；本期未接入此类专用事件 |
| `malware` | 恶意软件检测 | 杀毒/EDR 等明确报告恶意软件检测；仅下载文件或命中可疑域名不能证明 malware |
| `network` | 网络通信活动 | conn、DNS、TLS、SSH、SMB 等协议活动；可与 web、file、authentication 等组合 |
| `package` | 软件包信息/变更 | 软件包安装、升级、卸载或软件信息观察；software.log 观察结果不代表发生安装 |
| `process` | 进程活动 | 4688/4689、execve、sudo 命令请求等；以原记录区分请求、执行及结束 |
| `registry` | Windows 注册表活动 | 目标确属注册表，例如适用对象类型的 4670；普通文件 ACL 变化不适用 |
| `session` | 逻辑登录会话活动 | 会话建立、注销、PAM session 开关；普通 TCP 握手不自动算已登录会话 |
| `threat` | 威胁信息/指标 | 后续直接接入威胁情报条目时使用；本表 intel.log 是匹配事件，不是原始 IOC 条目 |
| `vulnerability` | 漏洞信息 | 漏洞扫描/检测结果；软件版本老旧但没有漏洞判断依据时不能直接选 |
| `web` | Web 访问活动 | HTTP 请求、Web 访问日志；TLS 握手中只有 SNI 时不能声称已经看到 Web 请求 |

`event.category` 没有合法值 `unknown`、`other`、`system`、`security`；无法可靠分类时省略字段。枚举及语义依据：[ECS event.category](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-category)。

### 8.2 module.dataset（自定义）：数据集枚举

此处完整覆盖分类目录的 **43 个数据集**。一个记录只选一个 dataset，多个 category 不产生多个 dataset。识别依据优先采用采集配置的来源标识及匹配的解析器，不用事件正文任意指定写入索引。

| 枚举值（均为自定义） | 含义 | 满足什么条件时选择 |
|---|---|---|
| `windows.security`（自定义） | Windows 安全审计 | 记录来自原始 Security 通道、匹配本表 Windows 事件规则；WEF 转发后仍按原事件来源识别 |
| `zeek.conn`（自定义） | 网络连接摘要 | Zeek conn.log 结构匹配；不因其他日志也含 uid 就选此数据集 |
| `zeek.dns`（自定义） | DNS 事务 | Zeek dns.log 及匹配解析器 |
| `zeek.ssh`（自定义） | SSH 协议会话 | Zeek ssh.log；结果未知/失败/成功均留在此数据集 |
| `zeek.rdp`（自定义） | RDP 协议活动 | Zeek rdp.log |
| `zeek.kerberos`（自定义） | Kerberos 协议活动 | Zeek kerberos.log；不能把 Windows 4768 路由到这里 |
| `zeek.ntlm`（自定义） | NTLM 协议活动 | Zeek ntlm.log |
| `zeek.http`（自定义） | HTTP 事务 | Zeek http.log；不是任意 Linux Web access.log |
| `zeek.ssl`（自定义） | SSL/TLS 握手 | Zeek ssl.log；数据集名保留来源名称，业务分类仍可写 TLS |
| `zeek.x509`（自定义） | X.509 证书观察 | Zeek x509.log 独立证书记录 |
| `zeek.ocsp`（自定义） | 证书状态响应 | Zeek ocsp.log |
| `zeek.files`（自定义） | 网络文件元信息 | Zeek files.log；有文件数据记录，不要求已提取文件实体 |
| `zeek.smb_files`（自定义） | SMB 文件操作 | Zeek smb_files.log |
| `zeek.smb_mapping`（自定义） | SMB 共享映射 | Zeek smb_mapping.log，不与 smb_files 合并结构 |
| `zeek.dce_rpc`（自定义） | DCE/RPC 调用 | Zeek dce_rpc.log |
| `zeek.ftp`（自定义） | FTP 命令/响应 | Zeek ftp.log；先按规定保护可能出现的凭据信息 |
| `zeek.smtp`（自定义） | SMTP 邮件活动 | Zeek smtp.log |
| `zeek.dhcp`（自定义） | DHCP 地址分配 | Zeek dhcp.log |
| `zeek.ntp`（自定义） | NTP 交换 | Zeek ntp.log |
| `zeek.snmp`（自定义） | SNMP 活动 | Zeek snmp.log；遵守敏感 community 处理要求 |
| `zeek.quic`（自定义） | QUIC 会话 | 部署版本支持并生成 quic.log |
| `zeek.tunnel`（自定义） | 隧道观察 | Zeek tunnel.log |
| `zeek.ldap`（自定义） | LDAP 操作 | 部署版本/脚本支持 ldap.log；按操作类型再分 category/action |
| `zeek.ldap_search`（自定义） | LDAP 查询细节 | 实际存在 ldap_search.log；不与同次 ldap 交换简单相加 |
| `zeek.radius`（自定义） | RADIUS 交换 | 启用并生成 radius.log |
| `zeek.sip`（自定义） | SIP 信令 | 启用并生成 sip.log |
| `zeek.irc`（自定义） | IRC 协议活动 | 启用并生成 irc.log |
| `zeek.syslog`（自定义） | 网络侧 syslog 观察 | Zeek syslog.log，而非主机直接读取的 /var/log/syslog |
| `zeek.weird`（自定义） | 协议异常观察 | Zeek weird.log；不论是否进一步研判为攻击，原记录仍放这里 |
| `zeek.notice`（自定义） | Zeek 通知/检测记录 | Zeek notice.log；通知种类决定 kind/category |
| `zeek.intel`（自定义） | 情报匹配记录 | 启用情报框架并生成 intel.log；不是导入 IOC 原始清单 |
| `zeek.signatures`（自定义） | 签名匹配记录 | 生成 signatures.log；检测还是协议识别由签名用途判断 |
| `zeek.software`（自定义） | 软件指纹观察 | Zeek software.log |
| `zeek.known_hosts`（自定义） | 已观察主机信息 | 启用并生成 known_hosts.log |
| `zeek.known_services`（自定义） | 已观察服务信息 | 启用并生成 known_services.log |
| `zeek.sensor`（自定义） | 探针运行信息 | stats.log、capture_loss.log 或 reporter.log；使用 zeek.log_type 区分，event.action 可选；不能无差别混入所有 Zeek 日志 |
| `zeek.analyzer`（自定义） | 协议分析器诊断 | 实际版本的 dpd.log/analyzer.log，匹配对应结构 |
| `linux.auth`（自定义） | 主机认证相关日志 | 直接采集 secure/auth.log；同文件中的 session、iam、sudo 记录仍在此数据集 |
| `linux.audit`（自定义） | Linux 内核/用户审计 | audit.log 或审计采集器提供的记录；跨行关联是否完成必须明确 |
| `linux.system`（自定义） | 系统/服务运行日志 | messages/syslog/journal 的系统记录；不能覆盖已有 auth/audit 专用采集 |
| `linux.package`（自定义） | 软件包管理日志 | dpkg、apt、dnf、yum 等已适配的管理日志 |
| `linux.web_access`（自定义） | Linux Web 访问日志 | nginx/apache access.log 已配置采集与解析；不是 Zeek HTTP |
| `linux.application`（自定义） | 应用运行日志 | 显式配置的应用日志路径/服务；类别依业务语义判断，不能将所有未知日志随意投入 |

例如选 `zeek.ssh` 后：`event.module="zeek"`、`event.dataset="zeek.ssh"`，生产存储名为 `zeek.ssh-prod`。`（自定义）`、`-prod` 都不进入 event.dataset 的值。

### 8.3 event.type：行为子类（ECS 标准）

| 枚举值 | 含义 | 满足什么条件时选择 |
|---|---|---|
| `access` | 对对象的访问 | 文件打开、目录列举、Web 访问等访问行为；访问是否成功另看 outcome |
| `admin` | 管理类对象操作 | IAM 中不直接针对单个用户/组的管理对象变化，例如域信任配置；不是操作者为管理员就选 |
| `allowed` | 安全策略明确允许 | 防火墙/访问控制明确给出 allow/pass 决策；看到 TCP 建连成功不足以证明策略允许事件 |
| `change` | 修改已有对象 | 4738 属性修改、组成员变化、ACL/配置修改；新建和删除分别使用 creation/deletion |
| `connection` | 网络连接 | conn.log 的连接记录；可与 start/end/allowed/denied 等适用类型组合 |
| `creation` | 新建对象 | 4720 创建用户、4741 创建计算机账户、明确文件创建；进程启动在本项目使用 start |
| `deletion` | 删除对象 | 4726 删除用户、4743 删除计算机账户、文件删除；移除组成员通常为 change+group，不是删除组 |
| `denied` | 安全策略拒绝 | 明确防火墙/策略拦截；SELinux需结合permissive与实际结果判断，不能仅据denied文字认定已阻断 |
| `device` | 设备相关子类 | 有设备接入/移除等专门记录时使用；本期主表未使用，不因机器账户以 $ 结尾就选 |
| `end` | 活动结束 | 4634/4647、4689、PAM 会话结束、明确主机停止 |
| `error` | 错误信息 | 应用/系统明确错误记录；Windows 4625 是认证失败，不统一改成 error |
| `group` | 组对象相关 | 安全组或组成员操作；常与 change/creation/deletion 组合 |
| `indicator` | 威胁指标条目 | 导入 IOC 等情报指标本身；intel.log 匹配活动不等于原始 indicator 条目 |
| `info` | 信息性/无法再细分的活动 | 特权服务调用、协议诊断、资产观察等；有更明确 start/change 时优先准确分类 |
| `installation` | 安装软件包 | 包管理日志明确安装动作；被动看到软件版本不满足条件 |
| `protocol` | 协议事务/交换 | DNS、TLS、SSH、NTLM、RPC 等协议日志；不要求事务成功 |
| `start` | 活动开始或开始尝试 | 进程启动、登录/会话开始、登录尝试；4625 可用 start 且 outcome=failure，不能理解为一定建立会话 |
| `user` | 用户对象相关 | 用户创建、启停、密码管理；常与 creation/change/deletion 组合，不用于所有包含用户名的事件 |

合法 type 没有 `success`、`failure`、`unknown`、`login`；这些不应写入 event.type。例：添加组成员使用 `event.type=["change","group"]`，不是同时输出两份事件。依据：[ECS event.type](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-type)。

### 8.4 event.action：具体动作（值自定义）

以下为本项目可选动作字典，覆盖前版方案动作并补齐组管理分支，不代表最小实现必须生成全部动作。ECS 不规定这些字符串。动作描述“做了什么”，结果仍由 event.outcome 表达；`*-observed` 只表示观察到，不证明操作成功。

#### 8.4.1 认证、会话、身份管理及主机操作

| 枚举值（自定义） | 含义 | 满足什么条件时选择 |
|---|---|---|
| `logon-success` | 登录成功 | Windows 4624；不能因为拿到 Kerberos 票据或 SSH 建连就使用 |
| `logon-failure` | 登录失败 | Windows 4625 等明确登录失败记录；本表 Windows 专用规则使用 |
| `logon-attempt` | 登录尝试 | Linux sshd/PAM 的一次认证尝试记录；Accepted/Failed 决定 outcome，动作保持一致 |
| `logoff` | 登录会话注销 | Windows 4634 |
| `user-initiated-logoff` | 用户主动注销 | Windows 4647 |
| `explicit-credentials-use` | 显式凭据使用 | Windows 4648；不承诺远端认证结果 |
| `kerberos-tgt-request` | 请求 TGT | Windows 4768 |
| `kerberos-service-ticket-request` | 请求服务票据 | Windows 4769 |
| `kerberos-preauth-failure` | Kerberos 预认证失败 | Windows 4771；原因按实际 Status（本报告字段名）解释 |
| `ntlm-credential-validation` | NTLM 凭据验证 | Windows 4776；Status 决定结果 |
| `privilege-authentication` | su/sudo 权限相关认证检查 | Linux 认证记录明确针对 su/sudo，不是仅记录执行命令 |
| `audit-authentication` | 审计侧认证事件 | Linux USER_AUTH 等匹配的认证审计类型 |
| `session-start` | 会话开始 | Linux PAM session opened 或对应 USER_START |
| `session-end` | 会话结束 | Linux PAM session closed 或对应 USER_END |
| `user-create` | 创建用户 | Windows 4720 或明确 Linux 用户创建记录 |
| `user-enable` | 启用用户 | Windows 4722 或明确启用动作 |
| `user-disable` | 禁用用户 | Windows 4725 或明确禁用动作；禁用不等于临时锁定 |
| `user-delete` | 删除用户 | Windows 4726 或明确 Linux 用户删除记录 |
| `user-change` | 修改用户属性 | Windows 4738、Linux usermod 等属性修改；已有更具体密码/锁定动作时优先用具体值 |
| `user-lock` | 锁定账户 | Windows 4740 或明确 Linux 锁定记录；认证失败次数多不等于已发生锁定 |
| `user-unlock` | 解锁账户 | 明确解锁操作；不能从后续登录成功反推产生过解锁记录 |
| `user-password-change` | 修改用户密码 | Windows 4723 或明确 Linux passwd 自身改密；不保存密码值 |
| `user-password-reset` | 重置目标用户密码 | Windows 4724 或明确管理重置动作；操作人与目标分离 |
| `computer-account-create` | 创建计算机账户 | Windows 4741 |
| `computer-account-change` | 修改计算机账户 | Windows 4742 |
| `computer-account-delete` | 删除计算机账户 | Windows 4743 |
| `group-member-add` | 向组加入成员 | Windows 4728/4732/4756 或明确 Linux 组成员添加 |
| `group-member-remove` | 从组移除成员 | Windows 4729/4733/4757 或明确 Linux 组成员移除 |
| `group-create` | 创建组 | Linux 实际 groupadd 等记录；本报告 Windows 范围未包含组创建事件 |
| `group-change` | 修改组属性 | Linux 明确组属性修改；成员增删优先用 member-add/remove |
| `group-delete` | 删除组 | Linux 实际 groupdel 等记录；不是移除一个成员 |
| `account-operation` | 尚未细分的账号管理操作 | audit 类型明确属于账号管理但解析器不能可靠再细分；已能细分时使用具体 user/group 动作，并保留原 op |
| `sam-handle-request` | 请求 SAM 对象句柄 | 本报告 4661 对象确属 SAM；不自动表示读取密码或修改对象 |
| `directory-object-operation` | 操作目录服务对象 | Windows 4662；读/写等细节保留 AccessMask/Properties |
| `object-permissions-change` | 修改对象权限 | Windows 4670；category 还必须根据 ObjectType 选择 |
| `privileged-service-call` | 调用特权服务 | Windows 4673；不等于成功提升当前账号权限 |
| `process-start` | 进程创建 | Windows 4688 |
| `process-end` | 进程结束 | Windows 4689；进程退出码另存 process.exit_code |
| `process-exec` | 执行程序 | Linux execve/execveat 审计关联完成并可识别执行尝试；成败按 syscall 结果 |
| `sudo-command-request` | sudo 命令请求 | sudo 日志提供 COMMAND 等请求信息；不能直接当作已执行且正常退出 |
| `file-operation` | 文件操作 | Linux syscall+PATH/CWD 等足够判断操作对象，具体访问/修改/删除用 type 和原 syscall 区分 |
| `configuration-change` | 配置修改 | 审计证明确实对配置对象进行修改；只读访问不适用 |
| `audit-configuration-change` | 审计配置修改 | Linux 审计规则/审计设置变化记录 |
| `access-denied` | 访问被拒绝 | SELinux AVC 等明确拒绝判定；是否实际阻止还要看permissive与系统调用结果，保留原始证据 |
| `host-start` | 主机启动 | 明确 OS 启动记录，不是服务启动 |
| `host-stop` | 主机停止 | 明确关机/停止记录，不从日志中断推断 |
| `service-start` | 服务启动动作 | systemd 等明确服务启动事件；结果另看状态 |
| `service-stop` | 服务停止动作 | 明确服务停止事件 |
| `service-state` | 服务状态记录 | 仅状态信息，不能证明确切启动/停止动作 |
| `system-message` | 普通系统运行消息 | linux.system 中未匹配更具体动作的保留记录；不隐式认定为异常 |
| `package-install` | 安装软件包 | 包管理记录明确安装动作 |
| `package-upgrade` | 升级软件包 | 明确升级操作或可信的新旧版本变化记录 |
| `package-remove` | 卸载软件包 | 包管理记录明确删除/卸载动作 |
| `application-event` | 应用运行事件 | 已纳入采集的应用日志但尚无更具体业务动作；新增业务动作须登记字典，不能将整段消息作为 action |

#### 8.4.2 网络、协议、检测及探针操作

| 枚举值（自定义） | 含义 | 满足什么条件时选择 |
|---|---|---|
| `connection-observed` | 观察到连接记录 | Zeek conn.log，不保证认证或应用事务成功 |
| `dns-transaction` | DNS 事务 | Zeek dns.log，返回码保留在 dns.response_code |
| `ssh-session-observed` | 观察到 SSH 协议会话 | Zeek ssh.log，认证结果有值才映射 outcome |
| `rdp-session-observed` | 观察到 RDP 协议活动 | Zeek rdp.log，不代表建立了认证后的桌面会话 |
| `kerberos-exchange` | 网络侧 Kerberos 交换 | Zeek kerberos.log，与 Windows 票据事件区分来源 |
| `ntlm-exchange` | 网络侧 NTLM 交换 | Zeek ntlm.log |
| `http-request` | HTTP 请求 | Zeek HTTP 或主机 Web access 日志；不同来源用 dataset 区分，不能直接叠加为独立请求次数 |
| `tls-handshake` | TLS 握手活动 | Zeek ssl.log；完成握手不代表应用登录成功 |
| `certificate-observed` | 证书观察 | Zeek x509.log |
| `certificate-status-observed` | 证书状态观察 | Zeek ocsp.log，不将证书状态误作用户认证结果 |
| `network-file-observed` | 网络文件元信息观察 | Zeek files.log；不保证完整获取文件 |
| `smb-file-operation` | SMB 文件操作 | Zeek smb_files.log，原 action 决定具体 type |
| `smb-share-access` | SMB 共享访问/映射 | Zeek smb_mapping.log，不证明发生文件读取 |
| `rpc-call` | RPC 调用 | Zeek dce_rpc.log，接口/操作名称另保留 |
| `ftp-command` | FTP 命令交换 | Zeek ftp.log，命令及响应决定业务含义 |
| `smtp-transaction` | SMTP 事务 | Zeek smtp.log，不根据建立连接推定邮件已送达 |
| `dhcp-lease-observed` | DHCP 分配/租约活动观察 | Zeek dhcp.log；按原始报文/字段区分请求与确认，不能给请求虚构已生效租约 |
| `ntp-exchange` | NTP 交换 | Zeek ntp.log |
| `snmp-exchange` | SNMP 交换 | Zeek snmp.log |
| `quic-session-observed` | QUIC 会话观察 | 实际存在且结构匹配的 quic.log |
| `tunnel-observed` | 隧道观察 | Zeek tunnel.log，不等于恶意隧道检测 |
| `ldap-operation` | LDAP 操作 | Zeek ldap.log，绑定、搜索、修改按原始 opcode 再判断 |
| `ldap-search` | LDAP 查询 | Zeek ldap_search.log 或明确查询记录，不等于目录被修改 |
| `radius-authentication` | RADIUS 认证交换 | 当前 radius 数据集中的认证消息；非认证记录不能套用该动作，需先扩展规则 |
| `sip-transaction` | SIP 信令交换 | Zeek sip.log |
| `irc-message` | IRC 协议消息 | Zeek irc.log |
| `syslog-message-observed` | 网络侧 syslog 消息 | Zeek syslog.log，不替代主机本地事件的来源标识 |
| `protocol-anomaly-observed` | 协议异常观察 | Zeek weird.log，不自动表示攻击 |
| `zeek-notice` | Zeek 通知 | Zeek notice.log；note 类型决定是否为检测告警 |
| `intel-match` | 情报匹配 | Zeek intel.log 中实际匹配记录，而非仅加载 IOC 清单 |
| `signature-match` | 签名匹配 | Zeek signatures.log，签名用途决定是否按安全告警处理 |
| `software-observed` | 软件指纹观察 | Zeek software.log；不是 package-install |
| `host-observed` | 主机资产观察 | Zeek known_hosts.log；不是 host-start |
| `service-observed` | 服务资产观察 | Zeek known_services.log；不是 service-start |
| `sensor-stats` | 探针统计 | Zeek stats.log；kind=metric |
| `capture-loss-measured` | 丢包情况测量 | Zeek capture_loss.log；kind=metric，不代表登录失败 |
| `sensor-report` | 探针运行报告 | Zeek reporter.log；按实际等级保留错误说明 |
| `analyzer-report` | 分析器诊断 | 实际版本的 dpd.log/analyzer.log，保留原因和关联连接 |

### 8.5 event.kind：记录性质（ECS 标准）

| 枚举值 | 含义 | 满足什么条件时选择 |
|---|---|---|
| `event` | 普通活动记录 | 本表大多数 Windows、Linux、Zeek 原始行为日志的默认值 |
| `metric` | 数值测量记录 | stats/capture_loss 等以测量量为核心的记录；conn 有字节计数但整体仍是连接事件，不因此改成 metric |
| `alert` | 外部检测系统告警 | Zeek 明确检测告警等，且确由检测产生；不是根据 ERROR 字样直接指定，也不是用来伪造 Kibana 内部告警对象 |
| `pipeline_error` | 采集/清洗处理错误 | 处理链无法正常解析等失败路径；保留原文与错误说明，不把它认作来源业务认证失败 |
| `state` | 某时刻的状态快照 | 专门的状态采集记录；普通服务启动事件仍是 event，首版无须额外生成快照 |
| `enrichment` | 供其他事件补充上下文的数据 | 原始 IOC、上下文数据导入；实际 intel.log 匹配不是仅作 enrichment |
| `asset` | 专门的资产/实体清单 | 从资产/目录系统同步实体清单时才考虑；不是每条 AD 日志或 known_hosts 观察都强制选，需确认固定 ECS 版本支持 |
| `signal` | Elastic 内部检测信号 | 保留给相应内部机制，本项目采集器和自定义原始日志 Pipeline 不设置 |

依据：[ECS event.kind](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-kind)。

### 8.6 event.outcome：动作结果（ECS 标准）

| 枚举值 / 处理方式 | 含义 | 满足什么条件时选择 |
|---|---|---|
| `success` | 当前事件所描述动作成功 | 4624、明确审计成功、明确 Accepted、适用的 auth_success=true；成功范围仅限该事件描述的动作 |
| `failure` | 当前动作明确失败 | 4625/4771、明确认证失败、适用的 auth_success=false；连接断开/字段缺失/auth_attempts=0 不足以成立 |
| `unknown` | 动作有结果概念，但观察不到结果 | 只有请求、认证尝试但结果不可判定；不将未知纳入明确失败计数 |
| 省略字段（不是枚举值） | 结果语义不适用 | 探针指标、证书元信息等无成功失败概念的记录，不统一填 unknown |

从事件生产者视角判断结果。例如 4648 的凭据使用动作与目标服务器的登录结果不同；进程被成功创建也不代表业务任务执行成功。依据：[ECS event.outcome](https://www.elastic.co/docs/reference/ecs/ecs-allowed-values-event-outcome)。

### 8.7 event.module 与 namespace（项目约定）

| 字段 | 值 | 含义 | 选择条件 |
|---|---|---|---|
| `event.module` | `windows` | Windows 事件来源 | 本表 Windows Security 记录；与 windows.security 前缀一致 |
| `event.module` | `zeek` | Zeek 观测来源 | Zeek 生成的日志，即使探针运行在 Linux 上也不能改为 linux |
| `event.module` | `linux` | Linux 主机/应用来源 | 主机文件或审计采集；不是 Zeek 网络侧的 Linux 协议观察 |
| namespace | `prod` | 生产环境 | 当前生产写入目标，由部署配置指定 |
| namespace | `test` | 隔离测试环境 | 后续明确采用测试目标时使用；模拟事件不能仅因内容像攻击而自动转 test |
| namespace | `dev` | 开发环境 | 后续开发解析器/应用环境使用；不在生产中自动创建 |

namespace 值为项目建议，不是 ECS 封闭枚举；当前主表生产后缀仍为 prod。`event.module` 和 `event.dataset` 必须匹配，环境不能从成功/失败推断。

### 8.8 network.direction：网络方向（ECS 约定值）

| 枚举值 | 含义 | 选择条件 |
|---|---|---|
| `inbound` | 从边界外进入边界内 | Zeek 等网络观察视角，源在已配置边界外、目的在内 |
| `outbound` | 从边界内到边界外 | 源在内、目的在外 |
| `internal` | 边界内双方通信 | 源和目的都属于明确配置的内部网络 |
| `external` | 边界外双方通信 | 源和目的都在定义的内部网络之外，且探针确实观察到该流量 |
| `ingress` | 进入被监控主机 | 主机监控视角且可明确流量进入该主机；不要混用于 Zeek 的网络边界方向 |
| `egress` | 离开被监控主机 | 主机监控视角且可明确流量由该主机发出 |
| `unknown` | 方向不能确定 | 地址/网段/观测上下文不足；首版未启用方向富化时也可直接省略 |

内部网络必须显式配置，并考虑多网段、NAT、代理和观测点；RFC1918 私网地址不是“属于本企业”的充分条件。依据：[ECS Network 字段](https://www.elastic.co/docs/reference/ecs/ecs-network)。

### 8.9 其他字段不是统一的封闭枚举

| 字段 | 值的来源 / 例子 | 选择规则 |
|---|---|---|
| `event.code` | Windows 4624/4625 等；Linux 实际审计类型 | 原始事件代码按字符串保存；本期 Windows 支持范围为主表 32 个 ID，不是 ECS 官方只允许这 32 个值 |
| `event.provider` | Microsoft-Windows-Security-Auditing、sshd、sudo 等 | 原始提供者或可信采集上下文决定，不从 category 拼造 |
| `event.reason` | 状态解释、拒绝原因 | 原始明确原因或固定映射规则；没有证据时不填“密码错误” |
| `log.level` | info、warning、error 等来源级别 | ECS 没有要求所有产品共用同一组日志等级；若归一化需定义映射并保留原文，不能据此直接决定 outcome |
| `network.transport` | tcp、udp、icmp、ipv6-icmp 等 | 按实际协议归一化为小写；只有 UDP 时不能把它写成 quic |
| `network.protocol` | dns、http、ssh、rdp、tls、kerberos、ntlm 等 | 按识别出的应用层协议设定；不是封闭枚举，也不从端口号单独下结论 |
| `dns.question.type` / `dns.response_code` | A、AAAA、CNAME / NOERROR、NXDOMAIN 等 | 依 DNS 协议结果；不限定成示例里的几种 |
| `http.response.status_code` | 实际 HTTP 数字状态码 | 有响应才填写，缺失不补 0；4xx/5xx 的应用语义需独立定义 |
| `observer.type` | 本项目 Zeek 使用 sensor | 来自采集配置与设备角色；sensor 是项目选值，不是所有观测器唯一合法值 |
| `agent.type` | filebeat、winlogbeat 或实际采集器类型 | 由采集器事实提供，不能因日志内容是 Linux 就填 linux |
| `ecs.version` | 实际固定的 ECS 版本 | 与所用字段 schema 一致，不能取 ES/Beat 版本冒充 |
| `zeek.log_type`（自定义） | conn、dns、ssh、stats、capture_loss、reporter 等本表文件基本类型 | 来自采集配置；共享 zeek.sensor 时必须保留，不能靠可选 action 才能区分 |
| `linux.record_type`（自定义） | sshd_auth、pam_auth、su_auth、sudo_auth、pam_session_start、pam_session_end、account_management、group_management、sudo_command、audit_auth、audit_session_start、audit_session_end、audit_iam、audit_exec、audit_file、audit_configuration、audit_rules、audit_avc、host_start、host_stop、service_lifecycle、system_message、package_change、web_access、application | 由第 6 节已匹配模板/审计语义生成，未识别类型保留原文并进入明确的未知模板处理，不伪装已解析 |
| `linux.operation`（自定义） | create、change、delete、group_create、group_delete、group_change、member_add、member_remove、password_change、password_reset、lock、unlock、command_request、start、stop、state、install、upgrade、remove | 与 record_type 共同确定动作；无可靠动作证据省略。应用新增动作须登记，不保存整段正文作操作名 |
| `auditd.assembly_status`（自定义） | complete、incomplete、late | 完整组装/不完整/完成后的迟到记录；只有 complete 进入按一次系统调用计数的基线 |

### 8.10 组合选择示例与冲突规则

| 原始证据 | category | module.dataset（自定义） | type | action（自定义） | outcome |
|---|---|---|---|---|---|
| Windows 4625 登录失败 | [authentication] | windows.security | [start] | logon-failure | failure |
| Windows 4728 成功向组添加成员 | [iam] | windows.security | [change,group] | group-member-add | success |
| Windows 4670、ObjectType=File、审计成功 | [file] | windows.security | [change] | object-permissions-change | success |
| Zeek ssh.log，无法判断认证结果 | [network] | zeek.ssh | [protocol] | ssh-session-observed | 省略；若规则明确表达认证尝试但结果不明可用 unknown |
| Zeek ssh.log，auth_success=false | [network,authentication] | zeek.ssh | [protocol] | ssh-session-observed | failure（Zeek 推断，不当作端点权威审计） |
| Zeek capture_loss.log | 省略 | zeek.sensor | [info] | capture-loss-measured | 省略；kind=metric |
| Linux PAM session closed | [session] | linux.auth | [end] | session-end | 按来源，关闭不代表认证失败 |

表中数组为便于阅读的简写，实际 JSON 使用带引号字符串数组。组合约束：

1. **先认来源定 dataset，再按事件 ID/操作/对象判 category、type 和 action，最后独立判 outcome。** 展示顺序“来源→category→dataset”不意味着分类字段可以随意控制存储路由。
2. 主表某格出现 `start/end`、`file / registry / iam` 或多个动作时，是条件分支说明，不是可直接写入的字符串。
3. “多 category”仅用于同一记录真实具有多种语义；“多 type”如 change+group 是行为与对象子类组合。不能为了查全而给所有事件添加全部类别。
4. category/type 不能自行增加新值；dataset/action 如需扩展，先登记本字典并增加样本测试，再改变解析规则，避免同一动作产生多种拼写。
5. 当前文档中的枚举是设计契约，不代表对应日志已入库，也不会因新增枚举条目自动创建索引或启用采集。
