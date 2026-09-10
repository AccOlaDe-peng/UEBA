# 本地 UEBA 检测详解与实现(SPL)

> 调研对象:Splunk ES 8.6 管理手册「UEBA detection reference for UEBA on-premises」及配套机制页(8.6/8.7)
> 调研日期:2026-09-09
> 上游文档:01-UEBA检测与数据源.md(119 条清单与分类)

## 0. 重要结论:官方文档不公开 SPL

经逐版核实(ES 8.6 / 8.7 help.splunk.com),**官方「UEBA detection reference for UEBA on-premises」页面只有 119 个检测名的扁平字母序列表,没有提供任何检测描述或 SPL**。此前搜索结果显示"including SPL"是对页面的误判。SPL 实际存放于本地部署的 UEBA Content App 内部的 `savedsearches.conf`(随应用分发,Content Management 中只读、不可编辑)。

因此本文第 2 节采用如下结构:**每个检测族先给出官方披露的机制(来自 sourcetype 映射页、知识对象页、UEBA System 仪表盘页),族内每条检测给出按命名语义 + 族机制的判定逻辑推断,全部标注【推断】**。判定逻辑只能保证"检测什么"准确,"怎么算异常"的具体阈值/窗口是推断。

---

## 1. 实现机制总览(官方披露)

### 1.1 知识对象结构(来源:8.7「Roles and knowledge objects in UEBA」)

UEBA Content App(on-prem)中,每个 `UEBA - <检测名> - Rule` 背后是一组协同的知识对象:

| 知识对象 | 在 UEBA 中的作用 |
| --- | --- |
| Saved searches | 不仅包含检测规则本身,还包含配套的 **summarization(摘要)、consolidation(合并)、feature(特征计算)、scoring(打分)** 保存搜索——即"检测规则 = 特征提取 → 基线累积 → 打分/比较 → 产出 finding"的多级搜索流水线 |
| KV Store collections | 持久保存 **feature values(特征值/基线)**、related identities(关联身份)、related assets(关联资产) |
| Search macros | 封装 **数据映射(CIM 字段适配)、字段值转换、特征计算、事件打分** 逻辑 |
| Transforms | 让 KV Store 集合可被 SPL 查询(external lookup 形式回读基线) |
| Views | UEBA 仪表板(含仅本地版的 `ueba_system` 仪表板) |

这意味着典型实现范式是:
1. **feature 搜索**按时间窗(通常当日/过去 24h)从 CIM 数据模型聚合出每实体特征值,写入 KV Store;
2. KV Store 累积历史基线(身份/资产框架补充 Company/Business Unit 归属);
3. **scoring 搜索**将当前特征值与"个体基线"或"同组(peer group)分布"比较,给出 rarity/异常分;
4. **检测 Rule 搜索**在分值越过阈值(或稀有特征计数足够)时输出 intermediate finding 到 `risk` 索引;
5. finding 汇入 ERS(实体风险分),可被 finding exclusion 过滤。

### 1.2 数据源与 CIM 数据模型映射(来源:8.6「Required sourcetypes for UEBA detections」)

官方明确:本地 UEBA 的已验证 sourcetype 对齐以下 **CIM 数据模型**:

- **Authentication**(认证登录类 34 条)
- **Network_Traffic**(网络流量/数据传输类 34 条、HTTP 代理类、USB 部分类)
- **Web**(HTTP / Web 代理访问异常 4 条)
- **Change**(账号管理/日志篡改、USB 文件操作类)
- **Endpoint**(主机失陷关联、Windows 登录过程类)
- **Email**(邮件外发与 DLP 类 7 条)

本地版已验证 sourcetype 清单(全部标注 CIM 对齐):

| Sourcetype | 厂商 | 推荐 TA | 关键事件码 | 必须? |
| --- | --- | --- | --- | --- |
| XmlWinEventLog:Security / WinEventLog:Security | Windows | TA-Windows | 4624, 4625, 4720–4729, 4756–4757 | 否 |
| WinEventLog(/Xml):Microsoft-Windows-PrintService/Operational、/Admin | Windows 打印服务 | TA-Windows | EventCode=307(打印作业) | 否 |
| auditd | Linux Audit Daemon | TA-nix | 登录、提权等可疑活动 | 否 |
| cloudtrail | AWS CloudTrail | TA-AWS | API 访问、认证、IAM 变更 | 否 |
| suricata | Suricata IDS/IPS | Suricata TA(社区) | 出站流量、阻断流量、IDS 告警 | 否 |
| symantec:ep:behavior:file | Symantec Endpoint Protection | Symantec EP TA | 文件读/写/放行/阻断行为 | **是** |
| gws:gmail | Google Workspace Gmail | Google Workspace TA | 外发邮件事件 | 否 |

Windows 事件码 ↔ 检测族对应(推断自事件码语义):4624/4625 → 成功/失败登录(Unusual/Rare Login、Brute Force);4720–4729 → 账号创建/管理(Short Lived Accounts、Password Policy Circumvention);4756–4757 → 通用/安全组成员变更(Member Added Removed In Short Span);1102 → Windows Event Log Cleared;打印 307 → 全部打印类检测。

### 1.3 判定机制的关键参数(来源:8.6「Auditing UEBA with dashboards」)

UEBA System 仪表板(`(instance)/en-US/app/SplunkEnterpriseSecuritySuite/ueba_system`,仅本地、仅 Premier)直接披露了两族检测的内部机制:

- **Rare Device\* 系列(feature rarity 模型)**:模型对登录活动的多个特征(feature)打分,**分数越低越稀有**;**feature score < 0.002 即判定为稀有**(仪表板中标红);`behavior_rarity` 字段 = 该事件命中的稀有特征计数;高分不必然产生 finding——系统还有额外减误报逻辑。
- **Unusual Volume of \* 系列(个体基线模型)**:每行 = 一个用户 × 被跟踪特征;仪表板同时显示**特征计算值**与**阈值(individual baseline,个体基线)**;**特征值超过个体基线阈值 → 视为潜在风险 finding**。即该系列是"与该用户/设备自身历史对比",而非与全局分布对比。
- `by Company` / `by Business Unit` 变体:比较对象从"个体自身基线"扩展到"同公司/同业务单元的同伴组分布"(【推断】,机制页未展开,但命名与 Rare/Unusual 双系列结构一致)。

### 1.4 与本次调研的边界

- 本地 UEBA 检测只读:不可编辑 SPL,只能用 finding exclusions 调整产出。
- findings 写 `risk`(生产)或 `ba_test`(测试)索引,`source` 字段 = 检测名(`UEBA - ... - Rule`)。
- 不支持 CIM entity zones。

---

## 2. 按分类逐条详解(8 个分类,119 条)

> 格式说明:官方未提供任何描述/SPL,以下"判定逻辑"均为【推断】,基于:检测名语义 + 所属检测族的官方机制(第 1 节)+ sourcetype/事件码映射。同族同构的检测给出一条,后用"同上变体"简要注明差异维度。

### 2.1 网络流量与数据传输异常(34 条)

**族机制(官方)**:数据模型 Network_Traffic;主要 sourcetype:suricata(出站/阻断流量);判定方式:Unusual Volume 系列 = 当前窗口特征值 > 个体基线阈值;`by Company/Business Unit` = 与同伴组比较【推断】。

- #### UEBA - Unusual Volume of Outgoing Connections per Device by Company
  - 判定逻辑【推断】:统计设备(Asset,Network_Traffic 模型 src)在窗口内外连方向连接数,若超过该设备个体基线且在同类设备(同 Company)同伴组中异常突出,产生 finding。
  - SPL:未公开。
- #### UEBA - Unusual Volume of Outgoing Connections per Device by Business Unit
  - 判定逻辑【推断】:同上,同伴组改为同 Business Unit。
- #### UEBA - Unusual Volume of Outgoing Connections per Device
  - 判定逻辑【推断】:同上,仅与设备自身历史基线比较。
- #### UEBA - Unusual Volume of Outgoing Connections Per User By Company / By Business Unit / Per User
  - 判定逻辑【推断】:同上三变体,实体从 Device 换为 User(经身份/资产框架映射到人)。
- #### UEBA - Unusual Volume of Data Uploaded per User by Company / per User
  - 判定逻辑【推断】:对 Network_Traffic 的 bytes_out(上传字节)按用户聚合,超过个体基线/同公司同伴组阈值即告警——外传数据量异常,潜在数据渗出。
- #### UEBA - Unusual Volume of Data Uploaded per Device by Company / by Business Unit / per Device
  - 判定逻辑【推断】:同上,实体为设备。三变体差异仅比较范围(同伴组 Company / BU / 个体)。
- #### UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User By Company / By Business Unit / Per User
  - 判定逻辑【推断】:限定目标 dest 为 DMZ 区设备(资产框架 zone/类别)的上传字节量异常;用户向 DMZ 大量传数据是横向渗透/数据落地的信号。
- #### UEBA - Unusual Volume of Data Downloaded per User by Company / per User
  - 判定逻辑【推断】:下载字节量(bytes_in)按用户聚合超过个体基线/同伴组——潜在批量取数(内部数据窃取)。
- #### UEBA - Unusual Volume of Data Downloaded per Device by Company / by Business Unit / per Device
  - 判定逻辑【推断】:同上,实体为设备。
- #### UEBA - Unusual Volume of Data Bytes per Device by Company / by Business Unit / per Device
  - 判定逻辑【推断】:不区分方向的总字节数(uploaded+downloaded)按设备聚合超基线。
- #### UEBA - Unusual Volume of Blocked Connections per Device by Company / by Business Unit / per Device
  - 判定逻辑【推断】:被防火墙/IDS 阻断(action=blocked)的连接次数按设备聚合超基线——设备被攻陷后反复尝试外连的信号。数据源 suricata(阻断流量)。
- #### UEBA - Unusual Volume Of Data Uploaded Per User By Business Unit
  - 判定逻辑【推断】:"Of/Per"大写变体,与 `Unusual Volume of Data Uploaded per User by Business Unit` 语义相同(疑似不同批次发布的内容副本)。
- #### UEBA - Unusual Volume Of Data Downloaded Per User By Business Unit
  - 判定逻辑【推断】:同上,下载方向。
- #### UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User By Company / By Business Unit / Per User
  - 判定逻辑【推断】:限定源 dest 为内部服务器的下载量按用户聚合超基线——内部服务器批量拉数据。
- #### UEBA - Unusual Volume Of Blocked Connections Per User By Company / By Business Unit / Per User
  - 判定逻辑【推断】:阻断连接数按用户(而非设备)聚合超基线。
- #### UEBA - Unauthorized Activity Time
  - 判定逻辑【推断】:检测用户/设备在"非授权时段"(工作时间外)发生活动;属于 Unusual Time 范式——对活动时间分布建模,偏离正常时段即告警。族内唯一的"时间"类网络检测。

### 2.2 认证与登录行为异常(34 条)

**族机制(官方)**:数据模型 Authentication;sourcetype:WinEventLog(:Security) EventCode 4624(成功)/4625(失败);判定方式分三派:①Unusual Volume = 计数超个体基线;②Rare 系列 = feature rarity 模型,feature score < 0.002 判稀有,`behavior_rarity` 累计稀有特征数,再经减误报逻辑输出;③Brute Force = 失败次数阈值 + 成功转换。

- #### UEBA - Unusual Volume Success Logins To Computer By Company / By Business Unit / (无后缀)
  - 判定逻辑【推断】:目标主机(Computer,dest)上的成功登录(4624)次数,对比该主机个体基线/同公司、同 BU 主机同伴组;主机被大量登录(如横向移动落点)时触发。
- #### UEBA - Unusual Volume Success Login Per User by Company / by Business Unit / Per User
  - 判定逻辑【推断】:用户成功登录次数(跨所有主机)超个体基线/同伴组——账号被多点并发使用、被滥用的信号。
- #### UEBA - Unusual Volume Login Type Per User by Company / by Business Unit / Per User
  - 判定逻辑【推断】:按"登录类型"(logon_type:2 交互、3 网络、10 远程交互/RDP 等)分别计数,用户使用某登录类型的频次超基线——如突然大量 RDP(类型 10)。
- #### UEBA - Unusual Unlock Time Per User By Company / Per User
  - 判定逻辑【推断】:屏幕解锁(4800/4801 或会话解锁事件)的时间点建模,解锁发生在该用户历史未出现的时间段即告警;By Company 变体叠加同伴组时间分布对比。
- #### UEBA - Unusual Login Time Per User By Company / Per User
  - 判定逻辑【推断】:登录时间点偏离用户个体基线(如深夜首次登录);经典 Unusual Time 范式,常用于失陷账号发现。
- #### UEBA - Unauthorized Machine Login
  - 判定逻辑【推断】:用户登录到其历史从未/几乎未登录过的机器(用户×设备对稀有),或登录到资产框架标记为非授权的机器。属于 Rare(用户,设备)组合范式。
- #### UEBA - Unauthorized Login Type
  - 判定逻辑【推断】:用户使用了其历史基线中未出现过的登录类型(如一直交互登录的账号突然远程交互)。
- #### UEBA - Rare Windows User Login By Device
  - 判定逻辑【推断】:Rare 系列feature rarity:从设备视角,登录该设备的"用户"特征稀有(score<0.002 量级);陌生用户登录此设备。
- #### UEBA - Rare Windows Logon Type By User / By Device
  - 判定逻辑【推断】:登录类型特征对用户/设备分别做稀有度打分——用户/设备出现历史上极罕见的 logon_type。
- #### UEBA - Rare Windows Logon Process By User And Device / By User / By Device
  - 判定逻辑【推断】:登录所用的认证进程(initpkg: ksecdd、svchost、lsass 或 RDP 的 termdd 相关调用方)作为特征,用户×设备 / 用户 / 设备维度上出现稀有登录进程——pass-the-hash/离线伪造登录常用异常认证路径。
- #### UEBA - Rare Windows Domain Login By User
  - 判定逻辑【推断】:用户登录的"域"特征稀有——账号跨域登录、或登录到其不属于的域。
- #### UEBA - Rare Login Return Code By Windows User / By Device
  - 判定逻辑【推断】:登录结果码(4625 的 Sub Status:0xC0000064 用户不存在、0xC000006A 密码错误等)对用户/设备出现稀有取值——侦察式登录尝试、异常失败原因。
- #### UEBA - Rare Device Login By Windows User
  - 判定逻辑【推断】:用户视角,登录目标设备特征稀有——该用户首次/极罕见地登录某台设备(与 Unauthorized Machine Login 互补的 rarity 实现)。
- #### UEBA - Brute Force Access Logon Type Per User by Company / by Business Unit / Per User
  - 判定逻辑【推断】:按登录类型统计的失败登录(4625)次数超阈值;by Company/BU 变体在同组内比较失败密度——低慢爆破在同伴组对比下更易暴露。
- #### UEBA - Brute Force Access Behavior Per User by Company / by Business Unit / Per User
  - 判定逻辑【推断】:不区分登录类型的爆破行为模型:窗口内失败次数显著超基线(或失败后成功转换)即触发,实体为用户。
- #### UEBA - Brute Force Access Behavior Per Device By Company / By Business Unit / Per Device
  - 判定逻辑【推断】:同上,实体为目标设备(针对单台主机的口令喷洒/爆破)。

### 2.3 打印行为异常(24 条)

**族机制(官方)**:数据源 Windows PrintService(EventCode=307,WinEventLog/XmlWinEventLog 的 Operational 与 Admin 通道);CIM 对齐 Endpoint/Change【推断】;判定方式全部为 Unusual Volume(特征值 > 个体基线)与 Unusual Time(打印时间偏离基线)。特征维度:打印作业数(Print)、传输字节(Data Transmitted to Printer);实体维度:User / Device / Printer;范围维度:Company / Business Unit / 无。

- #### UEBA - Unusual Volume of Print per Device by Business Unit
  - 判定逻辑【推断】:设备打印作业数超该设备基线/同 BU 同伴组。
- #### UEBA - Unusual Volume of Data Transmitted to Printer per Device by Business Unit
  - 判定逻辑【推断】:设备发送到打印机的字节量超基线——大批量打印(泄密打印的常见形态)。
- #### UEBA - Unusual Volume of Print Per User By Business Unit- Rule
  - 判定逻辑【推断】:用户打印作业数超个体基线/同 BU 同伴组。
- #### UEBA - Unusual Volume of Data Transmitted To Printer Per User By Business Unit- Rule
  - 判定逻辑【推断】:用户打印字节量超基线/同 BU。
- #### UEBA - Unusual Volume of Print per Printer by Business Unit- Rule
  - 判定逻辑【推断】:单台打印机接收的作业数超其基线/同 BU 打印机同伴组——异常汇聚点(有人把敏感文件集中到某台偏远打印机打印)。
- #### UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Business Unit- Rule
  - 判定逻辑【推断】:打印机接收字节量超基线/同 BU。
- #### UEBA - Unusual Volume of Print per User by Company / per User
  - 判定逻辑【推断】:同 Print Per User By BU,比较范围为同公司同伴组 / 仅个体基线。
- #### UEBA - Unusual Volume of Print per Printer by Company / per Printer
  - 判定逻辑【推断】:同 Print per Printer By BU,比较范围为公司同伴组 / 个体。
- #### UEBA - Unusual Volume of Print per Device by Company / per Device
  - 判定逻辑【推断】:同 per Device By BU,比较范围为公司同伴组 / 个体。
- #### UEBA - Unusual Volume of Print at Unusual Time per User by Company / per Printer by Company / per Device by Company
  - 判定逻辑【推断】:双条件组合(AND):打印量超基线 **且** 打印时间偏离该实体(用户/打印机/设备)的历史时间分布——工作时间外的批量打印是内部泄密最强信号之一。
- #### UEBA - Unusual Volume of Data Transmitted to Printer per User by Company / per User
  - 判定逻辑【推断】:用户打印字节量,公司同伴组 / 个体基线。
- #### UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Company / per Printer
  - 判定逻辑【推断】:打印机字节量,公司同伴组 / 个体。
- #### UEBA - Unusual Volume of Data Transmitted to Printer per Device by Company / per Device
  - 判定逻辑【推断】:设备打印字节量,公司同伴组 / 个体。
- #### UEBA - Unusual Print Time per User / per Printer / per Device
  - 判定逻辑【推断】:纯 Unusual Time:打印行为的时间点偏离该用户/打印机/设备的历史时间分布(如深夜、周末首次出现打印)。

### 2.4 USB 外设行为异常(8 条)

**族机制(官方)**:sourcetype:symantec:ep:behavior:file(唯一标记 Required=Yes 的 sourcetype);CIM 对齐 Change(文件操作)/Endpoint;判定方式全部为 Unusual Volume;实体固定为 User,范围维度 Company/无。"By Company"在 8 条中全部存在,说明 USB 检测强依赖同伴组对比。

- #### UEBA - Unusual Volume Of USB Denies Per User By Company / Per User
  - 判定逻辑【推断】:USB 设备被策略阻断(deny)的次数按用户聚合超基线/同公司同伴组——用户反复尝试使用被禁 USB,动机异常信号。
- #### UEBA - Unusual Volume Of File Operations To USB Per User By Company / Per User
  - 判定逻辑【推断】:针对 USB 的文件操作(复制/写入/移动)次数超基线——批量拷贝文件到 U 盘。
- #### UEBA - Unusual Volume Of Bytes Written To USB Per User By Company / Per User
  - 判定逻辑【推断】:写入 USB 的字节数超基线——大容量外拷(数据窃取直接指标)。
- #### UEBA - Unusual Volume Of Bytes Read From USB Per User By Company / Per User
  - 判定逻辑【推断】:从 USB 读取字节数超基线——大容量导入(可执行文件/数据投放)。

### 2.5 邮件外发与 DLP 异常(7 条)

**族机制(官方)**:数据模型 Email;sourcetype:gws:gmail(外发邮件)、o365(本地版参考清单之外【推断】,DLP 两条为 O365);这几条命名无 Rare/Unusual Volume 前缀,属于**确定性规则 + 少量统计**(条件匹配式),而非基线模型。

- #### UEBA - Email over 5 MB Sent to Personal Email
  - 判定逻辑【推断】:发给个人邮箱(webmail 收件人列表匹配)且附件/邮件体积 > 5MB 的外发——固定阈值规则。
- #### UEBA - Email Sent to Personal Email with Privacy Keywords
  - 判定逻辑【推断】:发往个人邮箱且正文/主题命中隐私关键词(如 PII、confidential、内部项目名等词表)。
- #### UEBA - Email Sent to Personal Email with Attachment
  - 判定逻辑【推断】:发往个人邮箱且带附件——数据外发基础规则。
- #### UEBA - Email Sent to Personal Email Using Same Alias
  - 判定逻辑【推断】:发件人使用与收件个人邮箱相同/相似的别名(self-forwarding:发给自己个人邮箱),规避监控的典型手法。
- #### UEBA - Email Sent to Disposable Email Provider
  - 判定逻辑【推断】:收件域命中一次性邮箱服务商域名表(10minutemail 等)——毁证型外发。
- #### UEBA - Large Office 365 Message Flagged by DLP Policy
  - 判定逻辑【推断】:O365 消息被 DLP 策略命中且体积超过阈值的组合条件。
- #### UEBA - Office 365 DLP Policy Violations Allowed
  - 判定逻辑【推断】:O365 DLP 违规且处理动作为"允许发送"(override/allow)的事件——策略被人绕过而非被阻断。

### 2.6 账号管理与日志篡改异常(5 条)

**族机制(官方)**:数据源 WinEventLog(:Security),CIM 对齐 Change/Authentication;确定性规则为主(短时间窗内的状态翻转 / 单事件)。

- #### UEBA - Windows Event Log Cleared
  - 判定逻辑【推断】:EventCode 1102(安全日志被清除)单事件规则——日志擦除即告警,攻陷强指标。
- #### UEBA - Short Lived Windows Accounts
  - 判定逻辑【推断】:账户创建(4720)后极短时间窗内即被删除/禁用(4722/4726 等)的"短命账号"——攻击者建临时后门账号再销毁。
- #### UEBA - Password Policy Circumvention
  - 判定逻辑【推断】:绕过密码策略的事件(如 4724 重置后未按策略更改、或权限内批量重置他人密码的模式)——对应 Account Management 事件族。
- #### UEBA - Member Added Removed In Short Span Universal Groups
  - 判定逻辑【推断】:Universal 组(4756 添加成员 / 4757 移除成员)在短时间窗内"加了又删"——权限提权后清理痕迹。
- #### UEBA - Member Added Removed In Short Span Global Groups
  - 判定逻辑【推断】:同上,Global 组(4728 添加 / 4729 移除)。

### 2.7 HTTP / Web 代理访问异常(4 条)

**族机制(官方)**:数据模型 Web;命名 Http 前缀,围绕代理日志中的站点类别/域名/传输量。判定方式为类别表匹配 + 量/频率基线组合【推断】。

- #### UEBA - Http Unusual Traffic to Anonymizing Sites
  - 判定逻辑【推断】:访问匿名化站点(代理/Tor/VPN 网关类别表)的流量超基线或出现在从未访问的用户上——规避审计行为。
- #### UEBA - Http Unusual Job Search Activity
  - 判定逻辑【推断】:访问求职/招聘类站点的活动超个体基线——离职倾向信号(内部威胁项目的经典用例)。
- #### UEBA - Http Suspicious Domain File Download
  - 判定逻辑【推断】:从可疑域名(威胁情报/类别表命中)下载文件——恶意载荷投递通道。
- #### UEBA - Http Excessive Transfer to Storage Site
  - 判定逻辑【推断】:向云存储/网盘站点上传流量超阈值——经授权网盘的数据渗出。

### 2.8 主机失陷关联检测(3 条)

**族机制(官方)**:命名 Correlation——多条低阶信号聚合成高阶中间 finding(consolidation 保存搜索的典型用途,见 1.1 节知识对象流水线);数据源:Windows 事件(Endpoint)、auditd(Linux)、cloudtrail(AWS)。

- #### UEBA - Compromised Windows Host Correlation
  - 判定逻辑【推断】:将同一 Windows 主机上的多个 UEBA findings(登录稀有 + 爆破 + 数据外传等)在时间窗内关联,聚合为"主机疑似失陷"的复合 finding——即 consolidation 搜索,关联的是其他 UEBA 检测的产出而非原始日志。
- #### UEBA - Compromised Linux Host Correlation
  - 判定逻辑【推断】:同上,信号源为 auditd 登录/提权类异常。
- #### UEBA - AWS Compromised Account
  - 判定逻辑【推断】:关联 cloudtrail 中的异常 API 访问、异常认证、IAM 变更等信号,聚合判定云账号失陷。

---

## 3. 通用模式总结

1. **Rare 系列**(Rare Windows Login/Logon Type/Logon Process/Domain/Return Code/Device Login,Unauthorized Machine/Login Type):feature rarity 模型。把事件拆成多个离散特征(用户、设备、登录类型、认证进程、结果码、域名等),在 KV Store 累积各特征的历史分布;当前事件的特征在分布中过稀有(feature score < 0.002)则计入 `behavior_rarity`(稀有特征计数),计数达标并经过减误报逻辑后输出 finding。变体维度 = 特征的组合方式(By User / By Device / By User And Device)。
2. **Unusual Volume 系列**(网络流量、打印、USB、成功登录计数等约 80 条):同一模板的三层参数化——①特征(连接数/上传字节/下载字节/总字节/阻断数/打印数/打印字节/USB 读写字节/文件操作数/deny 数);②实体(User/Device/Printer);③比较范围(个体基线 / 同 Company 同伴组 / 同 Business Unit 同伴组)。官方仪表盘证实:比较对象就是"特征计算值 vs individual baseline 阈值"。约 110 条检测 ≈ 十几个基础特征 × 2~3 实体 × 3 比较范围的展开。
3. **Unusual Time 系列**(Unusual Login/Unlock/Print Time、Unauthorized Activity Time、Print at Unusual Time):对实体活动的小时/星期分布建模,当前活动时间落入历史分布的低概率区间即告警;"Volume at Unusual Time"是量阈值与时间模型的 AND 组合。
4. **Brute Force 系列**(9 条):窗口内失败登录(4625)计数超阈值;按实体(User/Device)、按登录类型细分、按比较范围(个体/Company/BU)展开参数化。
5. **确定性规则系列**(Email/DLP 7 条 + 账号管理 5 条 + HTTP 4 条):词表/域名表/事件码匹配为主,个别叠加体积或频率阈值;无需基线。
6. **Correlation 系列**(3 条):consolidation 保存搜索,把同实体在时间窗内的多个 UEBA findings 聚合成一个高阶失陷判定。
7. **公共流水线**:feature 搜索(CIM 模型 → 特征值)→ KV Store 基线 → scoring 搜索(打分/比较,宏封装)→ Rule 搜索(输出 finding 至 risk/ba_test)→ ERS 实体风险分。宏封装数据映射/转换/特征/打分;transform 把 KV Store 以 lookup 形式回给 SPL。

## 4. 来源 URL

- 检测参考清单(119 条,仅名称):https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/ueba-detection-reference-for-ueba-on-premises
- sourcetype ↔ CIM 映射:https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections
- UEBA 仪表盘审计(Rare 0.002 阈值、个体基线、ueba_system):https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/user-and-entity-behavior-analytics/auditing-ueba-with-dashboards-in-splunk-enterprise-security
- 知识对象/角色(保存搜索分级、KV Store、宏):https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/user-and-entity-behavior-analytics/ueba-content-app-for-on-premises/roles-and-knowledge-objects-in-ueba-for-splunk-enterprise-security
- 机制背景沿用:01-UEBA检测与数据源.md(UEBA overview、finding/risk index 机制)
