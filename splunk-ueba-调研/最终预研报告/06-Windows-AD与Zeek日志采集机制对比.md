# Windows AD 与 Zeek 日志采集机制对比

## 1. 结论先行

采集 Windows AD 日志时，Splunk Universal Forwarder（UF）通常部署在域控制器或 Windows Event Collector（WEC）服务器上。UF 通过 Windows Event Log 输入订阅事件日志通道，读取新产生的事件，保存采集检查点，再将事件发送到 Splunk Indexer。

这与 Zeek 采集的核心差异是：

- Windows AD 安全审计使用 `WinEventLog://` 模块化输入，通过 Windows Event Log API 读取事件通道；
- Zeek 使用 `monitor://` 文件输入，跟踪 `conn.log`、`dns.log` 等文件的增长与轮转；
- 两者后续都会添加 `host`、`source`、`sourcetype` 等元数据，经 `outputs.conf` 发往 Indexer，再由对应 Add-on 完成字段标准化和 CIM 映射；
- AD 事件日志、AD 目录对象变化和 AD 健康状态是三类不同数据，不能只启用 Security 日志后就认为已采全 AD 数据。

## 2. Windows AD 有哪些不同的数据来源

| 数据类型 | 典型内容 | UF 输入方式 | 主要用途 |
|---|---|---|---|
| Security 事件日志 | 登录、注销、账号创建、组成员变化、权限使用、目录对象访问 | `WinEventLog://Security` | 认证分析、账号与权限变更、攻击行为调查 |
| Directory Service 日志 | AD DS 服务、数据库和目录服务运行事件 | `WinEventLog://Directory Service` | AD 服务运行和故障分析 |
| System / Application | 服务启动、系统错误及应用事件 | `WinEventLog://System`、`Application` | 主机和服务上下文 |
| ForwardedEvents | WEF 从多台 Windows 主机集中转来的事件 | `WinEventLog://ForwardedEvents` | 集中式 Windows 审计采集 |
| AD 对象监控 | 用户、组、计算机等目录对象及其变化 | `admon://<name>` | 资产身份画像、目录对象当前状态和变更 |
| AD 健康与复制 | 复制状态、站点、拓扑和健康信息 | TA-Windows 脚本或 PowerShell 输入 | AD 运维健康监控 |
| Netlogon、DNS、DHCP 文件 | 域认证诊断、DNS/DHCP 服务日志 | `monitor://` 或专用输入 | 补充基础设施上下文 |

Security 日志记录的是“发生过什么审计事件”。`admon://` 面向目录对象状态和变化。二者可以互补，但数据语义、权限和采集机制不同。

## 3. 直接在域控制器安装 UF 时如何工作

```text
域用户、计算机及攻击者操作
              │
              ▼
   Windows 审计策略生成事件
              │
              ▼
 Windows Event Log Service
   Security / System / Directory Service
              │ 本机 Event Log API
              ▼
 Universal Forwarder + Splunk_TA_windows
   订阅通道 → 过滤 → XML 渲染 → 检查点
              │ Splunk 转发协议
              ▼
        Indexer / Indexer Cluster
   解析、索引、字段提取与保存原始事件
              │
              ▼
 Search Head / ES / UEBA
   CIM → 检测 → 风险 → 调查
```

### 3.1 Windows 先负责产生事件

UF 不会自动让 Windows 生成所有安全事件。域控制器必须启用相应的高级审核策略；部分目录访问事件还依赖对象上的 SACL。若 Windows 没有生成某类事件，Forwarder 无法补出该事件。

例如，UEBA 常用事件可能包括：

| 行为 | 常见事件 ID 示例 |
|---|---|
| 登录成功、失败、注销 | 4624、4625、4634 |
| 使用显式凭据、特殊权限登录 | 4648、4672 |
| 新进程创建 | 4688 |
| 用户账号创建、启停或修改 | 4720、4722～4726、4738 |
| 全局组成员变化 | 4728、4729 |
| 本地域组成员变化 | 4732、4733 |
| 通用组成员变化 | 4756、4757 |
| 目录对象访问 | 4661、4662 |
| 安全审计日志被清除 | 1102 |

事件 ID 只能说明事件类别，具体行为还要结合 Subject、Target、Logon ID、源地址、工作站、组 SID、对象 DN 和结果字段解释。不同 Windows 版本、审计策略和事件提供程序会影响实际字段。

### 3.2 UF 订阅事件日志通道

本地 `Splunk_TA_windows` 11.0.2 的默认配置包含以下模板，但默认均为关闭状态；实际修改应放在 `local/inputs.conf`，不直接编辑 `default/inputs.conf`。[本地 inputs.conf](../Splunk_TA_windows/default/inputs.conf)

```ini
[WinEventLog://Security]
disabled = 0
start_from = oldest
current_only = 0
evt_resolve_ad_obj = 1
checkpointInterval = 5
renderXml = true
index = wineventlog
```

参数含义：

| 参数 | 作用 | 需要注意 |
|---|---|---|
| `disabled=0` | 启用输入 | TA 默认模板通常是 `1`，安装 TA 不等于已经采集 |
| `start_from=oldest` | 没有既有检查点时从较早事件开始 | 首次上线可能产生大量历史回补和延迟 |
| `current_only=0` | 允许读取已有历史事件 | 与 `start_from`、既有检查点共同影响起点 |
| `checkpointInterval=5` | 周期性保存读取检查点 | 这是检查点刷新配置，不是“每 5 秒才采一次日志”的简单轮询结论 |
| `renderXml=true` | 以 XML 格式采集事件 | 本地 TA 会将 XML sourcetype 归一并提取字段 |
| `evt_resolve_ad_obj=1` | 尝试解析 AD 对象信息 | 会增加域控查询或解析开销，应结合负载测试 |
| `index=wineventlog` | 指定目标索引 | Indexer 必须预先存在该索引及权限配置 |

Splunk 官方说明 `WinEventLog` 输入针对本地 Windows 系统。采集远端事件更常见的做法是在目标主机部署 UF，或者先由 WEF 汇总到 WEC，再在 WEC 上部署 UF。[Windows Event Log 官方说明](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.3/get-windows-data/monitor-windows-event-log-data-with-splunk-enterprise)

### 3.3 检查点与重启恢复

UF 保存每个事件日志输入的读取状态。正常重启后，它依据检查点继续读取，而不是无条件从 `start_from=oldest` 重新发送所有事件。`start_from` 主要影响没有有效检查点时的初始位置。

这不等于端到端业务层面绝对不重不丢。仍需考虑：

- Windows 事件日志覆盖速度是否快于 UF 恢复速度；
- 首次回补旧事件时新事件是否出现较大延迟；
- UF 到接收端中断期间的本地队列和磁盘容量；
- Indexer 接收确认、重试及下游检测是否具有幂等性；
- 管理员清空日志、事件通道损坏或检查点被删除的情况。

繁忙域控制器首次从 oldest 回补可能造成采集积压。Splunk 官方故障排查建议根据需要仅采近期日志、从 newest 开始，或减少采集事件范围，但这些选择会改变历史完整性，必须在上线方案中明确。[事件索引延迟说明](https://help.splunk.com/en/splunk-enterprise/administer/troubleshoot/9.3/data-acquisition-problems/event-indexing-delay)

### 3.4 UF 添加元数据并转发

`outputs.conf` 的工作方式与 Zeek 主机上的 UF 相同：定义一个或多个接收端，由 UF 将采集到的事件发送给 Indexer 或中间 Forwarder。

```ini
[tcpout]
defaultGroup = splunk_indexers

[tcpout:splunk_indexers]
server = 10.10.10.21:9997,10.10.10.22:9997
autoLB = true
```

`autoLB=true` 表示在多个接收端之间分配转发流，不表示同一事件主动复制到每台 Indexer。索引集群的数据副本由索引集群机制负责。

Windows 事件通常带有：

```text
host       = 产生或承载事件的 Windows 主机
source     = WinEventLog:Security 或 XmlWinEventLog:Security
sourcetype = WinEventLog:Security 或 XmlWinEventLog:Security
index      = wineventlog（示例）
```

使用 WEF 时要额外保证 `host` 最终表示事件原始主机，而不是全部显示为 WEC 收集器。当前 TA-Windows 为 ForwardedEvents 配置了主机覆盖逻辑。[本地 props.conf](../Splunk_TA_windows/default/props.conf)

### 3.5 Indexer 和 Search Head 如何处理

当前本地 TA-Windows 对 XML Windows 事件配置了 XML 字段提取，并把不同来源归一到兼容的 `XmlWinEventLog:*` / `WinEventLog:*` sourcetype。部分高基数字段可以调整为搜索时提取，以权衡索引空间与查询成本。[本地 props.conf](../Splunk_TA_windows/default/props.conf)

典型字段随后被映射到 CIM：

```text
SubjectUserName / TargetUserName → user、src_user 或目标账号字段
IpAddress / WorkstationName      → src、src_nt_host
Computer                         → dest 或 dvc
EventCode                        → signature_id / 事件分类
NewProcessName                   → process_name
TargetSid / MemberSid            → 用户或组标识
```

具体映射随 EventCode 和 TA 版本变化，不能仅根据字段名称统一套用。Authentication、Change、Endpoint 等 CIM 数据模型会消费这些标准字段，供 ES 和 UEBA 检测使用。

## 4. WEF 集中采集模式如何工作

```text
DC1 ─┐
DC2 ─┼─ Windows Event Forwarding ─→ WEC / ForwardedEvents
DC3 ─┘                                   │
                                  UF + TA-Windows
                                  读取 ForwardedEvents
                                         │
                                         ▼
                                      Splunk
```

在这种模式下，Windows 自己先通过 WEF 把多个域控或成员服务器的事件汇聚到 WEC。UF 只需在 WEC 上订阅 `ForwardedEvents`：

```ini
[WinEventLog://ForwardedEvents]
disabled = 0
start_from = oldest
current_only = 0
checkpointInterval = 5
renderXml = true
host = WinEventLogForwardHost
index = wineventlog
```

当前 TA-Windows 明确要求 WEF 采集采用 XML 格式，并通过 `WinEventLogForwardHost` 触发主机还原转换。Splunk 9.1 以后还需让 `wec_event_format` 与 WEF Subscription 的 Content Format（Events 或 RenderedText）一致；多个格式不同的 Subscription 不宜混入同一目标通道。[inputs.conf 参考](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/inputs.conf)

| 直接在每台 DC 部署 UF | WEF/WEC 集中后部署 UF |
|---|---|
| 少一层 Windows 转发链路，问题定位直接 | 端点侧代理数量较少，Windows 可集中控制订阅 |
| 每台 DC 独立缓冲、独立转发 | WEC 容量和可用性成为集中关注点 |
| 需要统一管理每台 UF 与 TA 配置 | 需要同时治理 WEF Subscription、WEC 通道和 UF |
| 原始主机语义通常直接 | 必须验证 host 还原和事件格式一致性 |
| 域控上有额外采集进程与开销 | WEF 本身仍在每台源主机运行并传输事件 |

二者没有脱离约束的绝对优劣。选择前应实测事件量、域控负载、允许安装代理的范围、网络隔离、WEC 高可用和故障恢复时间。

## 5. AD Monitor 不是 Security 日志输入

如果 UEBA 需要完整的用户、组、计算机属性和对象变化，可以单独配置 AD Monitor：

```ini
[admon://domain_directory]
disabled = 0
targetDc = dc01.example.com
```

该输入只能在 Windows 上运行；执行监控的主机需要属于目标域或林，并具备读取目录的权限。它可以运行在 Windows Splunk 实例或 Forwarder 上，再把数据发送给 Linux Indexer。官方建议谨慎配置对象路径和目标 DC，参数大小写也有明确要求。[AD Monitor 官方说明](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.0/get-windows-data/monitor-active-directory)

| Security Event Log | AD Monitor |
|---|---|
| 审计事件流 | 目录对象状态与变化 |
| 依赖审核策略和 SACL | 依赖目录读取权限和 LDAP 可达性 |
| 适合回答谁在何时执行了什么 | 适合补充用户、组、计算机及属性上下文 |
| 可用于行为序列和安全检测 | 可用于身份画像、组关系及富化 |

实际部署仍要验证 AD Monitor 是否满足所需历史语义。用当前目录快照富化过去事件，可能把今天的部门或权限错误地套到过去。自研 UEBA 应对重要身份属性保存有效时间。

## 6. Windows AD 与 Zeek 的完整对比

| 对比项 | Windows AD 日志 | Zeek 日志 |
|---|---|---|
| 原始数据来源 | Windows Event Log、AD 目录、脚本或服务日志 | SPAN/TAP 流量经 Zeek 协议分析生成日志 |
| UF 是否解析网络包 | 否 | 否，网络包由 Zeek 解析 |
| 主采集输入 | `WinEventLog://Security` 等模块化输入 | `monitor://.../*.log` 文件监控 |
| 读取接口 | Windows Event Log API / AD 接口 | 文件系统读增量 |
| 位置状态 | 事件日志输入检查点 | 文件读取游标与文件识别状态 |
| 轮转问题 | Event Log 容量、覆盖和清空 | 文件 rename、软链接、压缩和轮转 |
| 原始身份信息 | 用户 SID、账号、域、Logon ID 等，具体事件而异 | 多数网络日志只有 IP/主机/协议信息，用户字段并不稳定存在 |
| 时间语义 | Windows 事件发生时间和采集时间 | Zeek 观测到连接或协议事件的时间 |
| 常用 sourcetype | `XmlWinEventLog:Security` 等 | `zeek:conn`、`zeek:dns`、`zeek:http`、`zeek:ssl` |
| 主要 CIM | Authentication、Change、Endpoint 等 | Network_Traffic、Web、部分 Authentication 等 |
| 对 UEBA 的贡献 | 明确账号、权限、登录和终端行为 | 连接对象、传输量、协议和网络关系 |
| 单独可证明的事实 | 某账号发生某类被审计操作 | 某设备或地址出现某类网络行为 |
| 单独难以证明 | 完整网络传输内容和所有外联关系 | 操作者真实身份、文件内容和目录权限变化 |
| 集中采集方式 | WEF/WEC 后由 UF 读取 ForwardedEvents | 多个 Zeek Sensor 各自生成日志，可本地 UF 或集中日志管道 |
| 首次上线风险 | oldest 回补压垮繁忙 DC、审核策略缺失 | 大量历史文件重复采集、日志头和轮转处理错误 |

二者结合后，可以形成更可靠的链路：

```text
AD 4624：账号 A 在设备 D 登录
        +
AD/终端：账号 A 访问资源或发生权限变化
        +
Zeek：设备 D 向新目的地发送异常数据量
        ↓
身份、设备、时间和网络证据关联
        ↓
行为异常信号 → 风险聚合 → 疑似外泄调查
```

关联成立不代表已经证明文件内容被外泄。若要回答“哪些文件”，还需要文件审计、EDR、代理上传或 DLP 等证据。

## 7. 推荐的配置分层

```text
域控制器或 WEC 上的 UF
├── Splunk_TA_windows/default：厂商默认配置，不修改
├── Splunk_TA_windows/local/inputs.conf：启用通道、过滤和目标索引
├── outputs.conf：Indexer / 中间转发层
└── deploymentclient.conf：接收 Deployment Server 配置

Indexer / Heavy Forwarder（按实际解析拓扑）
├── TA-Windows 的索引时解析配置
├── indexes.conf
└── 路由、脱敏或过滤配置

Search Head / ES
├── TA-Windows 搜索时字段提取和 lookup
├── CIM 数据模型
├── 资产与身份富化
└── 检测、风险和调查内容
```

在多个层次安装 TA 的目的不同：采集端需要输入定义，解析端需要索引时配置，搜索端需要字段、事件类型、标签和 lookup。不能笼统地说“TA 只装在 UF”或“只装在 Search Head”。

## 8. 上线验证清单

1. 在 Windows 事件查看器确认目标事件确实产生，再检查 Splunk；不要先把没有事件归因于 UF。
2. 检查每台 DC 或每个 WEF Subscription 的事件量、最后事件时间和延迟。
3. 验证 `host` 表示原始事件主机，尤其是 ForwardedEvents。
4. 对比 EventCode、EventRecordID、Computer、Subject/Target、SID、IP 和 Logon ID 与原始 XML。
5. 验证 UF 重启、网络中断、Indexer 切换后是否漏采或重复。
6. 测试日志接近覆盖上限、WEC 积压和首次历史回补。
7. 检查 TA 版本、XML/RenderedText 格式和 WEF Content Format 是否匹配。
8. 分别验证 Authentication、Change、Endpoint 数据模型的事件覆盖和字段完整性。
9. 对 4624/4625、4720～4729、4756/4757、4662、4688、1102 等实际需要的事件建立覆盖率监控。
10. 记录输入配置版本、检查点状态、最后成功事件时间和数据缺口，供 UEBA 判断“零行为”还是“未采到”。

## 9. 主要证据

- Splunk，[Monitor Windows event log data with Splunk Enterprise](https://help.splunk.com/en/splunk-enterprise/get-data-in/get-started-with-getting-data-in/9.3/get-windows-data/monitor-windows-event-log-data-with-splunk-enterprise)，Windows Event Log 输入与运行权限。
- Splunk，[Get Windows Data into Splunk Cloud Platform](https://help.splunk.com/en/splunk-cloud-platform/administer/admin-manual/10.4.2604/get-data-into-splunk-cloud-platform/get-windows-data-into-splunk-cloud-platform)，TA-Windows、Security 输入和 XML 示例。
- Splunk，[inputs.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.4/configuration-file-reference/9.4.0-configuration-file-reference/inputs.conf)，WinEventLog、WEC 格式及 AD Monitor 参数。
- Splunk，[Monitor Active Directory](https://help.splunk.com/en/splunk-enterprise/get-started/get-data-in/9.0/get-windows-data/monitor-active-directory)，AD Monitor 部署条件。
- 本地 [TA-Windows inputs.conf](../Splunk_TA_windows/default/inputs.conf) 与 [props.conf](../Splunk_TA_windows/default/props.conf)，版本见 [app.conf](../Splunk_TA_windows/default/app.conf)。
- 本报告的 [Splunk 数据平台与工程机制](02-数据平台与工程机制.md)，用于理解 Forwarder、Indexer、Search Head 与 CIM 的共同处理层次。
