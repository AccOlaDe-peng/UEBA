# UEBA 异常检测实现设计（用户、主机与网络行为）

## 1. 目标与边界

本文描述一套以 **UEBA（User and Entity Behavior Analytics，用户与实体行为分析）**为核心的异常检测实现方案。系统同时采集身份认证、目录服务、Windows、Linux、VPN/IdP 和网络元数据，将用户、账号、主机、会话、目的地等实体关联起来，识别账号失陷、权限滥用、横向移动、异常外联、隧道、扫描和自动化回连等行为。

UEBA 不是一个统一风险分，也不是把所有行为塞进同一种规则或模型。不同检测场景必须选择与其语义相符的判定方式：

- **确定性规则**：出现即异常或需要立即处置，例如非授权账号加入 Domain Admins；
- **基线偏离**：当前行为相对用户自身、主机自身或同类群组发生显著变化；
- **异常组合**：多个弱异常在同一用户、会话或时间范围内叠加后符合一个风险场景；
- **行为序列**：事件按顺序组成攻击链，例如异地登录成功 → 提权 → 横向访问 → 异常外联；
- **统计或机器学习模型**：发现多维特征中的罕见组合，作为候选信号而非攻击结论；
- **风险评分**：用于对已经成立的证据做排序、升级和案件聚合，不能作为所有检测的唯一入口。

系统最终输出的是可解释的原子信号、场景命中和风险案件，并能够回答“谁、使用什么账号、在哪台设备、何时、做了什么、与其历史有何不同、为什么危险”。

本文不覆盖：

- TLS 解密、HTTP Body 或文件正文解析；
- 敏感数据识别、数据分级和 DLP 内容策略；
- 未部署 EDR、Sysmon、auditd/eBPF 等数据源时，无法覆盖完整的文件内容、USB 和所有进程级行为；
- UEBA 只产生检测和调查证据，不直接替代 IAM/PAM、EDR、DLP 或阻断控制。

## 2. 总体架构

### 2.1 端到端处理链路

```text
┌──────────────────────────── 数据采集层 ────────────────────────────┐
│ 身份与目录                  Windows                   Linux        │
│ AD/DC Security Log          WEF / Winlogbeat          auditd       │
│ Entra ID / IdP / MFA        Sysmon / EDR              journald     │
│ VPN / PAM                   PowerShell 日志            auth.log     │
│ 4624/4625/4672/4728...      进程/服务/计划任务         sudo/SSH     │
│                                                                    │
│ 网络与边界：Zeek conn/dns/tls/http、DNS、Proxy、Firewall、NAC      │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ WEF、Beats、Agent、Syslog、API
                               ▼
┌──────────────────────────── 传输与标准化层 ─────────────────────────┐
│ Filebeat / Winlogbeat / Auditbeat / Elastic Agent / Syslog         │
│                              ↓                                      │
│ Logstash / Ingest Pipeline                                          │
│ 解析 → 类型转换 → ECS/统一事件模型 → 事件 ID → 质量标记 → 路由     │
└──────────────────────────────┬─────────────────────────────────────┘
                               │ 统一行为事件
                   ┌───────────┴───────────┐
                   ▼                       ▼
        Elasticsearch 原始事件          Kafka 事件主题
        ueba-raw-*                      ueba.raw.identity
        用于检索、调查和回算            ueba.raw.endpoint
                                       ueba.raw.network
                                                │
                                                ▼
┌──────────────────────── UEBA 实时计算与状态层 ──────────────────────┐
│ ① 质量与时间：去重 → 事件时间 → Watermark → 迟到标记              │
│ ② 身份解析：SID/UPN/账号别名 → user.id / account.id                │
│ ③ 实体关联：用户 ↔ 账号 ↔ 主机 ↔ IP ↔ 会话 ↔ 目的地               │
│ ④ 上下文富化：组织/岗位/权限/资产角色/网段/地理/批准服务/例外       │
│ ⑤ 状态与画像：首次出现、常用设备、登录时段、常用来源、访问资源       │
│                                                                      │
│ ┌─────────────── 检测方法按场景选择，不强制统一打分 ──────────────┐ │
│ │ A. 确定性规则：命中即告警                                      │ │
│ │ B. 基线 + 异常：自身/同类基线偏离，一个或多个异常成立            │ │
│ │ C. 异常组合：多个弱信号叠加后满足场景                           │ │
│ │ D. 行为序列：按时间顺序匹配账号失陷、提权、横移、外联链路         │ │
│ │ E. 统计/ML：发现多维罕见组合，输出候选信号                       │ │
│ │ F. 风险评分：对已成立证据排序和升级，不作为唯一判定方式           │ │
│ └─────────────────────────────────────────────────────────────────┘ │
│                              ↓                                       │
│ 原子信号 → 场景命中 → 例外复核 → 用户/实体风险案件                 │
└──────────────────────────────┬─────────────────────────────────────┘
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
   用户/实体画像与特征      原子信号与场景命中        UEBA 风险案件
   ueba-*-profile           ueba-detection-*         ueba-risk-case-*
          └────────────────────┴──────────┬─────────┘
                                         ▼
┌──────────────────────── 调查、响应与治理层 ─────────────────────────┐
│ Kibana / SIEM / UEBA 调查工作台 / SOAR / 工单                       │
│ 用户、账号、主机、会话、权限变化、网络行为与时间线统一展示            │
│ 调查结论 → 规则/场景/基线/模型/例外版本化更新                        │
└─────────────────────────────────────────────────────────────────────┘
```

### 2.2 一条网络事件如何走完整个流程

以下以“办公终端通过 TLS 访问一个新目的地”为例说明各阶段如何串联。

#### 阶段 1：流量复制与协议日志生成

交换机通过 SPAN/TAP 将流量副本发送给 Zeek。Zeek 不改变业务流量，也不负责阻断。它将一次连接解析为多类日志：

```text
conn.log：10.10.2.15:52341 → 203.0.113.8:443，发送 85,231 字节
tls.log：同一 uid，SNI=example.com，TLS 1.3，JA4=t13d...
```

此阶段输出的是 Zeek 原始 JSON 日志。`uid` 用于把同一次连接的不同协议日志关联起来。

#### 阶段 2：日志可靠采集

Filebeat 分别监听 `conn.log`、`dns.log`、`tls.log` 等文件，为事件增加传感器 ID、日志类型和采集时间，然后发送至 Logstash。

Filebeat 在本地保存读取偏移，短时网络故障后可以继续发送。采集端只做轻量解析，不进行窗口统计和规则判断。

#### 阶段 3：清洗与标准化

Logstash 将 Zeek 字段映射为统一事件：

```text
id.orig_h   → source.ip
id.resp_h   → destination.ip
id.resp_p   → destination.port
orig_bytes  → source.bytes
service     → network.protocol
ts          → @timestamp
```

同时完成：

- 数字、布尔值、IP 和时间类型转换；
- 生成 `event.id` 与去重键；
- 区分事件发生时间和采集时间；
- 对字段缺失、格式错误的事件增加质量标记；
- 将合格事件写入 Kafka，并将原始标准化事件写入 Elasticsearch。

原始索引用于调查和离线回算；Kafka 用于实时、有状态计算。二者的数据应来自同一份标准化事件，避免在线检测与调查字段不一致。

#### 阶段 4：事件去重、排序和迟到处理

流计算层消费 Kafka 事件，根据 `sensor_id + zeek.uid + log_type` 去重，并使用 Zeek 的事件时间进行处理。

系统允许一定程度的乱序。例如 Watermark 设置为 2 分钟，表示窗口关闭前等待最多 2 分钟的迟到日志。严重迟到的日志仍写入原始索引并标记，供后续回算使用。

#### 阶段 5：跨日志关联

流计算层在短时状态中按 `sensor_id + zeek.uid` 保存连接上下文，并将 `conn`、`dns`、`tls`、`http` 日志合并为“增强连接事件”。

例如关联后可得到：

```text
资产 PC-023
→ 访问 203.0.113.8:443
→ 实际协议为 TLS
→ SNI 为 example.com
→ 上行 85,231 字节
→ JA4 为 t13d...
```

关联状态必须设置 TTL，例如 5～10 分钟，防止未完成连接长期占用内存。超过 TTL 仍未补齐的事件可以以“不完整关联”的形式继续进入后续流程。

#### 阶段 6：上下文富化

增强连接事件查询资产和策略数据：

```text
source.ip → asset.id、asset.role、asset.zone、asset.owner
destination.ip → 内/外网、ASN、国家/地区
domain / IP / ASN → 是否为批准服务
port + transport → 允许的应用协议
asset + destination + port → 是否存在有效例外
```

富化应使用“事件发生时间”查询有效记录。例如历史 DHCP 地址归属必须对应当时的设备，不能使用当前租约覆盖历史归属。

#### 阶段 7：目的地归一化与历史状态更新

系统生成统一的 `destination_key`：

```text
优先使用 TLS SNI / HTTP Host / DNS 注册主域；
没有域名时使用 destination.ip + ASN；
仍无法归类时退化为 destination.ip。
```

随后查询并更新目的地历史状态：

- 企业是否访问过该目的地；
- 当前主机是否访问过该目的地；
- 首次、最近一次出现时间；
- 近 30 天访问资产数和资产角色数；
- 是否为批准服务。

#### 阶段 8：进入两条检测支路

增强连接事件并行进入两类检测：

1. **单事件规则**：不等待窗口即可判断。例如目标端口 53，但 Zeek 明确识别为 TLS，且没有有效例外；
2. **窗口特征计算**：按资产、目的地或注册主域聚合。例如统计过去 5 分钟的唯一 DNS 子域比例，或过去 1 小时的连接间隔规律性。

两条支路不会互相替代。单事件规则负责确定性信号，窗口计算负责累积行为和未知异常。

#### 阶段 9：窗口特征与基线比较

窗口计算产生结构化特征对象，例如：

```text
PC-023 + example.com + 最近 1 小时
连接次数：58
平均连接间隔：60.1 秒
间隔变异系数：0.07
上行字节：230 MB
非工作时间比例：100%
企业首次出现：是
```

特征对象分别进入：

- 固定阈值检测：DNS 隧道、横向扫描、周期通信；
- 主机自身基线比较：当前值与该主机过去 7/30 天的 P95、P99、MAD 比较；
- 同类主机基线比较：当前值与相同资产角色、部门、区域的设备比较；
- 新颖度判断：目的地、ASN、端口或 TLS 指纹是否首次或罕见出现；
- 孤立森林检测：将多个窗口指标作为一个特征向量，识别单个阈值不突出、但组合关系偏离同类样本的异常。

#### 阶段 10：例外复核与告警抑制

所有候选信号在生成正式告警前再次执行策略检查：

- 是否命中批准目的地；
- 当前资产是否为扫描器、跳板机、备份服务器等特殊角色；
- 是否处于已批准的变更窗口；
- 是否存在限定资产、网段、目的地、协议、端口和有效期的例外；
- 相同规则、资产、目的地是否已在抑制时间内生成告警。

例外不建议直接删除数据。应保留候选信号并记录“因何降级或抑制”，以便发现例外配置过宽或批准服务被滥用。

#### 阶段 11：原子告警生成

候选信号通过复核后，生成原子告警。告警必须包含：

- 哪台资产、何时、访问了哪个目的地；
- 命中了哪条规则及规则版本；
- 实际指标、阈值和风险得分；
- 使用了哪些白名单、例外和资产上下文；
- 支撑结论的原始事件引用；
- 风险严重度与检测置信度。

#### 阶段 12：风险案件合并

案件引擎按 `asset.id + destination_key + 时间范围` 关联多个原子告警。例如：

```text
09:02  企业首次出现的外部目的地
09:05  TLS 指纹首次出现
09:20  检测到固定 60 秒周期通信
09:45  上行量超过主机自身 P99 的 12 倍
```

这些原子告警合并后形成“未知目的地异常周期外传”案件。案件风险通常高于任一单独信号，也比大量孤立告警更容易调查。

#### 阶段 13：展示、通知与调查

原始事件、窗口特征、原子告警和案件分别写入 Elasticsearch。调查工作台展示：

- 风险时间线；
- 资产、目的地、协议和流量指标；
- 相对自身与同类主机的异常程度；
- 命中规则与例外检查结果；
- 可回查的 Zeek 原始日志。

告警可以发送至 SIEM、SOAR 或工单系统。本文系统定位为检测与调查；是否执行阻断由独立响应策略决定。

#### 阶段 14：分析反馈与策略更新

分析人员将案件标记为确认异常、正常业务、误报或信息不足。反馈用于：

- 调整固定规则的阈值与权重；
- 更新资产角色和批准目的地；
- 创建有范围、有原因、有有效期的例外；
- 更新同类主机分组；
- 监控基线漂移并按日发布新版本；
- 评估规则的命中量、确认率和误报率。

更新后的策略通过配置中心或广播流发布到实时计算层，形成完整闭环。

### 2.3 一条用户行为如何形成 UEBA 案件

以下以“财务人员账号疑似失陷”为例说明身份、主机和网络事件如何合并，而不是分别产生互不相关的告警。

```text
21:48  VPN/IdP：用户 zhangsan 从非常用国家登录，MFA 成功
21:51  AD：同一账号在 PC-023 获得交互式登录成功（4624）
21:55  Windows：启动此前未使用的 PowerShell，随后访问凭据相关进程
22:01  AD：账号被加入高权限组（4728/4732/4756）
22:06  网络：PC-023 扫描多个服务器的 445/3389 端口
22:14  Linux：该用户关联账号首次 SSH 登录生产服务器并执行 sudo
22:21  网络：生产服务器向企业首次出现的目的地产生周期连接
22:54  网络：非工作时间异常上行 230 MB
```

各条事件分别处理如下：

1. **身份解析**：将 UPN、Windows SID、VPN 用户名、Linux UID/账号别名统一映射到稳定的 `user.id`；共享账号或服务账号保留独立 `account.id`，不能强行归属个人；
2. **会话关联**：按用户、账号、源 IP、主机、登录 ID、VPN 会话 ID 和时间范围形成 `session.id`；
3. **原子信号**：非常用地理位置、首次设备、异常 PowerShell、权限组变更、扫描、首次 SSH、周期连接和异常上行分别产生可解释信号；
4. **场景编排**：高权限组变更可由确定性规则直接告警；登录位置和首次设备使用基线；“登录 → 提权 → 横移 → 外联”使用有序场景；
5. **案件合并**：按 `user.id + account.id + session.id + 时间范围` 合并证据，形成“账号失陷并尝试横向移动/外传”的 UEBA 案件；
6. **风险排序**：风险分只用于案件优先级和升级，不取消已经成立的确定性规则或完整行为序列。

这个例子体现 UEBA 的核心：网络事件仍然重要，但必须被放入“用户使用哪个账号、从哪里登录、控制哪台主机、访问哪些资源、权限如何变化”的行为上下文中。

### 2.4 数据在各阶段的形态

| 阶段 | 输入对象 | 核心处理 | 输出对象 |
| --- | --- | --- | --- |
| Zeek 解析 | 镜像报文 | 协议识别和元数据提取 | Zeek `conn`、`dns`、`tls` 等 JSON 日志 |
| AD / IdP 采集 | DC Security Log、目录审计、MFA/VPN 事件 | 账号、认证、权限变化和会话提取 | 统一身份行为事件 |
| Windows 采集 | Security、Sysmon、PowerShell、EDR | WEF/Winlogbeat/Elastic Agent 采集与转发 | 统一 Windows 主机行为事件 |
| Linux 采集 | auditd、journald、auth.log、sudo、SSH | Auditbeat/Elastic Agent/rsyslog 采集与转发 | 统一 Linux 主机行为事件 |
| Beats / Agent 采集 | 身份、主机和网络日志 | 文件偏移、缓冲、断点续传和采集元数据 | 带采集元数据的原始事件 |
| Logstash 清洗 | 多源原始事件 | 字段映射、类型转换、时间处理、基本校验 | 统一行为事件 |
| 原始存储 | 统一行为事件 | 按时间、数据集和租户保存 | `ueba-raw-*` 文档 |
| Kafka 缓冲 | 统一行为事件 | 解耦生产和消费、支持重放 | `ueba.raw.*` 事件流 |
| 质量处理 | 原始事件流 | 去重、Watermark、迟到标记 | 有序有效事件流 |
| 身份与会话解析 | AD、IdP、VPN、Windows、Linux 事件 | SID/UPN/账号别名归一，关联登录会话 | 统一用户/账号/会话事件 |
| 跨日志关联 | 身份、主机、网络事件 | 按用户、账号、主机、IP、会话和 Zeek UID 关联 | 增强行为事件 |
| 上下文富化 | 增强行为事件 + 参考数据 | 组织、岗位、权限、资产、网段、目的地和策略查表 | 富化行为事件 |
| 用户与实体画像 | 富化行为事件 + 历史状态 | 常用设备、来源、时段、资源、权限和同类群组 | 用户/账号/主机画像与新颖度字段 |
| 目的地画像 | 富化连接事件 + 历史状态 | 首次出现、访问范围和批准状态 | 目的地状态与新颖度字段 |
| 确定性规则 | 富化行为事件 | 明确禁止行为和高置信度策略判断 | 确定性原子信号 |
| 窗口聚合 | 富化事件流 | 5 分钟/1 小时/1 天滑动统计 | 用户、认证、权限、主机和网络特征对象 |
| 基线检测 | 窗口特征 + 基线快照 | 用户自身、实体自身、同类群组与新颖度比较 | 基线异常信号 |
| 场景与序列检测 | 原子信号和行为事件 | 异常叠加、顺序、次数、时间约束与排除条件 | 场景命中 |
| 孤立森林评分 | 窗口特征 + 模型快照 | 多维特征预处理、模型推理和分数校准 | ML 候选异常信号 |
| 例外复核 | 原子信号/场景命中 + 策略 | 降级、抑制、例外审计 | 可告警信号或场景 |
| 告警生成 | 可告警信号/场景 | 固化判定方式、证据、风险与置信度 | 原子告警或场景告警 |
| 案件关联 | 告警和信号流 | 按用户、账号、会话、资产、目的地和时间关联 | UEBA 风险案件 |
| 调查反馈 | 告警、案件、分析结论 | 调阈值、白名单和基线 | 新版本策略和基线 |

### 2.5 运行时依赖关系

整个检测链并不是所有组件都强同步依赖。建议按以下方式解耦：

```text
实时强依赖：
AD/IdP/Windows/Linux/Zeek → Beats/Agent/Syslog/API → Logstash → Kafka → UEBA 计算 → 告警

实时查询或广播状态：
身份目录、组织与岗位、权限组、资产快照、网段表、批准目的地、规则例外、基线快照、场景版本、模型快照

异步落库：
原始事件、用户/实体画像、窗口特征、目的地画像、原子信号、场景命中、风险案件

离线/周期任务：
用户/账号/主机基线更新、同类群组统计、目的地近 30 天画像、模型训练、规则/场景/模型效果评估
```

身份、组织、权限、资产、白名单、基线、场景和模型不应在每条事件处理时直接查询业务数据库。推荐定期生成版本化快照并加载到流计算状态中，或通过 Kafka 广播流实时更新，以降低延迟并避免外部数据库故障拖垮检测链。

### 2.6 组件职责边界

- **Zeek**：从报文中提取协议元数据，不负责资产归属和业务规则；
- **AD 域控制器 / IdP / VPN / PAM**：提供认证、目录、权限、MFA 和远程接入事件；
- **WEF / Winlogbeat / Elastic Agent**：采集 Windows Security、Sysmon、PowerShell 和 EDR 行为事件；
- **auditd / Auditbeat / journald / rsyslog**：采集 Linux 登录、sudo、进程、文件审计和服务行为；
- **Filebeat / Agent**：可靠读取和转发日志，不负责跨事件计算；
- **Logstash / Ingest Pipeline**：单条事件的解析、字段映射、基础富化和路由；
- **Kafka**：隔离采集与计算、缓冲突发流量、支持事件重放；
- **身份解析与实体关联层**：统一 SID、UPN、账号别名和动态 IP，维护用户—账号—主机—会话关系；
- **流计算层**：去重、乱序处理、跨日志关联、窗口聚合、确定性规则、基线和场景序列检测；
- **模型训练与推理服务**：按用户或实体同类群组训练版本化模型，对窗口特征产生候选异常信号；
- **策略与画像存储**：保存身份、权限、资产、目的地、端口、例外、基线、场景和模型版本；
- **Elasticsearch**：保存事件和计算结果，支持检索、调查和离线回算；
- **案件引擎**：按用户、账号、会话和实体把多个信号/场景合并为可调查的风险时间线；
- **Kibana / 调查工作台**：展示证据、记录处置结论并形成规则反馈。

> 不建议使用 Logstash `aggregate` 插件承担生产环境的滑动窗口检测。多实例状态不共享、乱序处理弱、重启易丢状态，且高基数聚合会导致内存压力。Logstash 应保持“无状态清洗”的定位。

## 3. UEBA 数据源与关联方式

### 3.1 Zeek 日志用途

| 日志 | 主要能力 | 用于哪些检测 |
| --- | --- | --- |
| `conn.log` | 五元组、服务识别、连接状态、时长、双向字节和包数 | 协议端口不匹配、横向扫描、外联规模、周期通信 |
| `dns.log` | 查询域名、类型、响应码、解析结果 | DNS 隧道、异常域名、DNS 枚举 |
| `ssl.log` / `tls.log` | SNI、TLS 版本、证书、JA3/JA4、ALPN | 加密流量画像、罕见 TLS 指纹、无 SNI 连接 |
| `http.log` | Host、HTTP 方法、URI、User-Agent | HTTP 目的地识别和协议识别补充 |
| `weird.log` | 解析异常、协议格式异常 | 异常协议或采集质量排查 |
| `notice.log` | Zeek 已识别的高阶事件 | 作为已有检测信号补充 |

### 3.2 Windows AD、IdP 与远程访问日志

AD 域控的 Security Log 是用户身份和权限行为的核心数据源。建议通过 Windows Event Forwarding（WEF）汇聚到 Windows Event Collector，再由 Winlogbeat/Elastic Agent 采集；规模较小时也可直接从域控采集，但应避免采集器影响域控稳定性。

| 数据源 / 事件 | 主要能力 | 典型 UEBA 用途 |
| --- | --- | --- |
| AD 4624 / 4625 | 登录成功/失败、登录类型、源地址、工作站 | 暴力尝试后成功、非常用设备、非常用时段、横向登录 |
| AD 4634 / 4647 | 会话注销 | 登录会话边界和持续时间 |
| AD 4648 | 使用显式凭据 | 凭据切换、横向移动、RunAs/远程访问调查 |
| AD 4672 | 特权登录 | 高权限会话和非常用管理员行为 |
| AD 4688 | 进程创建（需启用审计） | 域控或关键 Windows 主机上的命令执行 |
| AD 4720 / 4726 | 用户创建/删除 | 影子账号、异常账号生命周期 |
| AD 4728 / 4732 / 4756 | 加入全局/本地/通用安全组 | Domain Admins 等高权限组变更 |
| AD 4729 / 4733 / 4757 | 从安全组移除 | 短时提权后清理痕迹 |
| AD 4738 | 用户账号变更 | UAC、登录名、属性等敏感变更 |
| AD 4740 / 4767 | 账号锁定/解锁 | 密码喷洒、异常认证和处置确认 |
| AD 4768 / 4769 / 4771 | Kerberos TGT/TGS 与预认证失败 | Kerberoasting、异常服务访问、认证失败模式 |
| AD 4776 | NTLM 凭据验证 | NTLM 异常使用与横向认证 |
| 目录服务变更 5136 | AD 对象属性修改 | 委派、SPN、ACL、GPO 等高风险变更 |
| Entra ID / IdP | 云登录、设备、应用、条件访问、MFA | 异地/不可能旅行、新应用、MFA 异常、令牌滥用 |
| VPN / ZTNA / NAC | 远程会话、源 IP、设备、接入时长 | 外部来源、会话绑定、账号与内网 IP 映射 |
| PAM | 特权账号申请、审批、签出和会话 | 区分已批准维护与未授权特权使用 |

事件 ID 只代表语义入口，生产规则还必须结合日志来源、审计策略、登录类型、状态码和环境版本校准，不能仅凭单个事件号直接推断攻击。

### 3.3 Windows 主机行为日志

| 数据源 | 采集方式 | 主要行为 |
| --- | --- | --- |
| Windows Security | WEF + Winlogbeat / Elastic Agent | 登录、进程创建、对象访问、服务安装、计划任务、账号变化 |
| Sysmon | WEF/Agent | 进程树、网络连接、驱动/模块、注册表、文件创建、DNS 查询 |
| PowerShell | Script Block、Module、Transcription 日志 | PowerShell 命令与脚本行为；注意日志可能包含敏感参数 |
| Microsoft Defender / 其他 EDR | 厂商 API、Agent 或 SIEM Connector | 进程、文件、设备控制、告警和响应上下文 |
| Windows DNS Client / Firewall | WEF/Agent | 主机侧 DNS、允许/拒绝连接与进程关联 |

Windows 行为至少应形成 `user.id/account.id + host.id + logon.id + process.entity_id` 关系。`LogonId` 在单机和单次启动范围内关联会话，不能脱离主机与启动周期当作全局唯一键。

### 3.4 Linux 主机行为日志

Linux 不存在统一等价于 Windows Security Log 的单一数据源，建议组合采集：

| 数据源 | 采集方式 | 主要行为 |
| --- | --- | --- |
| `auditd` | Auditbeat / Elastic Agent / audisp | `execve`、用户切换、文件/权限修改、内核审计、关键配置访问 |
| `journald` / syslog | Journalbeat（旧）/ Elastic Agent / Filebeat / rsyslog | systemd 服务、内核、应用和通用系统事件 |
| `/var/log/auth.log` 或 `/var/log/secure` | Filebeat / rsyslog | SSH、sudo、su、PAM 认证、失败登录 |
| SSHD | journald/syslog | 来源 IP、账号、认证方式、会话开始结束 |
| sudo I/O logging | sudoers + 集中存储 | 特权命令和终端会话；敏感环境需评估内容与隐私 |
| eBPF / EDR Agent | Elastic Defend、Falco、商业 EDR 等 | 进程、文件、网络和容器运行时高精度行为 |
| osquery | 定时查询 / 事件表 | 用户、进程、服务、计划任务和系统状态补充 |

Linux 最低可行采集范围是 SSH/PAM 登录、sudo/su、`auditd execve`、账号与组变更、cron/systemd 持久化和关键文件权限变化。容器环境还需关联 `container.id`、Pod、Namespace、Service Account 与宿主机。

### 3.5 关联键与实体图谱

Zeek 会为一次网络连接生成 `uid`。同一次连接产生的 `conn.log`、`dns.log`、`ssl.log`、`http.log` 等记录可通过 `uid` 关联。

```text
conn.log（uid = C8abc...）
  ↕
dns.log / tls.log / http.log / files.log（uid = C8abc...）
```

关联后的连接能够同时具备：连接规模、服务识别、DNS 域名、TLS 指纹和 HTTP Host 等上下文。

`community_id` 可以用于与 Suricata、防火墙、NetFlow 等其他网络设备日志对齐，但在 Zeek 内部关联时优先使用 `uid`。

UEBA 还需要以下跨源关联键：

| 实体 | 优先稳定键 | 辅助关联键 | 注意事项 |
| --- | --- | --- | --- |
| 用户 | HR/IdP 稳定人员 ID、`user.id` | 邮箱、UPN、员工号 | 姓名和邮箱可能变化，不应作为唯一主键 |
| 账号 | AD ObjectGUID/SID、IdP account ID、`account.id` | `domain\\username`、Linux UID | 个人、共享、服务和机器账号必须区分 |
| 主机 | EDR device ID、CMDB asset ID、`host.id` | hostname、IP、MAC | hostname/IP 可复用，必须支持事件时间映射 |
| 会话 | IdP/VPN session ID、Windows `LogonId`、SSH session | 用户 + 主机 + 源 IP + 时间 | 会话键需包含来源系统和主机范围 |
| 进程 | EDR/Sysmon ProcessGuid、`process.entity_id` | PID + host + start_time | PID 会复用，不能单独作为全局键 |
| 网络连接 | Zeek UID、community_id | 五元组 + 时间桶 | NAT、代理和负载均衡会改变地址 |
| 云/容器身份 | cloud principal ID、service account ID | 角色、租户、Namespace | 人员身份与工作负载身份分开建模 |

建议维护实体关系图：

```text
person/user.id
  ├── account.id（AD / IdP / Linux / PAM）
  ├── peer_group（部门、岗位、区域、权限等级）
  └── session.id
        ├── source.ip / geo / device
        ├── host.id
        │     └── process.entity_id
        ├── accessed_resource
        └── destination_key / network connection
```

共享账号、服务账号和机器账号没有可靠人员归属时，应以账号实体单独建立基线；不能为了形成用户画像而错误绑定到最近登录的个人。

## 4. 统一 UEBA 行为事件模型

AD、Windows、Linux、IdP 和 Zeek 原始字段不直接作为检测与场景规则的输入。应先转换为统一事件模型。以下是已经与用户会话关联的“归一化连接事件”示例；身份无法可靠关联时，保留空值和关联质量，不能猜测用户。

```json
{
  "@timestamp": "2026-09-02T10:03:12.123Z",
  "event": {
    "id": "zeek-gw-01-C8abc",
    "kind": "event",
    "category": ["network"],
    "type": ["connection"],
    "dataset": "zeek.conn"
  },
  "user": {
    "id": "USR-00023",
    "name": "zhangsan",
    "department": "finance",
    "risk_tier": "high_value"
  },
  "account": {
    "id": "S-1-5-21-...-1108",
    "name": "CORP\\zhangsan",
    "type": "person"
  },
  "session": {
    "id": "vpn-20260902-88721",
    "type": "vpn_to_windows_logon"
  },
  "host": {
    "id": "PC-023",
    "name": "FIN-PC-023",
    "os": {
      "type": "windows"
    }
  },
  "source": {
    "ip": "10.10.2.15",
    "port": 52341,
    "bytes": 85231,
    "packets": 85
  },
  "destination": {
    "ip": "203.0.113.8",
    "port": 443,
    "bytes": 6102,
    "packets": 29
  },
  "network": {
    "transport": "tcp",
    "protocol": "tls",
    "application": "https",
    "direction": "outbound",
    "community_id": "1:abc..."
  },
  "zeek": {
    "uid": "C8abc",
    "service": ["ssl"],
    "conn_state": "SF",
    "duration": 2.6
  },
  "tls": {
    "version": "1.3",
    "server_name": "example.com",
    "ja4": "t13d...",
    "alpn": ["h2"],
    "server": {
      "x509": {
        "issuer": {
          "common_name": "Example CA"
        }
      }
    }
  },
  "asset": {
    "id": "PC-023",
    "role": "office_endpoint",
    "zone": "office",
    "owner": "zhangsan"
  },
  "destination_context": {
    "is_internal": false,
    "is_approved": false,
    "asn": 12345,
    "country": "US"
  },
  "entity_correlation": {
    "method": "vpn_ip_and_logon_session",
    "confidence": 0.94,
    "valid_at_event_time": true
  }
}
```

### 4.1 字段说明

| 字段 | 含义 | 典型来源 | 检测用途 |
| --- | --- | --- | --- |
| `@timestamp` | 网络事件真实发生时间，使用 Zeek 的 `ts` 转换 | Zeek | 所有事件时间窗口的依据 |
| `event.id` | 事件唯一标识，建议由传感器标识和 Zeek `uid` 组成 | 清洗层 | 去重和证据回溯 |
| `event.kind` | 事件大类；本例为普通网络事件 | 清洗层 | 统一检索分类 |
| `event.category` | 事件分类列表；本例为网络 | 清洗层 | 统一检索分类 |
| `event.type` | 事件类型列表；本例为连接 | 清洗层 | 区分连接、DNS、TLS 等事件 |
| `event.dataset` | 数据集名称 | 清洗层 | 标识 Zeek 日志来源和类型 |
| `user.id` | 稳定的人员实体 ID | HR/IdP/身份映射 | 跨账号和跨设备用户画像 |
| `account.id` | 账号稳定 ID，如 AD SID/ObjectGUID | AD、IdP、Linux | 账号基线、共享/服务账号区分 |
| `account.type` | `person`、`shared`、`service`、`machine` 等 | IAM/CMDB/规则 | 选择正确的基线和检测场景 |
| `session.id` | VPN、IdP、Windows 或 SSH 会话标识 | 源日志/关联层 | 在会话范围内组合行为序列 |
| `host.id` | 设备稳定 ID | EDR/CMDB | 用户—设备—进程—网络关联 |
| `entity_correlation.method` | 身份与网络/主机关联方式 | 关联层 | 解释关联依据 |
| `entity_correlation.confidence` | 关联可信度 | 关联层 | 低置信关联不可用于高危自动处置 |
| `source.ip` | 发起连接的一端 IP 地址 | `id.orig_h` | 主机、源地址聚合 |
| `source.port` | 发起连接的源端口 | `id.orig_p` | 五元组和协议分析 |
| `source.bytes` | 源端向目的端发送的字节数；对出站流量通常代表上行量 | `orig_bytes` | 外发流量、上行比例、周期通信 |
| `source.packets` | 源端向目的端发送的报文数 | `orig_pkts` | 连接和报文形态分析 |
| `destination.ip` | 被访问的目标 IP 地址 | `id.resp_h` | 目的地画像、内外网判断 |
| `destination.port` | 被访问的目标端口 | `id.resp_p` | 协议端口不匹配、扫描检测 |
| `destination.bytes` | 目的端向源端发送的字节数；对出站流量通常代表下行量 | `resp_bytes` | 上下行比例分析 |
| `destination.packets` | 目的端向源端发送的报文数 | `resp_pkts` | 连接和报文形态分析 |
| `network.transport` | 传输层协议，如 `tcp`、`udp` | `proto` | 端口策略和协议识别 |
| `network.protocol` | 实际识别出的主要应用协议，如 `dns`、`tls`、`http` | `service`、关联日志 | 协议端口不匹配 |
| `network.application` | 面向业务的应用名称，如 `https` | 清洗层推导 | 展示与辅助分析 |
| `network.direction` | 网络方向，如 `outbound`、`inbound`、`internal` | 网段富化 | 外联、横向行为判断 |
| `network.community_id` | 跨设备关联连接的标准化标识 | Zeek/其他设备 | Zeek、Suricata、流设备关联 |
| `zeek.uid` | Zeek 对一次连接生成的唯一 ID | Zeek | Zeek 多类日志关联的主键 |
| `zeek.service` | Zeek 识别出的服务列表 | `service` | 保存完整识别结果 |
| `zeek.conn_state` | Zeek 连接状态代码，如 `SF` 表示正常完成 | `conn_state` | 失败率、扫描和重试分析 |
| `zeek.duration` | 连接持续时间，单位秒 | `duration` | 周期通信和连接形态分析 |
| `tls.version` | TLS 协议版本 | `ssl.log` / `tls.log` | 罕见或过旧 TLS 检测 |
| `tls.server_name` | TLS ClientHello 中的 SNI 域名 | `server_name` | 目的地归属、无 SNI 检测 |
| `tls.ja4` | TLS 客户端握手指纹；没有 JA4 时可使用 JA3 | TLS 日志/扩展脚本 | 客户端指纹的新颖度检测 |
| `tls.alpn` | TLS 协商的应用层协议，如 `h2` | TLS 日志 | TLS 行为画像 |
| `tls.server.x509.issuer.common_name` | 服务端证书签发者名称 | TLS 证书日志 | 自签名、罕见证书辅助判断 |
| `asset.id` | 稳定的资产唯一标识，不应仅使用动态 IP | CMDB、EDR、DHCP 映射 | 主机画像、基线和例外策略 |
| `asset.role` | 资产角色，如办公终端、服务器、跳板机 | CMDB | 同类主机分组和规则例外 |
| `asset.zone` | 资产所在安全区域 | 网段表、CMDB | 内外网和横向移动判断 |
| `asset.owner` | 资产责任人或当前使用人 | CMDB、EDR、DHCP/VPN 映射 | 告警归属和调查 |
| `destination_context.is_internal` | 目标是否位于企业内部受管网段 | 网段表 | 外联与横向通信判断 |
| `destination_context.is_approved` | 目标是否位于批准服务清单 | 白名单表 | 降低正常业务误报 |
| `destination_context.asn` | 目标 IP 所属自治系统编号 | GeoIP/ASN 库 | 目的地聚合与新颖度判断 |
| `destination_context.country` | 目标 IP 对应国家/地区代码 | GeoIP 库 | 辅助调查与地理策略 |

### 4.2 统一身份与主机行为字段

不同来源映射到统一字段后，场景规则不需要直接依赖 Windows Event ID 或 Linux 原始文本。建议至少统一以下语义：

| 统一字段 | 示例 | 说明 |
| --- | --- | --- |
| `event.category` | `authentication`、`iam`、`process`、`network`、`configuration` | 行为大类 |
| `event.action` | `logon-success`、`group-member-added`、`process-started`、`sudo-command` | 标准化动作 |
| `event.outcome` | `success`、`failure`、`unknown` | 行为结果 |
| `authentication.type` | `kerberos`、`ntlm`、`password`、`mfa`、`ssh-key` | 认证方式 |
| `logon.type` | `interactive`、`network`、`remote_interactive`、`service` | Windows/Linux 归一化会话类型 |
| `group.id/name` | `Domain Admins` | 权限组或角色 |
| `privilege.level` | `normal`、`local_admin`、`domain_admin`、`root` | 统一权限等级 |
| `process.entity_id` | Sysmon ProcessGuid / EDR entity ID | 稳定的进程实例标识 |
| `process.parent.entity_id` | 父进程实体 ID | 进程树关联 |
| `file.path` / `registry.path` | 关键文件或注册表路径 | 配置、持久化和敏感对象访问 |
| `resource.id/type` | 文件服务器、数据库、SaaS、Linux 主机 | 被访问资源统一标识 |
| `source.geo.*` / `device.id` | 登录来源地理与设备 | 登录基线和会话关联 |

原始字段、原始 Event ID、audit key 和原始日志引用必须保留，统一字段用于检测，原始字段用于取证和校准。

## 5. 多源采集与 Logstash 实现

### 5.1 Zeek / Filebeat 采集

建议 Zeek 输出 JSON。Filebeat 读取不同日志文件时，为日志附加固定来源标签。

```yaml
filebeat.inputs:
  - type: filestream
    id: zeek-conn
    paths:
      - /opt/zeek/logs/current/conn.log
    parsers:
      - ndjson:
          target: ""
    fields:
      log_source: zeek
      zeek_log_type: conn
    fields_under_root: true

  - type: filestream
    id: zeek-dns
    paths:
      - /opt/zeek/logs/current/dns.log
    parsers:
      - ndjson:
          target: ""
    fields:
      log_source: zeek
      zeek_log_type: dns
    fields_under_root: true

  - type: filestream
    id: zeek-tls
    paths:
      - /opt/zeek/logs/current/ssl.log
      - /opt/zeek/logs/current/tls.log
    parsers:
      - ndjson:
          target: ""
    fields:
      log_source: zeek
      zeek_log_type: tls
    fields_under_root: true
```

配置字段说明：

| 字段或配置 | 含义 |
| --- | --- |
| `type: filestream` | Filebeat 文件采集器类型，适合持续追加的日志文件 |
| `id` | 本采集输入的唯一名称，避免不同输入状态冲突 |
| `paths` | 要读取的 Zeek 日志文件路径 |
| `parsers.ndjson` | 将每行 JSON 日志解析为字段，而不是作为纯文本消息 |
| `target: ""` | 将 JSON 的字段写入事件根对象，而非嵌套对象 |
| `log_source` | 自定义字段，标记日志来自 Zeek |
| `zeek_log_type` | 自定义字段，标记当前记录的 Zeek 日志类型 |
| `fields_under_root` | 将 `fields` 中的自定义字段直接放在根对象 |

#### 5.1.1 Windows AD 与 Windows 主机采集

推荐拓扑：

```text
域控制器 / Windows 服务器 / Windows 终端
  → Windows Event Forwarding（源发起订阅）
  → Windows Event Collector 集群
  → Winlogbeat / Elastic Agent
  → Logstash / Kafka
```

源发起订阅便于大规模部署；Collector 需要容量规划、高可用、订阅分组和事件积压监控。域控安全日志、普通服务器日志和高噪声 Sysmon 日志建议拆分订阅与 Kafka 主题，避免单一队列互相影响。

关键配置原则：

- 先定义审计策略和目标 Event ID，再决定采集范围，避免无差别全量采集导致成本失控；
- 开启 4688 命令行、PowerShell Script Block 或 Transcription 前评估口令、令牌和业务参数泄露风险；
- Sysmon 配置必须版本化，并对规则变更前后的事件量和字段完整性做监控；
- 域控上尽量只保留系统审计和转发组件，复杂解析放在 Logstash/Ingest/Flink；
- WEF 事件必须保留原始 `computer`、`channel`、`provider`、`event.code`、`record_id` 与生成时间。

#### 5.1.2 Linux 主机采集

推荐最小拓扑：

```text
auditd → Auditbeat / Elastic Agent ┐
journald / auth.log → Agent/rsyslog ├→ Logstash / Kafka
EDR / eBPF Agent → 厂商连接器       ┘
```

关键配置原则：

- 为 auditd 规则设置稳定 `key`，例如 `identity_change`、`privilege_use`、`persistence`、`sensitive_config`；
- 进程事件保留 `auid`、`uid`、`euid`、`ses`、`tty`、`exe`、`cwd` 和 `execve` 参数，区分登录用户与有效执行用户；
- SSH、sudo、su、cron、systemd、账号/组变化和关键配置文件至少进入第一期采集；
- 容器主机需要补齐容器、Pod、Namespace、Service Account 标签，避免把短生命周期容器当成普通主机；
- 对高频 `execve` 和文件审计进行容量测试，使用明确的排除规则，不能因为数据量大而静默丢弃。

### 5.2 Logstash 清洗

Logstash 只处理单条事件：时间转换、字段重命名、类型转换和查表富化。以下是 `conn.log` 的简化示例。

```ruby
filter {
  if [zeek_log_type] == "conn" {
    date {
      match => ["ts", "UNIX"]
      target => "@timestamp"
    }

    mutate {
      rename => {
        "[id][orig_h]" => "[source][ip]"
        "[id][orig_p]" => "[source][port]"
        "[id][resp_h]" => "[destination][ip]"
        "[id][resp_p]" => "[destination][port]"
        "orig_bytes" => "[source][bytes]"
        "resp_bytes" => "[destination][bytes]"
        "orig_pkts" => "[source][packets]"
        "resp_pkts" => "[destination][packets]"
        "proto" => "[network][transport]"
        "uid" => "[zeek][uid]"
        "conn_state" => "[zeek][conn_state]"
      }
      convert => {
        "[source][port]" => "integer"
        "[destination][port]" => "integer"
        "[source][bytes]" => "integer"
        "[destination][bytes]" => "integer"
        "[source][packets]" => "integer"
        "[destination][packets]" => "integer"
      }
    }
  }
}
```

处理规则：

- 用 Zeek 的 `ts` 填充 `@timestamp`，不要用 Filebeat 接收日志的时间；
- 将空服务识别值与“明确识别为其他协议”区分开；空值只代表未知或解析不完整，不能直接作为协议伪装证据；
- `service` 统一保存为字符串数组，避免同字段既为字符串又为数组；
- 基于 `sensor_id + zeek.uid + log_type` 生成去重键；
- 原始字段可保留在 `zeek.raw` 或独立原始索引，便于排错和回溯。

### 5.3 ELK 在系统中的完整落地方式

本方案中的 ELK 不只是日志查询界面，而是承担标准化、热数据检索、低规模特征聚合、规则执行、证据回查和运营展示。ELK 各组件的边界如下：

```text
Filebeat
  → 读取 Zeek JSON、标记日志类型、可靠转发
  ↓
Logstash
  → 清洗、类型转换、基础富化、事件路由
  ↓
Elasticsearch Data Stream
  → 保存标准化原始事件
  ↓
Elasticsearch Transform / 定时聚合任务
  → 生成 5 分钟、1 小时、1 天特征索引
  ↓
检测任务 / 流计算结果回写
  → 生成原子告警和风险案件
  ↓
Kibana
  → 仪表盘、规则运营、案件调查、原始证据回查
```

#### 5.3.1 Elasticsearch 数据流

建议按数据集拆分 Data Stream，而不是将所有 Zeek 日志写入一个大索引：

```text
logs-zeek.conn-default
logs-zeek.dns-default
logs-zeek.tls-default
logs-zeek.http-default
logs-zeek.weird-default
```

拆分的原因：不同日志的字段结构、查询方式、数据量和保留周期不同。`conn` 和 `dns` 通常数据量最大，可以使用更短的热存储周期；告警和案件量较小，可保留更长时间。

推荐的通用数据流字段：

```json
{
  "data_stream": {
    "type": "logs",
    "dataset": "zeek.conn",
    "namespace": "default"
  },
  "event": {
    "ingested": "2026-09-02T10:03:13.010Z",
    "original": "{...}"
  },
  "observer": {
    "name": "zeek-gw-01",
    "type": "network",
    "product": "Zeek"
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `data_stream.type` | 数据流类型；网络日志统一使用 `logs` |
| `data_stream.dataset` | 数据集名称，用于区分 `zeek.conn`、`zeek.dns` 等日志 |
| `data_stream.namespace` | 环境或租户命名空间，如 `default`、`prod`、`office` |
| `event.ingested` | Elasticsearch 接收到事件的时间，用于监控采集延迟 |
| `event.original` | 可选的原始日志文本；用于排错，需评估存储成本 |
| `observer.name` | 产生日志的 Zeek 传感器名称 |
| `observer.type` | 观察设备类型；本例为网络传感器 |
| `observer.product` | 产生事件的产品名称；本例为 Zeek |

#### 5.3.2 Mapping 与索引模板

必须通过 Index Template 固定关键字段类型，避免 Elasticsearch 动态映射把端口、字节数或布尔值映射为字符串。

| 字段类型 | 示例字段 | Elasticsearch 类型 |
| --- | --- | --- |
| 时间 | `@timestamp`、`event.ingested` | `date` |
| IP | `source.ip`、`destination.ip` | `ip` |
| 端口、计数 | `source.port`、`query_count` | `integer` 或 `long` |
| 字节数 | `source.bytes`、`outbound_bytes` | `long` |
| 比例、熵、模型分数 | `failed_ratio`、`avg_subdomain_entropy` | `double` |
| 精确聚合文本 | `asset.id`、`network.protocol`、`destination_key` | `keyword` |
| 可全文检索说明 | 告警描述、分析备注 | `text`，必要时附带 `keyword` 子字段 |
| 布尔值 | `is_approved`、`event.late` | `boolean` |

`dns.question.name`、`tls.server_name`、`destination_key` 等用于分组的字段必须是 `keyword`。高基数字段不应开启不必要的全文分析，也不应在 Kibana 中默认加载全部唯一值。

#### 5.3.3 ILM 生命周期管理

根据数据价值区分生命周期：

```text
原始 conn/dns/tls：热层 7～14 天 → 温层 30～90 天 → 删除或归档
窗口特征：热层 30 天 → 温层 180 天
原子告警：热层 90 天 → 温/冷层 1 年或按合规要求
风险案件：长期保留，按案件状态与合规要求决定
```

实际周期应由每日事件量、磁盘容量、调查回溯周期和监管要求共同确定。原始日志量大时，优先保留聚合特征和告警证据引用，而不是无限延长热数据存储。

#### 5.3.4 Elasticsearch Transform 计算窗口特征

低数据量或 PoC 阶段，可以用 Continuous Transform 将原始事件持续汇总到特征索引。例如按 `asset.id + destination_key + 5分钟` 生成连接特征：

```json
{
  "transform_id": "net-conn-5m-feature",
  "source_index": "logs-zeek.conn-*",
  "destination_index": "net-conn-feature-5m",
  "sync_field": "@timestamp",
  "sync_delay": "120s",
  "group_by": [
    "asset.id",
    "destination_key",
    "@timestamp/5m"
  ],
  "aggregations": [
    "connection_count",
    "outbound_bytes",
    "inbound_bytes",
    "unique_dst_ip_count",
    "unique_dst_port_count",
    "failed_connection_count"
  ]
}
```

该对象是设计层抽象，不是可直接提交的 Elasticsearch API 请求；正式配置需转换为实际 Transform DSL。

| 字段 | 含义 |
| --- | --- |
| `transform_id` | 特征汇总任务的唯一名称 |
| `source_index` | Transform 读取的原始数据流或索引模式 |
| `destination_index` | 聚合特征写入的目标索引 |
| `sync_field` | 增量同步依据的事件时间字段 |
| `sync_delay` | 为迟到日志预留的等待时间，本例为 120 秒 |
| `group_by` | 聚合维度，本例按资产、目的地和 5 分钟时间桶分组 |
| `aggregations` | 需要计算的计数、总和、去重数和状态数量 |

需要注意：Continuous Transform 更适合固定时间桶。真正的“5 分钟窗口、每 1 分钟滑动一次”会产生重叠窗口，使用 Flink 更自然。只有 ELK 时，可以每分钟执行一次“查询最近 5 分钟”的任务并使用确定性窗口 ID 覆盖写入，但要自行处理重复、迟到修正和任务并发。

#### 5.3.5 ELK 规则执行路径

ELK 内可以实现三类基础检测；复杂高吞吐序列建议放在 Flink/专用场景引擎：

1. **确定性单事件规则**：直接查询原始事件，例如高权限组变化、停用账号登录、协议与端口不匹配；
2. **聚合/基线规则**：查询用户或实体特征索引，例如登录失败率、首次设备、5 分钟内目标主机数或 1 小时上行量；
3. **低频组合/序列规则**：通过 EQL/ES|QL/告警编排匹配有限步骤的行为链，适合 PoC 或低吞吐场景。

规则、基线和场景任务输出统一写入 `ueba-signal-*`、`ueba-scenario-match-*` 或 `ueba-detection-event-*`，不要只保留在 Kibana 的临时告警状态中。这样案件引擎、外部 SIEM 和模型分析可以使用同一份证据。

#### 5.3.6 Kibana 页面规划

建议至少提供六组视图：

| 页面 | 主要内容 | 使用者 |
| --- | --- | --- |
| 采集健康 | AD/WEF、IdP、Windows、Linux、Zeek 各来源事件量、延迟、解析失败、迟到率、字段缺失率 | 平台运维 |
| 身份与权限 | 登录、MFA、账号状态、权限组/角色变化、PAM 会话 | IAM、安全运营 |
| 用户与实体画像 | 用户常用设备/来源/时段/资源，账号类型，Windows/Linux 主机行为基线 | 安全运营 |
| 网络概览 | 内外网流量、协议分布、外部目的地、DNS 与 TLS 趋势 | 安全运营 |
| 异常检测 | 按判定方法展示确定性规则、基线、组合、序列和模型信号 | 安全分析 |
| UEBA 案件调查 | 用户—账号—会话—主机—进程—网络完整时间线、证据、例外和处置状态 | 事件调查人员 |

### 5.4 ELK 与 Kafka/Flink 的组合选择

| 部署方式 | 适用条件 | 优点 | 局限 |
| --- | --- | --- | --- |
| Filebeat + Logstash + Elasticsearch + Kibana | PoC、数据量小、分钟级时效可接受 | 组件少、上线快 | 重叠滑动窗口、乱序和复杂状态处理较弱 |
| Filebeat + Logstash + Kafka + Flink + Elasticsearch + Kibana | 生产环境、高吞吐、需要秒到分钟级检测 | 状态、Watermark、重放和滑动窗口能力完整 | 组件和运维复杂度更高 |
| Filebeat + Kafka + 流计算 + Elasticsearch | 清洗逻辑已在流计算中统一实现 | 链路更短、吞吐高 | 需自行补齐 Logstash 常用解析和富化能力 |

推荐路线是：PoC 阶段使用 ELK 快速验证统一字段、确定性规则、基线和低频场景；数据量增大后，将高基数实体状态、复杂行为序列、重叠滑动窗口、周期通信和模型实时推理迁移到 Kafka/Flink/专用场景引擎，Elasticsearch 继续承担存储、检索、调查和离线回算。

## 6. 必要富化数据

UEBA 原始日志只有账号名、主机名、IP 或事件码，不能直接支撑低误报检测。至少应维护如下参考表。

| 参考表 | 查询键 | 富化输出 | 说明 |
| --- | --- | --- | --- |
| 人员与组织表 | HR/IdP user ID、员工号、UPN | 部门、岗位、经理、区域、在职状态、风险等级 | 用户画像、同类群组和离职账号检测 |
| 账号目录表 | SID/ObjectGUID、IdP ID、Linux UID | `account.id`、账号类型、人员归属、状态 | 区分个人、共享、服务和机器账号 |
| 权限与角色表 | 账号、组、云角色 | 权限等级、关键权限、有效期、审批信息 | 提权、权限滥用和高价值账号检测 |
| IdP/VPN/PAM 会话表 | session ID、用户、源 IP、事件时间 | 设备、来源、MFA、审批单、会话边界 | 登录与后续主机/网络行为关联 |
| 资产表 / CMDB | 源 IP、MAC、主机名、EDR 设备 ID | 资产 ID、角色、部门、责任人、区域 | 建立主机基线和规则例外 |
| DHCP / VPN 映射表 | IP + 事件时间 | 资产 ID、用户 | 解决动态 IP 与远程接入映射 |
| 网段表 | IP/CIDR | 内外网属性、安全区域 | 判定出站流量与横向流量 |
| 端口协议策略表 | 端口 + 传输协议 | 允许协议集合、默认严重度 | 协议端口不匹配 |
| 批准目的地表 | 域名、CIDR、ASN | 服务名、类别、有效期 | 识别批准 SaaS 与合作方 |
| 规则例外表 | 资产、网段、目的地、端口、协议 | 例外原因、有效期、降级策略 | 减少定制服务误报 |
| Public Suffix List | FQDN | 注册主域、子域 | DNS 隧道聚合 |
| GeoIP / ASN 表 | 目的 IP | 国家、ASN、组织名称 | 目的地画像和调查 |
| 业务资源目录 | 主机、数据库、SaaS、文件共享、应用 ID | 资源类型、数据级别、责任人、重要性 | 判断异常访问和案件影响范围 |
| 变更/工单/值班表 | 用户、资产、时间范围、工单 ID | 已批准操作、维护窗口、审批人 | 区分正常运维与未授权行为 |

身份、权限、IP 到资产和组织归属的映射必须支持事件时间查询。例如 DHCP 租约、部门、岗位、账号状态或权限组发生变化后，历史事件仍应使用当时有效的关系，而不是当前快照覆盖历史归属。

## 7. 时间语义、去重与滑动窗口

### 7.1 三种时间

| 时间字段 | 含义 | 使用位置 |
| --- | --- | --- |
| `event_time` | 行为实际发生的时间，来自 Zeek `ts`、Windows `TimeCreated`、IdP/AD/Linux 事件时间等 | 窗口、基线、序列和规则判断的唯一时间依据 |
| `ingest_time` | Filebeat 或 Logstash 接收到日志的时间 | 链路延迟与采集质量监控 |
| `process_time` | 流计算引擎处理该事件的时间 | 系统性能和处理延迟监控 |

所有检测窗口必须基于 `event_time`。如果按接收时间计算，日志积压、链路抖动或传感器短暂离线都会造成误报或漏报。

### 7.2 Watermark 与迟到数据

建议允许日志最多迟到 2 分钟：

```text
watermark = 当前已观测到的最大 event_time - 2分钟
```

当一个窗口的结束时间早于 watermark 时，窗口关闭并计算结果。例如：

```text
10:00:00 至 10:05:00 的窗口，
当系统已看到 10:07:00 之后的事件时关闭。
```

超过允许迟到时间的日志不应静默丢弃。应写入原始索引并标记 `event.late = true`，随后通过窗口更正或离线回算修正结果。

### 7.3 去重键

去重键必须按数据源定义，不能对所有事件套用 Zeek UID：

```text
Zeek：sensor_id + zeek.uid + zeek_log_type
Windows/WEF：collector + channel + computer + record_id
IdP/VPN/PAM：tenant/source + provider_event_id
Linux auditd：host.id + boot_id + audit_sequence / serial
Syslog：host.id + source + event_time + message_hash（仅在没有稳定 ID 时使用）
```

原因是 WEF 转发、Beats 重传、Logstash 重试以及 Kafka 的“至少一次投递”都可能导致重复数据；重复会直接放大登录失败、权限变更、进程次数、DNS 查询、字节量和扫描次数。不同来源的真实重复行为不能被粗粒度哈希误删。

## 8. UEBA 检测编排与判定框架

### 8.1 核心原则：先定义场景，再选择判定方法

UEBA 不应先计算一个统一风险分，再用分数决定所有行为是否危险。正确顺序是：

```text
业务风险场景
  → 明确实体、时间、顺序、次数和必要证据
  → 选择适合的判定方式
  → 产生原子信号或场景命中
  → 执行例外、质量和关联置信度检查
  → 进入案件关联与优先级排序
```

每个检测场景必须声明 `detection_method`：

| 判定方式 | 适用问题 | 输出 | 是否依赖总分 |
| --- | --- | --- | --- |
| `deterministic_rule` 确定性规则 | 行为本身明确违反策略或具有足够高的风险 | 直接告警或高置信原子信号 | 否 |
| `baseline_anomaly` 基线 + 异常 | 当前行为是否明显偏离用户/实体自身或同类历史 | 一个或多个基线异常信号 | 否 |
| `composite_pattern` 异常组合 | 多个弱异常同时出现是否构成一个场景 | 组合场景命中 | 否，可用分数选择组合阈值，但必须保留条件 |
| `sequence_pattern` 行为序列 | 多个行为按顺序和时间约束是否形成攻击链 | 序列场景命中 | 否 |
| `statistical_model` 统计/ML | 多维组合是否罕见，且无法用简单规则完整描述 | 候选异常信号 | 模型可输出分数，但分数不是攻击概率 |
| `risk_aggregation` 风险聚合 | 已成立的信号和场景哪个更应优先调查 | 案件优先级、升级或抑制建议 | 是，但只用于排序和案件层 |

禁止出现以下设计：

- 所有事件先加减分，达到 60 就统一认定为攻击；
- 高置信确定性规则因模型低分而被取消；
- 多个相互无关的低风险事件仅因分数相加而组成高危案件；
- 模型异常分直接解释为“攻击概率”；
- 缺少身份关联或数据质量不足时仍自动形成高危用户案件。

### 8.2 原子信号标准

任何方法输出的原子信号都应包含：

```json
{
  "signal_id": "sig-ueba-20260902-001",
  "signal_type": "unusual_login_source",
  "detection_method": "baseline_anomaly",
  "entity": {
    "user_id": "USR-00023",
    "account_id": "S-1-5-21-...-1108",
    "host_id": "PC-023",
    "session_id": "vpn-20260902-88721"
  },
  "event_time": "2026-09-02T21:48:00Z",
  "severity": "medium",
  "confidence": 0.86,
  "evidence": {
    "current_country": "US",
    "usual_countries": ["CN"],
    "first_seen_device": true,
    "user_baseline_percentile": 99.6
  },
  "source_event_refs": ["idp-event-77821"],
  "quality": {
    "identity_correlation_confidence": 0.98,
    "required_fields_complete": true
  }
}
```

原子信号是场景编排的输入。它必须说明“哪种方法、基于什么证据、对哪个实体成立”，而不只是一个数字。

### 8.3 确定性规则

适合“符合即异常或至少必须调查”的行为。示例：

- 非授权账号被加入 Domain Admins、Enterprise Admins 或等价关键角色；
- 已停用/离职账号恢复并成功登录；
- 普通用户创建新的域信任、修改关键 GPO、委派或敏感 ACL；
- Linux 非批准账号直接获得 UID 0、修改 `/etc/sudoers` 或创建隐藏特权账号；
- 明确恶意目的地、已知阻断协议、确认的凭据转储工具等高置信行为；
- 服务账号发生交互式登录，而策略明确禁止。

确定性规则也必须检查作用域、审批、变更窗口和账号类型，但不能因为用户历史上“经常这样做”而自动视为正常。

### 8.4 基线 + 异常

基线用于回答“这次行为相对这个用户/实体是否异常”，可单独产生信号，也可作为组合或序列的条件。至少建立：

| 基线对象 | 典型特征 | 对比方式 |
| --- | --- | --- |
| 用户登录基线 | 常用设备、来源网段、国家、登录时间、认证方式、并发会话 | 用户自身 7/30/90 天 + 同岗位/同区域群组 |
| 账号使用基线 | 登录类型、目标主机、调用服务、权限使用、失败率 | 个人/共享/服务/机器账号分别建模 |
| Windows 主机基线 | 常用用户、父子进程、PowerShell 使用、服务/任务变更、远程登录 | 主机自身 + 同角色主机 |
| Linux 主机基线 | SSH 来源、sudo 用户/命令、进程、cron/systemd、敏感文件 | 主机自身 + 同环境服务器 |
| 资源访问基线 | 常用文件共享、数据库、SaaS、服务器和访问时段 | 用户自身 + 部门/岗位同类 |
| 网络基线 | 目的地、协议、端口、流量、周期、DNS/TLS 指纹 | 用户、账号、主机和同类实体 |

基线异常不能只使用平均值和固定倍数。根据特征使用分位数、MAD、频率/新颖度、类别分布或时间序列方法，并保留冷启动策略：

```text
个人历史充足 → 用户自身基线 + 同类基线
个人历史不足 → 同岗位/同权限/同区域基线
同类样本不足 → 更粗粒度群组
仍不足 → 仅输出“新颖度/数据不足”，不自动判高危
```

### 8.5 异常组合：多个弱信号构成一个场景

组合场景不是简单加总任意分数，而是定义必要条件、可选增强条件、时间范围和排除条件。

示例：**可疑账号接管**

```text
时间范围：30分钟
聚合键：user.id 或 account.id

必要条件：
  登录成功

异常条件至少满足 2 项：
  - 来源国家/网段偏离用户基线
  - 首次设备或设备不受管
  - 非常用认证方式，或 MFA 行为异常
  - 登录时间偏离用户和同类基线
  - 登录前存在密码喷洒/高失败率

增强条件任一：
  - 登录后访问高价值资源
  - 登录后发生提权或凭据操作
  - 登录后出现异常外联或大流量上传

排除条件：
  - 已批准出差、应急值班或跳板机/PAM 会话
```

示例：**内部人员异常数据访问**

```text
基线异常：访问资源数量或读取量超过用户自身 P99/MAD 阈值
+ 新颖度：首次访问高价值资源或跨部门资源
+ 时间/设备异常：非工作时间、非常用设备或远程会话
+ 后续行为：压缩、云盘上传、异常 DNS/TLS/外联任一成立
→ 形成 UEBA 场景，而不是把四个低风险分数无条件相加
```

### 8.6 行为序列：按顺序匹配风险链

序列检测必须支持事件顺序、最大间隔、整体窗口、允许缺失和排除条件。典型场景：

#### 场景 A：账号失陷 → 提权 → 横向移动 → 外联

```text
T0：非常用来源或设备登录成功
  在 30 分钟内
T1：特权登录、组成员变化、显式凭据使用或异常 sudo
  在 60 分钟内
T2：远程服务访问、SMB/RDP/WinRM/SSH 扩散或内网扫描
  在 120 分钟内
T3：首次目的地、周期回连、DNS 隧道或异常上行
```

T1 的关键权限变更本身可由确定性规则直接告警；完整 T0→T3 序列命中后再形成更高置信的“账号失陷与横向移动”案件。

#### 场景 B：Linux 账号失陷与持久化

```text
首次/非常用 SSH 来源登录
→ sudo/su 到 root 或异常特权命令
→ 创建用户、修改 authorized_keys、cron 或 systemd service
→ 访问此前未使用的生产资源或外部目的地
```

#### 场景 C：AD 权限滥用与痕迹清理

```text
普通账号进入高权限组
→ 使用显式凭据或特权登录访问多台关键主机
→ 短时间内从高权限组移除或删除新建账号
```

序列引擎应在案件中保留未命中的可选步骤和每一步原始事件，便于分析人员判断链路是否完整。

### 8.7 统计/机器学习模型

模型适合发现无法用少数阈值表达的联合异常，例如用户在一个小时内同时出现：新设备比例略高、资源访问范围略高、PowerShell 使用略高、外联目的地新颖度略高。每项都不够单独告警，但组合显著偏离同岗位用户。

模型输出只能作为 `statistical_model` 原子信号或场景增强条件。关键限制：

- 人员姓名、账号字符串、IP、域名和事件 ID 不直接作为数值特征；
- 训练与推理使用相同的特征版本、缺失值和预处理；
- 用户、服务账号、主机、容器和网络目的地应选择不同样本粒度和同类群组；
- 数据质量不足、身份关联置信度低或群组样本不足时不评分；
- 模型低分不得取消确定性规则或完整序列命中。

### 8.8 风险评分只用于案件优先级

风险评分可以融合已经成立的证据，但必须保留证据之间的关系：

```text
case_priority =
  场景基础风险
  + 关键资产/高权限账号影响修正
  + 多源证据一致性修正
  + 高置信规则/完整序列升级
  + 基线或模型异常增强
  - 有效例外/已批准变更降级
  - 数据质量或关联不确定性降级
```

推荐优先级策略：

| 情况 | 处理 |
| --- | --- |
| 高置信确定性规则命中 | 不依赖总分，直接告警；分数只决定处置优先级 |
| 完整高风险序列命中 | 直接生成场景告警和案件，可按关键资产升级 |
| 基线异常 + 另一个独立异常 | 生成中风险组合场景或进入观察状态 |
| 只有单个弱基线异常 | 记录信号、等待后续行为或用于画像，不一定告警 |
| 只有模型高分 | 默认进入模型评分索引或中低风险信号，不直接判定攻击 |
| 模型高分 + 规则/序列/新颖度 | 作为案件增强证据，提高优先级和置信度 |
| 低关联置信度或采集不完整 | 降低置信度，禁止自动高危处置 |

### 8.9 场景定义对象

建议将组合和序列场景配置版本化：

```yaml
scenario_id: UEBA-ACCOUNT-COMPROMISE-001
name: 可疑账号接管并访问高价值资源
version: 3
entity_key: [user.id, account.id]
window: 30m
detection_method: composite_pattern
required:
  - signal_type: authentication_success
conditions:
  min_match: 2
  any_of:
    - signal_type: unusual_login_source
    - signal_type: first_seen_device
    - signal_type: abnormal_login_time
    - signal_type: password_spray_preceded_success
enhancers:
  - signal_type: privileged_action
  - signal_type: high_value_resource_access
  - signal_type: anomalous_outbound_transfer
exclusions:
  - approved_travel
  - active_pam_session
quality_requirements:
  identity_correlation_confidence_gte: 0.9
  required_fields_complete: true
```

场景版本、命中的条件、未命中的可选条件、例外结果和原始证据必须写入告警，保证回放、调优和审计可解释。

## 9. 网络检测一：协议与端口不匹配

该检测通常基于单条连接，不需要时间窗口。

### 9.1 参考策略对象

```json
{
  "port": 53,
  "transport": "udp",
  "allowed_protocols": ["dns"],
  "severity": "high"
}
```

| 字段 | 含义 |
| --- | --- |
| `port` | 需要受管控的目标端口号 |
| `transport` | 该策略适用的传输层协议，如 TCP 或 UDP |
| `allowed_protocols` | 允许在该端口出现的、由 Zeek 明确识别出的应用协议列表 |
| `severity` | 发生不匹配时的默认告警严重度 |

典型端口策略如下：

| 目标端口 | 传输层 | 允许协议 |
| --- | --- | --- |
| 53 | UDP/TCP | `dns` |
| 80 | TCP | `http` |
| 443 | TCP | `tls`、`http` |
| 25、465、587 | TCP | `smtp`、`tls` |
| 22 | TCP | `ssh` |
| 3389 | TCP | `rdp` |
| 445 | TCP | `smb` |

### 9.2 判定流程

```text
1. 从 conn.log 获取 destination.port、network.transport、zeek.service；
2. 根据目标端口和传输层查询端口协议策略；
3. 无匹配策略时，标记为“非典型端口”，但不直接判定违规；
4. 实际协议为空时，标记为“未识别”，不作为不匹配证据；
5. 实际协议明确存在且不在 allowed_protocols 中，生成候选事件；
6. 查询未过期的例外策略；
7. 无例外时生成告警，并保留五元组、Zeek UID 与命中依据。
```

例如，`UDP / 53 / tls` 是高风险协议端口不匹配；而 `TCP / 8443 / tls` 是非典型端口 TLS，初始应为低风险，需叠加陌生目的地、异常流量或周期通信后再升级。

## 10. 网络检测二：DNS 隧道

### 10.1 单条 DNS 事件模型

```json
{
  "@timestamp": "2026-09-02T10:01:04.000Z",
  "event": {
    "id": "zeek-gw-01-C8abc-dns",
    "dataset": "zeek.dns"
  },
  "zeek": {
    "uid": "C8abc"
  },
  "source": {
    "ip": "10.10.2.15"
  },
  "asset": {
    "id": "PC-023"
  },
  "dns": {
    "question": {
      "name": "a8f9d82ks9.example.com",
      "type": "TXT"
    },
    "response_code": "NXDOMAIN",
    "registered_domain": "example.com",
    "subdomain": "a8f9d82ks9",
    "subdomain_length": 10,
    "subdomain_entropy": 3.12
  }
}
```

| 字段 | 含义 | 来源或计算方式 |
| --- | --- | --- |
| `event.id` | 本条 DNS 事件唯一 ID | 传感器 ID + Zeek UID + 日志类型 |
| `event.dataset` | 数据集名称，标识为 Zeek DNS 日志 | 清洗层 |
| `zeek.uid` | 与 `conn.log` 关联的 Zeek 连接 ID | Zeek `dns.log` |
| `source.ip` | 发起 DNS 查询的 IP | Zeek 原始地址字段 |
| `asset.id` | 发起查询的资产稳定 ID | CMDB / DHCP 时间映射 |
| `dns.question.name` | 客户端查询的完整域名 | Zeek DNS 查询字段 |
| `dns.question.type` | DNS 查询类型，如 `A`、`AAAA`、`TXT` | Zeek DNS 查询字段 |
| `dns.response_code` | DNS 响应码，如 `NOERROR`、`NXDOMAIN` | Zeek DNS 响应字段 |
| `dns.registered_domain` | 可注册主域，如 `example.com` | 使用 Public Suffix List 计算 |
| `dns.subdomain` | 去除注册主域后的剩余前缀 | 由完整查询名计算 |
| `dns.subdomain_length` | 子域字符长度 | 由 `dns.subdomain` 计算 |
| `dns.subdomain_entropy` | 子域字符的 Shannon 熵 | 由 `dns.subdomain` 计算 |

注册主域不能简单取最后两段。例如 `a.example.co.uk` 的注册主域是 `example.co.uk`，需要使用 Public Suffix List 解析器。

Shannon 熵的计算方式：

```text
entropy = - Σ p(character) × log2(p(character))
```

其中 `p(character)` 是某个字符在子域字符串中出现的比例。随机编码、Base32、Base64 或十六进制形式的子域通常会表现出较高熵。

### 10.2 DNS 特征滑动窗口

按以下键分组：

```text
asset.id + dns.registered_domain
```

建议窗口参数：

```text
窗口长度：5分钟
滑动步长：1分钟
时间语义：event_time
允许迟到：2分钟
```

流计算伪代码：

```text
DNS 事件流
  .keyBy(asset.id, dns.registered_domain)
  .slidingEventTimeWindow(size = 5分钟, slide = 1分钟)
  .aggregate(
      query_count,
      distinct(question.name),
      distinct(subdomain),
      avg(subdomain_length),
      max(subdomain_length),
      avg(subdomain_entropy),
      count(question.type == "TXT"),
      count(response_code == "NXDOMAIN")
  )
```

输出对象示例：

```json
{
  "window_start": "2026-09-02T10:00:00Z",
  "window_end": "2026-09-02T10:05:00Z",
  "asset": {
    "id": "PC-023"
  },
  "dns": {
    "registered_domain": "example.com"
  },
  "query_count": 214,
  "unique_query_count": 210,
  "unique_subdomain_count": 206,
  "unique_subdomain_ratio": 0.963,
  "avg_subdomain_length": 41.2,
  "max_subdomain_length": 63,
  "avg_subdomain_entropy": 4.21,
  "txt_ratio": 0.72,
  "nxdomain_ratio": 0.08
}
```

| 字段 | 含义 |
| --- | --- |
| `window_start` | 当前统计窗口的起始事件时间 |
| `window_end` | 当前统计窗口的结束事件时间 |
| `asset.id` | 产生 DNS 查询的资产 ID |
| `dns.registered_domain` | 当前窗口聚合的注册主域 |
| `query_count` | 窗口内 DNS 查询总数 |
| `unique_query_count` | 窗口内不同完整查询名数量 |
| `unique_subdomain_count` | 窗口内不同子域数量 |
| `unique_subdomain_ratio` | 不同子域数除以查询总数；接近 1 代表每次查询都在变换子域 |
| `avg_subdomain_length` | 窗口内子域平均字符长度 |
| `max_subdomain_length` | 窗口内最长子域字符长度 |
| `avg_subdomain_entropy` | 窗口内子域 Shannon 熵平均值 |
| `txt_ratio` | TXT 查询次数除以查询总数 |
| `nxdomain_ratio` | 返回 `NXDOMAIN` 的查询次数除以查询总数 |

DNS 检测器内部推荐采用多指标证据计分而非单阈值：唯一子域比例、子域长度、熵、TXT 比例、NXDOMAIN 比例、查询周期性和企业内使用稀有度各自贡献证据；达到该检测器阈值后生成 `dns_tunnel_suspected` 原子信号。这个局部得分只表示 DNS 隧道证据强度，不是 UEBA 总风险分，也不能无条件与其他场景分数相加。

## 11. 网络检测三：横向扫描

### 11.1 过滤范围

输入来自 `conn.log`，保留满足以下条件的事件：

```text
source 为内部资产
destination 为内部资产
source 与 destination 不属于同一资产
```

按以下键聚合：

```text
asset.id
```

窗口建议：5 分钟长度，1 分钟步长。

### 11.2 连接状态归类

应先将 Zeek `conn_state` 归类为成功、失败和未知：

| 类别 | 示例 | 说明 |
| --- | --- | --- |
| `success` | `SF` | 正常完成连接 |
| `failed` | 拒绝、超时、无响应、异常重置等状态 | 用于扫描和重试特征 |
| `unknown` | 日志字段缺失、采集不完整 | 不纳入失败率分母，或单独统计 |

具体 Zeek 状态代码与归类需要根据部署版本、网络设备行为和流量方向进行校准，不建议未经验证地将所有非 `SF` 状态直接视为攻击失败。

### 11.3 扫描窗口特征

```json
{
  "window_start": "2026-09-02T10:00:00Z",
  "window_end": "2026-09-02T10:05:00Z",
  "asset": {
    "id": "PC-023"
  },
  "unique_dst_ip_count": 42,
  "unique_dst_port_count": 3,
  "unique_dst_ip_port_pair_count": 44,
  "connection_count": 52,
  "failed_connection_count": 41,
  "failed_ratio": 0.788,
  "internal_dst_ratio": 1.0,
  "syn_only_count": 33
}
```

| 字段 | 含义 |
| --- | --- |
| `window_start` | 扫描统计窗口开始时间 |
| `window_end` | 扫描统计窗口结束时间 |
| `asset.id` | 发起内网连接的资产 ID |
| `unique_dst_ip_count` | 窗口内被访问的不同内部目标 IP 数 |
| `unique_dst_port_count` | 窗口内尝试的不同目标端口数 |
| `unique_dst_ip_port_pair_count` | 不同“目标 IP + 目标端口”组合数 |
| `connection_count` | 进入统计范围的连接总数 |
| `failed_connection_count` | 被归为失败的连接数 |
| `failed_ratio` | 失败连接数除以可判定连接总数 |
| `internal_dst_ratio` | 内部目标连接数占全部参与统计连接数的比例 |
| `syn_only_count` | 仅观察到 SYN 或未形成完整会话的连接数；依赖 Zeek 状态映射 |

检测示例：

```text
主机扫描：
unique_dst_ip_count >= 30
AND failed_ratio >= 0.7
AND internal_dst_ratio >= 0.9

端口扫描：
unique_dst_port_count >= 20
AND unique_dst_ip_count <= 3
AND failed_ratio >= 0.7
```

对漏洞扫描器、运维跳板机、安全设备等资产角色设置明确例外或降级策略，但保留原始事件和聚合画像。

## 12. 网络检测四：异常外联目的地

### 12.1 目的地键

为避免 CDN、负载均衡和共享云 IP 造成误判，目的地的优先识别顺序建议为：

```text
TLS SNI / HTTP Host / DNS 注册主域
→ destination.ip + destination_context.asn
→ destination.ip
```

对应的统一字段为 `destination_key`。

### 12.2 目的地状态对象

```json
{
  "destination_key": "domain:example.com",
  "first_seen_enterprise": "2026-08-10T01:00:00Z",
  "last_seen_enterprise": "2026-09-02T10:00:00Z",
  "distinct_asset_count_30d": 126,
  "distinct_asset_roles_30d": ["office_endpoint", "server"],
  "approved": false,
  "observed_count_30d": 189223
}
```

| 字段 | 含义 |
| --- | --- |
| `destination_key` | 目的地标准化主键；示例表示以域名作为目的地标识 |
| `first_seen_enterprise` | 该目的地首次被企业任一资产访问的时间 |
| `last_seen_enterprise` | 该目的地最近一次被企业资产访问的时间 |
| `distinct_asset_count_30d` | 最近 30 天访问该目的地的不同资产数 |
| `distinct_asset_roles_30d` | 最近 30 天访问该目的地的资产角色集合 |
| `approved` | 是否为已批准服务或合作方 |
| `observed_count_30d` | 最近 30 天企业访问该目的地的连接总次数 |

“企业首次出现”与“主机首次出现”应分别维护：

```text
企业首次出现：目的地对全企业均未知，风险更高。
主机首次出现：当前主机未见过，但企业其他设备可能长期使用，风险较低。
```

### 12.3 外联窗口特征

建议按 `asset.id + destination_key + 1小时窗口` 聚合：

```text
outbound_bytes
inbound_bytes
upload_ratio
connection_count
is_first_seen_by_asset
is_first_seen_by_enterprise
is_approved
is_workhour
```

其中：

```text
upload_ratio = outbound_bytes / max(inbound_bytes, 1)
```

初始规则示例：

```text
asset.role == office_endpoint
AND destination_context.is_internal == false
AND is_approved == false
AND is_first_seen_by_enterprise == true
AND is_workhour == false
AND outbound_bytes > 100MB
```

该规则单独命中建议产生中风险事件；若再叠加直连 IP、无 SNI、罕见 TLS 指纹或周期通信，升级为高风险案件。

## 13. 网络检测五：周期性未知外联

### 13.1 分组与窗口

聚合键：

```text
asset.id + destination_key + network.protocol
```

建议参数：

```text
窗口长度：1小时
滑动步长：5分钟
最少连接数：20
允许迟到：2分钟
```

窗口内按事件时间排序：

```text
t1, t2, t3, ..., tn
Δt = [t2-t1, t3-t2, ..., tn-t(n-1)]
```

### 13.2 周期通信特征对象

```json
{
  "window_start": "2026-09-02T09:00:00Z",
  "window_end": "2026-09-02T10:00:00Z",
  "asset": {
    "id": "PC-023"
  },
  "destination_key": "domain:example.com",
  "network": {
    "protocol": "tls"
  },
  "connection_count": 58,
  "interval_mean_seconds": 60.1,
  "interval_stddev_seconds": 4.2,
  "interval_cv": 0.07,
  "outbound_bytes_cv": 0.12,
  "duration_cv": 0.09,
  "non_workhour_ratio": 1.0,
  "is_first_seen_by_enterprise": true,
  "is_approved": false
}
```

| 字段 | 含义 |
| --- | --- |
| `window_start` | 周期通信统计窗口的开始时间 |
| `window_end` | 周期通信统计窗口的结束时间 |
| `asset.id` | 发起通信的资产 ID |
| `destination_key` | 经过域名/IP 标准化后的通信目的地 |
| `network.protocol` | 连接实际识别出的应用协议 |
| `connection_count` | 窗口内该资产与目的地的连接次数 |
| `interval_mean_seconds` | 相邻两次连接的平均时间间隔，单位秒 |
| `interval_stddev_seconds` | 相邻连接间隔的标准差，单位秒 |
| `interval_cv` | 连接间隔变异系数，即标准差除以均值；越低表示节奏越固定 |
| `outbound_bytes_cv` | 单次连接上行字节数的变异系数；越低表示每次上传规模越固定 |
| `duration_cv` | 连接持续时间的变异系数；越低表示连接形态越固定 |
| `non_workhour_ratio` | 窗口内发生在非工作时段的连接比例 |
| `is_first_seen_by_enterprise` | 该目的地是否企业首次出现 |
| `is_approved` | 该目的地是否属于批准服务 |

计算公式：

```text
interval_cv = interval_stddev_seconds / interval_mean_seconds
outbound_bytes_cv = 上行字节数标准差 / 上行字节数均值
duration_cv = 连接持续时间标准差 / 连接持续时间均值
```

均值为零时应返回空值或特殊值，不能直接除零。

周期通信评分示例：

```text
连接数 >= 20                              +20
平均间隔位于 30 秒至 1 小时                +10
interval_cv < 0.15                        +30
outbound_bytes_cv < 0.30                  +10
duration_cv < 0.30                        +10
非工作时间通信比例高                      +10
目的地为企业首次出现或未批准目标           +20
```

以上分数只用于“周期通信”这个单一检测器内部衡量证据强度，不能直接作为 UEBA 总风险分。达到阈值后生成 `periodic_communication` 原子信号，而不是直接判定危险行为。若“高规律性 + 未批准新目的地 + 非工作时间”满足预定义组合场景，或它出现在“异常登录 → 提权 → 横移 → 外联”序列中，再生成对应场景告警；否则仅进入画像或观察队列。

## 14. 孤立森林异常检测

固定规则和场景序列适合发现已知模式，用户/账号/主机自身与同类基线适合判断单个指标是否偏离历史。孤立森林仅用于补充识别“每个指标单独看都没有越过阈值，但多个指标组合起来非常少见”的样本。

例如某用户在一小时内同时表现为：

```text
上行量略高
+ 新目的地数量略高
+ TLS 无 SNI 比例略高
+ 非工作时间连接略高
+ 连接间隔较稳定
+ 首次设备登录比例略高
+ 高价值资源访问数量略高
```

这些指标可能都未达到单独告警阈值，但联合出现时可能明显偏离该用户自身历史和同岗位用户。孤立森林适合对这种多维稀有组合生成候选异常分。

### 14.1 定位与使用限制

孤立森林是无监督异常检测模型，核心假设是：异常样本在特征空间中数量少、与正常样本分隔较容易，因此会在随机树中以较短路径被“孤立”。

它不直接证明攻击或数据泄露，也不能代替高置信度规则。正确定位是：

```text
固定规则：回答“是否命中已知且确定的异常模式”
统计基线：回答“某个指标是否偏离自身或同类历史”
孤立森林：回答“多个指标的组合是否在同类样本中罕见”
组合/序列场景：回答“多个异常信号能否组成定义明确的风险场景”
案件关联：回答“哪些已成立信号和场景属于同一用户/实体风险事件”
```

孤立森林不应直接读取人员姓名、账号字符串、`src_ip`、域名字符串、Zeek UID 等标识字段。模型输入必须是固定窗口生成的数值或布尔特征。用户、共享账号、服务账号、主机和容器等实体类型不得混在同一训练群组中。

### 14.2 模型处理链路

```text
AD / IdP / Windows / Linux / Zeek 原始事件
  ↓
ELK / Flink 生成窗口特征
  ↓
特征校验与预处理
  ├── 缺失值处理
  ├── 极端值截断
  ├── 长尾数值 log1p 转换
  ├── 比例限制在 0～1
  └── 按特征版本固定顺序
  ↓
按实体类型 / 岗位或资产角色 / 权限等级 / 区域 / 时间类型选择模型
  ↓
孤立森林推理
  ↓
原始模型分数
  ↓
按训练分布校准为 0～100 异常分
  ↓
作为基线、组合或序列场景的增强信号
  ↓
ML 原子信号或现有案件优先级增强
```

训练链路独立运行：

```text
最近 30～60 天窗口特征
  ↓
排除已确认攻击、采集故障、变更窗口和明显规则告警
  ↓
按同类用户、账号或资产与时间类型分组
  ↓
训练 / 验证时间切分
  ↓
训练孤立森林并确定分数阈值
  ↓
离线回放评估告警量与已知案例召回
  ↓
模型注册、审批、发布
  ↓
流计算或模型服务加载新版本
```

### 14.3 训练样本粒度与模型分组

推荐一条样本代表“某个用户或实体在固定窗口内的聚合行为”，而不是一条登录、一条进程或一条连接。

可以建立多组彼此独立的模型：

| 模型 | 样本粒度 | 主要目标 |
| --- | --- | --- |
| 用户小时模型 | `user.id + 1小时` | 登录、设备、资源、权限、进程和网络行为的联合异常 |
| 账号会话模型 | `account.id + session.id` | 单次会话中的认证、提权、访问资源和外联异常 |
| 资产小时模型 | `asset.id + 1小时` | 检测整体外联、扫描、DNS、TLS 和时间习惯异常 |
| 资产目的地模型 | `asset.id + destination_key + 1小时` | 检测对单个目的地的周期、上行和新颖度异常 |

UEBA 第一期优先实现用户登录/资源访问基线和用户小时模型，同时保留现有资产小时模型；账号会话模型和资产目的地模型可在会话关联质量稳定后增加。

模型应尽量按同类实体分组训练，例如：

```text
user_model_group = job_role + department + privilege_tier + region + time_type
asset_model_group = asset.role + asset.zone + time_type

示例：
finance_analyst + finance + normal_user + CN + workhour
domain_admin + it_ops + privileged + CN + non_workhour
office_endpoint + office + workhour
application_server + production + workhour
```

不建议给每个用户或每台主机单独训练孤立森林，因为单实体样本少、正常模式变化大且维护成本高。单实体差异由统计基线处理，孤立森林主要学习同类用户或实体的多维联合分布。

当某个模型组样本不足时，逐级回退：

```text
岗位/资产角色 + 权限等级 + 区域 + 时间类型
→ 岗位/资产角色 + 权限等级 + 时间类型
→ 岗位/资产角色
→ 全局模型
→ 样本仍不足时不输出模型告警，仅使用规则和统计基线
```

用户小时模型可增加以下特征：登录失败率、非常用来源比例、首次设备比例、非工作时间登录比例、远程交互式登录比例、特权操作次数、高价值资源访问数、新资源比例、异常 PowerShell/命令次数、横向访问主机数和外联新颖度。账号类型、岗位和权限等级用于选择模型，不直接作为连续数值输入。

### 14.4 特征向量设计

资产小时模型的输入对象示例：

```json
{
  "feature_set_id": "asset-hour-v1",
  "window_start": "2026-09-02T09:00:00Z",
  "window_end": "2026-09-02T10:00:00Z",
  "asset": {
    "id": "PC-023",
    "role": "office_endpoint",
    "zone": "office"
  },
  "time_type": "non_workhour",
  "features": {
    "outbound_bytes_log": 19.25,
    "inbound_bytes_log": 16.30,
    "upload_ratio_log": 2.91,
    "connection_count_log": 6.42,
    "external_destination_count_log": 3.04,
    "new_destination_ratio": 0.38,
    "failed_connection_ratio": 0.12,
    "unique_dst_port_count_log": 2.20,
    "dns_query_count_log": 6.81,
    "dns_nxdomain_ratio": 0.08,
    "dns_high_entropy_ratio": 0.21,
    "tls_no_sni_ratio": 0.17,
    "rare_tls_fingerprint_ratio": 0.09,
    "periodic_destination_count_log": 1.10,
    "internal_destination_count_log": 1.61
  },
  "quality": {
    "completeness_ratio": 0.98,
    "late_event_ratio": 0.01,
    "is_eligible_for_scoring": true
  }
}
```

对象公共字段说明：

| 字段 | 含义 |
| --- | --- |
| `feature_set_id` | 特征集合名称和版本；决定字段列表、顺序及预处理规则 |
| `window_start` | 特征窗口开始时间 |
| `window_end` | 特征窗口结束时间 |
| `asset.id` | 被评分的资产 ID；用于结果归属，不作为模型数值输入 |
| `asset.role` | 资产角色；用于选择同类模型，不直接作为连续数值输入 |
| `asset.zone` | 资产区域；用于模型分组和上下文展示 |
| `time_type` | 时间类型，如工作时间、非工作时间、工作日、节假日 |
| `features` | 按固定版本产生的数值特征集合，是孤立森林的真正输入 |
| `quality` | 特征窗口的数据质量信息，决定当前样本是否可以评分 |

模型特征说明：

| 特征 | 含义 | 预处理 |
| --- | --- | --- |
| `outbound_bytes_log` | 窗口内向外发送总字节数 | `log1p(outbound_bytes)` |
| `inbound_bytes_log` | 窗口内从外部接收总字节数 | `log1p(inbound_bytes)` |
| `upload_ratio_log` | 上行字节数与下行字节数的比例 | `log1p(outbound/max(inbound,1))` |
| `connection_count_log` | 窗口内连接总数 | `log1p(connection_count)` |
| `external_destination_count_log` | 不同外部目的地数量 | `log1p(count)` |
| `new_destination_ratio` | 首次出现目的地数占外部目的地总数的比例 | 限制为 0～1 |
| `failed_connection_ratio` | 失败连接数占可判定连接数的比例 | 限制为 0～1 |
| `unique_dst_port_count_log` | 不同目标端口数量 | `log1p(count)` |
| `dns_query_count_log` | DNS 查询总数 | `log1p(count)` |
| `dns_nxdomain_ratio` | NXDOMAIN 查询占全部 DNS 查询的比例 | 限制为 0～1 |
| `dns_high_entropy_ratio` | 高熵子域查询占 DNS 查询的比例 | 限制为 0～1 |
| `tls_no_sni_ratio` | 没有 SNI 的 TLS 连接占 TLS 连接的比例 | 限制为 0～1 |
| `rare_tls_fingerprint_ratio` | 罕见 JA3/JA4 指纹连接占 TLS 连接的比例 | 限制为 0～1 |
| `periodic_destination_count_log` | 被识别为周期通信的不同目的地数 | `log1p(count)` |
| `internal_destination_count_log` | 被访问的不同内部目标资产数 | `log1p(count)` |
| `quality.completeness_ratio` | 当前窗口必需字段完整事件占比 | 限制为 0～1 |
| `quality.late_event_ratio` | 当前窗口迟到事件占比 | 限制为 0～1 |
| `quality.is_eligible_for_scoring` | 当前窗口数据质量是否达到模型评分要求 | 布尔判断，不作为模型特征 |

对字节数、连接数、目的地数等长尾特征使用 `log1p`，可以降低少量极大值对随机切分的支配。孤立森林不强制要求标准化，但训练和推理必须使用完全相同的预处理流程。

### 14.5 缺失值、极端值与数据质量

模型不能直接接收含义不清的空值。处理原则：

- 没有 DNS 流量时，`dns_query_count` 可以是 0；
- DNS 日志采集失败时，DNS 特征应为“缺失”，不能伪装成 0；
- 比例分母为 0 时，应按业务定义返回 0、空值或专用缺失标记；
- 训练集每个数值特征可按 P0.1～P99.9 截断，避免采集错误形成极端值；
- `completeness_ratio` 低于阈值，例如 0.9 时，不进行模型评分；
- 采集故障期间的特征窗口不得进入下一次训练集。

缺失值填充参数属于模型的一部分。可保存训练集的中位数作为填充值，同时增加相应的 `*_missing` 布尔特征；训练和推理必须加载同一版本的填充参数。

### 14.6 模型训练配置

模型元数据对象示例：

```json
{
  "model_id": "iforest-office-office-nonwork-v12",
  "algorithm": "isolation_forest",
  "model_group": "office_endpoint|office|non_workhour",
  "feature_set_id": "asset-hour-v1",
  "training_start": "2026-07-01T00:00:00Z",
  "training_end": "2026-08-30T23:59:59Z",
  "training_sample_count": 186420,
  "parameters": {
    "n_estimators": 300,
    "max_samples": 2048,
    "max_features": 1.0,
    "contamination": "auto",
    "random_state": 20260902
  },
  "thresholds": {
    "medium": 70,
    "high": 85,
    "critical": 95
  },
  "status": "active",
  "created_at": "2026-09-01T03:00:00Z"
}
```

| 字段 | 含义 |
| --- | --- |
| `model_id` | 模型唯一标识，包含模型组和版本 |
| `algorithm` | 使用的算法名称，本例为孤立森林 |
| `model_group` | 模型适用的资产角色、区域和时间类型组合 |
| `feature_set_id` | 模型使用的特征集合版本 |
| `training_start` | 训练数据开始时间 |
| `training_end` | 训练数据结束时间 |
| `training_sample_count` | 实际参与训练的窗口样本数量 |
| `parameters` | 孤立森林训练参数集合 |
| `parameters.n_estimators` | 随机树数量；越多通常越稳定，但训练和推理成本越高 |
| `parameters.max_samples` | 每棵树抽取的最大训练样本数 |
| `parameters.max_features` | 每棵树使用的特征比例；`1.0` 表示使用全部特征 |
| `parameters.contamination` | 训练时对异常比例的假设；`auto` 表示不硬编码业务异常率 |
| `parameters.random_state` | 随机种子，保证相同数据和配置可复现 |
| `thresholds.medium` | 中风险异常分阈值 |
| `thresholds.high` | 高风险异常分阈值 |
| `thresholds.critical` | 极高风险异常分阈值 |
| `status` | 模型状态，如候选、活动、回滚、停用 |
| `created_at` | 模型训练或注册完成时间 |

参数不是全局固定值，应通过时间切分验证集和历史回放确定。`contamination` 不等于真实攻击比例，也不应直接决定生产告警量；生产阈值应根据训练分数分布、每日可处理告警量和已知案例表现校准。

### 14.7 训练数据清理和时间切分

建议使用最近 30～60 天窗口样本，并排除：

- 已确认攻击和调查中的高风险时间段；
- Zeek、Filebeat 或 Logstash 故障窗口；
- 资产大规模变更、网络割接和演练窗口；
- 命中高置信度规则的明显异常样本；
- 字段完整率低于要求的窗口；
- 已标记为扫描器、压力测试、备份迁移等特殊任务窗口。

训练和验证必须按时间切分，不能随机打散：

```text
训练：前 80% 时间范围
验证：后 20% 时间范围
```

这样更接近“用过去预测未来”，也可以发现业务变化导致的模型漂移。

### 14.8 模型分数校准

不同实现的孤立森林原始分数方向和范围可能不同。例如某些实现中原始 `decision_function` 越小越异常。因此系统不能直接把库返回值作为统一风险分。

建议根据模型训练或验证集的异常程度分布，转换成统一的 0～100 分：

```text
1. 将模型原始输出统一转换为 anomaly_raw，数值越大越异常；
2. 计算当前 anomaly_raw 在同模型验证集中的百分位；
3. anomaly_score = 百分位 × 100；
4. 根据模型版本中的 thresholds 映射风险等级。
```

例如 `anomaly_score = 99.4` 表示该样本比模型验证集中约 99.4% 的窗口更异常，并不表示“有 99.4% 的概率是攻击”。

### 14.9 在线推理结果对象

```json
{
  "scoring_id": "ml-PC-023-20260902T100000Z",
  "scored_at": "2026-09-02T10:02:15Z",
  "model_id": "iforest-office-office-nonwork-v12",
  "feature_set_id": "asset-hour-v1",
  "window_start": "2026-09-02T09:00:00Z",
  "window_end": "2026-09-02T10:00:00Z",
  "asset": {
    "id": "PC-023"
  },
  "raw_score": -0.184,
  "anomaly_score": 96.8,
  "severity": "critical",
  "threshold": 95,
  "is_anomaly": true,
  "top_deviations": [
    {
      "feature": "new_destination_ratio",
      "value": 0.38,
      "peer_median": 0.04,
      "peer_p99": 0.19
    },
    {
      "feature": "tls_no_sni_ratio",
      "value": 0.17,
      "peer_median": 0.01,
      "peer_p99": 0.08
    }
  ],
  "quality": {
    "completeness_ratio": 0.98,
    "fallback_model_used": false
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `scoring_id` | 本次模型评分记录的唯一 ID |
| `scored_at` | 模型完成推理的时间 |
| `model_id` | 执行推理的孤立森林模型版本 |
| `feature_set_id` | 本次评分使用的特征集合版本 |
| `window_start` | 被评分窗口的开始时间 |
| `window_end` | 被评分窗口的结束时间 |
| `asset.id` | 被评分的资产 ID |
| `raw_score` | 模型库产生的原始分数，只用于模型诊断，不直接解释为风险 |
| `anomaly_score` | 校准后的 0～100 异常分，数值越高表示越罕见 |
| `severity` | 根据当前模型阈值映射的风险级别 |
| `threshold` | 当前风险级别对应的模型异常分阈值 |
| `is_anomaly` | 当前分数是否达到最低生产告警阈值 |
| `top_deviations` | 与同类统计分布偏差最大的若干特征，用于解释，不等同于模型原生因果解释 |
| `top_deviations.feature` | 偏差特征名称 |
| `top_deviations.value` | 当前窗口的特征值 |
| `top_deviations.peer_median` | 同类样本该特征的中位数 |
| `top_deviations.peer_p99` | 同类样本该特征的 P99 |
| `quality.completeness_ratio` | 当前评分样本的字段完整率 |
| `quality.fallback_model_used` | 是否因精细分组样本不足而使用了上一级模型 |

孤立森林本身不会天然说明“哪个特征导致异常”。`top_deviations` 是通过当前值与同类中位数、P99 或 MAD 比较得出的辅助解释，不能表述为严格的模型因果贡献。

### 14.10 模型结果与规则融合

模型分数不建议单独直接产生高危告警。可采用以下使用方式：

```text
模型异常分 70～84：只写模型评分索引，不单独告警
模型异常分 85～94：生成中风险 ML 原子信号，等待场景组合或人工调查
模型异常分 >= 95：生成高置信候选信号；若无其他证据，仍不得表述为已确认攻击
模型高分 + 任一固定规则命中：固定规则照常告警，模型只增强案件优先级
模型高分 + 登录/设备/资源新颖度 + 非工作时间：可命中定义明确的组合场景
模型高分但命中批准业务和有效例外：降级并保留审计记录
```

案件层可保留一个优先级计算示例，但不能替代第 8 节的场景判定：

```text
case_priority =
  0.35 × rule_score
  + 0.25 × baseline_score
  + 0.25 × isolation_forest_score
  + 0.15 × novelty_score
  - exception_reduction
```

权重只作为调查队列排序的初始值，需要用历史案件回放和安全团队可处理告警量调优。高置信度明确规则和完整高风险序列不应因为模型分数低而被取消；模型高分也不能替代组合/序列场景的必要条件。

### 14.11 ELK 中的模型集成方式

孤立森林可以通过三种方式与 ELK 结合：

| 方式 | 实现 | 适用场景 |
| --- | --- | --- |
| Elasticsearch 特征 + 外部批量评分 | Transform 生成特征索引，定时模型任务读取、评分并回写 | PoC、分钟级或小时级检测 |
| Kafka/Flink + 模型服务 | Flink 生成窗口特征，通过嵌入模型或推理服务评分，再写回 Elasticsearch | 生产实时检测 |
| Elasticsearch 特征 + 独立训练平台 | Elasticsearch 提供训练样本，训练平台产出版本化模型，实时层加载模型 | 已有机器学习平台 |

推荐将模型评分结果写入：

```text
ueba-ml-score-*
```

Kibana 应同时展示模型异常分、模型版本、特征版本、同类偏差和数据质量。不能只显示一个没有依据的模型分数。

### 14.12 模型更新、漂移与回滚

建议每周或每两周训练候选模型，是否发布由指标决定，而不是训练完成后自动替换生产模型。

需要监控：

- 每日模型高分样本比例；
- 不同资产组的异常分分布是否明显漂移；
- 特征缺失率和数值分布变化；
- 候选模型与当前模型的告警重合率；
- 人工确认率、误报率及每日报警量；
- 推理延迟和模型加载失败次数。

模型注册表至少保留当前版本、上一稳定版本、特征版本、训练范围、参数、阈值、评估结果和状态。当新模型导致告警量异常上升、特征不兼容或确认率下降时，应能快速回滚到上一稳定版本。

## 15. 原子告警、场景命中与风险案件

### 15.1 原子告警对象

```json
{
  "event_id": "det-ueba-account-20260902-001",
  "event_type": "account_compromise_with_lateral_movement",
  "scenario_id": "UEBA-ACCOUNT-COMPROMISE-001",
  "scenario_version": 3,
  "detection_method": "sequence_pattern",
  "severity": "high",
  "confidence": 0.91,
  "window_start": "2026-09-02T21:48:00Z",
  "window_end": "2026-09-02T22:54:00Z",
  "user": {
    "id": "USR-00023",
    "name": "zhangsan"
  },
  "account": {
    "id": "S-1-5-21-...-1108",
    "name": "CORP\\zhangsan"
  },
  "session": {
    "id": "vpn-20260902-88721"
  },
  "asset": {
    "id": "PC-023",
    "role": "office_endpoint"
  },
  "destination_key": "domain:example.com",
  "evidence": {
    "matched_sequence": [
      "unusual_login_source",
      "privileged_group_membership_change",
      "lateral_scan",
      "anomalous_outbound_transfer"
    ],
    "baseline_anomalies": [
      "first_seen_device",
      "non_workhour_login"
    ],
    "model_signal": {
      "present": true,
      "anomaly_score": 96.8
    }
  },
  "source_event_refs": [
    "idp-event-77821",
    "ad-dc01-security-99318",
    "zeek-gw-01-C8abc"
  ],
  "exception_check": {
    "matched": false
  }
}
```

| 字段 | 含义 |
| --- | --- |
| `event_id` | 检测系统生成的告警唯一 ID |
| `event_type` | 检测场景类型，如疑似账号接管、权限滥用、横向移动或异常外联 |
| `scenario_id/version` | 命中的场景与版本，用于回放、审计和调优 |
| `detection_method` | 确定性规则、基线、组合、序列、模型或案件聚合 |
| `severity` | 影响严重度，如低、中、高、极高 |
| `confidence` | 对事件成立的置信度，范围通常为 0 到 1 |
| `window_start` | 触发检测的统计窗口开始时间 |
| `window_end` | 触发检测的统计窗口结束时间 |
| `user.id` | 关联的人员实体；无法可靠归属时可为空 |
| `account.id` | 行为实际使用的账号实体 |
| `session.id` | 关联的认证/VPN/主机会话 |
| `asset.id` | 告警关联的资产 ID |
| `asset.role` | 告警关联资产的角色 |
| `destination_key` | 告警关联的标准化目的地 |
| `evidence` | 命中规则的指标实际值、得分与其他解释证据 |
| `source_event_refs` | 支撑告警的原始日志事件 ID 列表或引用 |
| `exception_check.matched` | 是否命中有效例外；`false` 表示未命中例外 |

### 15.2 风险案件

原子信号和场景告警不应孤立展示。系统可按 `user.id`、`account.id`、`session.id`、`asset.id` 和共享证据关系，在 30 分钟、2 小时、24 小时等窗口聚合为风险案件。只有时间接近但实体和行为链无关的信号不能强行合并。

示例链路：

```text
非常用来源和首次设备登录
→ 非授权高权限组变更
→ 内网扫描与多主机远程登录
→ Linux 首次 SSH + sudo
→ 高度周期性外联与异常上行
```

案件中应保留：用户、账号、会话、关联资产、资源和目的地；确定性规则、基线异常、组合/序列场景及模型信号各自的证据；风险优先级、数据质量、身份关联置信度、白名单与例外检查结果，以及可追溯的原始日志引用。

## 16. 推荐索引与存储分层

```text
ueba-raw-identity-*       AD、IdP、VPN、PAM 等身份事件
ueba-raw-endpoint-*       Windows、Linux、EDR 等主机行为事件
net-raw-*                 Zeek 等原始标准化网络事件（保留原网络分层）
ueba-entity-link-*        用户、账号、会话、主机、IP、进程关联结果
ueba-user-profile-*       用户登录、设备、时间、资源和行为基线
ueba-account-profile-*    个人、共享、服务和机器账号画像
ueba-host-profile-*       Windows/Linux 主机行为画像和历史基线
net-dns-feature-*         DNS 5 分钟滑动窗口特征
net-conn-feature-*        连接、扫描、周期通信窗口特征
net-destination-profile   企业目的地观测状态
net-asset-profile         主机网络画像和历史基线
ueba-feature-*            用户/账号/主机/会话窗口特征
ueba-signal-*             规则、基线、组合和模型原子信号
ueba-scenario-match-*     组合与行为序列场景命中
ueba-ml-score-*           按实体分组的模型评分结果
ueba-model-registry       模型、特征、群组、阈值和状态
ueba-detection-event-*    原子告警和场景告警
ueba-risk-case-*          用户与实体风险案件
ueba-reference-*          身份、权限、组织、资产、资源、例外和变更数据
```

每一条信号或告警至少保留判定方式、规则/场景/模型版本、窗口范围、实体键、条件、阈值和实际值、基线参照、原始事件引用、身份关联质量及上下文富化结果。这样场景回放、阈值调优、误报排除和事件取证都不需要重新解释原始日志。

## 17. 实施顺序

1. 明确 UEBA 首期场景、实体和数据需求，优先选择账号接管、权限滥用、异常登录、横向移动和异常外联；
2. 从 AD 域控开始，通过 WEF + Winlogbeat/Elastic Agent 采集关键 Security 与目录变更事件，并验证审计策略；
3. 接入 IdP/MFA、VPN/ZTNA 和 PAM，建立远程会话、来源设备、审批与用户映射；
4. 在关键 Windows 终端/服务器接入 Security、Sysmon、PowerShell 或 EDR 数据；
5. 在关键 Linux 服务器接入 SSH/PAM、sudo/su、auditd、账号/组、cron/systemd 与 EDR/eBPF 数据；
6. 保留 Zeek JSON 的 `conn`、`dns`、`tls` 网络检测链，作为 UEBA 的网络行为证据；
7. 用 Logstash/Ingest 建立统一 UEBA 事件模型和数据质量指标，保留所有原始事件引用；
8. 建立 `user.id`、`account.id`、`host.id`、`session.id`、`process.entity_id` 和动态 IP 的事件时间关联；
9. 接入组织岗位、权限、账号类型、资产、业务资源、变更工单、批准目的地和例外策略；
10. 先实现确定性规则：高权限组变化、停用账号登录、异常服务账号交互登录、Linux UID 0/关键 sudoers 变化等；
11. 建立用户登录、账号使用、Windows/Linux 主机和资源访问基线，并落实冷启动与同类群组回退；
12. 实现组合场景：异常登录来源 + 首次设备 + 高价值资源访问，以及异常数据访问 + 新资源 + 异常外联；
13. 实现序列场景：登录 → 提权 → 横向移动 → 外联，以及 Linux SSH → sudo → 持久化；
14. 将现有协议端口、DNS 隧道、扫描、异常目的地和周期通信输出改造为可被 UEBA 场景消费的原子信号；
15. 在数据质量和同类群组稳定后训练用户小时、账号会话和资产小时模型；模型只输出候选信号；
16. 输出原子信号、场景命中和按用户/账号/会话/资产关联的 UEBA 风险案件；
17. 通过安全分析反馈、红队回放、告警处理容量和漂移监控，分别校准规则、基线、场景、例外与模型。
