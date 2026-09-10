# Splunk CIM、Zeek 映射与 Dataset 参考

## 1. 文档范围与结论

本册汇总三个互相关联但不能混为一谈的对象：

```text
CIM Data Model：定义一个分析领域，例如网络流量或认证
Dataset：在模型内定义具体事件集合、继承关系、字段和计算
TA/Add-on：把厂商原始字段、eventtype 和 tag 映射到 CIM
```

对 Zeek 而言，一条事件进入 CIM 的主要判断链是：

```text
sourcetype
  → eventtypes.conf 匹配 eventtype
  → tags.conf 为 eventtype 增加 tag
  → CIM Dataset constraint 检查 tag/字段条件
  → props.conf 的 FIELDALIAS/EVAL/LOOKUP 提供 CIM 字段
```

Dataset Constraint 决定事件是否属于模型集合；字段映射决定事件进入后有哪些可分析字段；具体检测还会提出额外字段、取值、时间范围和质量要求。

【事实】Splunk 官方把 CIM 定义为面向搜索时数据规范化的共享语义模型。CIM Add-on 包含预配置 Data Model、字段、Tag、文档和验证工具；原始机器数据可以保持不变。[1](https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/overview-of-the-splunk-common-information-model)

## 2. 本地证据范围

本册以仓库中的以下配置为实际证据：

- `Splunk_SA_CIM/default/app.conf`：本地 CIM 版本为 8.7.0；
- `Splunk_SA_CIM/default/data/models/*.json`：模型、Dataset、字段、计算和约束；
- `Splunk_TA_zeek/default/app.conf`：Corelight Add-on for Zeek 1.0.11；
- `Splunk_TA_zeek/default/eventtypes.conf`：sourcetype 到 eventtype；
- `Splunk_TA_zeek/default/tags.conf`：eventtype 到 tag；
- `Splunk_TA_zeek/default/props.conf`：字段别名、EVAL 和 lookup 调用；
- `Splunk_TA_zeek/default/transforms.conf` 与 lookup CSV：连接状态等值映射。

官网当前文档和本地 8.7.0 文件可能存在版本差异。本册涉及本地 Zeek 映射时以本地配置为准，不把官网其他版本的字段清单强行覆盖到本地文件。

## 3. 本地 CIM 数据模型总表

本地目录共有 27 个 JSON 模型文件，包括正式业务模型、2 个已废弃模型和 CIM 验证模型。

| 模型 | 中文含义 | 主要用途 |
|---|---|---|
| Alerts | 告警 | 安全产品告警、严重度和描述 |
| Authentication | 认证 | 登录、注销、成功、失败和认证方式 |
| Certificates | 证书 | X.509、签发者、主体、有效期和指纹 |
| Change | 变更 | 账号、权限、策略、系统和资源变更 |
| Compute Inventory | 计算资源清单 | 主机、OS、CPU、内存、网络和存储资产 |
| Data Access | 数据访问 | 对数据对象的读取、写入和操作 |
| Databases | 数据库 | 数据库实例、查询、会话和性能 |
| Data Loss Prevention | 数据防泄漏 | DLP 命中、敏感数据和处置动作 |
| Email | 邮件 | 发件人、收件人、附件和投递 |
| Endpoint | 终端 | 进程、服务、文件、端口和注册表 |
| Event Signatures | 事件签名 | 签名、签名 ID 和分类 |
| Interprocess Messaging | 进程间通信 | IPC 行为和消息 |
| Intrusion Detection | 入侵检测 | IDS/IPS 攻击事件 |
| Inventory | 资产清单 | 本地文件名为 `Compute_Inventory.json`，显示名为 Inventory |
| JVM | Java 虚拟机 | 内存、线程、GC 和运行状态 |
| Malware | 恶意软件 | 恶意文件、感染和处置 |
| Network Resolution | 网络解析 | DNS 查询、响应和返回码 |
| Network Sessions | 网络会话 | DHCP、VPN 和会话开始/结束 |
| Network Traffic | 网络流量 | 源/目的、端口、协议、字节和动作 |
| Performance | 性能 | CPU、内存、磁盘、网络和设施指标 |
| Splunk Audit Logs | Splunk 审计 | Splunk 管理、搜索和模块化动作审计 |
| Ticket Management | 工单管理 | 事件、问题和变更工单 |
| Updates | 更新 | 补丁、软件和签名更新 |
| Vulnerabilities | 漏洞 | 漏洞、CVE、资产和严重度 |
| Web | Web/代理 | URL、HTTP、代理和存储访问 |
| Application State | 应用状态 | 已废弃，相关能力由 Endpoint 等模型取代 |
| Change Analysis | 变更分析 | 已废弃，由 Change 模型取代 |
| CIM Validation | CIM 验证 | 检查未打 Tag 或缺失提取，不是业务日志模型 |

Splunk 官方说明，模型 JSON 位于 `$SPLUNK_HOME/etc/apps/Splunk_SA_CIM/default/data/models`；Data Model Editor 和 JSON 能显示完整层级、约束、继承字段、计算和类型。[2](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.2/data-models/how-to-use-the-cim-data-model-reference-tables)

## 4. 当前 UEBA 优先使用的 CIM

| 优先级 | 模型 | UEBA 用途 |
|---:|---|---|
| P0 | Authentication | 登录频率、失败、首次设备、位置和时间异常 |
| P0 | Network Traffic | 对外流量、连接数、稀有目的地、扫描和横向连接 |
| P0 | Endpoint | 进程、服务、文件和终端行为链 |
| P0 | Change | 账号创建、组变更、提权和策略修改 |
| P1 | Web | URL、代理、上传下载和域名行为 |
| P1 | Email | 外部收件人、附件和邮件外发 |
| P1 | Data Access | 文件、数据库和云存储对象访问 |
| P1 | Network Sessions | VPN、DHCP 和远程会话 |
| P1 | Network Resolution | 罕见域名、NXDOMAIN、DGA 和 DNS 隧道迹象 |
| P1 | DLP | 敏感内容命中和阻断证据 |
| P2 | Alerts/IDS/Malware | 融合外部告警和安全判定 |
| P2 | Inventory/Vulnerabilities | 资产和漏洞上下文 |

ES 本地 UEBA 的公开数据要求重点涉及 Authentication、Network Traffic、Web、Change、Endpoint 和 Email。模型存在并不表示任意数据源已经通过该 UEBA 内容的生产验证。

## 5. Zeek 到 CIM 的完整判断链

以 `zeek:conn` 为例：

### 5.1 sourcetype 命中 Event Type

本地 `eventtypes.conf`：

```ini
[zeek_network_traffic]
search = sourcetype IN (zeek:conn) OR eventtype IN (bro_conn)
```

因此 `sourcetype=zeek:conn` 在搜索时命中：

```text
eventtype=zeek_network_traffic
```

### 5.2 Event Type 获得 Tag

本地 `tags.conf`：

```ini
[eventtype=zeek_network_traffic]
network     = enabled
communicate = enabled
```

事件因此获得：

```text
tag=network
tag=communicate
```

### 5.3 Dataset 检查 Constraint

本地 `Network_Traffic.json` 的 `All_Traffic` 约束：

```spl
`cim_Network_Traffic_indexes` tag=network tag=communicate
```

本地默认宏 `cim_Network_Traffic_indexes` 定义为空约束，所以默认主要检查两个 Tag。若生产环境在 `local/macros.conf` 覆盖了该宏，还必须位于允许的 index。

### 5.4 搜索时生成 CIM 字段

本地 `props.conf` 的主要映射：

| Zeek 字段 | CIM 字段 |
|---|---|
| `id_orig_h` | `src`、`src_ip` |
| `id_orig_p` | `src_port` |
| `id_resp_h` | `dest`、`dest_ip` |
| `id_resp_p` | `dest_port` |
| `orig_ip_bytes` | `bytes_out` |
| `resp_ip_bytes` | `bytes_in` |
| `orig_pkts` | `packets_out` |
| `resp_pkts` | `packets_in` |
| `service` | `app` |
| `uid` | `flow_id`、`session_id` |
| `proto` | `transport` |

并计算：

```text
bytes = bytes_out + bytes_in
packets = packets_out + packets_in
vendor_product = "Zeek"
```

所以完整链路是：

```text
zeek:conn
  → zeek_network_traffic
  → network + communicate
  → Network_Traffic.All_Traffic
  → 使用 src、dest、bytes_out、action 等字段分析
```

## 6. 当前 `zeek:*` sourcetype 与 CIM 映射表

| Sourcetype | Event Type 链 | Tag | CIM Dataset |
|---|---|---|---|
| `zeek:conn` | `zeek_network_traffic` | `network`, `communicate` | `Network_Traffic.All_Traffic` |
| `zeek:dns` | `zeek_dns` | `network`, `resolution`, `dns` | `Network_Resolution.DNS` |
| `zeek:http` | `zeek_web` | `web`, `proxy`, `storage` | `Web.Web`、`Web.Proxy`、`Web.Storage` |
| `zeek:http` 且用户名、密码条件成立 | `zeek_web_auth` → `zeek_authentication` | `authentication`, `cleartext` | `Authentication.Authentication`、`Insecure_Authentication` |
| `zeek:ssh` | `zeek_ssh` → `zeek_authentication` | `authentication`, `cleartext` | `Authentication.Authentication`、`Insecure_Authentication` |
| `zeek:ntlm` | `zeek_authentication` | `authentication`, `cleartext` | `Authentication.Authentication`、`Insecure_Authentication` |
| `zeek:ssl` | `zeek_certificates` | `certificate`, `ssl`, `tls` | `Certificates.All_Certificates`、`Certificates.SSL` |
| `zeek:x509` | `zeek_certificates` | 同上 | 同上 |
| `zeek:ocsp` | `zeek_certificates` | 同上 | 同上 |
| `zeek:files` | `zeek_files` | `endpoint`, `filesystem`, `report`, `attack`, `ids`, `malware` | `Endpoint.Filesystem`、`Intrusion_Detection.IDS_Attacks`、`Malware.Malware_Attacks` |
| `zeek:smb_files` | `zeek_files` | 同上 | 同上 |
| `zeek:smb_mapping` | `zeek_files` | 同上 | 同上 |
| `zeek:notice` | `zeek_notice` | `alert` | `Alerts.Alerts` |

### 6.1 HTTP 认证条件

本地规则为：

```spl
sourcetype IN (zeek:http)
(NOT username IN (-) AND NOT password IN (-))
```

只有满足该条件的 HTTP 事件才继续获得 `authentication` 和 `cleartext` Tag。实际部署必须验证字段不存在、空值、`-` 和脱敏值的行为。

### 6.2 Connection Action 子 Dataset

`zeek:conn` 通过 `conn_state` lookup 生成 `action`：

```text
SF/S1/OTH 等 → action=allowed
S0/REJ 等    → action=blocked
```

对应继承关系：

```text
All_Traffic                         tag=network tag=communicate
└── Traffic_By_Action              action=*
    ├── Allowed_Traffic            action=allowed
    └── Blocked_Traffic            action=blocked
```

因此 `action=allowed` 的一条事件同时属于父子三个 Dataset，但仍只有一条原始事件。

## 7. 旧版 `bro_*` 兼容映射

| Sourcetype | CIM Dataset |
|---|---|
| `bro_conn`、`bro:conn:json` | `Network_Traffic.All_Traffic` |
| `bro_dns`、`bro:dns:json` | `Network_Resolution.DNS` |
| `bro_http`、`bro:http:json` | `Web.Web`、`Web.Proxy`、`Web.Storage` |
| `bro_files`、`bro:files:json` | `Endpoint.Filesystem`、`IDS_Attacks`、`Malware_Attacks` |
| `bro_ssl`、`bro:ssl:json` | `Certificates.All_Certificates`、`Certificates.SSL` |
| `bro_x509`、`bro:x509:json` | 同上 |
| `bro_ssh`、`bro:ssh:json` | `Authentication.Authentication`、`Insecure_Authentication` |
| `bro_smtp`、`bro:smtp:json` | `Email.All_Email`、`Email.Delivery` |
| `bro_smtp_entities`、`bro:smtp_entities:json` | `Email.All_Email` |
| `bro_dhcp`、`bro:dhcp:json` | `Network_Sessions.All_Sessions`、`Network_Sessions.DHCP` |
| `bro_notice`、`bro:notice:json` | `Alerts.Alerts`、`Intrusion_Detection.IDS_Attacks` |

本地 `zeek:notice` 只有 `alert` Tag，而旧 `bro_notice` 还有 `ids` 和 `attack` Tag，所以二者并非完全等价。

## 8. 有字段配置但没有自动 CIM 映射的 Zeek 类型

以下 sourcetype 在本地 `props.conf` 中存在 stanza，但没有完整的 eventtype/tag 到 CIM 约束链：

```text
zeek:ftp              zeek:smtp            zeek:dhcp
zeek:ntp              zeek:irc             zeek:rdp
zeek:traceroute       zeek:tunnel          zeek:dpd
zeek:software         zeek:weird           zeek:capture_loss
zeek:reporter         zeek:dce_rpc         zeek:analyzer
zeek:kerberos         zeek:smb_cmd         zeek:snmp
zeek:quic             zeek:pe              zeek:known_certs
zeek:known_hosts      zeek:known_services
```

“没有自动映射”表示当前本地 Add-on 未通过 Event Type/Tag 让其满足 CIM Constraint，不表示数据没有价值或不能自定义映射。尤其是旧 `bro_smtp`、`bro_dhcp` 有映射，而新的 `zeek:smtp`、`zeek:dhcp` 没有对应规则，应作为版本兼容性和本地补充项验证。

## 9. Tag 到 CIM Dataset 的核心规则

```text
tag=alert
  → Alerts.Alerts

tag=authentication
  → Authentication.Authentication

tag=authentication + (tag=insecure OR tag=cleartext)
  → Authentication.Insecure_Authentication

tag=certificate
  → Certificates.All_Certificates

tag=certificate + (tag=ssl OR tag=tls)
  → Certificates.SSL

tag=endpoint + tag=filesystem
  → Endpoint.Filesystem

tag=ids + tag=attack
  → Intrusion_Detection.IDS_Attacks

tag=malware + tag=attack
  → Malware.Malware_Attacks

tag=network + tag=resolution + tag=dns
  → Network_Resolution.DNS

tag=network + tag=session
  → Network_Sessions.All_Sessions

tag=network + tag=session + tag=dhcp
  → Network_Sessions.DHCP

tag=network + tag=communicate
  → Network_Traffic.All_Traffic

tag=email
  → Email.All_Email

tag=email + tag=delivery
  → Email.Delivery

tag=web
  → Web.Web

tag=web + tag=proxy
  → Web.Proxy

tag=web + tag=storage
  → Web.Storage
```

## 10. Dataset 的作用

Dataset 是 Data Model 内带语义的事件集合，主要有五个作用：

1. 用 Constraint 选择属于该业务语义的事件；
2. 通过父子结构复用并细化约束；
3. 定义字段、字段类型和计算字段；
4. 为 SPL、Pivot、Dashboard 和检测提供稳定查询入口；
5. 启用 Data Model Acceleration 后，规定需要摘要的分析字段范围。

例如：

```text
Authentication
├── Failed_Authentication
├── Successful_Authentication
├── Default_Authentication
├── Insecure_Authentication
└── Privileged_Authentication
```

检测可以直接查询失败认证 Dataset，而不必知道底层来自 Windows、VPN、SSH 还是 Web：

```spl
| datamodel Authentication Failed_Authentication search
```

## 11. 同一事件命中多个模型或 Dataset

必须区分原始事件、逻辑归属、摘要和检测结果：

| 对象 | 数量含义 |
|---|---|
| 原始事件 | 通常仍为一条 |
| Event Type/Tag | 可以有多组 |
| CIM 模型归属 | 可以有多个 |
| Dataset 归属 | 可同时属于父级和多个符合约束的子级 |
| DMA 摘要 | 不同加速模型可能分别维护摘要表示 |
| Finding/Risk Event | 取决于命中的检测，可能为零、一条或多条 |

例如本地 `zeek:files` 会获得多组 Tag，逻辑上可同时进入：

```text
Endpoint.Filesystem
Intrusion_Detection.IDS_Attacks
Malware.Malware_Attacks
```

这表示同一事件有三个模型视角，不是自动复制成三条 `_raw`。如果三个检测分别命中，则可能产生三条独立检测结果。

需要特别注意：所有 `zeek:files` 被打上 `ids+attack`、`malware+attack` 并不自动证明每个文件都是攻击或恶意软件。进入模型是配置事实，安全结论还要检查 signature、notice、category、hash、action 和检测来源，防止语义过度映射。

## 12. Dataset 的字段缺失边界

事件满足 Tag Constraint 后，即使缺少部分字段也可能进入根 Dataset。例如 `All_Traffic` 的约束没有直接要求 `src=*`、`dest=*`、`bytes_out=*` 或 `user=*`。

CIM 可把部分缺失字段补成 `unknown` 或 `0`，但必须区分：

```text
模型命中：满足 Constraint
字段合规：字段名、类型和值符合 CIM
检测可用：具体检测需要的字段真实完整
```

所以：

```text
进入 Network_Traffic
≠ 高质量符合 Network_Traffic
≠ 满足某条 UEBA 检测要求
```

## 13. 在哪里查看 Dataset

### 13.1 Splunk Web

```text
Settings
→ Data Models
→ 选择模型
→ Edit Data Model
```

在 Enterprise Security 中也可以：

```text
Search
→ Datasets
→ Manage / Edit Data Model
```

Data Model Editor 能看到 Dataset 层级、Constraint、继承字段、计算字段和类型。需要相应读取或编辑权限。[2](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.2/data-models/how-to-use-the-cim-data-model-reference-tables)

### 13.2 服务器 JSON

```text
$SPLUNK_HOME/etc/apps/Splunk_SA_CIM/default/data/models/
```

关键属性：

| 属性 | 含义 |
|---|---|
| `objectName` | Dataset 内部名称 |
| `displayName` | 显示名称 |
| `parentName` | 父 Dataset |
| `constraints` / `baseSearch` | 事件选择条件 |
| `fields` | 字段定义 |
| `calculations` | 计算字段 |
| `children` | 子 Dataset |

## 14. 怎样查询 Dataset

### 14.1 展开为普通事件搜索

```spl
| datamodel Network_Traffic All_Traffic search
```

```spl
| datamodel Network_Traffic Allowed_Traffic search
```

```spl
| datamodel Endpoint Filesystem search
```

这种方式适合首次验证 Constraint 和原始事件。

### 14.2 使用 `from datamodel`

```spl
| from datamodel:"Authentication.Failed_Authentication"
| stats count BY user
```

### 14.3 使用加速摘要和 `tstats`

```spl
| tstats
    count
    sum(All_Traffic.bytes_out) AS bytes_out
  FROM datamodel=Network_Traffic.All_Traffic
  BY All_Traffic.src All_Traffic.dest
```

只读取已完成摘要：

```spl
| tstats summariesonly=true count
  FROM datamodel=Network_Traffic.All_Traffic
  BY All_Traffic.sourcetype
```

`summariesonly=true` 返回少量数据可能表示摘要滞后，而不是源事件少。首次验证应同时对比未加速 Data Model Search。

## 15. 怎样列出模型和 Dataset

列出当前 Search Head 可见模型：

```spl
| rest splunk_server=local count=0 /services/data/models
| rename title AS model
| table model eai:acl.app eai:acl.owner eai:acl.sharing
| sort model
```

展开某模型的 Dataset：

```spl
| rest splunk_server=local count=0 /services/data/models
| search title="Network_Traffic"
| spath input=eai:data output=datasets path=objects{}
| mvexpand datasets
| spath input=datasets output=dataset path=objectName
| spath input=datasets output=display_name path=displayName
| spath input=datasets output=parent path=parentName
| spath input=datasets output=constraints path=constraints{}.search
| table dataset display_name parent constraints
```

不同 Splunk/CIM 版本的 REST 返回结构可能变化，最终以 Data Model Editor 和模型 JSON 为准。

## 16. 怎样验证 Zeek 是否真正命中

### 16.1 验证 Event Type 和 Tag

```spl
index=<目标索引> sourcetype=zeek:conn
| head 20
| table _time sourcetype eventtype tag::eventtype
```

应看到 `zeek_network_traffic` 以及 `network`、`communicate`。

### 16.2 验证模型命中

```spl
| datamodel Network_Traffic All_Traffic search
| search sourcetype=zeek:conn
| stats count
```

### 16.3 验证字段语义

```spl
index=<目标索引> sourcetype=zeek:conn
| head 20
| table
    _time uid
    id_orig_h src src_ip
    id_resp_h dest dest_ip
    id_orig_p src_port
    id_resp_p dest_port
    orig_ip_bytes bytes_out
    resp_ip_bytes bytes_in
    conn_state action direction transport
```

要对照原字段验证，不是只检查 CIM 字段非空。`ASNEW` 不会覆盖已经存在的目标字段，多个 Add-on 同时生效时可能出现 `src` 与 `id_orig_h` 不一致。

### 16.4 验证允许/阻断子 Dataset

```spl
| datamodel Network_Traffic Allowed_Traffic search
| search sourcetype=zeek:conn
| stats count BY conn_state action
```

```spl
| datamodel Network_Traffic Blocked_Traffic search
| search sourcetype=zeek:conn
| stats count BY conn_state action
```

## 17. 常见失败原因

| 现象 | 可能原因 |
|---|---|
| 有事件但模型无数据 | sourcetype 不匹配 eventtype；Tag 未生效；index 宏限制 |
| 有 eventtype 但无模型数据 | tags.conf 未进入正确 App/权限作用域 |
| 模型有数据但字段为空 | props/lookup 未部署到搜索执行层；字段名称或格式变化 |
| 字段存在但值错误 | 多 Add-on 冲突；`ASNEW` 保留了旧值；方向和字节口径错误 |
| 普通 Data Model Search 有数据、`tstats` 少数据 | DMA 未开启、摘要范围不足或 Summarization Lag |
| 模型有数据但 UEBA 无结果 | 检测必需字段缺失、窗口不满足、任务未运行或基线未成熟 |

## 18. 实施建议

1. 第一阶段优先验证 Authentication、Network Traffic、Endpoint、Change、Web 和 Email；
2. 为每种 sourcetype 保存 `eventtype → tag → Dataset → 必需字段` 映射表；
3. 把“模型命中率”和“关键字段完整率”分开监控；
4. 对多模型映射执行语义复核，尤其是 `zeek:files`；
5. 不修改 Add-on 的 `default` 文件，本地补充放在 `local` 并记录版本；
6. 升级 TA 或 CIM 后重新执行 Dataset、字段、DMA 和检测回归；
7. 最终异常必须能够回查 sourcetype、eventtype、tag、Dataset、字段版本和原始事件。

## 19. 主要官方资料

- Splunk，[Overview of the Splunk Common Information Model](https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/overview-of-the-splunk-common-information-model)。
- Splunk，[How to use the CIM data model reference tables](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.2/data-models/how-to-use-the-cim-data-model-reference-tables)。
- Splunk，[Use the CIM to normalize data at search time](https://help.splunk.com/en/data-management/common-information-model/6.3/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time)。
- Splunk，[CIM fields per associated data model](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/6.0/data-models/cim-fields-per-associated-data-model)。
- 本地证据：`Splunk_TA_zeek/default/eventtypes.conf`、`tags.conf`、`props.conf`、`transforms.conf` 及 `Splunk_SA_CIM/default/data/models/*.json`。
