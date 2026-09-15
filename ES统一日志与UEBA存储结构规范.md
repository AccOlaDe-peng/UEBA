# ES 统一日志与 UEBA 存储结构规范

> 版本：1.0.0  
> 日期：2026-09-15  
> 输入依据：[Windows AD 日志 ECS 字段映射规范](./Windows-AD日志ECS字段映射规范.md)、Zeek ECS 字段映射表  
> 适用范围：Windows AD、Zeek，以及后续 VPN、DHCP、Linux、堡垒机、EDR、代理、邮件、数据库和云审计日志  
> 配套 Mapping：[elasticsearch-storage-schema](./elasticsearch-storage-schema)

## 1. 核心结论

最终存储结构不采用“一张包含全部厂商字段的大表”，而采用：

```text
统一事件外壳
  + 按事件出现的 ECS 字段集
  + ueba.* 质量、语义和证据字段
  + 来源专用的少量显式字段
  + 不受控长尾字段容器
  + 原始证据或原始证据引用
```

所有日志共享字段语义和类型，但每条事件只填写自身适用的字段。不存在或不适用的字段必须省略，不写 `null`、空字符串或厂商占位符 `-`。

## 2. ES 中的完整存储分层

```text
L0 原始证据层
  object storage / logs-ueba.raw-*
          │
L1 标准事件层
  logs-ueba.<dataset>-<namespace>
          │
L2 实体与时态关系层
  ueba-entities-*
  ueba-entity-relations-*
          │
L3 特征与基线层
  ueba-features-*
  ueba-baselines-*
          │
L4 检测与风险层
  ueba-anomalies-*
  ueba-risk-events-*
  ueba-cases-*
```

Windows 和 Zeek 字段首先进入 L1 标准事件层。本规范同时定义后续 UEBA 索引的职责，避免把实体、基线和风险结果写回原始日志 Data Stream。

## 3. 索引与 Data Stream 清单

### 3.1 标准事件 Data Stream

命名格式：

```text
logs-ueba.<dataset>-<namespace>
```

| Data Stream | 典型来源 | 主要事件 |
|---|---|---|
| `logs-ueba.authentication-default` | Windows、VPN、IdP、Linux、堡垒机 | 登录、失败、注销、票据、凭据验证 |
| `logs-ueba.iam-default` | Windows AD、IdP、云 IAM | 用户、计算机、组、权限变更 |
| `logs-ueba.directory-default` | Windows AD、LDAP 审计 | 对象访问、目录操作、安全描述符变更 |
| `logs-ueba.endpoint-default` | Windows、Linux Audit、EDR | 进程、服务、注册表、模块 |
| `logs-ueba.network-default` | Zeek conn、Firewall、NDR、EDR | 网络连接和流量 |
| `logs-ueba.dns-default` | Zeek DNS、DNS Server、Resolver | DNS 查询和响应 |
| `logs-ueba.web-default` | Zeek HTTP、Proxy、WAF | HTTP 请求和响应 |
| `logs-ueba.tls-default` | Zeek SSL、Proxy、NDR | TLS 会话和证书观察 |
| `logs-ueba.file-default` | Zeek files、EDR、DLP、文件审计 | 文件访问、创建、传输和哈希 |
| `logs-ueba.session-default` | VPN、DHCP、堡垒机 | 会话及地址分配 |
| `logs-ueba.alert-default` | Zeek notice、EDR、IDS、DLP | 来源系统告警 |
| `logs-ueba.state-default` | Zeek known_*、资产采集 | 软件、服务和资产观察状态 |
| `logs-ueba.metric-default` | Zeek stats/telemetry、Pipeline 监控 | 采集与传感器指标 |

`namespace` 表示租户、环境或隔离域，例如 `default`、`prod`、`tenant-a`。多租户系统还必须写入 `organization.id`，不能只依赖 Data Stream 名称隔离。

### 3.2 原始证据与隔离

| 存储 | 类型 | 用途 |
|---|---|---|
| 对象存储 `ueba-raw/<tenant>/<source>/<date>/...` | 首选 | 保存完整 XML、JSON、TSV、Syslog，支持低成本留存和重放 |
| `logs-ueba.raw-<namespace>` | 可选 Data Stream | 小规模或短周期保存原文信封 |
| Data Stream Failure Store | Elasticsearch 系统能力 | 保存 Mapping、时间、IP 类型等索引失败 |
| `logs-ueba.quarantine-<namespace>` | Data Stream | 保存可索引但语义为 `invalid`、`unsupported` 的事件 |

Pipeline 捕获的业务错误进入隔离流；无法完成索引的错误进入 Failure Store。两者不能混为同一种失败。

### 3.3 UEBA 派生存储

| 索引或 Data Stream | 推荐形态 | 主键/时间键 | 用途 |
|---|---|---|---|
| `ueba-entities-<namespace>` | 普通索引＋Alias | `entity.id` | 人员、账号、设备、IP、应用等实体当前视图 |
| `ueba-entity-relations-<namespace>` | Data Stream | `@timestamp`＋`relation.id` | 用户—账号—设备—IP 的有效期关系和证据 |
| `ueba-features-<namespace>` | Data Stream | `@timestamp`＋实体＋窗口＋特征版本 | 行为窗口特征 |
| `ueba-baselines-<namespace>` | 普通索引＋版本 Alias | 实体/同群＋特征＋模型版本 | 已发布基线和训练元数据 |
| `ueba-anomalies-<namespace>` | Data Stream | `@timestamp`＋`anomaly.id` | 单项异常、解释和证据 |
| `ueba-risk-events-<namespace>` | Data Stream | `@timestamp`＋`risk.id` | 实体风险增量、衰减和关联结果 |
| `ueba-cases-<namespace>` | 普通索引 | `case.id` | 调查状态、处置和反馈 |

## 4. 标准事件顶层结构

```json
{
  "@timestamp": "2026-09-15T08:20:00.074Z",
  "ecs": {},
  "data_stream": {},
  "organization": {},
  "agent": {},
  "event": {},
  "log": {},
  "message": "",
  "tags": [],
  "labels": {},
  "user": {},
  "group": {},
  "host": {},
  "observer": {},
  "source": {},
  "destination": {},
  "client": {},
  "server": {},
  "network": {},
  "process": {},
  "service": {},
  "file": {},
  "url": {},
  "http": {},
  "dns": {},
  "tls": {},
  "related": {},
  "ueba": {},
  "winlog": {},
  "zeek": {},
  "vendor": {}
}
```

这不是要求每条事件都出现全部对象，而是定义允许出现的受控顶层命名空间。

## 5. 公共字段合同

### 5.1 事件与来源

| 字段 | ES 类型 | 要求 | 说明 |
|---|---|---|---|
| `@timestamp` | `date` | 必须 | 事件发生时间，统一 UTC |
| `event.id` | `keyword` | 必须 | 稳定幂等事件 ID |
| `event.kind` | `keyword` | 必须 | `event`、`alert`、`state`、`metric`、`pipeline_error` |
| `event.category` | `keyword[]` | 必须 | ECS 受控事件大类 |
| `event.type` | `keyword[]` | 必须 | ECS 受控事件类型 |
| `event.action` | `keyword` | 必须 | 来源动作的规范化名称 |
| `event.outcome` | `keyword` | 条件必填 | `success`、`failure`、`unknown` |
| `event.code` | `keyword` | 条件必填 | Windows Event ID 或来源事件代码 |
| `event.module` | `keyword` | 必须 | `windows`、`zeek`、`vpn`、`linux` 等 |
| `event.dataset` | `keyword` | 必须 | 来源数据集，例如 `zeek.conn` |
| `event.provider` | `keyword` | 推荐 | 原始事件提供者 |
| `event.created` | `date` | 推荐 | 采集器创建事件时间 |
| `event.ingested` | `date` | 必须 | ES Ingest 时间 |
| `event.start` / `event.end` | `date` | 条件推荐 | 有持续时间的事件 |
| `event.duration` | `long` | 条件推荐 | 纳秒 |
| `event.reason` | `keyword` | 条件推荐 | 受控或短失败原因 |
| `event.original` | `keyword,index:false` | 可选 | 短期原文；长期原文首选对象存储 |
| `data_stream.type` | `constant_keyword` | 必须 | 固定 `logs` |
| `data_stream.dataset` | `constant_keyword` | 必须 | 与目标 Data Stream dataset 一致 |
| `data_stream.namespace` | `constant_keyword` | 必须 | 环境或租户命名空间 |
| `organization.id` | `keyword` | 多租户必须 | 租户稳定 ID |

### 5.2 身份、资产与角色

| 字段组 | 主要字段 | 用途 |
|---|---|---|
| `user.*` | `id`、`name`、`domain`、`full_name`、`email`、`roles` | 主要行为用户或认证账号 |
| `user.target.*` | 与 `user.*` 相同 | 被操作的目标用户 |
| `user.effective.*` | 与 `user.*` 相同 | 提权、模拟后的有效用户 |
| `user.changes.*` | 与 `user.*` 相同 | 可证明的用户属性变化结果 |
| `group.*` | `id`、`name` | 被操作的安全组 |
| `host.*` | `id`、`name`、`hostname`、`domain`、`ip`、`mac`、`os.*` | 行为涉及的设备 |
| `observer.*` | `id`、`name`、`hostname`、`ip`、`vendor`、`product`、`type` | Zeek、Firewall、域控等观测点 |
| `related.*` | `ip`、`user`、`hosts`、`hash` | 一跳检索关联标识，不作为角色替代品 |

Windows IAM 事件中，`SubjectUser*` 通常映射到 `user.*`，被操作账号映射到 `user.target.*`。Windows 登录事件中，正在认证的 `TargetUser*` 是主要行为用户，应映射到 `user.*`。组成员可能是用户、设备或嵌套组，实体类型不明确时只保留来源字段。

### 5.3 网络、应用和内容

| 字段组 | 关键字段 | 主要来源 |
|---|---|---|
| `source.*` | `ip`、`port`、`mac`、`address`、`bytes`、`packets` | Zeek、Firewall、VPN、登录来源 |
| `destination.*` | 与 source 对应 | Zeek、Proxy、EDR、堡垒机 |
| `client.*` / `server.*` | IP、端口、地址、字节 | 角色明确的客户端/服务端协议 |
| `network.*` | `transport`、`protocol`、`direction`、`community_id`、`bytes`、`packets` | Zeek、Firewall、NDR |
| `process.*` | PID、名称、路径、命令行、父进程 | Windows 4688/4689、Linux、EDR |
| `file.*` | 名称、路径、大小、MIME、哈希 | Zeek files、EDR、DLP、文件审计 |
| `url.*` | original、full、domain、path、query | Zeek HTTP、Proxy、WAF |
| `http.*` | 方法、状态码、请求/响应字节 | Zeek HTTP、Proxy、WAF |
| `dns.*` | 问题、响应码、回答、resolved_ip | Zeek DNS、DNS Server |
| `tls.*` | 版本、Cipher、证书、JA3/JA4 扩展 | Zeek SSL、Proxy、NDR |

`source`/`destination` 表示事件的方向事实；`client`/`server` 表示协议角色。两组字段可以同时填写，但不得用采集接口的入站/出站方向机械替代通信方向。

## 6. UEBA 扩展结构

```json
{
  "ueba": {
    "schema": {"version": "1.0.0"},
    "source": {
      "type": "zeek_conn",
      "namespace": "tenant-a/zeek-01",
      "native_event_id": "C7ITfR36nj8uB9HvO6",
      "collected_at": "2026-09-15T08:20:01Z",
      "received_at": "2026-09-15T08:20:02Z"
    },
    "event": {
      "type": "network.connection",
      "semantic_tags": ["outbound"]
    },
    "session": {
      "id": "C7ITfR36nj8uB9HvO6",
      "type": "network_flow"
    },
    "time": {
      "source": "zeek_ts",
      "quality": "exact"
    },
    "provenance": {
      "raw_event_id": "...",
      "parser_id": "zeek_json",
      "parser_version": "1.0.0",
      "mapping_id": "zeek_conn_json",
      "mapping_version": "1.0.0"
    },
    "quality": {
      "status": "qualified",
      "score": 1.0,
      "errors": [],
      "warnings": []
    }
  }
}
```

`ueba.event.type` 是跨来源检测使用的稳定事件类型。`event.action` 可以保留来源动作差异，但检测不得仅依赖未经治理的自由动作字符串。

## 7. 来源扩展结构

### 7.1 Windows

```json
{
  "winlog": {
    "record_id": "185808",
    "channel": "Security",
    "provider_guid": "{...}",
    "version": "3",
    "activity_id": "{...}",
    "logon": {
      "type": "3",
      "status": "0x0",
      "authentication_package": "Kerberos",
      "guid": "{...}"
    },
    "kerberos": {
      "status": "0x0",
      "ticket_options": "0x40810010",
      "ticket_encryption_type": "0x12"
    },
    "group": {
      "member_sid": "S-1-5-21-...",
      "member_name": "CN=...",
      "scope": "global"
    },
    "raw": {}
  }
}
```

`winlog.logon.*`、`winlog.kerberos.*`、`winlog.group.*` 等高价值字段使用显式 Mapping。其余 EventData 放入 `winlog.raw` 的 `flattened` 容器，不能让任意 EventData 名称动态创建 ES 字段。

### 7.2 Zeek

```json
{
  "zeek": {
    "session_id": "C7ITfR36nj8uB9HvO6",
    "conn": {
      "state": "SF",
      "history": "ShADdafR",
      "local_orig": true,
      "local_resp": false,
      "missed_bytes": 0,
      "orig_ip_bytes": 2594,
      "resp_ip_bytes": 4769
    },
    "file": {"fuid": "Fiiom02ZsOnQsITcx9"},
    "raw": {}
  }
}
```

Zeek 能映射到 ECS 的字段写入 ECS；连接状态、UID、文件 UID、捕获质量等专有字段进入显式 `zeek.*`；其余 271 个长尾字段保存在 `zeek.raw`。

### 7.3 后续来源

后续来源采用统一规则：

```text
ECS 已有且语义一致
  → ECS 字段

UEBA 质量、证据或事件目录需要
  → ueba.*

来源专有且被查询、关联或检测使用
  → <source>.<domain>.<field> 显式 Mapping

来源专有长尾字段
  → vendor.name + vendor.dataset + vendor.payload(flattened)

完整原始消息
  → event.original(index:false) 或对象存储引用
```

通用厂商容器：

```json
{
  "vendor": {
    "name": "vendor-name",
    "product": "product-name",
    "dataset": "source-log-type",
    "schema_version": "source-version",
    "payload": {}
  }
}
```

`vendor.payload` 使用 `flattened`，不得在其下声明动态对象。

## 8. Mapping 组合方式

```text
logs-ueba.authentication-*
  = ueba-events-base@1.0.0
  + ueba-authentication@1.0.0
  + ueba-winlog@1.0.0

logs-ueba.network-*
  = ueba-events-base@1.0.0
  + ueba-network@1.0.0
  + ueba-zeek@1.0.0

logs-ueba.web-*
  = ueba-events-base@1.0.0
  + ueba-network@1.0.0
  + ueba-http@1.0.0
  + ueba-zeek@1.0.0
```

实际部署时，不应把来源模板永久绑定到领域模板。一个认证 Data Stream 可能同时接收 Windows、VPN 和 Linux；其 Index Template 可以组合多个兼容的来源模板，或将来源模板中的显式字段并入稳定公共版本。

## 9. 动态字段和字段爆炸控制

生产 Mapping 使用以下策略：

| 区域 | `dynamic` 策略 | 原因 |
|---|---|---|
| 顶层标准事件 | `strict` | 阻止未知顶层对象绕过治理 |
| ECS 核心对象 | `strict` 或显式字段集合 | 保证类型、单位和角色稳定 |
| `ueba.*` | `strict` | 检测合同必须版本化 |
| `winlog.*` / `zeek.*` | `strict` | 来源高价值字段必须受控 |
| `winlog.raw` / `zeek.raw` | `flattened` | 保存长尾字段且不产生大量 Mapping |
| `vendor.payload` | `flattened` | 为未知后续来源提供受控扩展区 |

同时设置：

```text
index.mapping.total_fields.limit = 2500
index.mapping.depth.limit = 20
index.mapping.nested_fields.limit = 20
```

字段名中包含用户、文件、注册表路径或任意动态 Key 时，禁止直接展开为 Mapping。

## 10. 一个 Windows 标准事件

```json
{
  "@timestamp": "2026-09-11T03:41:51.777Z",
  "event": {
    "id": "<stable-id>",
    "kind": "event",
    "code": "4624",
    "module": "windows",
    "dataset": "microsoft.windows.security",
    "category": ["authentication"],
    "type": ["start"],
    "action": "logged-in",
    "outcome": "success"
  },
  "host": {"hostname": "win-139.test.local"},
  "user": {
    "id": "S-1-5-21-...-1122",
    "name": "UEBALOGON-11113950",
    "domain": "TEST.LOCAL"
  },
  "source": {"ip": "10.6.6.169", "port": 57035},
  "winlog": {
    "record_id": "185808",
    "channel": "Security",
    "version": "3",
    "logon": {"type": "3", "authentication_package": "Kerberos"}
  },
  "ueba": {
    "schema": {"version": "1.0.0"},
    "event": {"type": "authentication.login", "semantic_tags": ["network_logon"]},
    "session": {"id": "0x1719f29d", "type": "windows_logon"},
    "quality": {"status": "qualified", "score": 1.0},
    "provenance": {
      "raw_event_id": "tenant-a/win-139/Security/185808",
      "parser_id": "windows_security_xml",
      "parser_version": "1.0.0",
      "mapping_id": "windows_security_4624",
      "mapping_version": "1.0.0"
    }
  }
}
```

## 11. 一个 Zeek 标准事件

```json
{
  "@timestamp": "2026-09-15T08:20:00.074Z",
  "event": {
    "id": "<stable-id>",
    "kind": "event",
    "module": "zeek",
    "dataset": "zeek.conn",
    "category": ["network"],
    "type": ["connection"],
    "action": "network-connection",
    "outcome": "success",
    "duration": 63023000
  },
  "source": {"ip": "10.6.69.21", "port": 58832, "bytes": 1858, "packets": 14},
  "destination": {"ip": "10.6.68.71", "port": 9200, "bytes": 4189, "packets": 11},
  "network": {
    "transport": "tcp",
    "protocol": "ssl",
    "direction": "internal",
    "bytes": 6047,
    "packets": 25
  },
  "observer": {"hostname": "zeek-01", "vendor": "Zeek", "product": "Zeek", "type": "nids"},
  "zeek": {
    "session_id": "C7ITfR36nj8uB9HvO6",
    "conn": {
      "state": "SF",
      "history": "ShADdafR",
      "local_orig": true,
      "local_resp": true,
      "missed_bytes": 0
    }
  },
  "ueba": {
    "schema": {"version": "1.0.0"},
    "event": {"type": "network.connection", "semantic_tags": ["internal"]},
    "session": {"id": "C7ITfR36nj8uB9HvO6", "type": "network_flow"},
    "quality": {"status": "qualified", "score": 1.0},
    "provenance": {
      "raw_event_id": "tenant-a/zeek-01/conn/C7ITfR36nj8uB9HvO6/1789448400.074496",
      "parser_id": "zeek_json",
      "parser_version": "1.0.0",
      "mapping_id": "zeek_conn_json",
      "mapping_version": "1.0.0"
    }
  }
}
```

Zeek 标准事件不直接填写无法由日志证明的 `user.*`。实体解析服务通过事件时间、IP、DHCP/VPN/Windows 登录关系产生用户归属，并在派生关系或特征中保存置信度。

## 12. UEBA 派生索引核心结构

### 12.1 实体索引 `ueba-entities-*`

| 字段 | 类型 | 说明 |
|---|---|---|
| `entity.id` | `keyword` | 全局稳定实体 ID |
| `entity.type` | `keyword` | `person`、`account`、`device`、`ip`、`application` |
| `entity.name` | `keyword` | 展示名称 |
| `entity.status` | `keyword` | active、disabled、deleted 等 |
| `entity.attributes` | `flattened` | 来源属性当前视图 |
| `entity.first_seen` / `last_seen` | `date` | 生命周期 |
| `entity.source_refs` | `keyword[]` | HR、AD、CMDB 等主档引用 |
| `organization.id` | `keyword` | 租户 |
| `version` | `long` | 乐观并发和修订版本 |

### 12.2 时态关系 `ueba-entity-relations-*`

| 字段 | 类型 | 说明 |
|---|---|---|
| `@timestamp` | `date` | 关系观察或生效时间 |
| `relation.id` | `keyword` | 稳定关系 ID |
| `relation.type` | `keyword` | owns、uses、logged_on、assigned_ip 等 |
| `relation.source.entity_id` | `keyword` | 关系起点 |
| `relation.target.entity_id` | `keyword` | 关系终点 |
| `relation.valid_from` / `valid_to` | `date` | 事件时态有效区间 |
| `relation.confidence` | `scaled_float` | 归属置信度 |
| `relation.evidence_event_ids` | `keyword[]` | Windows、VPN、DHCP 等证据 |
| `relation.resolution_version` | `keyword` | 实体解析版本 |

### 12.3 特征与基线

| 字段 | 特征索引 | 基线索引 |
|---|---|---|
| 主体 | `entity.id/type` | `entity.id/type` 或 `peer_group.id` |
| 定义 | `feature.id/version` | `feature.id/version` |
| 时间 | `window.start/end` | `training.start/end` |
| 数值 | `feature.value`、`sample_count` | `baseline.mean/stddev/quantiles` |
| 版本 | `mapping_version`、`resolution_version` | `model.id/version` |
| 质量 | `quality.status/score` | `training.quality` |

### 12.4 异常和风险

| 字段 | 类型 | 说明 |
|---|---|---|
| `anomaly.id` / `risk.id` | `keyword` | 稳定结果 ID |
| `entity.id/type` | `keyword` | 被评分人员、账号或设备 |
| `anomaly.type` | `keyword` | 新设备、异常时段、异常传输等 |
| `anomaly.score` | `scaled_float` | 单项异常分 |
| `risk.score` | `scaled_float` | 实体累计风险分 |
| `risk.level` | `keyword` | low、medium、high、critical |
| `evidence.event_ids` | `keyword[]` | 标准事件证据 |
| `explanation.*` | 显式字段＋`flattened` | 基线、当前值和偏离原因 |
| `rule.id/version`、`model.id/version` | `keyword` | 检测和模型版本 |
| `status` | `keyword` | open、investigating、closed、suppressed |

派生索引必须引用标准事件 ID 和处理版本，不复制全部原始事件。关系修正或 Mapping 升级后，系统应能够定位并重算受影响的特征、异常和风险。

## 13. 字段晋升机制

新来源字段进入系统时执行：

```text
原始字段进入 vendor.payload
  → 观察覆盖率、类型和业务用途
  → 确认用于搜索、实体、关联、特征或检测
  → 定义语义、角色、类型、单位和缺失规则
  → 增加显式 Mapping 与 Pipeline
  → 增加正常、异常和版本兼容测试
  → 发布新 Minor 版本
```

只有满足下列条件之一的字段才应晋升：

- 能映射到语义一致的 ECS 字段；
- 是实体稳定标识或时态关系证据；
- 被行为特征或检测规则直接使用；
- 被高频调查查询使用；
- 用于数据质量和采集健康判断；
- 是跨事件关联键。

## 14. 模板发布与兼容规则

| 变化 | 版本影响 |
|---|---|
| 增加可选字段、来源或事件类型 | Minor |
| 修改字段含义、角色、单位、主类型或实体键 | Major |
| 修正文档且不改变运行结果 | Patch |

字段废弃采用：

```text
新增替代字段
  → 双写观察
  → 消费者迁移
  → 停止写入旧字段
  → 后续 Major 版本移除
```

每条事件必须保存 Schema、Parser 和 Mapping 版本，确保旧数据可解释、可重放。

## 15. 生产验收条件

最终结构投入生产前至少验证：

1. Windows 32 个关键 Event ID 的核心字段和角色正确；
2. Zeek 17 类日志可映射 ECS，271 个字段不会形成动态 Mapping；
3. 未知来源字段只能进入 `vendor.payload` 或隔离流；
4. 同名字段在不同来源中保持相同类型、单位和方向；
5. `event.id` 在重放中稳定且不重复；
6. 原始证据、Parser 和 Mapping 版本可追溯；
7. `qualified`、`partial`、`invalid`、`unsupported` 能触发正确检测门禁；
8. Windows 登录和 Zeek 网络事件能通过时态关系关联到正确设备和用户；
9. Mapping 冲突进入 Failure Store，并具备修复和重放流程；
10. ILM、Shard、字段权限、脱敏和租户隔离通过容量与安全评审。

## 16. 最终设计边界

“统一”表示共同的语义合同、类型、角色、质量和证据规则，并不表示所有日志必须拥有相同字段集合，也不表示所有厂商字段都要建立索引。

最终原则是：

> ECS 承载跨来源事实，`ueba.*` 承载检测合同，来源命名空间承载高价值专有字段，`flattened` 承载长尾属性，对象存储承载完整原始证据；实体、特征、基线和风险使用独立索引。
