# 数据进入与 UEBA 特征计算机制

## 1. 本册回答什么问题

本册以建议的 `采集器 + Kafka + OpenSearch + ClickHouse + Flink + 对象存储` 架构为对象，回答四个问题：

1. 一条 Windows、AD、Zeek、终端或云审计日志怎样进入平台；
2. 每个环节什么时候可以确认数据已成功交付；
3. UEBA 特征到底在什么时候、由哪个组件、对什么数据执行；
4. 当前行为怎样与历史基线比较并生成可调查的异常证据。

文中的组件能力事实引用项目官方文档；具体字段、周期、阈值和数据表是建议设计或示例，需要通过本项目 POC 确认。

## 2. 端到端总图

```text
Windows / AD / Zeek / 终端 / 云审计 / 业务日志
                       │
                       ▼
          本地 Agent：读取、检查点、批量、重试
                       │
                       ▼
          区域 Gateway：接入、鉴权、限流（可选）
                       │
                       ▼
                     Kafka
            持久缓冲、回放、消费组、扇出
                       │
       ┌───────────────┼──────────────────┐
       ▼               ▼                  ▼
 原始归档消费者    标准化处理流水线       实时特征任务
 S3/MinIO/Ceph     Data Prepper/Flink       Flink
       │               │                  │
       │               ▼                  ▼
       │        normalized Kafka      feature/anomaly Kafka
       │          │          │              │
       │          ▼          ▼              ▼
       │     OpenSearch   ClickHouse     OpenSearch
       │     近期调查     长期明细/基线    异常与证据
       │          ▲          │              │
       └──────────┴──────────┴──────────────┘
              以 event_id / raw_ref 贯通证据
```

OpenSearch 在该架构中主要负责近期全文检索、规则检测、异常展示和调查；ClickHouse 负责长期标准化明细、聚合特征和历史基线；Flink 负责需要持续状态和事件时间窗口的实时计算；对象存储保留不可变原始证据。

## 3. 第一阶段：源系统产生事实

| 数据源 | 典型记录 | 原始形态 |
|---|---|---|
| Windows Security | 登录、进程、账号和权限变更 | Windows Event XML |
| Active Directory | 用户、组、目录对象及审计事件 | Windows Event、LDAP/目录快照 |
| Zeek | conn、dns、http、ssl、files 等日志 | TSV、JSON |
| EDR/终端 | 进程、文件、注册表、网络连接 | JSON、API |
| 网络和安全设备 | 防火墙、VPN、DNS、代理 | Syslog、CEF、厂商格式 |
| 云平台 | 登录、控制面和资源变更 | API、消息、对象文件 |
| 业务系统 | 用户操作、文件下载、审批 | JSON、数据库审计 |

源系统此时只产生事实。例如 4624 表示一条登录成功事件，Zeek conn 表示一次连接；它们还不是“异常登录”或“数据外泄”。

每条进入采集层的记录至少需要保留：

```json
{
  "source_type": "windows_security",
  "source_host": "dc01",
  "source_native_id": "Security:987654",
  "event_time": "2026-09-10T10:15:23.123+08:00",
  "observed_time": "2026-09-10T10:15:24.002+08:00",
  "raw": "<Event>...</Event>"
}
```

- `event_time` 是行为发生时间，用于 UEBA 时间窗；
- `observed_time` 是采集器观察到它的时间，用于测量采集延迟；
- `source_native_id` 是源系统记录标识；
- `raw` 是未经标准化覆盖的原始证据。

不能只保留接收时间。网络恢复后补采的上午事件可能下午才到，如果按下午时间进入行为窗口，就会产生错误顺序和基线污染。

## 4. 第二阶段：本地 Agent 采集

Agent 可选 Vector、Fluent Bit、OpenTelemetry Collector 或满足具体数据源要求的专用采集器。它负责读取文件、事件通道、Syslog 或 API，记录读取位置，补充来源元数据，批量压缩并发送。

【事实】OpenTelemetry Collector 官方将流水线组织为 Receiver、可选 Processor 和 Exporter：Receiver 接收或主动获取遥测数据，Processor 按顺序处理，Exporter 发往一个或多个下游。[1](https://opentelemetry.io/docs/collector/architecture/)

### 4.1 检查点

文件采集要保存文件身份和偏移量；Windows 事件采集要保存相应通道进度。检查点必须持久化并和发送确认配合：

```text
读取记录
  → 写入本地发送队列
  → 下游确认
  → 推进可提交检查点
```

若读取后立即推进检查点、尚未等下游确认，Agent 崩溃可能漏数据；若永不推进，重启后会重复读取。因此生产目标通常是“允许重发、下游幂等”，而不是以牺牲数据完整性换取表面无重复。

### 4.2 本地队列和重试

【事实】OpenTelemetry 官方说明，网络 Exporter 可以使用发送队列和指数退避重试；纯内存队列在进程崩溃时会丢失，队列满或超过重试期限也可能丢数据。不能接受该风险时应配置持久化 WAL，并监控队列容量、入队失败和发送失败。[2](https://opentelemetry.io/docs/collector/resiliency/)[3](https://opentelemetry.io/docs/collector/internal-telemetry/)

建议监控：读取量、发送量、最后检查点、本地队列使用率、最老待发事件年龄、永久失败和丢弃数。

## 5. 第三阶段：Gateway 与 Kafka

Gateway 是可选区域汇聚层，用于统一 TLS/mTLS、认证、限流、批量和网络隔离。复杂解析、目录查询和模型计算不宜堆在 Gateway 上，否则一个慢处理器可能阻塞入口。OpenTelemetry 官方也提示，同一 Receiver 同步扇出到多个流水线时，一个阻塞的 Processor 可能阻塞其他流水线；需要可靠扇出时应借助消息队列解耦。[1](https://opentelemetry.io/docs/collector/architecture/)

Kafka 接收后，记录由 `topic + partition + offset` 定位。建议至少区分原始与标准化主题：

```text
raw.windows.security
raw.zeek.conn
raw.endpoint
normalized.security.events
ueba.features
ueba.anomalies
```

原始 Topic 可以按 `source_host` 或 `sensor_id` 分区；当身份已经解析后，实时 UEBA Topic 可按 `user_id` 或 `device_id` 重新分区，使同一实体的状态由同一 Keyed Operator 管理。

【事实】Kafka 的幂等 Producer 默认依赖重试和 `acks=all`；官方给出的耐久配置示例包括副本因子 3、`min.insync.replicas=2` 和事务/幂等 Producer。`acks=all` 只表示 Kafka 按副本配置确认写入，不表示后续数据库已经完成处理。[4](https://kafka.apache.org/41/javadoc/org/apache/kafka/clients/producer/KafkaProducer.html)

【事实】Kafka 默认更接近至少一次投递。消费者可能在写完外部系统后、提交 Offset 前崩溃，恢复后重新消费同一批；写外部系统要达到端到端 exactly-once，需要目标系统配合，否则必须通过主键、稳定标识或幂等写入处理重复。[5](https://kafka.apache.org/40/design/design/)

## 6. 稳定事件标识和原始归档

建议在采集或标准化早期生成稳定 `event_id`：

```text
event_id = hash(
  tenant_id,
  source_type,
  source_host,
  source_native_id,
  event_time,
  raw_content_hash
)
```

同一原始事实重放后仍得到相同 ID。它用于 Kafka 重放去重、OpenSearch 文档 ID、ClickHouse 批次/事件核对以及异常证据回查。

原始数据应由独立消费者尽早归档到 S3、MinIO 或 Ceph RGW，例如：

```text
s3://ueba-raw/
  tenant=company-a/
  source_type=windows_security/
  date=2026-09-10/
  hour=10/
  part-00001.parquet
```

对象文件同时保存 schema 版本、事件数、最小/最大事件时间和内容校验值。原始区尽量不可变，标准化、脱敏和富化不能覆盖源证据。

## 7. 第四阶段：解析、标准化、富化和质量检查

Data Prepper 或 Flink 从 Kafka 读取原始记录，执行：

```text
解码原始格式
  → 解析事件时间
  → 映射统一字段
  → 补充来源和租户
  → 身份/资产/网络轻量富化
  → 数据质量校验
  → 输出 normalized Topic
```

【事实】OpenSearch 将 Data Prepper 定义为首选摄取工具，其 Pipeline 包括 Source、可选 Buffer、Processors 和 Sink，可执行过滤、丰富、转换、标准化和聚合。[6](https://docs.opensearch.org/latest/data-prepper/)

标准化示例：

```json
{
  "event_id": "...",
  "event_time": "2026-09-10T10:15:23+08:00",
  "event.category": "authentication",
  "event.action": "logon",
  "event.outcome": "success",
  "user.name": "zhangsan",
  "host.name": "DC01",
  "source.ip": "10.0.0.8",
  "schema_version": 12,
  "raw_ref": "s3://ueba-raw/..."
}
```

富化字段要与源字段分开，并记录富化快照版本。例如 `TargetUserName` 是日志事实，`employee_id` 和 `department` 是身份目录在某一时刻给出的上下文。目录关系变化后，应能解释当时使用了哪个版本。

解析错误不能静默丢弃。建议将 `failure_stage`、`failure_reason`、Pipeline 版本和原始事件写入 DLQ。Data Prepper 官方支持端到端确认及 DLQ；在多 Sink 链路中，最终 Sink 成功后才正向确认，无法处理的事件应可靠进入 DLQ，避免毒丸事件无限重放。[7](https://docs.opensearch.org/latest/data-prepper/pipelines/pipelines/)[8](https://docs.opensearch.org/latest/data-prepper/pipelines/configuration/sinks/opensearch/)

## 8. 第五阶段：OpenSearch 与 ClickHouse 双写

建议让两个引擎消费同一 `normalized.security.events`，不要各自独立解析原始文本。

### 8.1 OpenSearch

OpenSearch 保存近期可调查事件，主要服务：全文检索、字段过滤、SOC 时间线、规则检测、异常证据和告警。使用稳定 `event_id` 作为文档 ID，可降低至少一次重放造成的重复影响。

进入前应通过 Index Template 固定时间、IP、数值、`keyword` 和全文字段类型，禁止不受控动态字段扩张；再使用 ISM 管理 rollover、只读、合并和删除。[9](https://docs.opensearch.org/latest/im-plugin/ism/index/)

### 8.2 ClickHouse

ClickHouse 保存长期标准化明细和特征表。Kafka Consumer、Kafka Connect 或 Vector 以批次插入，成功后再提交消费位置。ClickHouse 官方列出的 Kafka 接入方案包括 Kafka Connect 和 Vector。[10](https://clickhouse.com/integrations/kafka)

写入成功但 Offset 未提交时会重放，因此应使用稳定批次 Token 或经验证的幂等方案。ClickHouse 官方说明 MergeTree 系列表支持对重试插入进行自动去重，但具体去重窗口、Token、表引擎及物化视图行为必须配置和测试，不能仅因表里存在 `event_id` 就声称自动 exactly-once。[11](https://clickhouse.com/blog/clickhouse-release-26-01)

## 9. UEBA 特征是什么

特征不是原始字段的简单改名，而是为了描述某个实体在一个观察窗口内行为的可比较数值或类别。

```text
原始事件：用户 A 在 10:03 访问外部 IP，发送 35 MB
当前特征：用户 A 在 10:00～11:00 对外发送 8 GiB
历史基线：用户 A 可比小时的 P95 为 0.8 GiB
异常结果：当前值约为历史 P95 的 10 倍
```

建议特征记录至少包含：

```json
{
  "entity_type": "user",
  "entity_id": "employee-1024",
  "feature_name": "outbound_bytes_1h",
  "window_start": "2026-09-10T10:00:00+08:00",
  "window_end": "2026-09-10T11:00:00+08:00",
  "value": 8589934592,
  "event_count": 1832,
  "feature_version": 5,
  "data_watermark": "2026-09-10T11:05:00+08:00",
  "evidence_refs": ["event-id-1", "event-id-2"]
}
```

特征必须明确实体、时间窗、统计口径和版本。“登录次数=20”不是完整特征定义，因为还缺少按谁、在哪个窗口、哪些登录类型、成功还是失败、是否去重等信息。

## 10. 特征计算在什么时候执行

没有一个统一时刻。建议分成四条执行路径：

| 类型 | 触发时机 | 典型延迟 | 适合计算什么 | 推荐执行位置 |
|---|---|---:|---|---|
| 单事件派生 | 每条标准化事件到达时 | 毫秒～秒 | 内外网方向、非工作时间、是否新域名格式 | Data Prepper/Flink |
| 增量聚合 | 每批事件插入时持续更新 | 秒～分钟 | 分钟计数、字节和、去重近似值 | ClickHouse 增量 MV/Flink |
| 窗口闭合 | Watermark 超过窗口结束并保留迟到容忍后 | 分钟级 | 1h 外发量、15m 登录失败、序列和会话 | Flink |
| 周期批量 | 每小时、每日或模型计划周期 | 小时级 | 7/30/90 天基线、同伴组、重算和回填 | ClickHouse SQL/Refreshable MV/批处理 |

### 10.1 单事件派生

事件一到即可执行，不依赖历史，例如：

- IP 是否属于内部网段；
- 事件发生时间是否属于工作时间；
- 目标端口是否为管理端口；
- 账号类型是否为服务账号；
- 日志质量是否缺少关键字段。

这些字段可以随标准化一起产生，但外部 lookup 必须有版本和超时策略，不能因为目录服务不可用而阻塞整条入口。

### 10.2 增量聚合

【事实】ClickHouse Incremental Materialized View 类似插入触发器：新 Block 写入源表时，View 只对该 Block 执行 SELECT，并将部分聚合写入目标表；它不会定期扫描完整源表。[12](https://clickhouse.com/blog/clickstack-faster-observability)[13](https://clickhouse.com/demos/explore-github-with-clickhouse-powered-real-time-analytics)

适合预计算：

```text
每用户每分钟登录成功/失败数
每设备每分钟对外字节量
每用户每小时访问资源数
每传感器每分钟事件覆盖量
```

它把部分查询成本移到写入时，但不适合依赖频繁变化右表的复杂关联。ClickHouse 官方提醒，增量 MV 只由源表 insert 触发，源数据更新、删除或 Join 右表变化不会自动传播，必须另行重建或选择周期刷新。[14](https://clickhouse.com/blog/10-best-practice-tips)

### 10.3 窗口闭合计算

Flink 用事件时间而不是服务器当前时间把记录分入窗口。官方区分 event time、ingestion time 和 processing time，并使用 Watermark 表示系统认为事件时间已经推进到哪里；Watermark 同时构成延迟与完整性的取舍。[15](https://nightlies.apache.org/flink/flink-docs-stable/docs/learn-flink/streaming_analytics/)

【示例】1 小时外发特征允许迟到 5 分钟：

```text
事件窗口：10:00:00 ～ 11:00:00
首次出结果：Watermark 越过 11:00
接受修正：允许迟到窗口内的事件更新结果
最终版本：Watermark 越过 11:05 后封版
```

具体 5 分钟只是示例，应从实际到达延迟 P95/P99 决定。等待越久，结果越完整但告警越慢；等待越短，告警更快但后续修正更多。

### 10.4 周期批量计算

适合计算：

- 用户过去 30 个可比日的均值、标准差、P50/P95/P99；
- 部门或角色同伴组分布；
- 90 天首次出现集合；
- 特征质量、覆盖率和模型成熟度；
- schema 或算法升级后的历史重算。

ClickHouse Refreshable Materialized View 可以按计划完整重新执行查询，适合复杂多表查询或周期更新；Incremental MV 则随插入触发。两者要根据实时性、Join 变化和写入成本选择。[15a](https://clickhouse.com/blog/common-getting-started-issues-with-clickhouse)

## 11. 特征计算怎么执行

### 11.1 Flink 实时执行链

```text
Kafka normalized
  → 提取 event_time
  → 分配 Watermark
  → keyBy(user_id / device_id)
  → 过滤有效事件
  → 窗口/定时器/序列状态
  → 输出 feature Topic
  → 当前特征与基线比较
  → 输出 anomaly Topic
```

【事实】Flink Keyed State 只能用于 KeyedStream，状态随 Key 分区；例如同一 `user_id` 的计数、最近设备集合和序列状态由相应 Key 的 Operator 实例管理。[16](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/datastream/fault-tolerance/state/)

Flink 状态可能包括：

| 状态 | 示例 |
|---|---|
| ValueState | 上次登录时间、最近一次风险值 |
| MapState | 最近 30 天见过的设备及最后出现时间 |
| ListState | 尚未闭合的行为序列证据 |
| 窗口聚合状态 | 当前小时字节和、连接数、失败数 |
| Broadcast State | 小规模规则、网段或版本化策略 |

【事实】Flink 使用可重放 Source 与持久 Checkpoint 保存流位置和 Operator State，故障后恢复状态并从对应位置重放。Checkpoint 默认需要显式启用，存储位置也必须配置。[17](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/datastream/fault-tolerance/checkpointing/)

### 11.2 ClickHouse 批量执行链

```text
security_events 明细表
  → 每小时/每日 SQL
  → 按 entity_id + comparable_period 聚合
  → 写 feature_baseline
  → 记录 input_watermark + feature_version
```

执行任务必须用固定输入截止点。例如 02:00 计算前一天基线时，先确认前一天数据 Watermark 已达到可接受完整度，再记录：

```text
baseline_date=2026-09-09
input_event_time_end=2026-09-10 00:00:00
input_arrival_cutoff=2026-09-10 01:30:00
schema_version=12
feature_version=5
```

否则同一查询在不同时间运行可能因迟到数据得到不同结果，却无法解释版本变化。

## 12. 具体执行什么特征

建议分六类，而不是一开始追求复杂模型。

### 12.1 量与频率

| 特征 | 实体 | 窗口 | 示例计算 |
|---|---|---|---|
| 登录失败次数 | 用户/IP | 15 分钟 | `countIf(outcome='failure')` |
| 对外发送字节 | 用户/设备 | 1 小时 | `sum(bytes_out)` |
| 外部连接数 | 设备 | 1 小时 | `count()` |
| 文件读取量 | 用户 | 1 小时 | `sum(file_bytes)` |

### 12.2 去重与覆盖面

- 唯一目的 IP/国家/域名数量；
- 唯一设备、应用、资源数量；
- 一段时间内访问的敏感目录覆盖面；
- 同账号同时活动的设备数量。

### 12.3 首次出现和稀有度

- 用户首次使用某设备；
- 设备首次连接某外部域名；
- 用户首次访问某敏感系统；
- 某部门中仅极少实体出现的工具或目的地。

首次出现必须定义回看期和历史完整性。“过去 30 天没见过”不等于“从未见过”。历史不足的新用户要标记 `baseline_mature=false`，不能直接按老用户阈值评分。

### 12.4 时间行为

- 非工作时间行为占比；
- 与个人常用活跃时段的偏移；
- 两次活动间隔；
- 短时间内跨地域登录；
- 登录、访问、压缩、外传之间的时间差。

### 12.5 序列和关联

- 多次登录失败后成功；
- 新设备登录后访问敏感目录；
- 权限提升后批量读取；
- 批量读取后异常外发；
- DNS 探测后建立长连接。

这类特征需要保存尚未完成的序列状态，并为每一步保留证据 ID。它比单窗口计数更适合 Flink 状态机或 CEP，而不是只依赖 ClickHouse 单条增量 MV。

### 12.6 数据质量和可信度

UEBA 还需要计算“能否相信当前特征”：

- 数据源覆盖率；
- 关键字段缺失率；
- 迟到比例；
- 身份解析置信度；
- 同一实体关系冲突数；
- 基线样本数和成熟度。

没有输入和行为为零必须区分。质量不足时应降低结论强度或暂停评分，而不是把零值当正常。

## 13. 当前特征怎样与基线比较

基线不是固定阈值，而是一个带比较对象、历史范围和版本的参考分布。

### 13.1 个人基线

```text
当前：用户 A 今天 10:00～11:00 对外 8 GiB
历史：用户 A 过去 30 个可比工作日同小时 P95=0.8 GiB
```

### 13.2 同伴基线

```text
当前：用户 A 今日访问 42 个敏感项目
同伴：相同岗位用户今日 P99=9 个
```

### 13.3 全局或策略阈值

```text
明确禁止：普通用户访问域控管理接口
```

三者可以同时产生证据，但不能把倍数、Z-score、分位数和恶意概率混为一个含义。异常结果应记录：

```json
{
  "feature_name": "outbound_bytes_1h",
  "current_value": 8589934592,
  "baseline_type": "personal_comparable_hour",
  "baseline_p95": 858993459,
  "sample_count": 27,
  "deviation_ratio": 10.0,
  "feature_version": 5,
  "baseline_version": 18,
  "evidence_event_ids": ["e1", "e2"]
}
```

## 14. 什么时候执行异常评分

推荐门槛：

```text
当前窗口已达到发布 Watermark
AND 当前特征计算成功
AND 对应 baseline_version 可用
AND 样本成熟度达标
AND 数据质量未处于阻断状态
THEN 执行异常比较和评分
```

可分两次发布：

1. **快速初判**：窗口首次闭合即计算，标记 `provisional=true`；
2. **迟到修正**：允许迟到期限结束后更新同一个 `anomaly_id`，标记最终版本。

不要每来一条事件都重新扫描 30 天历史。正确做法是提前维护基线状态，当前窗口闭合时读取相应基线进行常数级比较；需要重算的长期基线由批量任务完成。

## 15. 迟到、重复、回放和版本升级

### 15.1 迟到事件

- 在允许迟到范围内：更新窗口特征和同一异常版本；
- 超过允许范围：写入 late-event 旁路，按重要性修正或批量重算；
- 不能直接丢弃而不计数。

### 15.2 重复事件

- 保持稳定 `event_id`；
- OpenSearch 采用稳定文档 ID；
- ClickHouse 使用经验证的批次 Token/去重策略；
- 特征任务对同一输入版本保持幂等；
- anomaly ID 由检测版本、实体、窗口和证据集合稳定生成。

### 15.3 历史回放

回放进入单独版本或 Topic，明确：输入时间范围、schema 版本、特征版本、基线版本和输出目标。不能让历史回放再次给生产实体重复加风险。

### 15.4 算法升级

新旧特征版本应并行：

```text
outbound_bytes_1h:v5 → 现网评分
outbound_bytes_1h:v6 → 影子验证
```

对比覆盖率、结果差异和误报原因后再切换；不能原地覆盖导致历史异常失去解释。

## 16. Kafka Offset 在什么时候提交

错误顺序：

```text
读取 Kafka → 先提交 Offset → 写数据库失败 = 数据丢失
```

建议顺序：

```text
读取 Kafka
  → 处理和校验
  → 写目标系统或可靠 DLQ
  → 收到确认
  → 提交 Offset
```

如果写成功但提交前崩溃，会发生重复消费，所以目标必须幂等。这是“至少一次 + 幂等”的核心，不应笼统宣传全链路 exactly-once。

## 17. 一条登录到外发异常的完整实例

```text
10:15 DC01 产生 4624 登录
  → Agent 读取并生成 event_id=W1
  → Kafka raw.windows.security
  → 原始 XML 归档
  → 标准化 user_id=U1, device_id=D1
  → OpenSearch 保存近期事件
  → ClickHouse 保存长期明细
  → Flink 查询 D1 是否属于 U1 的近期设备集合
  → 产生 new_device_login=true

10:20～10:55 Zeek 记录 D1 多次对外连接
  → 标准化并归到 device_id=D1
  → Flink 按 D1 聚合 10:00～11:00 外发字节
  → Watermark 越过窗口边界后得到 8 GiB
  → 读取 U1/D1 历史可比窗口 P95=0.8 GiB
  → 组合“新设备 + 10 倍外发偏离”证据
  → anomaly_id=A1 回写 OpenSearch
  → 分析师从 A1 回查 W1 和 Zeek event_id 集合
```

这里仍只能得出“新设备登录后出现异常外发迹象”，不能仅凭流量元数据确认敏感文件已经泄露。文件审计、DLP、代理或终端证据决定结论强度。

## 18. 运行调度建议示例

以下周期用于说明分层，不是生产默认值：

| 任务 | 触发 | 输出 |
|---|---|---|
| 原始解析与标准化 | 事件持续到达 | normalized event |
| 分钟级基础聚合 | 新批次插入/1 分钟窗口 | entity-minute feature |
| 15 分钟登录失败 | Watermark 闭合 | authentication feature |
| 1 小时外发量 | Watermark 闭合并允许迟到 | network feature |
| 快速异常评分 | 当前特征首次发布 | provisional anomaly |
| 最终异常修正 | 迟到期限结束 | final anomaly version |
| 日基线 | 每日且数据完整度达标 | baseline snapshot |
| 同伴组刷新 | 每日/组织关系变化后 | peer-group version |
| 历史回算 | 人工审批或版本发布 | versioned backfill |

## 19. 必须监控的端到端指标

```text
源端产生数
≈ Agent 接收数
≈ Kafka 写入数
≈ 原始归档数
≈ 标准化成功数 + DLQ 数
≈ OpenSearch 写入数
≈ ClickHouse 写入数
```

同时监控：

- Agent 检查点、队列容量和最老事件年龄；
- Kafka Consumer Lag、ISR 和写入失败；
- 解析成功率、关键字段覆盖率和 DLQ；
- OpenSearch 写入拒绝、查询延迟和磁盘水位；
- ClickHouse 插入延迟、Part 数、重复和扫描字节；
- Flink Watermark、迟到量、Checkpoint、状态大小和重启次数；
- 特征完成时间、基线截止点、成熟度和异常证据完整率。

组件进程存活不等于数据链路正常。应对每个来源建立事件数、最后事件时间和关键字段覆盖的端到端对账。

## 20. 最终设计原则

1. 原始事实、标准化事件、特征、基线、异常和案件分层保存；
2. 事件时间决定行为窗口，处理时间用于观察系统延迟；
3. 实时任务算当前窗口和短状态，批量任务算长期基线与重算；
4. 不重复扫描长历史，基线提前物化并带版本；
5. 至少一次投递配合稳定 ID 和幂等写入；
6. 迟到和失败进入可观测旁路，不能静默丢弃；
7. 任何异常都保留当前值、基线值、版本、窗口和原始证据引用；
8. 数据不足时输出“不确定或未成熟”，不能把没有数据解释成正常。

## 21. 主要官方资料

- OpenTelemetry：[Collector architecture](https://opentelemetry.io/docs/collector/architecture/)、[Resiliency](https://opentelemetry.io/docs/collector/resiliency/)、[Internal telemetry](https://opentelemetry.io/docs/collector/internal-telemetry/)。
- Apache Kafka：[Producer API](https://kafka.apache.org/41/javadoc/org/apache/kafka/clients/producer/KafkaProducer.html)、[Design and delivery semantics](https://kafka.apache.org/40/design/design/)。
- OpenSearch：[Data Prepper](https://docs.opensearch.org/latest/data-prepper/)、[Data Prepper pipelines](https://docs.opensearch.org/latest/data-prepper/pipelines/pipelines/)、[OpenSearch sink](https://docs.opensearch.org/latest/data-prepper/pipelines/configuration/sinks/opensearch/)、[Index State Management](https://docs.opensearch.org/latest/im-plugin/ism/index/)。
- ClickHouse：[Kafka integration](https://clickhouse.com/integrations/kafka)、[Incremental materialized views](https://clickhouse.com/blog/clickstack-faster-observability)、[Materialized view design cautions](https://clickhouse.com/blog/10-best-practice-tips)。
- Apache Flink：[Streaming analytics and event time](https://nightlies.apache.org/flink/flink-docs-stable/docs/learn-flink/streaming_analytics/)、[Generating watermarks](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/datastream/event-time/generating_watermarks/)、[Keyed State](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/datastream/fault-tolerance/state/)、[Checkpointing](https://nightlies.apache.org/flink/flink-docs-stable/docs/dev/datastream/fault-tolerance/checkpointing/)。
