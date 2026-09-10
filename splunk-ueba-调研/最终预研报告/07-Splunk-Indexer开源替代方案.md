# Splunk Indexer 开源替代方案预研

## 1. 结论摘要

【结论】Splunk Indexer 可以被开源产品组合替代，但不能把它理解成可以单独更换的通用存储。Indexer 同时承担数据接收后的解析与索引、压缩原文和索引文件的持久化、副本管理，以及执行 Search Head 下发的分布式搜索。因此，替换 Indexer 通常意味着同步迁移查询语言、仪表盘、告警规则、数据模型、字段提取和部分采集链路，而不是在 Splunk Search Head 下方换一个数据库。

对本项目的建议分两层：

1. **近期检索与安全调查使用 OpenSearch。**它与 Splunk 的字段检索、全文搜索、仪表盘、规则检测和告警形态最接近，迁移风险相对可控。
2. **长期明细、行为画像与高基数聚合使用 ClickHouse。**它更适合 UEBA 的实体窗口统计、基线、特征计算和长周期数据分析。
3. **Kafka 作为可回放的数据缓冲，Vector、Fluent Bit 或 OpenTelemetry Collector 负责采集，Data Prepper 或流处理任务负责解析和标准化；S3 兼容对象存储保留原始归档和备份。**

推荐目标不是复制一个开源版 Splunk，而是让搜索引擎负责“找事件”，列式分析引擎负责“算行为”，对象存储负责低成本保留原始证据。

## 2. 为什么不能只替换 Indexer 的磁盘

【事实】Splunk 将索引数据组织成 bucket。bucket 中包含压缩原始数据、指向原始数据的索引文件和元数据；Indexer Cluster 按 bucket 复制，Search Head 把查询分发到作为 Search Peer 的 Indexer，并汇总结果。[1](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.0/how-indexer-clusters-work/buckets-and-indexer-clusters)[2](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.4/overview-of-indexer-clusters-and-index-replication/the-basics-of-indexer-cluster-architecture)[3](https://help.splunk.com/en/splunk-enterprise/get-started/deployment-capacity-manual/9.1/hardware-capacity-planning/components-of-a-splunk-enterprise-deployment)

【事实】Splunk 的常规分布式搜索要求 Search Head 连接 Splunk Indexer/Search Peer。Splunk 官方对 Federated Search for Splunk 的说明明确指出，它只面向远端 Splunk 部署，不支持把任意第三方系统作为该类 Provider。[4](https://help.splunk.com/?resourceId=Platform_FederatedSearch_fsoptions)

【解释】这意味着以下设想不可作为受支持的替换路径：

```text
Splunk Search Head → OpenSearch / ClickHouse → 原样运行现有 SPL
```

Splunk Cloud 提供面向 S3 等外部数据的特定联邦查询能力，但它有产品版本、部署区域、数据格式和使用场景限制。官方说明 S3 联邦查询主要面向低频历史数据，不应替代高频或实时的原生索引搜索。[5](https://help.splunk.com/en/splunk-enterprise/splunk-validated-architectures/splunk-platform-indexing-and-search/federated-search-for-amazon-s3)

因此需要替换的是一组能力，而非一个文件格式：

| Splunk 能力 | 替代层需要提供的能力 |
|---|---|
| Forwarder/输入 | 文件、Windows 事件、Syslog、API、OTLP 等采集及断点续传 |
| Indexer 解析 | 事件切分、时间解析、过滤、字段标准化、富化与脱敏 |
| Indexer 存储与索引 | 原文保存、字段/全文检索、分区、副本、恢复和生命周期 |
| Search Peer 执行 | 分布式过滤、聚合、关联、排序和结果返回 |
| Search Head 与知识对象 | 查询入口、仪表盘、保存查询、告警、权限和检测内容 |
| CIM、摘要与行为状态 | 统一语义、可复用宽表/摘要、实体特征及基线状态 |

## 3. 候选方案比较

| 方案 | 与 Splunk 检索体验接近度 | 长期存储成本 | 全文与任意字段检索 | UEBA 聚合计算 | 安全分析现成功能 | 主要风险 |
|---|---:|---:|---:|---:|---:|---|
| OpenSearch 全栈 | 高 | 中等偏高 | 强 | 中等 | 较强 | 分片、映射、JVM 和容量治理 |
| ClickHouse + ClickStack | 中 | 低 | 中等 | 强 | 中等偏弱 | Schema 设计及安全内容需建设 |
| OpenSearch + ClickHouse | 高 | 中等 | 强 | 强 | 较强 | 双写、一致性和运维复杂度 |
| Loki + Grafana | 较低 | 很低 | 偏弱 | 偏弱 | 较弱 | 标签索引不适合任意安全字段检索 |
| Quickwit + 对象存储 | 中 | 很低 | 强 | 中等 | 较弱 | 生态、运营工具和项目成熟度需验证 |

表中的判断是基于各项目公开架构的工程比较，不是同一硬件、同一数据集上的性能测试。最终成本与性能必须用本项目日志、查询和保留周期实测。

## 4. 方案一：OpenSearch 全栈

建议组合：

```text
日志源
  → Vector / Fluent Bit / OpenTelemetry Collector
  → Kafka
  → OpenSearch Data Prepper
  → OpenSearch Cluster
  → OpenSearch Dashboards / Security Analytics / Alerting
  → S3、MinIO 或 Ceph RGW 快照仓库
```

【事实】OpenSearch 将 Data Prepper 定义为首选数据摄取工具。Data Prepper 可以通过流水线执行过滤、丰富、转换、标准化和聚合，官方列出的常见用途包括日志分析。[6](https://docs.opensearch.org/latest/data-prepper/)

【事实】OpenSearch Index State Management 可以根据索引年龄、大小或文档数执行 rollover、只读、force merge、调整副本和删除等生命周期操作。[7](https://docs.opensearch.org/latest/im-plugin/ism/index/)

【事实】OpenSearch Security Analytics 提供 Detector、基于 Sigma 的检测规则、Finding、Alert 和跨日志类型的关联规则；OpenSearch Security 还能对相关功能及索引应用角色、文档级和字段级访问控制。[8](https://docs.opensearch.org/latest/security-analytics/)[9](https://docs.opensearch.org/latest/security-analytics/security/)

### 4.1 与 Splunk 的主要映射

| Splunk | OpenSearch 组合 |
|---|---|
| Universal/Heavy Forwarder | Vector、Fluent Bit、OTel Collector、Data Prepper |
| Indexer | OpenSearch Data Node |
| Indexer Cluster | OpenSearch Cluster |
| `indexes.conf` 生命周期 | Index Template、Data Stream、ISM |
| Search Head | OpenSearch Dashboards 与协调节点 |
| SPL | Query DSL、PPL、SQL；需重写和语义验证 |
| ES 检测及告警 | Security Analytics、Sigma、Alerting |
| 冷备和恢复 | Snapshot Repository；不能未经验证等同于 Splunk SmartStore |

### 4.2 适用条件与边界

适合近期原始事件检索、SOC 交互调查、关键词搜索、字段过滤和规则检测。它是最接近 Splunk 平台形态的开源路线，但仍需承担倒排索引的磁盘、内存和写放大成本。高字段数、高基数和不受控动态映射会造成集群压力，不能依赖默认配置直接承载生产 UEBA。

OpenSearch 能降低软件许可依赖，但不会自动降低运维成本。生产设计仍需明确分片大小、主副本、故障域、映射模板、写入背压、快照恢复目标、滚动升级和租户隔离。

### 4.3 是否推荐 Elasticsearch（ES）

【结论】推荐 Elasticsearch 作为候选的**近期检索与安全调查引擎**，但不建议把它作为整个 UEBA 平台唯一的长期存储和计算引擎。本项目以开源替代和自主可控为主要前提时，OpenSearch 的推荐优先级高于 Elasticsearch；如果组织已经具备 Elastic 技术栈、运维经验并能接受相应订阅，则 Elasticsearch 也是成熟备选。

需要区分两个产品：本文前述推荐的 OpenSearch 不是 Elasticsearch 的简称。二者均能承担日志索引、字段检索、聚合和仪表盘，但项目治理、插件、安全功能和许可证边界已经不同，不能把配置及功能清单直接视为完全兼容。

【事实】Elastic 官方提供 hot、warm、cold、frozen 数据层，支持使用生命周期策略在不同层之间管理时序数据；cold 和 frozen 层可以利用 searchable snapshots 降低本地磁盘占用，但 frozen 查询通常比 cold 更慢。[15](https://www.elastic.co/docs/manage-data/lifecycle/data-tiers)

【事实】Elastic 官方文档明确标注 searchable snapshots 需要 Enterprise 许可证。该能力能够让只读历史索引从快照仓库按需挂载，并省去默认副本，但不能把这一商业能力计入“纯开源免费方案”的容量和成本假设。[16](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/searchable-snapshots)

选型建议如下：

| 条件 | 建议 |
|---|---|
| 强调纯开源、自主可控及避免关键能力订阅依赖 | 优先 OpenSearch + ClickHouse |
| 已有 Elastic 集群、人员经验和安全内容，并能接受订阅 | Elasticsearch + ClickHouse 可进入 POC |
| 数据规模较小，希望第一阶段降低组件数量 | 可先单独部署 OpenSearch 或 Elasticsearch，但保留消息层与对象归档 |
| 日志量大、需要数月或数年的 UEBA 基线 | 不建议只依赖 OpenSearch/Elasticsearch，长期明细和行为聚合逐步进入 ClickHouse |

无论选择 OpenSearch 还是 Elasticsearch，其推荐职责均是近期全文搜索、交互调查、检测结果和告警；ClickHouse 负责长期明细、行为基线和高基数聚合，Kafka/Flink 负责缓冲回放与实时特征，对象存储负责原始归档和备份。最终应在同一 POC 中比较许可证范围、三年总成本、查询结果、故障恢复和运维复杂度。

## 5. 方案二：ClickHouse 与 ClickStack

建议组合：

```text
日志源 → Vector / OTel Collector → Kafka → ClickHouse → HyperDX / Grafana
```

【事实】ClickHouse 官方的 ClickStack 由 OpenTelemetry、ClickHouse 和 HyperDX 等组件组成，面向日志、指标和 Trace，提供 Lucene 风格搜索、SQL、仪表盘和告警；官方同时说明 ClickHouse 可以利用 MergeTree、物化视图和 HTTP 摄取构建自定义遥测栈。[10](https://clickhouse.com/clickstack)

【解释】ClickHouse 的主要价值不是复制 Splunk 的全文倒排索引，而是通过列式存储、分区、排序键、跳数索引、物化视图和并行聚合处理长周期、高基数事件。UEBA 中常见的以下计算更适合这一形态：

- 按用户、设备、IP、应用和资源聚合时间窗口；
- 计算首次出现、稀有值、访问频率、数据量和同伴组分布；
- 维护小时、日、周粒度的行为摘要；
- 形成模型训练和回放所需的特征宽表；
- 对半年或数年的审计数据执行批量分析。

其不足是任意字段全文调查体验通常不如以倒排索引为核心的搜索引擎；若字段模型和排序键设计不合理，也会产生大范围扫描。ClickStack 提供可观测性界面，但不能被视为与 Splunk Enterprise Security 或 UEBA 一一等价的安全产品。

## 6. 方案三：Loki 与 Grafana

【事实】Loki 只为日志标签建立索引，日志正文压缩后保存在 chunk 中。官方推荐 TSDB 作为索引存储；可扩展部署依赖 S3、GCS、Azure 或兼容对象存储。[11](https://grafana.com/docs/loki/latest/configure/storage/)[12](https://grafana.com/docs/loki/latest/setup/install/helm/configure-storage/)

这一设计能显著减少全文索引成本，适合 Kubernetes、应用运行日志和 SRE 故障排查。但安全日志通常包含用户、设备、进程、文件、域名、IP、规则标识等大量高基数字段，不能把它们全部设计为 Loki label。否则会形成过多日志流并增加索引和运行压力。

因此 Loki 可以承担运维日志子集或成为旁路平台，不建议作为本项目完整替代 Splunk Indexer 的首选。

## 7. 方案四：Quickwit 与对象存储

【事实】Quickwit 的官方定位是从对象存储直接执行搜索，通过计算与存储解耦独立扩展索引和查询，适用场景包括日志、审计日志和安全日志；官方配置支持 S3、GCS、Azure、MinIO 和 Garage 等存储后端。[13](https://quickwit.io/docs/overview/introduction)[14](https://quickwit.io/docs/configuration/storage-config)

这种架构适合长周期、不可变和低成本日志，也适合验证“对象存储作为主数据、查询计算按需扩展”的路线。但与 OpenSearch 相比，其 SIEM 检测内容、案件调查、权限运营和第三方集成生态需要专项验证。建议先作为历史数据或冷查询 POC，不在第一阶段承担全部生产安全日志。

## 8. UEBA 推荐目标架构

综合检索体验、长期成本和行为计算，本项目建议验证双引擎架构：

```text
Windows / AD / Zeek / 终端 / 云审计 / 业务日志
                       │
        Vector / Fluent Bit / OTel Collector
                       │
                       ▼
                     Kafka
          可回放、削峰、消费进度与数据扇出
                       │
        ┌──────────────┴──────────────┐
        ▼                             ▼
Data Prepper / 标准化任务         Flink / 流式特征任务
        │                             │
        ▼                             ▼
OpenSearch                       ClickHouse
近期事件、全文检索、告警          长期明细、行为特征、基线
SOC 调查、检测结果与证据          高基数聚合、批量回放、模型输入
        ▲                             │
        └──── 异常/评分/证据回写 ─────┘
                       │
                       ▼
             S3 兼容对象存储
       原始不可变归档、快照、离线重放
```

### 8.1 数据职责建议

| 数据对象 | 建议主存储 | 示例保留策略 | 说明 |
|---|---|---|---|
| 近期可调查原始事件 | OpenSearch | 7～30 天，仅为待测起点 | 服务高频交互搜索和检测 |
| 长期标准化明细 | ClickHouse | 6～24 个月，按合规要求确定 | 服务画像、聚合和历史分析 |
| 原始不可变日志 | 对象存储 | 按审计与取证要求确定 | 支持重新解析、追溯和灾难恢复 |
| 实体特征与基线 | ClickHouse/专用状态层 | 覆盖模型窗口并保留版本 | 不能用原始日志保留期代替 |
| 异常、风险与调查证据 | OpenSearch | 覆盖调查及复核周期 | 必须保留规则、模型和数据版本 |

表中的天数只是 POC 起始假设，不是容量承诺。真实周期需要结合每日摄取量、查询频率、法规、恢复目标和硬件成本计算。

### 8.2 为什么不建议只使用一个引擎

只用 OpenSearch 能简化架构，但长周期全量倒排索引可能使存储和内存成本接近原问题；只用 ClickHouse 能降低成本，却会提高 SOC 任意文本调查和安全内容建设难度。双引擎把近期高价值检索与长期行为分析分开，代价是要解决双写、一致性、字段版本和跨引擎证据定位。

可以通过以下原则控制复杂度：

- Kafka 消息或原始对象使用稳定 `event_id`，两侧保留同一标识；
- 原始事件只解析一次，标准化 schema 有明确版本；
- 不是所有日志都双写，只把需要高频调查的数据写入 OpenSearch；
- 异常结果回写时保存特征值、基线值、时间窗、模型版本和证据 `event_id`；
- OpenSearch 不作为唯一原始档案，ClickHouse 聚合结果也不替代取证原文。

## 9. Splunk 迁移工作量与风险

| 迁移对象 | 主要工作 | 风险 |
|---|---|---|
| SPL 与保存搜索 | 改写为 PPL、DSL、SQL 或流处理逻辑 | 命令语义、时间边界、空值和关联行为不等价 |
| CIM 与字段提取 | 建立自研 schema、解析器和映射测试 | 同名字段口径不一致导致静默误判 |
| Data Model Acceleration、`tstats` | 改为物化视图、汇总表或预聚合索引 | 摘要覆盖与新鲜度变化 |
| Lookup、KV Store | 迁移到关系库、ClickHouse 字典或状态服务 | 有效时间、更新原子性和历史版本丢失 |
| Dashboard 与告警 | 在 Dashboards、Grafana、HyperDX 或自研界面重建 | 展示一致不代表数据语义一致 |
| ES/UEBA 内容 | 规则、特征、基线、风险及调查流程重建 | 开源存储不会自动提供等价检测内容 |
| 权限和审计 | 重新设计租户、字段、实体画像和操作审计 | 画像数据可能比单条日志更敏感 |
| 历史数据 | 选择迁移、双跑、归档查询或按需恢复 | 全量重建索引成本高，旧 SPL 仍不可直接复用 |

## 10. POC 设计与验收指标

POC 不应只比较每秒写入量。建议选取 Windows 安全日志、AD 变更、Zeek 连接日志以及一类高字段数终端日志，覆盖近期检索、长周期聚合和 UEBA 特征计算。

### 10.1 必测查询

1. 精确字段过滤、关键词和通配符搜索；
2. 单实体 24 小时时间线与上下文事件；
3. 10 万级实体的小时/日聚合；
4. 30～90 天首次出现、稀有值和个人基线；
5. 多数据源身份、设备、IP 关联；
6. 晚到数据补采、规则重跑和特征回算；
7. 节点故障、消费者重启、重复消息和对象存储短暂不可用；
8. 按字段权限、租户权限和审计日志验证越权边界。

### 10.2 建议记录的指标

| 类别 | 指标 |
|---|---|
| 摄取 | 原始 GB/日、EPS、峰均比、端到端延迟、拒绝和重试量 |
| 数据质量 | 事件数对账、解析失败率、关键字段覆盖率、重复率、迟到分布 |
| 查询 | P50/P95/P99 延迟、并发、扫描字节、缓存命中、超时和内存峰值 |
| 存储 | 压缩后容量、索引/明细/副本/快照分别占用、每日增长和恢复时间 |
| UEBA | 特征完成时间、基线新鲜度、回算时间、异常可解释字段完整率 |
| 可用性 | 单节点故障影响、恢复点目标、恢复时间目标、积压追平时间 |
| 运维 | 部署升级工时、告警数量、扩容步骤、备份恢复成功率 |

验收必须使用同一批事件、同一时间边界和等价查询比较结果集合；仅比较界面返回速度会掩盖漏数据、字段差异和摘要不完整。

## 11. 分阶段落地建议

### 第一阶段：旁路采集与结果对账

保留现有 Splunk，利用源端或消息层把同一数据送入候选平台。首先验证事件数量、时间、字段和原文一致性，不立即迁移告警。

### 第二阶段：代表性查询与检测双跑

选择高频检索、典型 Dashboard、确定性安全规则和 3～5 个 UEBA 特征进行双跑，比较结果、延迟、资源和误差原因。

### 第三阶段：历史与长期计算迁移

优先把长周期报表、聚合和行为基线迁移到 ClickHouse，降低 Splunk 长窗口扫描和长期索引压力。异常结果仍可在过渡期送回现有调查流程。

### 第四阶段：调查入口与安全内容迁移

在查询、权限、告警、案件和恢复能力达标后，再逐批迁移 OpenSearch 调查入口及安全检测。每批都保留回退和对账窗口。

## 12. 最终判断

如果目标是以最低迁移风险替代 Splunk 平台，首选 `Kafka + Data Prepper + OpenSearch + OpenSearch Dashboards/Security Analytics + 对象存储`。

如果目标是显著降低长期存储成本并支撑自研 UEBA，首选验证 `Kafka + OpenSearch（近期调查）+ ClickHouse（长期行为分析）+ 对象存储（原始归档）+ Flink（流式特征）`。

Elasticsearch 推荐作为近期检索层的备选，而不是被排除：已有 Elastic 技术栈且可接受订阅时，可将上述架构中的 OpenSearch 替换为 Elasticsearch；强调纯开源和自主可控则仍优先 OpenSearch。两种情况下都不建议让单一搜索引擎同时承担全部长期日志与 UEBA 计算。

当前证据支持架构可行性判断，但不支持直接承诺容量、成本节省比例或与 Splunk 功能完全等价。下一步应以真实数据和等价查询完成 POC，再决定单引擎还是双引擎、热数据周期、是否需要 Flink，以及哪些 Splunk 内容值得迁移。

## 13. 主要官方资料

- Splunk：[Buckets and indexer clusters](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.0/how-indexer-clusters-work/buckets-and-indexer-clusters)、[Indexer cluster architecture](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.4/overview-of-indexer-clusters-and-index-replication/the-basics-of-indexer-cluster-architecture)、[Federated Search options](https://help.splunk.com/?resourceId=Platform_FederatedSearch_fsoptions)。
- OpenSearch：[Data Prepper](https://docs.opensearch.org/latest/data-prepper/)、[Index State Management](https://docs.opensearch.org/latest/im-plugin/ism/index/)、[Security Analytics](https://docs.opensearch.org/latest/security-analytics/)。
- Elastic：[Data tiers](https://www.elastic.co/docs/manage-data/lifecycle/data-tiers)、[Searchable snapshots](https://www.elastic.co/docs/deploy-manage/tools/snapshot-and-restore/searchable-snapshots)。
- ClickHouse：[ClickStack](https://clickhouse.com/clickstack)。
- Grafana：[Loki storage](https://grafana.com/docs/loki/latest/configure/storage/)、[Loki object storage configuration](https://grafana.com/docs/loki/latest/setup/install/helm/configure-storage/)。
- Quickwit：[Introduction](https://quickwit.io/docs/overview/introduction)、[Storage configuration](https://quickwit.io/docs/configuration/storage-config)。
