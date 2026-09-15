# UEBA Elasticsearch L0—L4 完整存储制品

> 版本：1.0.0  
> 输入规范：[UEBA日志分类与最小ECS字段全量表](../UEBA日志分类与最小ECS字段全量表.md)、[ES统一日志与UEBA存储结构规范](../ES统一日志与UEBA存储结构规范.md)

## 1. 范围

```text
L0 原始证据：logs-ueba.raw-<namespace>
L1 标准事件：logs-ueba.<domain>-<namespace>
L2 实体当前视图：ueba-entities-<namespace>
L2 时态关系：ueba-entity-relations-<namespace>
L3 窗口特征：ueba-features-<namespace>
L3 发布基线：ueba-baselines-<namespace>
L4 异常事件：ueba-anomalies-<namespace>
L4 风险流水：ueba-risk-events-<namespace>
L4 当前风险：ueba-entity-risk-current-<namespace>
L4 调查案件：ueba-cases-<namespace>
```

L1 字段模板覆盖文档契约中的 Windows、Zeek、Linux 公共最小 ECS 字段；32 个 Windows Event ID、38 类 Zeek 日志和 22 类 Linux 记录通过来源 Parser 映射到这些字段。`event.id` 在当前最小合同中允许缺失，但生产幂等写入应生成稳定 `_id` 或 `event.id`。

## 2. 分层与实际存储

| 层  | 存储                         | 形态                 | 写入者                             |
| --- | ---------------------------- | -------------------- | ---------------------------------- |
| L0  | `logs-ueba.raw-*`            | Data Stream          | Agent、Collector、Raw Gateway      |
| L1  | `logs-ueba.<domain>-*`       | Data Stream          | Parser＋归一 Pipeline＋语义 Router |
| L2  | `ueba-entities-*`            | 版本索引＋写 Alias   | 实体解析服务                       |
| L2  | `ueba-entity-relations-*`    | Data Stream          | 时态关系解析服务                   |
| L3  | `ueba-features-*`            | Data Stream          | 特征计算任务                       |
| L3  | `ueba-baselines-*`           | 版本索引＋当前 Alias | 训练与模型发布服务                 |
| L4  | `ueba-anomalies-*`           | Data Stream          | 异常检测服务                       |
| L4  | `ueba-risk-events-*`         | Data Stream          | 风险计算服务                       |
| L4  | `ueba-entity-risk-current-*` | 版本索引＋写 Alias   | 风险快照任务                       |
| L4  | `ueba-cases-*`               | 版本索引＋写 Alias   | 调查案件服务                       |

## 3. 目录

```text
elasticsearch-l0-l3/
├── component-templates/
│   ├── l0-raw.json
│   ├── l1-events.json
│   ├── l2-entities.json
│   ├── l2-relations.json
│   ├── l3-features.json
│   ├── l3-baselines.json
│   ├── l4-anomalies.json
│   ├── l4-risk-events.json
│   ├── l4-risk-current.json
│   └── l4-cases.json
├── index-templates/
│   ├── l0-raw.json
│   ├── l1-events.json
│   ├── l2-entities.json
│   ├── l2-relations.json
│   ├── l3-features.json
│   ├── l3-baselines.json
│   ├── l4-anomalies.json
│   ├── l4-risk-events.json
│   ├── l4-risk-current.json
│   └── l4-cases.json
├── ilm/
│   ├── l0-raw-30d.json
│   ├── l1-events-90d.json
│   ├── l2-relations-365d.json
│   ├── l3-features-180d.json
│   └── l4-analysis-365d.json
├── pipelines/
│   ├── l0-raw-envelope.json
│   ├── l1-common-validate.json
│   └── l1-domain-router.json
├── examples/
│   └── route-simulate.ndjson
└── scripts/
    ├── install.sh
    ├── validate.sh
    └── smoke-test-routing.sh
```

## 4. L1 路由

写入入口为：

```text
logs-ueba.ingress-<namespace>
```

采集或来源 Parser 必须先按字段契约生成 `event.module`、`event.dataset`、`event.kind`、`event.category`、`event.type` 和来源扩展字段。默认 Pipeline 执行公共校验，再根据语义重路由：

| 优先级 | 条件                                 | 目标 dataset                    |
| ------ | ------------------------------------ | ------------------------------- |
| 1      | 质量为 invalid/unsupported           | `ueba.quarantine`               |
| 2      | `event.kind=metric`                  | `ueba.metric`                   |
| 3      | `event.kind=state`                   | `ueba.state`                    |
| 4      | `event.kind=alert`                   | `ueba.alert`                    |
| 5      | `event.dataset` 为 DNS               | `ueba.dns`                      |
| 6      | `event.dataset` 为 Web/HTTP          | `ueba.web`                      |
| 7      | `event.dataset` 为 TLS/SSL/X509/OCSP | `ueba.tls`                      |
| 8      | category 含 authentication           | `ueba.authentication`           |
| 9      | category 含 iam                      | `ueba.iam` 或 `ueba.directory`  |
| 10     | category 含 process/package/host     | `ueba.endpoint` 或 `ueba.state` |
| 11     | category 含 file                     | `ueba.file`                     |
| 12     | category 含 session                  | `ueba.session`                  |
| 13     | category 含 network                  | `ueba.network`                  |
| 14     | 不能分类                             | `ueba.quarantine`               |

DNS、Web、TLS 等协议路由优先于笼统的 network 类别；认证优先于 network，使 Zeek Kerberos/NTLM/SSH 认证结果进入认证流。同一输入只进入一个 Data Stream。

## 5. 来源字段

核心 ECS 字段使用显式 Mapping。来源专有字段使用三个 `flattened` 容器：

```text
winlog.fields
zeek.fields
linux.fields
```

未来来源使用：

```text
vendor.name
vendor.product
vendor.dataset
vendor.schema_version
vendor.payload
```

只有进入查询、关联、实体解析、特征或质量判断的字段才从 `flattened` 晋升为显式字段。

## 6. 安装与验证

```bash
./elasticsearch-storage-full/scripts/validate.sh

export ES_URL='http://localhost:9200'
export ES_API_KEY='...'
./elasticsearch-storage-full/scripts/install.sh
./elasticsearch-storage-full/scripts/smoke-test-routing.sh
```

安装脚本不会删除索引或模板。同名版本的 `PUT` 会更新制品，生产发布应使用不可变版本名并经过影子验证。
