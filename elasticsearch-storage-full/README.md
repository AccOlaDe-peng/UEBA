# UEBA Elasticsearch 数据对象与存储制品

> 版本：1.1.0
> 输入规范：[UEBA日志分类与最小ECS字段全量表](../UEBA日志分类与最小ECS字段全量表.md)、[ES统一日志与UEBA存储结构规范](../ES统一日志与UEBA存储结构规范.md)

## 1. 架构原则

本方案以数据对象和业务职责组织存储，不把 L0、L1、L2、L3、L4 作为产品接口或固定处理链。解析、实体解析、特征计算、检测和风险服务按合同消费所需对象，可以并行处理，也可以直接从统一事件产生结果。

| 数据对象 | 物理存储 | 主要职责 |
| --- | --- | --- |
| 原始证据 | `logs-ueba.raw-<namespace>` | 回放、审计和取证 |
| 统一事件入口 | `logs-ueba.ingress-<namespace>` | 受控分类、校验和路由，不长期保存事件 |
| 统一事件 | `logs-ueba.<domain>-<namespace>` | ECS＋UEBA 标准事件 |
| 隔离事件 | `logs-ueba.quarantine-<namespace>` | 无效、不支持或无法分类的输入 |
| 实体当前视图 | `ueba-entities-<namespace>` | 用户、主机、IP等实体当前状态 |
| 实体关系 | `ueba-entity-relations-<namespace>` | 带有效期的时态关系 |
| 行为特征 | `ueba-features-<namespace>` | 窗口统计与行为特征 |
| 行为基线 | `ueba-baselines-current-<namespace>` | 当前发布基线 |
| 异常 | `ueba-anomalies-<namespace>` | 异常结果及证据引用 |
| 风险流水 | `ueba-risk-events-<namespace>` | 不可变风险变化记录 |
| 当前风险 | `ueba-entity-risk-current-<namespace>` | 实体当前风险快照 |
| 调查案件 | `ueba-cases-<namespace>` | 案件状态和证据引用 |

对象通过稳定的事件标识、实体标识、证据引用、规则版本和时间窗口关联。派生对象保存输入引用及计算结果，不逐级复制完整日志。

## 2. 来源合同

所有来源统一使用：

```text
vendor.name
vendor.product
vendor.dataset
vendor.schema_version
vendor.payload
```

`vendor.payload` 使用 `flattened` 保存尚未标准化的原生字段。Windows、Zeek、Linux 和后续来源不创建各自的顶层扩展对象。

字段使用顺序：

1. 跨来源通用字段映射到 ECS。
2. ECS 无法准确表达且 UEBA 持续使用的字段晋升为正式 UEBA 扩展字段。
3. 尚未进入查询、实体解析、特征、检测、路由或质量判断的字段保留在 `vendor.payload`。
4. 完整原始内容只由原始证据对象负责保存。

`vendor.dataset` 标识输入格式，`event.dataset` 表达标准化逻辑数据集，`ueba.route.domain` 表达存储域，`data_stream.dataset` 表达最终物理位置。

## 3. 受控统一事件入口

生产者只写：

```text
logs-ueba.ingress-<namespace>
```

入口模板独立配置默认 Pipeline。最终统一事件模板没有入口默认 Pipeline，因此重路由后不会重复解析或形成 Pipeline 循环。

```text
标准化输入
  → normalized-event-classifier
  → normalized-event-validate
  → normalized-event-router
  → logs-ueba.<domain>-<namespace>
```

分类器会删除输入中已有的 `ueba.route`，根据受控注册表重新生成：

```text
ueba.route.domain
ueba.route.rule_id
ueba.route.version
```

公共路由器只校验允许域、生成 `ueba.route.dataset` 并执行一次 `reroute`。非法、缺失或质量不合格的事件进入 quarantine。

## 4. 路由规则

[routing/route-registry.json](routing/route-registry.json) 是路由规则的配置源，[compile-route-pipeline.py](scripts/compile-route-pipeline.py) 将其编译为可安装的 Elasticsearch Pipeline。运行时不读取外部配置文件。

规则匹配顺序为：

1. `vendor.dataset + event.code`
2. `vendor.dataset + vendor.payload.record_type/event_type`
3. 固定 `vendor.dataset`
4. 无匹配时进入 quarantine

`event.category`、`event.type` 和 `ueba.event.type` 表达检测语义，不承担物理路由。一个事件只选择一个主存储域，其他用途通过 `ueba.event.semantic_tags` 和 `ueba.quality.usable_for` 表达。

## 5. 公共与领域字段模板

统一事件 Mapping 由公共合同和一个领域合同组合：

```text
normalized-event-common
  + normalized-event-authentication
  + normalized-event-network
  + normalized-event-dns
  + normalized-event-web
  + ...
```

实际每个领域模板只组合公共组件与自己的领域组件。例如：

```text
logs-ueba.authentication-*
  = normalized-event-common
  + normalized-event-authentication
```

公共组件包括时间、租户、事件元数据、来源合同、质量、证据和路由字段。领域组件分别管理用户认证、网络、DNS、Web、TLS、端点、文件、邮件等字段，使领域字段可以独立演进。

## 6. 数据质量

`ueba.quality.status` 表达事件整体状态：

```text
qualified | partial | invalid | unsupported
```

`ueba.quality.usable_for` 表达事件可支持的具体能力，例如：

```json
{
  "ueba": {
    "quality": {
      "status": "partial",
      "usable_for": [
        "user_entity",
        "host_entity",
        "authentication_baseline",
        "sessionization"
      ]
    }
  }
}
```

检测与特征任务应依据所需字段和 `usable_for` 判断可用性，而不是仅凭整体状态排除所有 partial 事件。

## 7. 版本与字段所有权

| 字段 | 负责方 |
| --- | --- |
| `vendor.*` | Collector或来源 Parser |
| ECS字段 | 来源映射Pipeline |
| `ueba.event.*` | UEBA语义映射 |
| `ueba.route.*` | 受控分类与路由Pipeline |
| `ueba.quality.*` | 数据质量Pipeline |
| `ueba.provenance.*` | 发布流水线 |

事件应记录来源 Schema、Parser、Mapping、路由规则和统一事件 Schema 版本。Parser、Mapping、Route Registry、Schema 和测试集共同构成一个发布包。

## 8. 制品目录

```text
component-templates/
  raw-evidence.json
  normalized-event-common.json
  normalized-event-<domain>.json
  quarantine-event.json
  entities.json
  entity-relations.json
  behavior-features.json
  behavior-baselines.json
  anomalies.json
  risk-events.json
  entity-risk-current.json
  cases.json

index-templates/
  raw-evidence.json
  normalized-event-ingress.json
  normalized-event-<domain>.json
  quarantine-event.json
  entities.json
  entity-relations.json
  behavior-features.json
  behavior-baselines.json
  anomalies.json
  risk-events.json
  entity-risk-current.json
  cases.json

pipelines/
  raw-evidence-envelope.json
  normalized-event-classifier.json
  normalized-event-validate.json
  normalized-event-router.json
  normalized-event-ingress.json

routing/
  route-registry.json
```

文件名、Elasticsearch 模板名和 Pipeline 名均使用职责名称，不再包含 L0—L4 编号。

## 9. 验证和安装

```bash
python3 ./elasticsearch-storage-full/scripts/compile-route-pipeline.py
./elasticsearch-storage-full/scripts/validate.sh

export ES_URL='http://localhost:9200'
export ES_API_KEY='...'
./elasticsearch-storage-full/scripts/install.sh
./elasticsearch-storage-full/scripts/smoke-test-routing.sh
```

安装脚本不会删除现有索引。生产升级应使用不可变版本名，经过模拟、样例回放、影子运行和切换后再停用旧版本。

单节点测试环境使用 `index.auto_expand_replicas=0-1`，避免产生无法分配的副本；增加数据节点后可自动扩展到一个副本。实际环境验证结果见 [deployment-validation-2026-09-15.md](deployment-validation-2026-09-15.md)。
