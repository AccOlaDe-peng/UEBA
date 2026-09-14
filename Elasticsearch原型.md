# Elasticsearch 原型

> 原型目录：[elasticsearch-prototype](./elasticsearch-prototype)  
> 版本：1.0.0

## 1. 目的

原型验证统一事件模型可以落实为 Elasticsearch 模板、Data Stream、Ingest Pipeline、Failure Store 和查询。它不是完整 UEBA 产品，也不包含实体解析、模型训练和风险服务。

## 2. 制品

| 制品 | 文件 | 用途 |
|---|---|---|
| Component Template | [ueba-base.json](./elasticsearch-prototype/component-templates/ueba-base.json) | 核心 ECS/UEBA Mapping |
| Index Template | [logs-ueba.json](./elasticsearch-prototype/index-templates/logs-ueba.json) | Data Stream、ILM、Failure Store |
| Windows Pipeline | [windows-security.json](./elasticsearch-prototype/pipelines/windows-security.json) | 4624/4625 示例归一 |
| Zeek Pipeline | [zeek.json](./elasticsearch-prototype/pipelines/zeek.json) | conn/dns 示例归一 |
| Router | [router.json](./elasticsearch-prototype/pipelines/router.json) | 按来源选择子 Pipeline |
| ILM | [ueba-events-90d.json](./elasticsearch-prototype/ilm/ueba-events-90d.json) | 示例 90 天生命周期 |
| 查询 | [examples.ndjson](./elasticsearch-prototype/queries/examples.ndjson) | 认证、流量、质量查询 |
| 安装脚本 | [install.sh](./elasticsearch-prototype/scripts/install.sh) | 非破坏性安装版本化制品 |
| 离线校验 | [validate-fixtures.sh](./elasticsearch-prototype/scripts/validate-fixtures.sh) | JSON 与固定断言 |
| 冒烟测试 | [smoke-test.sh](./elasticsearch-prototype/scripts/smoke-test.sh) | Elasticsearch `_simulate` |

## 3. 索引设计

原型索引模式为 `logs-ueba.*-*`，具体建议：

```text
logs-ueba.authentication-default
logs-ueba.network-default
logs-ueba.dns-default
logs-ueba.web-default
logs-ueba.session-default
```

Data Stream 适合追加型时序事件。实体当前状态、时态关系、特征、基线和风险应使用各自索引，不写入日志 Data Stream。

## 4. 生产化前必须补齐

- 锁定 Elasticsearch/ECS 版本并调整模板；
- 原始 XML/TSV Parser 与 Kafka/对象存储归档；
- 生产级 SHA-256 event.id；
- 按租户的数据隔离、RBAC 和字段级权限；
- 容量压测后的 Shard、ILM 和保留策略；
- VPN/DHCP 具体厂商 Pipeline；
- HTTP、Windows IAM、4688 等全部首期映射；
- 证书、密钥和 Secret 管理；
- Failure Store 重放作业；
- 实体关系、特征和检测服务。

## 5. 验证边界

本原型能够证明 JSON 制品有效、核心 Mapping 可安装、两个 Pipeline 能通过模拟并生成关键标准字段。它不能证明客户现场日志覆盖、吞吐容量、实体归属准确率或 UEBA 检测效果，这些由完整验证链验收。

