# Elasticsearch UEBA 日志归一原型

> 原型版本：1.0.0  
> 目标 Elasticsearch：9.x；8.x 使用前需核对 Failure Store 与 ECS 版本兼容性。  
> 状态：预研原型，不是生产配置。

## 内容

```text
elasticsearch-prototype/
├── component-templates/
│   └── ueba-base.json
├── index-templates/
│   └── logs-ueba.json
├── pipelines/
│   ├── windows-security.json
│   └── zeek.json
├── queries/
│   └── examples.ndjson
└── scripts/
    ├── install.sh
    ├── smoke-test.sh
    └── validate-fixtures.sh
```

## 快速使用

仅验证本地 JSON 和测试断言：

```bash
./elasticsearch-prototype/scripts/validate-fixtures.sh
```

连接测试 Elasticsearch：

```bash
export ES_URL='http://localhost:9200'
export ES_API_KEY='...'
./elasticsearch-prototype/scripts/install.sh
./elasticsearch-prototype/scripts/smoke-test.sh
```

如果没有 API Key，可显式设置 `ES_AUTH_ARGS`，例如测试环境 Basic Auth。脚本不会删除索引或模板。

## 设计范围

- Component Template 定义公共 ECS/UEBA 字段；
- Index Template 创建 `logs-ueba.*-*` Data Stream；
- Pipeline 接受“已完成格式解析”的 Windows/Zeek 文档，演示语义映射；
- 原始 XML、TSV 行切分、对象存储归档、Kafka、实体解析和风险引擎不在这个最小原型中；
- event.id 在原型中使用可读稳定组合，生产应按规范实现 SHA-256 幂等 ID；
- `vendor.*` 动态字段关闭索引，防止 Mapping Explosion。

## Failure Store

Index Template 声明 Data Stream Failure Store。不同 Elasticsearch 版本对该功能和 API 的支持存在差异；安装前必须在目标版本验证。Pipeline 内部错误同时通过 `on_failure` 标记 `event.kind=pipeline_error` 和 `ueba.quality.status=invalid`。

