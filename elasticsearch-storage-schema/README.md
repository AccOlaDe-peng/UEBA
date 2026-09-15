# Elasticsearch 统一存储结构 Mapping 骨架

该目录是《ES 统一日志与 UEBA 存储结构规范》的可执行 Mapping 骨架：

- `component-templates/ueba-events-base.json`：ECS 与 UEBA 公共字段；
- `component-templates/ueba-winlog.json`：Windows 高价值来源字段；
- `component-templates/ueba-zeek.json`：Zeek 高价值来源字段；
- `index-templates/logs-ueba.json`：标准事件 Data Stream 模板示例。

这些文件用于评审和原型验证。上线前应锁定 Elasticsearch/ECS 版本、按具体 Data Stream 配置 `data_stream.dataset`、ILM、权限、分片和 Pipeline。
