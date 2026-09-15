# UEBA 原型部署验证记录

> 验证日期：2026-09-15  
> 凭证未写入项目文件。

## 环境

| 对象 | 验证结果 |
| --- | --- |
| Elasticsearch | 8.19.0，单节点 |
| Zeek | 6.0.5，服务运行中 |
| Zeek日志格式 | JSON |
| Zeek活动日志 | conn、dns、http、ssh、ssl、files 等 |
| Windows域控 | SMB、WinRM、RDP端口可达 |
| Windows成员机 | SMB、WinRM、RDP端口可达 |

Elasticsearch 在部署前后均为 yellow，未分配分片为99，属于环境已有状态。本次新建测试 Data Stream 使用 `index.auto_expand_replicas=0-1`，两个测试 Data Stream 均为 green，没有增加未分配分片。

## 已安装制品

- 5个 ILM Policy
- 25个 Component Template
- 25个 Index Template
- 原始证据 Pipeline
- 统一事件分类、校验、路由和入口 Pipeline
- 4个 test 命名空间的当前视图索引及 Alias

已有早期 UEBA 制品未删除。本次制品使用职责名称和版本号，与早期名称并存。

## 路由模拟

| 样例 | 结果 |
| --- | --- |
| Windows Security 4624 | `logs-ueba.authentication-prod` |
| Zeek DNS | `logs-ueba.dns-prod` |
| Linux Audit EXECVE | `logs-ueba.endpoint-prod` |
| 无效来源 | `logs-ueba.quarantine-prod` |

四条 Ingest Pipeline `_simulate` 均通过。

## 真实写入

通过 `logs-ueba.ingress-test` 写入两条隔离测试数据：

| 输入 | 实际目标 | 状态 |
| --- | --- | --- |
| Windows Security 4624 | `logs-ueba.authentication-test` | GREEN |
| Zeek DNS | `logs-ueba.dns-test` | GREEN |

查询确认：

- `vendor.*` 来源合同已保存。
- 分类器生成了 `ueba.route.domain/rule_id/version`。
- 路由器生成了 `ueba.route.dataset`。
- 公共校验生成了 qualified 状态、质量分数和空的错误/警告数组。
- 输入没有保存在 ingress Data Stream，而是直接进入目标 Data Stream。

## Zeek字段核对

实时日志字段已读取并与领域 Mapping 对照：

- conn：连接端点、协议、状态、字节、包数、持续时间和 uid。
- dns：查询名、类型、响应码、DNS标志和 uid。
- http：方法、主机、URI、状态码、User-Agent、MIME和长度。
- ssh：认证结果、尝试次数、客户端/服务端版本和算法。
- ssl：版本、密码套件、证书指纹、SNI和证书验证状态。
- files：文件标识、来源协议、哈希、MIME、大小和分析器。

其中 `uid/fuid`、认证结果、哈希、字节数、包数和持续时间属于后续应从 `vendor.payload` 晋升到 ECS 或 UEBA 显式字段的候选字段。

