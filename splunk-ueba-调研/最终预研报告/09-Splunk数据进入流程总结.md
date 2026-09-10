# Splunk 数据进入流程总结

## 1. 一句话结论

Splunk 的数据进入不是“Forwarder 把文件上传到数据库”，而是一条由输入、解析、索引和搜索四个阶段组成的流水线：源端日志先由 Universal Forwarder 或其他输入组件读取，必要时由 Heavy Forwarder 解析和路由，随后由 Indexer 切分事件、确定时间和元数据、写入原文与索引文件；用户搜索时，再由 Search Head 与 Indexer 应用字段提取、lookup、eventtype、tag 和 CIM 等知识对象，把已索引事件解释为可分析数据。

```text
数据源
  → Universal Forwarder / 输入端
  → 可选 Intermediate/Heavy Forwarder
  → Indexer / Indexer Cluster
  → Bucket：rawdata + tsidx + metadata
  → Search Head 发起搜索
  → 搜索时字段、lookup、tag、CIM
  → 检测、摘要、UEBA 特征、风险与调查
```

【事实】Splunk 官方将数据管道划分为 Input、Parsing、Indexing 和 Search 四个阶段；典型部署由数据输入层、索引层和搜索管理层承载这些阶段。[1](https://help.splunk.com/en/splunk-enterprise/administer/distributed-deployment-manual/9.0/overview-of-splunk-enterprise-distributed-deployments/how-data-moves-through-splunk-deployments-the-data-pipeline)

## 2. 组件与阶段对应

| 数据管道阶段 | 主要工作 | 可承担的 Splunk 组件 |
|---|---|---|
| Input | 读取文件、事件通道、网络流或 API 数据，增加基础来源元数据 | Universal Forwarder、Heavy Forwarder、Indexer |
| Parsing | 事件切分、行合并、时间戳、路由、过滤和部分结构化解析 | Heavy Forwarder、Indexer |
| Indexing | 压缩原文、生成索引文件、写入 bucket、执行副本流程 | Indexer |
| Search | 搜索时字段提取、别名、lookup、eventtype、tag、CIM、SPL 执行 | Indexer、Search Head |

【事实】大多数部署由 Forwarder 处理输入，Indexer 处理解析和索引；Heavy Forwarder 可以在发送前完成解析，此时接收端 Indexer 主要执行索引阶段。Universal Forwarder 通常只做轻量处理，但结构化输入等场景存在例外。[2](https://help.splunk.com/en/splunk-enterprise/administer/distributed-deployment-manual/9.1/overview-of-splunk-enterprise-distributed-deployments/components-and-the-data-pipeline)

## 3. 第一步：数据源产生原始记录

Splunk 可以接入日志文件、Windows Event Log、Syslog、HTTP、脚本或模块化输入等数据。源端记录首先是事实，并不是检测结论。例如：

```text
Windows 4624         → 一次登录成功记录
Windows 4728         → 一次组成员添加记录
Zeek conn            → 一次网络连接记录
VPN 登录日志          → 一次远程访问记录
文件审计              → 一次文件访问记录
```

进入 Splunk 前应先确认：源端确实产生了事件、源时间是否可信、日志轮转和保留是否足够、网络型输入是否存在无重传风险。源端没有产生的事实，后续字段映射和 UEBA 模型无法补造。

## 4. 第二步：Universal Forwarder 采集

Universal Forwarder，UF，通常部署在数据源附近。主要职责包括：

- 根据 `inputs.conf` 读取文件、Windows 事件等输入；
- 标记 `host`、`source`、`sourcetype` 等基础元数据；
- 保存文件或输入读取进度；
- 根据 `outputs.conf` 把数据发给 Indexer 或中间转发层；
- 在多个接收端之间负载均衡和故障切换；
- 根据 Deployment Server 下发的应用和配置更新采集行为。

```text
源文件 / Windows 事件通道
  → inputs.conf 选择输入
  → UF 读取并维护检查点
  → 添加 host/source/sourcetype
  → 输出队列
  → outputs.conf 指定接收端
```

UF 的读取进度、输出队列和 Indexer 写盘状态不是同一件事。生产验证不能只检查 UF 进程运行，还要检查最后事件时间、读取位置、输出阻塞、目标连接和 Indexer 接收量。

## 5. 第三步：可选的中间或 Heavy Forwarder

对于跨网络区域、集中路由、过滤、脱敏或协议汇聚，可在 UF 与 Indexer 之间部署 Intermediate Forwarder 或 Heavy Forwarder，HF。

```text
UF
  → HF：解析、过滤、路由、索引选择
  → Indexer
```

HF 能承担完整或较多的 Parsing 工作，包括事件切分、时间戳和索引时转换。若 HF 已经完成解析，Indexer 不应对同一数据再次执行不兼容的解析配置。

部署时要明确每项配置在哪一层生效：

| 配置 | 常见职责 |
|---|---|
| `inputs.conf` | 选择采集对象和输入参数 |
| `outputs.conf` | 指定接收端、负载均衡和 ACK |
| `props.conf` | 时间、事件切分、字段别名、计算字段等；具体阶段由 stanza 决定 |
| `transforms.conf` | 路由、过滤、字段转换和 lookup 定义 |
| `indexes.conf` | 索引、bucket 路径、大小及生命周期 |
| `deploymentclient.conf` | 接收 Deployment Server 配置 |

配置必须部署到真正执行对应阶段的组件。只把索引时解析配置装到 Search Head，不会改变 Indexer 已写入的事件边界和时间戳。

## 6. 第四步：可靠转发与 Indexer acknowledgment

默认转发不能简单理解为全链路不丢不重。对可靠性要求较高的 Splunk Enterprise 部署，可以在 Forwarder 的 `outputs.conf` 中开启 Indexer acknowledgment：

```ini
[tcpout:indexer_group]
server = idx01:9997,idx02:9997,idx03:9997
useACK = true
```

确认链路为：

```text
Forwarder 发送数据块
  → 在 wait queue 中保留副本
  → Indexer 接收
  → Indexer 解析
  → 写入 rawdata 和索引数据
  → Indexer 返回 ACK
  → Forwarder 释放对应数据块
```

【事实】Splunk 官方说明，开启 ACK 后 Forwarder 会在 wait queue 中保留数据块，直到 Indexer 成功写入文件系统并返回确认；该功能默认关闭。[3](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/forwarding-and-receiving-data/9.4/perform-advanced-configuration/protect-against-loss-of-in-flight-data)

ACK 提高在途数据可靠性，但不等于绝对 exactly-once。若写入已成功而确认丢失，重发可能造成重复；官方也提示 Indexer acknowledgment 在特定故障情况下可能产生重复事件。[4](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/10.4/get-data-into-the-indexer-cluster/connect-forwarders-directly-to-peer-nodes)

Splunk 还为部分输入提供 Persistent Queue：内存输入队列积压后可以写磁盘，但不是所有输入都支持；尚在内存或解析/索引管道且未写盘的数据仍存在崩溃丢失边界。[5](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.0.2503/improve-the-data-input-process/use-persistent-queues-to-help-prevent-data-loss)

## 7. 第五步：Parsing 解析

Parsing 通常在 Indexer 上执行；使用 HF 时也可提前执行。主要内容包括：

1. 将连续字节流切分成事件；
2. 合并多行事件；
3. 提取或确定事件时间；
4. 确定 `host`、`source`、`sourcetype`；
5. 决定目标 index；
6. 执行索引时过滤、路由和脱敏；
7. 对部分结构化输入进行索引时字段提取。

【事实】Splunk 官方列出的索引时处理包括默认元数据、时间戳、line breaking、事件分段、结构化字段提取以及自定义索引时字段提取。[6](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.3/indexing-overview/index-time-versus-search-time)

解析阶段存在三类高影响错误：

| 错误 | 后果 |
|---|---|
| 事件边界错误 | 多条事件被合并或一条事件被拆开 |
| 时间戳错误 | 事件进入错误时间范围，搜索和 UEBA 窗口失真 |
| sourcetype/index 错误 | 错误规则生效或目标数据无法被预期搜索命中 |

这些问题一旦随事件写入，通常不能只靠修改 Search Head 查询完整修复；需要重新索引或在搜索时做有限补偿。

## 8. 第六步：Indexer 写入 bucket

Indexer 将解析后的事件写入索引。一个 bucket 概念上包含：

```text
bucket
  ├── rawdata：压缩原始事件
  ├── tsidx：词项/字段值到原始事件位置的索引信息
  └── metadata：时间范围和 bucket 元数据
```

Indexer 同时也是 Search Peer：不仅存储数据，还执行 Search Head 分发的过滤、字段处理和局部聚合。

索引通常经历：

```text
hot → warm → cold → frozen/deleted
```

hot bucket 正在写入；warm bucket 已滚动并保持可搜索；cold bucket 仍可搜索但可位于不同存储；frozen 通常退出常规搜索，需要归档/恢复策略。SmartStore 场景使用远端对象存储和本地缓存，不应简单等同于传统 cold 目录。

## 9. 第七步：Indexer Cluster 副本

Indexer Cluster 按 bucket 复制。需要区分：

- Replication Factor：数据副本数量；
- Search Factor：立即可搜索副本数量。

搜索只应使用一份主可搜索 bucket 副本，避免同一事件因副本而重复出现在结果中。当节点失败时，集群管理层重新选择主副本或恢复可搜索副本。

副本用于可用性，不等于备份。误删除、错误配置和污染数据可能影响多个副本，仍需独立备份和恢复验证。

## 10. 第八步：Search Head 发起分布式搜索

Search Head 保存或管理 SPL、知识对象、Dashboard、计划任务和用户交互。搜索过程概念上是：

```text
用户或 Scheduler 发起 SPL
  → Search Head 解析搜索任务
  → 把可分布部分下发到 Indexer/Search Peer
  → Indexer 按 index、时间和词项筛选事件
  → Indexer 执行可分布字段处理和局部聚合
  → Search Head 汇总结果
  → 展示、告警或写入派生数据
```

限制 index、sourcetype、时间和高选择性条件越早，通常越能减少读取与网络汇总。全局排序、高基数聚合、大规模 Join 和复杂搜索时正则可能把更多工作集中到 Search Head。

## 11. 第九步：搜索时字段与 CIM 标准化

Splunk 的很多字段语义并不是在写入时物理固化，而是在搜索时通过知识对象应用：

- 搜索时字段提取；
- `FIELDALIAS`；
- `EVAL-*` 计算字段；
- lookup；
- eventtype；
- tag；
- CIM Data Model。

【事实】Splunk 官方把字段提取、字段别名、lookup、eventtype 和 tag 等列为搜索时处理，并建议一般优先在搜索时完成知识构建，因为过多索引时字段会增加写入及索引成本。[6](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.3/indexing-overview/index-time-versus-search-time)

示例：

```text
Zeek 原字段
  id_orig_h / id_resp_h / orig_ip_bytes
       ↓ FIELDALIAS
  src / dest / bytes_out
       ↓ eventtype + tag
  CIM Network_Traffic
       ↓
  tstats、检测和 UEBA 特征搜索
```

CIM 是语义契约，不是消息 Topic，也不会创造缺失信息。只有 IP 而没有用户身份的 Zeek 事件，不能靠别名自动得到可信 `user`。

## 12. 第十步：摘要、特征与 UEBA 衔接

事件可搜索后，后台计算才进一步生成摘要、特征和安全结果。

### 12.1 Data Model Acceleration

```text
原始索引事件
  → 后台 Summarization Search
  → Indexer 上的 DMA tsidx Summary
  → tstats 快速访问标准化字段
```

【事实】Data Model Acceleration 在 Indexer 层、源 bucket 旁构建 `.tsidx` 摘要，用于加速针对数据模型字段的分析；摘要有自己的范围、更新周期和可能的滞后。[7](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/use-data-summaries-to-accelerate-searches/accelerate-data-models)

### 12.2 ES 内置 UEBA

公开的知识对象显示，ES UEBA 由多类保存搜索组成：

```text
可分析事件/CIM
  → Summarization Search
  → Consolidation Search
  → Feature Search
  → Scoring Search
  → Intermediate Finding / Finding
  → Risk / ERS / 调查
```

KV Store 跟踪特征值、相关身份和资产；Macro 封装字段映射、特征计算和评分逻辑。[8](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/user-and-entity-behavior-analytics/roles-and-knowledge-objects-in-ueba-for-splunk-enterprise-security)

这说明日志成功写入 Indexer 还不等于 UEBA 已经计算完成。后续仍受 CIM 覆盖、摘要进度、计划搜索、KV 状态、特征成熟度和评分任务影响。

## 13. 一条 Windows 登录事件的完整路径

```text
1. DC01 产生 Security 4624
2. UF 的 WinEventLog Input 读取事件并维护读取进度
3. UF 添加 host/source/sourcetype/index 元数据
4. UF 通过 outputs.conf 发送到 Indexer Cluster
5. 若 useACK=true，UF 在 wait queue 保留数据块
6. Indexer 接收并执行事件时间、边界和元数据解析
7. Indexer 把原文和 tsidx 写入目标 bucket
8. Indexer 返回 ACK，UF 释放数据块
9. Search Head 查询该时间范围
10. 搜索时字段提取生成 user、src、action 等字段
11. eventtype/tag 将事件纳入 Authentication CIM
12. DMA/摘要搜索可建立加速数据
13. UEBA Feature/Scoring Search 读取事件或摘要
14. 产生行为特征、异常或中间 Finding
15. 风险规则把结果关联到 user/system 实体
16. Mission Control、Dashboard 或调查页呈现证据
```

其中任何一层失败都可能表现为“没有告警”：源端未产生、UF 未读取、队列阻塞、解析错误、写入错误、字段缺失、CIM 未命中、摘要落后、任务未运行、KV 状态不成熟或被例外规则排除。

## 14. Splunk 可靠性边界总结

| 问题 | Splunk 提供的机制 | 仍需验证的边界 |
|---|---|---|
| 源端断点续采 | 文件/输入检查点 | 日志轮转、覆盖、检查点丢失 |
| 网络中断 | Forwarder 队列、重连和负载均衡 | 队列容量及最长中断时间 |
| 写入确认 | Indexer acknowledgment | ACK 丢失可能重发和重复 |
| 瞬时积压 | 内存/部分输入的 Persistent Queue | 内存数据和不支持的输入 |
| Indexer 故障 | Cluster bucket 副本 | 恢复期间性能和可搜索副本 |
| 历史恢复 | bucket、归档、SmartStore/备份 | 恢复时间和配置一致性 |
| 迟到数据 | SPL 时间窗、调度延迟、补跑 | 没有与 Flink Watermark 完全相同的通用抽象 |
| 数据完整性 | Internal logs、Monitoring Console、审计 | 必须另做源端到索引端事件数与字段覆盖对账 |

不能笼统声称 Splunk 全链路 exactly-once。更准确的表述是：Splunk 提供检查点、队列、ACK、集群副本和补跑机制降低丢失风险，但仍要针对输入协议、队列、失败时点和重复事件进行实测。

## 15. 上线核对清单

1. 先确认源端事件确实产生，并记录源端事件数和最后时间；
2. 验证 `inputs.conf` 的通道、路径、过滤和目标 index；
3. 验证 `host` 表示原始事件主机，尤其是 WEF 和中转场景；
4. 确认解析发生在 HF 还是 Indexer，并把配置部署到正确层；
5. 检查时间戳、事件边界、sourcetype 和原始文本；
6. 根据可靠性要求开启并验证 `useACK`；
7. 测试网络中断、UF/HF/Indexer 重启后的漏采和重复；
8. 验证 Indexer Cluster 的 RF、SF、负载均衡和故障恢复；
9. 核对字段提取、别名、lookup、eventtype、tag 和 CIM 命中；
10. 检查 DMA Summary Range、更新时间和 Summarization Lag；
11. 检查 UEBA 保存搜索、KV Store、特征和评分更新时间；
12. 对“源端 → UF → Indexer → CIM → UEBA”建立事件数、延迟和关键字段覆盖率监控。

## 16. 最终总结

Splunk 的数据进入可以归纳为三次转换：

```text
第一次：字节或记录 → 可索引事件
由 UF/HF/Indexer 的 Input 和 Parsing 完成

第二次：可索引事件 → 可搜索知识
由 Indexer 存储、Search Head、字段提取、lookup 和 CIM 完成

第三次：可搜索知识 → 安全证据和行为结果
由 DMA、Scheduled Search、UEBA Feature/Scoring、RBA 和 ERS 完成
```

第一阶段错误会影响原始事实，第二阶段错误会影响数据语义，第三阶段错误会影响异常与风险判断。生产建设不能只验证“日志能搜到”，还必须验证事件边界和时间正确、字段语义一致、摘要没有明显滞后、特征计算完成，并能从最终异常回查到原始证据。

## 17. 主要官方资料

- Splunk，[How data moves through Splunk deployments: The data pipeline](https://help.splunk.com/en/splunk-enterprise/administer/distributed-deployment-manual/9.0/overview-of-splunk-enterprise-distributed-deployments/how-data-moves-through-splunk-deployments-the-data-pipeline)。
- Splunk，[Components and the data pipeline](https://help.splunk.com/en/splunk-enterprise/administer/distributed-deployment-manual/9.1/overview-of-splunk-enterprise-distributed-deployments/components-and-the-data-pipeline)。
- Splunk，[Index time versus search time](https://help.splunk.com/en/data-management/manage-splunk-enterprise-indexers/9.3/indexing-overview/index-time-versus-search-time)。
- Splunk，[Protect against loss of in-flight data](https://help.splunk.com/en/splunk-enterprise/forward-and-process-data/forwarding-and-receiving-data/9.4/perform-advanced-configuration/protect-against-loss-of-in-flight-data)。
- Splunk，[Persistent queues](https://help.splunk.com/en/splunk-cloud-platform/get-started/get-data-in/10.0.2503/improve-the-data-input-process/use-persistent-queues-to-help-prevent-data-loss)。
- Splunk，[Accelerate data models](https://help.splunk.com/en/splunk-enterprise/manage-knowledge-objects/knowledge-management-manual/10.2/use-data-summaries-to-accelerate-searches/accelerate-data-models)。
- Splunk，[Roles and knowledge objects in UEBA for Splunk Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/user-and-entity-behavior-analytics/roles-and-knowledge-objects-in-ueba-for-splunk-enterprise-security)。
