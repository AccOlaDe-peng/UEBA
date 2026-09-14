# Elasticsearch 原型文件与日志归一流程说明

> 配套设计：[Elasticsearch原型.md](./Elasticsearch原型.md)  
> 原型目录：[elasticsearch-prototype](./elasticsearch-prototype)  
> 文档版本：1.0.0  
> 文档定位：说明原型中各文件的含义、定义原因及其在统一日志结构流程中的作用。

## 1. 原型解决什么问题

该原型验证以下技术链路能否在 Elasticsearch 中实现：

1. 已完成基础格式解析的 Windows、Zeek 日志进入统一入口；
2. Router 根据日志来源选择相应的归一 Pipeline；
3. 来源专用 Pipeline 将原始字段转换成 ECS 与 `ueba.*` 标准字段；
4. Component Template 约束字段名称和数据类型；
5. Index Template 将模板、Data Stream、ILM 和 Failure Store 组合起来；
6. 正常事件写入对应 Data Stream，异常数据被标记或隔离；
7. 标准事件能够被统一查询，并作为实体解析和行为特征计算的输入。

该原型不是完整 UEBA 产品，不包含完整的原始 XML/TSV Parser、实体解析、基线训练、异常检测和风险计算服务。

## 2. 统一日志处理流程

```text
Windows XML / Zeek JSON、TSV
          │
          ▼
采集器或格式 Parser
将原始文本拆解为 JSON 字段
          │
          ▼
目标 Data Stream
logs-ueba.authentication-default
logs-ueba.network-default
logs-ueba.dns-default
          │
          ▼
默认 Pipeline：ueba-router-1.0.0
识别日志来源
     ┌────┴─────┐
     ▼          ▼
Windows       Zeek
Pipeline      Pipeline
     └────┬─────┘
          ▼
ECS 字段 + ueba.* 扩展字段
          │
          ▼
质量判断与 Mapping 类型校验
     ┌────┴────────────┐
     ▼                 ▼
标准事件            处理或写入失败
Data Stream         invalid / Failure Store
     │
     ▼
实体解析 → 特征计算 → 基线训练 → 异常与风险
```

流程中需要区分三个动作：

| 动作 | 解决的问题 | 当前原型 |
|---|---|---|
| 格式解析 | 把 XML、TSV、Syslog 转换成可访问的 JSON 字段 | 未完整包含，假设上游已完成 |
| 语义归一 | 把不同来源字段转换成 ECS 与 UEBA 统一语义 | 已包含 Windows、Zeek 示例 |
| 实体解析 | 把账号、人员、设备、IP 按事件时间关联 | 未包含，属于后续 UEBA 服务 |

## 3. 原型目录结构

```text
elasticsearch-prototype/
├── README.md
├── component-templates/
│   └── ueba-base.json
├── index-templates/
│   └── logs-ueba.json
├── ilm/
│   └── ueba-events-90d.json
├── pipelines/
│   ├── router.json
│   ├── windows-security.json
│   └── zeek.json
├── queries/
│   └── examples.ndjson
└── scripts/
    ├── install.sh
    ├── validate-fixtures.sh
    └── smoke-test.sh
```

配套的 `testdata/` 目录保存 Pipeline 输入样例、预期标准事件和异常样例。

## 4. 文件职责总览

| 文件 | 文件性质 | 在流程中的位置 | 核心作用 |
|---|---|---|---|
| `Elasticsearch原型.md` | 设计说明 | 设计阶段 | 说明原型目的、制品、索引设计和验证边界 |
| `README.md` | 使用说明 | 安装与操作入口 | 说明版本、目录、运行方法和输入假设 |
| `ueba-base.json` | Component Template | 归一和写入阶段 | 定义 ECS/UEBA 字段、数据类型及默认 Router |
| `logs-ueba.json` | Index Template | Data Stream 创建阶段 | 组合字段模板、ILM、Data Stream 和 Failure Store |
| `ueba-events-90d.json` | ILM Policy | 数据保存阶段 | 控制 rollover、warm 和删除周期 |
| `router.json` | Ingest Pipeline | 统一入口 | 判断来源并调用对应的版本化子 Pipeline |
| `windows-security.json` | Ingest Pipeline | Windows 语义归一 | 将 4624/4625 转成统一认证事件 |
| `zeek.json` | Ingest Pipeline | Zeek 语义归一 | 将 conn/dns 转成统一网络和 DNS 事件 |
| `examples.ndjson` | 查询样例 | 使用验证阶段 | 验证认证、流量和数据质量字段可统一查询 |
| `install.sh` | 安装脚本 | 发布阶段 | 按依赖顺序安装全部版本化制品 |
| `validate-fixtures.sh` | 离线校验脚本 | 提交前验证 | 校验 JSON 语法、样例数量和关键预期值 |
| `smoke-test.sh` | 在线冒烟脚本 | 集成验证 | 调用 Elasticsearch `_simulate` 执行 Pipeline |
| `testdata/manifest.json` | 测试清单 | 测试管理 | 关联测试 ID、输入文件和预期结果 |
| `testdata/raw/*.jsonl` | 测试输入 | Pipeline 输入 | 保存正向和异常的解析后日志样例 |
| `testdata/expected/*.jsonl` | 预期结果 | 测试断言 | 定义关键标准字段和错误结果 |

## 5. Component Template：统一字段字典

文件：[ueba-base.json](./elasticsearch-prototype/component-templates/ueba-base.json)

该文件是原型的核心字段规范，作用类似统一日志结构的数据库字段字典。

### 5.1 字段类型约束

| 字段 | Elasticsearch 类型 | 定义原因 |
|---|---|---|
| `@timestamp` | `date` | 用于时间查询、行为窗口和 Data Stream |
| `source.ip`、`destination.ip` | `ip` | 支持合法性校验、CIDR 查询和 IP 聚合 |
| `source.port`、`destination.port` | `long` | 支持数字过滤和范围查询 |
| `source.bytes`、`network.bytes` | `long` | 支持流量求和、均值和基线计算 |
| `event.duration` | `long` | 按 ECS 约定保存纳秒值 |
| `user.name`、`event.action` | `keyword` | 用于精确查询、分组和聚合 |
| `ueba.quality.score` | `scaled_float` | 保存质量分并控制存储成本 |
| `dns.answers` | `nested` | 保持每个 Answer 的数据和 TTL 对应关系 |

类型约束可以防止同一字段在不同日志中被写成不同类型，避免 Mapping 冲突，并保证后续聚合和特征计算的稳定性。

### 5.2 ECS 公共字段

模板定义了以下公共语义：

- `event.*`：事件分类、动作、结果、代码和数据集；
- `user.*`：原始事件直接提供的账号；
- `host.*`：事件涉及的主机；
- `observer.*`：采集或观察行为的系统；
- `source.*`、`destination.*`：行为或通信的两端；
- `network.*`：协议、方向、字节和包数；
- `dns.*`：DNS 问题、响应码和回答。

采用 ECS 的原因是让不同厂商日志能够被同一查询和特征定义消费。例如，Windows、VPN 和 IdP 的认证日志完成映射后，都可以使用 `user.name`、`source.ip` 和 `event.outcome` 计算登录特征。

### 5.3 UEBA 扩展字段

| 字段组 | 作用 |
|---|---|
| `ueba.schema.*` | 标明统一事件模型版本 |
| `ueba.source.*` | 记录来源类型、命名空间和原生事件 ID |
| `ueba.event.*` | 提供项目统一事件类型和语义标签 |
| `ueba.session.*` | 保存 VPN、网络等会话信息 |
| `ueba.time.*` | 说明事件时间来源和质量 |
| `ueba.provenance.*` | 保存 Parser、Mapping、版本和原始证据标识 |
| `ueba.quality.*` | 保存 qualified、partial、invalid 等质量结果 |

ECS 解决通用事件表达，`ueba.*` 则解决 UEBA 所需的版本追溯、质量门禁、事件目录和证据管理。

### 5.4 默认 Router

模板通过以下设置指定统一入口：

```json
"index.default_pipeline": "ueba-router-1.0.0"
```

所有写入匹配 Data Stream 的事件会默认经过 Router。采集端无需分别指定 Windows 或 Zeek Pipeline，减少日志绕过统一归一流程的风险。

### 5.5 动态字段策略

原型允许动态字段，并将动态字符串映射为 `keyword`。这适合安全日志中的用户名、代码、域名和标签等精确匹配场景，也避免自动生成 `text` 与 `.keyword` 两套字段。

生产环境仍应显式定义关键字段，限制未审查字段自动进入 Mapping。

### 5.6 厂商扩展字段

```json
"vendor": {
  "type": "object",
  "enabled": false
}
```

厂商特有字段保留在 `_source`，但不建立索引。这样既能保留调查证据，又能防止不同厂商产生大量动态字段导致 Mapping Explosion。

## 6. Index Template：把规范应用到 Data Stream

文件：[logs-ueba.json](./elasticsearch-prototype/index-templates/logs-ueba.json)

Index Template 匹配：

```text
logs-ueba.*-*
```

对应的 Data Stream 示例：

```text
logs-ueba.authentication-default
logs-ueba.network-default
logs-ueba.dns-default
logs-ueba.web-default
logs-ueba.session-default
```

命名结构可以理解为：

```text
logs-ueba.<事件领域>-<namespace>
```

按事件领域组织，而不是按厂商组织，可以让同类事件进入同一套查询、权限和检测逻辑。Windows、VPN、IdP 认证事件都可以进入认证领域，Zeek、Firewall 和 EDR 网络事件可以进入网络领域。

该模板主要完成：

1. 通过 `composed_of` 引用 `ueba-base@1.0.0`；
2. 声明使用 Data Stream；
3. 绑定 `ueba-events-90d` ILM；
4. 启用 Data Stream Failure Store；
5. 通过优先级降低与其他通用模板冲突的风险。

日志事件适合使用 Data Stream。人员和设备主档、时态关系、特征、基线及风险结果更新方式不同，应使用独立索引或专用 Data Stream。

## 7. ILM：管理日志生命周期

文件：[ueba-events-90d.json](./elasticsearch-prototype/ilm/ueba-events-90d.json)

| 阶段 | 当前配置 | 作用 |
|---|---|---|
| Hot | 1 天或主分片达到 50 GB 时 rollover | 控制 backing index 的时间和大小 |
| Warm | 7 天后合并为一个 segment | 降低长期保存的资源开销 |
| Delete | 90 天后删除 | 控制总体存储成本 |

同时使用时间和大小条件，可以适配不同日志量：低流量环境按时间滚动，高流量环境按大小提前滚动。

90 天只是原型值。生产环境需要结合合规留存、行为基线窗口、调查回溯周期和存储容量重新计算。如果训练或解释需要 180 天证据，日志不能在 90 天时直接删除。

## 8. Router Pipeline：统一分流入口

文件：[router.json](./elasticsearch-prototype/pipelines/router.json)

Router 根据输入字段判断来源：

```text
存在 winlog 且存在 event.code
    → ueba-windows-security-1.0.0

_path 为 conn 或 dns
    → ueba-zeek-1.0.0
```

采用 Router 的原因是：

- 采集端只需写入目标 Data Stream；
- 来源 Pipeline 可以独立开发、测试和发布；
- 不同版本可以并存、回放和回滚；
- 统一入口便于审计和控制绕过。

当前原型存在两个限制：

1. 未命中任何条件的文档会直接通过，生产版应标记为 `unsupported` 并进入隔离流程；
2. 两个条件顺序执行，生产版应使用可靠来源标识，确保一条事件只能选择一个子 Pipeline。

## 9. Windows Pipeline：认证事件归一

文件：[windows-security.json](./elasticsearch-prototype/pipelines/windows-security.json)

该文件演示 Windows Security 4624 和 4625：

```text
4624 → logged-in    + success
4625 → logon-failed + failure
```

### 9.1 主要字段映射

| Windows 字段 | 标准字段 |
|---|---|
| `event.code` | `event.code` |
| `TargetUserSid` | `user.id` |
| `TargetUserName` | `user.name` |
| `TargetDomainName` | `user.domain` |
| `IpAddress` | `source.ip` |
| `IpPort` | `source.port` |
| `computer_name` | `observer.hostname` |

统一事件被定义为：

```text
event.category = authentication
ueba.event.type = authentication.login
```

这样，下游不必直接理解 Windows Event ID。VPN 或 IdP 登录只要映射到相同标准字段，就可以进入同一认证特征。

### 9.2 语义标签

| Windows 条件 | 标签 |
|---|---|
| `LogonType=10` | `remote_access` |
| `LogonType=3` | `network_logon` |
| `LogonType=5` | `service` |
| 用户名以 `$` 结尾 | `machine_account` |

标签用于区分远程、网络、服务和机器账号登录，避免把性质不同的行为混入同一基线。

### 9.3 溯源与幂等

Pipeline 保存 Parser、Mapping 及其版本，并根据租户、主机、Channel 和 Record ID 形成原型事件 ID。生产环境应改成规范定义的稳定 SHA-256 ID，以避免拼接冲突并保证重放幂等。

### 9.4 质量处理

满足当前必填条件时标记为：

```text
ueba.quality.status = qualified
ueba.quality.score = 1.0
```

缺少用户名、事件数据或遇到不支持的 Event ID 时，进入 `on_failure`，标记为 `pipeline_error` 和 `invalid`，并保存错误原因。

## 10. Zeek Pipeline：网络和 DNS 归一

文件：[zeek.json](./elasticsearch-prototype/pipelines/zeek.json)

该文件演示 Zeek `conn` 和 `dns` 两种日志。

### 10.1 展开带点字段

Zeek JSON 中可能存在：

```json
"id.orig_h": "10.10.1.25"
```

`dot_expander` 将其展开为对象结构，使 Painless 脚本能够通过 `ctx.id.orig_h` 访问。

### 10.2 公共端点映射

| Zeek 字段 | ECS 字段 |
|---|---|
| `id.orig_h` | `source.ip` |
| `id.orig_p` | `source.port` |
| `id.resp_h` | `destination.ip` |
| `id.resp_p` | `destination.port` |

Zeek `orig` 表示连接发起端，`resp` 表示响应端，因此映射到 ECS source/destination。

### 10.3 网络方向

| `local_orig` | `local_resp` | `network.direction` |
|---|---|---|
| true | false | `outbound` |
| false | true | `inbound` |
| true | true | `internal` |
| 其他 | 其他 | `unknown` |

该判断依赖 Zeek Local Networks 配置，现场网段配置错误会直接影响方向质量。

### 10.4 Observer 角色

Zeek Sensor 被写入 `observer.*`，因为它是观察流量的设备，不是通信参与者或行为发生的主机。

```text
source/destination = 通信参与者
host               = 事件涉及的主机
observer           = 观察或记录事件的系统
```

### 10.5 conn 事件

conn 被映射为：

```text
event.category = network
event.type = connection
ueba.event.type = network.connection
```

原发端和响应端的字节、包数分别写入 `source.*`、`destination.*`，合计值写入 `network.*`。持续时间由秒转换为 ECS 使用的纳秒。

如果 `missed_bytes > 0`，表明 Zeek 没有完整看到流量，事件标记为 `partial`，并写入 `zeek_missed_bytes` 警告。依赖精确流量值的检测应据此停止或降级。

### 10.6 DNS 事件

DNS 被映射为：

```text
event.category = network
event.type = protocol
ueba.event.type = dns.response
network.protocol = dns
```

Query、QType、Response Code、Answer 和 TTL 分别进入 `dns.question.*`、`dns.response_code` 和 `dns.answers`。

当前将 `NOERROR` 视为成功，其他响应码统一视为失败。生产版应进一步区分 `NXDOMAIN`、`SERVFAIL`、`REFUSED` 等语义。

### 10.7 为什么不直接填写用户

Zeek 一般只能证明 IP、端口、协议、流量和域名，不能直接证明使用者身份。因此 Zeek Pipeline 不生成 `user.*`。

后续必须根据事件发生时间，使用 DHCP、VPN、Windows、NAC 或 EDR 证据建立：

```text
source.ip
  → 当时对应的设备
  → 当时登录的账号
  → 账号所属人员
```

关系置信度不足时，只能形成 IP 或设备异常，不能强制归属到人员。

## 11. 两层失败处理机制

### 11.1 Pipeline `on_failure`

Pipeline `on_failure` 处理可以表达为标准错误事件的语义问题，例如：

- Windows 缺少用户名；
- Zeek 缺少源端或目的端；
- DNS 缺少 Query；
- 事件类型暂不支持。

处理结果为：

```text
event.kind = pipeline_error
ueba.quality.status = invalid
error.message = 具体错误
```

由于异常已被捕获，文档仍可能成功写入正常 Data Stream。

### 11.2 Data Stream Failure Store

Failure Store 处理最终无法正常索引的文档，例如：

- IP 格式不合法；
- 日期格式错误；
- 字段类型与 Mapping 冲突；
- 未被捕获的 Pipeline 异常；
- 写入阶段失败。

两者的分工是：

```text
能够形成标准错误事件
    → Pipeline on_failure 或质量隔离流

无法完成 Elasticsearch 索引
    → Data Stream Failure Store
```

当前原型尚未实现 Failure Store 的读取、修复和重放作业。

## 12. 查询样例

文件：[examples.ndjson](./elasticsearch-prototype/queries/examples.ndjson)

该文件保存三类查询：

1. 按 `user.name` 和 `event.outcome` 统计认证事件；
2. 按 `source.ip` 聚合 Zeek 出站字节；
3. 按 `ueba.provenance.mapping_id` 统计不合格事件。

这些查询验证统一结构可以支持：

- 跨来源认证行为特征；
- 网络流量特征；
- Pipeline 和 Mapping 健康监控。

该文件是项目自定义的查询清单格式，不是直接提交给 Elasticsearch Bulk API 的 NDJSON。

## 13. 安装脚本

文件：[install.sh](./elasticsearch-prototype/scripts/install.sh)

安装顺序为：

```text
1. ILM Policy
2. Component Template
3. Windows Pipeline
4. Zeek Pipeline
5. Router Pipeline
6. Index Template
```

先安装被依赖对象，再安装引用对象，可以减少模板或 Pipeline 找不到依赖的问题。

所有核心制品使用语义版本名称，以支持版本并存、回放、影子运行和回滚。脚本不执行删除操作，但同名 `PUT` 会更新同名制品，生产发布仍需增加审批、模拟验证和变更审计。

## 14. 测试脚本与测试数据

### 14.1 离线校验

文件：[validate-fixtures.sh](./elasticsearch-prototype/scripts/validate-fixtures.sh)

该脚本不连接 Elasticsearch，检查：

- JSON、JSONL、NDJSON 语法；
- 测试样例数量与 ID；
- Windows 成功/失败映射；
- Zeek 字节数与通信方向；
- 异常样例的预期质量状态。

它能发现文件损坏和基础预期变化，但不会真正执行 Painless Pipeline。

### 14.2 在线冒烟测试

文件：[smoke-test.sh](./elasticsearch-prototype/scripts/smoke-test.sh)

该脚本连接 Elasticsearch，通过 `_simulate` 执行 Windows 和 Zeek Pipeline，验证真实 Elasticsearch 能否加载 JSON、运行 Painless 并生成关键标准字段。

当前只验证 Windows 4624 和 Zeek conn 的正向样例。生产测试还应覆盖 4625、DNS、异常样例、Router、实际 Data Stream、Mapping 失败、Failure Store 和 ILM。

### 14.3 测试清单和样例

| 文件 | 作用 |
|---|---|
| [manifest.json](./testdata/manifest.json) | 关联测试 ID、原始输入、预期结果和行号 |
| [raw/windows-security.jsonl](./testdata/raw/windows-security.jsonl) | Windows 4624、4625 输入 |
| [raw/zeek.jsonl](./testdata/raw/zeek.jsonl) | Zeek conn、dns 输入 |
| [raw/invalid.jsonl](./testdata/raw/invalid.jsonl) | 缺用户名、端点或 DNS Query 的异常输入 |
| [expected/windows-security.jsonl](./testdata/expected/windows-security.jsonl) | Windows 关键标准字段 |
| [expected/zeek.jsonl](./testdata/expected/zeek.jsonl) | Zeek 关键标准字段 |
| [expected/errors.jsonl](./testdata/expected/errors.jsonl) | 预期错误和 invalid 状态 |

JSONL 一行表示一条独立事件，适合批量回放、按行定位和版本比较。预期文件只保留测试关心的关键字段，避免新增无关字段导致全部测试失败。

## 15. 两条事件的实际处理示例

### 15.1 Windows 4624

解析后输入：

```text
event.code = 4624
TargetUserName = zhangsan
IpAddress = 10.10.1.25
LogonType = 10
```

处理过程：

```text
Router 识别 winlog
  → Windows Pipeline
  → authentication.login
  → qualified
  → logs-ueba.authentication-default
```

关键输出：

```text
event.action = logged-in
event.outcome = success
user.name = zhangsan
source.ip = 10.10.1.25
ueba.event.semantic_tags = remote_access
```

后续可用于登录时段、登录来源、新设备和失败后成功等行为特征。

### 15.2 Zeek conn

解析后输入：

```text
id.orig_h = 10.10.1.25
id.resp_h = 8.8.8.8
orig_ip_bytes = 428
resp_ip_bytes = 1240
local_orig = true
local_resp = false
```

处理过程：

```text
Router 识别 _path=conn
  → Zeek Pipeline
  → network.connection
  → qualified
  → logs-ueba.network-default
```

关键输出：

```text
source.ip = 10.10.1.25
destination.ip = 8.8.8.8
network.direction = outbound
network.bytes = 1668
```

该事件只能直接支持 IP 或设备层面的网络特征。要形成人员行为，还需结合事件时刻有效的 DHCP/VPN/Windows/资产身份关系。

## 16. 原型的设计边界

当前原型能够证明：

- JSON 制品语法有效；
- ECS 与 `ueba.*` Mapping 可以定义；
- Windows、Zeek 样例可以表达为统一事件；
- Pipeline 可以执行质量标记和错误处理；
- 标准字段可以支持统一查询和聚合。

当前原型不能证明：

- 客户现场原始日志能够完整解析；
- 所有必接日志源和事件类型已覆盖；
- 集群吞吐量、分片和保存成本满足生产要求；
- 人员、账号、设备和 IP 的归属准确；
- UEBA 基线、异常和风险计算有效；
- Failure Store 已形成修复和重放闭环。

## 17. 从原型到完整 UEBA 的后续链路

```text
标准事件 Data Stream
  → 时态实体解析
  → 人员、账号、设备、IP 关系
  → 行为特征计算
  → 个人基线与同群基线
  → 异常识别
  → 实体风险累计
  → 调查、反馈与模型迭代
```

因此，该原型的定位是完整 UEBA 架构中的“统一事件生产层”。它保证下游实体解析和行为计算面对的是语义一致、类型稳定、质量可判定、版本可追溯的标准事件。
