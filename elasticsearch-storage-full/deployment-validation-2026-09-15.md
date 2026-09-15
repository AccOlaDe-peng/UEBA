# UEBA 原型现场验证报告

> 验证日期：2026-09-15  
> 凭证未写入项目文件。

## 结论

> **技术路线可行，日志已经能够“采进来、看得懂、分得对、存得下”；实体识别和富化也已完成样例验证。但完整自动化链路还没做完，目前属于“原型验证通过”，不能宣布生产上线。**

## 当前完成度

| 能力 | 状态 | 说明 |
| --- | --- | --- |
| 连接现场环境 | 🟢 通过 | ES、Zeek、域控和成员服务器均可访问 |
| 采集 Zeek 日志 | 🟢 通过 | 能从现场读取真实网络日志，ES 中也有持续写入的数据 |
| 解析日志 | 🟢 通过 | 能把 Zeek 原始字段翻译成来源 IP、目的 IP、端口、流量等标准字段 |
| 统一归一化 | 🟢 通过 | Windows、Zeek、Linux 可以使用同一套字段和质量标准 |
| 自动分类存储 | 🟢 通过 | 登录、DNS、终端行为和错误数据能够自动进入各自存储区 |
| 实体数据存储 | 🟢 通过 | 用户、主机及二者关系能够按设计写入和查询 |
| 实体发现 | 🟡 样例通过 | 已从 AD 和 Windows 登录事件发现用户、主机及登录关系，但目前由验证程序生成 |
| 日志实体富化 | 🟡 POC通过 | 已证明可根据 IP 找到对应主机并补充主机名称、域和状态 |
| 自动持续运行 | 🔴 未完成 | 还没有常驻实体解析服务，不能随着新日志自动更新实体和关系 |
| 富化结果正式入库 | 🔴 未完成 | 事件结构还缺少正式的实体引用字段，富化结果暂不能安全写回正式事件流 |
| 两台指定 Windows 的持续采集 | 🔴 未确认 | 主机本地存在安全日志，但尚未证明这些日志持续进入 ES |

## 链路

```text
现场日志          解析/归一             分类存储             实体处理                 UEBA 使用

Zeek JSON   ──→   ECS + UEBA字段   ──→  network/dns/... ──→  发现 IP/主机      ──→   网络实体行为
                    🟢 已通过             🟢 已通过              🟡 样例通过

Windows XML ──→   登录/账号语义     ──→  authentication   ──→  用户—主机关系     ──→   用户行为分析
                    🟡旧链路需修复         🟢 路由通过            🟡 样例通过

AD 主数据   ─────────────────────────────────────────────→  主机/账号身份      ──→   资产与身份富化
                                                              🟡 POC通过
```

当前分界线：

```text
已自动运行并有现场数据 ───────────────┤ 仍需工程化
日志采集 → 解析 → 标准化 → 分类存储   │ 自动实体解析 → 持续富化 → 正式写回
```

## 实际效果是什么

原始 Zeek 日志看起来是下面这种机器字段：

```text
id.orig_h=10.6.69.142
id.resp_h=106.54.244.49
id.resp_p=123
proto=udp
orig_ip_bytes=76
resp_ip_bytes=76
```

处理后，系统能够直接表达业务含义：

```text
来源地址：10.6.69.142:38274
访问目标：106.54.244.49:123
协议：UDP / NTP
通信方向：出站
总流量：152 字节，2 个数据包
数据质量：合格
事件类型：网络连接
```

实体富化的效果是把“只有 IP 的日志”变成“知道它是谁的日志”：

```text
富化前：source.ip = 10.6.6.169

富化后：
  实体类型 = 主机
  主机名称 = WIN-169
  完整域名 = win-169.test.local
  所属域   = test.local
  状态     = 启用
```

Windows 登录事件还可以形成如下关系：

```text
WIN-169\Administrator
        │
        │ 登录到（证据：Windows Security 4624）
        ▼
win-169.test.local
```

这说明后续可以回答“哪个账号在什么时间登录了哪台主机”“某个网络 IP 对应哪台资产”等 UEBA 基础问题。

## 日志是怎样进入 Elasticsearch 的

### Zeek：现场已存在自动链路

```text
网络流量
   ↓ Zeek 6.0.5 抓包分析
/opt/zeek/spool/zeek/*.log
   ↓ 每行一个 JSON 对象（NDJSON）
Filebeat filestream
   ↓ ndjson parser + 点号字段名规范化
Elasticsearch 10.6.68.71:9200
   ↓ 索引默认 Pipeline：ueba-router-1.0.0
ueba-zeek-1.0.0
   ↓ ECS + UEBA 语义映射
logs-ueba.network-poc / logs-ueba.dns-poc
```

现场 Zeek 日志不是普通文本，也不是 CSV，而是 **NDJSON**：一个日志文件包含多行，每一行都是独立 JSON。例如：

```json
{"uid":"C2AYY025ghpgidEZRd","id.orig_h":"10.6.69.140","id.resp_h":"10.6.69.144","proto":"tcp"}
```

Zeek 主机上的 `/etc/filebeat/filebeat.yml` 使用 `filestream` 读取 `conn.log`、`dns.log`、`http.log`、`ssh.log`、`ssl.log`、`files.log` 等文件，并使用 `ndjson` parser 将每一行解析成字段。发送前的 JavaScript processor 会把点号改为下划线，例如：

```text
id.orig_h → id_orig_h
id.resp_h → id_resp_h
```

PoC 输入文件 `/etc/filebeat/inputs.d/zeek-ueba-poc.yml` 还会增加：

```text
tenant_id = poc
sensor_id = zeek-10.6.69.21
_path = conn 或 dns
```

Filebeat 直接输出到 Elasticsearch，不经过 Logstash。输出连通测试已通过。`logs-ueba.network-poc` 的实际 backing index 配置了默认 Pipeline `ueba-router-1.0.0`，它根据 `_path` 调用 `ueba-zeek-1.0.0`，完成以下转换：

| Zeek 原字段 | 标准字段 | 含义 |
| --- | --- | --- |
| `id_orig_h/id_orig_p` | `source.ip/source.port` | 连接发起端 |
| `id_resp_h/id_resp_p` | `destination.ip/destination.port` | 响应端 |
| `proto/service` | `network.transport/network.protocol` | 传输层和应用协议 |
| `orig_ip_bytes/resp_ip_bytes` | `source.bytes/destination.bytes/network.bytes` | 双向及总流量 |
| `orig_pkts/resp_pkts` | `source.packets/destination.packets/network.packets` | 双向及总包数 |
| `uid` | `event.id`、`ueba.session.id` | 事件与会话标识 |
| `local_orig/local_resp` | `network.direction` | 内部、入站或出站 |

现场同时还有两类 Zeek 数据：

- `zeek_*_log`：保留 Zeek 原始字段的索引，适合核对和回放。
- `logs-zeek.*-prod`：另一套 Filebeat Zeek Module 产生的 ECS 数据流，与上述 UEBA PoC 链路并存。

### Windows：目标主机尚未建立自动采集链路

```text
WIN-139 / WIN-169 Security Event Log
   ↓
目前只能通过 WinRM 现场读取
   ✕ 尚无 Winlogbeat/Filebeat/NXLog 服务
   ✕ 尚未持续发送到 Elasticsearch
```

`WIN-139` 和 `WIN-169` 上均未发现 Winlogbeat、Filebeat、NXLog、Fluent Bit 或 Vector 服务及 Winlogbeat 配置文件。因此，本次验证读取到的 Windows 4624 是通过 WinRM 直接查询 Windows Security 通道得到的，不是从 ES 消费到的。

Windows Event Log 的原生载体是 EVTX；采集程序通常通过 Windows Event Log API 读取事件，并转换成 XML/结构化 JSON。预期送入解析 Pipeline 的 JSON 形态为：

```json
{
  "event": {"code": "4624"},
  "winlog": {
    "channel": "Security",
    "record_id": 34980,
    "computer_name": "win-169.test.local",
    "event_data": {
      "TargetUserName": "Administrator",
      "TargetDomainName": "WIN-169",
      "TargetUserSid": "S-1-5-...-500",
      "IpAddress": "10.8.11.158",
      "LogonType": "3"
    }
  }
}
```

已安装的 `ueba-windows-security-1.0.0` 可以把这种结构映射为：

| Windows 字段 | 标准字段 | 示例含义 |
| --- | --- | --- |
| `event.code` | `event.code/action/outcome` | 4624、登录成功 |
| `TargetUserSid` | `user.id` | 账号稳定标识 |
| `TargetUserName` | `user.name` | 登录账号 |
| `TargetDomainName` | `user.domain` | 本地域或 AD 域 |
| `IpAddress/IpPort` | `source.ip/source.port` | 登录来源 |
| `computer_name` | `observer.hostname` | 记录登录事件的主机 |
| `LogonType` | `ueba.event.semantic_tags` | 网络登录、远程登录或服务登录 |
| `record_id` | `event.id`、`ueba.provenance.raw_event_id` | 可追溯证据编号 |

ES 中确实存在其他 Windows 主机通过 **Winlogbeat → Logstash → `logstash-*`** 进入的历史/实时数据。其文档已经包含 `event.*`、`winlog.*`、`host.*` 和 `agent.*`，说明 Winlogbeat 已完成 EVTX/XML 到 JSON 的基础解析；但该链路不是 `WIN-139/WIN-169` 的已确认链路，并且当前存在中文乱码以及 4624 被错误标记为 `Handle Manipulation` 的问题。

### 两类解析不要混为一层

| 层次 | 作用 | Zeek | Windows |
| --- | --- | --- | --- |
| 格式解析 | 把文件/EVTX变成字段 | Filebeat NDJSON parser | Winlogbeat Event Log API/XML parser |
| 来源语义映射 | 把厂商字段变成 ECS/UEBA | `ueba-zeek-1.0.0` | `ueba-windows-security-1.0.0` |
| 统一合同校验 | 检查必填字段和质量 | `normalized-event-validate` | 同左 |
| 领域路由 | 按语义写入目标 Data Stream | network/dns/web等 | authentication/session/iam等 |
| 实体解析与富化 | 关联 IP、主机、账号 | 当前仅 POC | 当前仅 POC |

## 已经证明了什么

1. Elasticsearch 8.19.0 能正确加载并运行本项目的模板和 Pipeline。
2. 真实 Zeek JSON 能转换为标准网络事件，不只是使用人工编写的测试数据。
3. Windows 登录、Zeek DNS、Linux 进程和异常数据能够被正确分类。
4. 数据能通过统一入口真实落盘，不会停留在入口或进入错误的存储区。
5. AD 主机、Windows 账号以及登录关系能够按照设计的数据结构保存。
6. Elasticsearch 自带的 Enrich 能力可以按 IP 补充资产身份。

## 目前还不能承诺什么

- 不能承诺已经形成完整、自动运行的 UEBA 产品链路。
- 不能承诺任意 Zeek IP 都能准确关联到具体用户。只有 IP、主机、账号关系具有足够证据时才能关联。
- 不能承诺 `WIN-139`、`WIN-169` 的日志已经稳定进入 ES，目前只确认主机本地有日志。
- 不能直接使用现有旧 Windows 日志链路作为正式输入：部分中文内容乱码，4624 登录事件的分类也存在错误。
- 不能承诺生产容量、长期稳定性和实体归属准确率；本次验证重点是技术可实现性。

## 建议的下一步

| 优先级 | 工作 | 完成标志 |
| --- | --- | --- |
| P0 | 打通 `WIN-139`、`WIN-169` 到 ES 的持续采集 | 两台主机的新 4624/4625 事件能在 ES 中按分钟级延迟查询到 |
| P0 | 修复 Windows 中文乱码和事件分类错误 | 中文可读，4624 明确归类为登录成功 |
| P0 | 为统一事件增加正式实体引用字段 | 富化结果可通过严格 Mapping 并写入测试 Data Stream |
| P1 | 实现自动实体解析任务 | 新日志到达后自动创建/更新用户、主机及其关系 |
| P1 | 增加关系有效期和冲突处理 | 同一 IP 被不同主机使用时不会错误归属 |
| P1 | 进行连续运行与容量测试 | 完成约定时长的稳定性、延迟、失败率和吞吐验收 |


> **建议批准进入“小范围工程化试点”，暂不按“生产就绪”验收。**

试点应优先完成三个闭环：Windows 实时采集、自动实体解析、富化结果正式入库。完成后再用真实账号登录和真实网络访问进行端到端验收。

---

# 技术验证证据

以下内容供实施、研发和测试同事复核；只关心决策结论的读者看到这里即可。

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

## 现场复验：解析、归一、实体发现与富化

### 连通性与运行状态

- Elasticsearch `10.6.68.71` 的 SSH、HTTP 端口可达，版本为 8.19.0。
- Zeek `10.6.69.21` 的 SSH 端口可达，Zeek 6.0.5，systemd 服务为 active。
- 域控 `10.6.6.139` 与成员机 `10.6.6.169` 的 SMB、WinRM、RDP 端口均可达。
- 两台 Windows 主机均属于 `test.local`；域控近 15 分钟有 92 条 Security 事件，成员机有 5 条。
- Elasticsearch 仍为单节点 yellow、99 个未分配分片，与初次验证一致。

### Zeek 原文到归一事件

从 Zeek 当前 `conn.log` 读取到 JSON 原文，样例 UID 为 `Cn5Lqq4PyH49ioUjV6`。关键原始字段为：

```json
{
  "uid": "Cn5Lqq4PyH49ioUjV6",
  "id.orig_h": "10.6.69.142",
  "id.orig_p": 38274,
  "id.resp_h": "106.54.244.49",
  "id.resp_p": 123,
  "proto": "udp",
  "service": "ntp",
  "duration": 0.006799936294555664,
  "orig_ip_bytes": 76,
  "resp_ip_bytes": 76,
  "orig_pkts": 1,
  "resp_pkts": 1
}
```

同一原文通过已安装的 `ueba-zeek-1.0.0` Pipeline 模拟后得到：

| 原始字段 | 归一字段 | 结果 |
| --- | --- | --- |
| `id.orig_h/id.orig_p` | `source.ip/source.port` | `10.6.69.142:38274` |
| `id.resp_h/id.resp_p` | `destination.ip/destination.port` | `106.54.244.49:123` |
| `proto/service` | `network.transport/network.protocol` | `udp/ntp` |
| 双向字节、包数 | `network.bytes/network.packets` | `152/2` |
| `local_orig/local_resp` | `network.direction` | `outbound` |
| `uid` | `ueba.session.id` | `Cn5Lqq4PyH49ioUjV6` |
| 来源与映射版本 | `ueba.provenance.*` | `zeek_json/zeek_conn_json/1.0.0` |
| 完整性检查 | `ueba.quality.*` | `qualified/1.0` |

### 统一入口与真实写入

`ueba-normalized-event-ingress-1.1.0` 的四条路由模拟均通过：

- Windows 4624 → authentication，qualified。
- Zeek DNS → dns，qualified。
- Linux EXECVE → endpoint，qualified。
- 非法来源 → quarantine，invalid。

重新向 `logs-ueba.ingress-test` 写入 Windows 4624 和 Zeek DNS 后，实际分别存储到：

- `.ds-logs-ueba.authentication-test-2026.09.15-000001`
- `.ds-logs-ueba.dns-test-2026.09.15-000001`

查询确认两条事件都包含受控路由信息且质量为 qualified。

### 实体发现与关系

域控 AD 查询确认：

- `WIN-169`：`win-169.test.local`、IP `10.6.6.169`、启用状态、Windows Server 2025。
- `WIN-139`：`win-139.test.local`、IP `10.6.6.139`、启用状态、Windows Server 2025。

成员机真实 4624 事件提供了本地 Administrator 的 SID、域、来源 IP、LogonType 和 RecordId。按存储合同生成并写入 test 命名空间：

- 主机实体 `ad-host-win169` → `ueba-entities-test`。
- 本地账号实体 `local-user-win169-administrator` → `ueba-entities-test`。
- `authenticated_to` 关系 → `ueba-entity-relations-test`，证据引用 `windows-security:WIN-169:34980`，置信度 1.0。

以上对象通过严格 Mapping 写入并可查询，证明实体当前视图和时态关系的物理存储定义可用。当前写入是验证程序根据现场证据生成，并不代表仓库已有自动实体解析服务。

### 富化效果与缺口

ES 初始没有任何 Enrich Policy。验证期间创建了仅用于 test 的：

- Policy：`ueba-test-entity-by-ip`
- Pipeline：`ueba-test-entity-enrich-poc-1.0.0`

输入 `source.ip=10.6.6.169` 后，Pipeline 能补出：

```json
{
  "entity_context": {
    "source": {
      "entity": {
        "id": "ad-host-win169",
        "type": "host",
        "name": "WIN-169",
        "display_name": "win-169.test.local",
        "status": "active"
      },
      "identifiers": {
        "ip": ["10.6.6.169"],
        "hostname": "win-169.test.local",
        "domain": "test.local"
      }
    }
  }
}
```

此结果目前只通过 `_simulate` 验证。`normalized-event-common` 使用严格 Mapping，但没有定义 `entity_context` 或等价的实体引用字段；因此该富化结果尚不能按当前合同安全写回统一事件 Data Stream。

### 结论

- 日志读取、Zeek JSON 解析、ECS/UEBA 归一、质量校验、领域路由和真实 Data Stream 写入：通过。
- 实体当前视图与实体关系的模板及真实写入：通过。
- Elasticsearch 基于实体 IP 的运行时富化能力：POC 模拟通过。
- 自动实体发现、时态消歧、持续增量更新：仓库未实现。
- 富化后统一事件的持久化合同：缺少事件侧实体引用 Mapping，需补充后才能形成完整生产链路。

另有两个现场接入问题不能计为通过：

- `WIN-139` 和 `WIN-169` 本机存在实时 Security 事件，但尚未在 ES 中确认来自这两台主机的持续采集链路；本次 Windows 实体证据是通过 WinRM读取后生成的验证数据。
- ES 现有 `logstash-*` 中其他 Winlogbeat 4624 事件的中文 `message/event.original` 出现乱码，且 `event.action` 被标记为 `Handle Manipulation`，与 4624 登录语义不符。该旧链路需要修正字符编码及 Windows 事件分类，不能作为合格的归一化输入。

