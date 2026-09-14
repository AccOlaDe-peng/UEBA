# CIM—ECS—UEBA 语义对照表

> 版本：1.0.0  
> 范围：Windows Security、Zeek conn/dns/http、VPN、DHCP、HR/AD/CMDB  
> 上位文档：[统一事件模型规范](./统一事件模型规范.md)、[日志源接入与映射清单](./日志源接入与映射清单.md)

## 1. 对照原则

Splunk CIM 是以 Data Model、Dataset、字段和 Tag 组织的搜索时共享语义模型；ECS 是 Elasticsearch 中的公共字段和类型规范；`ueba.*` 是本项目为行为语义、实体角色、质量和可追溯性增加的扩展。三者不能按字段名机械一一替换。

```text
Splunk CIM：事件属于什么分析领域、应具有哪些公共字段
ECS：       在 Elasticsearch 中如何存储通用事实
UEBA 扩展： 该事实对行为分析是什么角色、质量如何、源自哪版规则
```

参考：[Splunk CIM](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[Elastic ECS](https://www.elastic.co/docs/reference/ecs)。

## 2. 模型级对照

| Splunk CIM Data Model / Dataset | Splunk 识别语义 | ECS 主要表达 | UEBA 主类型 | 首期来源 |
|---|---|---|---|---|
| Authentication | 登录活动，含成功、失败、特权等 Dataset | `event.category=authentication`、`user.*`、`source.*`、`host.*` | `authentication.*` | Windows、VPN |
| Change | 对账号、组、配置等对象的变更 | `event.category=iam/configuration`、`user.target.*`、`group.*` | `iam.*` | Windows |
| Endpoint.Processes | 进程开始、结束和状态 | `event.category=process`、`process.*`、`host.*` | `process.*` | Windows 4688 |
| Network_Traffic.All_Traffic | 网络连接及双方流量 | `event.category=network`、`source.*`、`destination.*`、`network.*` | `network.*` | Zeek conn |
| Network_Resolution.DNS | DNS 请求和响应 | `dns.*`、`source.*`、`destination.*` | `dns.*` | Zeek dns |
| Web | Web Server/Proxy 请求 | `event.category=web`、`http.*`、`url.*` | `web.*` | Zeek http |
| Network_Sessions.VPN | VPN 会话开始、结束、阻止 | `event.category=session`、`user.*`、`source.*`、`client.*` | `session.vpn_*` | VPN |
| Network_Sessions.DHCP | DHCP 租约及地址分配 | `event.category=network/session`、`client.*` | `address.lease_*` | DHCP |
| Asset / Identity Framework | 资产和身份上下文，并非普通行为 Dataset | Entity Store/自研实体索引 | `identity.*`、`asset.*` 快照 | HR/AD/CMDB |

Splunk 当前 UEBA 依赖 Asset and Identity Framework 将发现关联到正确用户或资产，并用于同伴分组和风险对象规范化。[Splunk ES UEBA 身份配置](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/user-and-entity-behavior-analytics/configure-asset-and-identity-data-for-ueba-in-splunk-enterprise-security)

## 3. 公共字段对照

| CIM 字段 | CIM 含义 | ECS 字段 | UEBA 补充 | 映射说明 |
|---|---|---|---|---|
| `_time` | 事件时间 | `@timestamp` | `ueba.time.*` | 保存原始时间、时区、选择来源和质量 |
| `action` | 动作/结果，按模型规定值 | `event.action`、`event.outcome` | `ueba.event.type` | CIM Authentication action=success/failure 主要映射到 outcome |
| `signature_id` | 事件或签名 ID | `event.code` | `ueba.source.native_event_id` | 代码与原生记录 ID分开 |
| `signature` | 人类可读签名 | `event.reason` 或 `message` | — | 不作为稳定分类键 |
| `app` | 应用或协议 | `network.application`、`service.name` | — | 按上下文选择，禁止统一塞入单字段 |
| `user` | 事件用户 | `user.name` / `user.id` | `ueba.actor.*` | 特权变更需区分发起者和目标用户 |
| `user_id` | 用户唯一 ID | `user.id` | `ueba.actor.account_key` | 优先 SID/目录对象 ID |
| `src_user` | 发起变更/提权的用户 | `user.effective.*` | `ueba.actor.*` | 目标用户放 `user.target.*`/`ueba.target` |
| `src` | 行为来源 | `source.address`、`source.ip` | `ueba.actor` | 仅当来源确实是网络端点才用 source.ip |
| `src_ip` | 来源 IP | `source.ip` | 关系解析版本 | IP 不是人员身份 |
| `src_port` | 来源端口 | `source.port` | — | long |
| `dest` | 行为目标 | `destination.address` 或 `host.*` | `ueba.target` | 认证目标通常是 host；网络目标是 destination |
| `dest_ip` | 目标 IP | `destination.ip` | — | VPN/DHCP 的“分配地址”例外映射到 client/会话扩展 |
| `dest_port` | 目标端口 | `destination.port` | — | long |
| `src_mac` | 来源 MAC | `source.mac` | 实体候选 | 统一小写冒号格式 |
| `dest_mac` | 目标/客户端 MAC | `destination.mac` 或 `client.mac` | 实体候选 | DHCP 中是获得租约的客户端 MAC |
| `bytes_out` | 来源发出的字节 | `source.bytes` | 质量说明 | 必须核实厂商方向和协议层次 |
| `bytes_in` | 响应端发出的字节 | `destination.bytes` | 质量说明 | 不等于采集接口 inbound |
| `bytes` | 总字节 | `network.bytes` | — | 仅分量均可靠时求和 |
| `packets_out/in` | 双方包数 | `source.packets` / `destination.packets` | — | 同方向原则 |
| `duration` | CIM 多用秒 | `event.duration` | 原单位记录在映射注册表 | ECS 使用纳秒，必须转换 |
| `transport` | 传输层协议 | `network.transport` | — | 规范小写 |
| `protocol` | 网络/应用协议 | `network.protocol` | — | 按来源真实语义 |
| `direction` | 相对网络边界方向 | `network.direction` | 网段版本 | 必须引用事件时刻有效的受管网段 |
| `query` | DNS 查询名 | `dns.question.name` | — | 原值与规范值可并存 |
| `record_type` | DNS RR 类型 | `dns.question.type` | — | A/AAAA/MX 等 |
| `reply_code` | DNS 响应码 | `dns.response_code` | — | 保留厂商原码 |
| `transaction_id` | 事务 ID | `transaction.id` / `dns.id` | — | 不能当全局事件 ID |
| `http_method` | HTTP 方法 | `http.request.method` | — | 规范大写 |
| `status` | HTTP 状态 | `http.response.status_code` | — | long |
| `url` / `uri_path` | URL 与路径 | `url.full` / `url.path` | 敏感性标签 | 查询参数按权限控制 |
| `http_user_agent` | User-Agent | `user_agent.original` | — | 可用于稀有度特征 |
| `file_name/path/size` | 文件属性 | `file.name/path/size` | `ueba.resource` | 一个事件多文件时保留关联 |
| `vendor_product` | 厂商产品 | `observer.vendor/product` | `ueba.source.*` | 行为主机与观察设备不得混淆 |
| `tag` | CIM Dataset 约束标签 | `event.category/type` | `ueba.event.semantic_tags` | 不复制 Splunk tag 字符串作为唯一语义 |

## 4. 事件分类值对照

| Splunk 表达 | ECS 表达 | UEBA 表达 | 说明 |
|---|---|---|---|
| `tag=authentication action=success` | category authentication + outcome success | `authentication.login` | 成功/失败由 outcome 区分 |
| `tag=authentication tag=privileged` | authentication + change/info | `authentication.privilege_assigned` | 会话特权，不等于目录永久提权 |
| `tag=network tag=communicate` | network + connection | `network.connection` | Zeek conn |
| `tag=network tag=dns tag=resolution` | network + protocol | `dns.query` / `dns.response` | Zeek 一条事务可保留问答两侧 |
| `tag=web` | web + access/protocol | `web.request` | 上传下载作为有证据的附加语义 |
| `tag=network tag=session tag=vpn tag=start` | session + start | `session.vpn_started` | 创建时态会话关系 |
| `tag=network tag=session tag=dhcp tag=end` | network/session + end | `address.lease_ended` | 收敛租约有效期 |

## 5. 无法直接对照的内容

下列内容必须由自研模型承担：

- CIM Dataset Constraint 对应的来源选择和分类规则；
- Splunk 搜索时 Lookup 对应的版本化字典和 Enrich；
- `ueba.actor/target/resource/session` 行为角色；
- `ueba.quality` 与检测就绪条件；
- 原始证据 URI、Offset、Hash 和 Parser/Mapping 版本；
- 时态实体关系、候选、置信度和排除规则；
- 映射重放、影子运行和版本切换。

## 6. 审核规则

新增或修改映射时必须同时审核：

1. Splunk CIM 参考模型和 Dataset 是否与行为上下文一致；
2. ECS 字段是否保持官方含义和数据类型；
3. 是否需要 UEBA 角色或质量扩展；
4. 字节、包、持续时间的方向和单位是否明确；
5. 来源没有用户时是否错误写入人员实体；
6. 能否通过 Mapping ID 和版本追溯转换依据。

## 参考资料

- [Splunk Authentication](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/authentication)
- [Splunk Network Traffic](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-traffic)
- [Splunk Network Resolution](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-resolution-dns)
- [Splunk Web](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/web)
- [Splunk Network Sessions](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/network-sessions)
- 本地 CIM 8.7.0 与 TA 配置：`splunk-ueba-调研/Splunk_SA_CIM`、`Splunk_TA_windows`、`Splunk_TA_zeek`

