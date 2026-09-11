# Splunk 实体识别与身份解析机制

## 1. 结论摘要

Splunk 的“实体识别”不是从文本中识别人名、地名的 NLP 能力，也不是单纯依靠机器学习猜测日志属于谁。它是一条由**事件字段标准化、资产与身份主数据、标识符合并、时态关系解析、事件归属和风险对象聚合**组成的数据链路。

需要区分两个产品层次：

1. **Splunk Enterprise Security（ES）**主要依靠 Asset and Identity Framework，把资产、账号和组织信息维护在 Lookup/KV Store 中，在搜索时根据事件里的 `user`、`src`、`dest` 等字段进行匹配和上下文补全。
2. **Splunk User Behavior Analytics（UBA）**进一步执行 Account Normalization、Identity Resolution 和 Device Resolution，把多个账号归并到自然人，把 IP、MAC、主机名归并到设备，并维护用户、设备和地址之间随时间变化的关系。

对自研 UEBA 最有价值的启发是：**检测和画像不应直接使用日志里的原始用户名或 IP 作为长期实体主键，而应使用内部稳定的 `user_entity_id` 和 `device_entity_id`；每一次归属还要保留时间范围、证据来源、解析规则和置信度。**

## 2. 实体识别的总体链路

```text
Windows AD / HR / CMDB / DHCP / DNS / VPN / Zeek / EDR
                            │
                            ▼
                    原始日志采集与解析
                            │
                            ▼
                 字段标准化：CIM / UBA Schema
                            │
           ┌────────────────┴────────────────┐
           ▼                                 ▼
     用户及账号解析                     设备标识解析
账号、UPN、邮件、员工号          IP、MAC、主机名、DNS 名称
           │                                 │
           └────────────────┬────────────────┘
                            ▼
                       时态关系图
        账号属于谁、某时刻 IP 属于哪台设备、谁登录了设备
                            │
                            ▼
                 原始事件归属到用户和设备实体
                            │
                            ▼
               行为特征、基线、异常、风险和调查
```

这条链路解决的不是“日志中是否出现了一个名字”，而是以下问题：

- `CORP\\zhangsan`、`zhangsan@corp.example` 和 `adm_zhangsan` 是否属于同一自然人；
- `10.10.8.25`、`WIN-LAPTOP-023` 和 `00:11:22:33:44:55` 是否代表同一设备；
- Zeek 在 10:20 记录的 `10.10.8.25` 当时由谁使用；
- 一个 IP 被 DHCP 重新分配后，历史事件是否仍然归属于原设备和原用户；
- 域控、代理、堡垒机等共享设备是否应该归属于某个个人。

## 3. 第一层：将异构日志转换为统一语义

不同厂商对同一个概念使用不同字段。用户名可能位于 `TargetUserName`、`Account_Name`、`uid`、`src_user` 或厂商自定义字段中；设备可能表现为 IP、NetBIOS 名、FQDN 或传感器字段。

Splunk Add-on 通过事件切分、字段提取、字段别名、计算字段和 CIM 映射，将原始字段转换成相对统一的安全语义，例如：

```text
user          行为主体账号
src_user      源端用户
dest_user     目标用户
src           源端设备或地址
dest          目标设备或地址
dvc           记录事件的设备
src_ip        源 IP
dest_ip       目标 IP
```

一条 Windows 4624 登录事件经过解析后可能形成：

```json
{
  "event_id": "4624",
  "action": "success",
  "user": "CORP\\zhangsan",
  "src_ip": "10.10.8.25",
  "dest": "WIN-LAPTOP-023",
  "authentication_method": "Kerberos",
  "event_time": "2026-09-11T09:05:00+08:00"
}
```

Zeek `conn.log` 可能形成：

```json
{
  "src_ip": "10.10.8.25",
  "src_port": 51731,
  "dest_ip": "203.0.113.20",
  "dest_port": 443,
  "network_transport": "tcp",
  "event_time": "2026-09-11T10:20:00+08:00"
}
```

标准化只解决“字段含义一致”，还没有证明两个字符串属于同一个实体。实体解析必须在其后完成。

## 4. 第二层：建设资产和身份主数据

### 4.1 身份主数据

身份数据通常来自 AD、LDAP、HR、IAM 或其他人员目录。Splunk ES 的身份记录包含账号标识和组织上下文，常见字段有：

```text
identity、email、first、last、managedBy、priority、bunit、category、
watchlist、startDate、endDate、work_city、work_country
```

`identity` 可以保存同一身份的多个可匹配值：

```text
zhangsan|CORP\zhangsan|zhangsan@corp.example|adm_zhangsan
```

ES 可以将字段配置为 Key、Tag、单值或多值字段。不同来源的身份记录命中关键字段时进入合并流程；多值字段合并去重，单值字段冲突时按照输入源的排序优先级选择。身份命名规则还可以根据姓名字段生成组织内常用的账号形式。官方说明见 [Identity Lookup 配置策略](https://help.splunk.com/splunk-enterprise-security-7/administer/7.3/asset-and-identity-management/manage-identity-lookup-configuration-policies-in-splunk-enterprise-security) 和 [身份字段设置](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-identity-field-settings-in-splunk-enterprise-security)。

### 4.2 资产主数据

资产数据通常来自 CMDB、AD Computer 对象、DHCP、DNS、EDR、漏洞扫描和云资产清单。Splunk ES 默认使用以下关键字段识别资产：

```text
ip、mac、nt_host、dns
```

合并后的一条资产记录可能是：

```json
{
  "asset_id": "device-92381",
  "ip": ["10.10.8.25"],
  "mac": ["00:11:22:33:44:55"],
  "nt_host": ["WIN-LAPTOP-023"],
  "dns": ["win-laptop-023.corp.example"],
  "owner": "zhangsan",
  "category": ["workstation"],
  "priority": "medium"
}
```

相同关键字段会触发资产合并，因此数据治理非常重要。若两个实际不同的系统在资产源中错误共享同一个 IP，合并结果也可能错误。Splunk 官方明确提示，默认关键字段是 `dns`、`ip`、`mac` 和 `nt_host`，重复关键值可能把记录合成同一个资产。[资产合并策略](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-asset-lookup-configuration-policies-in-splunk-enterprise-security)

## 5. 第三层：账号标准化与自然人归并

同一个账号在日志中可能出现为：

```text
ZhangSan
CORP\zhangsan
CORP\\zhangsan
zhangsan@corp.example
zhangsan/corp
```

同一个自然人还可能拥有多个账号：

```text
employee_id = E10293
human_entity = 张三

├── CORP\zhangsan       普通账号
├── zhangsan@corp.com   UPN/邮件形式
├── ADM_zhangsan        管理员账号
└── svc_zs_report       服务账号，是否归属需明确配置
```

Splunk UBA 的处理可以概括为：

1. 从事件中提取账号并保留原始值；
2. 解析域名、UPN 和账号主体，处理不同分隔符及大小写；
3. 使用完整账号匹配 HR/AD 数据；
4. 未命中时去除域信息，再匹配规范账号；
5. 根据员工号、邮件、登录名或配置规则将多个账号关联到自然人；
6. 标记普通、管理员、服务和系统账号等账号类型；
7. 以稳定的人员实体作为行为建模主体。

官方示例说明，UBA 可以将 `jsmith` 与 `adm_jsmith` 归并到同一个人员，并将两个账号产生的事件共同用于异常检测。[为什么 UBA 需要 HR 数据](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.2.1/add-hr-data-to-splunk-uba/why-splunk-uba-requires-hr-data)

## 6. 第四层：设备实体解析

同一设备在不同日志中可能表现为：

```text
10.10.8.25
WIN-LAPTOP-023
win-laptop-023.corp.example
00:11:22:33:44:55
```

UBA 对设备标识的公开优先级是：

```text
主机名 > MAC 地址 > IP 地址
```

- IP 是设备的临时网络表示，可能被 DHCP 重复分配，标识等级最低；
- MAC 更接近物理接口，稳定性高于 IP；
- 主机名是可读的规范表示，UBA 将其作为最高等级，但准确性依赖 AD 域、DNS 和资产数据质量。

如果最初只看到 IP，系统可能先产生未解析设备；当后续数据证明该 IP 对应某个 MAC 和主机名时，IP 设备会被更稳定的设备实体取代或标记为 superseded。UBA 的仪表盘和模型主要使用解析后的设备。[UBA Device Resolution](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/hunter-workflow/see-all-devices-on-the-devices-table)

## 7. 第五层：建立随时间变化的关联关系

静态映射 `10.10.8.25 → 张三` 不足以支持 UEBA。IP、设备和用户的关系具有有效时间：

```text
10.10.8.25
  09:00—12:00 → WIN-LAPTOP-023 → 张三
  13:00—18:00 → WIN-LAPTOP-088 → 李四
```

UBA 使用多类日志建立时态关系：

| 数据源 | 可提供的关系证据 |
|---|---|
| AD/认证日志 | 用户—主机、用户—IP、IP—主机 |
| DHCP | IP—MAC—主机名及租约有效时间 |
| DNS | IP—主机名 |
| VPN | 用户—VPN 地址及登录会话时间 |
| HR/AD 目录 | 账号—自然人、部门、岗位、经理 |
| CMDB/资产清单 | 主机名—资产属性—业务归属 |

Splunk 官方说明，UBA 使用认证、DNS、DHCP 和 VPN 数据解析 IP、主机名与用户之间的实时关联，并随时间维护这些关系。[UBA 实体解析所需数据源](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/which-data-sources-do-i-need)

## 8. Windows AD、DHCP 与 Zeek 串联实例

### 8.1 DHCP 建立地址与设备关系

09:00，DHCP 产生租约：

```text
MAC=00:11:22:33:44:55
IP=10.10.8.25
hostname=WIN-LAPTOP-023
lease_start=09:00
lease_end=17:00
```

解析后形成：

```text
10.10.8.25 ↔ 00:11:22:33:44:55 ↔ WIN-LAPTOP-023
有效时间：09:00—17:00
```

### 8.2 Windows 登录建立用户与设备关系

09:05，域控或终端产生 Windows 4624：

```text
EventCode=4624
user=CORP\zhangsan
dest=WIN-LAPTOP-023
src_ip=10.10.8.25
```

账号归一化和主数据匹配后形成：

```text
E10293/张三 ↔ WIN-LAPTOP-023
E10293/张三 ↔ 10.10.8.25
开始时间：09:05
证据：Windows 4624
```

### 8.3 Zeek 网络事件补全用户

10:20，Zeek 记录外联：

```text
ts=10:20
id.orig_h=10.10.8.25
id.resp_h=203.0.113.20
service=ssl
```

Zeek 事件没有用户名。身份解析组件使用事件时间查询关系：

```text
10:20 时：10.10.8.25 → WIN-LAPTOP-023 → E10293/张三
```

最终生成可用于 UEBA 的富化事件：

```json
{
  "event_time": "2026-09-11T10:20:00+08:00",
  "src_ip": "10.10.8.25",
  "dest_ip": "203.0.113.20",
  "device_entity_id": "device-92381",
  "device_name": "WIN-LAPTOP-023",
  "user_entity_id": "employee-E10293",
  "user_display_name": "张三",
  "attribution_sources": ["DHCP", "Windows-4624"],
  "attribution_confidence": 0.95
}
```

此处的 `0.95` 仅是自研设计示例，不代表 Splunk 公布的内部评分。Splunk 并未公开完整的实体解析评分公式。

## 9. ES Lookup 与 UBA Identity Resolution 的区别

| 能力 | Splunk ES | Splunk UBA |
|---|---|---|
| 字段标准化 | CIM | UBA 数据类型映射 |
| 用户与资产主数据 | Asset/Identity Lookup | HR、AD、资产数据 |
| 多来源记录合并 | 支持 | 支持 |
| 搜索时上下文补全 | 核心机制 | 支持 |
| 多账号归并到自然人 | 依赖 Lookup 配置 | 核心机制 |
| IP—主机—用户动态关联 | 有限，常需搜索逻辑补充 | 核心机制 |
| 关系有效时间 | 通常需要自行设计 | Identity Resolution 持续维护 |
| 行为模型 | ES 检测和 RBA 为主 | 用户、账号和设备模型 |
| 实体风险聚合 | Risk Object | 用户/设备异常和威胁评分 |

可以把两者简化为：

```text
ES：事件字段 → 查询资产/身份表 → 补充部门、类别、优先级

UBA：事件标识 → 解析账号和设备 → 建立动态关系
   → 将行为归属给实体 → 形成基线、异常和威胁
```

## 10. 实体如何成为风险对象

Splunk ES 的检测规则可以把查询结果中的字段指定为 `risk_object` 和 `risk_object_type`：

```spl
...
| eval risk_object=user
| eval risk_object_type="user"
| eval risk_score=30
```

设备风险对象可以写为：

```spl
...
| eval risk_object=dest
| eval risk_object_type="system"
| eval risk_score=20
```

风险修饰事件写入 `risk` index，同一用户或系统在不同检测中产生的风险可以继续聚合：

```text
张三
├── 新国家登录                 +20
├── 非工作时间使用管理员账号     +25
├── 访问异常域名                +30
└── 大量文件下载                +35
                                ───
累计风险                       110
```

ES 可以对资产和身份表进行反向查询，将同一对象的 IP、MAC、主机名或账号别名共同用于风险展示。[Splunk ES Risk Analysis](https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.2/dashboard-reference/risk-analysis) 官方同时说明，风险对象可以是 `system`、`user` 或其他对象，匹配资产/身份表不是创建风险对象的硬性前提。[Risk Object 机制](https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/risk-analysis/analyze-risk-in-splunk-enterprise-security)

## 11. 误关联场景与控制方法

实体解析不会天然准确，常见风险包括：

| 场景 | 可能造成的错误 | 控制方法 |
|---|---|---|
| DHCP 地址复用 | 新用户的行为归到旧用户 | 使用租约有效时间，禁止静态永久绑定 |
| NAT、代理、出口网关 | 多人被合并成一个用户 | 标记共享基础设施，不执行用户归属 |
| 域控、VDI、终端服务器 | 共享设备归属于最近登录用户 | 使用会话级归属或加入排除列表 |
| 服务账号 | 机器行为被归到员工 | 单独建立账号实体和账号类型 |
| 多 AD 域存在重名账号 | 不同用户被合并 | 使用 `domain + account` 或不可变目录 ID |
| 主机重装、克隆 | 同名设备或重复机器标识冲突 | 综合设备目录 ID、主机名、MAC 和生命周期 |
| VPN 未正常退出 | 用户—IP 关系持续过久 | 设置会话超时并吸收后续登录/注销证据 |
| 日志迟到或乱序 | 使用当前映射解释历史事件 | 使用事件时间，允许迟到修正和历史回算 |

UBA 维护身份解析排除列表，避免把域控、共享服务器和代理等多用户系统绑定给个人。其公开机制还可以根据一台设备关联的用户数量识别不适合归属的服务器。[UBA Identity Resolution 排除机制](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/add-assets-data-and-identify-assets-to-exclude-from-detections/exclude-identity-resolution-for-devices-or-users)

## 12. 对自研 UEBA 的数据模型建议

### 12.1 稳定实体表

```text
entity
├── entity_id              内部稳定主键
├── entity_type            human/account/device/ip/service/resource
├── display_name
├── lifecycle_status       active/disabled/retired/unknown
├── first_seen
├── last_seen
└── attributes             部门、职位、资产级别等扩展属性
```

自然人、账号和设备建议作为不同实体保存，不要把账号直接当作自然人：

```text
human:E10293 ──owns──> account:CORP\zhangsan
human:E10293 ──owns──> account:CORP\ADM_zhangsan
account:CORP\zhangsan ──logged_on──> device:D92381
```

### 12.2 实体标识表

```text
entity_identifier
├── entity_id
├── identifier_type        samAccountName/upn/email/ip/mac/hostname/dns
├── identifier_value
├── normalized_value
├── valid_from
├── valid_to
├── source
├── confidence
└── is_primary
```

同一标识符在不同时段可以指向不同实体。查询时必须同时匹配 `identifier_value` 与事件时间。

### 12.3 时态关系表

```text
entity_relation
├── subject_entity_id
├── relation_type          owns/logged_on/resolved_to/member_of/managed_by
├── object_entity_id
├── valid_from
├── valid_to
├── evidence_event_id
├── evidence_source
├── resolution_rule
├── confidence
├── is_shared
└── is_excluded
```

### 12.4 事件归属结果

事件表中保留解析后的实体字段，同时保留解析元数据：

```text
actor_user_entity_id
actor_account_entity_id
src_device_entity_id
dest_device_entity_id
attribution_version
attribution_sources
attribution_confidence
attribution_status
```

原始字段必须保留，以便关系规则升级后重新解析历史数据。

## 13. 自研解析流程建议

建议按以下顺序执行，不要一开始使用模糊匹配把全部标识强行合并：

1. **确定性强匹配**：员工号、AD objectGUID、云目录 immutable ID、资产 ID。
2. **规范标识匹配**：`domain + account`、UPN、规范 FQDN、MAC。
3. **时态网络匹配**：根据 DHCP、VPN、DNS 的有效时间关联 IP 和设备。
4. **会话归属**：根据登录、注销和超时规则关联用户与设备。
5. **弱证据推断**：使用姓名、相似账号名、设备 owner 等信息产生候选关系。
6. **冲突裁决**：根据数据源可靠性、时间接近度和排除规则选择结果。
7. **保留未解析状态**：证据不足时保持 unknown，避免错误合并污染长期画像。

推荐的置信度分层示例：

| 等级 | 示例证据 | 建议用途 |
|---|---|---|
| 高 | AD immutable ID、员工号、有效 DHCP 租约加登录事件 | 可直接进入实体画像和检测 |
| 中 | 同域账号、有效 VPN 会话、DNS 与资产信息组合 | 可进入检测，但应展示证据 |
| 低 | 仅 IP、仅相似用户名、仅 CMDB owner | 用作调查线索，不宜自动合并 |

## 14. 实施时应监控的质量指标

实体解析本身需要作为一项持续运营的数据产品。至少监控：

- 用户事件解析率、设备事件解析率；
- 仅凭 IP 完成归属的事件比例；
- unknown、ambiguous、conflict 的数量及趋势；
- 一个账号关联多个自然人的冲突率；
- 一个设备同时关联大量用户的比例；
- DHCP、DNS、VPN、认证日志的延迟和缺口；
- 关系被追溯修正的数量；
- 排除列表命中数量；
- 每种解析规则的人工抽样准确率；
- 解析规则版本变更后，检测结果和风险分数的变化。

## 15. 最终判断

Splunk 的实体识别可以概括为三类数据共同作用：

```text
主数据：谁是员工、有哪些账号、有哪些设备
事件证据：谁在什么时候登录、IP 在什么时候分配给谁
解析规则：哪些标识可以合并、证据冲突时相信谁
```

ES 重点解决搜索时的资产与身份上下文补全，UBA 重点解决跨账号、跨设备和跨时间的行为归属。自研 UEBA 若只按 `username` 或 `src_ip` 聚合，短期可以生成统计结果，但会因为别名、共享设备、DHCP、VPN 和服务账号持续污染基线。

应先建设可审计、可回放、带有效时间的实体解析层，再在稳定实体之上计算特征、基线和风险。实体解析结果也不应只有“匹配/不匹配”，还必须回答：**在什么时间，依据哪些证据，通过哪条规则，以多大置信度，把这条行为归给了谁。**

## 16. 主要官方资料

1. [Splunk UBA：数据源与身份解析关系](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/which-data-sources-do-i-need)
2. [Splunk UBA：HR 数据与多账号归并](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.2.1/add-hr-data-to-splunk-uba/why-splunk-uba-requires-hr-data)
3. [Splunk UBA：Device Resolution](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/hunter-workflow/see-all-devices-on-the-devices-table)
4. [Splunk UBA：身份解析排除机制](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/add-assets-data-and-identify-assets-to-exclude-from-detections/exclude-identity-resolution-for-devices-or-users)
5. [Splunk ES：资产与身份管理](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-assets-and-identities-in-splunk-enterprise-security)
6. [Splunk ES：资产合并配置策略](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-asset-lookup-configuration-policies-in-splunk-enterprise-security)
7. [Splunk ES：身份合并配置策略](https://help.splunk.com/splunk-enterprise-security-7/administer/7.3/asset-and-identity-management/manage-identity-lookup-configuration-policies-in-splunk-enterprise-security)
8. [Splunk ES：Risk Analysis](https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/risk-analysis/analyze-risk-in-splunk-enterprise-security)
