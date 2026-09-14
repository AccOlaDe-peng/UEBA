# UEBA 异构日志归一设计——最终合订本

> 文档状态：预研设计合订本  
> 编制日期：2026-09-14  
> 总体架构：Elasticsearch 作为事件、特征和分析结果的存储检索底座  
> 首期范围：HR/AD、CMDB/AD Computer、Windows Security、DHCP、VPN、Zeek conn/dns/http  
> 参考体系：Splunk CIM、Splunk UEBA/Asset and Identity、Elastic ECS  
> 配套制品：[Elasticsearch 原型](./elasticsearch-prototype/README.md)、[机器可读测试集](./testdata/manifest.json)

## 文档说明

本合订本将总体架构、统一事件模型、日志源映射、CIM—ECS—UEBA 语义对照、事件目录、质量规则、测试集、Pipeline 发布、健康监控、Elasticsearch 原型和端到端验证链组织为一份完整设计。各分册仍作为独立维护单元；本文件由分册机械合并生成，用于统一评审和交付。

Splunk 官方资料用于确认 CIM、身份解析、资产与身份、行为分析和数据源要求；文中的 Elasticsearch 结构、`ueba.*` 扩展、质量阈值、版本机制和实现流程属于本项目自研设计，不代表 Splunk 内部实现。

核心判断是：任何单一日志源都不能形成完整、高可信的 UEBA。Zeek 单独只能形成 IP、设备候选和网络会话行为；用户级输出必须同时具备身份源、资产源、含用户活动源及事件时刻有效的用户—设备—IP 关系。

## 总目录

1. [第一篇　总体架构](#part-01)
2. [第二篇　统一事件模型规范](#part-02)
3. [第三篇　日志源接入与映射清单](#part-03)
4. [第四篇　CIM—ECS—UEBA 语义对照表](#part-04)
5. [第五篇　事件类型目录](#part-05)
6. [第六篇　数据质量规则](#part-06)
7. [第七篇　解析与映射测试集](#part-07)
8. [第八篇　Pipeline 版本和发布规范](#part-08)
9. [第九篇　数据源健康监控指标](#part-09)
10. [第十篇　Elasticsearch 原型](#part-10)
11. [第十一篇　完整验证链](#part-11)

---

<a id="part-01"></a>

## 第一篇　总体架构

> 本篇来源：[UEBA整体架构预研-Elasticsearch方案.md](./UEBA整体架构预研-Elasticsearch方案.md)

可以。我的预研结论是：**以 Elasticsearch 作为事件、特征和分析结果的存储检索底座，围绕它建设“日志标准化 → 实体解析 → 行为基线 → 异常检测 → 风险关联 → 调查反馈”的完整 UEBA 链路。**

需要把“Splunk 官网确认的能力”和“我们自行设计的实现”分开，避免把 Elasticsearch 的聚合能力直接等同于完整 UEBA。

**一、先明确参考哪部分 Splunk**

Splunk 的相关能力分布在不同产品中：

| 参考对象 | 主要借鉴内容 |
|---|---|
| Splunk Platform + CIM | 异构日志接入、字段与事件语义规范化 |
| 独立 Splunk UBA | 身份解析、个体与同群基线、异常检测、威胁关联 |
| Splunk Enterprise Security 的 RBA | 将多个风险事件按实体累计、关联，形成调查告警 |
| 当前 Splunk UEBA 产品 | 集成于安全分析流程的实体行为与风险分析方向 |

CIM 是共享语义模型；独立 UBA 则进一步完成账号归一、身份解析、行为建模和威胁检测；RBA 属于 Enterprise Security 的风险告警机制。这三者需要分别映射。[CIM 官方说明](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[UBA 官方说明](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/plan-and-scale/5.2.1/plan-and-scale-your-splunk-uba-deployment/about-splunk-user-behavior-analytics)、[RBA 官方说明](https://help.splunk.com/en/splunk-enterprise-security-7/tutorials-and-use-cases/7.3/risk-based-alerting-tutorial/about-the-risk-based-alerting-tutorial)

另外，官网已公告**独立 Splunk UBA 将于 2027 年 1 月 31 日结束支持**。因此，它适合作为机制参考，但不能与当前 Splunk UEBA 产品混为一谈。[UBA 生命周期提示](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/understand-data-flow-in-splunk-uba)、[当前 UEBA 产品页](https://www.splunk.com/en_us/products/user-and-entity-behavior-analytics.html)

**二、整体能力映射**

以下 Elasticsearch 方案是架构建议，不是对 Splunk 内部实现的复刻。

| 环节 | Splunk 对应机制 | 基于 Elasticsearch 的实现建议 | 需要补齐的业务能力 |
|---|---|---|---|
| 日志统一 | CIM 字段、标签和数据模型 | Logstash / Ingest Pipeline → ECS 标准事件 | 映射注册表、语义校验、版本管理 |
| 实体发现 | 从 HR、资产及活动数据识别用户、设备 | 提取账号、人员、设备等实体，保存实体主档 | 稳定 ID、实体生命周期 |
| 身份解析 | 账号归并，关联 IP、设备、用户及历史关系 | 实体解析服务 + 带有效期的关系记录 | 冲突消解、归属置信度、历史纠错 |
| 行为画像 | 按用户、设备、应用及同群建立行为上下文 | Transform / 聚合任务生成实体特征 | 特征定义、同群管理 |
| 基线训练 | 行为建模、同群分析、无监督学习 | 自研统计/模型服务，或 Elastic ML | 冷启动、漂移、训练发布 |
| 异常检测 | 流式模型、批模型、异常规则 | 规则任务 + 当前特征与历史基线比较 | 统一异常对象、解释与去重 |
| 威胁关联 | 将异常组合为有上下文的威胁 | 时间窗口、序列、实体关系关联 | 攻击链与证据组织 |
| 实体风险 | Enterprise Security RBA | 风险事件索引 + 风险计算服务 | 衰减、重复证据抑制、优先级 |
| 调查反馈 | 异常与威胁调查 | Kibana / 自研界面 + 案件服务 | 原始证据下钻、处置反馈 |

Splunk 官网明确区分流式异常模型、批处理模型和威胁模型，并说明异常可进一步组合成威胁；这也是建议保留“异常”和“风险/威胁”两个层次的依据。[UBA 数据流](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/understand-data-flow-in-splunk-uba)

**三、推荐的逻辑架构**

```text
Windows / AD / VPN / Zeek / EDR / 邮件 / 数据库 / 云审计
                            │
                         日志采集
                            │
                   缓冲与重放：Kafka（按需）
                            │
                解析 → ECS标准化 → 质量校验
                            │
           HR / AD / CMDB ─→ 实体解析 ←─ DHCP / VPN / DNS
                            │
                 Elasticsearch 标准事件
                            │
                ┌───────────┴───────────┐
                │                       │
           确定性规则              实体窗口特征
                │                       │
                │              ┌────────┴────────┐
                │           历史特征           当前特征
                │              │                 │
                │        训练、验证、发布 ─→ 基线比较
                │                                │
                └─────────────┬──────────────────┘
                              │
                           统一异常
                              │
                  证据去重 → 关联 → 实体风险
                              │
                       威胁 / 案件 / 调查
                              │
                       反馈与检测调优

对象存储：原始证据、历史重放、模型制品
控制数据库：规则、映射、模型版本、发布状态、案件事务
```

规模较小时，可以先采用 **Logstash + Elasticsearch + Python 定时任务 + Kibana**。Kafka、有状态流计算和独立模型服务按吞吐、延迟与重放要求逐步引入，不必一开始全部拆成微服务。

**四、异构日志统一：统一语义，不只是统一 JSON**

Splunk CIM 通过字段和标签让不同来源的事件具有一致语义，并支持搜索时规范化、保留原始数据。Elasticsearch 路线建议以 **ECS 作为落库规范，同时维护 CIM → ECS 的语义对照表**。[Splunk CIM](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[Elastic ECS](https://www.elastic.co/docs/reference/ecs)

例如，Windows、VPN、Linux 都可能产生认证事件：

| 统一含义 | 建议字段 | 设计重点 |
|---|---|---|
| 事件发生时间 | `@timestamp` | 明确源时区，保留采集时间 |
| 数据来源 | `event.dataset` | 区分来源与解析规则 |
| 行为类别 | `event.category` | 认证统一为 `authentication` |
| 行为动作 | `event.action` | 登录、登出、认证失败等分别定义 |
| 结果 | `event.outcome` | 区分成功、失败、未知 |
| 账号 | `user.id`、`user.name`、`user.domain` | 避免跨域同名误合并 |
| 网络端点 | `source.ip`、`destination.ip` | 根据事件语义映射 |
| 原始证据 | `event.original` 或归档引用 | 能回查真实原文 |
| 解析后的人员归属 | 自定义 `ueba.person_id` | 不覆盖原始账号身份 |

特别要区分 `host` 与 `observer`：设备产生或采集日志，不代表它就是行为发生的终端。

每个数据源都应交付一份**数据合同**：源字段、目标字段、类型、枚举、单位、空值规则、适用事件、映射版本、样例与验证结果。解析失败进入隔离队列；关键字段缺失时，降低对应检测的可用性，而不是填默认值掩盖问题。

如果要求“兼容 CIM”，应明确兼容的是字段与 Dataset 语义；这不意味着 Elasticsearch 能直接运行 SPL、`tstats` 或 Splunk 检测内容。

**五、实体发现与身份解析：这是最容易影响检测准确率的一层**

Splunk 官方说明，HR 用于将账号关联到人员，资产数据用于识别设备；认证、DNS、DHCP、VPN 日志用于建立和维护身份关系。[数据源要求](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need)

建议区分四类对象：

| 对象 | 示例 | 稳定身份依据 |
|---|---|---|
| 人员 | 张三 | HR 人员 ID |
| 账号 | 普通账号、管理员账号 | 租户/域 + 目录对象 ID |
| 设备 | 笔记本、服务器 | 资产 ID、可信设备 ID |
| 会话 | VPN、终端登录会话 | 来源命名空间 + 会话 ID |

关系独立保存，例如：

```text
账号 A ─属于→ 人员 P
账号 A ─登录→ 设备 H
IP X   ─分配给→ 设备 H，生效区间 [t1, t2)
会话 S ─关联→ 账号 A、设备 H
```

关系记录至少包含：

```text
关系两端、关系类型、有效期、证据来源、置信度、解析版本
```

必须按**事件发生时的关系**归属日志。上午某 IP 属于张三，下午分配给李四，不能用最新关系解释上午的事件。

还需要保留“未知”和“多个候选”。共享服务器、代理、NAT 出口不能仅凭 IP 强行归属到单个人员。Splunk 也明确提供身份解析排除机制，避免将共享系统关联给特定用户。[Splunk 身份解析排除机制](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/add-assets-data-and-identify-assets-to-exclude-from-detections/exclude-identity-resolution-for-devices-or-users)

Elasticsearch Enrich 可用于较稳定的部门、资产属性，但官方不建议用它追加实时变化的数据。因此，DHCP/VPN 时态关系建议由专门的解析任务维护。[Enrich 使用边界](https://www.elastic.co/guide/en/elasticsearch/reference/current/enrich-setup.html)

**六、基线训练：先定义特征，再选择算法**

Elasticsearch Transform 可以把事件转换为按实体组织的汇总索引，适合生成行为特征；**它负责特征计算，不等于完成基线训练。**[Transform 官方说明](https://www.elastic.co/docs/explore-analyze/transforms)

建议先建设以下基线：

| 基线类型 | 特征示例 | 首期实现 |
|---|---|---|
| 数值基线 | 每小时登录次数、上传字节数、文件读取量 | 分位数、Median/MAD |
| 时间基线 | 活跃小时、工作日与周末分布 | 按星期和时段统计 |
| 稀有行为基线 | 访问设备、域名、应用 | 历史频次、最近出现时间 |
| 同群基线 | 同岗位的数据访问量 | 同群分布与偏离程度 |
| 关系基线 | 用户常用设备、常访问服务 | 关系频次与新颖度 |

基线的完整主键应类似：

```text
租户 × 实体 × 特征 × 窗口粒度 × 周期分组 × 特征版本
```

例如“用户每小时上传量”应区分工作时段与夜间，也应区分人类用户与批量作业账号。

训练流程建议：

1. 从历史事件生成版本一致的窗口特征。
2. 排除当前待检测窗口，避免训练数据泄漏。
3. 检查日志覆盖率、有效样本和周期覆盖。
4. 训练个人基线，样本不足时回退到同群基线。
5. 用按时间切分的留出数据评估。
6. 发布基线版本，并保留回滚能力。

可以用 **28 天历史、小时级窗口、每日更新**作为首轮实验参数，但这属于建议，不是 Splunk 固定配置；月度业务、低频行为需要更长观察期。日志断流也不能直接当作“行为量为零”。

**七、风险识别：把异常强度、风险和案件分开**

一个异常回答“哪里偏离了正常行为”；实体风险回答“这个用户或设备值得多大优先级关注”；案件回答“有哪些证据支持一个待调查的安全问题”。

建议采用三层输出：

| 层次 | 示例 | 必须保存 |
|---|---|---|
| 异常 | 用户上传量显著增加 | 实际值、基线、偏离度、证据、模型版本 |
| 风险事件 | 异常上传涉及敏感资产 | 异常引用、上下文、评分原因 |
| 威胁/案件 | 异常访问后疑似集中外传 | 时间线、关联依据、原始证据 |

自研风险评分可以采用以下思路：

```text
单条贡献 = 检测强度 × 证据可信度 × 业务影响 × 时间衰减
实体风险 = 去重后的贡献聚合 + 经过验证的关联加权
```

这只是待校准的设计框架，不是 Splunk 官方公式。分数映射到 0–100 后，也不能直接解释成攻击概率。

需要控制三个问题：

- 同一批日志被多个检测命中，不能无限重复加分。
- 低可信身份关联不能直接变成高置信人员指控。
- 新设备、新地点、首次行为可以产生观察记录，但不应单独认定威胁。

例如，同一人员出现“罕见设备登录 → 大量读取敏感文件 → 向新外部目的地上传”，才适合进一步关联调查。仅有流量日志时，可以支持“疑似外传”，不能据此证明具体文件泄露。

**八、Elasticsearch 的落库设计与产品边界**

建议将事件、状态、模型和结果分开：

| 数据集合 | 用途 |
|---|---|
| `logs-ueba-*` | 标准事件，按生命周期管理 |
| `ueba-entities` | 实体当前主档 |
| `ueba-entity-relations-*` | 带有效期的身份关系 |
| `ueba-features-*` | 小时/日窗口特征 |
| `ueba-baselines-*` | 基线参数与版本 |
| `ueba-anomalies-*` | 异常及解释 |
| `ueba-risk-events-*` | 风险贡献明细 |
| `ueba-risk-current` | 实体当前风险 |
| `ueba-risk-history-*` | 风险变化历史 |

不建议按用户创建索引。特征、异常和风险写入应采用可重复生成的业务 ID，支持重放去重；身份纠错后，应能定位受影响窗口并重新计算。

实施路线有两种：

- **自研 UEBA：** Elasticsearch 承担存储、搜索和聚合，实体解析、基线、评分与案件逻辑自行实现。
- **采用 Elastic Security：** 复用其机器学习规则、实体分析和风险评分，再补业务特征。

Elastic 当前已有实体分析和身份关联能力，不能简单认为这些都必须从零开发；但也不能把它们当作基础 Elasticsearch 自带能力。官网列出的实体分析要求包括订阅和权限条件，预研需要锁定目标版本与部署形态核验。[Elastic 实体分析](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics)、[功能要求](https://www.elastic.co/docs/solutions/security/advanced-entity-analytics/entity-analytics-requirements)

**九、首期验证建议**

先用 **AD/认证 + VPN/DHCP + Zeek 或代理 + HR/资产**打通链路，验证四个场景：

1. 非常用设备登录。
2. 异常认证失败后成功登录。
3. 用户访问设备数量异常。
4. 上传量异常，并结合新目的地进行关联。

验收应同时检查：字段语义正确率、身份归属准确率、基线有效覆盖、误报情况、检测延迟、重放一致性，以及异常能否回查原始证据。

这套预研最关键的交付物应是：**Splunk 官网能力证据表、标准事件合同、实体关系模型、特征与基线清单、检测与风险规则、Elasticsearch 数据设计，以及可重放验证方案。** 有了这些，架构才能进入研发评审，而不只是组件选型图。


---

<a id="part-02"></a>

## 第二篇　统一事件模型规范

> 本篇来源：[统一事件模型规范.md](./统一事件模型规范.md)

> 文档状态：预研设计稿  
> 编制日期：2026-09-14  
> 上位架构：[UEBA 整体架构预研—Elasticsearch 方案](./UEBA整体架构预研-Elasticsearch方案.md)  
> 参考基线：Splunk Common Information Model（CIM）、Splunk Enterprise Security UEBA 数据要求、Elastic Common Schema（ECS）  
> 适用范围：Windows、AD、VPN、DHCP、DNS、Zeek、EDR、邮件、数据库、云审计、业务应用及 HR/CMDB 等数据进入 UEBA 前的统一事件处理。

### 1. 目的

本规范定义异构日志进入 UEBA 后的公共事件语义、字段结构、数据类型、事件分类、参与者角色、时间、证据、质量和版本规则，使后续实体解析、特征计算、行为基线、异常检测、风险关联和调查取证使用同一份稳定的数据合同。

统一事件模型的验收目标不是“所有日志都转换成 JSON”，而是：

1. 不同厂商对同一种行为的记录可被同一检测或特征定义消费；
2. 标准字段具有确定的含义、方向、单位、类型和缺失语义；
3. 每个标准结果都能追溯到原始证据、解析器和映射版本；
4. 数据不满足检测条件时能够明确降级，不能使用默认值掩盖缺失；
5. 映射升级后可以重放、比较、回滚和解释历史结果。

本文定义的是自研 UEBA 的工程规范，不声称复刻 Splunk 的内部实现。Splunk 事实、Elastic 事实和本文自研约定在相应章节中分别说明。

### 2. 规范用语

本文使用下列约束词：

| 术语 | 含义 |
|---|---|
| 必须 | 实现和数据必须满足；不满足时不得标记为完全合格 |
| 应当 | 默认要求；只有记录并评审过的原因才能偏离 |
| 可以 | 可选能力，由数据源和用例决定 |
| 禁止 | 不允许出现，违反时属于模型或映射错误 |

### 3. 参考模型与设计取舍

#### 3.1 Splunk CIM 的参考方式

Splunk 官方将 CIM 定义为共享语义模型。CIM Add-on 提供数据模型、Dataset、字段、Tag、文档和验证工具，通过字段提取、字段别名、计算字段、Lookup、Event Type 和 Tag 在搜索时解释已索引的原始数据。CIM 的价值在于让等价事件使用一致字段和分类，同时保留原始机器数据。[Splunk CIM 概述](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[Splunk CIM 归一方法](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time)

本项目借鉴以下机制：

| Splunk CIM 机制 | 本项目采用方式 |
|---|---|
| Data Model | 定义认证、网络、Web、端点、变更、邮件等事件领域 |
| Dataset | 定义领域内的具体事件集合和继承关系 |
| Dataset Constraint | 转换为来源匹配、语义分类和准入条件 |
| Field Alias / Extraction | 转换为显式的来源字段到 ECS 字段映射 |
| Calculated Field | 转换为版本化标准化函数或派生字段规则 |
| Lookup | 转换为受控枚举表、静态 Enrich 或上下文服务 |
| Event Type / Tag | 转换为 `event.category`、`event.type` 和 `ueba.event.type` |
| Required / Recommended Field | 转换为事件合同中的必填、条件必填和推荐字段 |
| CIM Validation | 转换为映射单元测试、回放测试和运行时质量监控 |
| Data Model Acceleration | 按用例转换为 Elasticsearch Transform 或特征索引，不属于事件归一本身 |

Splunk 官方指出应按事件上下文选择数据模型，不能因为某个模型存在同名字段就强行归类；一条来源事件也可能适用于多个数据模型。本规范继承这一原则。

仓库中的 Splunk CIM 8.7.0 模型和 TA 配置作为本地静态证据，例如：

- `Splunk_SA_CIM/default/data/models/*.json` 定义模型、Dataset、约束、字段与计算；
- `Splunk_TA_zeek/default/props.conf` 展示 Zeek 字段别名、计算和 Lookup；
- `Splunk_TA_zeek/default/eventtypes.conf` 与 `tags.conf` 展示事件选择和模型归属；
- `Splunk_TA_windows/default/eventtypes.conf` 与 `tags.conf` 展示 Windows EventCode 到认证、变更、端点等语义的分类。

这些文件证明对应版本的配置声明，不等于本项目已验证 Splunk 的实际运行结果。

#### 3.2 ECS 的使用方式

ECS 定义 Elasticsearch 中事件、日志和指标的公共字段名、数据类型和扩展规则，其目标包括跨来源分析、可视化和关联。[ECS 官方参考](https://www.elastic.co/docs/reference/ecs)

本项目采用以下边界：

- ECS 字段优先承载通用事实，例如时间、用户、主机、网络端点、进程、文件、DNS 和 HTTP；
- `ueba.*` 只承载 ECS 无法完整表达的事件语义、角色投影、质量、来源追踪和检测就绪状态；
- 厂商字段保存在受控的 `vendor.*` 命名空间；
- 不修改 ECS 字段的既有含义；
- ECS 未覆盖的字段先判断能否通过字段复用表达，再决定是否扩展。

#### 3.3 Splunk 与 Elasticsearch 的关键差异

Splunk CIM 主要是搜索时模式。自研 UEBA 需要频繁聚合、重放和训练，因此本项目采用“写入时确定性归一 + 原始证据独立保留”的方式：

```text
原始日志
  → 原始证据归档
  → 来源格式解析
  → ECS 字段与类型归一
  → UEBA 事件语义分类
  → 数据质量判定
  → Elasticsearch 标准事件
  → 实体解析、特征和检测
```

此处的“支持 CIM”表示字段和 Dataset 语义可以建立可审计对照，不表示 Elasticsearch 可以直接执行 SPL、`tstats`、Splunk Data Model 或 Splunk UEBA 内容。

### 4. 总体数据分层

#### 4.1 四层模型

| 层次 | 内容 | 是否允许修改原始值 | 主要消费者 |
|---|---|---:|---|
| 原始证据层 | 原始字节、来源、采集位置、校验值 | 否 | 重放、取证、审计 |
| 来源事件层 | 按厂商格式解析的字段 | 仅做无损类型恢复 | 映射开发、故障调查 |
| 公共事件层 | ECS 公共字段和数据类型 | 按明确规则生成 | 搜索、关联、可视化 |
| UEBA 语义层 | 事件类型、角色、质量、来源追踪 | 由版本化规则生成 | 实体、特征、基线、检测 |

四层信息可以在同一 Elasticsearch 文档中组合，但原始大字段可只存对象存储，并在标准事件中保存引用。

#### 4.2 标准事件顶层结构

```json
{
  "@timestamp": "2026-09-14T08:10:30.000Z",
  "ecs": { "version": "9.5.0" },
  "event": {},
  "log": {},
  "agent": {},
  "observer": {},
  "host": {},
  "user": {},
  "source": {},
  "destination": {},
  "network": {},
  "process": {},
  "file": {},
  "dns": {},
  "http": {},
  "url": {},
  "related": {},
  "labels": {},
  "vendor": {},
  "ueba": {
    "schema": {},
    "source": {},
    "event": {},
    "actor": {},
    "target": {},
    "resource": {},
    "session": {},
    "time": {},
    "provenance": {},
    "quality": {}
  }
}
```

未适用的对象必须省略，禁止批量写入空对象、空字符串或虚构默认值。

### 5. 事件标识与幂等

#### 5.1 标识类型

| 字段 | 类型 | 要求 | 含义 |
|---|---|---|---|
| `event.id` | keyword | 必须 | 标准事件的全局稳定标识 |
| `event.original` | wildcard 或不索引 | 可选 | 短期保留的原始文本 |
| `ueba.provenance.raw_event_id` | keyword | 必须 | 原始事件信封标识 |
| `ueba.provenance.parent_event_id` | keyword | 条件必填 | 一个原始记录拆分为多个语义事件时的父标识 |
| `ueba.source.native_event_id` | keyword | 推荐 | 来源提供的 Record ID、UID、Message ID 等 |
| `trace.id` / `transaction.id` | keyword | 按来源 | 来源系统中的调用链或事务标识 |

#### 5.2 ID 生成规则

来源存在可靠原生 ID 时：

```text
raw_event_id = SHA-256(
  tenant_id || source_namespace || source_instance_id || native_event_id
)
```

来源没有可靠原生 ID 时：

```text
raw_event_id = SHA-256(
  tenant_id || collector_id || source_locator || source_position || raw_content_hash
)
```

一个原始事件只生成一个标准事件时：

```text
event.id = raw_event_id
```

需要拆分语义子事件时：

```text
event.id = SHA-256(raw_event_id || semantic_type || child_ordinal)
```

重放相同原始证据和相同映射版本必须生成相同 `event.id`。禁止使用随机 UUID 作为重放事件的唯一幂等依据。

### 6. 时间模型

#### 6.1 时间字段

| 字段 | 必填性 | 含义 |
|---|---|---|
| `@timestamp` | 必须 | 行为实际发生时间或按回退规则选定的事件时间 |
| `event.start` | 按事件 | 会话或活动开始时间 |
| `event.end` | 按事件 | 会话或活动结束时间 |
| `event.duration` | 按事件 | 持续时间，使用 ECS 纳秒单位 |
| `event.created` | 推荐 | 来源系统生成日志的时间 |
| `event.ingested` | 必须 | 进入 Elasticsearch 的时间 |
| `ueba.source.collected_at` | 必须 | 采集器读取事件的时间 |
| `ueba.source.received_at` | 必须 | 平台入口接收时间 |
| `ueba.time.original` | 条件必填 | 来源原始时间字符串 |
| `ueba.time.original_timezone` | 条件必填 | 原始时区或时区推断来源 |
| `ueba.time.source` | 必须 | `@timestamp` 取值来源 |
| `ueba.time.quality` | 必须 | `exact`、`inferred`、`fallback`、`invalid` |
| `ueba.time.clock_skew_ms` | 可选 | 已验证的源设备时钟偏差 |

#### 6.2 `@timestamp` 选择优先级

```text
可信、带时区的源事件时间
  > 经来源配置补足时区的源事件时间
  > 采集器读取时间
  > 平台入口接收时间
```

使用采集或接收时间回退时，`ueba.time.quality` 必须为 `fallback`，并将依赖准确事件顺序的检测能力标记为不可用或降级。

时间统一保存为 UTC。原始时间字符串和原始时区必须保留，不能只保存换算结果。发生夏令时歧义、时间超前、明显过旧或无法解析时，必须产生质量告警。

### 7. 来源与证据模型

#### 7.1 来源身份

| 字段 | 类型 | 要求 |
|---|---|---|
| `event.dataset` | keyword | 必须，格式建议为 `vendor.product.dataset` |
| `event.provider` | keyword | 按来源填写云服务或提供者 |
| `observer.vendor` | keyword | 观察设备厂商 |
| `observer.product` | keyword | 观察产品 |
| `observer.version` | keyword | 推荐 |
| `agent.id` | keyword | 有采集代理时必填 |
| `agent.type` | keyword | 有采集代理时必填 |
| `ueba.source.type` | keyword | 必须，如 `windows_security`、`zeek_conn` |
| `ueba.source.namespace` | keyword | 必须，隔离同名来源 |
| `ueba.source.instance_id` | keyword | 推荐，标识具体来源实例 |
| `ueba.source.format_version` | keyword | 来源存在版本差异时必填 |

`host.*` 表示行为发生或事件涉及的主机，`observer.*` 表示观察或记录行为的设备。防火墙、IDS、代理、Zeek Sensor 通常应写入 `observer.*`，禁止仅因日志由某设备产生就把它写入 `host.*`。

#### 7.2 原始证据引用

```json
{
  "ueba": {
    "provenance": {
      "raw_event_id": "sha256:...",
      "raw_uri": "s3://ueba-raw/tenant-a/2026/09/14/part-001.zst",
      "raw_offset": 183821,
      "raw_length": 1462,
      "raw_hash": "sha256:...",
      "parser_id": "windows_security_xml",
      "parser_version": "2.3.0",
      "mapping_id": "windows_security_4624",
      "mapping_version": "3.4.1"
    }
  }
}
```

`raw_uri` 只有在归档成功后才可写入正式证据引用。尚未持久化的预计地址不得表示为已归档证据。

### 8. 事件分类

#### 8.1 ECS 分类字段

| 字段 | 用法 |
|---|---|
| `event.kind` | 区分原始事件、告警、状态、指标等，标准行为事件通常为 `event` |
| `event.category` | ECS 受控的高层领域，可多值 |
| `event.type` | ECS 受控的行为形态，可多值 |
| `event.action` | 来源或平台定义的具体动作，不作为跨来源唯一分类键 |
| `event.outcome` | `success`、`failure`、`unknown` |
| `event.code` | 来源事件代码，例如 Windows `4624` |
| `event.reason` | 来源提供或规则生成的原因说明 |

ECS 明确说明 `event.action` 不是受控分类字段，可保留来源动作细节；跨来源检测不得只依赖未经治理的 `event.action`。[ECS User 字段使用示例](https://www.elastic.co/docs/reference/ecs/ecs-user-usage)

#### 8.2 UEBA 事件类型

`ueba.event.type` 是本项目稳定的跨来源行为分类键，格式必须为：

```text
<domain>.<activity>[.<subtype>]
```

首期目录如下：

| 领域 | `ueba.event.type` 示例 | 主要参考 CIM |
|---|---|---|
| 认证 | `authentication.login`、`authentication.logout`、`authentication.ticket_requested` | Authentication |
| IAM | `iam.account_created`、`iam.account_disabled`、`iam.privilege_granted` | Change / Authentication |
| 会话 | `session.vpn_started`、`session.vpn_ended`、`session.remote_started` | Network_Sessions / Authentication |
| 网络 | `network.connection`、`network.transfer`、`network.connection_blocked` | Network_Traffic |
| DNS | `dns.query`、`dns.response`、`dns.update` | Network_Resolution |
| Web | `web.request`、`web.download`、`web.upload` | Web |
| 进程 | `process.start`、`process.end`、`process.access` | Endpoint.Processes |
| 文件 | `file.create`、`file.read`、`file.modify`、`file.delete` | Endpoint.Filesystem / Data_Access |
| 邮件 | `email.send`、`email.receive`、`email.forward` | Email |
| 数据库 | `database.query`、`database.export`、`database.modify` | Databases / Data_Access |
| 外部告警 | `security.alert`、`malware.detected`、`dlp.violation` | Alerts / Malware / DLP |
| 人员上下文 | `identity.person_snapshot`、`identity.account_snapshot` | Asset and Identity 数据，不作为普通行为 |
| 资产上下文 | `asset.device_snapshot`、`asset.application_snapshot` | Asset / Inventory 数据，不作为普通行为 |
| 地址关系 | `address.lease_started`、`address.lease_ended` | Network_Sessions / DHCP 来源 |

`ueba.event.type` 必须来源于版本化映射目录，禁止接入方自由生成。新增类型需要同时提交语义定义、字段合同、样例、检测用途和兼容性说明。

#### 8.3 多分类规则

一条事件允许多个 `event.category` 和 `event.type`，但只能有一个主 `ueba.event.type`。附加语义写入：

```json
{
  "ueba": {
    "event": {
      "type": "authentication.login",
      "semantic_tags": ["remote_access", "privileged_activity"]
    }
  }
}
```

一个管理员通过 RDP 登录仍以 `authentication.login` 为主类型；远程访问和特权活动作为标签，避免同一原始行为在特征层被重复计数。

### 9. 行为角色模型

#### 9.1 角色定义

| 角色 | 含义 | 例子 |
|---|---|---|
| Actor | 发起或执行行为的主体 | 用户账号、服务账号、进程、主机 |
| Target | 行为直接作用的对象 | 被登录主机、被修改账号、目标服务 |
| Resource | 行为访问或处理的资源 | 文件、数据库表、邮箱、云对象 |
| Observer | 记录行为的设备或系统 | 域控、防火墙、EDR、Zeek Sensor |
| Session | 承载行为的会话 | VPN、RDP、SSH、Web Session |

#### 9.2 角色字段

角色字段不是实体解析结果的替代品。归一阶段记录来源可直接证明的标识，实体解析阶段再补充稳定实体 ID 和置信度。

```json
{
  "ueba": {
    "actor": {
      "type": "account",
      "source_id": "DOMAIN\\zhangsan",
      "entity_id": null,
      "resolution_status": "unresolved"
    },
    "target": {
      "type": "host",
      "source_id": "PC-001"
    },
    "resource": {
      "type": "file",
      "source_id": "server-a|/finance/budget.xlsx"
    },
    "session": {
      "id": "0x981af",
      "type": "windows_logon"
    }
  }
}
```

实体解析后可以补充：

```json
{
  "ueba": {
    "actor": {
      "entity_id": "account-8fd2",
      "person_id": "person-87321",
      "resolution_status": "resolved",
      "resolution_confidence": 0.98,
      "resolution_version": "1.8.0"
    }
  }
}
```

低置信关系必须保留候选和证据，禁止强制归属。共享主机、域控、代理、NAT、跳板机和批处理账号必须支持排除或特殊实体类型。Splunk UBA 同样通过认证、DNS、DHCP、VPN 建立时态关系，并对共享设备提供身份解析排除机制。[Splunk UBA 数据源与身份解析](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need)

### 10. 核心公共字段

#### 10.1 用户与账号

| 字段 | 类型 | 语义 |
|---|---|---|
| `user.id` | keyword | 来源提供的稳定账号 ID，不能用显示名代替 |
| `user.name` | keyword | 不含域的账号名 |
| `user.domain` | keyword | 身份域、目录或租户域 |
| `user.email` | keyword | 规范化邮件地址 |
| `user.type` | keyword | `user`、`admin`、`service`、`machine`、`unknown` 等本地受控值 |
| `user.roles` | keyword[] | 来源明确提供的角色 |
| `related.user` | keyword[] | 用于调查检索的相关账号标识，不作为权威实体键 |
| `ueba.actor.account_key` | keyword | 规范账号键，优先由目录对象 ID 构造 |

当来源提供 `DOMAIN\\username` 时，必须拆分到 `user.domain` 和 `user.name`，原字符串保留在来源字段中。仅按小写用户名生成实体键是禁止的，因为不同域可能存在同名账号。

#### 10.2 主机、设备与观察者

| 字段 | 类型 | 语义 |
|---|---|---|
| `host.id` | keyword | 来源提供的稳定主机标识 |
| `host.name` | keyword | 来源语义中的主机名称 |
| `host.hostname` | keyword | 规范主机名 |
| `host.domain` | keyword | 主机所属域 |
| `host.ip` | ip[] | 与主机相关的地址，不代表事件时刻一定归属 |
| `host.mac` | keyword[] | 规范 MAC |
| `device.id` | keyword | 设备稳定 ID |
| `observer.*` | 对应 ECS 类型 | 观测或生成日志的安全设备/传感器 |
| `related.hosts` | keyword[] | 调查检索用相关主机名称 |

短主机名、FQDN、资产 ID、云实例 ID 和 MAC 必须分别保留，后续由实体服务解决是否同一设备。

#### 10.3 网络字段

| 字段 | 类型 | 语义 |
|---|---|---|
| `source.ip` / `destination.ip` | ip | 网络连接发起侧/响应侧地址 |
| `source.port` / `destination.port` | long | 相应端口 |
| `source.bytes` / `destination.bytes` | long | 由该端发送的字节数 |
| `network.bytes` | long | 整个事件总字节数 |
| `source.packets` / `destination.packets` | long | 由该端发送的包数 |
| `network.packets` | long | 总包数 |
| `network.transport` | keyword | TCP、UDP、ICMP 等规范小写值 |
| `network.protocol` | keyword | 应用层协议规范小写值 |
| `network.direction` | keyword | 按受控网络边界推导的方向 |
| `network.community_id` | keyword | 可选的跨产品流关联键 |

字节方向必须按“谁发送”定义，不能按采集设备的入站/出站接口机械映射。字段缺失表示不可观测；明确为零才允许写 `0`。

#### 10.4 进程、文件、DNS、Web 与邮件

| 对象 | 优先字段 |
|---|---|
| 进程 | `process.entity_id`、`process.pid`、`process.executable`、`process.command_line`、`process.parent.*`、`process.hash.*` |
| 文件 | `file.path`、`file.name`、`file.size`、`file.hash.*`、`file.extension`、`file.mime_type` |
| DNS | `dns.question.name`、`dns.question.type`、`dns.response_code`、`dns.answers.*` |
| HTTP | `http.request.method`、`http.response.status_code`、`http.request.body.bytes`、`http.response.body.bytes` |
| URL | `url.full`、`url.domain`、`url.path`、`url.query`、`url.registered_domain` |
| 邮件 | `email.message_id`、`email.from.address`、`email.to.address`、`email.subject`、`email.attachments.*` |

敏感正文、命令行、URL 查询参数、邮件主题和文件路径需要按数据分级实施字段级访问控制、脱敏或仅保存哈希/引用，但安全策略不得改变字段语义。

### 11. 缺失值、未知值与冲突

#### 11.1 统一规则

| 状态 | 表达方式 |
|---|---|
| 来源没有该字段 | 省略字段 |
| 来源明确给出空值 | 默认省略，并在质量信息记录必要警告 |
| 来源明确给出数值零 | 写 `0` |
| 来源值存在但不能归类 | 受控枚举允许时写 `unknown`，并保留原值 |
| 解析失败 | 不写标准字段，记录错误和原值 |
| 多个来源值冲突 | 保留候选和来源，禁止静默择一 |

禁止将缺失的用户、IP、端口、字节数、持续时间、结果或时间批量填为 `unknown`、`0`、`-`、`N/A`。这些占位值会污染基线和聚合。

#### 11.2 非破坏性归一

标准化字段不得覆盖来源字段。来源值和标准值不一致时，必须能同时查看：

```json
{
  "vendor": { "product": { "src": "010.001.001.005" } },
  "source": { "ip": "10.1.1.5" },
  "ueba": {
    "provenance": {
      "field_mappings": [
        { "from": "vendor.product.src", "to": "source.ip", "transform": "normalize_ip@1" }
      ]
    }
  }
}
```

生产环境可不逐事件保存完整 `field_mappings`，但映射注册表必须可以通过 `mapping_id + mapping_version` 查询到相同信息。

### 12. 映射注册表与数据合同

#### 12.1 每个来源的映射定义

映射注册表必须包含：

```yaml
mapping_id: windows_security_4624
mapping_version: 3.4.1
status: published
owner: security-data-engineering

source:
  vendor: microsoft
  product: windows
  dataset: windows.security
  format: xml
  match:
    event.code: "4624"

classification:
  event.kind: event
  event.category: [authentication]
  event.type: [start]
  event.action: logged-in
  ueba.event.type: authentication.login

fields:
  - from: vendor.windows.TargetUserSid
    to: user.id
    type: keyword
    required: recommended
  - from: vendor.windows.TargetUserName
    to: user.name
    transform: normalize_account_name@1
    required: true
  - from: vendor.windows.TargetDomainName
    to: user.domain
    transform: normalize_windows_domain@1
    required: conditional
  - from: vendor.windows.IpAddress
    to: source.ip
    transform: normalize_ip@2
    required: conditional
  - from: vendor.windows.LogonType
    to: winlog.logon.type
    transform: to_long@1
    required: true

quality_contract:
  minimum:
    all_of: ["@timestamp", "event.code", "event.outcome", "user.name"]
  identity:
    any_of:
      - ["user.id"]
      - ["user.domain", "user.name"]

tests:
  - windows/4624_interactive.xml
  - windows/4624_network.xml
  - windows/4624_machine_account.xml
```

#### 12.2 数据合同字段等级

| 等级 | 定义 |
|---|---|
| `required` | 缺失则该事件类型不能标记为 `qualified` |
| `conditional` | 满足指定场景时必须存在，例如远程登录需要来源地址 |
| `recommended` | 缺失不阻止接入，但会降低调查或检测价值 |
| `optional` | 来源有可靠值时映射 |
| `forbidden` | 对该事件语义不应出现，出现时提示角色或方向错误 |

Splunk CIM 的 Required/Recommended 字段是重要参考，但本项目的必填等级必须结合具体 UEBA 用例定义。例如 CIM 合规不自动代表“非常用设备登录”检测已经具备设备标识。

### 13. 数据质量模型

#### 13.1 事件质量结构

```json
{
  "ueba": {
    "quality": {
      "status": "partial",
      "score": 0.82,
      "errors": [],
      "warnings": ["device_identifier_missing"],
      "missing_required_fields": [],
      "unknown_enum_fields": [],
      "capabilities": {
        "authentication_behavior": "ready",
        "unusual_login_time": "ready",
        "unusual_device_login": "unavailable",
        "sequence_detection": "degraded"
      }
    }
  }
}
```

#### 13.2 状态定义

| 状态 | 定义 | 路由 |
|---|---|---|
| `qualified` | 满足事件合同，关键语义明确 | 标准事件流 |
| `partial` | 可检索且部分用例可用，但存在非致命缺失 | 标准事件流并携带告警 |
| `invalid` | 无法可靠解析、关键类型冲突或主语义不能确定 | 隔离/失败流 |
| `unsupported` | 来源识别成功但尚无映射 | 未映射流，保留原始证据 |

#### 13.3 质量维度

| 维度 | 指标示例 |
|---|---|
| 完整性 | 必填字段、条件字段和推荐字段覆盖率 |
| 有效性 | 类型、格式、枚举、范围合法率 |
| 一致性 | 来源值与标准值、总量与分量是否一致 |
| 唯一性 | 原始重复率、标准事件重复率 |
| 时效性 | 采集延迟、入口延迟、处理延迟 |
| 语义准确性 | 事件分类、主体、客体和网络方向正确率 |
| 可追溯性 | 原文、解析器、映射版本和来源位置覆盖率 |

质量分数用于描述数据可信程度，禁止直接当作威胁风险分数。任何质量评分公式必须版本化，并保留各子项，不能只保存总分。

### 14. 处理流水线

#### 14.1 逻辑阶段

```text
P01 接收与信封
  → P02 来源识别
  → P03 格式解析
  → P04 类型与基础字段归一
  → P05 事件语义分类
  → P06 静态上下文增强
  → P07 质量校验
  → P08 数据流路由
```

| 阶段 | 主责 | 失败处理 |
|---|---|---|
| P01 | 租户、来源、ID、采集元数据 | 无法识别来源则隔离 |
| P02 | 厂商、产品、Dataset、格式版本 | 进入 `unsupported` |
| P03 | JSON/XML/CSV/TSV/syslog 等解析 | 进入 `invalid`，保留原文 |
| P04 | 时间、IP、MAC、账号、单位、枚举 | 字段级错误与质量降级 |
| P05 | ECS 分类和 `ueba.event.type` | 无主语义则 `unsupported/invalid` |
| P06 | 稳定字典、GeoIP、网段和资产属性 | 增强失败不应丢原事件 |
| P07 | 合同、跨字段约束、能力门槛 | 生成质量状态 |
| P08 | qualified、partial、invalid 路由 | 确保数量对账 |

#### 14.2 运行组件

简单、无状态、确定性的转换可以在 Elastic Agent、Logstash 或 Elasticsearch Ingest Pipeline 完成。以下任务应由独立服务或流处理承担：

- 多事件合并或一条事件拆分为多条文档；
- 依赖 DHCP/VPN 历史区间的时态身份解析；
- 多来源冲突消解；
- 需要外部强一致查询的业务上下文；
- 有状态会话拼接和序列计算。

Elasticsearch Pipeline 使用处理器级和流水线级 `on_failure`；索引 Mapping 冲突等写入错误交给 Failure Store。上线前必须使用模拟接口验证默认与最终 Pipeline 的组合效果。[Elasticsearch Ingest 错误处理](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/error-handling)、[Simulate ingest API](https://www.elastic.co/guide/en/elasticsearch/reference/current/simulate-ingest-api.html)

### 15. Elasticsearch 存储规范

#### 15.1 Data Stream

建议按稳定事件领域建设 Data Stream：

```text
logs-ueba.authentication-default
logs-ueba.iam-default
logs-ueba.network-default
logs-ueba.dns-default
logs-ueba.web-default
logs-ueba.endpoint-default
logs-ueba.file-default
logs-ueba.email-default
logs-ueba.database-default
logs-ueba.alert-default
logs-ueba.context-default
```

不得按用户或单台设备建索引。是否按租户物理拆分由容量、权限和生命周期要求决定，但事件模型保持一致。

#### 15.2 模板分层

```text
ecs-base
  + ueba-base
  + ueba-<domain>
  + vendor-<product>
  + tenant-overrides（严格受控）
```

核心字段必须显式 Mapping：

| 语义 | Elasticsearch 类型 |
|---|---|
| 标识、名称、枚举 | `keyword` |
| IP | `ip` |
| 时间 | `date` |
| 持续时间、字节、计数 | `long` |
| 置信度、质量分 | `scaled_float` 或 `float` |
| 全文说明 | `text`，按需附 `keyword` 子字段 |
| 不受控厂商对象 | `flattened` 或 `enabled: false` |
| 原始文本 | 不索引、`wildcard` 或外部对象存储引用，按需求选择 |

核心对象禁止动态类型猜测。必须限制字段总数、嵌套深度和动态模板范围，防止厂商把用户名、路径或 ID 作为 JSON Key 引起 Mapping Explosion。

### 16. 映射示例

#### 16.1 Windows 4624 登录成功

```json
{
  "@timestamp": "2026-09-14T08:10:30.123Z",
  "ecs": { "version": "9.5.0" },
  "event": {
    "id": "sha256:...",
    "kind": "event",
    "category": ["authentication"],
    "type": ["start"],
    "code": "4624",
    "action": "logged-in",
    "outcome": "success",
    "dataset": "microsoft.windows.security",
    "created": "2026-09-14T08:10:30.500Z",
    "ingested": "2026-09-14T08:10:32.018Z"
  },
  "user": {
    "id": "S-1-5-21-...-1105",
    "name": "zhangsan",
    "domain": "CORP"
  },
  "source": { "ip": "10.10.1.25", "port": 51324 },
  "host": { "hostname": "SRV-APP-01", "domain": "corp.example" },
  "winlog": { "logon": { "id": "0x981af", "type": "10" } },
  "related": {
    "ip": ["10.10.1.25"],
    "user": ["CORP\\zhangsan", "S-1-5-21-...-1105"],
    "hosts": ["SRV-APP-01"]
  },
  "ueba": {
    "schema": { "version": "1.0.0" },
    "source": {
      "type": "windows_security",
      "namespace": "tenant-a/domain-corp",
      "native_event_id": "8827134",
      "collected_at": "2026-09-14T08:10:31.512Z",
      "received_at": "2026-09-14T08:10:31.810Z"
    },
    "event": {
      "type": "authentication.login",
      "semantic_tags": ["remote_access"]
    },
    "actor": {
      "type": "account",
      "source_id": "CORP\\zhangsan",
      "account_key": "tenant-a|corp|S-1-5-21-...-1105",
      "resolution_status": "unresolved"
    },
    "target": { "type": "host", "source_id": "SRV-APP-01" },
    "session": { "id": "0x981af", "type": "windows_logon" },
    "time": { "source": "system_time", "quality": "exact" },
    "provenance": {
      "raw_event_id": "sha256:...",
      "parser_id": "windows_security_xml",
      "parser_version": "2.3.0",
      "mapping_id": "windows_security_4624",
      "mapping_version": "3.4.1"
    },
    "quality": {
      "status": "qualified",
      "score": 0.98,
      "errors": [],
      "warnings": []
    }
  }
}
```

说明：4624 还必须结合 LogonType、账号类型和来源地址判断本地、网络、批处理、服务、远程交互等子语义。机器账号不能默认当作人员账号。

#### 16.2 Zeek conn 网络连接

仓库中的 Zeek TA 将 `id_orig_h/id_orig_p` 映射到 `src/src_port`，将 `id_resp_h/id_resp_p` 映射到 `dest/dest_port`，并由双方字节和包数计算总量。本项目保留这一方向语义，但映射到 ECS：

```json
{
  "@timestamp": "2026-09-14T08:20:00.000Z",
  "event": {
    "id": "sha256:...",
    "kind": "event",
    "category": ["network"],
    "type": ["connection", "end"],
    "action": "network-connection",
    "outcome": "success",
    "dataset": "zeek.zeek.conn",
    "duration": 1340000000
  },
  "source": {
    "ip": "10.10.1.25",
    "port": 51324,
    "bytes": 428,
    "packets": 6
  },
  "destination": {
    "ip": "8.8.8.8",
    "port": 53,
    "bytes": 1240,
    "packets": 8
  },
  "network": {
    "transport": "udp",
    "protocol": "dns",
    "direction": "outbound",
    "bytes": 1668,
    "packets": 14
  },
  "observer": {
    "type": "sensor",
    "name": "zeek-sensor-01",
    "vendor": "Zeek",
    "product": "Zeek"
  },
  "vendor": {
    "zeek": {
      "uid": "C8N...",
      "conn_state": "SF",
      "local_orig": true,
      "local_resp": false
    }
  },
  "ueba": {
    "schema": { "version": "1.0.0" },
    "source": {
      "type": "zeek_conn",
      "namespace": "tenant-a/sensor-01",
      "native_event_id": "C8N...",
      "collected_at": "2026-09-14T08:20:01.100Z",
      "received_at": "2026-09-14T08:20:01.300Z"
    },
    "event": { "type": "network.connection", "semantic_tags": [] },
    "actor": { "type": "network_endpoint", "source_id": "10.10.1.25" },
    "target": { "type": "network_endpoint", "source_id": "8.8.8.8:53" },
    "session": { "id": "C8N...", "type": "network_flow" },
    "time": { "source": "zeek_ts", "quality": "exact" },
    "provenance": {
      "raw_event_id": "sha256:...",
      "parser_id": "zeek_json",
      "parser_version": "1.1.0",
      "mapping_id": "zeek_conn",
      "mapping_version": "1.0.0"
    },
    "quality": {
      "status": "qualified",
      "score": 0.97,
      "errors": [],
      "warnings": []
    }
  }
}
```

`network.direction` 只有在内部网段定义与事件时间有效时才能推导。仅凭 RFC1918 地址判断企业内外边界可能错误，规则必须引用版本化网段配置。

### 17. 版本治理

#### 17.1 版本对象

每条事件必须记录：

```text
ECS 版本
UEBA Schema 版本
解析器 ID 和版本
映射 ID 和版本
标准化函数版本
静态字典/网段版本（使用时）
实体解析版本（增强后）
```

#### 17.2 语义化版本规则

| 变更 | 版本级别 |
|---|---|
| 修正实现错误且不改变合同 | Patch |
| 增加可选字段、事件类型或兼容来源 | Minor |
| 改变字段含义、单位、角色、主分类、实体键或必填条件 | Major |

禁止修改已发布规则后继续沿用旧版本号。字段弃用应经历“新增替代字段—双写观察—消费者迁移—停止写入—移除”的过程。

#### 17.3 重算影响

下列变化必须评估历史重算：

- `ueba.event.type` 改变；
- source/destination 或 actor/target 方向改变；
- 时间解析规则改变；
- 字节、持续时间等单位改变；
- 账号或设备键生成规则改变；
- 关键字段从默认值改为缺失，或反向改变；
- 数据质量门槛改变并影响训练样本。

重算结果应写入新版本数据流或影子索引，比较完成后再切换读取别名。

### 18. 测试、发布与验收

#### 18.1 测试层次

| 测试 | 内容 |
|---|---|
| 解析单元测试 | 原文到来源字段，覆盖正常、缺失、编码和边界情况 |
| 字段合同测试 | 来源字段到 ECS/UEBA 字段、类型、单位、枚举 |
| 语义测试 | 事件分类、角色、方向、结果是否符合真实行为 |
| 跨字段约束 | 总字节是否等于分项、开始是否早于结束等 |
| 幂等测试 | 重复接入和历史重放不产生重复事件 |
| Pipeline 模拟 | 默认、子 Pipeline、最终 Pipeline 和 Mapping 联合验证 |
| 回放测试 | 脱敏真实日志按事件时间回放，核对总量和延迟 |
| 下游回归 | 特征、基线样本和检测输出差异 |
| 性能测试 | 峰值吞吐、P95/P99 延迟、失败流承载能力 |

#### 18.2 每个来源的最小样例集

必须包含：

- 正常成功事件；
- 明确失败事件；
- 必填字段缺失；
- 字段类型错误；
- 未知枚举；
- 不同产品或日志版本；
- 多语言、Unicode 和特殊字符；
- 极端时间、时区和延迟到达；
- 超长字符串、超大数组和嵌套对象；
- 重复事件；
- 机器账号、服务账号和共享设备等实体边界；
- 方向容易混淆的网络事件。

#### 18.3 发布门禁

新映射版本必须经历：

```text
草稿
  → 静态校验
  → 样例测试
  → 历史回放
  → 影子运行
  → 差异评审
  → 分批发布
  → 全量发布
  → 观察与回滚窗口
```

影子运行至少比较：

- 事件数量；
- 分类变化；
- 字段覆盖率；
- 无效与部分合格比例；
- 重复率；
- 时间和处理延迟；
- 特征值变化；
- 异常数量和高风险实体变化。

#### 18.4 运行验收指标

不同数据源应单独设阈值，首期至少观测：

| 指标 | 定义 |
|---|---|
| 接收守恒率 | 标准流 + 部分流 + 失败流相对入口事件数的比例 |
| 解析成功率 | 能恢复来源字段的事件比例 |
| 合格率 | `qualified` 事件比例 |
| 关键字段覆盖率 | 按事件合同计算，不做全局平均 |
| 未知事件比例 | 已识别来源但无语义映射的比例 |
| 重复率 | 原始和标准两个层面的重复比例 |
| 时间回退率 | `@timestamp` 使用采集/接收时间的比例 |
| P95/P99 延迟 | 事件时间到可检索、入口到可检索的延迟 |
| 可追溯率 | 能定位原始证据和映射版本的比例 |
| 检测就绪率 | 满足指定检测数据条件的事件或实体比例 |

### 19. 首期实施范围

Splunk Enterprise Security 当前 UEBA 文档列出的重要来源包括 Windows 安全事件、Microsoft 365 活动和 DHCP；本地部署验证来源对应 Authentication、Network_Traffic、Web、Change、Endpoint、Email 等 CIM 模型。[Splunk UEBA 所需 Sourcetype](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections)

结合总体架构，首期建议按以下顺序落地：

| 优先级 | 来源 | 事件 | 主要验证目标 |
|---:|---|---|---|
| P0 | Windows Security | 4624、4625、4634、4648、4672、4688、4720–4781、4768、4769 | 账号、登录、权限、进程和变更语义 |
| P0 | HR / AD | 人员、账号、组织、角色快照 | 稳定身份键和上下文合同 |
| P0 | DHCP / VPN | 租约、登录、登出、会话 | IP—设备—账号时态关系输入 |
| P1 | Zeek | conn、dns、http、ssl、files | 网络方向、会话、字节和协议语义 |
| P1 | EDR | process、file、network、alert | 用户—进程—设备—资源关系 |
| P2 | 邮件 / 云审计 | 发送、附件、文件操作、权限操作 | 数据访问和外传用例 |

首期完成条件是打通以下可复算链路：

```text
原始 Windows/VPN/Zeek 证据
  → 版本化标准事件
  → 数据质量与检测就绪判定
  → 账号、设备和会话实体解析
  → 登录与网络行为特征
  → 原始证据下钻
```

### 20. 责任边界

| 角色 | 责任 |
|---|---|
| 数据源负责人 | 提供格式、版本、字段语义、时间与样例 |
| 数据接入工程 | 采集、信封、来源识别、解析与失败处理 |
| 标准模型负责人 | ECS/UEBA 字段、事件目录、映射评审和版本治理 |
| 检测工程 | 声明检测所需事件、字段和质量门槛 |
| 实体服务负责人 | 时态关系、冲突消解、置信度和实体版本 |
| 平台工程 | Data Stream、模板、Pipeline、容量和生命周期 |
| 安全运营 | 语义抽检、调查反馈和误映射报告 |

来源接入完成不代表 UEBA 用例完成。只有标准模型负责人确认语义，检测工程确认数据门槛，回放测试确认下游影响后，来源才可以标记为相应用例“Ready”。

### 21. 最终判定原则

统一事件模型是否有效，以以下问题作为最终评审标准：

1. Windows、VPN 和云身份源的登录事件能否被同一认证特征消费，同时保留各自细节？
2. Zeek、防火墙和 EDR 的网络事件是否使用一致的端点与字节方向？
3. 日志缺失用户或设备时，系统是否如实表达未知，而不是伪造实体归属？
4. 任一标准字段能否定位到原始值、转换规则和版本？
5. 来源升级或映射变化时，能否在不污染生产基线的情况下回放比较和回滚？
6. 数据质量下降时，系统能否准确指出哪些检测仍可运行、哪些必须降级或停止？

全部满足后，统一事件层才具备支撑实体发现、基线训练和风险识别的工程条件。

### 参考资料

1. Splunk，[Overview of the Splunk Common Information Model](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)。
2. Splunk，[Use the CIM to normalize data at search time](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time)。
3. Splunk，[Set up the Splunk Common Information Model Add-on](https://help.splunk.com/en/data-management/common-information-model/8.5/introduction/set-up-the-splunk-common-information-model-add-on)。
4. Splunk，[Required sourcetypes for UEBA detections](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections)。
5. Splunk，[Which data sources do I need?](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need)。
6. Elastic，[Elastic Common Schema reference](https://www.elastic.co/docs/reference/ecs)。
7. Elastic，[User fields usage and examples](https://www.elastic.co/docs/reference/ecs/ecs-user-usage)。
8. Elastic，[Error handling for ingest pipelines](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/error-handling)。
9. Elastic，[Simulate data ingestion](https://www.elastic.co/guide/en/elasticsearch/reference/current/simulate-ingest-api.html)。
10. 本地静态证据：`splunk-ueba-调研/Splunk_SA_CIM/default/data/models/*.json`、`Splunk_TA_zeek/default/*.conf`、`Splunk_TA_windows/default/*.conf`。


---

<a id="part-03"></a>

## 第三篇　日志源接入与映射清单

> 本篇来源：[日志源接入与映射清单.md](./日志源接入与映射清单.md)

> 文档状态：首期预研设计稿  
> 编制日期：2026-09-14  
> 上位架构：[UEBA 整体架构预研—Elasticsearch 方案](./UEBA整体架构预研-Elasticsearch方案.md)  
> 数据规范：[统一事件模型规范](./统一事件模型规范.md)  
> 首期范围：Microsoft Windows Security、Zeek、VPN、DHCP；HR/AD/CMDB 作为实体上下文依赖。  
> 目标：给出可以直接转化为采集配置、解析规则、映射注册表和验收用例的首期清单。

### 1. 文档目的

本清单回答五个工程问题：

1. 首期接入哪些日志源、哪些事件，不接哪些事件；
2. 每类源日志如何映射到 ECS 和 `ueba.*` 统一事件字段；
3. 映射结果参考哪个 Splunk CIM Data Model/Dataset；
4. 每类事件能支持哪些实体关系、行为特征和检测；
5. 缺少哪些字段时应降级、隔离或停止相关检测。

本文是接入与映射清单，不重复定义所有公共字段。字段类型、缺失值、角色、证据、版本及质量通则以《统一事件模型规范》为准。

### 2. Splunk 参考结论

Splunk CIM 通过 Data Model、Dataset、字段、Event Type 和 Tag 统一不同厂商日志的语义；Splunk 官方要求根据事件上下文选择模型，不能只因字段名称相同就归入某模型。[Splunk CIM 概述](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[Splunk CIM 归一方法](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time)

本清单采用以下对照：

| 日志行为 | Splunk 参考模型 | Elasticsearch/UEBA 目标 |
|---|---|---|
| 登录、登录失败、注销、Kerberos 票据 | Authentication | `event.category=authentication`，`ueba.event.type=authentication.*` |
| 账号与组变更 | Change | `event.category=iam`，`ueba.event.type=iam.*` |
| 进程创建 | Endpoint.Processes | `event.category=process`，`ueba.event.type=process.start` |
| 网络连接 | Network_Traffic | `event.category=network`，`ueba.event.type=network.connection` |
| DNS 查询和响应 | Network_Resolution | `event.category=network`，`ueba.event.type=dns.*` |
| HTTP 请求 | Web | `event.category=web`，`ueba.event.type=web.request` |
| VPN 与 DHCP 会话 | Network_Sessions | `event.category=session` 或 `network`，`ueba.event.type=session.*` / `address.*` |

Splunk 当前 UEBA 文档列出的主要数据包括 Windows 安全事件、Microsoft 365 活动和 DHCP；本地部署验证来源涉及 Authentication、Network_Traffic、Web、Change、Endpoint 和 Email 等 CIM 模型。[Splunk UEBA 所需 Sourcetype](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections)

Splunk Network Sessions 模型明确覆盖 DHCP 和 VPN，会话动作使用 started、ended、blocked 等语义，并将 DHCP/VPN 分配的内部地址作为客户端获得的地址。[Splunk Network Sessions](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/network-sessions)

本文中的 ECS/UEBA 字段、质量门槛和适配优先级是自研方案，不代表 Splunk 内部实现。

### 3. 首期范围与状态

#### 3.1 UEBA 最小数据组合与支持矩阵

##### 3.1.1 结论

任何单一日志源都不能形成完整、高可信的 UEBA。尤其是 Zeek 的 conn、dns、http 日志通常没有可靠人员账号：

```text
Zeek 事件中的 source.ip
  ≠ 设备稳定身份
  ≠ 当时使用设备的账号
  ≠ 账号背后的自然人
```

Zeek 单独接入时，只能建立 IP、网络端点和会话层面的网络行为基线，能力应标记为 **Network Entity Behavior Analytics**，不得把异常直接归属到用户。要形成用户级 UEBA，必须补齐身份主数据、资产主数据，以及能够在事件时间建立“用户—设备—IP”关系的日志。

Splunk 的公开机制支持这一结论：独立 Splunk UBA 将 HR 与资产数据列为生成高保真异常和威胁的必要数据；认证、DNS、DHCP、VPN 用于持续建立 IP、主机和用户之间的关系。[Splunk UBA 数据源要求](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need) 当前 Splunk Enterprise Security UEBA 同样要求 Asset and Identity Framework 有准确数据，并至少启用一个身份源，才能把发现归到正确用户或资产、进行同伴分组和风险计算。[Splunk ES UEBA 资产与身份配置](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/user-and-entity-behavior-analytics/configure-asset-and-identity-data-for-ueba-in-splunk-enterprise-security)

##### 3.1.2 客户侧必须接入的数据类别

“必须”是能力类别要求，每一类可以选择现场已有的一个或多个权威来源，不要求客户同时部署表中所有产品。

| 类别 | 是否必须 | 客户可提供的来源 | 首期首选 | 解决的问题 | 缺失后的能力边界 |
|---|---:|---|---|---|---|
| 身份与账号主数据 | 必须 | HR、AD/LDAP、Entra ID、Okta、IAM | HR + AD；没有 HR 时至少 AD/IdP | 账号唯一键、账号到人员、账号类型、部门/岗位、在离职状态 | 只能做账号级分析；无法可靠合并一人多账号、建立同伴组或判断离职账号 |
| 资产主数据 | 必须 | CMDB、AD Computer、EDR 资产清单、云资产清单 | CMDB + AD Computer | 设备稳定 ID、资产类型、关键性、共享设备/服务器识别 | 只能做 IP/主机名候选分析；设备复用、重装、同名和共享设备容易误归属 |
| 含用户的认证/会话日志 | 用户级 UEBA 必须 | Windows Security、VPN、IdP/SSO、Linux auth、SaaS 登录 | Windows Security + VPN | 直接观察账号登录、登录结果、来源和目标，建立用户活动基线 | Zeek 等无用户日志无法归到账号；只能保留实体或网络异常 |
| IP—设备时态关系 | 动态地址环境必须 | DHCP、VPN 分配地址、NAC、EDR 网络状态、可靠终端遥测 | DHCP；远程接入补 VPN | 说明某个事件时间的 IP 属于哪台设备 | 当前 IP 查询会污染历史；新旧租约、漫游设备和地址复用无法区分 |
| IP—主机名辅助关系 | 强烈推荐 | DNS、DHCP 主机名、AD DNS、EDR | DNS + DHCP | 提高设备解析覆盖和证据交叉验证 | 不一定阻断 UEBA，但设备解析率和置信度下降 |
| 行为遥测 | 至少一类必须；按用例选 | Zeek、代理、Firewall、EDR、文件审计、邮件、数据库、云审计 | 首期 Zeek conn/dns/http + Windows 4688 | 提供用于建模的真实行为 | 只能做登录行为；不能覆盖网络访问、外传、进程、文件等行为 |
| 安全告警与业务上下文 | 可选增强 | EDR/DLP/IDS 告警、资产关键性、敏感资源目录 | CMDB 关键性，告警后续接入 | 提高风险优先级和调查上下文 | 不影响基础基线，但风险排序和威胁解释较弱 |

##### 3.1.3 首期最低接入基线

本项目若要对外声明“支持用户与实体行为分析”，客户至少应提供以下组合：

| 必接项 | 最低可接受来源 | 首期要求 |
|---|---|---|
| 身份源 | AD/LDAP 或其他企业 IdP；建议叠加 HR | 必须包含稳定账号 ID、域/租户、账号状态；做人员级分析时必须有人—账号关系 |
| 资产源 | CMDB、AD Computer 或 EDR 资产清单之一 | 必须包含稳定设备 ID与主机名；IP/MAC 只能作为关联键之一 |
| 用户活动源 | Windows Security、VPN、IdP/SSO 登录日志之一 | 必须直接包含账号和时间；至少覆盖成功、失败及来源/目标中的一种 |
| 实体关系源 | DHCP、VPN、NAC 或包含可靠账号/设备/IP 同现的终端日志之一 | 动态地址环境必须能生成带有效期的关系 |
| 行为源 | Zeek、EDR、代理、Firewall、文件、邮件、数据库或云审计至少一种 | 根据首期用例选择；本方案首选 Zeek + Windows 4688 |

首期推荐组合为：

```text
HR/AD 身份数据
  + CMDB/AD Computer 资产数据
  + Windows Security 认证日志
  + DHCP 租约日志
  + VPN 会话日志（存在远程办公时）
  + Zeek conn/dns/http 网络行为日志
```

其中 VPN 不是所有环境绝对必接：没有远程接入时可以不接；存在远程接入而不接 VPN 时，无法可靠建立“远程用户—公网 IP—内部分配 IP—会话”的关系。DHCP 也不是所有网络绝对必接：如果终端地址固定，或 EDR/NAC 能提供等价且带有效期的设备—IP 关系，可以替代；必须记录替代来源及其证据质量。

##### 3.1.4 可声明的能力等级

| 等级 | 已接入组合 | 可声明能力 | 禁止声明 |
|---|---|---|---|
| L0 单源事件分析 | 只有 Zeek 或只有 Windows 日志 | 规则检测、单字段统计 | 完整 UEBA |
| L1 网络实体行为 | 资产源 + DHCP/NAC + Zeek | 设备/IP 网络基线、新目的地、DNS/Web 异常 | 用户网络行为、人员风险 |
| L2 账号行为 | 身份源 + Windows/VPN/IdP 认证 | 账号登录时间、来源、失败量和特权认证基线 | 将无用户网络流量归属给人员 |
| L3 用户与设备 UEBA | 身份源 + 资产源 + 认证源 + 时态关系源 | 用户、账号、设备行为和基础风险 | 未接行为源对应的网络/文件/邮件等用例 |
| L4 用例完整 UEBA | L3 + Zeek/EDR/代理/文件/邮件等目标行为源 | 目标用例的跨源行为基线、异常和关联风险 | 未经过数据就绪验收的用例 |

系统必须按租户和用例记录当前能力等级，不能因某个索引中出现 `user.name` 就自动将 L1 提升为 L3。

##### 3.1.5 首期来源实施状态

| 编号 | 日志源 | 首期事件范围 | 映射状态 | 在组合中的角色 |
|---|---|---|---|---|
| CTX-ID | HR/AD | 人员、账号、组织、岗位、状态快照 | 上下文合同已定义 | 必接身份主数据 |
| CTX-ASSET | CMDB/AD Computer | 设备、资产类型、重要性、所有者快照 | 上下文合同已定义 | 必接资产主数据 |
| SRC-WIN-SEC | Windows Security | 4624、4625、4634、4648、4672、4688、账号/组变更、4768、4769、4776 | 可进入实现 | 首选用户认证和端点活动源 |
| SRC-DHCP | DHCP Server | ACK、续租、RELEASE、EXPIRE、NAK | 合同已定义，优先 Microsoft/Infoblox | 动态网络中的 IP—设备时态关系 |
| SRC-VPN | 企业 VPN | 登录成功/失败、会话开始/结束、分配地址 | 合同已定义，厂商适配待定 | 远程用户—公网/内部 IP 会话关系 |
| SRC-ZEEK | Zeek | conn、dns、http | 可进入实现 | 网络行为源；本身不提供可靠用户身份 |

“可进入实现”表示源格式和本地 TA/CIM 证据足以形成首版规则，仍需用客户现场样例验证。“合同已定义，厂商适配待定”表示公共语义已经确定，但不能在没有具体厂商、版本和原始样例时声称解析器已完成。

#### 3.2 暂缓范围

首期暂不纳入：

- Microsoft 365、Google Workspace 等 SaaS 审计；
- Linux auditd、Linux auth；
- 数据库审计；
- 邮件网关和邮件正文；
- DLP、IDS/IPS、EDR 告警；
- 文件完整性与完整端点遥测；
- 云控制面日志；
- Zeek ssl、files、smtp、ssh、notice 等日志；
- 业务应用自定义审计。

暂缓不表示这些日志无价值，而是首期先验证认证、网络和身份时态关系的完整链路。

### 4. 接入总体设计

#### 4.1 数据流

```text
Windows / Zeek / VPN / DHCP
           │
           ▼
采集器：读取、断点、来源元数据
           │
           ▼
Kafka raw.*（规模较小时可以直接进入 Logstash）
           ├──────────────→ 对象存储：原始证据
           │
           ▼
解析器：恢复厂商字段
           │
           ▼
映射器：ECS + ueba.*
           │
           ▼
质量校验：qualified / partial / invalid / unsupported
           │
           ▼
Elasticsearch：logs-ueba-*
           │
           ├──→ 实体解析：账号、设备、IP、会话关系
           └──→ 特征与检测
```

#### 4.2 Data Stream 路由

| 来源/事件 | 目标 Data Stream |
|---|---|
| Windows 登录、注销、票据 | `logs-ueba.authentication-default` |
| Windows 账号与组变更 | `logs-ueba.iam-default` |
| Windows 进程创建 | `logs-ueba.endpoint-default` |
| Zeek conn | `logs-ueba.network-default` |
| Zeek dns | `logs-ueba.dns-default` |
| Zeek http | `logs-ueba.web-default` |
| VPN 会话 | `logs-ueba.session-default` |
| DHCP 租约 | `logs-ueba.session-default` |
| HR/AD/CMDB 快照 | `logs-ueba.context-default`，随后生成实体主档 |
| 无映射来源 | `logs-ueba.unsupported-default` |
| 解析或 Mapping 失败 | Elasticsearch Failure Store 或 `logs-ueba.invalid-default` |

#### 4.3 每条事件共同必填字段

```text
@timestamp
event.id
event.kind
event.category
event.type
event.action
event.outcome（确实有结果语义时）
event.code（来源有事件代码时）
event.dataset
event.ingested
ueba.schema.version
ueba.source.type
ueba.source.namespace
ueba.source.collected_at
ueba.source.received_at
ueba.event.type
ueba.time.source
ueba.time.quality
ueba.provenance.raw_event_id
ueba.provenance.parser_id
ueba.provenance.parser_version
ueba.provenance.mapping_id
ueba.provenance.mapping_version
ueba.quality.status
```

### 5. Windows Security 接入清单

#### 5.1 来源定义

| 项目 | 约定 |
|---|---|
| 来源 ID | `SRC-WIN-SEC` |
| 推荐采集 | Elastic Agent Windows Integration 或 Windows Event Forwarding + Agent/Logstash |
| Channel | `Security`；PowerShell 等其他 Channel 不在本期 |
| 格式 | 优先 XML，保留 EventData 名称和值 |
| `event.dataset` | `microsoft.windows.security` |
| `ueba.source.type` | `windows_security` |
| 原生 ID | `Computer + Channel + EventRecordID` |
| 时间 | XML `System/TimeCreated/@SystemTime` |
| 参考 Splunk | TA-Windows、Authentication、Change、Endpoint |

Splunk Authentication 模型用于任何来源的登录活动，主要字段包括 action、app、src、dest、user、user_id、authentication_method 等；其 `src` 表示认证来源，`dest` 表示认证目标。[Splunk Authentication](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/authentication)

#### 5.2 事件目录

| Event ID | 含义 | 主 `ueba.event.type` | ECS 分类 | 参考 CIM | 首期用途 |
|---:|---|---|---|---|---|
| 4624 | 登录成功 | `authentication.login` | `authentication` / `start` | Authentication | 登录时间、来源、目标、登录类型 |
| 4625 | 登录失败 | `authentication.login` | `authentication` / `start` | Authentication | 失败量、失败原因、暴力尝试特征 |
| 4634 | 会话注销 | `authentication.logout` | `authentication` / `end` | Authentication | 会话结束和时长 |
| 4648 | 使用显式凭据登录 | `authentication.login.explicit_credentials` | `authentication` / `start` | Authentication | 凭据使用、横向移动线索 |
| 4672 | 新登录被赋予特殊权限 | `authentication.privilege_assigned` | `authentication` / `change` | Authentication.Privileged | 特权会话标记 |
| 4688 | 创建新进程 | `process.start` | `process` / `start` | Endpoint.Processes | 进程稀有度、父子关系 |
| 4720 | 创建用户账号 | `iam.account_created` | `iam` / `user,creation` | Change | 账号生命周期 |
| 4722 | 启用用户账号 | `iam.account_enabled` | `iam` / `user,change` | Change | 账号状态变化 |
| 4725 | 禁用用户账号 | `iam.account_disabled` | `iam` / `user,change` | Change | 账号状态变化 |
| 4726 | 删除用户账号 | `iam.account_deleted` | `iam` / `user,deletion` | Change | 账号生命周期 |
| 4728/4732/4756 | 向安全组添加成员 | `iam.group_member_added` | `iam` / `group,change` | Change | 提权、敏感组成员变化 |
| 4729/4733/4757 | 从安全组移除成员 | `iam.group_member_removed` | `iam` / `group,change` | Change | 权限回收 |
| 4768 | 请求 Kerberos TGT | `authentication.ticket_requested.tgt` | `authentication` / `info` | Authentication | TGT 行为与失败基线 |
| 4769 | 请求 Kerberos 服务票据 | `authentication.ticket_requested.service` | `authentication` / `info` | Authentication | 服务访问与横向活动 |
| 4776 | 域控验证凭据 | `authentication.credential_validated` | `authentication` / `info` | Authentication | NTLM 认证行为 |

#### 5.3 Windows 公共字段映射

| Windows XML/Winlog 字段 | 目标字段 | 转换 | 条件与说明 |
|---|---|---|---|
| `System/TimeCreated/@SystemTime` | `@timestamp` | ISO 8601 → UTC | 必须 |
| `System/EventID` | `event.code` | keyword | 必须 |
| `System/EventRecordID` | `ueba.source.native_event_id` | keyword | 与 Computer、Channel 共同形成唯一来源位置 |
| `System/Computer` | `observer.hostname` | 主机名规范化 | 域控代记客户端时，记录者是 observer |
| `System/Provider/@Name` | `event.provider` | 原值 | 推荐 |
| `System/Channel` | `log.logger` | 原值 | 必须为 Security |
| `Keywords` / Level | `log.level` | 枚举映射 | 可选 |
| `TargetUserSid` | `user.id` | SID 原值 | 优先账号稳定 ID |
| `TargetUserName` | `user.name` | 去除域前缀、保留原值 | 必须或条件必填 |
| `TargetDomainName` | `user.domain` | 规范域名 | 与 user.name 组合，不得跨域合并 |
| `IpAddress` | `source.ip` | IP 规范化 | `-`、`::1` 等按真实语义处理 |
| `IpPort` | `source.port` | long | 合法端口才写入 |
| `WorkstationName` | `source.address`、`ueba.source.workstation_name` | 规范化 | 作为来源主机候选，不能无条件当作权威主机实体 |
| `LogonType` | `winlog.logon.type` | keyword/long | 4624/4625 必须 |
| `LogonProcessName` | `winlog.logon.process.name` | 原值 | 推荐 |
| `AuthenticationPackageName` | `winlog.logon.authentication_package` | 原值 | 同时用于认证方法映射 |
| `TargetLogonId` | `winlog.logon.id`、`ueba.session.id` | keyword | 与主机命名空间组合使用 |
| `ProcessId` / `NewProcessId` | `process.pid` | 十六进制/十进制 → long | 按 Event ID 选择 |
| `ProcessName` / `NewProcessName` | `process.executable` | Windows 路径规范化 | 不删除原路径 |
| `CommandLine` | `process.command_line` | 原值，按权限保护 | 4688 条件可用 |
| `SubjectUserSid` | `user.effective.id` 或 `ueba.actor.source_id` | 按事件角色 | IAM 变更时为执行者 |
| `SubjectUserName` | `user.effective.name` 或 `ueba.actor.source_id` | 按事件角色 | 禁止覆盖变更目标账号 |
| `MemberSid` / `MemberName` | `group.*` 或 `ueba.target.*` | 按组事件映射 | 表示被添加/移除成员 |

#### 5.4 4624/4625 认证映射

| 目标字段 | 4624 | 4625 | 要求 |
|---|---|---|---|
| `event.outcome` | `success` | `failure` | 必须 |
| `event.action` | `logged-in` | `logon-failed` | 必须 |
| `event.category` | `authentication` | `authentication` | 必须 |
| `event.type` | `start` | `start` | 必须 |
| `ueba.event.type` | `authentication.login` | `authentication.login` | 用 outcome 区分结果，避免拆成不兼容类型 |
| `ueba.actor.type` | `account` | `account` | 必须 |
| `ueba.actor.source_id` | `domain\\user` 或 SID | 同左 | 至少一种可信标识 |
| `ueba.target.type` | `host` | `host` | 目标为被认证系统 |
| `ueba.target.source_id` | 事件目标主机 | 同左 | 必须 |
| `event.reason` | 可选 | Status/SubStatus 解释 | 失败时推荐 |

登录类型补充语义：

| LogonType | 语义 | `ueba.event.semantic_tags` |
|---:|---|---|
| 2 | Interactive | `interactive` |
| 3 | Network | `network_logon` |
| 4 | Batch | `batch` |
| 5 | Service | `service` |
| 7 | Unlock | `unlock` |
| 8 | NetworkCleartext | `cleartext` |
| 9 | NewCredentials | `new_credentials` |
| 10 | RemoteInteractive | `remote_access` |
| 11 | CachedInteractive | `cached_credentials` |

机器账号名称通常以 `$` 结尾，但不能只依赖字符串规则最终判定账号类型；应由 AD 上下文确认。机器、服务、批处理账号不得进入普通人员同伴组。

#### 5.5 4672 特权事件角色

4672 表示某次新登录被授予特殊权限，不等于用户刚刚完成永久权限变更：

```text
Actor：获得特殊权限的账号
Target：该账号在目标主机上的登录会话
Session：TargetLogonId
Semantic Tag：privileged_activity
```

必须通过 `TargetLogonId + observer/host namespace` 与 4624 会话关联。禁止仅根据 4672 把用户目录角色永久改成管理员。

#### 5.6 账号和组变更角色

对于 4720、4722、4725、4726、4728/29、4732/33、4756/57：

```text
Actor：SubjectUserSid / SubjectUserName（执行变更的人）
Target：TargetSid / TargetUserName 或 MemberSid / MemberName（被变更账号）
Resource：TargetDomainName / GroupName（相关域或组）
Observer：记录事件的域控
```

禁止把 SubjectUserName 和 TargetUserName 都映射到顶层 `user.name` 后丢失角色。顶层 `user.*` 可以保存主要分析对象，但 `ueba.actor`、`ueba.target` 必须同时明确。

#### 5.7 Windows 质量门槛

| 能力 | 必需字段 | 缺失处理 |
|---|---|---|
| 登录时间异常 | `@timestamp`、账号、outcome | 缺时间或账号则 invalid；时间回退则 degraded |
| 登录失败量 | 账号或来源、outcome=failure | 两者均缺则 unavailable |
| 非常用设备登录 | 账号、可信目标设备 | 设备不可识别则 unavailable |
| 非常用来源登录 | 账号、`source.ip` | IP 缺失则 unavailable |
| 特权会话 | 4672 账号、LogonId、目标主机 | 无法关联 4624 时 partial |
| 新进程行为 | host、process.executable、时间 | 缺进程路径则 partial/unavailable |
| 敏感组变化 | actor、target/member、group | 任一核心角色缺失则 partial，不生成高置信风险 |

### 6. Zeek 接入清单

#### 6.1 来源定义

| 项目 | 约定 |
|---|---|
| 来源 ID | `SRC-ZEEK` |
| 首期日志 | `conn.log`、`dns.log`、`http.log` |
| 格式 | 优先 Zeek JSON；TSV 作为兼容输入 |
| 采集 | Filebeat/Elastic Agent 或 Vector/Logstash，必须保存 sensor 与 path |
| `event.dataset` | `zeek.zeek.conn`、`zeek.zeek.dns`、`zeek.zeek.http` |
| `ueba.source.namespace` | `tenant + sensor_id` |
| 原生关联键 | `uid`，但不能单独视为跨传感器全局唯一 ID |
| 参考 Splunk | TA-Zeek、Network_Traffic、Network_Resolution、Web |

仓库中的 TA-Zeek 将 `id_orig_h/id_orig_p` 映射为源端，将 `id_resp_h/id_resp_p` 映射为目的端；将 `orig_ip_bytes/resp_ip_bytes` 映射为出/入字节并求总量。本清单沿用发起端/响应端方向，转换为 ECS source/destination 语义。

#### 6.2 Zeek 公共字段映射

| Zeek 字段 | 目标字段 | 转换与说明 |
|---|---|---|
| `ts` | `@timestamp` | epoch 秒 → UTC date |
| `uid` | `ueba.session.id`、`ueba.source.native_event_id` | 与 sensor namespace 组合形成稳定会话键 |
| `id.orig_h` / `id_orig_h` | `source.ip` | 连接发起端 |
| `id.orig_p` / `id_orig_p` | `source.port` | long |
| `id.resp_h` / `id_resp_h` | `destination.ip` | 连接响应端 |
| `id.resp_p` / `id_resp_p` | `destination.port` | long |
| `proto` | `network.transport` | 小写；ICMPv6 单独规范 |
| `service` | `network.protocol` | 小写；未知时不伪造 |
| `local_orig` / `local_resp` | `network.direction` | 使用版本化受管网段复核 |
| sensor/system name | `observer.name`、`observer.id` | 必须可区分多个传感器 |

#### 6.3 conn.log 映射

| Zeek conn 字段 | 目标字段 | 必填性 | 说明 |
|---|---|---|---|
| `uid` | `ueba.session.id` | 必须 | 与 dns/http 等日志关联 |
| `duration` | `event.duration` | 推荐 | 秒转换为纳秒 |
| `orig_ip_bytes` | `source.bytes` | 推荐 | 发起端发送的 IP 字节 |
| `resp_ip_bytes` | `destination.bytes` | 推荐 | 响应端发送的 IP 字节 |
| `orig_pkts` | `source.packets` | 推荐 | 发起端包数 |
| `resp_pkts` | `destination.packets` | 推荐 | 响应端包数 |
| 两端 bytes | `network.bytes` | 派生 | 仅双方均为有效数值时求和 |
| 两端 packets | `network.packets` | 派生 | 仅双方均为有效数值时求和 |
| `conn_state` | `event.outcome`、`vendor.zeek.conn_state` | 必须 | 原值保留；映射表需版本化 |
| `history` | `vendor.zeek.history` | 可选 | 不展开为动态字段 |
| `orig_l2_addr` | `source.mac` | 可选 | MAC 规范化 |
| `resp_l2_addr` | `destination.mac` | 可选 | MAC 规范化 |
| `missed_bytes` | `vendor.zeek.missed_bytes` | 推荐 | 大于零时降低流量完整性质量 |

固定分类：

```json
{
  "event.kind": "event",
  "event.category": ["network"],
  "event.type": ["connection"],
  "event.action": "network-connection",
  "ueba.event.type": "network.connection"
}
```

`conn_state` 到 `event.outcome` 的映射不能简单把非 `SF` 都视为 failure。状态用于描述连接观察结果，需保留原值，并按具体检测定义“建立”“拒绝”“重置”“不完整”。

#### 6.4 dns.log 映射

Splunk Network Resolution 模型以 network/resolution/dns Tag 识别 DNS，重点字段包括查询名、记录类型、回复码、源/目的端、事务 ID 和传输协议。[Splunk Network Resolution](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-resolution-dns)

| Zeek DNS 字段 | 目标字段 | 必填性 | 说明 |
|---|---|---|---|
| `uid` | `ueba.session.id` | 推荐 | 关联 conn/http |
| `trans_id` | `dns.id`、`transaction.id` | 推荐 | DNS 事务标识 |
| `query` | `dns.question.name` | 必须 | 规范化副本与原值均保留 |
| `qtype_name` | `dns.question.type` | 推荐 | A、AAAA、MX、TXT 等 |
| `qtype` | `vendor.zeek.qtype` | 可选 | 数值原值 |
| `rcode_name` | `dns.response_code` | 推荐 | 使用 ECS/本地枚举映射 |
| `rcode` | `vendor.zeek.rcode` | 可选 | 数值原值 |
| `answers` | `dns.answers.data` | 条件必填 | 多值数组；按类型生成 answer 对象更佳 |
| `TTLs` | `dns.answers.ttl` | 可选 | 与 answers 的位置关系必须保持 |
| `rtt` | `event.duration` | 可选 | 秒转纳秒，语义为响应时间 |
| `rejected` | `event.outcome` | 推荐 | 结合 rcode 判断，不能单字段覆盖真实返回码 |

分类规则：

| 条件 | `ueba.event.type` | `event.type` |
|---|---|---|
| 有 query、无响应字段且来源明确为请求 | `dns.query` | `protocol` |
| 有 rcode 或 answers | `dns.response` | `protocol` |
| 同一 Zeek 记录同时包含查询和响应 | `dns.response` | `protocol`，保留 question 与 answer |

Zeek 通常将一次 DNS 事务记录为包含问题和响应信息的一条日志。禁止为了形式统一强制拆为两个事件，除非实际来源明确提供两个独立消息且拆分规则可幂等重放。

#### 6.5 http.log 映射

Splunk Web 模型描述 Web Server/Proxy 活动，字段包括 action、bytes、bytes_in/out、src、dest、HTTP 方法、状态、URL 等。[Splunk Web](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/web)

| Zeek HTTP 字段 | 目标字段 | 必填性 | 说明 |
|---|---|---|---|
| `uid` | `ueba.session.id` | 必须 | 关联 conn |
| `method` | `http.request.method` | 必须 | 规范大写 |
| `host` | `url.domain` | 推荐 | 注意与传感器 host 区分 |
| `uri` | `url.original` | 推荐 | 原值保留，解析 path/query |
| `referrer` | `http.request.referrer` | 可选 | 可能含敏感查询参数 |
| `user_agent` | `user_agent.original` | 可选 | 可供稀有度特征使用 |
| `request_body_len` | `http.request.body.bytes`、`source.bytes` 的应用层候选 | 推荐 | 不与 conn IP bytes 混加 |
| `response_body_len` | `http.response.body.bytes`、`destination.bytes` 的应用层候选 | 推荐 | 不与 conn IP bytes 混加 |
| `status_code` | `http.response.status_code` | 推荐 | long |
| `status_msg` | `event.reason` | 可选 | 原值 |
| `username` | `user.name` | 可选 | 仅表示 HTTP 来源明确提供的账号，不能由 IP 猜测 |
| `resp_fuids` | `related.hash` 或 `file.id` 扩展 | 可选 | 多文件时保留数组和关联 |
| `orig_fuids` | 上传文件关联 | 可选 | 有值时可附 `web.upload` 标签 |

固定主分类为 `ueba.event.type=web.request`。只有在方法、正文长度、文件关联或来源语义足以证明上传/下载时，才增加 `upload` 或 `download` 语义标签，禁止仅凭流量方向直接认定文件外传。

#### 6.6 Zeek 质量门槛

| 能力 | 必需字段 | 降级条件 |
|---|---|---|
| 网络连接基线 | 时间、uid、source.ip、destination.ip、端口或协议 | missed_bytes>0 降低流量完整性 |
| 上传/下载流量基线 | 两端字节方向明确 | 仅有 network.bytes 时不可区分方向 |
| 新目的地 | source/目标实体、destination.ip | NAT/代理语义不清时只分析设备或 IP |
| DNS 稀有域名 | query、时间、来源端 | 来源端缺失则不能归属实体 |
| HTTP 稀有 URL/UA | URL/UA、来源端或已解析用户 | 明文不可见或字段缺失时 unavailable |
| 用户网络行为 | 可靠的时态身份关系 | 禁止从 IP 永久静态推断用户 |

### 7. VPN 接入合同

#### 7.1 边界

VPN 首期定义厂商无关合同，但正式 Parser 必须绑定具体厂商、产品版本和日志类型。以下字段名使用语义名称，不能直接假设任一厂商原字段与其相同。

首期要求至少支持：

| 事件 | `ueba.event.type` | 说明 |
|---|---|---|
| 登录成功/会话建立 | `session.vpn_started` | 建立用户、外部来源、内部地址与设备关系 |
| 登录失败/会话被拒 | `session.vpn_blocked` | 支持失败和来源基线 |
| 会话正常/异常结束 | `session.vpn_ended` | 关闭关系有效期并计算时长 |

#### 7.2 VPN 语义字段映射

| 来源语义 | 目标字段 | 必填性 | 说明 |
|---|---|---|---|
| Event time | `@timestamp` | 必须 | 需明确设备时区 |
| Native event/session ID | `event.code`、`ueba.session.id` | 会话 ID 推荐 | 开始/结束关联 |
| Username | `user.name` | 必须 | 同时采集域/租户 |
| User ID | `user.id` | 推荐 | 稳定 ID 优先 |
| Domain/realm | `user.domain` | 条件必填 | 避免同名账号合并 |
| Public client IP | `source.ip` | 推荐 | 用户接入前的公网来源 |
| Assigned internal IP | `client.ip`、`ueba.session.assigned_ip` | 成功会话必填 | 不要覆盖公网 source.ip |
| Client hostname/device ID | `client.address`、`device.id` 或扩展 | 推荐 | 主机名作为候选地址，按厂商可信度标记 |
| VPN gateway | `observer.*` | 必须 | 记录日志的网关 |
| Authentication method | `ueba.authentication.method` | 推荐 | Password、Certificate、MFA 等受控值，并保留厂商原值 |
| Result/reason | `event.outcome`、`event.reason` | 必须 | success/failure/unknown |
| Session duration | `event.duration` | 结束事件推荐 | 转为纳秒 |
| Bytes sent/received | `source.bytes`、`destination.bytes` 或会话扩展 | 可选 | 必须先确认厂商方向定义 |

#### 7.3 VPN 实体关系输出

会话建立后向实体解析层提供：

```text
账号 --使用--> VPN 会话
VPN 会话 --来自--> 公网 source.ip
VPN 会话 --获得--> assigned internal IP
VPN 会话 --声明设备--> hostname/device ID
```

每条关系包含：

```text
valid_from = 会话开始时间
valid_to = 会话结束时间或超时上限
evidence_event_id
source_namespace
confidence
```

VPN 结束事件找不到开始事件时仍应保存为 `partial`，不能凭结束时间倒推完整会话。并发会话必须按 session ID 区分。

#### 7.4 VPN 适配准入

取得具体厂商后，必须补充：

- 厂商、产品、版本和日志类型；
- 成功、失败、开始、结束原始样例各不少于 20 条；
- 时区和设备时钟说明；
- 用户、会话 ID、外部 IP、内部 IP 的字段说明；
- 断线、超时、重连和并发会话语义；
- 字节方向说明；
- 敏感字段及脱敏要求；
- 现场回放和会话配对结果。

在上述材料完成前，VPN 状态保持“合同已定义，厂商适配待定”。

### 8. DHCP 接入合同

#### 8.1 事件目录

| DHCP 语义 | 典型签名 | `ueba.event.type` | `event.outcome` |
|---|---|---|---|
| 租约分配/确认 | DHCPACK、ACK | `address.lease_started` | `success` |
| 租约续租 | RENEW/ACK | `address.lease_renewed` | `success` |
| 客户端释放 | DHCPRELEASE、RELEASE | `address.lease_ended` | `success` |
| 租约到期 | EXPIRE | `address.lease_ended` | `success` |
| 请求拒绝 | DHCPNAK、NAK | `address.lease_blocked` | `failure` |

Splunk UBA 使用 DHCP 新建、续租和释放记录建立 IP 到 MAC、IP 到主机名的映射；缺少 DNS 等来源不会完全阻止身份解析，但会影响实体映射准确性。[Splunk UBA 数据源要求](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need)

#### 8.2 DHCP 字段映射

| 来源语义 | 目标字段 | 必填性 | 说明 |
|---|---|---|---|
| Event time | `@timestamp` | 必须 | 服务器时区必须明确 |
| Signature/event type | `event.action`、`event.code` | 必须 | 保留 DHCPACK/RELEASE 等原值 |
| Leased IP | `client.ip`、`ueba.session.assigned_ip` | 必须 | 租给客户端的地址 |
| Client MAC | `client.mac` 或扩展设备 MAC | 必须或强推荐 | 小写、冒号分隔 |
| Client hostname | `client.address`、`vendor.dhcp.client_hostname` | 推荐 | 来源声明，不直接成为权威资产 ID |
| DHCP server | `observer.*` | 必须 | 服务器/采集实例 |
| Lease duration | `ueba.session.lease_duration_seconds` | 开始/续租推荐 | 保留秒，同时可计算 valid_to |
| Lease scope | `ueba.session.lease_scope` | 推荐 | Splunk CIM 将其列为 DHCP Dataset 关键字段 |
| Transaction ID | `transaction.id` | 可选 | 来源提供时保存 |
| User | `user.*` | 通常省略 | 未认证 DHCP 禁止由主机名猜用户 |

#### 8.3 DHCP 实体关系输出

```text
MAC/设备候选 --获得--> leased IP
主机名候选 --声明于--> DHCP 会话
DHCP Server --观察--> 租约事件
```

关系有效区间：

```text
ACK:     [event_time, event_time + lease_duration)
RENEW:   更新对应租约版本，不覆盖历史记录
RELEASE: 将匹配租约 valid_to 收敛到 release time
EXPIRE:  valid_to = expire time
NAK:     不创建 IP—设备有效关系
```

同一 IP 在不同时间分配给不同 MAC 时必须保留两段关系。禁止用当前租约表覆盖历史归属。

#### 8.4 DHCP 质量门槛

| 条件 | 状态 |
|---|---|
| 时间、租约 IP、MAC、动作均有效 | `qualified` |
| MAC 缺失但有可信 Client ID/主机名 | `partial`，不能生成高置信设备关系 |
| 租约 IP 缺失或无效 | `invalid` |
| 动作未知 | `unsupported`，保留原值 |
| 租期缺失 | `partial`，使用受控最大有效期并标明推断 |
| 服务器时区未知 | `partial` 或 `invalid`，取决于是否可从采集器可靠补足 |

### 9. HR、AD 与 CMDB 上下文清单

#### 9.1 定位

HR、AD 和 CMDB 是实体主数据，不作为普通行为日志参与行为计数。Splunk UBA 使用 HR 数据识别账号并关联人员，使用资产数据跟踪设备；本项目保持相同的职责分离。

#### 9.2 人员和账号字段

| 来源字段语义 | 目标上下文字段 | 必填性 |
|---|---|---|
| Employee ID | `person.id`（自研实体索引） | 必须且稳定 |
| Display name | `person.name` | 推荐 |
| Account object ID/SID | `account.id` | 必须，优先稳定目录 ID |
| Account name | `account.name` | 必须 |
| Domain/tenant | `account.domain` | 必须 |
| Email/UPN | `account.email` | 推荐 |
| Department | `person.department` | 推荐 |
| Position/role | `person.job_role` | 推荐 |
| Manager ID | `person.manager_id` | 可选 |
| Employment status | `person.status` | 必须 |
| Effective from/to | `valid_from` / `valid_to` | 必须 |
| Privileged/service/machine type | `account.type` | 推荐 |

#### 9.3 资产字段

| 来源字段语义 | 目标上下文字段 | 必填性 |
|---|---|---|
| CMDB/Cloud asset ID | `asset.id` | 必须且稳定 |
| Hostname/FQDN | `host.hostname` / `host.domain` | 必须至少一种 |
| Device type | `asset.type` | 必须 |
| Criticality | `asset.criticality` | 推荐 |
| Owner/business unit | `asset.owner` / `asset.business_unit` | 推荐 |
| Shared device flag | `asset.shared` | 推荐 |
| IP/MAC | 历史关系候选 | 推荐，不覆盖 DHCP 时态事实 |
| Effective from/to | `valid_from` / `valid_to` | 必须 |

快照必须带生效时间。当前 HR/CMDB 值不能直接覆盖历史事件时刻的部门、岗位、账号状态或资产重要性。

### 10. 统一映射注册表清单

首期至少创建以下映射 ID：

| Mapping ID | 来源选择条件 | 版本起点 |
|---|---|---|
| `windows_security_4624` | Security + EventID 4624 | `1.0.0` |
| `windows_security_4625` | Security + EventID 4625 | `1.0.0` |
| `windows_security_4634` | Security + EventID 4634 | `1.0.0` |
| `windows_security_4648` | Security + EventID 4648 | `1.0.0` |
| `windows_security_4672` | Security + EventID 4672 | `1.0.0` |
| `windows_security_4688` | Security + EventID 4688 | `1.0.0` |
| `windows_security_account_change` | 4720/22/25/26 | `1.0.0` |
| `windows_security_group_member_change` | 4728/29/32/33/56/57 | `1.0.0` |
| `windows_security_4768` | Security + EventID 4768 | `1.0.0` |
| `windows_security_4769` | Security + EventID 4769 | `1.0.0` |
| `windows_security_4776` | Security + EventID 4776 | `1.0.0` |
| `zeek_conn_json` | Zeek JSON + `_path=conn` | `1.0.0` |
| `zeek_dns_json` | Zeek JSON + `_path=dns` | `1.0.0` |
| `zeek_http_json` | Zeek JSON + `_path=http` | `1.0.0` |
| `vpn_<vendor>_session` | 待具体厂商确定 | 待定 |
| `dhcp_microsoft` | Microsoft DHCP 日志 | `1.0.0` |
| `dhcp_infoblox` | Infoblox DHCP 日志 | `1.0.0`，取得样例后实施 |
| `context_hr_snapshot` | HR 全量/增量快照 | `1.0.0` |
| `context_ad_account_snapshot` | AD Account/Group 快照 | `1.0.0` |
| `context_cmdb_asset_snapshot` | CMDB 资产快照 | `1.0.0` |

每个映射必须单独保存：负责人、来源版本、匹配条件、字段规则、枚举表、质量合同、测试样例、发布状态和依赖的 UEBA 用例。

### 11. 检测与数据源依赖

下表中的“Zeek 必需”只表示该网络行为用例需要 Zeek 证据，不表示 Zeek 可以独立完成用户归属。凡检测输出对象为“用户/人员”，除行为源外还必须满足：

```text
身份源 Ready
  + 资产源 Ready
  + 用户活动源 Ready
  + 行为发生时刻的用户—设备—IP 关系达到规定置信度
```

关系条件不满足时，同一检测最多输出 IP/设备异常，不得写入人员风险。

| 首期用例 | Windows | Zeek | VPN | DHCP | HR/AD | CMDB |
|---|---:|---:|---:|---:|---:|---:|
| 异常登录时间 | 必需 | — | 可选 | — | 推荐 | — |
| 登录失败量异常 | 必需或 VPN | — | 可替代 | — | 推荐 | — |
| 非常用登录来源 | 必需或 VPN | — | 推荐 | — | 推荐 | — |
| 非常用设备登录 | 必需 | — | 推荐 | 推荐 | 必需 | 推荐 |
| 特权账号异常登录 | 必需 | — | 可选 | — | 必需 | 推荐 |
| 新外部目的地 | 认证归属可选 | 必需行为源 | 远程归属可选 | 设备归属必需或由等价源替代 | 用户输出必需 | 设备输出必需 |
| 异常外发字节量 | 认证归属可选 | 必需行为源 | 远程归属可选 | 设备归属必需或由等价源替代 | 用户输出必需 | 设备输出必需 |
| 稀有 DNS 域名 | 认证归属可选 | 必需行为源 | 远程归属可选 | 设备归属必需或由等价源替代 | 用户输出必需 | 设备输出必需 |
| 罕见 HTTP User-Agent/URL | 认证归属可选 | 必需行为源 | 远程归属可选 | 设备归属必需或由等价源替代 | 用户输出必需 | 设备输出必需 |
| 新进程或罕见进程 | 必需 4688 | — | — | — | 推荐 | 必需 |
| 敏感组成员变化 | 必需 | — | — | — | 必需 | — |

“必需”表示该用例在当前首期方案中的主要证据来源；“用户输出必需”表示只有接入并验证该上下文后才允许把结果归到用户；“可替代”表示不同环境可以选择另一种等价来源，替代关系必须经过时态准确率验收。

### 12. 采集与映射验收清单

#### 12.1 每个日志源上线前

- [ ] 已确认厂商、产品、版本、日志类型和格式；
- [ ] 已记录时区、时钟同步和时间字段；
- [ ] 已确认原生事件 ID、文件位置或消息 Offset；
- [ ] 已收集正常、失败、缺字段、未知枚举和版本差异样例；
- [ ] 已定义 `event.dataset`、`ueba.source.type` 和 namespace；
- [ ] 已创建 Mapping ID 和初始版本；
- [ ] 已建立原始证据归档和回查路径；
- [ ] 已完成 ECS 类型、方向、单位和角色评审；
- [ ] 已建立 qualified/partial/invalid/unsupported 判定；
- [ ] 已声明下游检测所需字段和降级规则；
- [ ] 已进行 Pipeline 模拟、历史回放和重复事件测试；
- [ ] 已进行峰值吞吐与 Failure Store 测试；
- [ ] 已配置接收量、解析率、字段覆盖、延迟和未知事件监控。

#### 12.2 最小样例数量

首期建议每个事件类型至少准备：

| 样例类型 | 数量建议 |
|---|---:|
| 正常真实样例 | 20 条 |
| 失败/拒绝样例 | 10 条，若事件有失败语义 |
| 关键字段缺失 | 每种缺失场景 3 条 |
| 产品版本差异 | 每版本 10 条 |
| 边界账号/设备 | 机器、服务、共享、未知各 5 条 |
| 时间边界 | 时区、夏令时、迟到、乱序各 3 条 |
| 重复与重放 | 至少 1000 条批量测试 |

数量是首期工程建议，不是 Splunk 官方要求。样例覆盖比简单达到数量更重要。

#### 12.3 运行指标

| 指标 | 分组维度 |
|---|---|
| 入口事件数 | tenant/source/dataset/version |
| 原始归档成功数 | source/hour |
| 解析成功率 | parser/version/event.code |
| qualified/partial/invalid/unsupported 比例 | mapping/version |
| 关键字段覆盖率 | event type/field |
| 时间回退率 | source/observer |
| 重复率 | raw 和 normalized 两层 |
| P95/P99 处理延迟 | source/pipeline |
| Failure Store 增量 | failure type/pipeline |
| 检测就绪率 | use case/source |

### 13. 首期实施顺序

建议按以下顺序推进：

1. 固化《统一事件模型规范》对应版本和 Elasticsearch 组件模板；
2. 接入 HR/AD 身份与账号快照，验证账号键、人员归属和同伴组字段；
3. 接入 CMDB/AD Computer 资产快照，验证设备键、资产类型和共享设备标志；
4. 接入 Windows 4624/4625/4634，打通认证成功、失败和会话；
5. 接入 DHCP；存在远程办公时同时接入具体 VPN 产品，建立时态 IP 关系；
6. 先计算用户—设备—IP 关系覆盖率和准确率，未达门槛前不开放用户网络行为检测；
7. 接入 Zeek conn，验证设备网络行为与字节方向；
8. 接入 Zeek dns/http，补足域名和 Web 行为；
9. 增加 Windows 4672、4688 和账号/组变更；
10. 对所有映射执行历史回放和影子发布；
11. 分别以“账号异常登录、设备新目的地、用户新目的地、用户异常外发字节量”验收账号、设备和用户三个层次。

首期完成标准：

```text
身份、资产、认证、时态关系和目标行为源均达到 Ready
  + 不依赖单一 IP 当前值进行历史用户归属
  + 不可归属的 Zeek 事件保留为 IP/设备行为
  + 不同来源的事件能够稳定进入统一 Data Stream
  + 标准字段可追溯到原始证据
  + 账号/IP/设备关系按事件时间解析
  + 四个首期用例具备明确的数据就绪状态
  + 映射升级可以回放、比较和回滚
```

### 14. 风险与未决项

| 风险/未决项 | 影响 | 处理要求 |
|---|---|---|
| VPN 厂商和版本未确定 | 无法编写真实 Parser | 取得样例后创建专用 Mapping，不使用猜测字段 |
| DHCP 产品未确定 | 日志动作与字段不同 | 优先选现场主要 DHCP，Microsoft/Infoblox 分开适配 |
| Windows 采集格式不统一 | XML 与 Rendered Text 字段差异 | 首期锁定 XML，其他格式单独映射 |
| Zeek JSON/TSV 混用 | 类型和数组表达不同 | 建立独立 Parser，统一到同一 Mapping 合同 |
| 内部网段定义不完整 | network.direction 错误 | 建立版本化网段注册表，方向不足时写 unknown |
| NAT、代理、共享设备 | 用户归属误判 | 实体层保留候选、置信度和排除清单 |
| 将 Zeek IP 直接当作用户 | 网络异常错误写入人员风险 | 用户输出前强制检查时态关系、证据来源和置信度；不足时只输出 IP/设备异常 |
| 现场日志缺少关键字段 | 检测无法运行 | 以 capability 标记 unavailable，不填默认值 |
| 高吞吐 Zeek 数据 | Pipeline/存储压力 | 先压测 conn 峰值，按生命周期和字段索引需求裁剪 |

### 参考资料

1. Splunk，[Overview of the Splunk Common Information Model](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)。
2. Splunk，[Use the CIM to normalize data at search time](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.0/using-the-common-information-model/use-the-cim-to-normalize-data-at-search-time)。
3. Splunk，[Authentication data model](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/authentication)。
4. Splunk，[Network Traffic data model](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-traffic)。
5. Splunk，[Network Resolution data model](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-resolution-dns)。
6. Splunk，[Web data model](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/web)。
7. Splunk，[Network Sessions data model](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/network-sessions)。
8. Splunk，[Required sourcetypes for UEBA detections](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections)。
9. Splunk，[Which data sources do I need?](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.4/introduction/which-data-sources-do-i-need)。
10. Elastic，[Elastic Common Schema reference](https://www.elastic.co/docs/reference/ecs)。
11. 本地静态证据：`splunk-ueba-调研/Splunk_SA_CIM/default/data/models/*.json`、`Splunk_TA_windows/default/*.conf`、`Splunk_TA_zeek/default/*.conf`。


---

<a id="part-04"></a>

## 第四篇　CIM—ECS—UEBA 语义对照表

> 本篇来源：[CIM—ECS—UEBA语义对照表.md](./CIM—ECS—UEBA语义对照表.md)

> 版本：1.0.0  
> 范围：Windows Security、Zeek conn/dns/http、VPN、DHCP、HR/AD/CMDB  
> 上位文档：[统一事件模型规范](./统一事件模型规范.md)、[日志源接入与映射清单](./日志源接入与映射清单.md)

### 1. 对照原则

Splunk CIM 是以 Data Model、Dataset、字段和 Tag 组织的搜索时共享语义模型；ECS 是 Elasticsearch 中的公共字段和类型规范；`ueba.*` 是本项目为行为语义、实体角色、质量和可追溯性增加的扩展。三者不能按字段名机械一一替换。

```text
Splunk CIM：事件属于什么分析领域、应具有哪些公共字段
ECS：       在 Elasticsearch 中如何存储通用事实
UEBA 扩展： 该事实对行为分析是什么角色、质量如何、源自哪版规则
```

参考：[Splunk CIM](https://help.splunk.com/en/splunk-enterprise/common-information-model/6.1/introduction/overview-of-the-splunk-common-information-model)、[Elastic ECS](https://www.elastic.co/docs/reference/ecs)。

### 2. 模型级对照

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

### 3. 公共字段对照

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

### 4. 事件分类值对照

| Splunk 表达 | ECS 表达 | UEBA 表达 | 说明 |
|---|---|---|---|
| `tag=authentication action=success` | category authentication + outcome success | `authentication.login` | 成功/失败由 outcome 区分 |
| `tag=authentication tag=privileged` | authentication + change/info | `authentication.privilege_assigned` | 会话特权，不等于目录永久提权 |
| `tag=network tag=communicate` | network + connection | `network.connection` | Zeek conn |
| `tag=network tag=dns tag=resolution` | network + protocol | `dns.query` / `dns.response` | Zeek 一条事务可保留问答两侧 |
| `tag=web` | web + access/protocol | `web.request` | 上传下载作为有证据的附加语义 |
| `tag=network tag=session tag=vpn tag=start` | session + start | `session.vpn_started` | 创建时态会话关系 |
| `tag=network tag=session tag=dhcp tag=end` | network/session + end | `address.lease_ended` | 收敛租约有效期 |

### 5. 无法直接对照的内容

下列内容必须由自研模型承担：

- CIM Dataset Constraint 对应的来源选择和分类规则；
- Splunk 搜索时 Lookup 对应的版本化字典和 Enrich；
- `ueba.actor/target/resource/session` 行为角色；
- `ueba.quality` 与检测就绪条件；
- 原始证据 URI、Offset、Hash 和 Parser/Mapping 版本；
- 时态实体关系、候选、置信度和排除规则；
- 映射重放、影子运行和版本切换。

### 6. 审核规则

新增或修改映射时必须同时审核：

1. Splunk CIM 参考模型和 Dataset 是否与行为上下文一致；
2. ECS 字段是否保持官方含义和数据类型；
3. 是否需要 UEBA 角色或质量扩展；
4. 字节、包、持续时间的方向和单位是否明确；
5. 来源没有用户时是否错误写入人员实体；
6. 能否通过 Mapping ID 和版本追溯转换依据。

### 参考资料

- [Splunk Authentication](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/authentication)
- [Splunk Network Traffic](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-traffic)
- [Splunk Network Resolution](https://help.splunk.com/en/splunk-cloud-platform/common-information-model/8.5/data-models/network-resolution-dns)
- [Splunk Web](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/web)
- [Splunk Network Sessions](https://help.splunk.com/en/data-management/common-information-model/8.5/data-models/network-sessions)
- 本地 CIM 8.7.0 与 TA 配置：`splunk-ueba-调研/Splunk_SA_CIM`、`Splunk_TA_windows`、`Splunk_TA_zeek`


---

<a id="part-05"></a>

## 第五篇　事件类型目录

> 本篇来源：[事件类型目录.md](./事件类型目录.md)

> 目录版本：1.0.0  
> 字段：`ueba.event.type`  
> 命名：`<domain>.<activity>[.<subtype>]`  
> 首期来源：Windows、Zeek、VPN、DHCP、HR/AD/CMDB

### 1. 使用规则

- 每条标准事件只能有一个主 `ueba.event.type`；
- 成功与失败优先使用 `event.outcome` 区分，不重复创建两个不兼容主类型；
- 附加语义写入 `ueba.event.semantic_tags`；
- 类型必须来自本目录，接入方不能自由生成；
- 新增类型必须提供语义、选择条件、必填字段、反例、样例和检测消费者；
- 标记“实体关系输入”的事件进入关系服务，不代表关系已被解析成功。

### 2. 认证事件

| 类型 | 语义 | 首期来源 | 必填业务字段 | 角色 | 检测用途 |
|---|---|---|---|---|---|
| `authentication.login` | 一次登录尝试 | Win 4624/4625 | 时间、账号、outcome、目标；远程场景需来源 | Actor=账号，Target=系统/主机 | 登录时间、失败量、新来源、新目标 |
| `authentication.logout` | 认证会话结束 | Win 4634 | 时间、Session ID、目标主机 | Actor=账号候选，Session=登录会话 | 会话时长、异常断开 |
| `authentication.login.explicit_credentials` | 使用显式凭据发起登录 | Win 4648 | 发起账号、目标账号/服务、目标主机 | Actor=发起账号，Target=被用凭据/系统 | 凭据滥用、横向移动线索 |
| `authentication.privilege_assigned` | 新登录会话获得特殊权限 | Win 4672 | 账号、Logon ID、目标主机 | Actor=账号，Session=登录会话 | 特权会话标记 |
| `authentication.ticket_requested.tgt` | 请求 Kerberos TGT | Win 4768 | 账号、域、结果、服务 | Actor=账号，Target=KDC | TGT 失败量、加密类型变化 |
| `authentication.ticket_requested.service` | 请求 Kerberos 服务票据 | Win 4769 | 账号、服务、结果 | Actor=账号，Target=服务 | 新服务访问、票据异常 |
| `authentication.credential_validated` | 域控验证凭据 | Win 4776 | 账号、结果、来源候选 | Actor=账号，Observer=域控 | NTLM 行为和失败量 |

样例：

```json
{
  "event": {"category":["authentication"],"type":["start"],"outcome":"success","code":"4624"},
  "user": {"id":"S-1-5-21-...","name":"zhangsan","domain":"CORP"},
  "source": {"ip":"10.10.1.25"},
  "host": {"hostname":"SRV-01"},
  "ueba": {"event":{"type":"authentication.login"}}
}
```

### 3. IAM 事件

| 类型 | 语义 | 来源 | 必填业务字段 | 检测用途 |
|---|---|---|---|---|
| `iam.account_created` | 创建账号 | 4720 | Actor、Target 账号、域、时间 | 异常创建、非工作时间创建 |
| `iam.account_enabled` | 启用账号 | 4722 | Actor、Target、时间 | 闲置/禁用账号恢复 |
| `iam.account_disabled` | 禁用账号 | 4725 | Actor、Target、时间 | 生命周期审计 |
| `iam.account_deleted` | 删除账号 | 4726 | Actor、Target、时间 | 生命周期审计 |
| `iam.group_member_added` | 向组添加成员 | 4728/4732/4756 | Actor、成员、组、时间 | 敏感组提权 |
| `iam.group_member_removed` | 从组移除成员 | 4729/4733/4757 | Actor、成员、组、时间 | 权限回收异常 |

Actor 是执行变更者，Target 是被变更账号或成员，Resource 是组/域。禁止将两者折叠成一个 `user.name`。

### 4. 进程事件

| 类型 | 语义 | 来源 | 必填业务字段 | 检测用途 |
|---|---|---|---|---|
| `process.start` | 操作系统创建进程 | Win 4688 | 时间、主机、process.executable；可用时加用户和父进程 | 新进程、罕见命令、用户—进程基线 |

命令行缺失时事件可以为 partial，但不能用进程路径代替命令行。

### 5. 网络、DNS 与 Web 事件

| 类型 | 语义 | 来源 | 必填业务字段 | 检测用途 |
|---|---|---|---|---|
| `network.connection` | 发起端和响应端之间的一次连接/流 | Zeek conn | 时间、UID、两端 IP、端口或协议 | 新目的地、端口、流量、连接量 |
| `dns.query` | 独立 DNS 查询消息 | DNS 来源 | 时间、query、来源 | 稀有域名、新域名 |
| `dns.response` | DNS 响应或包含问答的事务记录 | Zeek dns | 时间、query、rcode/answer、来源 | NXDOMAIN、答案变化、稀有域名 |
| `web.request` | HTTP 请求/事务 | Zeek http | 时间、UID、method；URL/host 至少一个 | 新 URL、User-Agent、上传下载线索 |

Zeek DNS 一条记录同时含 query、rcode 和 answers 时使用 `dns.response`，不为形式统一强拆为两条事件。

### 6. VPN 与 DHCP 事件

| 类型 | 语义 | 必填业务字段 | 关系输出 |
|---|---|---|---|
| `session.vpn_started` | VPN 会话成功建立 | 用户、会话 ID、时间、网关；公网/分配 IP 至少按产品能力提供 | 用户—会话—公网 IP—内部 IP |
| `session.vpn_blocked` | VPN 会话建立失败/被拒 | 用户或来源、结果、原因、时间 | 不创建有效会话关系 |
| `session.vpn_ended` | VPN 会话结束 | 会话 ID、时间、网关 | 收敛会话 valid_to |
| `address.lease_started` | DHCP 租约创建 | IP、MAC/Client ID、时间、服务器 | 设备候选—IP 有效区间 |
| `address.lease_renewed` | DHCP 租约续租 | IP、MAC/Client ID、时间 | 创建新关系版本或延长区间 |
| `address.lease_ended` | 释放或到期 | IP、时间；可用时加 MAC | 收敛匹配租约 |
| `address.lease_blocked` | DHCP 请求被拒绝 | IP/Client ID、时间、原因 | 不创建有效关系 |

### 7. 上下文快照

| 类型 | 语义 | 必填字段 | 注意事项 |
|---|---|---|---|
| `identity.person_snapshot` | 人员主数据某一版本 | person.id、状态、valid_from | 不参与普通行为计数 |
| `identity.account_snapshot` | 账号主数据某一版本 | account.id/name/domain、状态、valid_from | 关联人员时保留证据 |
| `asset.device_snapshot` | 设备资产某一版本 | asset.id、主机标识、类型、valid_from | 当前 IP 不覆盖 DHCP 历史关系 |
| `asset.application_snapshot` | 应用/服务资产某一版本 | asset.id、名称、类型、valid_from | 供目标服务归一和关键性使用 |

### 8. 附加语义标签

首期允许值：

```text
interactive
network_logon
batch
service
unlock
cleartext
new_credentials
remote_access
cached_credentials
privileged_activity
upload
download
shared_device
machine_account
service_account
```

标签不能替代主类型，且必须有生成证据。例如仅凭出站字节量不能添加 `upload`。

### 9. 新类型准入模板

```yaml
type: file.read
version_introduced: 1.1.0
definition: 用户或进程读取一个文件资源
source_selectors: []
ecs_category: [file]
ecs_type: [access]
required_fields: ["@timestamp", file.path]
conditional_fields:
  - when: actor_is_user
    any_of: [user.id, user.name]
actors: [account, process]
target: file
counter_examples: []
detections: []
owner: security-data-model
```


---

<a id="part-06"></a>

## 第六篇　数据质量规则

> 本篇来源：[数据质量规则.md](./数据质量规则.md)

> 规则版本：1.0.0  
> 适用对象：原始接入、标准事件、实体关系和检测能力

### 1. 质量状态

| 状态 | 判定 | 数据路由 | 下游行为 |
|---|---|---|---|
| `qualified` | 解析成功，主语义明确，满足该事件合同的所有必填条件 | 标准 Data Stream | 可供声明为 ready 的能力消费 |
| `partial` | 事件可检索且部分能力可用，但存在非致命缺失、推断或冲突 | 标准 Data Stream | 仅允许 capability=ready/degraded 的消费者使用 |
| `invalid` | 格式无法解析、主时间/主类型无效、核心类型冲突或证据不可信 | Failure Store/invalid 流 | 禁止进入特征、基线和风险 |
| `unsupported` | 来源识别成功，但尚无已发布映射或事件代码未知 | unsupported 流 | 保留证据，进入映射待办 |

质量状态描述数据，不能直接作为威胁风险分数。

### 2. 判定顺序

```text
来源是否识别？否 → unsupported
格式能否解析？否 → invalid
事件时间能否确定？否 → invalid
主事件语义能否确定？否 → unsupported 或 invalid
必填字段是否满足？否 → invalid/partial，按事件合同
条件字段是否满足？否 → partial
跨字段约束是否满足？否 → partial/invalid
全部满足 → qualified
```

### 3. 通用规则

| Rule ID | 条件 | 严重度 | 结果 |
|---|---|---:|---|
| Q-SRC-001 | 缺 `ueba.source.namespace` | 高 | invalid，无法安全去重和隔离来源 |
| Q-ID-001 | 缺 `event.id` 或 `raw_event_id` | 高 | invalid |
| Q-TIME-001 | 源时间无效且无可信接收时间 | 高 | invalid |
| Q-TIME-002 | 使用接收时间回退 | 中 | partial；序列检测 degraded |
| Q-TIME-003 | 事件时间超前超过配置阈值 | 中/高 | partial 或 invalid，按偏差 |
| Q-TYPE-001 | `ueba.event.type` 不在已发布目录 | 高 | unsupported |
| Q-ECS-001 | 字段值与 Mapping 类型冲突 | 高 | Failure Store/invalid |
| Q-ENUM-001 | 未知枚举但主语义仍明确 | 中 | partial，保留原值 |
| Q-ROLE-001 | Actor 与 Target 应不同但被折叠 | 高 | invalid |
| Q-PROV-001 | 缺 Parser/Mapping 版本 | 高 | invalid，不可追溯 |
| Q-RAW-001 | 无原文且无有效证据引用 | 高 | partial；高风险结果不可自动升级 |
| Q-DUP-001 | 同一 event.id 重复到达 | 信息 | 幂等覆盖/丢弃并计数 |

### 4. 字段级规则

#### 4.1 缺失值

- 来源没有字段：字段省略；
- 明确数值零：写 `0`；
- 无法归类但允许 unknown：写 `unknown` 并记录原值；
- 空字符串、`-`、`N/A` 不得直接写入 IP、数值、时间或实体 ID；
- 缺失字节不得当作零参与基线；
- 缺失用户不得从 IP 当前值直接补齐。

#### 4.2 类型和范围

| 字段 | 规则 |
|---|---|
| IP | 必须可被 Elasticsearch `ip` 类型接受 |
| Port | 0–65535；0 是否有效按来源合同 |
| Bytes/Packets | 非负 long；溢出或负数 invalid/partial |
| `event.duration` | 非负纳秒；来源单位必须版本化 |
| `event.outcome` | success/failure/unknown |
| MAC | 小写、冒号分隔；无法规范化则保留厂商值并不写标准字段 |
| Timestamp | UTC date；原始字符串和时区可追溯 |

#### 4.3 跨字段约束

| Rule ID | 约束 | 失败处理 |
|---|---|---|
| Q-NET-001 | `network.bytes = source.bytes + destination.bytes` 仅在两侧均存在时成立 | 不可靠则删除派生总量并 partial |
| Q-NET-002 | source/destination 不能由采集设备 inbound/outbound 机械替代 | 方向不明则 invalid/partial |
| Q-SES-001 | event.end >= event.start | invalid |
| Q-DHCP-001 | ACK/RENEW 必须有 leased IP 和 MAC/Client ID | 缺 IP invalid；缺设备键 partial |
| Q-VPN-001 | 成功 VPN 会话必须有用户和网关 | 缺用户 invalid for UBA；可保留设备事件时 partial |
| Q-WIN-001 | 4624 outcome 必须 success，4625 必须 failure | invalid |
| Q-WIN-002 | IAM 变更必须区分 Subject 与 Target | invalid |

### 5. 检测能力状态

每条事件和每个租户的数据源状态均可声明：

| 状态 | 含义 |
|---|---|
| `ready` | 满足字段、覆盖率、延迟和实体关系门槛 |
| `degraded` | 可以运行，但结果覆盖或置信度下降 |
| `unavailable` | 条件不足，禁止运行或输出该实体类型风险 |
| `unknown` | 尚未完成数据就绪评估 |

#### 5.1 首期能力合同

| 能力 | Ready 条件 | Degraded 条件 | Unavailable 条件 |
|---|---|---|---|
| 登录时间异常 | 账号和准确时间覆盖达标 | 少量时间 fallback | 账号或时间核心字段不可用 |
| 登录失败量 | outcome、账号/来源覆盖达标 | 仅能按来源 IP 统计 | outcome 不可靠 |
| 非常用设备登录 | 账号、设备、会话关联可信 | 设备为候选且置信度中等 | 无设备标识 |
| 设备新目的地 | Zeek 两端 IP + 设备时态关系 | 仅按 source.ip 建模 | 来源端缺失 |
| 用户新目的地 | 身份/资产/认证/时态关系均 Ready | 关系置信度中等，仅生成观察 | Zeek 无法归到用户 |
| 异常外发量 | 字节方向、设备/用户关系可靠 | 只有设备输出 | 仅有总字节或方向未知 |
| DNS 稀有域名 | query、来源和时间可靠 | 仅按 IP 建模 | query 缺失 |

### 6. 数据源级门槛

门槛应按客户规模基线校准。首轮验收建议值：

| 指标 | 建议门槛 | 说明 |
|---|---:|---|
| 原始接收守恒率 | ≥99.99% | 标准 + partial + invalid + unsupported 与入口对账 |
| Parser 成功率 | ≥99.5% | 已知受支持事件 |
| 可追溯率 | 100% | 必须定位 raw_event_id 和 Mapping 版本 |
| event.id 覆盖 | 100% | 幂等基础 |
| 核心时间有效率 | ≥99.9% | fallback 单独统计 |
| Windows 认证账号覆盖 | ≥99% | 排除系统噪声后计算 |
| Zeek conn 双端 IP 覆盖 | ≥99.9% | 非标准/损坏记录另计 |
| DHCP IP+设备键覆盖 | ≥98% | 客户端类型可能影响门槛 |
| 用户—设备—IP 关系覆盖 | 上线前实测并按用例规定 | 不设虚假通用阈值；需人工抽样准确率 |

这些数字是预研验收建议，不是 Splunk 官方阈值。

### 7. 质量评分

如需总分，应保存子项和公式版本：

```text
quality_score =
  completeness*w1 + validity*w2 + consistency*w3
  + timeliness*w4 + provenance*w5 + semantic_accuracy*w6
```

缺失的维度不能直接按零替代并误导总分。风险引擎使用质量信息时，应降低证据贡献或停止评分，不得把低质量本身解释为恶意。

### 8. 处置流程

```text
invalid → 原始证据保留 → 按 error.type 聚类 → 修复 Parser/Mapping
        → 模拟 → 历史回放 → 影子比较 → 重放失败事件

unsupported → 统计来源/事件代码 → 评估价值 → 新建映射或明确忽略

partial → 进入标准流 → capability 限制 → 持续监控缺失率
```

所有人工忽略规则必须有负责人、原因、生效范围和失效时间。


---

<a id="part-07"></a>

## 第七篇　解析与映射测试集

> 本篇来源：[解析与映射测试集.md](./解析与映射测试集.md)

> 测试集版本：1.0.0  
> 机器可读数据：[testdata](./testdata)  
> 首期验证：Windows 4624/4625、Zeek conn/dns

### 1. 目录结构

```text
testdata/
├── manifest.json
├── raw/
│   ├── windows-security.jsonl
│   └── zeek.jsonl
└── expected/
    ├── windows-security.jsonl
    └── zeek.jsonl
```

测试数据为人工构造的脱敏样例，用于验证合同和原型，不代表客户现场格式。接入客户数据后应为每个产品版本补充已脱敏的真实样例。

### 2. 测试案例

| ID | 来源 | 场景 | 预期状态 | 核心断言 |
|---|---|---|---|---|
| WIN-4624-001 | Windows | 远程登录成功 | qualified | outcome=success、账号拆分、source.ip、remote_access |
| WIN-4625-001 | Windows | 登录失败 | qualified | outcome=failure、reason 保留 |
| WIN-4624-002 | Windows | 机器账号登录 | partial/qualified | machine_account 标签，不进入人员同伴组 |
| WIN-4624-NEG-001 | Windows | 缺 TargetUserName | invalid | 不生成用户认证特征 |
| WIN-TIME-NEG-001 | Windows | 源时间非法 | partial/invalid | 使用可信接收时间时 fallback，否则 invalid |
| ZEEK-CONN-001 | Zeek | 出站连接 | qualified | orig→source、resp→destination、字节求和 |
| ZEEK-CONN-002 | Zeek | missed_bytes>0 | partial | 流量完整性降级 |
| ZEEK-CONN-NEG-001 | Zeek | 缺双端 IP | invalid | 不进入连接特征 |
| ZEEK-DNS-001 | Zeek | DNS 成功响应 | qualified | query、rcode、answers 保留 |
| ZEEK-DNS-002 | Zeek | NXDOMAIN | qualified | response_code=NXDOMAIN |
| ZEEK-DNS-NEG-001 | Zeek | 缺 query | invalid | 不进入域名基线 |
| CROSS-DUP-001 | 全部 | 同一原始事件重复投递 | 去重 | event.id 相同，只保留一次 |

### 3. 断言类型

#### 3.1 精确断言

```text
event.code
event.outcome
event.dataset
ueba.event.type
source/destination 方向
user.name/domain/id
parser/mapping/schema version
quality.status
```

#### 3.2 类型断言

- `@timestamp` 可被 date 解析；
- IP 可被 `ip` Mapping 接受；
- 端口、字节、包数为非负 long；
- `event.duration` 为非负纳秒；
- 多值字段保持数组；
- 空占位符不进入标准字段。

#### 3.3 不变量

| 不变量 | 断言 |
|---|---|
| 证据不丢 | 每个输出都有 raw_event_id |
| 幂等 | 相同输入和版本产生相同 event.id |
| 非破坏 | 厂商原字段仍可查 |
| 缺失不造值 | 缺用户不能生成 person_id |
| 方向一致 | Zeek orig 永远映射 source，resp 映射 destination |
| 关系受控 | Zeek 单独输出不得写人员风险对象 |

### 4. 执行方式

原型提供 [validate-fixtures.sh](./elasticsearch-prototype/scripts/validate-fixtures.sh) 做离线 JSON 和断言检查；连接 Elasticsearch 后使用 [smoke-test.sh](./elasticsearch-prototype/scripts/smoke-test.sh) 安装原型、调用 `_simulate` 并执行样例查询。

验收报告至少记录：测试集版本、Pipeline/Mapping 版本、Elasticsearch 版本、通过/失败数、差异、负责人和执行时间。

### 5. 扩充要求

每增加一个 Mapping ID，至少增加：

1. 正常样例；
2. 失败或拒绝样例；
3. 一个关键字段缺失样例；
4. 一个类型或未知枚举样例；
5. 重放幂等断言；
6. 对应检测所需字段断言。


---

<a id="part-08"></a>

## 第八篇　Pipeline 版本和发布规范

> 本篇来源：[Pipeline版本和发布规范.md](./Pipeline版本和发布规范.md)

> 版本：1.0.0  
> 对象：采集配置、Parser、Mapping、标准化函数、Enrich、Elasticsearch Ingest Pipeline 和模板

### 1. 版本对象

| 对象 | ID 示例 | 独立版本 |
|---|---|---:|
| Parser | `windows_security_xml` | 是 |
| Mapping | `windows_security_4624` | 是 |
| 标准化函数 | `normalize_ip` | 是 |
| 枚举字典 | `windows_status_codes` | 是 |
| 网段表 | `managed_networks` | 是 |
| Ingest Pipeline | `ueba-windows-security-1.0.0` | 是 |
| Component Template | `ueba-base@1.0.0` | 是 |
| Index Template | `logs-ueba@1.0.0` | 是 |
| UEBA Schema | `1.0.0` | 是 |

事件中必须写入实际执行的 Parser、Mapping 和 Schema 版本。配置仓库 Tag 不能替代事件级版本。

### 2. 语义化版本

| 变化 | 版本 |
|---|---|
| 修复实现错误，合同和输出不变 | Patch |
| 新增可选字段、兼容来源或事件类型 | Minor |
| 改变字段语义、单位、方向、主类型、实体键或必填条件 | Major |

紧急修复同样必须生成新版本，禁止原地修改已发布 Pipeline。

### 3. 环境与状态

```text
draft → tested → shadow → canary → active → deprecated → retired
```

| 状态 | 可写生产流 | 可回放 | 说明 |
|---|---:|---:|---|
| draft | 否 | 开发样例 | 未评审 |
| tested | 否 | 测试数据 | 单元和合同测试通过 |
| shadow | 影子索引 | 生产副本 | 与当前版并行比较 |
| canary | 小比例 | 是 | 受控租户/采集器 |
| active | 是 | 是 | 正式版本 |
| deprecated | 只处理存量 | 是 | 消费者迁移期 |
| retired | 否 | 受控 | 保留定义供历史解释 |

### 4. 发布制品

每次发布必须包含：

- 版本清单和变更说明；
- Parser、Mapping、函数和字典；
- Component/Index Template；
- Ingest Pipeline；
- 原始样例、预期输出、负向样例；
- 兼容的 Schema、ECS 和 Elasticsearch 版本；
- 依赖的 Data Stream 和权限；
- 影子比较报告；
- 回滚目标和重放范围；
- 负责人和批准记录。

### 5. 测试与模拟

发布前顺序：

1. JSON/YAML/脚本静态校验；
2. Parser 单元测试；
3. 字段和事件合同测试；
4. Elasticsearch `_simulate` Pipeline 测试；
5. 目标 Index Template/Mapping 联合模拟；
6. 脱敏历史数据回放；
7. 下游特征与检测回归；
8. 峰值性能及失败路径测试。

Elastic 的模拟摄取接口不会索引数据，会执行适用 Pipeline 并根据目标 Mapping 验证结果，适合上线前联合检查。[Simulate ingest API](https://www.elastic.co/guide/en/elasticsearch/reference/current/simulate-ingest-api.html)

### 6. 历史回放

回放作业必须固定：

```text
raw dataset manifest
parser version
mapping version
schema version
dictionary/network version
replay time range
destination shadow data stream
```

回放不能读取“当前最新配置”而不记录版本。回放输出使用相同幂等 ID；写入影子索引时附加 `ueba.replay.run_id`。

### 7. 影子运行

新旧版本消费同一原始事件，分别写入：

```text
active: logs-ueba.<domain>-default
shadow: logs-ueba-shadow.<domain>-<candidate-version>
```

比较项：事件守恒、主类型、字段覆盖、类型错误、quality 状态、字节/时长、实体键、特征值、异常量和风险实体变化。差异必须归类为预期、修复、接受风险三种。

### 8. Canary 与切换

Canary 选择明确的租户、采集器或来源实例，禁止用不稳定随机比例导致同一会话分流到两版。观察窗口至少覆盖业务周期和周末/工作日差异；紧急安全修复可缩短，但需记录原因。

切换使用别名、默认 Pipeline 或采集策略的版本化引用。切换前记录：

```text
old_version
new_version
effective_at
selected_sources
rollback_deadline
owner
```

### 9. 回滚

触发条件包括：

- invalid/Failure Store 比例显著上升；
- 关键字段覆盖下降；
- source/destination 或 actor/target 方向错误；
- 重复事件增加；
- 数据延迟或资源消耗越界；
- 特征/告警量出现无法解释的变化。

回滚步骤：停止候选路由、恢复上一 active 版本、冻结受影响时间窗、确定原始事件范围、修复后重放、重算受影响特征/基线/异常。禁止仅删除错误标准事件而不处理下游派生结果。

### 10. Failure Store

Processor 异常使用 `on_failure` 写入错误类型、processor tag、Pipeline 版本；Mapping 冲突等索引失败进入 Failure Store。失败事件必须保留进入 Pipeline 前的原始内容和来源位置。[Elastic Ingest 错误处理](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/error-handling)

重放失败事件前必须先在 `_simulate` 验证；重放成功后记录原失败 ID、新 event.id、修复版本和时间。

### 11. 发布门禁

- [ ] 所有制品有不可变版本；
- [ ] 样例和负向测试通过；
- [ ] `git diff --check`、JSON 校验通过；
- [ ] `_simulate` 与目标 Mapping 通过；
- [ ] 回放事件守恒；
- [ ] 影子差异已解释；
- [ ] 数据质量门槛通过；
- [ ] 下游检测回归通过；
- [ ] Canary 观察完成；
- [ ] 回滚目标、脚本和原始证据范围已验证。


---

<a id="part-09"></a>

## 第九篇　数据源健康监控指标

> 本篇来源：[数据源健康监控指标.md](./数据源健康监控指标.md)

> 版本：1.0.0  
> 监控链路：来源 → 采集 → 原始归档 → 解析 → 标准化 → Elasticsearch → 实体关系 → 检测就绪

### 1. 监控目标

监控不仅判断“有没有日志”，还要判断数据是否仍能支持对应 UEBA 用例。每项指标按 tenant、source、dataset、source version、parser version、mapping version 分组。

### 2. 核心指标

| Metric | 类型 | 定义 | 首轮建议告警 |
|---|---|---|---|
| `ueba_ingest_received_total` | counter | 平台入口接收事件数 | 相对历史同期骤降/归零 |
| `ueba_raw_archived_total` | counter | 原始证据成功归档数 | 与 received 对账不一致 |
| `ueba_parse_success_total` | counter | Parser 成功数 | 成功率 <99.5% |
| `ueba_event_routed_total{status}` | counter | 四种质量状态数 | invalid/unsupported 比例异常 |
| `ueba_field_present_total{field}` | counter | 字段非空且类型有效数 | 核心字段覆盖跌破合同 |
| `ueba_ingest_delay_seconds` | histogram | source event 到入口时间 | P95/P99 超阈值 |
| `ueba_processing_delay_seconds` | histogram | 入口到可检索时间 | P95/P99 超阈值 |
| `ueba_duplicate_total` | counter | 幂等重复事件 | 比率突增 |
| `ueba_failure_store_total{error}` | counter | Failure Store 写入 | 持续增长或新错误类型 |
| `ueba_relation_resolved_total{type}` | counter | 成功实体关系数 | 关系覆盖下降 |
| `ueba_relation_conflict_total` | counter | 多来源冲突 | 突增 |
| `ueba_capability_status{use_case}` | gauge | ready=3/degraded=2/unavailable=1/unknown=0 | 状态下降 |

### 3. 对账公式

每个统计窗口：

```text
received
= qualified + partial + invalid + unsupported
 + buffered_not_processed
 + explicitly_dropped_by_approved_policy
```

原始归档与分析处理分别对账。归档成功不代表解析成功；解析失败也不允许丢失原始证据。

### 4. 来源专项指标

#### Windows

- EventID 分布及新 EventID；
- 4624/4625 账号、域、LogonType、source.ip 覆盖；
- EventRecordID 重复/倒退；
- 域控/主机最后事件时间；
- 机器账号、服务账号比例；
- 4672 与 4624 会话关联率；
- 4688 command_line 覆盖率。

#### Zeek

- sensor、log type、uid 事件量；
- conn 双端 IP/port、bytes、packets 覆盖；
- `missed_bytes>0` 比例；
- dns query/rcode/answers 覆盖；
- http method/host/uri/status 覆盖；
- uid 在 conn/dns/http 间的关联率；
- 每传感器乱序、延迟和断流。

#### DHCP/VPN

- 会话/租约开始与结束配对率；
- DHCP IP+MAC/Client ID 覆盖；
- VPN user+session+assigned IP 覆盖；
- 未关闭会话数量与年龄；
- 同时段冲突租约；
- 用户—设备—IP 时态关系覆盖和人工抽样准确率。

#### HR/AD/CMDB

- 快照新鲜度；
- 稳定 ID、状态、生效时间覆盖；
- 孤立账号和一人多账号比例；
- 同一资产多稳定 ID 冲突；
- 共享设备、域控、代理排除清单覆盖。

### 5. 告警等级

| 等级 | 条件 | 动作 |
|---|---|---|
| P1 | 数据完全中断、原始证据丢失、Mapping 大面积失败 | 停止相关评分，通知值班和负责人 |
| P2 | 核心字段/实体关系覆盖明显下降、延迟影响检测窗口 | capability 降级，调查来源与 Pipeline |
| P3 | 未知枚举、新 EventID、局部样例失败 | 创建映射待办，保持观察 |
| Info | 计划发布、重放、已批准丢弃 | 记录审计，不触发事故 |

### 6. 数据就绪面板

面板至少显示：

1. 来源事件量与最近到达时间；
2. 原始归档、解析、质量状态漏斗；
3. 核心字段覆盖热力表；
4. P50/P95/P99 延迟；
5. Failure Store 错误 Top N；
6. 身份、资产、关系覆盖；
7. 每个用例的 ready/degraded/unavailable；
8. 当前 Parser/Mapping/Schema 版本；
9. 发布前后差异标记。

### 7. 防止静默失败

检测任务成功运行但输入为零不算健康。每个检测必须同时检查数据窗口事件数、所需字段覆盖、实体关系版本和 capability 状态；不满足时输出“数据不可用”，禁止输出“未发现异常”。


---

<a id="part-10"></a>

## 第十篇　Elasticsearch 原型

> 本篇来源：[Elasticsearch原型.md](./Elasticsearch原型.md)

> 原型目录：[elasticsearch-prototype](./elasticsearch-prototype)  
> 版本：1.0.0

### 1. 目的

原型验证统一事件模型可以落实为 Elasticsearch 模板、Data Stream、Ingest Pipeline、Failure Store 和查询。它不是完整 UEBA 产品，也不包含实体解析、模型训练和风险服务。

### 2. 制品

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

### 3. 索引设计

原型索引模式为 `logs-ueba.*-*`，具体建议：

```text
logs-ueba.authentication-default
logs-ueba.network-default
logs-ueba.dns-default
logs-ueba.web-default
logs-ueba.session-default
```

Data Stream 适合追加型时序事件。实体当前状态、时态关系、特征、基线和风险应使用各自索引，不写入日志 Data Stream。

### 4. 生产化前必须补齐

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

### 5. 验证边界

本原型能够证明 JSON 制品有效、核心 Mapping 可安装、两个 Pipeline 能通过模拟并生成关键标准字段。它不能证明客户现场日志覆盖、吞吐容量、实体归属准确率或 UEBA 检测效果，这些由完整验证链验收。


---

<a id="part-11"></a>

## 第十一篇　完整验证链

> 本篇来源：[完整验证链.md](./完整验证链.md)

> 验证场景：Windows/VPN 登录 → 标准认证事件 → 账号与人员实体 → 用户登录行为特征 → 异常证据  
> 版本：1.0.0

### 1. 验证目标

证明日志归一结果确实能被 UEBA 消费，并验证“日志有 user”到“风险属于正确人员”之间的所有关系。网络事件如果无法达到时态归属门槛，只验证到设备/IP 层。

### 2. 输入组合

| 输入 | 最低字段 | 用途 |
|---|---|---|
| AD/HR 快照 | person ID、account SID/ID、domain、status、有效期 | 账号→人员、同伴组 |
| CMDB/AD Computer | asset ID、hostname、类型、共享标志、有效期 | 主机→设备 |
| Windows 4624/4625/4634 | 时间、账号、Logon ID、目标、结果、来源 | 登录行为和本机会话 |
| VPN 开始/结束 | 时间、用户、Session ID、公网 IP、分配 IP | 远程会话与地址关系 |
| DHCP | 时间、IP、MAC/Client ID、租期 | 内网 IP→设备时态关系 |

### 3. 验证链

```text
原始 Windows/VPN 日志
  │ 证据归档、event.id
  ▼
Parser + Mapping 1.0.0
  │ ECS + ueba.event.type
  ▼
qualified 标准认证事件
  │ 账号键、Session ID、来源/目标
  ▼
时态实体解析
  ├── account SID → person ID（AD/HR）
  ├── hostname → asset ID（CMDB/AD Computer）
  ├── DHCP IP ↔ device [valid_from, valid_to)
  └── VPN user ↔ assigned IP [session start, end)
  ▼
实体增强事件/关系记录
  │ person_id + account_id + device_id + confidence
  ▼
小时级登录特征
  │ count、failure_count、source_ip_count、new_device
  ▼
历史基线比较
  │ 当前值、个人/同伴参考、质量因子
  ▼
异常
  │ 证据 event.id、特征/基线/映射版本
  ▼
调查下钻到原始日志
```

### 4. 验证数据场景

构造用户张三：

- AD SID `S-1-5-21-1000-1105` 对应 person `P-1001`；
- 常用设备 `ASSET-001`，常用来源网段 `10.10.1.0/24`；
- 训练期 28 天主要在 08:00–19:00 登录；
- 验证日在 02:13 从新公网 IP 登录 VPN，获得 `10.20.8.15`；
- 同一会话随后访问一台从未使用的设备；
- DHCP/VPN/Windows 关系均能在事件时间对齐。

对照负向场景：

- 相同 IP 在两个时间段分配给不同设备；
- 共享跳板机同时有多个用户；
- VPN 结束事件缺开始事件；
- Windows 事件迟到 20 分钟；
- HR 状态在事件发生后才变化；
- Zeek 事件只有 IP，关系置信度不足。

### 5. 阶段验收

| 阶段 | 断言 | 失败含义 |
|---|---|---|
| 原始证据 | 入口、归档、各路由数量守恒，raw 可定位 | 无法重放或取证 |
| 标准化 | 4624/4625 类型、outcome、角色、时间正确 | 统一模型不可用 |
| 账号解析 | SID/域账号在事件时间对应正确人员 | 人员风险可能错误 |
| 设备解析 | 主机/IP 在事件时间对应正确资产 | 设备基线污染 |
| 会话 | 开始/结束与 Logon ID/Session ID 配对 | 时长和归属不可信 |
| 特征 | 固定输入产生确定的小时特征 | 无法复算 |
| 基线 | 训练窗口不含评分窗口，版本一致 | 数据泄漏或版本污染 |
| 异常 | 保存当前值、参考值、阈值和证据 | 不可解释 |
| 调查 | 异常→特征→事件→原文完整下钻 | 证据链中断 |

### 6. 最小特征

| Feature ID | 实体 | 窗口 | 计算 |
|---|---|---|---|
| `auth.login.count` | person/account | 1h | 成功登录数 |
| `auth.failure.count` | account/source | 1h | 失败登录数 |
| `auth.source_ip.cardinality` | person | 24h | 来源 IP 去重数 |
| `auth.device.cardinality` | person | 24h | 目标设备去重数 |
| `auth.new_source_ip` | person | event | 历史窗口未出现来源 |
| `auth.new_device` | person | event | 历史窗口未出现设备 |
| `auth.off_hours` | person | event | 相对个人/同伴活跃时段偏离 |

每个特征保存 feature version、mapping version、entity resolution version、窗口、样本量和质量。

### 7. 通过标准

- 同一原始输入重复执行不产生重复标准事件、关系、特征或异常；
- 事件发生时的身份和资产关系正确，不使用当前快照覆盖历史；
- 共享设备不会被强制归到单一人员；
- 低置信 Zeek 事件只输出 IP/设备观察，不写人员风险；
- 固定样例的特征结果可重复；
- 训练窗口与评分窗口隔离；
- 异常能够下钻到原始证据和所有处理版本；
- 删除或修复一条关系后，可定位并重算受影响窗口；
- 数据源 capability 降级时，检测停止或降级而不是返回“无异常”。

### 8. 执行步骤

1. 运行 `./elasticsearch-prototype/scripts/validate-fixtures.sh`；
2. 在隔离 Elasticsearch 安装原型；
3. 运行 `_simulate` 冒烟测试；
4. 导入脱敏 AD/HR、资产和会话样例；
5. 写入 Windows/VPN/DHCP 事件；
6. 检查实体关系及有效期；
7. 计算固定特征并与预期表比对；
8. 训练基线并冻结版本；
9. 回放异常登录场景；
10. 验证异常解释和原文下钻；
11. 修改映射或关系版本并验证定向重算；
12. 输出验证报告和未通过项。

### 9. 交付证据

验证结束保存：输入 Manifest、所有制品版本、命令和环境版本、事件/关系/特征/异常预期与实际值、性能数据、差异说明、截图或查询结果、负责人和时间。
