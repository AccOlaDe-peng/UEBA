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