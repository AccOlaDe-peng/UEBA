# Splunk 风险评分(RBA)与 Splunk UBA 调研

> 调研时间:2026-09-09。资料来源:help.splunk.com 官方文档(Splunk Enterprise Security 8.5 管理手册、Splunk UBA 5.4.x 文档)。
> 本笔记面向自研 UEBA 产品的风险评分体系设计参考,重点提取:RBA 风险分计算公式、风险因子体系、实体风险分(ERS)、以及老一代独立产品 Splunk UBA 的架构 / ML 模型机制 / 检测模型清单 / 数据源 / ES 集成 / 生命周期。

---

## 第一部分:ES Risk-Based Alerting / 实体风险评分

Splunk Enterprise Security(ES)8.5 中,Risk-based Alerting(RBA)是与 UEBA 紧耦合的实体风险评分体系。章节位于 Administer 手册下的 "Risk-based alerting",共 11 个主题页(目录见文末 URL 列表)。

### 1. 风险评分机制(计算方式、累加/加权、阈值触发)

**核心概念与流水线(两级检测架构)**

- **风险分(risk score)**:衡量一个实体(entity)随时间相对风险的单一指标。实体 = 环境中任意 asset / identity / user / device,实体类型分 `system`(资产表映射)与 `user`(身份表映射)两类,也支持自定义类型。
- **流水线**:
  1. 检测(correlation search / event-based detection)搜索匹配到可疑事件 → 在 **risk index** 中写入一条 **intermediate finding(中间发现)**,携带 `risk_score` 及 MITRE ATT&CK tactic/technique 标注;
  2. 另一个检测(risk incident rule 或 **finding-based detection**)随时间聚合某实体的 intermediate findings,当聚合风险**超过阈值**时生成 **finding**(写入 notable index),进入分析师队列(Mission Control → Analyst queue)调查。
- **intermediate finding 关键字段**:`entity`、`entity_type`、`risk_score`、`risk_message`。

**风险累加(事件级)**

- finding 的风险分 = 所有贡献 intermediate finding 风险分的**求和**。文档示例:5 个 intermediate finding 分数为 10/20/30/40/50,聚合风险分为 150。
- 同一实体多个显示名通过 `normalized_risk_object` 归一化合并计分(如 `rob`、`rob@splunk.com`、`rob@splunk` 视为同一身份,合并后更容易过阈值)。显示名取出现频次最高者,但计分依据 Asset/Identity lookup 中第一个匹配项。
- **entity zones(实体区域)**:为同名实体增加地理/部门等上下文区分(如同一账号分属不同部门、同一 IP 分属 San Jose / San Francisco),避免无关实体的分数被错误合并,降低告警量。

**实体风险分 ERS(Entity Risk Score,ES 8.3+ 引入)—— 加权混合模型 ★**

- ERS 是原始风险分的增强版:**基于规则的风险评分 + 加权、数据驱动的因子分析**的混合方法。
- 度量实体(用户/资产)的整体风险等级;计算**过去 7 天**窗口,归一化到 **0~100**。
- 由计划搜索 **`Risk - EWA Entity Risk Score Calculation`**(EWA = Exponentially Weighted Average 风格的加权平均)计算,默认**每 20 分钟**运行一次,针对过去 7 天内至少有 1 条 intermediate finding 的所有实体;官方警示:不要修改该保存搜索。
- **ERS 是下列 5 个组件的加权平均**(基于 Risk Index 中的 findings):
  1. 所有 intermediate finding 的 `calculated_risk_score` **总和**;
  2. 单条 intermediate finding 的**最大** `calculated_risk_score`;
  3. `calculated_risk_score ≥ 50` 的 intermediate finding **数量**;
  4. intermediate finding **总数**;
  5. **跨检测的求和**(每个 detection 只取其最高风险分再累加,防止单一检测刷分)。
- 结果存入 **`ers` index**,在 ES 全局以徽章展示:**0-25 黄、25-50 橙、50-75 浅红、>75 深红**;仅显示过去 7 天有风险事件的 `system`/`user` 实体,涉及字段:`orig_host`、`dvc`、`src`、`dest`、`src_user`、`user`。
- 风险因子公式作用于事件分:`(risk_base_score + Σ 加法因子) × Π 乘法因子`(见第 3 节)。
- 注:ES 内置 UEBA 使用 Risk Data Model 数据;官方建议 correlation search 配置 MITRE ATT&CK 标注以提升检测准确度与风险评分质量。

**分数展示与重置**

- 展示位置:Mission Control Analyst queue 专门列;Analytics → Dashboards → **Risk analysis dashboard**(按实体/按 MITRE 标注两个视图,可下钻 Timeline)。
- 手动重置:Risk Analysis dashboard → **Ad-Hoc Risk Entry**,可输入负分(如 -180)对冲分数;由于分数按时间窗计算,原始事件滑出窗口后负分会短暂生效。

### 2. 风险因子(risk factors)分类与配置

**定义与作用**

- Risk factor 是**修改实体风险分的规则/调参因子**:满足配置条件时对关联实体的风险分施加加法或乘法调整,**无需编写新搜索**。典型场景:同样行为,总监的笔记本比普通员工加更高分(×2)。
- 存储于 `risk_factors.conf` 配置文件;总风险分基于 **Risk Data Model**(而非仅 risk index)动态计算。
- 两种分值类型:
  - **Base risk score**:基于检测事件的数值;风险因子按实体元数据(priority、category、user、asset 等)条件生成 calculated risk score;
  - **Total risk score**:某实体在时间窗内所有 calculated risk score 之和。

**计算公式 ★**

```
(risk_base_score + sum(expression_group_addition)) * product(expression_group_multiplication)
```

- **加法因子总是先于乘法因子应用**(运算顺序)。
- 官方示例:base score 5,4 个命中因子(2 个 ×2,1 个 +5,1 个 +6):(5+5+6)=16 → 16×2×2 = **64**。

**配置方式(Risk factor editor)**

- 入口:Security content → Risk factors → Add risk factor;需要 `edit_risk_factor` 能力;可先预览匹配的风险事件再保存。
- **Operation**:Addition 或 Multiplication。
- **条件(Conditions)**:
  - Basic:风险事件字段 = 值(静态值或另一字段名);
  - Advanced:8 种比较器 —— `is equal to`、`is not equal to`、`matches regular expression`、`like`、`is greater than or equal`、`is less than or equal`、`is greater than`、`is less than`;多条件用 **AND** 聚合;支持 "Compare against field"(值取自字段);有 SPL 预览,如 `if(like('risk_object',"bennay"), 0.0)`。
- 针对资产/身份字段(如 `src_bunit=emea`)写条件时,需启用 sourcetype(含 `stash`)以自动获得资产字段富化。
- 管理:搜索/排序(Name、Operation、Value)/激活/停用/克隆/删除,右侧面板实时显示匹配的风险事件。

**内置默认风险因子(7 个,默认全部关闭,可自定义)★**

| 风险因子 | 条件 | 操作 |
|---|---|---|
| Admin user | `user_category` 匹配正则 "admin" | ×1.5 |
| Contractor user | `user_category` = "contractor" | +5 |
| Critical priority destination | `dest_priority` = "critical" | ×1.5 |
| High priority user | `user_priority` = "high" | ×1.25 |
| PCI source | 与 PCI 合规相关的源 | 提分 |
| Watchlisted priority user | `user_watchlist`="true" 且 `user_priority`!="low" | ×1.5 |
| Watchlisted user | `user_watchlist` = "true" | ×1.5 |

- 组合示例:风险修饰 120 分 + "priority=critical 时 +50" 的因子 → 170;AWS GuardDuty / Security Hub critical 告警源 ×2.5;watchlist 用户 + critical 资产 ×1.2。

### 3. 风险修饰(risk modifiers)

- **定义**:写入 risk index 的**事件**,用于给实体加风险。最小字段集:`risk score`、`risk_object`、`risk_object_type`。
- **检测编辑器中配置**(Security content → Content management → +Content → Detection):
  - `Risk message`:描述风险活动,支持 `$field$` 变量引用事件字段,如 `Suspicious Activity to $domain$`;
  - `Entity type`(system/user/自定义,决定分组方式)、`Entity`(取检测结果中的字段名,如 `src`)、`Finding risk score`(整数);可对成功/失败行为差异化打分(如成功 HTTP POST=20 分、失败=0 分);
  - **0 分修饰**:score=0 仍写入 risk index 作为上下文但不抬分;
  - **Output 输出类型**:intermediate findings 或 finding;多个风险实体时建议主实体用 Finding、附加实体用 Intermediate Findings;ES 8.1+ 中 Entity/Entity type 为空会自动填 "N/A";
  - 可 `+Add entity` 给多个实体加风险。
- **Threat object(威胁对象)作为风险修饰**:在检测中添加 `Threat object`(如 payload、域名、IP、命令行、文件名、注册表键)+ `Threat object type`(file_hash、domain、URL、IP、command line、process name 等),把实体的行为/交互存入风险事件 —— 这是 **Threat topology 可视化**的数据基础。
- **手动风险条目**:Analytics → Security Intelligence → Risk analysis → Create ad-hoc risk entry,一次性加减分(可用于关闭 finding 的自动化流程中做中和)。
- **SPL 方式**:`... | sendalert risk param._risk_object_type="system" param._risk_object=<field> param._risk_score=<int>`,可无 appendpipe 直接赋分。

### 4. 实体风险分反哺检测的机制

- **ERS → finding-based detection(以分做检测)★**:ERS 每 20 分钟聚合写入 `ers` index 后,可创建 finding-based detection,当实体风险分超过自定义阈值时自动生成 finding。官方示例(用户 ERS > 80 报警):

  ```
  index=ers ers>=80 risk_object_type=user
  | stats max(ers) as entity_risk_score values(detections) as detections by normalized_risk_object
  ```

  - `index=ers`:查 ERS 索引;`ers>=80`:分数阈值;`risk_object_type=user`:限定用户实体;`stats max(ers)`:每实体取最高 ERS;`values(detections)`:列出已关联检测;`by normalized_risk_object`:按归一化实体分组。
- **Cumulative entity risk 分组**:finding-based detection 编辑器中选 Group type = "Cumulative entity risk",按实体累计风险分阈值生成高置信 finding group,压低告警量、聚焦真正威胁。
- **风险分作为检测输入的闭环**:event-based detection 产分 → 风险因子/修饰调分 → ERS 聚合 → finding-based detection 按分报警 → 调查结果(关闭 finding 时)可通过手动/自动 risk entry 回写调分。
- **RBA 替代 sequence templates**:ES 8.0+ 弃用 sequence templates(8.1+ 只读),改用 RBA + SPL 检测行为链(`delta` 计时差 + `autoregress` 取上一行 + `where gap<600` 限窗口),可把链式结果生成为一个更高风险分的新风险事件。

### 5. 风险调查界面(findings 审查、时间线、威胁拓扑)

**Review risk-based findings**

- 风险 finding 关键字段:`Entity`、`Entity type`、`Risk score`(可被 risk factor 修改)、`Risk event count`、`Risk message`(可选)、`Threat object` / `Threat object type`(可选)。
- 辅助字段:`drilldown_search` / `drilldown_earliest` / `drilldown_latest` —— 定义贡献事件的回溯搜索与时间窗(需返回 `calculated_risk_score` 字段),驱动 Timeline 可视化。
- 调查方法:同实体 findings 聚合审查(normalized entity)、entity zones 富化、drill-down search(基于 `| from datamodel:"Risk.All_Risk"`,同时检索 primary_object 与 dest/src/user 命中的 related_object,输出 MITRE tactic/technique、risk_factor* 等字段)、finding 上下文中的 **MITRE ATT&CK posture** 矩阵图(调查内展示所有事件的战术/技术)。

**Intermediate findings timeline(中间发现时间线)**

- 头部显示 Entity、Risk score、Threshold、Intermediate findings 数;图标颜色编码风险等级(浅色低、深色高),与明细表一致。
- X 轴=时间,Y 轴=风险分;支持 +/- 缩放、Scroll to zoom(x 轴)、拖拽缩放(y 轴);点击散点 tooltip 显示 risk score、detection、描述、时间、MITRE tactic/technique。
- 配套 Intermediate findings details 表(分页,最多显示 100 条,超出显示 100+ 并链接完整搜索);可按 Time/Description/Detection/Risk score 排序;展开可见 Entity、Detection、Risk score、Description、Detection description、Annotations、Threat object(查看贡献中间发现)。
- 由宏 `risk_event_timeline_search` 驱动:`from datamodel:"Risk.All_Risk" | search normalized_risk_object=... risk_object_type=... | get_correlations` + MITRE 字段重命名(可编辑 macros.conf 但可能破坏可视化)。
- 入口:Mission Control → Analyst queue → finding 侧板 Entity 旁箭头 / Intermediate findings 列数字链接 / 调查详情页。

**Threat topology visualization(威胁拓扑可视化)**

- 用途:超越单个被感染用户,展示 finding 中**实体之间如何通过共享的 threat object 关联**,单次最多显示 **20 个实体**。
- 逻辑:不同实体的 intermediate findings 引用同一 threat object 时,拓扑图把威胁对象与实体连边;点击实体高亮相关实体/威胁对象,显示 risk scores、priority 等;可跳转 Risk analysis / Threat activity dashboard,并可指定时间范围下钻。

---

## 第二部分:Splunk UBA(老产品)

### 1. 产品定位与功能全景

- **Splunk User Behavior Analytics (UBA)**:使用**行为建模、同伴群体分析(peer-group analysis)和机器学习**发现环境中隐藏威胁的独立产品;自动检测用户、设备、应用的异常行为,并把异常模式组合成具体、可行动的威胁(threat)。
- 提供精简的威胁审查工作流、kill chain 与地理可视化;从 Splunk 平台(Splunk Enterprise / Cloud)取数。
- **部署形态特殊**:不像多数 Splunk 安全产品是装在 Splunk 平台上的 app,UBA 必须**安装在专用资源**(物理服务器或客户管理的云主机)上;由 Splunk 专业服务(PS)负责安装。
- **7 大内置用例(use cases)★**:Account Misuse(账号滥用)、Compromised User Account(失陷账号)、Compromised and Infected Machine(失陷/受感染机器)、Contextual Intelligence(上下文情报)、Data Exfiltration(数据外泄)、Lateral Movement(横向移动)、Suspicious Behavior / Unknown Threats(可疑行为/未知威胁,常用于反哺 correlation search/threat rule 内容建设)。

### 2. 架构与 ML 模型机制

**数据流管道(7 步)★**

1. **原始/解析数据接入**:从 Splunk 平台取数。CIM 合规数据走 **Splunk Direct** 连接器(在 Splunk 侧解析);部分/非 CIM 但 UBA 有原生解析器的走 **Splunk Raw Events**(UBA 侧解析);两者皆非走 Generic data source(配自定义内容框架)。
2. **账户规范化与身份解析**:规范化设备/域名,把 HR 数据中的所有账号关联到同一自然人;实时维护 IP ↔ 主机名 ↔ 用户映射。
3. **View 抽象 + 数据 cube**:按数据类型打 view 标签(如 Firewall/Network/AD/DLP),抽象掉厂商格式差异,存入数据 cube(如 `semiaggr_s`、`dlpsummary_s`、`emailsummary`、`fileaccess_s`、`windowsevents`、`badgeaccess`);字段以 `view.Network.bytesFromClient` 形式被模型消费。
4. **异常模型计算**:Streaming 模型实时处理(短窗口如过去 1 小时,可产出异常/IoC/分析数据);Batch 模型与异常规则处理大窗口(典型 24h,通常夜间运行);批模型分 **Rare event models**(稀有/首次行为)与 **Time series models**(时序偏移)两类。
5. **Anomalies(异常)**:模型的输出;带 **type**(具体名称)与 **category**(通用描述,如 Exfiltration、Infection、Expansion,对应 kill chain 阶段);可用 anomaly action rules 管理(删除/恢复/改分/加 watchlist)、自定义 anomaly scoring rules。
6. **威胁模型 + 自定义威胁规则**:威胁模型基于系统内数据与异常生成动态威胁;威胁规则在特定时间窗内匹配特定异常模式产生威胁,按预设调度运行。
7. **Threats(威胁)**:一个或多个异常构成明确定义的安全用例(如 Data Exfiltration),关联 IoC 与证据。计算方式 4 种:
   - **Kill-chain threats**:检查特定用户/设备的异常是否吻合 kill chain 阶段(如 Data Exfiltration by Suspicious User or Device、Data Exfiltration by Compromised Account);
   - **Graph-based threats**:按相似异常群组计算,而非按用户/设备分组(如 Public-facing Website Attack、Fraudulent Website Activity);
   - **Data-driven threats**:数据驱动的可能性计算,内部威胁走此路(如 Lateral Movement、Data Exfiltration);
   - **Rule-based threats**:自定义威胁规则触发(如 Brute Force、Data Exfiltration after Data Staging)。

**ML 机制要点**

- **无监督机器学习**为每个身份与资产画像基线,检测偏离;再对异常本身跑 ML 找异常模式 → **High Fidelity Threat**。漏斗:数百万事件 → 数百个异常 → 少数威胁。
- **4 种 peer group**:HR peer group(AD 组 + 汇报链)、Organizational Unit(OU)peer group、Behavioral peer group(行为聚类)、Device peer group(网络活动);entity profiling 基于用户/设备属性(AD 活动推导)。
- **模型注册表**:`/etc/caspida/local/conf/modelregistry/offlineworkflow/ModelRegistry.json`,可调 threshold(最小数学异常分)、anomalyScoreThreshold(可疑度阈值)、anomalyCountThreshold(最大异常数)、thresholdSimilarity 等;支持自定义 supportive fields、模型克隆与新建(custom use case framework)。
- **False Positive Suppression Model**:自监督深度学习向量化异常 + 基于用户反馈的排序,相似度超阈值(thresholdSimilarity 默认 0.99)的新异常自动打误报标签(不隐藏,打标保留可见);每天 3:30 am 跑;只从"打误报标"学习,不支持从"取消标"学习。

**部署架构(节点角色)★**

| 节点角色 | 职责 | 典型服务 | 代表模型 |
|---|---|---|---|
| Management server | 托管 UBA Web 界面(仅需 1 个) | UI server、job manager master、InfluxDB、PostgreSQL、Impala、Zookeeper Quorum | — |
| Streaming server | 流式模型实时处理,短窗口(如 1h),产出异常/IoC/分析数据 | Kafka、Docker、Kubernetes、Zookeeper、Redis | Web Beaconing Detection、Network Transport、Land Speed Violation、Unusual Windows Events Sequences |
| Batch server | 批模型大窗口(如 24h)处理,夜间运行;所有威胁模型均为批模型 | Apache Spark、HDFS | Unusual Volume of Authentication Events per User、Network Scanning Detection、Suspicious Privilege Escalation、Lateral Movement Threat、Threat Computation Task |

- 单节点部署时所有服务在同一节点;分布式按节点分配任务(如 7 节点中 Spark 只在 node7,Hadoop 在除 node3 外所有节点)。UI 中 System → Models 可查看 Streaming/Batch 模型清单。监控:Splunk UBA Monitoring App。

### 3. 检测模型/规则分类清单(★重点)

**模型四大类型**:Batch models、Security analytics models(建立安全上下文、多检测算法、内部/外部用户排序、watchlist/allow-deny list 个性化)、Streaming models、Threat models(全部以批方式运行)。

**官方 Batch models 页详述的 14 个模型**:
Account Exfiltration Model、Device Exfiltration Model、Excessive File Size Change Model、False Positive Suppression Model、New Access Model for Box、Rare File Access Model、Rare Microsoft Windows Device Access Model (Using Authentication Data / Using Login Data 两版)、Rare VPN Login Location Model、Rare Events Model Scaling、Unusual Volume of Box Downloads per User Model、Unusual Volume of Box Login Failure Events per User Model、Unusual Volume of VPN Login Events per User Model、Unusual Volume of VPN Traffic per User Model。

**Rare Events Model 家族(13 个变体,可按 `cardinalitySizeLimit` 默认 1000 万控制规模)**:
RareEventsModel_HTTPUserAgentString、FWPortApplication、WindowsLogs、WindowsLogins、WindowsAuthentications、NetworkCommunicationRareGeo、VPNRareGeo、ExternalAlarm、FileAccess、FWScopePortApp、UnusualProcessAccess、RareEmailDomain、UnusualDBActivity。

**Time-series 批模型(5.4.0+,数据外泄检测,5 个)**:
Unusual Volume of Data Uploaded per User Model(基础版+网络流量画像版)、Unusual Volume of Data Uploaded per Device Model(基础版+画像版)、Unusual Volume of File Access Related Events per User Model;异常类型 BytesTransmitted / MultipleFileOps;按用户/设备/peer group 建 30 天日/周高斯基线,出向字节超 `threshold × mean` 且超绝对阈值即告警。

**VPN 登录相关模型(2 个)**:Abnormal VPN Session Associated with Rare Location(VPN 登录后当日行为序列模式挖掘)、Changepoint Model for VPN Location of Authentication Events(认证地理位置变点检测)。

**Lateral Movement Model**:图计算 + 序列分析 + 多异常检测算法;采集 AD 日志、防火墙、Endpoint;默认 30 天窗口;支持 Windows 事件/进程特征(内置 mimikatz、keylogger、psexec 等进程库,可配置 allow/deny list);输出 Threat Relations 图、异常时间线、IoC、设备位置等面板。

**Streaming 模型(代表)**:Web Beaconing Detection Model、Network Transport Model、Land Speed Violation Model、Unusual Windows Events Sequences Model。

**数据映射表(data mapping)中出现的全部模型(去重约 70 个)**,除上述外还包括:
Active Directory Markov-Chain Correlation Model、Box Pattern Model、Browser Exploitation Model、Denylisted Entity Model、External Alarm Analysis Model、Fixed Patterns in Microsoft Windows Logs Model、Fixed Patterns in Network Traffic Model、Land Speed Violation Model、Malware Communication Model、Network Scanning Detection Model、Network Transport Model、New Access Model、O365 File Access Pattern Model、Powershell Detection Offline Model、Rare Badge Reader Access Model、Rare Database Activity Model、Rare Destination IP Geolocation Model、Rare Egress Application Model、Rare External Alarms Model、Rare Microsoft Windows Events Model、Rare Port for Application Model、Rare User Agent String Model、Suspicious Account Lockout Model、Suspicious Email Detection Model、Suspicious Patterns in Incoming Web Traffic Model、Suspicious Privilege Escalation Model、USB Activity Model、Unusual Per Day/Week Activity Time Model、Unusual Time of Badge Access Model、Unusual VPN Duration Model、Web Beaconing Detection Model、Web Shell Model,以及大量 "Unusual Volume of ... per User/Device Model"(Authentication、Authentication Failure、Failed Login、Badge Accesses、Blocked Connections、Outgoing Connections、Admin commands、Help commands、Grants、Database Records Read/Modified/Deleted、Bytes Written to USB、File Operations to USB、Data Printer、Data Uploaded to DMZ Devices、Data Downloaded from Internal Server、Box Events/Login Events、External Alarms per Device 等)、Users Increasing Device Access Model、User Exfiltration Model。

**Rule-based anomalies(异常规则,数据映射表提取约 60 条,带下划线命名)**,代表:
audit_log_cleared(AD 审计日志清空)、ad_recovery_account、admin_changes_on_self、disabled_account_activity、terminated_user_activity、account_creation_deletion_in_short_span、member_added_removed_in_short_span、local_account_creation、new_account_detected2、password_policy_circumvention、service_account_login_ad、service_account_login_vpn、spear_phishing、email_to_competitor、email_to_self、email_resume、data_transfer_over_email、job_search_pan、job_search_proxy、usage_of_proxy_anonymizer、amplification_dos_pan、malicious_credentialaccess_uri_pan、malicious_infection_uri_pan、suspicious_blacklisted_uri_pan、suspicious_defenseevasion_uri_pan、suspicious_policyviolation_uri_pan、download_from_suspicious_blacklisted/credentialacces/infection/policyviolation_domain、http_transfer_to_storage_site、suspicious_file_transfer、csendpoint_high_infection/lateralmovement/datadeleton、cloud_high_number_of_deletions/downloads、cloud_unusual_fileextension_access、dlp_* 系列(changed_name、multiple_sourcefile、multiple_types、print_multiple_policy、source_multiple_types、ssn_and_cc、web_personal)、pga_* 系列(fileaccess、dlptype、file_extension_printed、number_of_pages、number_of_print_jobs、unusualadevent)、daily_user_* 系列(dlp_file_transfer、dlpmatches、prints、usb_data_transfer、usb_denies、usb_file_write)、potential_confidential_documents_printed、badge 系列(Failed_Badge_Entry_Multiple_Doors、disabled_badge_access、unauthorized_activity_time、unauthorized_logintype、unauthorized_machine_login)、unusual_usb_plugin、multiple_usb_plugs 等。

**模型总量口径**:官方不公布单一总数;按文档可盘点出 4 大类 —— 批模型(含 Rare Events 13 变体 + 时序 5 + VPN 2 + Lateral Movement 1 + 官方详述 14)≈ 35+,数据映射表全量模型名约 70 个,异常规则约 60 条,流式模型若干(代表 4 个),威胁模型(全部批式,含 Kill-chain/Graph/Data-driven/Rule-based 四种计算)。

### 4. 支持的数据源

**必需数据源(顺序强制)**:
1. **HR 数据**(第一个接入):标识账号、分类账号类型、关联到自然人;
2. **Assets 资产数据**(第二个,来自 CMDB / Splunk ES / AD):跟踪设备行为、实体元数据、设备黑名单;需配合 DNS 做设备身份解析。

**身份解析数据源(至少其一,越全越准)**:Authentication(登录事件:IP↔主机名、IP↔账号、主机名↔账号)、DNS(IP↔主机名)、DHCP(IP↔MAC、IP↔主机名)、VPN(IP↔用户)。Windows AD 认证事件支持清单:4663、4672、4673、4698、4768、4769、4776、5140、5142、5144、5145、5156、5379、7045、8222 等 Event ID。

**Splunk Direct 连接器(CIM 合规)支持的数据源类型**:Authentication、Badge Access(门禁)、Cloud Data、Database、DHCP、DLP、DNS、Email、Endpoint、External Alarm、Firewall、HTTP、Host AV、NetFlow(nfdump/IPFIX)、Network IDS/IPS、Printer、USB logs、VPN、Windows PowerShell logs、Windows event logs(XML/multiline)、Cisco logs 等 20+ 类。

**其他接入方式**:Splunk Raw Events(UBA 原生解析器)、Generic data source(自定义,配 custom use case framework)、HR/Assets 专用数据源类型;UBA 5.4.0+ 经 **HEC(HTTP Event Collector)** 回传事件(弃用 TCP inputs.conf);大数据量可用 **Splunk UBA Kafka Ingestion App** 从索引器直发 UBA Kafka。

**用例 × 数据源映射(节选)**:Account Misuse / Compromised User Account(Authentication、Badge Access、Cloud Data、Email、Endpoint、External Alarm、VPN、AD);Compromised and Infected Machine(DLP、DNS、External Alarm、Firewall、HTTP、Network IDS/IPS、AD);Data Exfiltration(Cloud Data、DLP、Email、Firewall、HTTP、Network IDS/IPS、Printer、VPN);Lateral Movement(External Alarm、Network IDS/IPS、AD)。

### 5. 与 Splunk ES 的集成方式

- 集成组件:**Splunk Add-on for Splunk UBA** —— 不在 Splunkbase 单独提供,**随 Splunk ES 默认安装**。
- 双向数据流(4 类):
  1. UBA 的 **anomalies 与 threats → ES notable events**;
  2. **ES notable events → UBA**(供 UBA 的 External Alarm Analysis 等模型消费,如 critical 级 notable 超阈值生成 External Alarm Activity 异常);
  3. UBA **audit events → ES**;
  4. UBA **user/device association(用户设备关联)数据 → ES**。
- **状态双向同步**:ES 侧与 UBA 侧共享的 notable/threat 状态保持一致;操作规范:必须在 **ES 侧**关闭/重开 notable(对应 UBA threat 同步关闭/重开),**不要在 UBA 侧**直接关闭 threat。
- 原始事件下钻:UBA 异常详情页可跳回 Splunk 平台查看贡献异常的原始事件(event drilldown)。
- 版本演进:UBA 5.4.0+ 用 HEC 传输;新 ES Premier 的内置 UEBA 依赖 ES Risk Data Model(见第一部分 ERS)。

### 6. 生命周期(EOS 时间线佐证)★

官方公告页(help.splunk.com,UBA 5.4.5 Release Notes → Additional resources)明确:

- **2025-12-12:Splunk 宣布 standalone Splunk UBA End-of-Sale**,产品停止销售;
- **2027-01-31:End-of-Support / End-of-Life**,此后不再提供支持、修复与更新;在此之前存量客户可继续使用并获得支持与软件修复;
- 公告明确该决定仅针对**独立 UBA 软件产品**;官方原话:"Splunk has developed a new User and Entity Behavior Analytics (UEBA) capability that is part of the **Splunk Enterprise Security Premier (ES Premier)** product." —— 即继任者是 ES Premier 内置的新一代 UEBA 能力(行为基线 + UEBA detections + Entity risk scoring + Finding exclusions + Entity lists,见 ES 8.5 "User and entity behavior analytics" 手册);
- UBA 文档多个页面(data flow 等)已顶部挂 EOL 提示;最新文档版本线为 5.4.x(5.4.0~5.4.5)。
- 对自研的启示:Splunk 自己的演进路径是"独立 UEBA 设备 → 并入 SIEM 的风险评分 + 行为分析引擎",风险评分(RBA/ERS)成为两代产品共享的核心资产。

---

## 第三部分:来源 URL 列表

### ES 8.5 Risk-based alerting(administer 手册,base: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/)

| 主题 | URL |
|---|---|
| Risk scoring in Splunk Enterprise Security(章节首页) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting |
| Entity risk scoring in Splunk Enterprise Security ★ | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/entity-risk-scoring-in-splunk-enterprise-security |
| Using entity risk scores for detections ★ | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/using-entity-risk-scores-for-detections-in-splunk-enterprise-security |
| Assign risk using risk modifiers | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/assign-risk-using-risk-modifiers-in-splunk-enterprise-security |
| Adjusting risk using risk factors(公式+默认因子) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/adjusting-risk-using-risk-factors-in-splunk-enterprise-security |
| Create risk factors to adjust risk scores | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/create-risk-factors-to-adjust-risk-scores-in-splunk-enterprise-security |
| Review risk-based findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/review-risk-based-findings-in-splunk-enterprise-security |
| Reviewing findings using the intermediate findings timeline | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/reviewing-findings-using-the-intermediate-findings-timeline-in-splunk-enterprise-security |
| Access the intermediate findings timeline | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/access-the-intermediate-findings-timeline-to-review-findings-in-splunk-enterprise-security |
| Review findings using the threat topology visualization | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/review-findings-using-the-threat-topology-visualization-in-splunk-enterprise-security |
| Use risk based alerting instead of sequence templates | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/use-risk-based-alerting-instead-of-sequence-templates-to-detect-threats |
| (用户视角)Analyze risk with RBA in ES(用户手册) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.5/mission-control/analyze-risk-with-risk-based-alerting-in-splunk-enterprise-security |
| ES 8.5 内置 UEBA 概述(继任能力) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics |

### Splunk UBA(security-offerings,最新版本线 5.4.x)

| 主题 | URL |
|---|---|
| UBA 文档门户(手册总目录) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics |
| About Splunk User Behavior Analytics(概述) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/plan-and-scale/5.2.1/plan-and-scale-your-splunk-uba-deployment/about-splunk-user-behavior-analytics |
| Splunk UBA deployment architecture(架构) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/plan-and-scale/5.4.0/plan-and-scale-your-splunk-uba-deployment/splunk-uba-deployment-architecture |
| Splunk UBA models overview(模型总览/四分类) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.0/splunk-uba-models/splunk-uba-models-overview |
| Batch models(批模型清单) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.0/splunk-uba-models/batch-models |
| Time-series models | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.0/splunk-uba-models/time-series-models |
| VPN login related anomaly detection models | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.0/splunk-uba-models/vpn-login-related-anomaly-detection-models |
| Lateral Movement model | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.0/splunk-uba-models/lateral-movement-model |
| Which data sources do I need?(数据源+数据映射大表) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/which-data-sources-do-i-need |
| Understand data flow in Splunk UBA(管道) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/understand-data-flow-in-splunk-uba |
| Use connectors to add data(连接器) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/introduction/use-connectors-to-add-data-from-the-splunk-platform-to-splunk-uba |
| Integrate Splunk ES and Splunk UBA(Add-on) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/send-and-receive-data-from-the-splunk-platform/5.4.3/use-the-splunk-add-on-for-splunk-uba-to-send-and-receive-data-from-splunk-es |
| About the Splunk Add-on for Splunk UBA | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/send-and-receive-data-from-the-splunk-platform/5.4.1/introduction/about-the-splunk-add-on-for-splunk-uba |
| EOS/EOL 公告 ★ | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/release-notes/5.4.5/additional-resources/splunk-announces-end-of-sale-and-end-of-life-for-standalone-splunk-user-behavior-analytics-software |
| About Splunk UBA and release types(含 EOL 提示) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/install-and-upgrade/5.4.4/introduction/about-splunk-user-behavior-analytics-and-release-types |
