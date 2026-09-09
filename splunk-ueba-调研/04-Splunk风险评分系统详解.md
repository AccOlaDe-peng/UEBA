# Splunk 风险评分系统详解(RBA + ERS)

> 调研时间:2026-09-09。资料来源:help.splunk.com《Splunk Enterprise Security 8.5 管理手册》Risk-Based Alerting 与 User and Entity Behavior Analytics 章节(官方原文逐页提取,来源 URL 见文末)。
> 定位:面向自研 UEBA 的风险评分体系设计参考。Splunk 风险评分是其 UEBA 能力的核心资产——独立产品 UBA 停售后,风险评分引擎被完整继承进 ES 8.x 内置 UEBA,是两代产品共享的骨架。

---

## 一、体系全景:两级评分架构

Splunk 的风险评分分**事件层**和**实体层**两级,中间由风险因子/修饰做调分,形成"检测产分 → 调分 → 聚合 → 以分做检测"的闭环:

```
检测命中(搜索匹配可疑行为)
   │  写入 risk index
   ▼
intermediate finding(中间发现,带 risk_score + MITRE 标注)     ← 事件层
   │  风险因子(risk factors)调分:(base + Σ加法) × Π乘法
   │  风险修饰(risk modifiers):多实体加分 / threat object / 0分上下文
   ▼
聚合:finding-based detection 按实体求和,超阈值 → finding(进调查队列)
   │  每 20 分钟
   ▼
实体风险分 ERS(7 天窗口,归一化 0–100,存 ers index)            ← 实体层
   │
   ├─▶ 仪表盘/徽章展示(Risk analysis、UEBA 仪表盘、Analyst queue)
   ├─▶ 反哺检测:ers>=80 触发 finding-based detection(飞轮)
   └─▶ 调查:时间线 + 威胁拓扑 + 手动 ad-hoc 调分回写
```

**关键认知**:Splunk 里"风险"永远是挂在**实体**(asset/identity/user/device,类型分 `system`/`user`,支持自定义)上的;单条事件只是"贡献分",真正的评分对象是实体随时间的累计风险。

## 二、事件层:intermediate finding 与风险累加

### 2.1 intermediate finding(中间发现)

- 检测(correlation search / event-based detection)匹配到可疑行为后,写入 **risk index**,即 ES 8.0+ 术语的 intermediate finding(取代旧称 risk event)。
- 最小字段集:`risk_score`(整数)、`risk_object`(实体值)、`risk_object_type`(system/user/自定义)、`risk_message`(描述,支持 `$field$` 引用事件字段)。
- 检测编辑器中可为成功/失败行为差异化打分(如成功 HTTP POST = 20 分、失败 = 0 分);**0 分修饰**仍写入索引作为上下文但不抬分。
- 一个检测可 `+Add entity` 给多个实体同时加分;多实体场景官方建议主实体用 Finding、附加实体用 Intermediate Findings。
- SPL 打分方式:`... | sendalert risk param._risk_object_type="system" param._risk_object=<field> param._risk_score=<int>`。

### 2.2 风险累加规则

- **finding 风险分 = 贡献它的所有 intermediate finding 分数之和**(官方示例:10+20+30+40+50 = 150)。
- **实体归一化** `normalized_risk_object`:同一身份的多个显示名(`rob`、`rob@splunk.com`、`rob@splunk`)合并计分;显示名取出现频次最高者,计分依据 Asset/Identity lookup 第一个匹配项。
- **entity zones(实体区域)**:为同名实体增加地理/部门上下文,避免不同部门同名账号、不同地区同 IP 的分数被错误合并——一个防"错误合并导致误报"的细节设计。
- 检索口径:基于 **Risk Data Model**(`from datamodel:"Risk.All_Risk"`),而非裸索引搜索。

## 三、调分层:风险因子(risk factors)与风险修饰(risk modifiers)

### 3.1 风险因子公式 ★

```
(risk_base_score + Σ 加法因子) × Π 乘法因子
```

- **加法因子总是先于乘法因子应用**。官方示例:base 5,+5,+6,×2,×2 → (5+5+6)×2×2 = **64**。
- 因子按**实体元数据**条件触发(优先级、类别、watchlist 等),无需编写新搜索;存于 `risk_factors.conf`。
- 条件配置:Basic(字段=值)或 Advanced(**8 种比较器**:等于/不等于/regex/like/≥/≤/>/<),多条件 AND,支持"值取自另一字段";保存前可预览匹配的风险事件。
- 两个口径:Base risk score(单事件,经因子调整后为 calculated risk score)、Total risk score(实体在时间窗内全部 calculated risk score 之和)。

**内置 7 个默认风险因子(默认全部关闭)**:

| 风险因子 | 条件 | 操作 |
|---|---|---|
| Admin user | `user_category` 匹配 "admin" | ×1.5 |
| Contractor user | `user_category` = "contractor" | +5 |
| Critical priority destination | `dest_priority` = "critical" | ×1.5 |
| High priority user | `user_priority` = "high" | ×1.25 |
| PCI source | PCI 合规相关源 | 提分 |
| Watchlisted user | `user_watchlist` = "true" | ×1.5 |
| Watchlisted priority user | watchlist 且 priority ≠ low | ×1.5 |

组合示例:修饰 120 分 + "priority=critical 加 50" → 170;AWS GuardDuty/Security Hub critical 告警 ×2.5;watchlist 用户 × critical 资产 ×1.2。

**设计语义**:因子的本质是"**同样行为,不同身份/资产的权重不同**"——总监笔记本的可疑行为比普通员工更值得关注。这是把组织上下文(资产/身份数据)注入评分的标准化接口。

### 3.2 风险修饰(risk modifiers)

- 定义:写入 risk index 的**事件型加分**,最小字段集同上(risk score / risk object / risk object type)。
- 除检测自动产分外,支持**手动风险条目**(Risk analysis → Ad-Hoc Risk Entry):可输入**负分**对冲(如 -180),用于"关闭 finding"时人工中和;由于分数按时间窗计算,原始事件滑出窗口后负分会短暂生效——一个值得注意的边界行为。
- **Threat object(威胁对象)作为修饰**:检测中可附加 threat object(payload、域名、IP、文件名、注册表键等)+ 类型(file_hash、domain、URL、IP、command line、process name),把"实体与什么威胁对象发生过交互"存进风险事件——这是威胁拓扑可视化的数据基础。

## 四、实体层:实体风险分 ERS(ES 8.3+)★

ERS(Entity Risk Score)是"基于规则的风险评分 + 加权、数据驱动的因子分析"的**混合模型**,度量实体的整体风险等级。

- **窗口与量纲**:过去 **7 天**,归一化 **0–100**。
- **计算**:计划搜索 `Risk - EWA Entity Risk Score Calculation`(官方警示:勿修改),**每 20 分钟**运行,针对 7 天内至少有 1 条 intermediate finding 的实体。
- **ERS = 5 个组件的加权平均**(输入来自 risk index 的 findings):
  1. 所有 intermediate finding 的 `calculated_risk_score` **总和**(总量);
  2. 单条**最大**分(最恶劣单次行为);
  3. 分数 **≥50 的发现数量**(高危次数);
  4. 发现**总数**(频次);
  5. **跨检测求和——每个 detection 只取其最高分再累加**(防止单一检测反复触发刷分)★
- **存储**:`ers` index。**展示**:4 档徽章配色 0–25 黄 / 25–50 橙 / 50–75 浅红 / >75 深红;只展示 7 天内有风险事件的实体;按 ATT&CK tactic 拆解、可 Show calculation(分数可解释)。
- **防刷分设计**是 ERS 组件选取的精髓:同时约束"总量、峰值、高危次数、频次、检测多样性"五个维度,任何单一维度暴涨都无法独力推高实体分。

## 五、闭环:实体分反哺检测

- **以分做检测**:ERS 写入 `ers` index 后,可建 finding-based detection 按阈值自动生成 finding。官方示例(用户 ERS > 80 报警):

  ```
  index=ers ers>=80 risk_object_type=user
  | stats max(ers) as entity_risk_score values(detections) as detections by normalized_risk_object
  ```

- **Cumulative entity risk 分组**:finding-based detection 中选 Group type = "Cumulative entity risk",按实体累计分阈值生成高置信 finding group,压低告警量。
- **完整闭环**:event-based detection 产分 → 因子/修饰调分 → ERS 聚合 → finding-based detection 按分报警 → 调查结论(关闭 finding 时)通过手动/自动 risk entry 回写调分。
- **行为链检测**:ES 8.0+ 用 RBA 替代 sequence templates——SPL 组合 `delta`(计时差)+ `autoregress`(取上一行)+ `where gap<600`(限窗口)检测多步行为链,链式命中可生成一个更高分的新风险事件。

## 六、调查与可视化

| 能力 | 要点 |
|---|---|
| finding 关键字段 | Entity、Entity type、Risk score(可被因子修改)、Risk event count、Risk message、Threat object/type;辅助字段 `drilldown_search/earliest/latest` 定义贡献事件回溯(需返回 `calculated_risk_score`) |
| 中间发现时间线 | X=时间 Y=分数散点图;头部显示实体、风险分、阈值、发现数;点颜色编码风险等级;tooltip 含 detection、MITRE 标注;明细表最多 100 条;由宏 `risk_event_timeline_search` 驱动 |
| 威胁拓扑 | 展示**实体之间如何通过共享 threat object 关联**(超越单实体视角);单次最多 20 个实体;连边依据是不同实体的中间发现引用同一威胁对象 |
| ATT&CK posture | 调查内矩阵图展示该实体所有事件的战术/技术覆盖 |
| Risk analysis 仪表盘 | 按实体/按 MITRE 标注两个视图,可下钻 Timeline;含 ba_test 与 risk index 对比视图(灰度验证用) |

## 七、对自研 UEBA 评分体系的设计启示

1. **两级结构是骨架**:事件级贡献分(intermediate finding,带 MITRE 标注)+ 实体级综合分(0–100 归一化),不要试图用单层分数同时表达"事件恶劣度"和"实体危险度"。
2. **ERS 五组件防刷分**值得直接借鉴:总和、峰值、高危次数、频次、跨检测多样性——多维约束天然抵抗单规则高频误报拉高实体分。
3. **风险因子 = 组织上下文的标准化注入接口**:`(base + Σ加法) × Π乘法`、因子挂在实体元数据(优先级/类别/watchlist)上、内置因子默认关闭——把"谁更重要"和"行为多可疑"解耦。
4. **实体归一化 + entity zones** 提醒我们:实体身份解析(同一人多账号、同名不同人)必须在计分之前解决,否则分数要么漏要么错。
5. **分数必须可解释**:Show calculation、按 ATT&CK tactic 拆解、时间线逐点下钻,是分析师信任分数的前提;自研系统应把"每个分为什么来"作为一等公民设计。
6. **评分闭环**:`ers>=80 反哺检测`让评分系统成为"检测的检测器";人工调分(含负分中和)要有生命周期治理( Splunk 的教训:负分在时间窗滑出后会短暂失效)。
7. **威胁对象先行**:风险事件里记录"与哪个威胁对象交互过"(域名/文件哈希/进程名),才能支撑后续的实体关联拓扑——这比事后从日志重建便宜得多。

## 八、来源 URL

| 主题 | URL |
|---|---|
| Risk scoring(章节首页) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting |
| Entity risk scoring(ERS)★ | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/entity-risk-scoring-in-splunk-enterprise-security |
| Using entity risk scores for detections ★ | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/using-entity-risk-scores-for-detections-in-splunk-enterprise-security |
| Assign risk using risk modifiers | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/assign-risk-using-risk-modifiers-in-splunk-enterprise-security |
| Adjusting risk using risk factors(公式+默认因子) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/adjusting-risk-using-risk-factors-in-splunk-enterprise-security |
| Create risk factors | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/create-risk-factors-to-adjust-risk-scores-in-splunk-enterprise-security |
| Review risk-based findings | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/review-risk-based-findings-in-splunk-enterprise-security |
| Intermediate findings timeline | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/reviewing-findings-using-the-intermediate-findings-timeline-in-splunk-enterprise-security |
| Threat topology visualization | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/review-findings-using-the-threat-topology-visualization-in-splunk-enterprise-security |
| RBA 替代 sequence templates | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/risk-based-alerting/use-risk-based-alerting-instead-of-sequence-templates-to-detect-threats |
| 8.5 内置 UEBA 概述(ERS 所在体系) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics |

> 相关分册:[00-总览](00-总览.md) · [01-UEBA检测与数据源](01-UEBA检测与数据源.md) · [02-部署配置与运营功能](02-部署配置与运营功能.md) · [03-风险评分RBA与Splunk-UBA](03-风险评分RBA与Splunk-UBA.md)(含 UBA 老产品模型体系)
