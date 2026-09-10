# Splunk 平台整体预研

> 目标:让读者在 30 分钟内快速、完整、直观地了解 Splunk——它是什么、怎么工作、产品版图如何、值不值得用/怎么用。
> 日期:2026-09-10。本文是平台级总览;UEBA/RBA 专项内容见同目录 00~05 分册,此处只做串联性简介。

---

## 一、一句话认识 Splunk

**Splunk 是一个"机器数据"搜索与分析平台**:任何格式、任何来源的日志/事件/指标,采集进来后建立索引,然后用类 SQL 的搜索语言(SPL)实时查询、统计、可视化、告警。业内常用类比:

- 像 **Elasticsearch + Kibana 的商用整合版**,但 ingestion 免 schema、可视化/告警/权限开箱即用;
- 像 **"日志界的数据库"**:数据落盘为可检索的分布式存储,查询即算力;
- 在安全领域它是 **SIEM 市场常年第一**(Gartner MQ Leader),也是本文档团队最关心的用途。

关键数字与现状:

| 项目 | 现状 |
|---|---|
| 公司归属 | 2024-03 被 **Cisco 以约 280 亿美元**完成收购,定位为 Cisco 安全与可观测性的数据/AI 核心 |
| 主要版本线 | Splunk Enterprise **9.4.x**(本地部署)/ Splunk Cloud Platform(托管) |
| 两大业务 | **安全**(SIEM=Enterprise Security、SOAR、UEBA)与 **可观测性**(Observability Cloud:APM/日志/指标/trace) |
| 商业模式 | 按每日采集量(GB/天)计 license;Cloud 订阅制;对规模敏感(见"第七节 成本") |

---

## 二、核心工作原理:数据流水线(必须理解的一张图)

```
数据源                      转发层               索引层                搜索层
──────                  ──────────          ─────────           ─────────
服务器日志 ─┐                                  ┌─ Indexer ─┐
网络设备  ──┤→ Universal Forwarder ──┐         │  (集群×N)  │ ←─ Search Head ──→ 用户/仪表盘/告警
终端/EDR  ──┤   (轻量 agent,不解析)   ├→ (Heavy ├─ 存储为   │    (搜索分发、
应用/API  ──┘                        │ Forwarder│   bucket)  │     SPL 解析、
Syslog/HEC/文件                     └──────────┘  索引+压缩  │     报表、可视化)
```

数据的四个处理阶段(Splunk 管道):**Input(输入)→ Parsing(解析:断行、时间戳抽取、sourcetype 识别)→ Indexing(索引:分桶存储、建倒排索引)→ Search(查询时才计算)**。

理解 Splunk 的 4 个关键点:

1. **Schema on read**:写入时不强制字段结构,搜索时才按需抽取字段(对比数据库的 schema on write)。好处是任意数据直接进,坏处是查询时若不预先抽取字段则慢——所以有"字段提取(FIELDALIAS/EXTRACT/计算字段)"的知识管理机制。
2. **时间是一等公民**:每个事件必有 `_time`,绝大多数查询按时间范围裁剪;`_raw` 保存原始报文,永远可回溯。
3. **存储结构**:索引按时间分 **bucket**(hot→warm→cold→frozen,可配 SmartStore 把冷数据放 S3 等对象存储),天然适合"近热远冷"的安全数据留存策略。
4. **搜索即计算**:SPL 查询由 Search Head 分发到各 Indexer 并行执行后归并,扩展靠加 indexer(横向)。

---

## 三、部署架构与核心组件

| 组件 | 角色 | 说明 |
|---|---|---|
| **Universal Forwarder (UF)** | 采集 agent | 极轻量(~几十 MB),只转发不解析;装在每台数据源上 |
| **Heavy Forwarder (HF)** | 中间转发/预处理 | 完整 Splunk 实例,可解析、过滤、路由、改写数据;syslog 集中接收常用它 |
| **Indexer (集群中叫 peer node)** | 存储+检索 | 负责索引与数据存储,集群由 **Cluster Manager** 管理(多副本复制因子) |
| **Search Head (SH)** | 查询入口 | 接收搜索、分发、归并;承载 App/仪表盘/告警;可做 SH Cluster(SHC)高可用 |
| 部署服务器 Deployment Server | 运维 | 向成百上千个 UF 下发配置/App |
| License Manager / Monitoring Console / Deployer | 支撑 | 许可、健康监控、SHC 应用发布 |

**典型规模**:POC 用单机 All-in-One(即免安装的"本地 UEBA 检测详解"分册中的实验环境);生产安全场景常见 UF ×数千 → 若干 HF → 3~20 个 indexer 集群 + 3+ SHC。云端则对应 Splunk Cloud,组件托管,用户拿到的是 Victoria 体验(自管能力受限、免运维)。

---

## 四、SPL:与 Splunk 打交道的语言(10 分钟能上手)

SPL(Search Processing Language)是**管道式**:数据从左到右流经一串命令,像 Unix 管道。

```spl
# 例:找过去 1 小时失败登录超过 10 次的用户并告警
index=auth sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+)"
| stats count AS failures, values(src_ip) AS srcs BY user
| where failures > 10
```

常用命令速查:

| 类别 | 命令 |
|---|---|
| 过滤 | `search`、`where` |
| 统计 | `stats`(count/avg/dc…)、`eventstats`(全局回填)、`streamstats`(流式累计)、`timechart`、`top/rare` |
| 变换 | `eval`(算字段)、`rex`(正则提取)、`lookup`(维表 join)、`iplocation`、`geostats` |
| 关联 | `join`、`append`、`appendcols`、`transaction`(会话化) |
| 机器学习 | `fit`/`apply`(MLTK 应用:聚类、异常打分、预测) |
| 保存/输出 | `outputlookup`(写 KV Store 表)、`sendalert`、`collect`(写回索引) |

直观感受:Stats+eval+rex 三个命令覆盖日常 80% 需求;SPL 学习曲线平缓,但写复杂检测(如基线对比、会话重建)时性能调优是门手艺。

---

## 五、知识管理与 App 生态(让"任意日志"变成"结构化事件")

1. **知识对象**:字段提取(extract)、别名、计算字段、事件类型、tag、lookup 表、宏、数据模型——这些把原始日志"翻译"成统一语义。
2. **CIM(Common Information Model)**:官方定义的标准字段模型(如 Authentication、Network_Traffic、Endpoint…)。**所有安全检测都建立在 CIM 之上**——异构日志规范化成相同字段后,一条规则才能跨设备复用。这是 Splunk 生态最值得借鉴的设计(我们自研 UEBA 的数据规范层可直接对标)。
3. **App/TA(Technical Add-on)**:
   - **TA** 负责采集与解析(把某产品的日志解析成 CIM 字段),Splunkbase 上有 2000+ 官方/第三方 TA(Windows、Cisco、Palo Alto、Okta…);
   - **App** 负责展示与用例(仪表盘、告警、检测规则)。
4. **Splunkbase + .spl 安装**:本地部署完全支持离线安装 App;Cloud 需走 App 审核流程。

---

## 六、产品版图:平台之上叠安全与可观测性

```
                    ┌────────────────────────────┐
   安全产品线        │ Enterprise Security (SIEM) │ ← 检测规则/事件管理/RBA 风险评分
                    │ Splunk SOAR (Phantom)      │ ← 剧本自动化响应
                    │ ES 内置 UEBA + BA Service   │ ← 行为分析(见分册 00-05)
                    ├────────────────────────────┤
   可观测性产品线    │ Observability Cloud         │ ← APM/日志/指标/trace/RUM
                    ├────────────────────────────┤
   底座(本文主角)   │ Splunk Enterprise / Cloud   │ ← 采集、索引、SPL、仪表盘、告警
                    └────────────────────────────┘
```

安全产品线速览(与我们 UEBA 预研直接相关):

- **Enterprise Security(ES)**:付费 Add-on 叠加在平台上。核心能力:相关性搜索规则(内置数百条映射 MITRE ATT&CK)、notable event 事件管理、威胁情报管理、**Risk-Based Alerting(RBA)**——先给事件/实体累积风险分、超过阈值才告警,是降误报的主流方法论。ES 8.x 进一步把 UEBA(findings、实体风险分 ERS)内置,取代独立 UBA 产品(UBA 已 EOL,详见分册 00 与 04)。
- **Splunk SOAR**:剧本(playbook)自动化,与 ES 事件联动做自动响应。
- **安全成熟度路径**:基础平台(搜索+仪表盘)→ CIM 规范 → ES 检测 → RBA 风险评分 → UEBA 行为分析 → SOAR 自动响应。我们的本地实验环境(分册 05)正处于"基础平台+自研检测"阶段。

---

## 七、License 与成本(选型关键约束)

- **计量单位:每日索引的数据量(GB/天)**,与用户数、索引数据总量无关(留存存储另算硬件/云费)。搜索、告警、仪表盘不限量。
- 档位:免费(500MB/天,功能受限)→ Dev/Test → 生产 license(几十 GB/天 到 数 TB/天,越贵单价越低但总量成本可观)。Cloud 按订阅(VCPS)。
- **成本控制是运营常态**:Ingest Actions(采集时过滤/路由/脱敏)、路由到无 license 的 summary index、把高保留期数据转对象存储(SmartStore)。业界常见"把 30%~50% 噪音日志在转发层丢弃"的做法。
- 本地部署资源经验值:单 indexer 每核心每天约索引 50~150GB(视数据类型),安全日志典型留存 90 天~1 年 → 磁盘与节点数按此估算。

---

## 八、优势与局限(决策视角)

**优势**
1. 数据接入能力最强:2000+ 现成 TA,异构日志"开箱即解析";
2. SPL + 实时搜索,交互式调查体验业界标杆;
3. 安全内容生态厚:ES 内置检测规则全映射 ATT&CK,RBA/UEBA 方法论成熟可直接借鉴;
4. 单一平台吃下 SIEM/日志分析/可观测性,企业粘性高。

**局限**
1. **贵**:按量计费,数据量增长直接推高成本,大客户普遍抱怨 license 费用;这正是 Cribl 等日志路由器兴起的土壤;
2. 生态相对封闭:自有存储格式(闭源,不能像 ES 那样直接读文件)、SPL 不可移植;
3. 长时序聚合/大历史扫描性能一般(索引按时间分桶,跨全量统计需靠 summary index/数据模型加速);
4. 本地部署运维重(集群、容量规划);Cloud 版失去部分底层控制。

**对比参照**(一句话版):
- vs **Elastic Security**:ES 生态更开放、成本结构更灵活;Splunk 现成内容与开箱体验更强。
- vs **Microsoft Sentinel**:云原生按分析量计费,与 Defender/Entra 深度整合;Splunk 跨厂商中立性更好。
- vs **自研(我们的场景)**:Splunk 是方法论金矿(CIM、RBA、findings、ERS、peer group、风险因子),即便不采购,其设计与分册 04/05 的落地笔记也直接指导自研实现。

---

## 九、动手路径(POC 建议)

1. **最小环境**:Docker 或单机包跑 Splunk Enterprise(免费 500MB/天),Web UI 8000 端口;
2. 接两类数据:Windows 事件日志(UF)+ 一份 syslog/Zeek 样本,体验 Input→Search 全流程;
3. 装 **Splunk Common Information Model** 与 **Security Essentials(免费)** App,体会 CIM 规范化与内置检测;
4. 用 SPL 复现一个典型检测:失败登录 burst → `stats` 聚合 → `where` 阈值 → 保存为告警;
5. 进阶:按分册 05 搭本地 UEBA 检测(risk 索引 + RBA 评分 + ERS),验证我们自研方案对标的设计。

---

## 十、延伸阅读

- 官方文档入口:https://help.splunk.com (Splunk Enterprise 9.4 / ES 8.x / UBA 5.4)
- Splunkbase:https://splunkbase.splunk.com
- Cisco 收购公告:https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2024/m03/cisco-completes-acquisition-of-splunk.html
- 本仓库分册:00-总览、01-UEBA检测与数据源、02-部署配置与运营功能、03-风险评分RBA与Splunk-UBA、04-Splunk风险评分系统详解、05-本地UEBA检测详解与实现
