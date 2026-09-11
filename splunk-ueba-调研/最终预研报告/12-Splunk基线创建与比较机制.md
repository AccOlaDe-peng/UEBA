# Splunk 基线创建与比较机制

## 1. 结论摘要

Splunk 创建行为基线的核心过程是：**先把事件归属到稳定的用户或设备，再按时间窗口计算行为特征，使用实体历史、同伴组和企业全局行为形成参考分布，最后将当前窗口与这些参考分布及安全阈值比较。**

基线不是给每个用户设置一个固定的“正常值”，而是由多条不同维度的参考模型组成。例如，同一个用户可以同时具有登录次数、登录时间、常用设备、访问目标、失败认证、下载量和外发流量基线。

需要区分两个产品层次：

1. **独立 Splunk UBA**公开了批处理模型、流式模型、稀有事件模型、时间序列模型、同伴组和威胁模型等机制；部分模型公开了滑动窗口、移动平均、分位数、绝对阈值等比较方式，但没有公开全部特征、参数、公式和权重。
2. **Splunk Enterprise Security 内置 UEBA**公开说明其从多数据源抽取行为特征，学习用户或资产的历史基线，显著偏离时产生 Intermediate Finding，并参与 Entity Risk Score；底层 SPL 和检测逻辑通常不能由管理员直接修改。

对自研 UEBA 的关键启发是：**基线、当前特征、比较结果和模型版本都必须可追溯。系统不能只输出异常分数，还要说明当前值、历史参考值、同伴参考值、命中的阈值和原始证据。**

## 2. 什么是行为基线

以用户张三为例，系统可能维护以下基线：

| 行为维度 | 当前行为 | 历史参考 |
|---|---:|---|
| 每日登录次数 | 42 次 | 通常为每天 8～15 次 |
| 登录时间 | 02:13 | 通常为 08:30～20:00 |
| 登录设备 | SERVER-DB01 | 通常使用 LAPTOP-023 |
| 登录国家 | 德国 | 通常位于中国 |
| 每日外发流量 | 18 GB | 通常为 200 MB～1.2 GB |
| 访问服务器数量 | 37 台 | 通常为 3～8 台 |
| 失败登录次数 | 55 次 | 通常低于 3 次 |
| 访问对象 | 财务数据库 | 历史从未访问 |

从工程角度可以定义为：

```text
基线 = 实体 + 行为特征 + 统计粒度 + 历史窗口
     + 时间分段 + 参考群体 + 统计分布 + 模型版本
```

例如：

```text
实体：user_entity=E10293
特征：每日向外部地址发送的字节数
统计粒度：1 天
历史窗口：最近 30 天
时间分段：工作日
参考群体：个人、财务同伴组、全公司
统计量：均值、标准差、中位数、P95、P99
```

## 3. 创建基线的前提：稳定实体和统一事件

基线必须建立在实体解析之后：

```text
原始日志
  ↓
字段解析与 CIM/UBA 语义标准化
  ↓
账号、自然人、IP、设备解析
  ↓
稳定 user_entity_id / device_entity_id
  ↓
按实体计算行为特征
  ↓
形成和更新基线
```

如果直接按照日志中的 `user` 或 `src_ip` 聚合，会产生以下问题：

- `CORP\zhangsan`、`zhangsan@corp.example` 和 `adm_zhangsan` 被建成三套割裂基线；
- DHCP 地址复用导致不同设备共享同一 IP 基线；
- 域控、代理、VDI 等共享设备的行为被归给某个个人；
- Zeek 网络事件无法与 Windows 登录行为关联。

因此，实体解析的准确性、关系有效时间和置信度会直接决定基线质量。实体机制详见 [11-Splunk 实体识别与身份解析机制](11-Splunk实体识别与身份解析机制.md)。

## 4. 从事件抽取可比较的行为特征

Splunk UBA 不需要逐条比较当前日志与历史原文，而是先将事件转换成数值、集合、时间分布和序列特征。

### 4.1 数量与容量

```text
login_count_1h
login_failure_count_1h
download_count_24h
outbound_bytes_1h
outbound_bytes_24h
uploaded_file_size_24h
```

### 4.2 去重与覆盖范围

```text
distinct_src_ip_24h
distinct_device_24h
distinct_country_7d
distinct_server_24h
distinct_database_24h
new_destination_count_24h
```

### 4.3 时间行为

```text
first_login_hour
last_login_hour
night_activity_ratio
weekend_activity_ratio
session_duration
```

### 4.4 集合、首次出现和稀有性

```text
是否首次使用该设备
是否首次访问该服务器
是否首次在该国家登录
目标是否只被少量用户访问
应用是否属于用户历史常用集合
```

### 4.5 行为序列

```text
登录失败 → 登录成功
登录 → 权限提升 → 敏感文件访问
新设备登录 → 大量查询 → 外部传输
PowerShell 启动 → 下载文件 → 建立外联
```

【事实】Splunk UBA 的批处理模型在分析存储中的聚合数据上运行；官方资料将部分聚合结构称为 data cubes。流式模型逐事件处理短时间窗口，批处理模型分析较长时间范围。[Splunk UBA 模型概览](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/splunk-uba-models-overview)

## 5. 三层参考基线与规则阈值

### 5.1 个人历史基线

个人基线比较实体当前行为与其自身历史：

```text
张三今日外发 18 GB
张三历史通常每天外发 200 MB～1.2 GB
```

适合识别：

- 非常用时间登录；
- 首次使用设备或访问资源；
- 文件下载量突然增加；
- 访问资源范围扩大；
- 网络流量显著增长。

它回答的是：**这个实体现在是否偏离了自己的通常行为？**

### 5.2 同伴组基线

同伴基线将当前实体与行为或组织属性相近的实体比较：

```text
财务组每日外发量：
中位数 = 400 MB
P95 = 1.2 GB
P99 = 1.8 GB

张三今日外发 = 18 GB
```

UBA 公开的同伴组包括：

- Behavior Account Group：按照登录、会话、访问来源和目标等行为聚类；
- OU User Group：来自组织单位；
- AD Account Group：来自 AD 权限组；
- HR Peer Group：来自岗位、部门等人员属性；
- Device Group：按照设备网络行为分组。

【事实】UBA 使用聚类方法寻找行为相似的用户账号和设备；行为同伴组会参考登录、会话、AD 活动及访问来源和目标，并按日更新。[Splunk UBA Peer Groups](https://help.splunk.com/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.3/assess-security-posture/review-peer-groups-in-splunk-uba)

同伴基线可以缓解新用户缺少个人历史的问题，但岗位调动、权限变化和同伴组选择错误也会带来误报。

### 5.3 企业全局基线

全局基线比较实体与企业整体分布：

```text
全公司每日访问服务器数 P99 = 25 台
张三今日访问服务器数 = 37 台
```

它用于识别在个人历史或小规模同伴组中不明显、但在企业范围内极端的行为。

### 5.4 安全规则和绝对阈值

统计偏离通常需要与领域规则结合：

```text
外发流量必须大于 5 GB
失败登录必须超过 20 次
访问设备必须不少于 10 台
目标必须位于企业外部
```

绝对阈值避免低基线造成无安全意义的异常。例如某用户的日常外发量从 1 KB 增长到 10 KB，比例上增长十倍，但通常不构成数据外泄风险。

## 6. 基线的时间窗口

Splunk UBA 根据模型使用不同窗口：

| 窗口 | 典型范围 | 作用 |
|---|---|---|
| 流式短窗口 | 几分钟至一小时 | 序列、频率、扫描、Beacon、突发行为 |
| 当前评分窗口 | 一小时或一天 | 形成待比较的当前特征 |
| 历史训练窗口 | 多天至数周 | 估计均值、分布、分位数、集合和趋势 |
| 周期窗口 | 小时、工作日、周末、日、周 | 识别周期差异 |

【事实】UBA 流式模型逐事件分析，短窗口示例为过去一小时；批处理模型通常分析过去 24 小时等较大窗口，并通常在夜间运行。[Splunk UBA 模型概览](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/splunk-uba-models-overview)

【事实】公开的时间序列模型示例会为用户或设备建立每日和每周基线，并使用 30 天数据检测异常数据传输；这不表示所有 Splunk 模型都固定使用 30 天。[Splunk UBA Time-series Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/time-series-models)

## 7. 时间序列基线如何创建

以“用户每日向外部发送的字节数”为例。

### 7.1 按日聚合

```text
日期          外发流量
09-01         400 MB
09-02         520 MB
09-03         380 MB
09-04         610 MB
09-05         450 MB
09-06          19 GB
09-07         520 MB
```

### 7.2 处理历史极端值

【事实】部分 UBA 时间序列模型公开使用去除极端值后的 Gaussian moving average。其目的之一是避免一次历史异常显著抬高正常参考范围。[Splunk UBA Batch Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.2.1/splunk-uba-models/available-batch-models-in-splunk-uba)

示意如下：

```text
原历史序列：0.40, 0.52, 0.38, 0.61, 0.45, 19.0, 0.52 GB
清洗后序列：0.40, 0.52, 0.38, 0.61, 0.45, 0.52 GB
```

### 7.3 形成统计参考

基线可以维护：

```text
均值和移动平均
标准差或其他离散程度
中位数
P95/P99 等分位数
近期趋势
按小时、工作日和周末划分的周期分布
```

【边界】官方公开资料提到移动平均、估计分布、分位数偏移、硬阈值和高斯均值，但没有公开所有模型统一使用的数学公式、异常值清洗算法和参数。

## 8. 当前行为如何与基线比较

不同模型使用不同的比较方式。以下方式可以组合使用。

### 8.1 比例偏离

```text
ratio = current_value / baseline_mean
```

例如：

```text
历史均值 = 0.6 GB
当前值   = 18 GB
比例     = 30
```

公开的 UBA 时间序列模型会检查：

```text
current_value > baseline_gaussian_mean × ratio_threshold
并且
current_value > absolute_threshold
```

如果存在同伴组，还可以同时检查同伴组基线和比例阈值。比例阈值可配置。[Splunk UBA Time-series Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/time-series-models)

### 8.2 分布距离

一种便于理解的统计距离是：

```text
z = (current_value - mean) / standard_deviation
```

例如：

```text
历史均值 μ = 0.6 GB
标准差 σ   = 0.2 GB
当前值 x   = 18 GB

z = (18 - 0.6) / 0.2 = 87
```

【示例边界】z-score 用于说明如何度量偏离，不表示 Splunk 的所有模型都使用该公式。

### 8.3 分位数偏离

```text
历史 P95 = 1.3 GB
历史 P99 = 2.1 GB
当前值   = 18 GB
```

当前值超过历史 P99，可产生较高异常程度。分位数适合大量偏斜、长尾和零值较多的安全行为数据。

### 8.4 首次出现和稀有性

```text
用户历史登录国家 = {中国}
当前登录国家 = 德国
结果 = 首次出现
```

也可以计算群体稀有度：

```text
访问 DB-PROD-07 的用户数 = 2
公司总用户数 = 10,000
```

此类比较关注“是否见过”和“有多少同类实体做过”，而非数值增长比例。

### 8.5 时间分布偏离

```text
08:00—12:00   45%
12:00—18:00   40%
18:00—22:00   14%
00:00—05:00    1%
```

02:13 登录属于低概率时间行为，但应与设备、位置、认证结果和后续行为共同判断，避免仅凭夜间活动产生高风险结论。

### 8.6 多参考系综合比较

同一个当前特征可以得到多项偏差：

```text
个人历史偏差       0.92
同伴组偏差         0.88
企业全局偏差       0.76
绝对阈值命中       true
首次访问目标       true
```

【事实】Splunk 对部分模型的公开描述是：个人、同伴组和企业全局等多个参考来源均可产生偏移，每项偏移被评分，累计分数越多，异常越可疑。完整加权公式未公开。[Splunk UBA Batch Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.2.1/splunk-uba-models/available-batch-models-in-splunk-uba)

## 9. 稀有事件模型的比较方式

稀有事件模型关注当前行为或属性组合是否首次出现、很少出现，或者只出现在极少数实体中。

以 Windows 设备访问为例：

```text
主体：张三
动作：成功登录
对象：DB-PROD-07
时间：02:13
认证方式：远程交互
```

模型可以从多个维度检查：

```text
张三历史是否登录过 DB-PROD-07？
财务同伴组是否经常访问 DB-PROD-07？
全公司有多少用户访问过 DB-PROD-07？
张三是否经常在 02:00 登录？
该设备是否属于张三的常用设备？
```

单个条件不一定足以形成高风险异常，多个稀有条件共同出现时，综合可疑度会上升。

## 10. 基线如何更新与重新训练

基线可以通过滑动窗口持续更新：

```text
昨日历史窗口：08-12 ～ 09-10
今日历史窗口：08-13 ～ 09-11
```

新数据进入，最旧数据退出，使模型适应岗位、业务量和工作方式的变化。

但持续学习会产生“基线中毒”风险：

```text
攻击者每天缓慢增加外发量
  ↓
移动平均逐步升高
  ↓
恶意行为可能被学习为正常
```

因此应组合使用：

- 异常值剔除或降低异常样本权重；
- 长周期和短周期双基线；
- 个人、同伴组与全局多层参考；
- 不随历史变化的绝对安全阈值；
- 已知攻击规则、威胁情报和资产重要性；
- 模型版本、训练范围和重新训练策略；
- 岗位变更、休假、入离职等组织上下文。

【事实】Splunk UBA 的批处理模型支持在滑动数据窗口上重新计算训练和评分，并允许管理员制定模型重新训练策略。[Splunk UBA 模型概览](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/splunk-uba-models-overview)

## 11. 流式模型与批处理模型

### 11.1 流式模型

```text
事件到达
  ↓
更新最近几分钟或一小时的状态
  ↓
检查频率、序列和突发行为
  ↓
立即生成异常、IoC 或分析数据
```

适合检测：

- Beacon；
- 扫描；
- 短时间大量失败登录；
- 认证和攻击序列；
- 短时流量突增。

### 11.2 批处理模型

```text
一天内的事件
  ↓
形成聚合数据
  ↓
模型按计划运行
  ↓
与多日历史和同伴组比较
  ↓
生成异常和威胁
```

适合检测：

- 每日下载或外发量异常；
- 稀有文件和资源访问；
- 新设备访问；
- VPN 地点变化；
- 日、周周期变化；
- 较长时间范围的横向移动。

所有威胁模型在独立 UBA 中按批处理方式运行，它们可以在指定时间窗口内寻找多个异常组成的模式。

## 12. 从偏差到实体风险

基线比较只是风险链路的前半部分：

```text
当前行为
   │
   ▼
与历史、同伴和全局基线比较
   │
   ▼
数学偏差或异常分数
   │
   ▼
异常规则、最小阈值、抑制和重评分
   │
   ▼
Anomaly / Intermediate Finding
   │
   ├── 与其他异常按实体和时间关联
   ▼
Threat / Finding
   │
   ▼
用户或设备风险分数
```

需要区分：

1. **异常分数**：当前行为偏离参考基线的程度；
2. **威胁或 Finding 评分**：一个或多个异常是否构成有安全意义的模式；
3. **实体风险分数**：一段时间内用户或设备积累的总体风险。

行为偏离很大并不必然代表攻击。例如新员工第一次访问大量系统可能具有较高统计偏差，但如果符合入职配置流程，其安全风险可以被上下文或抑制规则降低。

【事实】UBA 可配置最低数学异常分数、最低可疑度阈值和异常数量阈值，并支持异常动作和评分规则。不同模型的默认参数和完整评分逻辑不完全公开。[Splunk UBA Batch Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.3/splunk-uba-models/batch-models)

## 13. Splunk ES 内置 UEBA 的公开机制

Splunk ES 的行为型 UEBA 检测公开流程为：

```text
认证、终端、网络等数据
  ↓
抽取登录频率、访问量等行为特征
  ↓
为用户或资产学习历史基线
  ↓
当前行为与基线比较
  ↓
显著偏离时生成 Intermediate Finding
  ↓
Finding 参与 Entity Risk Score
```

【事实】Splunk 官方说明，ES 中的行为型检测使用统计模型和机器学习，将用户或资产的当前行为与学习到的历史基线比较。管理员可以通过 Finding Exclusion 调整输出，但不能直接修改底层 SPL 或检测逻辑。[Splunk ES 行为型检测](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/behavior-based-detections-for-ueba-in-splunk-enterprise-security)

因此，公开资料可以确认“特征—实体基线—偏差—Finding—ERS”的产品链路，但不能据此还原每个内置检测的所有特征、算法、训练参数和权重。

## 14. Zeek 外发流量完整实例

目标是检测用户每日向外部地址发送的数据量是否异常。

### 14.1 将 Zeek 事件归属到用户

```text
Zeek conn.log：src_ip=10.10.8.25
             ↓ DHCP + Windows 登录事件
device_entity_id=D92381
user_entity_id=E10293
```

### 14.2 计算当前窗口特征

```text
窗口：2026-09-11 00:00—24:00

outbound_bytes_24h       = 18 GB
distinct_dest_ip_24h     = 42
new_dest_ip_count_24h    = 31
night_outbound_bytes_24h = 12 GB
connection_count_24h     = 8,300
```

### 14.3 读取个人和同伴基线

```text
用户近 30 日：
outbound_bytes_mean = 0.6 GB
outbound_bytes_p99  = 2.1 GB
distinct_dest_p99   = 12
night_bytes_mean    = 0.02 GB

财务同伴组：
outbound_bytes_p99  = 1.8 GB
distinct_dest_p99   = 15
```

### 14.4 执行比较

```text
18 GB > 用户 P99 2.1 GB
18 GB > 同伴组 P99 1.8 GB
42 个目标 > 用户历史 P99 12 个
31 个目标为首次出现
12 GB 发生在夜间
绝对外发流量阈值被突破
```

### 14.5 形成可解释输出

```json
{
  "entity_id": "E10293",
  "feature": "outbound_bytes_24h",
  "current_value": 19327352832,
  "personal_baseline_p99": 2254857830,
  "peer_baseline_p99": 1932735283,
  "new_destination_count": 31,
  "off_hours_ratio": 0.67,
  "absolute_threshold_hit": true,
  "anomaly_score": 0.97,
  "baseline_version": "example-v3"
}
```

【示例边界】上述数据、阈值、字段格式和异常分数用于说明自研实现，不代表 Splunk 内部事件格式或评分公式。

## 15. 对自研 UEBA 的基线数据模型建议

### 15.1 基线定义

```text
baseline_definition
├── baseline_id
├── entity_type
├── feature_name
├── aggregation_window
├── history_window
├── segmentation          工作日、周末、小时、地区等
├── reference_type        personal/peer/global
├── algorithm
├── parameters
├── minimum_samples
├── model_version
├── effective_from
└── effective_to
```

### 15.2 基线快照

```text
baseline_snapshot
├── baseline_id
├── entity_or_group_id
├── window_start
├── window_end
├── sample_count
├── mean
├── standard_deviation
├── median
├── p95
├── p99
├── known_value_set
├── quality_status
└── generated_at
```

### 15.3 当前特征与比较结果

```text
baseline_evaluation
├── entity_id
├── feature_name
├── window_start
├── window_end
├── current_value
├── personal_baseline_value
├── peer_baseline_value
├── global_baseline_value
├── personal_deviation
├── peer_deviation
├── global_deviation
├── absolute_threshold_hit
├── novelty_score
├── anomaly_score
├── baseline_version
└── evidence_event_ids
```

## 16. 冷启动、漂移和数据质量处理

### 16.1 冷启动

新用户或新设备没有足够历史样本时，应按以下顺序降级：

```text
个人基线样本充足 → 使用个人 + 同伴 + 全局
个人样本不足     → 使用同伴 + 全局
同伴组也不足     → 使用全局 + 绝对阈值
证据仍不足       → 标记低置信度，避免强结论
```

### 16.2 行为漂移

岗位调整、项目切换、出差和组织变更会引起正常行为变化。应保留：

- 短期基线和长期基线；
- 实体所属同伴组的历史版本；
- HR、部门、权限和设备归属变更时间；
- 基线重新训练时间及触发原因。

### 16.3 数据缺口

基线异常也可能源于数据异常：

```text
采集停机 → 当前计数异常降低
积压集中补传 → 当前计数异常升高
身份解析失败 → 用户特征突然减少
字段映射变更 → 特征口径前后不一致
```

因此评分前应检查数据完整度、延迟、解析率和模型版本。低质量窗口不应直接用于更新基线。

## 17. 必须监控的基线质量指标

- 每个实体和特征的有效样本数；
- 个人基线覆盖率、同伴组覆盖率；
- 冷启动实体数量；
- 基线生成延迟和失败率；
- 当前窗口数据完整度；
- 被极端值处理排除的样本比例；
- 同伴组每日变动率；
- 分数分布和超过阈值的实体比例；
- 异常点进入训练窗口的比例；
- 不同模型版本的告警量和人工确认率；
- 迟到数据引起的历史重算数量；
- 数据源、字段映射变更后的特征漂移。

## 18. 最终判断

Splunk 的基线和比较机制可以概括为：

```text
实体解析
  ↓
按时间窗口聚合行为特征
  ↓
形成个人、同伴和全局参考分布
  ↓
使用比例、分位数、统计距离、首次出现和绝对阈值比较
  ↓
生成异常分数
  ↓
结合时间、上下文和其他异常形成 Finding/Threat
  ↓
累计到实体风险
```

自研 UEBA 不应只实现“过去 30 天平均值加三倍标准差”。稳定的系统需要同时处理实体归属、周期性、长尾分布、同伴组、冷启动、基线漂移、异常污染、数据缺口和模型版本。

面向分析师的结果应至少解释：

> 当前值是多少；个人、同伴和全局参考值是多少；偏离发生在哪个维度；命中了哪些绝对条件；使用了哪个基线版本；哪些事件支持这个结论。

## 19. 主要官方资料

1. [Splunk UBA Models Overview](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/splunk-uba-models-overview)
2. [Splunk UBA Time-series Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.5/splunk-uba-models/time-series-models)
3. [Splunk UBA Available Batch Models](https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.2.1/splunk-uba-models/available-batch-models-in-splunk-uba)
4. [Splunk UBA Peer Groups](https://help.splunk.com/security-offerings/splunk-user-behavior-analytics/use-splunk-user-behavior-analytics/5.4.3/assess-security-posture/review-peer-groups-in-splunk-uba)
5. [Splunk ES Behavior-based Detections for UEBA](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.3/user-and-entity-behavior-analytics/behavior-based-detections-for-ueba-in-splunk-enterprise-security)
6. [Splunk ES UEBA Overview](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/user-and-entity-behavior-analytics/user-and-entity-behavior-analytics-ueba-overview-in-splunk-enterprise-security)
