# Splunk 本地 UEBA 内置检测清单（119 条）

## 1. 口径说明

本文中的“本地事件”按 **Splunk Enterprise Security on-premises 的 UEBA 内置检测**理解。准确对象是检测规则及其命中后生成的 Intermediate Finding，不是 Splunk 平台 `_internal` 索引中的进程、组件和运行日志。

【事实】Splunk 官方的 on-premises UEBA detection reference 当前列出这组检测；UEBA Content App for On-premises（`DA-ESS-UEBAContent`）包含这些内容。

- 官方清单：[UEBA detection reference for UEBA on-premises](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/ueba-detection-reference-for-ueba-on-premises)
- 产品说明：[Splunk ES UEBA overview](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/user-and-entity-behavior-analytics/user-and-entity-behavior-analytics-ueba-overview-in-splunk-enterprise-security)

【边界】官方参考页主要公开检测名称。下表的中文名称是忠实翻译；“核心特征、安全意义、检测机制”根据名称、检测族和官方公开机制整理，用于预研和需求映射，不代表已获得对应 Content App 的完整 SPL。具体窗口、阈值、特征权重和抑制条件需要在持证环境中核验。

## 2. 分类统计

| 分类 | 数量 |
|---|---:|
| 网络流量与数据传输异常 | 34 |
| 认证与登录行为异常 | 34 |
| 打印行为异常 | 24 |
| USB 外设行为异常 | 8 |
| 邮件外发与 DLP 异常 | 7 |
| 账号管理与日志篡改异常 | 5 |
| HTTP / Web 代理访问异常 | 4 |
| 主机失陷关联检测 | 3 |
| **合计** | **119** |

## 3. 字段说明

| 字段 | 用途 |
|---|---|
| 官方检测名称 | 与 Splunk Content Management 中规则名称对照 |
| 中文名称 | 供汇报、需求和场景评审使用 |
| 检测主体 | 说明特征按用户、设备、打印机或账号聚合 |
| 比较范围 | 区分实体自身历史、公司同伴组、业务单元同伴组或固定规则 |
| 核心特征或条件 | 说明模型实际需要统计或匹配的数据 |
| 检测机制 | 区分统计基线、时间基线、稀有度、时序规则和关联检测 |
| 主要数据源/CIM | 用于判断数据接入和标准化前置条件 |
| 安全意义 | 说明检测希望发现的风险行为 |

## 4. 完整清单

### 4.1 网络流量与数据传输异常（34 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 1 | `UEBA - Unusual Volume of Outgoing Connections per Device by Company - Rule` | 出站连接数量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 2 | `UEBA - Unusual Volume of Outgoing Connections per Device by Business Unit - Rule` | 出站连接数量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 3 | `UEBA - Unusual Volume of Outgoing Connections per Device - Rule` | 出站连接数量异常（设备） | 设备 | 实体个人历史/规则范围 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 4 | `UEBA - Unusual Volume of Outgoing Connections Per User By Company - Rule` | 出站连接数量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 5 | `UEBA - Unusual Volume of Outgoing Connections Per User By Business Unit - Rule` | 出站连接数量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 6 | `UEBA - Unusual Volume of Outgoing Connections Per User - Rule` | 出站连接数量异常（用户） | 用户 | 实体个人历史/规则范围 | 出站连接数 | 统计基线 | 发现失陷主机外联、扫描或异常通信扩张 |
| 7 | `UEBA - Unusual Volume of Data Uploaded per User by Company - Rule` | 上传数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 8 | `UEBA - Unusual Volume of Data Uploaded per User - Rule` | 上传数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 9 | `UEBA - Unusual Volume of Data Uploaded per Device by Company - Rule` | 上传数据量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 10 | `UEBA - Unusual Volume of Data Uploaded per Device by Business Unit - Rule` | 上传数据量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 11 | `UEBA - Unusual Volume of Data Uploaded per Device - Rule` | 上传数据量异常（设备） | 设备 | 实体个人历史/规则范围 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 12 | `UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User By Company - Rule` | 向 DMZ 设备上传数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 上传至 DMZ 的字节数 | 统计基线 | 发现向 DMZ 异常落地或中转数据 |
| 13 | `UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User By Business Unit - Rule` | 向 DMZ 设备上传数据量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 上传至 DMZ 的字节数 | 统计基线 | 发现向 DMZ 异常落地或中转数据 |
| 14 | `UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User - Rule` | 向 DMZ 设备上传数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 上传至 DMZ 的字节数 | 统计基线 | 发现向 DMZ 异常落地或中转数据 |
| 15 | `UEBA - Unusual Volume of Data Downloaded per User by Company - Rule` | 下载数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 16 | `UEBA - Unusual Volume of Data Downloaded per User - Rule` | 下载数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 17 | `UEBA - Unusual Volume of Data Downloaded per Device by Company - Rule` | 下载数据量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 18 | `UEBA - Unusual Volume of Data Downloaded per Device by Business Unit - Rule` | 下载数据量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 19 | `UEBA - Unusual Volume of Data Downloaded per Device - Rule` | 下载数据量异常（设备） | 设备 | 实体个人历史/规则范围 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 20 | `UEBA - Unusual Volume of Data Bytes per Device by Company - Rule` | 总数据流量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 总传输字节数 | 统计基线 | 发现设备通信量突增 |
| 21 | `UEBA - Unusual Volume of Data Bytes per Device by Business Unit - Rule` | 总数据流量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 总传输字节数 | 统计基线 | 发现设备通信量突增 |
| 22 | `UEBA - Unusual Volume of Data Bytes per Device - Rule` | 总数据流量异常（设备） | 设备 | 实体个人历史/规则范围 | 总传输字节数 | 统计基线 | 发现设备通信量突增 |
| 23 | `UEBA - Unusual Volume of Blocked Connections per Device by Company - Rule` | 被阻断连接数量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 24 | `UEBA - Unusual Volume of Blocked Connections per Device by Business Unit - Rule` | 被阻断连接数量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 25 | `UEBA - Unusual Volume of Blocked Connections per Device - Rule` | 被阻断连接数量异常（设备） | 设备 | 实体个人历史/规则范围 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 26 | `UEBA - Unusual Volume Of Data Uploaded Per User By Business Unit - Rule` | 上传数据量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 上传字节数 | 统计基线 | 发现异常上传和潜在数据外泄 |
| 27 | `UEBA - Unusual Volume Of Data Downloaded Per User By Business Unit - Rule` | 下载数据量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 下载字节数 | 统计基线 | 发现批量取数或数据收集 |
| 28 | `UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User By Company - Rule` | 从内部服务器下载数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 从内部服务器下载的字节数 | 统计基线 | 发现内部数据的大规模读取和潜在外泄准备 |
| 29 | `UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User By Business Unit - Rule` | 从内部服务器下载数据量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 从内部服务器下载的字节数 | 统计基线 | 发现内部数据的大规模读取和潜在外泄准备 |
| 30 | `UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User - Rule` | 从内部服务器下载数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 从内部服务器下载的字节数 | 统计基线 | 发现内部数据的大规模读取和潜在外泄准备 |
| 31 | `UEBA - Unusual Volume Of Blocked Connections Per User By Company - Rule` | 被阻断连接数量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 32 | `UEBA - Unusual Volume Of Blocked Connections Per User By Business Unit - Rule` | 被阻断连接数量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 33 | `UEBA - Unusual Volume Of Blocked Connections Per User - Rule` | 被阻断连接数量异常（用户） | 用户 | 实体个人历史/规则范围 | 被阻断连接数 | 统计基线 | 发现反复外联、扫描或策略违规 |
| 34 | `UEBA - Unauthorized Activity Time - Rule` | 非授权时段活动 | 用户或设备 | 实体历史及规则范围 | 授权/历史活动时段 | 规则与时间基线 | 发现非授权时段的异常活动 |

### 4.2 认证与登录行为异常（34 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 35 | `UEBA - Unusual Volume Success Logins To Computer By Company - Rule` | 计算机成功登录量异常（计算机，公司同伴组） | 计算机/设备 | 公司同伴组 | 目标计算机成功登录次数 | 统计基线 | 发现主机被大量登录或成为横向移动落点 |
| 36 | `UEBA - Unusual Volume Success Logins To Computer By Business Unit - Rule` | 计算机成功登录量异常（计算机，业务单元同伴组） | 计算机/设备 | 业务单元同伴组 | 目标计算机成功登录次数 | 统计基线 | 发现主机被大量登录或成为横向移动落点 |
| 37 | `UEBA - Unusual Volume Success Logins To Computer - Rule` | 计算机成功登录量异常（计算机） | 计算机/设备 | 实体个人历史/规则范围 | 目标计算机成功登录次数 | 统计基线 | 发现主机被大量登录或成为横向移动落点 |
| 38 | `UEBA - Unusual Volume Success Login Per User by Company - Rule` | 用户成功登录量异常 | 用户 | 公司同伴组 | 用户成功登录次数 | 统计基线 | 发现账号滥用或异常并发登录 |
| 39 | `UEBA - Unusual Volume Success Login Per User by Business Unit - Rule` | 用户成功登录量异常 | 用户 | 业务单元同伴组 | 用户成功登录次数 | 统计基线 | 发现账号滥用或异常并发登录 |
| 40 | `UEBA - Unusual Volume Success Login Per User - Rule` | 用户成功登录量异常（用户） | 用户 | 实体个人历史/规则范围 | 用户成功登录次数 | 统计基线 | 发现账号滥用或异常并发登录 |
| 41 | `UEBA - Unusual Volume Login Type Per User by Company - Rule` | 特定登录类型使用量异常 | 用户 | 公司同伴组 | 按登录类型统计的次数 | 统计基线 | 发现 RDP、网络登录等方式异常增加 |
| 42 | `UEBA - Unusual Volume Login Type Per User by Business Unit - Rule` | 特定登录类型使用量异常 | 用户 | 业务单元同伴组 | 按登录类型统计的次数 | 统计基线 | 发现 RDP、网络登录等方式异常增加 |
| 43 | `UEBA - Unusual Volume Login Type Per User - Rule` | 特定登录类型使用量异常（用户） | 用户 | 实体个人历史/规则范围 | 按登录类型统计的次数 | 统计基线 | 发现 RDP、网络登录等方式异常增加 |
| 44 | `UEBA - Unusual Unlock Time Per User By Company - Rule` | 用户解锁时间异常（用户，公司同伴组） | 用户 | 公司同伴组 | 解锁发生时段 | 时间基线 | 发现非惯常时段的会话解锁 |
| 45 | `UEBA - Unusual Unlock Time Per User - Rule` | 用户解锁时间异常（用户） | 用户 | 实体个人历史/规则范围 | 解锁发生时段 | 时间基线 | 发现非惯常时段的会话解锁 |
| 46 | `UEBA - Unusual Login Time Per User By Company - Rule` | 用户登录时间异常（用户，公司同伴组） | 用户 | 公司同伴组 | 登录发生时段 | 时间基线 | 发现非惯常时段登录 |
| 47 | `UEBA - Unusual Login Time Per User - Rule` | 用户登录时间异常（用户） | 用户 | 实体个人历史/规则范围 | 登录发生时段 | 时间基线 | 发现非惯常时段登录 |
| 48 | `UEBA - Unauthorized Machine Login - Rule` | 登录未授权计算机 | 用户 | 固定规则/关联范围 | 用户与目标设备关系 | 授权/稀有关系 | 发现账号登录非授权或历史罕见设备 |
| 49 | `UEBA - Unauthorized Login Type - Rule` | 使用未授权登录类型 | 用户 | 固定规则/关联范围 | 登录类型 | 授权/稀有关系 | 发现异常使用 RDP、网络登录等方式 |
| 50 | `UEBA - Rare Windows User Login By Device - Rule` | Windows 设备上的登录用户罕见（设备） | 设备 | 实体个人历史/规则范围 | 设备上的用户特征稀有度 | 稀有度模型 | 发现陌生用户登录设备 |
| 51 | `UEBA - Rare Windows Logon Type By User - Rule` | Windows 登录类型罕见（用户） | 用户 | 实体个人历史/规则范围 | 登录类型稀有度 | 稀有度模型 | 发现异常登录方式 |
| 52 | `UEBA - Rare Windows Logon Type By Device - Rule` | Windows 登录类型罕见（设备） | 设备 | 实体个人历史/规则范围 | 登录类型稀有度 | 稀有度模型 | 发现异常登录方式 |
| 53 | `UEBA - Rare Windows Logon Process By User And Device - Rule` | Windows 登录进程罕见（用户与设备） | 用户 | 实体个人历史/规则范围 | 登录进程稀有度 | 稀有度模型 | 发现异常认证链路或凭据滥用 |
| 54 | `UEBA - Rare Windows Logon Process By User - Rule` | Windows 登录进程罕见（用户） | 用户 | 实体个人历史/规则范围 | 登录进程稀有度 | 稀有度模型 | 发现异常认证链路或凭据滥用 |
| 55 | `UEBA - Rare Windows Logon Process By Device - Rule` | Windows 登录进程罕见（设备） | 设备 | 实体个人历史/规则范围 | 登录进程稀有度 | 稀有度模型 | 发现异常认证链路或凭据滥用 |
| 56 | `UEBA - Rare Windows Domain Login By User - Rule` | Windows 登录域罕见（用户） | 用户 | 实体个人历史/规则范围 | 登录域稀有度 | 稀有度模型 | 发现跨域或异常域登录 |
| 57 | `UEBA - Rare Login Return Code By Windows User - Rule` | 登录返回码罕见（Windows 用户） | 用户 | 实体个人历史/规则范围 | 认证返回码稀有度 | 稀有度模型 | 发现异常失败原因或侦察式认证 |
| 58 | `UEBA - Rare Login Return Code By Device - Rule` | 登录返回码罕见（设备） | 设备 | 实体个人历史/规则范围 | 认证返回码稀有度 | 稀有度模型 | 发现异常失败原因或侦察式认证 |
| 59 | `UEBA - Rare Device Login By Windows User - Rule` | 用户登录设备罕见（Windows 用户） | 用户 | 实体个人历史/规则范围 | 用户与设备组合稀有度 | 稀有度模型 | 发现首次或极少访问的设备 |
| 60 | `UEBA - Brute Force Access Logon Type Per User by Company - Rule` | 按登录类型发现暴力破解 | 用户 | 公司同伴组 | 失败登录量及次数 | 爆破检测 | 发现特定登录方式的口令爆破 |
| 61 | `UEBA - Brute Force Access Logon Type Per User by Business Unit - Rule` | 按登录类型发现暴力破解 | 用户 | 业务单元同伴组 | 失败登录量及次数 | 爆破检测 | 发现特定登录方式的口令爆破 |
| 62 | `UEBA - Brute Force Access Logon Type Per User - Rule` | 按登录类型发现暴力破解（用户） | 用户 | 实体个人历史/规则范围 | 失败登录量及次数 | 爆破检测 | 发现特定登录方式的口令爆破 |
| 63 | `UEBA - Brute Force Access Behavior Per User by Company - Rule` | 暴力破解访问行为 | 用户 | 公司同伴组 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |
| 64 | `UEBA - Brute Force Access Behavior Per User by Business Unit - Rule` | 暴力破解访问行为 | 用户 | 业务单元同伴组 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |
| 65 | `UEBA - Brute Force Access Behavior Per User - Rule` | 暴力破解访问行为（用户） | 用户 | 实体个人历史/规则范围 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |
| 66 | `UEBA - Brute Force Access Behavior Per Device By Company - Rule` | 暴力破解访问行为（设备，公司同伴组） | 设备 | 公司同伴组 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |
| 67 | `UEBA - Brute Force Access Behavior Per Device By Business Unit - Rule` | 暴力破解访问行为（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |
| 68 | `UEBA - Brute Force Access Behavior Per Device - Rule` | 暴力破解访问行为（设备） | 设备 | 实体个人历史/规则范围 | 失败登录次数及失败后原因/后续成功 | 爆破检测 | 发现口令爆破和密码喷洒 |

### 4.3 打印行为异常（24 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 69 | `UEBA - Unusual Volume of Print per Device by Business Unit - Rule` | 打印作业数量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 70 | `UEBA - Unusual Volume of Data Transmitted to Printer per Device by Business Unit - Rule` | 传输至打印机的数据量异常（设备，业务单元同伴组） | 设备 | 业务单元同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 71 | `UEBA - Unusual Volume of Print Per User By Business Unit- Rule` | 打印作业数量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 72 | `UEBA - Unusual Volume of Data Transmitted To Printer Per User By Business Unit- Rule` | 传输至打印机的数据量异常（用户，业务单元同伴组） | 用户 | 业务单元同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 73 | `UEBA - Unusual Volume of Print per Printer by Business Unit- Rule` | 打印作业数量异常（打印机，业务单元同伴组） | 打印机 | 业务单元同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 74 | `UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Business Unit- Rule` | 传输至打印机的数据量异常（打印机，业务单元同伴组） | 打印机 | 业务单元同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 75 | `UEBA - Unusual Volume of Print per User by Company - Rule` | 打印作业数量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 76 | `UEBA - Unusual Volume of Print per User - Rule` | 打印作业数量异常（用户） | 用户 | 实体个人历史/规则范围 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 77 | `UEBA - Unusual Volume of Print per Printer by Company - Rule` | 打印作业数量异常（打印机，公司同伴组） | 打印机 | 公司同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 78 | `UEBA - Unusual Volume of Print per Printer - Rule` | 打印作业数量异常（打印机） | 打印机 | 实体个人历史/规则范围 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 79 | `UEBA - Unusual Volume of Print per Device by Company - Rule` | 打印作业数量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 80 | `UEBA - Unusual Volume of Print per Device - Rule` | 打印作业数量异常（设备） | 设备 | 实体个人历史/规则范围 | 打印作业数 | 统计基线 | 发现批量打印和潜在纸质泄密 |
| 81 | `UEBA - Unusual Volume of Print at Unusual Time per User by Company - Rule` | 异常时段大量打印（用户，公司同伴组） | 用户 | 公司同伴组 | 打印量与打印时段 | 量值与时间基线 | 发现非工作时间批量打印和潜在泄密 |
| 82 | `UEBA - Unusual Volume of Print at Unusual Time per Printer by Company - Rule` | 异常时段大量打印（打印机，公司同伴组） | 打印机 | 公司同伴组 | 打印量与打印时段 | 量值与时间基线 | 发现非工作时间批量打印和潜在泄密 |
| 83 | `UEBA - Unusual Volume of Print at Unusual Time per Device by Company - Rule` | 异常时段大量打印（设备，公司同伴组） | 设备 | 公司同伴组 | 打印量与打印时段 | 量值与时间基线 | 发现非工作时间批量打印和潜在泄密 |
| 84 | `UEBA - Unusual Volume of Data Transmitted to Printer per User by Company - Rule` | 传输至打印机的数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 85 | `UEBA - Unusual Volume of Data Transmitted to Printer per User - Rule` | 传输至打印机的数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 86 | `UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Company - Rule` | 传输至打印机的数据量异常（打印机，公司同伴组） | 打印机 | 公司同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 87 | `UEBA - Unusual Volume of Data Transmitted to Printer per Printer - Rule` | 传输至打印机的数据量异常（打印机） | 打印机 | 实体个人历史/规则范围 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 88 | `UEBA - Unusual Volume of Data Transmitted to Printer per Device by Company - Rule` | 传输至打印机的数据量异常（设备，公司同伴组） | 设备 | 公司同伴组 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 89 | `UEBA - Unusual Volume of Data Transmitted to Printer per Device - Rule` | 传输至打印机的数据量异常（设备） | 设备 | 实体个人历史/规则范围 | 打印传输字节数 | 统计基线 | 发现大批量打印和潜在纸质泄密 |
| 90 | `UEBA - Unusual Print Time per User - Rule` | 打印时间异常（用户） | 用户 | 实体个人历史/规则范围 | 打印发生时段 | 时间基线 | 发现深夜、周末等非惯常打印 |
| 91 | `UEBA - Unusual Print Time per Printer - Rule` | 打印时间异常（打印机） | 打印机 | 实体个人历史/规则范围 | 打印发生时段 | 时间基线 | 发现深夜、周末等非惯常打印 |
| 92 | `UEBA - Unusual Print Time per Device - Rule` | 打印时间异常（设备） | 设备 | 实体个人历史/规则范围 | 打印发生时段 | 时间基线 | 发现深夜、周末等非惯常打印 |

### 4.4 USB 外设行为异常（8 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 93 | `UEBA - Unusual Volume Of USB Denies Per User By Company - Rule` | USB 拒绝事件数量异常（用户，公司同伴组） | 用户 | 公司同伴组 | USB 策略拒绝次数 | 统计基线 | 发现反复尝试使用受限 USB |
| 94 | `UEBA - Unusual Volume Of USB Denies Per User - Rule` | USB 拒绝事件数量异常（用户） | 用户 | 实体个人历史/规则范围 | USB 策略拒绝次数 | 统计基线 | 发现反复尝试使用受限 USB |
| 95 | `UEBA - Unusual Volume Of File Operations To USB Per User By Company - Rule` | 针对 USB 的文件操作量异常（用户，公司同伴组） | 用户 | 公司同伴组 | USB 文件操作次数 | 统计基线 | 发现批量复制或移动文件到 USB |
| 96 | `UEBA - Unusual Volume Of File Operations To USB Per User - Rule` | 针对 USB 的文件操作量异常（用户） | 用户 | 实体个人历史/规则范围 | USB 文件操作次数 | 统计基线 | 发现批量复制或移动文件到 USB |
| 97 | `UEBA - Unusual Volume Of Bytes Written To USB Per User By Company - Rule` | 写入 USB 的数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 写入 USB 字节数 | 统计基线 | 发现通过 USB 大规模外拷数据 |
| 98 | `UEBA - Unusual Volume Of Bytes Written To USB Per User - Rule` | 写入 USB 的数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 写入 USB 字节数 | 统计基线 | 发现通过 USB 大规模外拷数据 |
| 99 | `UEBA - Unusual Volume Of Bytes Read From USB Per User By Company - Rule` | 从 USB 读取的数据量异常（用户，公司同伴组） | 用户 | 公司同伴组 | 从 USB 读取字节数 | 统计基线 | 发现通过 USB 大规模导入文件 |
| 100 | `UEBA - Unusual Volume Of Bytes Read From USB Per User - Rule` | 从 USB 读取的数据量异常（用户） | 用户 | 实体个人历史/规则范围 | 从 USB 读取字节数 | 统计基线 | 发现通过 USB 大规模导入文件 |

### 4.5 邮件外发与 DLP 异常（7 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 101 | `UEBA - Email over 5 MB Sent to Personal Email - Rule` | 向个人邮箱发送超过 5 MB 的邮件 | 用户 | 固定规则/关联范围 | 邮件大小、收件域 | 固定规则 | 发现向个人邮箱大文件外发 |
| 102 | `UEBA - Email Sent to Personal Email with Privacy Keywords - Rule` | 包含隐私关键词的邮件发送至个人邮箱 | 用户 | 固定规则/关联范围 | 收件域、隐私关键词 | 固定规则 | 发现敏感内容通过个人邮箱外发 |
| 103 | `UEBA - Email Sent to Personal Email with Attachment - Rule` | 带附件的邮件发送至个人邮箱 | 用户 | 固定规则/关联范围 | 收件域、附件 | 固定规则 | 发现附件通过个人邮箱外发 |
| 104 | `UEBA - Email Sent to Personal Email Using Same Alias - Rule` | 使用相同别名向个人邮箱发送邮件 | 用户 | 固定规则/关联范围 | 企业邮箱与个人邮箱别名相似度 | 固定规则 | 发现用户向自己的个人邮箱转发数据 |
| 105 | `UEBA - Email Sent to Disposable Email Provider - Rule` | 向一次性邮箱服务商发送邮件 | 用户 | 固定规则/关联范围 | 收件域名单 | 名单规则 | 发现向临时邮箱外发数据 |
| 106 | `UEBA - Large Office 365 Message Flagged by DLP Policy - Rule` | 被 DLP 策略标记的 Office 365 大邮件 | 用户 | 固定规则/关联范围 | DLP 命中与邮件大小 | 组合规则 | 发现大体积敏感邮件外发 |
| 107 | `UEBA - Office 365 DLP Policy Violations Allowed - Rule` | 被允许通过的 Office 365 DLP 策略违规 | 用户 | 固定规则/关联范围 | DLP 违规与允许/绕过动作 | 组合规则 | 发现 DLP 命中后仍被放行或绕过 |

### 4.6 账号管理与日志篡改异常（5 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 108 | `UEBA - Windows Event Log Cleared - Rule` | Windows 事件日志被清除 | 用户/设备 | 固定规则/关联范围 | 日志清除事件 | 确定性规则 | 发现攻击者清理审计证据 |
| 109 | `UEBA - Short Lived Windows Accounts - Rule` | 短生命周期 Windows 账号 | 账号 | 固定规则/关联范围 | 账号创建后短时间删除/禁用 | 时序规则 | 发现临时后门账号及痕迹清理 |
| 110 | `UEBA - Password Policy Circumvention - Rule` | 规避密码策略 | 账号/用户 | 固定规则/关联范围 | 密码或账号管理事件组合 | 确定性/时序规则 | 发现密码策略绕过和异常重置 |
| 111 | `UEBA - Member Added Removed In Short Span Universal Groups - Rule` | 通用组成员短时间内加入后移除 | 用户/组 | 固定规则/关联范围 | 通用组成员变更序列 | 时序规则 | 发现短时提权后清理成员关系 |
| 112 | `UEBA - Member Added Removed In Short Span Global Groups - Rule` | 全局组成员短时间内加入后移除 | 用户/组 | 固定规则/关联范围 | 全局组成员变更序列 | 时序规则 | 发现短时提权后清理成员关系 |

### 4.7 HTTP / Web 代理访问异常（4 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 113 | `UEBA - Http Unusual Traffic to Anonymizing Sites - Rule` | 访问匿名代理站点的 HTTP 流量异常 | 用户/设备 | 实体历史及规则范围 | 匿名代理站点类别与流量 | 名单与统计基线 | 发现匿名代理、规避审计或隐蔽外联 |
| 114 | `UEBA - Http Unusual Job Search Activity - Rule` | HTTP 求职网站活动异常 | 用户 | 固定规则/关联范围 | 求职站点访问频率 | 类别与统计规则 | 发现潜在离职风险信号 |
| 115 | `UEBA - Http Suspicious Domain File Download - Rule` | 从可疑域名下载文件 | 用户/设备 | 固定规则/关联范围 | 可疑域名与文件下载 | 名单与组合规则 | 发现恶意载荷或工具下载 |
| 116 | `UEBA - Http Excessive Transfer to Storage Site - Rule` | 向存储站点大量传输数据 | 用户/设备 | 实体历史及规则范围 | 存储站点类别与传输量 | 名单与统计基线 | 发现借助云盘或存储站点外传数据 |

### 4.8 主机失陷关联检测（3 条）

| 序号 | 官方检测名称 | 中文名称 | 主体 | 比较范围 | 核心特征/条件 | 机制 | 安全意义 |
|---:|---|---|---|---|---|---|---|
| 117 | `UEBA - Compromised Windows Host Correlation - Rule` | Windows 主机失陷关联检测 | 设备 | 固定规则/关联范围 | 多个主机安全信号 | 关联检测 | 关联多种迹象判断 Windows 主机失陷 |
| 118 | `UEBA - Compromised Linux Host Correlation - Rule` | Linux 主机失陷关联检测 | 设备 | 固定规则/关联范围 | 多个主机安全信号 | 关联检测 | 关联多种迹象判断 Linux 主机失陷 |
| 119 | `UEBA - AWS Compromised Account - Rule` | AWS 账号失陷检测 | 账号/用户 | 固定规则/关联范围 | AWS 账号的异常活动组合 | 关联检测 | 发现云账号被盗用或权限滥用 |

## 5. 使用建议

该清单可以直接扩展成自研 UEBA 的检测覆盖矩阵。建议增加“是否计划实现、现有数据源、字段完整率、实体解析依赖、基线窗口、当前状态、负责人、验收数据集”等项目管理字段。

完整字段版见同目录 [13-Splunk本地UEBA内置检测清单.csv](13-Splunk本地UEBA内置检测清单.csv)。更详细的族级实现分析见 [本地 UEBA 检测详解与实现](../05-本地UEBA检测详解与实现.md)。
