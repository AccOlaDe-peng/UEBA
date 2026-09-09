# Splunk UEBA 检测与数据源调研

> 调研对象:Splunk Enterprise Security 8.5 管理手册「User and entity behavior analytics」章节
> 调研目的:为自研 UEBA 产品(Zeek 流量 + 用户行为日志)的检测设计提供参考
> 调研日期:2026-09-09
> 说明:官方"检测参考清单"页面本身是**按字母序排列的扁平列表,没有官方分类**。本文中的分类分组是根据检测名称做的功能性归纳,便于对比参考;检测名称本身与官方页面逐字一致。

---

## 1. 检测的运行机制

### 1.1 UEBA 检测是什么

- UEBA 检测通过将当前行为与**学习到的历史基线(baseline)**对比,识别异常或高风险行为。它不依赖固定规则,而是使用**统计模型和机器学习**判断某个特定用户或资产"什么算正常",再对偏离基线的行为进行标记(可能表示威胁或账号失陷)。
- 每个 UEBA 检测关联一个或多个实体(entity,用户/资产),当检测到与基线显著偏离的行为时生成**中间 findings(intermediate findings)**。
- Findings 会计入 **ERS(Entity Risk Score,实体风险分)** —— 基于近期 findings 计算的用户/资产综合风险等级。
- UEBA 检测**只读**:在 Content management 页面无法编辑或新建 UEBA 检测,不能修改底层 SPL 与检测逻辑;只能通过 **finding exclusions(finding 排除规则)** 调整其产出的 findings。
- UEBA 检测**不支持 CIM entity zones**(实体区域)。

### 1.2 数据写入哪个索引:risk vs ba_test(test index)

| 维度 | risk 索引 | ba_test 索引(test index) |
| --- | --- | --- |
| 定位 | 正式生产用的风险索引,与 RBA(基于风险的告警)共用 | UEBA 专用的"测试"索引,用于验证检测效果 |
| 可用性 | 云端与本地部署均可用 | **仅 UEBA cloud 云端部署可用** |
| 默认状态 | 需手动开启(detection 级别选择 Turn on in risk index) | **云端部署的 UEBA 检测默认在 ba_test 中开启** |

开关方式(Content management → Type 过滤器选 "UEBA detection" → 打开具体检测):

- **Turn on in risk index**:检测在 risk 索引生成 findings;
- **Turn on in test index**:检测在 ba_test 索引生成 findings;
- **Off**:检测不在任何索引生成 findings(即完全停用该检测)。

也就是说:**是否写入索引 = 检测是否启用**;同一检测的 findings 写入哪个索引取决于开启方式,一个检测可分别在 risk / test 索引独立开关。

### 1.3 Findings 是什么

Splunk ES 8.0+ 术语体系(替代旧概念):

- **finding** 取代 notable event( notable/告警事件):由 event-based 或 finding-based 检测产生的一个或多个异常事件/告警的载体;
- **intermediate finding** 取代 risk event(风险事件):表示异常但未必是独立安全事件的中间观察记录,可作为高阶 finding-based 检测的输入。UEBA 检测生成的即属于此类中间结果;
- **finding group**:多个 findings 的组合。
- 同一个检测不能同时产生 findings 和 intermediate findings(配置时二选一)。
- Intermediate findings 不会出现在 Mission Control 的 Analyst queue 中,不能被分诊(triage)。

### 1.4 Findings 里有哪些字段/列

Findings 存储在索引中是带字段的事件,一个 finding 包含(官方说明:"All metadata about the detection ... are included in the finding"):

- **时间戳**、**键值对字段**;
- **实体信息**(受影响的用户/资产);
- **行为摘要信息**;
- **元数据**:MITRE tactic / technique、confidence(置信度)、impact(影响)、threat objects(威胁对象);
- **risk_score**:基于 confidence 与 impact 计算的风险分。

示例 finding(官方文档给出的一条记录,注意 `search_name` 即检测名):

```text
1704664597, search_name="ESCU - BITS Job Persistence - Rule", count="2",
dest="win-host-...", firstTime="2024-01-07T20:00:07", lastTime="...",
info_max_time=..., info_min_time=..., info_search_time=...,
original_file_name="unknown", parent_process="C:\Windows\System32\cmd.exe",
parent_process_id="0x3a8", parent_process_name="cmd.exe",
process="C:\Windows\System32\bitsadmin.exe /setnotifycmdline ...",
process_id="0xcb8", process_name="bitsadmin.exe", user="Administrator"
```

审查 UEBA findings 时的关键检索字段(来自官方审查搜索语句):

| 字段 | 含义 |
| --- | --- |
| `source` | 检测名,格式为 `UEBA - <检测名>`(如 `UEBA - Unauthorized Activity Time - Rule`) |
| `index` | `risk` 或 `ba_test` |
| `risk_score` | 该 finding 的风险分 |
| `risk_object` | 风险实体(用户/设备) |
| `normalized_risk_object` | 归一化后的风险实体(配合资产/身份框架) |

官方审查搜索(在 Analytics → Security intelligence → Risk analysis 仪表板中选 Test index / Risk index 查看,也可直接搜):

```spl
index IN (ba_test, risk) source="UEBA -*"
| stats sum(risk_score) as finding_score,
        dc(risk_object) as entities,
        dc(normalized_risk_object) as normalized_entities,
        count by source index
| table source index normalized_entities entities count finding_score
| sort +count, +risk_score
```

其他运维要点:

- **UEBA 检测最长可能需要 30 天才能产出异常**(需要先学习基线);
- 可对某个检测配置 **Manage finding exclusion rules**,按条件排除特定 finding 的风险加分;
- 查看 UEBA 检测:Security content → Content management → Type 过滤 "UEBA detection";Status 列可 On/Off。

---

## 2. 云端 UEBA 检测完整清单

- **总数:176 个**(云端部署可用,名称以 `UEBA - ` 开头)。
- 官方页面为扁平字母序列表;以下分类为调研者按功能归纳(名称未改动)。

### 云端 UEBA 检测分类统计

| 分类 | 数量 |
| --- | --- |
| Windows 端点威胁行为(LOLBAS / 持久化 / 凭据窃取 / 防御规避) | 76 |
| 认证与登录行为异常(Windows / AD) | 38 |
| 云存储与文件访问异常 | 24 |
| 账号与权限管理异常 | 13 |
| 身份云与 SaaS 平台异常(Okta / O365 / Box) | 11 |
| 电子邮件行为异常 | 8 |
| VPN 登录位置异常 | 6 |
| **合计** | **176** |

#### Windows 端点威胁行为(LOLBAS / 持久化 / 凭据窃取 / 防御规避)(76 条)

- UEBA - Anomalous usage of Archive Tools
- UEBA - Attempt To Delete Services
- UEBA - Attempt To Disable Services
- UEBA - Attempted Credential Dump From Registry via Reg exe
- UEBA - BCDEdit Failure Recovery Modification
- UEBA - Clear Unallocated Sector Using Cipher App
- UEBA - DNS Exfiltration Using Nslookup App
- UEBA - Deleting Shadow Copies
- UEBA - Deny Permission using Cacls Utility
- UEBA - Detect PowerShell Applications Spawning cmd exe
- UEBA - Detect Prohibited Browsers Spawning cmd exe
- UEBA - Detect Prohibited Office Applications Spawning cmd exe
- UEBA - Detect RClone Command-Line Usage
- UEBA - Grant Permission Using Cacls Utility
- UEBA - Impacket Lateral Movement WMIExec Commandline Parameters
- UEBA - Impacket Lateral Movement smbexec CommandLine Parameters
- UEBA - Office Product Spawning Windows Script Host
- UEBA - Password Policy Circumvention
- UEBA - Possible Lateral Movement PowerShell Spawn
- UEBA - Powershell Suspicious Script Detection
- UEBA - Rare Windows Event Code by User
- UEBA - Rare Windows Event Code By User Business Unit
- UEBA - Rare Windows Process Name by Device
- UEBA - Rare Windows Process Name by User
- UEBA - Rare Windows Process Name By User Business Unit
- UEBA - Rare Windows Resource Type by User
- UEBA - Rare Windows Resource Type By User Business Unit
- UEBA - Resize Shadowstorage Volume
- UEBA - Sdelete Application Execution
- UEBA - ServicePrincipalNames Discovery with PowerShell
- UEBA - System Process Running from Unexpected Location
- UEBA - Unusual Volume of Kerberos TGS Ticket Requests
- UEBA - WBAdmin Delete System Backups
- UEBA - WevtUtil Usage To Clear Logs
- UEBA - Wevtutil Usage To Disable Logs
- UEBA - Windows Bits Job Persistence
- UEBA - Windows COM Hijacking InprocServer32 Modification
- UEBA - Windows CertUtil URLCache Download
- UEBA - Windows CertUtil VerifyCtl Download
- UEBA - Windows Curl Upload to Remote Destination
- UEBA - Windows Default Group Policy Object Modified with GPME
- UEBA - Windows Defender Tools in Non Standard Path
- UEBA - Windows Diskshadow Proxy Execution
- UEBA - Windows DotNet Binary in Non Standard Path
- UEBA - Windows Exchange PowerShell Module Usage
- UEBA - Windows Execute Arbitrary Commands with MSDT
- UEBA - Windows Findstr GPP Discovery
- UEBA - Windows Ingress Tool Transfer Using Explorer
- UEBA - Windows LOLBin Binary in Non Standard Path
- UEBA - Windows MSHTA Child Process
- UEBA - Windows MSHTA Command-Line URL
- UEBA - Windows MSHTA Inline HTA Execution
- UEBA - Windows OS Credential Dumping with Ntdsutil Export NTDS
- UEBA - Windows OS Credential Dumping with Procdump
- UEBA - Windows PowerShell Start-BitsTransfer
- UEBA - Windows PowerSploit GPP Discovery
- UEBA - Windows Powershell Connect to Internet With Hidden Window
- UEBA - Windows Powershell DownloadString
- UEBA - Windows Rasautou DLL Execution
- UEBA - Windows Rename System Utilities Acccheckconsole exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Adplus exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Advpack dll LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Agentexecutor exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Appinstaller exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Appvlp exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Aspnet compiler exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities At exe LOLBAS in Non Standard Path
- UEBA - Windows Rename System Utilities Atbroker exe LOLBAS in Non Standard Path
- UEBA - Windows Rundll32 Comsvcs Memory Dump
- UEBA - Windows Rundll32 Inline HTA Execution
- UEBA - Windows Screen Capture Via Powershell
- UEBA - Windows Script Host Spawn MSBuild
- UEBA - Windows System Binary Proxy Execution MSIExec DLLRegisterServer
- UEBA - Windows System Binary Proxy Execution MSIExec Remote Download
- UEBA - Windows System Binary Proxy Execution MSIExec Unregister DLL
- UEBA - Windows WMIPrvse Spawn MSBuild

#### 认证与登录行为异常(Windows / AD)(38 条)

- UEBA - Abnormal RDP Login Active Directory
- UEBA - Brute Force Login By User and Failure Reason In Active Directory
- UEBA - Brute Force Login Failures By Device In Active Directory
- UEBA - Land Speed Violation
- UEBA - Password Spraying In Active Directory Authentication Data
- UEBA - Password Spraying In Active Directory Data
- UEBA - Rare Device Authentication by Windows User
- UEBA - Rare Device Login by Windows User
- UEBA - Rare Device Authentication by Windows User Business Unit
- UEBA - Rare Windows Device Login by User Business Unit
- UEBA - Rare Windows Authentication Return Code by Device
- UEBA - Rare Windows Authentication Return Code by User
- UEBA - Rare Windows Authentication Return Code by User Business Unit
- UEBA - Rare Windows Domain Authentication by User
- UEBA - Rare Windows Domain Authentication by User Business Unit
- UEBA - Rare Windows Domain Login by User
- UEBA - Rare Windows Domain Login by User Business Unit
- UEBA - Rare Windows Login Return Code by Device
- UEBA - Rare Windows Login Return Code by User
- UEBA - Rare Windows Login Return Code by User Business Unit
- UEBA - Rare Windows Logon Process by Device
- UEBA - Rare Windows Logon Process by User
- UEBA - Rare Windows Logon Process by User and Device
- UEBA - Rare Windows Logon Process by User Business Unit
- UEBA - Rare Windows Logon Type by Device
- UEBA - Rare Windows Logon Type by User
- UEBA - Rare Windows Logon Type by User Business Unit
- UEBA - Rare Windows User Authentication by Device
- UEBA - Rare Windows User Login by Device
- UEBA - Unauthorized Activity Time
- UEBA - Unauthorized Login Type
- UEBA - Unauthorized Machine Login
- UEBA - Unusual Login Hour Of The Day
- UEBA - Unusual Volume of Active Directory Authentication Failures
- UEBA - Unusual Volume of Active Directory Login Failures
- UEBA - Unusual Volume of Successful Logins
- UEBA - Windows PowerShell Disabled Kerberos Pre-Authentication Discovery Get-ADUser
- UEBA - Windows PowerShell Disabled Kerberos Pre-Authentication Discovery With PowerView

#### 云存储与文件访问异常(24 条)

- UEBA - Cloud Storage New Access Data Model
- UEBA - Excessive File Size Change Model
- UEBA - Fsutil Zeroing File
- UEBA - Hiding Files And Directories With Attrib exe
- UEBA - Modify ACLs Permission Of Files Or Folders
- UEBA - Rare File Access by User
- UEBA - Rare File Access by User Business Unit
- UEBA - Rare File Activity by Company
- UEBA - Rare File Activity by User
- UEBA - Rare File Activity by User Business Unit
- UEBA - Rare File Client by Company
- UEBA - Rare File Client by User
- UEBA - Rare File Client by User Business Unit
- UEBA - Unusual Volume of Cloud File Activity
- UEBA - Unusual Volume of Cloud File Deletions
- UEBA - Unusual Volume of Cloud File Downloads
- UEBA - Windows Bitsadmin Download File
- UEBA - Windows CertUtil Decode File
- UEBA - Windows File Share Discovery With Powerview
- UEBA - Windows Odbcconf Load Response File
- UEBA - Windows Powershell DownloadFile
- UEBA - Windows System Binary Proxy Execution Compiled HTML File Decompile
- UEBA - Windows System Binary Proxy Execution Compiled HTML File URL In Command Line
- UEBA - Windows System Binary Proxy Execution Compiled HTML File Using InfoTech Storage Handlers

#### 账号与权限管理异常(13 条)

- UEBA - Abnormal Administrative Activity Model
- UEBA - Abnormal Group Changes Administrative Activity Model
- UEBA - Abnormal Privileges Activity Model
- UEBA - Abnormal Source IP during Administrative Activity Model
- UEBA - Abnormal User Agent during Administrative Activity Model
- UEBA - Account Creation Deletion In Short Span
- UEBA - Create Local Admin Accounts Using Net Exe
- UEBA - Create Local User Accounts Using Net Exe
- UEBA - Delete A Net User
- UEBA - Disable Net User Account
- UEBA - Member Added Removed In Short Span
- UEBA - Unusual Account Provisioning from Abnormal Source IP
- UEBA - Unusual Account Provisioning using Abnormal User Agent

#### 身份云与 SaaS 平台异常(Okta / O365 / Box)(11 条)

- UEBA - Abnormal Okta Application Activity Model - Actor User
- UEBA - Abnormal Okta Application Activity Model - App Category
- UEBA - Abnormal Okta Login Source IP Activity Model
- UEBA - Abnormal Okta Login Target User Activity Model
- UEBA - Abnormal Okta Login Temporal Activity Model
- UEBA - Abnormal Okta Login User Agent Activity Model
- UEBA - Password Spraying In Okta Data
- UEBA - Unusual Volume of Application Activity in Okta
- UEBA - Unusual Volume of Box Login Failures
- UEBA - Unusual Volume of O365 Login Failures
- UEBA - Unusual Volume of Okta Login Failures

#### 电子邮件行为异常(8 条)

- UEBA - Abnormal Email Handle Similarity and Time Activity Model
- UEBA - Abnormal Email Recipient Count and Time Activity Model
- UEBA - Abnormal Email Source IP and Time Activity Model
- UEBA - Abnormal Email Temporal Activity Model
- UEBA - Email Similarity
- UEBA - Unusual Large Email Size Sent Per User
- UEBA - Unusual Volume of Outbound Emails to External Recipients
- UEBA - Unusual Volume of Outgoing Emails to Rare Domains

#### VPN 登录位置异常(6 条)

- UEBA - Rare Successful VPN Login Location by Company
- UEBA - Rare Successful VPN Login Location by Device
- UEBA - Rare Successful VPN Login Location by User
- UEBA - Rare Successful VPN Login Location by User Business Unit
- UEBA - Unusual Service Account Login via VPN
- UEBA - Unusual Volume of VPN Login Failures

---

## 3. 本地 UEBA 检测完整清单

- **总数:119 个**(on-premises 部署可用,名称以 `UEBA - ` 开头、以 ` - Rule` 结尾)。
- 官方页面为扁平字母序列表;以下分类为调研者按功能归纳(名称未改动)。

### 本地 UEBA 检测分类统计

| 分类 | 数量 |
| --- | --- |
| 网络流量与数据传输异常 | 34 |
| 认证与登录行为异常 | 34 |
| 打印行为异常 | 24 |
| USB 外设行为异常 | 8 |
| 邮件外发与 DLP 异常 | 7 |
| 账号管理与日志篡改异常 | 5 |
| HTTP / Web 代理访问异常 | 4 |
| 主机失陷关联检测 | 3 |
| **合计** | **119** |

#### 网络流量与数据传输异常(34 条)

- UEBA - Unusual Volume of Outgoing Connections per Device by Company
- UEBA - Unusual Volume of Outgoing Connections per Device by Business Unit
- UEBA - Unusual Volume of Outgoing Connections per Device
- UEBA - Unusual Volume of Outgoing Connections Per User By Company
- UEBA - Unusual Volume of Outgoing Connections Per User By Business Unit
- UEBA - Unusual Volume of Outgoing Connections Per User
- UEBA - Unusual Volume of Data Uploaded per User by Company
- UEBA - Unusual Volume of Data Uploaded per User
- UEBA - Unusual Volume of Data Uploaded per Device by Company
- UEBA - Unusual Volume of Data Uploaded per Device by Business Unit
- UEBA - Unusual Volume of Data Uploaded per Device
- UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User By Company
- UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User By Business Unit
- UEBA - Unusual Volume of Data Uploaded To DMZ Devices Per User
- UEBA - Unusual Volume of Data Downloaded per User by Company
- UEBA - Unusual Volume of Data Downloaded per User
- UEBA - Unusual Volume of Data Downloaded per Device by Company
- UEBA - Unusual Volume of Data Downloaded per Device by Business Unit
- UEBA - Unusual Volume of Data Downloaded per Device
- UEBA - Unusual Volume of Data Bytes per Device by Company
- UEBA - Unusual Volume of Data Bytes per Device by Business Unit
- UEBA - Unusual Volume of Data Bytes per Device
- UEBA - Unusual Volume of Blocked Connections per Device by Company
- UEBA - Unusual Volume of Blocked Connections per Device by Business Unit
- UEBA - Unusual Volume of Blocked Connections per Device
- UEBA - Unusual Volume Of Data Uploaded Per User By Business Unit
- UEBA - Unusual Volume Of Data Downloaded Per User By Business Unit
- UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User By Company
- UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User By Business Unit
- UEBA - Unusual Volume Of Data Downloaded From Internal Server Per User
- UEBA - Unusual Volume Of Blocked Connections Per User By Company
- UEBA - Unusual Volume Of Blocked Connections Per User By Business Unit
- UEBA - Unusual Volume Of Blocked Connections Per User
- UEBA - Unauthorized Activity Time

#### 认证与登录行为异常(34 条)

- UEBA - Unusual Volume Success Logins To Computer By Company
- UEBA - Unusual Volume Success Logins To Computer By Business Unit
- UEBA - Unusual Volume Success Logins To Computer
- UEBA - Unusual Volume Success Login Per User by Company
- UEBA - Unusual Volume Success Login Per User by Business Unit
- UEBA - Unusual Volume Success Login Per User
- UEBA - Unusual Volume Login Type Per User by Company
- UEBA - Unusual Volume Login Type Per User by Business Unit
- UEBA - Unusual Volume Login Type Per User
- UEBA - Unusual Unlock Time Per User By Company
- UEBA - Unusual Unlock Time Per User
- UEBA - Unusual Login Time Per User By Company
- UEBA - Unusual Login Time Per User
- UEBA - Unauthorized Machine Login
- UEBA - Unauthorized Login Type
- UEBA - Rare Windows User Login By Device
- UEBA - Rare Windows Logon Type By User
- UEBA - Rare Windows Logon Type By Device
- UEBA - Rare Windows Logon Process By User And Device
- UEBA - Rare Windows Logon Process By User
- UEBA - Rare Windows Logon Process By Device
- UEBA - Rare Windows Domain Login By User
- UEBA - Rare Login Return Code By Windows User
- UEBA - Rare Login Return Code By Device
- UEBA - Rare Device Login By Windows User
- UEBA - Brute Force Access Logon Type Per User by Company
- UEBA - Brute Force Access Logon Type Per User by Business Unit
- UEBA - Brute Force Access Logon Type Per User
- UEBA - Brute Force Access Behavior Per User by Company
- UEBA - Brute Force Access Behavior Per User by Business Unit
- UEBA - Brute Force Access Behavior Per User
- UEBA - Brute Force Access Behavior Per Device By Company
- UEBA - Brute Force Access Behavior Per Device By Business Unit
- UEBA - Brute Force Access Behavior Per Device

#### 打印行为异常(24 条)

- UEBA - Unusual Volume of Print per Device by Business Unit
- UEBA - Unusual Volume of Data Transmitted to Printer per Device by Business Unit
- UEBA - Unusual Volume of Print Per User By Business Unit- Rule
- UEBA - Unusual Volume of Data Transmitted To Printer Per User By Business Unit- Rule
- UEBA - Unusual Volume of Print per Printer by Business Unit- Rule
- UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Business Unit- Rule
- UEBA - Unusual Volume of Print per User by Company
- UEBA - Unusual Volume of Print per User
- UEBA - Unusual Volume of Print per Printer by Company
- UEBA - Unusual Volume of Print per Printer
- UEBA - Unusual Volume of Print per Device by Company
- UEBA - Unusual Volume of Print per Device
- UEBA - Unusual Volume of Print at Unusual Time per User by Company
- UEBA - Unusual Volume of Print at Unusual Time per Printer by Company
- UEBA - Unusual Volume of Print at Unusual Time per Device by Company
- UEBA - Unusual Volume of Data Transmitted to Printer per User by Company
- UEBA - Unusual Volume of Data Transmitted to Printer per User
- UEBA - Unusual Volume of Data Transmitted to Printer per Printer by Company
- UEBA - Unusual Volume of Data Transmitted to Printer per Printer
- UEBA - Unusual Volume of Data Transmitted to Printer per Device by Company
- UEBA - Unusual Volume of Data Transmitted to Printer per Device
- UEBA - Unusual Print Time per User
- UEBA - Unusual Print Time per Printer
- UEBA - Unusual Print Time per Device

#### USB 外设行为异常(8 条)

- UEBA - Unusual Volume Of USB Denies Per User By Company
- UEBA - Unusual Volume Of USB Denies Per User
- UEBA - Unusual Volume Of File Operations To USB Per User By Company
- UEBA - Unusual Volume Of File Operations To USB Per User
- UEBA - Unusual Volume Of Bytes Written To USB Per User By Company
- UEBA - Unusual Volume Of Bytes Written To USB Per User
- UEBA - Unusual Volume Of Bytes Read From USB Per User By Company
- UEBA - Unusual Volume Of Bytes Read From USB Per User

#### 邮件外发与 DLP 异常(7 条)

- UEBA - Email over 5 MB Sent to Personal Email
- UEBA - Email Sent to Personal Email with Privacy Keywords
- UEBA - Email Sent to Personal Email with Attachment
- UEBA - Email Sent to Personal Email Using Same Alias
- UEBA - Email Sent to Disposable Email Provider
- UEBA - Large Office 365 Message Flagged by DLP Policy
- UEBA - Office 365 DLP Policy Violations Allowed

#### 账号管理与日志篡改异常(5 条)

- UEBA - Windows Event Log Cleared
- UEBA - Short Lived Windows Accounts
- UEBA - Password Policy Circumvention
- UEBA - Member Added Removed In Short Span Universal Groups
- UEBA - Member Added Removed In Short Span Global Groups

#### HTTP / Web 代理访问异常(4 条)

- UEBA - Http Unusual Traffic to Anonymizing Sites
- UEBA - Http Unusual Job Search Activity
- UEBA - Http Suspicious Domain File Download
- UEBA - Http Excessive Transfer to Storage Site

#### 主机失陷关联检测(3 条)

- UEBA - Compromised Windows Host Correlation
- UEBA - Compromised Linux Host Correlation
- UEBA - AWS Compromised Account

---

## 4. 云端 vs 本地差异

| 维度 | UEBA Cloud(云端) | UEBA on-premises(本地) |
| --- | --- | --- |
| 检测总数 | **176** | **119** |
| 两边同名共有的检测 | 12 个(见下) | 同左 |
| 仅云端有 | 164 个 | — |
| 仅本地有 | — | 107 个 |
| 检测命名风格 | `UEBA - <名称>` | `UEBA - <名称> - Rule` |
| 默认写入索引 | **ba_test(test index)**,可手动改到 risk | risk 索引(test 索引不可用) |
| 检测技术侧重 | 大量 **ML/统计基线模型(Activity Model)** + Windows LOLBAS 攻击行为规则 | 以 **CIM 数据模型上的统计偏差规则**为主(打印/流量/USB/认证维度按 per User / per Device / per Company / per Business Unit 组合展开) |
| 数据源侧重 | Windows 事件日志、O365、Okta、Box、Infoblox DHCP、Cisco ASA、Palo Alto GlobalProtect | Windows 安全/打印日志、auditd、Suricata、AWS CloudTrail、Symantec EP、Gmail |
| test 索引 | 有(ba_test) | 无 |

### 4.1 两版共有的 12 个检测

1. UEBA - Password Policy Circumvention
2. UEBA - Rare Device Login by Windows User
3. UEBA - Rare Windows Domain Login by User
4. UEBA - Rare Windows Logon Process by Device
5. UEBA - Rare Windows Logon Process by User
6. UEBA - Rare Windows Logon Process by User and Device
7. UEBA - Rare Windows Logon Type by Device
8. UEBA - Rare Windows Logon Type by User
9. UEBA - Rare Windows User Login by Device
10. UEBA - Unauthorized Activity Time
11. UEBA - Unauthorized Login Type
12. UEBA - Unauthorized Machine Login

### 4.2 仅本地有的检测主题(云端清单中没有对应项)

- **打印行为异常**(24 条):Unusual Volume of Print / Data Transmitted to Printer / Print at Unusual Time,按 per User / per Device / per Printer × by Company / by Business Unit 组合;
- **网络流量总量异常**(Upload / Download / Bytes / Outgoing / Blocked Connections,按实体维度组合);
- **USB 外设异常**(Bytes Read/Written、File Operations、Denies);
- **HTTP 代理异常**(4 条:Http Unusual Traffic to Anonymizing Sites、Unusual Job Search Activity、Suspicious Domain File Download、Excessive Transfer to Storage Site)——**这是与 Zeek/代理流量最相关的一组**;
- **邮件外发泄露**(Email to Personal Email 系列、Disposable Email Provider)与 **O365 DLP**(2 条);
- **主机失陷关联**(Compromised Windows / Linux Host Correlation、AWS Compromised Account);
- Windows Event Log Cleared、Short Lived Windows Accounts;
- Brute Force Access Behavior / Logon Type 系列(9 条,按 per User/Device × by Company/Business Unit)。

### 4.3 仅云端有的检测主题(本地清单中没有对应项)

- **Activity Model 基线模型系列**:Abnormal Administrative / Privileges / Email / Group Changes / Source IP / User Agent during Administrative Activity、Excessive File Size Change、Cloud Storage New Access 等(名称含 "Model");
- **Okta 全家桶**(9 条):Abnormal Okta Login/App Activity 系列、Password Spraying In Okta、Unusual Volume of Okta Login Failures / Application Activity in Okta;
- **O365 / Box / 云文件**(Unusual Volume of O365 / Box Login Failures、Cloud File 系列);
- **邮件 ML 模型**(Abnormal Email Handle Similarity / Recipient Count / Source IP / Temporal、Email Similarity、Unusual Volume of Outbound Emails to External Recipients / to Rare Domains);
- **VPN 登录位置基线**(Rare Successful VPN Login Location by User / Device / Company / Business Unit、Unusual Service Account Login via VPN);
- **Windows LOLBAS / 攻击工具行为规则**(约 80 条:CertUtil、MSHTA、MSIExec、Bitsadmin、Rundll32、Impacket、Rename System Utilities LOLBAS 系列等);
- Land Speed Violation(不可能旅行)、Abnormal RDP Login AD、AD 密码喷洒与暴力破解系列。

### 4.4 对自研 UEBA 的启示

- Splunk 的 UEBA 内容分两代:**本地版(旧)** = CIM 数据模型 + 统计偏差规则,维度展开为"per 实体 × by 组织单元";**云端版(新)** = 基线模型(ML)+ 端点攻击行为规则。
- 与 Zeek 流量最直接对应的本地版检测是:HTTP 代理 4 条 + Outgoing Connections / Data Uploaded / Data Downloaded / Data Bytes / Blocked Connections 系列(按 user/device/company/business-unit 维度展开)——可作为流量侧检测维度设计的直接参考。
- 认证侧的 "Rare X by Y" 系列(设备、登录类型、登录进程、返回码、域登录 × user/device/business-unit)是典型的稀有权值(rare)检测设计模式。

---

## 5. 检测所需的 sourcetype 完整清单

### 5.1 云端部署:必需(primary)sourcetypes

官方说明:以下为 UEBA cloud 部署所需的主要 sourcetypes 及对应厂商。

| Sourcetype | 厂商 | 推荐 TA(Add-on) | 相关事件码 / Activity ID |
| --- | --- | --- | --- |
| `wineventlog`、`xmlwineventlog`、`wineventlog:security`、`xmlwineventlog:security` | Microsoft | Splunk Add-on for Microsoft Windows **V8.5.x+** | 1102(日志清除);4103、4104(PowerShell);4624、4625、4634、4648、4661、4662、4663、4672、4673、4688、4689(登录/进程等);4720–4781(账号/组管理);5140、5145(网络共享访问) |
| `o365:reporting:messagetrace` | Microsoft | Splunk Add-on for Microsoft Office 365 **V4.8.1+** | messagetrace(邮件轨迹,用于邮件类检测) |
| `o365:management:activity` | Microsoft | Splunk Add-on for Microsoft Office 365 **V4.8.1+** | FileCopied、FileDeleted、FileDownloaded、FileModified、FileMoved、FileRenamed、FileRestored、FileUploaded(文件操作);SharingRevoked、SharingSet(共享);UserLoggedIn、UserLoginFailed(登录) |
| `infoblox:dhcp` | Infoblox | Splunk Add-on for Infoblox **V2.2.0+** | ack、expire、release(DHCP 租约事件,用于设备-用户映射/新设备识别) |
| `box:events`、`box:file` | Box | Splunk Add-on for Box **V3.12.1+** | add_login_activity_device、admin_login、collaboration_accept/remove、delete、download、edit、failed_login、item_modify/open/shared_update/sync/unsync、login、move、preview、rename、share、share_expiration、upload |
| `cisco:asa` | Cisco | Splunk Add-on for Cisco ASA **5.2.0+** | 113019、113039(认证/VPN);602303、602304(连接建立/拆除);611101、611103(ACL);716001–716006、716038(WebVPN 登录);722022–722034、722051(AnyConnect);723001、723002(WebVPN 会话) |
| `oktaim2:log` | Okta | Splunk Add-on for Okta Identity Cloud **V3.0.0+** | application.user_membership.add/update、device.enrollment.create、group.privilege.grant、group.user_membership.add、user.account.lock、user.account.privilege.grant、user.account.report_suspicious_activity_by_enduser、user.authentication.auth_via_mfa、user.authentication.sso、user.lifecycle.activate/create、user.session.start |
| `pan:globalprotect` | Palo Alto | Splunk Add-on for Palo Alto Networks **V2.0.1+** | gateway-auth、gateway-connected、gateway-logout、gateway-setup-ipsec、gateway-switch-to-ssl、portal-auth(VPN 接入行为) |

### 5.2 本地部署:已验证(validated)sourcetypes

官方说明:以下为 UEBA on-premises 部署的主要已验证 sourcetypes,**对齐 UEBA 所依赖的 CIM 数据模型**:

**依赖的 CIM 数据模型(6 个)**:

1. Authentication(认证)
2. Network_Traffic(网络流量)
3. Web(Web/代理)
4. Change(变更)
5. Endpoint(端点)
6. Email(邮件)

| Sourcetype | 厂商 | 推荐 TA | 相关活动 / 事件码 | 是否必需 |
| --- | --- | --- | --- | --- |
| `XmlWinEventLog:Security` | Microsoft Windows | Splunk Add-on for Microsoft Windows (TA-Windows) | EventCode IN (4624, 4625, 4720–4729, 4756–4757) | No |
| `WinEventLog:Security` | Microsoft Windows | Splunk Add-on for Microsoft Windows (TA-Windows) | EventCode IN (4624, 4625, 4720–4729, 4756–4757) | No |
| `WinEventLog:Microsoft-Windows-PrintService/Operational` | Windows 打印服务 | TA-Windows | EventCode=307(打印作业事件) | No |
| `XmlWinEventLog:Microsoft-Windows-PrintService/Operational` | Windows 打印服务 | TA-Windows | EventCode=307 | No |
| `WinEventLog:Microsoft-Windows-PrintService/Admin` | Windows 打印服务 | TA-Windows | EventCode=307 | No |
| `XmlWinEventLog:Microsoft-Windows-PrintService/Admin` | Windows 打印服务 | TA-Windows | EventCode=307 | No |
| `auditd` | Linux Audit Daemon | Splunk Add-on for Unix and Linux (TA-nix) | 可疑活动(登录、提权) | No |
| `Cloudtrail` | AWS CloudTrail | Splunk Add-on for AWS (TA-AWS) | 可疑活动(API 访问、认证、IAM 变更) | No |
| `suricata` | Suricata IDS/IPS | Splunk Add-on for Suricata(社区) | 外发流量、阻断流量、IDS 告警 | No |
| `symantec:ep:behavior:file` | Symantec Endpoint Protection | Splunk Add-on for Symantec Endpoint Protection | Action Blocked / Allowed、文件读写行为 | **Yes(唯一标记必需)** |
| `gws:gmail` | Google Workspace (Gmail) | Splunk Add-on for Google Workspace | 外发流量(邮件发送事件) | No |

要点:

- 云端清单是"**必需**"sourcetypes(8 行/10 个 sourcetype 名);本地清单是"**已验证**"sourcetypes(11 行),除 `symantec:ep:behavior:file` 外均标记"非必需",但检测只有在其数据存在时才会产出 findings。
- 云端数据源以 **SaaS 平台(O365/Okta/Box)+ Windows 事件 + 网络设备(ASA/PAN)+ DHCP** 为主;本地数据源以 **Windows 安全/打印日志 + Nix audit + IDS + EDR 文件行为 + 邮件** 为主。
- 对自研(Zeek + 用户行为日志)的映射参考:Zeek conn/http/dns 可对齐本地版的 Network_Traffic / Web 数据模型(对应 Outgoing Connections、Data Uploaded/Downloaded、HTTP 代理系列检测);Windows 事件日志(4624/4625/4720 系)是两端共同的核心认证数据源。

---

## 6. 服务限制(on-prem / cloud)

### 6.1 UEBA on-premises 服务限制

| 限制类别 | 限制值 |
| --- | --- |
| Entity lists(实体清单) | 身份与资产各类别(source、category、pattern match 等)合计 **500** |
| Finding exclusions(finding 排除规则) | 所有类型(field match、lookup 等)合计 **2,000** |

设置限制的目的(官方表述):保证环境平稳可预期运行、在不压垮系统的前提下保证分析质量、支撑规模增长、满足合规治理、控制成本。

### 6.2 UEBA Cloud 服务限制(按租户 per tenant)

| 限制类别 | 限制值 |
| --- | --- |
| 事件吞吐量(EPS) | **45,000 – 60,000 EPS** |
| 唯一用户数 | 最多 **3,000,000** |
| 唯一设备数 | 最多 **3,000,000** |
| Entity lists | 同本地:**500** |
| Finding exclusions | 同本地:**2,000** |

注:云端限制基于生产遥测与容量建模得出,为当前已验证阈值,随平台演进可能调整;预期超出规模需联系 Splunk Support。

---

## 7. 来源 URL 列表

全部为 Splunk Enterprise Security 8.5 管理手册(2026-09-09 抓取验证,均 200):

| # | 页面 | URL |
| --- | --- | --- |
| 1 | UEBA detections in Splunk Enterprise Security(章节主页) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security |
| 2 | View UEBA detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/view-ueba-detections |
| 3 | Review findings generated by UEBA detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/review-findings-generated-by-ueba-detections |
| 4 | Turn on or turn off UEBA detections in the risk or test index | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/turn-on-or-turn-off-ueba-detections-in-the-risk-or-test-index |
| 5 | UEBA detection reference for UEBA cloud | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/ueba-detection-reference-for-ueba-cloud |
| 6 | UEBA detection reference for UEBA on-premises | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/ueba-detection-reference-for-ueba-on-premises |
| 7 | Required sourcetypes for UEBA detections | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-detections-in-splunk-enterprise-security/required-sourcetypes-for-ueba-detections |
| 8 | UEBA on-premises service limits | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-on-premises-service-limits |
| 9 | UEBA cloud service limits | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/user-and-entity-behavior-analytics/ueba-cloud-service-limits |
| 10 | Monitor your SOC with findings(找 findings 字段定义) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/findings/monitor-your-security-operations-center-with-findings-in-splunk-enterprise-security |

备注:任务给定的 7 个 slug 中,除 `ueba-on-premises-service-limits`、`ueba-cloud-service-limits` 外,其余 5 个页面实际位于 `ueba-detections-in-splunk-enterprise-security/` 子路径下(已修正抓取)。
