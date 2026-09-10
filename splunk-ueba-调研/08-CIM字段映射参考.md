# CIM 字段映射参考(基于官方 TA 源码)

> 来源:Splunk 官方三个包的源码精读——`Splunk_SA_CIM`(CIM 8.7.0)、`Splunk_TA_windows`(11.0.2)、`Splunk_TA_zeek`(TA-for-Zeek 1.0.11,Corelight/Aplura),包已解压在本目录。
> 目的:把"CIM 等价物"从概念落成可抄的实现清单,指导自研 UEBA 的数据规范层设计。日期:2026-09-10。

---

## 一、CIM 包(Splunk_SA_CIM)里有什么

```
Splunk_SA_CIM/
├── default/
│   ├── data/models/*.json     ← 27 个数据模型(核心资产)
│   ├── tags.conf              ← 字段值 → 标签映射(84 行)
│   ├── eventtypes.conf        ← 事件类型定义
│   ├── macros.conf            ← 标准宏(339 行)
│   └── lookups/               ├── README/
└── lookups/                   ← 枚举翻译表(动作、类别等)
```

**27 个数据模型清单**(覆盖安全分析的全部数据域):Authentication、Network_Traffic、Network_Sessions、Network_Resolution、Endpoint、Web、Email、Change、Change_Analysis、Malware、Vulnerabilities、Intrusion_Detection、DLP、Data_Access、Alerts、Certificates、Ticket_Management、Updates、Compute_Inventory、Performance、Application_State、Databases、JVM、Interprocess_Messaging、Event_Signatures、Splunk_Audit、Splunk_CIM_Validation。

### 1.1 模型结构:层次化字段规范

以 Authentication.json 为例,模型的层次(m古典的"子类继承父类"结构):

```
Authentication(基类,34 个标准字段)
├── Successful_Authentication
├── Failed_Authentication
└── Default_Authentication
    ├── Successful_Default_Authentication
    └── Failed_Default_Authentication
```

基类的 34 个标准字段(节选,这是"一条认证事件应该有什么"的官方答案):

```
user / src_user_*      当事用户及其属性(user_role、user_type、user_category…)
src / dest             源、目的(认证是"谁从哪台机器连到哪台机器")
authentication_method  认证方式(如 Windows 的 LogonType)
authentication_service 认证包(如 NTLM / Kerberos)
reason / reason_id     失败原因(文本 + 编码)
signature / signature_id 事件签名(如 "An account failed to log on")
duration / session_id / tag / user_agent / vendor_account …
```

### 1.2 入模约束:一条 SPL 定义"什么事件属于这个模型"

Authentication 基类的约束(constraints):

```spl
(`cim_Authentication_indexes`) tag=authentication NOT (action=success user=*$)
```

三个要素:①限定在声明的认证索引里(宏);②必须打了 `authentication` 标签;③排除机器账号(`$` 结尾)的成功登录。**"事件集"不是声明出来的,是可执行的搜索**——自研时同样建议把每个数据域的入模条件写成一条可跑的校验查询。

### 1.3 tags.conf:标签如何产生

```
[action=failure]        failure = enabled      ← action 字段=failure 的事件自动获得 failure 标签
[action=success]        success = enabled
[user_category=privileged] privileged = enabled
[is_remote=true]        remote = enabled
```

机制:TA 先把原始字段归一为 `action`/`user_category` 等标准字段并赋值,CIM 再按字段值打标签,数据模型约束靠标签圈定事件。链路是:**原始字段 → 归一化字段 → 字段值标签 → 模型约束**。

### 1.4 macros.conf:检测规则只引用宏

339 行宏,如 `` `cim_Authentication_indexes` ``(索引清单)、`` `cim_authentication_service` ``(认证服务字段的兼容取值)。价值:检测规则里不写死任何物理细节,换环境/换索引只改宏定义。

---

## 二、Windows TA:端点事件映射的完整实现

体量:props.conf 2176 行、transforms.conf 1935 行、tags.conf 698 行。处理对象是 Windows 事件日志(Security/System 的 XML 或纯文本)。**三层流水线**:

### 2.1 第 1 层:REPORT 正则抽取(原始字段)

从 XML 事件体抠出厂商原始字段,保留原名:

```ini
# transforms.conf —— 从 EventData_Xml 里抠 TargetUserName
[TargetUserName_for_windows_security_from_xml]
SOURCE_KEY = EventData_Xml
REGEX = <Data Name=['"]TargetUserName['"]>(?<TargetUserName>[^<]+)<\/Data>
```

这一层的原则:**不改语义,只负责"把原始字段完整抠出来"**。

### 2.2 第 2 层:EVAL 归一化(原始字段 → CIM 字段)

props.conf 里按 EventCode 逐个定义归一化规则。**这是整个 TA 最有价值的部分**,三个代表:

**① 当事用户判定**(props.conf:485,一行定义了几十个事件 ID 的"行为归谁"):

```spl
EVAL-user = case(
  EventCode==4794, "DSRM administrator",
  EventCode IN (4727,4730,4731,4734,4735,4737,4754,4755,4758,4764), null(),
  EventCode==4688, if(user=="-" OR isnull(user), src_user, user),   ← 进程创建:回退到发起者
  EventCode IN (1102,4672,4673,…,5140), SubjectUserName,             ← 审计类:发起者
  EventCode IN (4703,4704,4705,4720,…,4798), TargetUserName,         ← 账号管理类:目标账号
  EventCode==4781, NewTargetUserName,                                ← 改名:新名字
  EventCode IN (4728,4729,4732,4733,4756,4757),                      ← 组成员变更:从 SID 尾段抠用户
    if(like(MemberSid, "%\%"), mvindex(split(MemberSid,"\\"),-1), …),
  true(), user)
```

**对自研 UEBA 的意义**:这就是"事件 → 实体"归属表的官方实现。防泄密场景同样的问题(这条行为算谁的)必须逐事件 ID 回答,这份 case 表可以直接当映射需求清单。

**② 源地址判定**(props.conf:多 EventCode case):

```spl
EVAL-src = case(EventCode==4798, Caller_Domain,
                EventCode IN (4727,4728,…,4764), dest,
                EventCode==4778, ClientAddress,
                EventCode==4624, IpAddress,          ← 登录成功:来源 IP
                EventCode==4625, WorkstationName,    ← 登录失败:工作站名
                EventCode IN (5154,5156,5157), SourceAddress, true(), src)
```

注意 **4624 用 IpAddress、4625 用 WorkstationName** 这种细节——失败登录常常拿不到 IP,只有主机名,官方选择是"分别取最可信的来源字段,归一到同一个 src"。自研检测按 src 聚合时必须做同样的归一,否则统计会分裂。

**③ 认证上下文**(props.conf:446):

```spl
EVAL-authentication_method  = case(EventCode IN (4624,4625), LogonType, true(), authentication_method)
EVAL-authentication_service = case(EventCode IN (4624,4625), AuthenticationPackageName, true(), authentication_service)
```

### 2.3 第 3 层:LOOKUP 语义翻译

```ini
# props.conf —— EventCode → 事件签名/动作
LOOKUP-CategoryString_for_windows = windows_signature_lookup signature_id OUTPUTNEW CategoryString,action,result
```

`windows_signature_lookup`(CSV 维表)把 4625+SubStatus 翻译成人话与标准 action(如 SubStatus=0xC0000064 → "User name does not exist")。**编码 → 语义** 的翻译永远放维表,不写死在代码里。

### 2.4 配套的 tags.conf(698 行)

按事件类型打标签,把 Windows 事件挂进 CIM 各模型(如认证类事件 → `authentication` 标签,进程类 → `endpoint`),是 1.3 链路里"TA 侧"的实现。

---

## 三、Splunk_TA_zeek(TA-for-Zeek 1.0.11):流量映射的完整实现

来源:Corelight 生态(Aplura 出品)的 Zeek TA,支持 **JSON + TSV 双格式**、覆盖 **35 种 zeek:\* sourcetype**(conn/dns/http/ssl/ssh/smtp/rdp/tunnel/software/weird/files/pe/dhcp/ntp/irc/dpd/traceroute…),体量 props.conf 1038 行。它同时是"日志接入 → 字段映射"全流程的最小完整实现,最适合当第一份精读材料。

props.conf 头部注释给出了官方的字段提取流水线顺序,可当口诀:

```
EXTRACT -> REPORT -> KV_MODE -> FIELDALIAS -> EVAL -> LOOKUP -> EVENTTYPES -> TAGS
```

### 3.1 接入层:按文件名分流 + `#fields` 头解析

```ini
# transforms.conf —— conn.log → zeek:conn,http.log → zeek:http …
[zeek_autotype]
SOURCE_KEY = MetaData:Source
REGEX = (?:[a-zA-Z0-9_]+\.)?([a-zA-Z0-9_]+)\.log
FORMAT = sourcetype::zeek:$1
WRITE_META = true

# props.conf [zeek] 段 —— TSV 自动读 #fields 头行做列名映射
FIELD_HEADER_REGEX     = ^#fields\t(.*)
HEADER_FIELD_DELIMITER = tab
TIMESTAMP_FIELDS       = ts
TIME_FORMAT            = %s.%6N
```

一套配置吃下全部 Zeek 日志种类;TSV 解析自动跟随 `#fields` 头,Zeek 升级改列时天然兼容,不用手改正则。

### 3.2 FIELDALIAS(ASNEW):Zeek 原生字段 → CIM 网络字段

以 conn.log 段(props.conf:[zeek:conn])为例:

```
FIELDALIAS-id_orig_h = id_orig_h ASNEW src id_orig_h ASNEW id.orig_h id_orig_h ASNEW src_ip
FIELDALIAS-id_resp_h = id_resp_h ASNEW dest id_resp_h ASNEW id.resp_h id_resp_h ASNEW dest_ip
FIELDALIAS-id_orig_p = id_orig_p ASNEW src_port
FIELDALIAS-uid       = uid ASNEW flow_id uid ASNEW session_id
FIELDALIAS-orig_bytes = orig_ip_bytes ASNEW bytes_out
FIELDALIAS-app        = service ASNEW app
```

**ASNEW 是关键**:同一原始字段同时映射到 `src`/`src_ip`/`id.orig_h` 多个标准形态,且"不覆盖已有字段"——兼容不同消费方的字段习惯。http 段另有 `status_code ASNEW status`、`username ASNEW user`、`user_agent ASNEW http_user_agent` 等映射。

### 3.3 EVAL:派生字段与语义规整

conn 段与 http 段共用的派生逻辑:

```spl
EVAL-direction = case(local_orig="true" AND local_resp="true", "internal",
                      local_orig="true" AND local_resp="false", "outbound",
                      local_orig="false" AND local_resp="false", "external",
                      local_orig="false" AND local_resp="true", "inbound",
                      1=1, "unknown")
EVAL-transport = if(proto=="icmp" and match('id.orig_h',".*:.*"), "icmp6", proto)
EVAL-bytes     = tonumber(bytes_out) + tonumber(bytes_in)
```

http 段:`url = extracted_host . uri`、`uri_query`(从 uri 切 query)、`http_user_agent_length`。**`direction` 是最值得抄的一条**:Zeek 原生不直接给"数据流向",基于传感器两侧 local_orig/local_resp 的判定逻辑可直接移植——防泄密检测里数据流向是核心维度。

### 3.4 LOOKUP:语义翻译维表

```ini
[zeek:conn]
LOOKUP-conn_state   = zeek_conn_state conn_state OUTPUTNEW action, conn_state_meaning AS connection_state_description
LOOKUP-conn_history = zeek_conn_history history_letter OUTPUTNEW history_meaning tcp_flag tcp_session_source
```

两张代表性维表:

- `bro_conn_state.csv`:连接状态码 → 含义 + 标准 action(`S0` → "Connection attempt seen, no reply" / blocked;`SF` → 正常建立并终止 / allowed);
- `zeek_conn_history.csv`:conn.log 的 history 字符串逐字母解码(S=SYN、h=SYN+ACK、d=带数据包…)——**异常扫描常表现为 history 字母组合异常**,这张表把技术痕迹变成可检测特征。另有 `zeek_ssl_history.csv` 同理。

---

## 四、给自研 UEBA 的落地清单

读完三个包,CIM 等价物可以收敛为**五类资产**,建议照此在自研设计(`UEBA 异常检测实现设计.md`)中建目录:

| # | 资产 | Splunk 对应物 | 内容 |
|---|---|---|---|
| 1 | **字段规范表** | data models/*.json | 每个数据域(认证/网络/端点/邮件…)的标准字段清单 + 层次分类 + 入模约束(可执行校验查询) |
| 2 | **归一化规则表** | props.conf EVAL / transforms.conf REPORT | 逐数据源逐事件的映射:原始字段 → 标准字段(含多字段 case 回退) |
| 3 | **实体归属规则** | EVAL-user / EVAL-src 的 case 表 | 每个事件 ID 回答"行为归哪个用户/哪台设备"——**防泄密场景最关键的一份资产** |
| 4 | **枚举翻译表** | lookups/*.csv | 编码 → 语义(事件签名、action、协议、状态码),永放维表不放代码 |
| 5 | **物理解耦层** | macros.conf | 检测规则不写死索引名/字段名,统一经命名引用 |

### 设计要点(官方实现反复出现的模式)

1. **三层流水**:抽取(保真)→ 归一(语义)→ 翻译(可读),各层职责绝不混杂;
2. **case 回退**:同一标准字段的来源按事件类型分派,且总有 `true(), 默认` 兜底——自研映射表同样要支持多候选回退;
3. **标签驱动分类**:分类(成功/失败、特权/普通)基于归一化后的字段值打标,检测与模型都只依赖标签/标准字段,不依赖厂商字段;
4. **映射本身是数据**(JSON/CSV),不是代码——方便比对、版本化、给非工程同学审阅。

### 建议的精读顺序(团队上手)

`Splunk_TA_zeek`(最小完整,半天)→ `Splunk_SA_CIM` 的 Authentication.json + tags.conf(半天)→ `Splunk_TA_windows` 的 EVAL-user/EVAL-src 段落(重点逐 EventCode 过一遍,产出我们的实体归属表初稿)。

---

## 附:本地文件位置

- `splunk-ueba-调研/Splunk_SA_CIM/` —— CIM 定义包(已解压)
- `splunk-ueba-调研/Splunk_TA_windows/` —— Windows TA(已解压)
- `splunk-ueba-调研/Splunk_TA_zeek/` —— Zeek TA,即 TA-for-Zeek 1.0.11(已解压)
- 原始下载包:`splunk-common-information-model-cim_870.tgz`、`splunk-add-on-for-microsoft-windows_1102.spl`、`ta-for-zeek_1011.tgz`
