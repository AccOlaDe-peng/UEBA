# UEBA 网络协议可疑事件与异常场景预研

日期：2026-09-07  
范围：从网络侧日志发现网络协议的可疑事件，并将多个事件关联为 UEBA 异常场景。本文补充《可疑事件与异常场景清单》和《网络协议异常检测简版设计》，重点覆盖原文尚未展开的协议语义。

## 1. 结论

1. 不能只采集 `conn/dns/tls`。建议第一期至少启用 Zeek 的 `conn、dns、http、ssl/tls、x509、ssh、rdp、smb_files、smb_mapping、dce_rpc、kerberos、ntlm、ldap、smtp、ftp、files、dhcp、ntp、tunnel、weird、notice、analyzer、capture_loss`；网络设备侧补充防火墙、代理、VPN、NAT、DHCP 和 NetFlow/IPFIX。QUIC、DoH、DoT 等加密协议需要专门补盲。
2. 网络协议检测要分四层：**协议确定性违规、协议窗口异常、实体行为基线偏离、跨协议时序场景**。单个“罕见”“长连接”“高熵”通常只能成为信号，不能直接判攻击。
3. 网络日志擅长回答“谁与谁、用什么协议、何时、多少、协议握手和事务是否异常”；无法独立证明“由哪个用户/进程发起、传的是不是敏感数据、登录是否真的成功”。这些结论必须关联 DHCP/VPN/NAT、AD/IdP、EDR/Sysmon、DLP、邮件/云审计。
4. 建议新增 **47 个协议可疑事件**、编排为 **18 个异常场景**。其中确定性规则优先落地，UEBA 基线用于减少误报和发现慢速、低频、首次出现的行为。

## 2. 网络日志如何获得

### 2.1 采集面

| 采集位置 | 日志/产品 | 能获得的证据 | 主要盲区 |
| --- | --- | --- | --- |
| 核心、出口、服务器区镜像 | Zeek | 协议识别、事务元数据、连接字节/包、文件元数据、协议异常 | 看不到交换机未镜像的流量；TLS 正文不可见 |
| 同一镜像流量 | Suricata EVE | 签名告警、协议/流/文件/异常 JSON，可用 `flow_id` 关联 | 规则覆盖与加密限制 |
| 边界设备 | Firewall/NGFW/Proxy/SWG | allow/deny、NAT、URL 类别、用户、应用识别、策略命中 | 内网东西向流量可能不可见 |
| 网络基础设施 | DHCP/DNS/NAC/交换机/VPN | IP—MAC—资产—用户—会话的时间映射 | 保留周期不足会导致历史归属错误 |
| 流量摘要 | NetFlow/IPFIX | 大范围流向、字节、包、持续时间 | 缺少应用层语义，不适合单独判断协议异常 |
| 终端与身份 | EDR/Sysmon/auditd/AD/IdP | 进程、用户、登录结果、命令和文件 | 不属于纯网络日志，但决定 UEBA 归因可信度 |

### 2.2 关联键与质量要求

- Zeek 内部优先使用 `uid` 关联 `conn` 与协议日志；跨 Zeek/Suricata/流记录使用 `community_id`，否则回退到时间约束五元组。
- IP 归属必须按**事件发生时间**查询 DHCP、VPN 和 NAT 历史，不能用当前快照回填历史。
- 每条信号保留 `sensor_id、event_time、uid/community_id、source/destination、asset_id、user_id、raw_event_refs、data_quality`。
- 必须监控 `capture_loss.log、reporter.log、analyzer.log`、日志延迟、字段缺失和传感器心跳；“没看到协议”不等于“协议未发生”。
- 方向判断先结合内网网段、NAT 和资产角色；`orig_bytes` 只有在已确认发起方和出站方向后才可解释为上行。

## 3. 判定方法

| 代码 | 方法 | 适用情况 | 例子 |
| --- | --- | --- | --- |
| R | 确定性规则 | 明确违反策略或协议约束 | 办公终端直连公网 SMB、明文 LDAP 简单绑定 |
| Q | 窗口聚合 | 数量、范围、比例、失败率或时序异常 | 扫描、密码喷洒、DNS 枚举 |
| B | UEBA 基线 | 必须先知道该实体平时如何行为 | 首次 SSH 对端、异常上传量、罕见证书 |
| S | 单检测器多特征评分 | 单一指标不可靠，需要同类证据共同成立 | DNS 隧道、Beacon、域前置疑似信号 |

基线至少比较“资产自身 7/30 天”“同角色同区域资产”“企业全局罕见度”，并按工作/非工作时间分桶。阈值必须用本企业正常流量和攻击回放标定，本文的数量仅给出窗口和方向，不把经验数字写成生产事实。

## 4. 协议级可疑事件矩阵

### 4.1 通用连接、隧道与规避

| ID | 可疑事件 | 方法 | 主要日志/字段 | 检测要点与排除项 |
| --- | --- | --- | --- | --- |
| NP-001 | 协议与受管端口不匹配 | R | `conn.service`、端口、Suricata `app_proto` | 仅在 DPI 已明确识别协议时判定；非标准业务端口走例外 |
| NP-002 | 资产使用禁止协议 | R | `conn`、资产角色、协议策略 | 如办公终端出公网 SMB/Telnet/IRC；批准运维资产排除 |
| NP-003 | 直连公网绕过代理 | R | `conn`、FW/NAT/Proxy | 应强制代理的资产直接出网；代理自身和更新节点排除 |
| NP-004 | 未识别或裸 TCP/UDP 异常 | B | `conn.service=-`、字节/包/持续时间 | 与资产历史、端口、新目的地、周期性组合，不能因未识别直接告警 |
| NP-005 | 协议切换/单向解析异常 | Q | `weird/analyzer`、Suricata anomaly | 同一资产/对端异常率聚集；采集截断、非对称路由先排除 |
| NP-006 | 通用 Beacon/心跳 | S | 连接时间、字节、包、duration | 间隔和包长低变异且目标罕见；更新、监控、EDR 白名单 |
| NP-007 | 低慢外传 | B | 分日上行量、对端、会话 | 自身趋势持续升高且高于同岗位/同角色；至少观察 2–4 周 |
| NP-008 | 分片外传 | Q | 连接/HTTP/文件日志 | 大量近等体积、小间隔、同目标上传；备份和对象存储分块排除 |
| NP-009 | IP/IPv6 隧道或嵌套隧道 | R/Q | `tunnel.log`、IP 协议号、GRE/Teredo | 非授权封装、办公网出现 GRE/6in4/Teredo；企业 VPN 排除 |
| NP-010 | ICMP 隧道或载荷异常 | S | ICMP type/code、包长、频率、双向字节 | 非 echo 类型、载荷大且稳定/高熵/周期；网络监控排除 |
| NP-011 | Tor/匿名代理/公共 VPN | R/B | 目的 IP/ASN、TLS、流量情报 | 高置信节点清单 + 资产策略；研发和获批隐私工具例外 |

### 4.2 DNS 与加密 DNS

| ID | 可疑事件 | 方法 | 主要日志/字段 | 检测要点与排除项 |
| --- | --- | --- | --- | --- |
| NP-012 | DNS 隧道 | S | `dns.query/qtype/rcode/answers` | 按资产+注册主域聚合长度、熵、唯一子域比、TXT 比、节奏和流量；CDN/安全软件排除 |
| NP-013 | DGA/NXDOMAIN 聚集 | S | query、rcode、TTL | 高 NXDOMAIN 比例 + 大量随机注册主域 + 低重复率；搜索域补全排除 |
| NP-014 | DNS 内网枚举 | Q | 内部名称、SRV/PTR 查询 | 批量 `_ldap/_kerberos`、主机名/PTR；域控制器和资产扫描器排除 |
| NP-015 | 绕过企业解析器 | R | DNS 目的 IP/端口、资产策略 | 客户端直接访问外部 53；批准递归服务器例外 |
| NP-016 | DoH/DoT/DoQ 使用异常 | R/B | TLS SNI/JA4/ALPN、HTTP、QUIC、目的情报 | 禁止资产访问已知解析器或突然出现加密 DNS；浏览器策略与企业解析器排除 |
| NP-017 | DNS 响应投毒/异常答案 | Q | answers、TTL、rcode、DNSSEC、来源 | 同域短时返回冲突 ASN/私网地址、异常短 TTL；CDN/GSLB 基线排除 |
| NP-018 | 超大 DNS 响应/放大行为 | Q | query/response 字节、qtype、源端分布 | 小请求大响应、ANY/TXT/DNSSEC 聚集、源地址异常；权威 DNS 角色区分 |

### 4.3 HTTP、TLS、QUIC 与 Web/API

| ID | 可疑事件 | 方法 | 主要日志/字段 | 检测要点与排除项 |
| --- | --- | --- | --- | --- |
| NP-019 | 异常 HTTP 方法或方法分布 | R/B | `http.method/host/uri/status` | CONNECT/PUT/DELETE/PROPFIND 等违反资产策略或首次出现；WebDAV/API 服务例外 |
| NP-020 | HTTP 大上传/POST 突增 | B | request body length、orig bytes、MIME | 超自身及同类基线并发往未批准目标；普通表单不能仅靠 POST 次数判断 |
| NP-021 | 自动化下载/投递 | S | UA、URI、MIME、文件哈希、状态码 | 罕见/空 UA、脚本式路径、大响应后短时外联；合法代理/软件分发排除 |
| NP-022 | URI/参数枚举与 Web 扫描 | Q | URI、status、method、目标数 | 大量不同 URI、404/401/403 比例高、固定字典节奏；健康检查/爬虫排除 |
| NP-023 | HTTP Host 与目的 IP/证书矛盾 | S | Host、SNI、证书 SAN、IP | Host≠SNI、SNI/Host 不在证书 SAN、目标归属异常；反向代理/CDN/域前置兼容性排除 |
| NP-024 | 直连 IP、无 Host/SNI 的 Web/TLS | B | Host、SNI、目的 IP、端口 | 相对资产/客户端类型罕见并叠加新目标或周期性；TLS 1.3 ECH、私有服务须降置信度 |
| NP-025 | 罕见或角色不符 TLS 指纹 | B | JA4/JA3、ALPN、TLS version | 首次/低频且不符合获批软件；浏览器升级造成的群体变更不告警 |
| NP-026 | 异常证书 | S | `x509` issuer、subject、SAN、validity、serial | 自签、短有效期、过期、主机名不符、全局罕见签发者，需结合服务场景 |
| NP-027 | 弱 TLS 或异常握手失败 | R/Q | version、cipher、established、alert | 禁用版本/套件可直接违规；失败突增需排除兼容性故障和扫描器 |
| NP-028 | HTTPS/云 API 外传 | B/Q | Host/SNI、方法、字节、URI 类别 | 未批准云盘/代码仓库/API 上行异常、分片或非工作时段；仅 TLS 元数据只能判“疑似” |
| NP-029 | QUIC/HTTP3 策略违规或异常 | R/B | `quic.log`、UDP/443、SNI/ALPN、字节 | 禁止区域出现 QUIC、目标/指纹/上行偏离；浏览器正常 HTTP/3 排除 |

### 4.4 远程访问、文件共享与 Windows 域协议

| ID | 可疑事件 | 方法 | 主要日志/字段 | 检测要点与排除项 |
| --- | --- | --- | --- | --- |
| NP-030 | SSH 首次/罕见访问关系 | B | `ssh`、conn、client/server、host key | 用户/源资产首次连生产服务器、非维护时段；堡垒机和自动化账户分组 |
| NP-031 | SSH 暴力破解或喷洒 | Q | SSH 连接、认证结果（服务端日志优先） | 单源多用户或单用户多失败；Zeek 的加密流量通常不能可靠给出登录结果，需关联 sshd |
| NP-032 | SSH 隧道/端口转发疑似 | S | 长连接、双向字节、会话时间、目的关系 | 服务器向外长时 SSH、流量形态偏离交互会话；需端点参数确认 `-L/-R/-D` |
| NP-033 | RDP 首次/异常横向访问 | B/Q | `rdp.log`、conn、TLS、目的主机数 | 普通终端首次 RDP、多目标扩散、非维护时段；管理员/跳板机基线 |
| NP-034 | SMB 管理共享横向访问 | R/B | `smb_mapping`、share、path、user | `ADMIN$/C$/IPC$` 新源—目标关系或跨区访问；软件分发和域管例外 |
| NP-035 | SMB 批量读取/写入/删除 | Q/B | `smb_files`、action、path、size | 文件数/字节/目录广度异常；备份、补丁和文件服务器角色排除 |
| NP-036 | DCE/RPC 远程服务调用异常 | B/Q | `dce_rpc` operation/endpoint、SMB | 首次远程服务/计划任务/服务控制接口，多目标扩散；管理工具基线 |
| NP-037 | Kerberos 服务票据请求异常 | Q/B | `kerberos`、4768/4769/4771 | 单主体短时请求大量 SPN、罕见加密类型、失败聚集；准确身份/结果需 DC 日志 |
| NP-038 | NTLM 使用异常或降级 | R/B | `ntlm`、SMB/HTTP、Windows 4776 | 禁止区域仍使用 NTLM、Kerberos 后退为 NTLM、来源新颖；旧系统例外 |
| NP-039 | LDAP 枚举/敏感查询 | Q/B | `ldap_search` base/scope/filter/attrs | 大范围 subtree、敏感对象/属性、大结果集、普通终端首次直连 DC；目录同步服务排除 |
| NP-040 | 明文 LDAP 简单绑定 | R | LDAP bind、端口、TLS 状态 | 凭据可能明文暴露；LDAPS/StartTLS 与受控遗留例外 |

### 4.5 邮件、文件传输与基础设施协议

| ID | 可疑事件 | 方法 | 主要日志/字段 | 检测要点与排除项 |
| --- | --- | --- | --- | --- |
| NP-041 | SMTP 异常外发/大附件 | B/Q | `smtp`、`files`、from/to、size | 终端直投公网、外部收件人突增、附件量异常；批准邮件网关必须单列 |
| NP-042 | SMTP 身份或路由异常 | R/B | relay、helo、from/to、TLS | 非邮件服务器中继、HELO/域/来源不一致、明文认证；业务设备例外 |
| NP-043 | FTP/TFTP 明文凭据或禁止使用 | R | `ftp`、command/reply、user、conn | 策略禁止即告警；区分 FTPS/SFTP，后者不是 FTP |
| NP-044 | FTP/SFTP 大量外传 | B/Q | FTP data channel、SSH/conn、files、bytes | 新外部目标、异常上传比、批量文件；SFTP 内容不可见，依赖流量和端点补证 |
| NP-045 | DHCP 伪服务器/地址池异常 | R/Q | `dhcp.log`、MAC、server、assigned IP | 未授权 Offer/Ack、同 MAC 多 IP、租约/服务器突变；网络变更窗口排除 |
| NP-046 | ARP 欺骗/网关 MAC 漂移 | R/Q | Suricata ARP、交换机/NAC、IP-MAC 历史 | 同 IP 多 MAC、网关 MAC 改变、高频 gratuitous ARP；HA 切换例外 |
| NP-047 | NTP 异常或放大行为 | R/Q/B | `ntp.log`、mode、version、bytes、目标 | 客户端访问非批准 NTP、控制查询/放大形态、时间服务器角色异常；批准 NTP 层级排除 |

## 5. 异常场景编排

| 场景 ID | 异常场景 | 必要事件 | 增强证据 | 关联键/窗口 |
| --- | --- | --- | --- | --- |
| NPSC-01 | DNS 隧道 C2/外传 | NP-012 | NP-015/016、NP-006、异常上行 | 资产+注册主域，30 分钟 |
| NPSC-02 | DGA 恶意程序回连 | NP-013 | 新目的 IP、NP-006、TLS 指纹罕见、威胁情报 | 资产，1 小时 |
| NPSC-03 | 加密 DNS 绕过监控 | NP-016 | NP-003、企业 DNS 无对应查询、目的地未批准 | 资产+解析器，1 小时 |
| NPSC-04 | Web C2 | NP-006 + NP-021 或 NP-024 | NP-001、NP-025/026、目标新颖 | 资产+目的地，2 小时 |
| NPSC-05 | HTTPS/云服务数据外传 | NP-020 或 NP-028 | NP-007/008、首次目的地、非工作时间、端点打包事件 | 用户+资产+服务，4 小时 |
| NPSC-06 | 非标准协议隧道 | NP-001/004/009/010 中任一 | NP-006、双向字节异常、目标新颖 | 资产+目的地，2 小时 |
| NPSC-07 | SSH 隧道建立 | NP-032 | NP-030、服务器反向外联、端点 SSH 参数 | 资产+对端，4 小时 |
| NPSC-08 | 暴力破解后 SSH 横向 | NP-031 + NP-030 | 多目标扩散、sudo/提权、非工作时段 | 账号+源资产，2 小时 |
| NPSC-09 | RDP 横向移动 | NP-033 | 认证失败后成功、同账号多主机、异常时段 | 账号+源资产，2 小时 |
| NPSC-10 | SMB 管理共享横向移动 | NP-034 + NP-036 | NP-038、远程服务创建、同文件多主机落地 | 账号+源资产，2 小时 |
| NPSC-11 | SMB 数据收集或勒索扩散 | NP-035 | 大量共享枚举、写入后重命名/删除、横向扩散 | 用户+资产，1 小时 |
| NPSC-12 | Kerberoasting/域服务枚举 | NP-037 或 NP-039 | 罕见账号/主机、RC4、短时大量 SPN | 账号+资产，1 小时 |
| NPSC-13 | NTLM 降级与中间人风险 | NP-038 | NP-046、LLMNR/NBNS 异常、认证失败/成功链 | 用户+资产，1 小时 |
| NPSC-14 | 邮件外传 | NP-041 | NP-042、非工作时间、外部新域、端点文件收集 | 用户+资产，4 小时 |
| NPSC-15 | FTP/SFTP 外传 | NP-044 | NP-043、首次对端、异常上传比、打包事件 | 用户+资产+目的地，4 小时 |
| NPSC-16 | 内网侦察 | DNS 枚举 NP-014、Web 枚举 NP-022、LDAP 枚举 NP-039 或连接扫描任一 | 失败率高、资产角色不符 | 源资产，30 分钟 |
| NPSC-17 | 网络中间人/流量劫持 | NP-045 或 NP-046 | DNS 答案异常 NP-017、TLS 证书异常 NP-026、NTLM 降级 | 二层区域+资产，30 分钟 |
| NPSC-18 | 监控盲区被利用 | 采集丢包/解析失败/日志中断 | 同资产出现 NP-003/004 或边界大流量、端点异常 | 传感器+网段，15 分钟至 2 小时 |

## 6. 与现有清单的关系

| 现有事件 | 本文细化 |
| --- | --- |
| NW-01 协议与端口不匹配 | NP-001、NP-005 |
| NW-03 使用禁止协议 | NP-002、NP-009、NP-029、NP-040、NP-043 |
| NW-04 非授权直连外部网络 | NP-003、NP-015、NP-016 |
| NW-07～09 异常时段/上行/上传比 | 所有外传类事件的 UEBA 增强条件，重点 NP-007/008/020/028/041/044 |
| NW-10 罕见 TLS 指纹 | NP-023～027，将指纹、证书、握手和身份矛盾拆开 |
| NW-11 异常远程管理协议 | NP-030～040，按 SSH/RDP/SMB/DCE-RPC/Kerberos/NTLM/LDAP 拆开 |
| NW-12～16 扫描/扩散/周期/失败 | NP-006、NP-014、NP-022、NP-031/033/036/039 与 NPSC-16 |
| NW-17～19 DNS 隧道/枚举/NXDOMAIN | NP-012～018，补加密 DNS、响应投毒和放大 |
| NW-20 长连接异常 | 不建议单独恢复；长连接只作为 NP-006/032 的一个特征 |

建议不要直接把 47 条全部塞回原有 `NW-*` 表。更稳妥的结构是：原表保留跨协议能力，本文矩阵作为“协议检测子目录”；每个 NP 信号映射到一个或多个 NW 事件/SC 场景，避免上层事件数量失控。

## 7. 仅靠网络日志不能可靠得出的结论

| 想判断的事实 | 网络日志局限 | 必须补充 |
| --- | --- | --- |
| 某用户登录成功 | SSH/RDP/TLS 加密后，探针未必获得认证结果或账号 | AD/Windows 4624/4625、sshd、VPN/IdP |
| 某进程发起连接 | 镜像流量通常只有 IP/端口 | EDR、Sysmon Event 3、eBPF |
| 外传了敏感数据 | 字节量和目标异常不等于内容敏感 | DLP、文件标签/哈希、代理或端点文件事件 |
| TLS 无 SNI 就恶意 | IP 直连、ECH、旧客户端和私有协议均可能无 SNI | 客户端类型、ECH 能力、目标/证书/进程上下文 |
| 端口开放等于登录成功 | TCP 成功仅代表连接或握手，不能证明认证成功 | 服务端认证日志 |
| 未见日志等于未发生 | 丢包、非对称路由、旁路、QUIC/ECH 可形成盲区 | 采集质量、边界日志、端点遥测 |

## 8. 落地优先级

### P0：先把证据做可信

1. 启用协议日志、`weird/analyzer/capture_loss`，统一 `uid/community_id`。
2. 接入按事件时间生效的资产、DHCP、VPN、NAT、网段、资产角色和批准服务表。
3. 验证镜像覆盖、东西向可见性、IPv6、UDP/443、分片和非对称路由。

### P1：高收益、易解释

- NP-001～003 协议/端口/代理策略违规；
- NP-012～016 DNS 隧道、DGA、枚举、外部/加密 DNS；
- NP-030、033～040 远程访问和域协议异常；
- NP-041～047 邮件、文件传输、DHCP/ARP/NTP 基础设施异常。

### P2：需要稳定基线

- Beacon、低慢和分片外传；
- HTTP 上传、TLS/证书/QUIC 新颖度；
- SMB/LDAP 数量与范围偏离；
- 18 个跨协议场景和用户/进程关联。

### P3：评测与运营

- 使用正常流量回放 + CALDERA/Atomic Red Team/自建 PCAP 验证字段和召回；
- 指标同时评估事件级 precision、场景级 precision、检测时延、字段完整率和日告警量；
- 每条检测维护适用资产、必要条件、增强条件、排除条件、最小样本、版本和回滚策略。

## 9. 参考资料

- Zeek 官方日志目录：<https://docs.zeek.org/en/current/reference/logs/index.html>
- Suricata EVE JSON 与跨事件 `flow_id`：<https://docs.suricata.io/en/latest/output/eve/eve-json-format.html>
- Suricata EVE 字段 Schema：<https://docs.suricata.io/en/latest/appendix/eve-schema.html>
- MITRE ATT&CK T1071 Application Layer Protocol：<https://attack.mitre.org/techniques/T1071/>
- MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol：<https://attack.mitre.org/techniques/T1048/>
- MITRE ATT&CK T1021 Remote Services：<https://attack.mitre.org/techniques/T1021/>
- MITRE ATT&CK T1572 Protocol Tunneling：<https://attack.mitre.org/techniques/T1572/>
- MITRE ATT&CK T1557 Adversary-in-the-Middle：<https://attack.mitre.org/techniques/T1557/>
- RFC 8484 DNS over HTTPS：<https://www.rfc-editor.org/rfc/rfc8484>
- RFC 9250 DNS over QUIC：<https://www.rfc-editor.org/rfc/rfc9250>
- RFC 9000 QUIC：<https://www.rfc-editor.org/rfc/rfc9000>
- RFC 9460 SVCB/HTTPS Resource Records：<https://www.rfc-editor.org/rfc/rfc9460>

