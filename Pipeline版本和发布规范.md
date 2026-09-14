# Pipeline 版本和发布规范

> 版本：1.0.0  
> 对象：采集配置、Parser、Mapping、标准化函数、Enrich、Elasticsearch Ingest Pipeline 和模板

## 1. 版本对象

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

## 2. 语义化版本

| 变化 | 版本 |
|---|---|
| 修复实现错误，合同和输出不变 | Patch |
| 新增可选字段、兼容来源或事件类型 | Minor |
| 改变字段语义、单位、方向、主类型、实体键或必填条件 | Major |

紧急修复同样必须生成新版本，禁止原地修改已发布 Pipeline。

## 3. 环境与状态

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

## 4. 发布制品

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

## 5. 测试与模拟

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

## 6. 历史回放

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

## 7. 影子运行

新旧版本消费同一原始事件，分别写入：

```text
active: logs-ueba.<domain>-default
shadow: logs-ueba-shadow.<domain>-<candidate-version>
```

比较项：事件守恒、主类型、字段覆盖、类型错误、quality 状态、字节/时长、实体键、特征值、异常量和风险实体变化。差异必须归类为预期、修复、接受风险三种。

## 8. Canary 与切换

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

## 9. 回滚

触发条件包括：

- invalid/Failure Store 比例显著上升；
- 关键字段覆盖下降；
- source/destination 或 actor/target 方向错误；
- 重复事件增加；
- 数据延迟或资源消耗越界；
- 特征/告警量出现无法解释的变化。

回滚步骤：停止候选路由、恢复上一 active 版本、冻结受影响时间窗、确定原始事件范围、修复后重放、重算受影响特征/基线/异常。禁止仅删除错误标准事件而不处理下游派生结果。

## 10. Failure Store

Processor 异常使用 `on_failure` 写入错误类型、processor tag、Pipeline 版本；Mapping 冲突等索引失败进入 Failure Store。失败事件必须保留进入 Pipeline 前的原始内容和来源位置。[Elastic Ingest 错误处理](https://www.elastic.co/docs/manage-data/ingest/transform-enrich/error-handling)

重放失败事件前必须先在 `_simulate` 验证；重放成功后记录原失败 ID、新 event.id、修复版本和时间。

## 11. 发布门禁

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

