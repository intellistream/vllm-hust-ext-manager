# 顶会成稿差距清单：Evidence-Carrying Plugin Architecture

主责与执行人：`ShuhaoZhangTony`（张书豪）。本课题由 PI 直接、自主推进；学生
贡献仅作为可选协作，不构成论文或实验关键路径。

## 已写成

- 已有完整英文双栏论文草稿，覆盖摘要、问题、系统/威胁模型、不变量、失败语义、设计、实现、评测方法、相关工作、局限与结论。
- typed manifest、capability negotiation、conflict planner、四态生命周期、process-owned evidence、fail-closed activation、deterministic rollback 和 provider/runtime authority separation 已形成统一叙事。
- H1--H4、三类 baseline、failure/composability/version-skew matrix、指标和 stop/go 门槛已进入正文。
- 已建立结果 JSON Schema、planned 示例和校验入口；缺失结果必须为 `null`，不能伪装为零。
- 已建立 11 个真实注册扩展、5 个 adaptation candidate 的证据语料库，并选出 BidKV、Mooncake、Production Stack、KV Admission、Request Lifecycle 五个差异化案例。
- 已建立 ECPA 0.1 contract 草案、manifest JSON Schema、有效/无效 fixture、L0--L4 分级和 conformance 骨架。Extension Manager 明确为 reference implementation，不等同于规范本身。

## 已有实现证据

- 当前 main 的 66 个 CPU 测试通过。
- typed manifest、静态 discovery、配置/enable intent、provider plan/render/check、冲突拒绝和非变更 authority 边界已有实现基础。
- `3201e133` namespace 变更提供真实负例：单测全过，但安装后的 Mooncake entry point 在错误 namespace 下从 1 个变 0，bundle discovery 为空。
- Mooncake、Production Stack、BidKV 有仓库内既有集成证据，但尚不是论文要求的 matched formal campaign，不能直接当作 H1--H4 成功结果。

## 必须补实现

- 冻结 machine-readable capability/resource taxonomy 和独立 ownership oracle。
- 实现跨 parent/worker 的 launch identity、process membership、load/invocation evidence 与 freshness/replay 校验。
- 将 conflict planner 扩展到 conditional ownership、同资源异名和三插件组合。
- 实现 prepare/launch/observe/commit 的事务边界，以及可验证 predecessor plan rollback。
- 将真实安装包 namespace probe 纳入持续测试，防止 mock-only 回归。
- 将 11 个注册扩展逐步迁移为 ECPA manifest；当前 corpus 证明扩展面存在，不证明 L2--L4 符合性。

## 必须补实验

- 逐 cell 跑 vanilla vLLM entry points、manual integration、ECPA 三臂对照。
- 完成 failure、composability、version-skew、multi-process、upgrade/rollback 矩阵；每个正式 cell 至少三次独立服务启动并交替 arm 顺序。
- 报告 activation coverage、false-effective、conflict precision/recall、rollback success/recovery、跨进程一致性。
- 分解 discovery/validation/planning/render/evidence 的启动成本，并报告吞吐、p99、CPU、内存、消息数与 evidence bytes。
- 形成原始 artifact、环境/版本 manifest、失败记录、置信区间和逐 cell 表；不能只报均值。

## 投稿前风险

- 当前最薄弱点是 process-owned runtime evidence 尚未形成跨真实多进程运行时的完整实现与测量。
- 若冲突 oracle 不能独立标注，precision/recall 会退化为自证；需要盲审或双人标注。
- 若 evidence 进入请求关键路径导致 H4 超限，应降级为生命周期采样或把论文重新定位为工程治理。
- deterministic rollback 只能覆盖 Manager-owned intent/config；不得暗示能够回滚外部服务、数据或集群。
- 相关工作仍需系统性补充论文级引用，目前官方文档引用只足以界定 upstream 行为。
- venue 未确定，当前模板仅为通用双栏；投稿前必须切换到当年官方模板并重新检查页数、匿名和 artifact 规则。
- “行业标准”仍无外部采用证据；必须先有独立实现互操作、上游 RFC、跨组织维护、公开符合性结果和中立治理，当前只能主张 candidate interoperability specification。
