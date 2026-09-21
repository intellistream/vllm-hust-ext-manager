# 顶会成稿差距清单：ECPA

状态更新时间：2026-09-21。文件名保留首次评审日期，本文内容以本节日期为准。

主责、系统设计、实验设计、oracle、分析和论文写作：`ShuhaoZhangTony`
（张书豪）。真实 Ascend 环境 preflight、服务启动和原始运行材料采集可作为冻结后的
执行任务交给 `Apei-520`（裴方瑞）；这不转移课题、结论或论文责任。

## 已完成并进入 `main`

- 完整英文双栏论文草稿可由 Tectonic 编译；摘要、问题、威胁模型、不变量、失败语义、
  设计、实现、评测、局限和结论已经连成同一主线。
- typed manifest、静态 discovery、capability/resource conflict planner、不可变 Plan、
  事务生命周期、ExposureGate、durable single-host coordinator、rollback 分类和
  authority-owned evidence 边界已有实现与测试。
- formal harness 已具备 challenge-bound phase protocol、独立 lifecycle fact source、
  Linux PID/start-ticks/argv identity、Plan-wide worker coverage、原子 generation 发布、
  adapter admission、manager-controlled `formal-run` 和 crash-consistent fault actuator。
- 论文外部有效性总体已经纠正为 vLLM-HUST 插件页面的 24 个 MOD。页面 metadata、
  24 个 repository identity/head、integration class、package/CPU evidence 和摘要均
  fail-closed 绑定；旧 11-extension corpus 只保留为 31-case static-planner seed。
- 24 个 MOD 中 16 个可被当前 ECPA bundle namespace 发现；DLA 的 near-miss
  namespace 是一个真实 negative。21 个一般 package project 在隔离环境构建通过；
  17 个 MOD 的本地 source/CPU tests 通过，5 个受 Ascend host dependency 阻塞，
  2 个 source scaffold 没有自动化测试。这些均不是 NPU/runtime-effective 结果。
- 当前完整 extension-manager 测试为 537 passed；paper evidence generator、research
  matrix、Ruff、diff hygiene 和 Tectonic build 均通过。

## PI 可直接快速推进

- 保持 paper、schema、generated tables/figures 与 24-MOD corpus 同步，清除旧的
  11-extension 或旧测试计数叙述。
- 完成静态 contract taxonomy、resource alias 和 representative 24-MOD case mapping
  的论文表达；不把 modeled precision/recall 写成 runtime effectiveness。
- 审核 runbook、部署 identity、三臂命令、workload 和统计口径；正式运行前冻结
  H1--H4、seed、arm order、warm/cold policy 和 missing-data policy。
- 完善相关工作、局限、artifact/reproduction 文档以及目标会议当年模板。
- 对收到的 raw records 做 schema validation、独立 oracle 重算、置信区间、图表和
  论文集成。缺失 cell 保持 `null`，不得补零。

## 交给 `Apei-520` 的真实环境执行包

执行入口是 Issue #9；Issue #12 的实验设计和论文汇总仍由 PI 负责。

- 在真实 Ascend 节点提交设备、CANN/driver、torch/torch_npu、vLLM/vLLM-Ascend
  exact-version preflight，并确认 `libhccl.so` 可解析。
- 准备 `partial-worker-coverage` 首个 cell 的 3 arms × 3 independent starts，保存
  exact commands、PID/start ticks/argv、Plan/launch identity、raw JSONL、逐样本延迟、
  失败和设备释放记录。
- 从页面 24 MOD 中准备第二个不同 authority domain 的真实案例；优先生命周期或
  KV-transfer observer，并以实际 entry point、hook 和 effect boundary 为依据。
- 在 producer PR、deployment registration 和 adapter registry 门槛未解除前，只交
  preflight/runbook 或明确标注的非正式 pilot，不得称为 formal-real。

## 尚未解除的硬门槛

- `vLLM-HUST/vllm-hust#27` 仍为 OPEN；当前 head
  `c9b6bbff27fc8241ba37abf037560cf2875317a2` 的 checks 成功，但没有 human review。
- `verified-adapters.json` 仍为空，首个 formal-real study 仍为 `pre-admission`，部署
  registration 仍为 `unregistered`。
- 首个 pilot 是 3 arms × 3 starts，当前 0/9；完整 formal matrix 当前 0/30 cells。
- H1--H4 的 activation coverage、false-effective、rollback 和 overhead 数值仍为空。
- request throughput、TTFT、TPOT、p99、CPU/memory/message/evidence-byte overhead 尚无
  matched formal campaign；不得用 repository-local benchmark 代替。

## 投稿前最低剩余结果

1. 一个 independently observed、registry-admitted 的三臂 9-start formal-real pilot。
2. 至少四类真实 MOD 的 effect-boundary case study：scheduler、speculative/model path、
   KV/state path、observability；每类区分 discovered/planned/invoked/effective/exposed。
3. failure、version-skew、multi-process replacement 和 rollback 的正式矩阵及 raw data。
4. phase-separated startup cost 与 steady-state throughput/TTFT/TPOT/p99 overhead，报告
   分布和置信区间而非只报均值。
5. 完整 artifact manifest、复现脚本、失败记录、匿名化检查和目标会议模板。

当前最大风险不再是缺少框架代码，而是把 source/package/CPU 或 modeled evidence
误写成真实运行结果。若无法取得真实多进程、真实插件和 matched performance 数据，
论文只能保持系统设计/Artifact 草稿，不能按 OSDI/SOSP/NSDI/EuroSys 完成稿投稿。
