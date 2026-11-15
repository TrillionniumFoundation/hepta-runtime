#!/usr/bin/env python3
"""Render frozen R15 audit results; never launch a workload or mutate evidence."""
import datetime
import hashlib
import json
import math
from pathlib import Path

ROOT = Path("/home/qian/hepta-runtime-optimization-20261103-r15")
R14 = ROOT.with_name("hepta-runtime-optimization-20261103-r14")
EXPECTED = {
    "independent-performance-audit.json": "3a3724e5a1cfbd4daade73d68ad96f2e97aad71f47a2f948fb8d1669cacfe4db",
    "performance-report-data.json": "e8203c3477de1ebeb353dfa74affc2bbc65090d33477b74c7852a39ae0f2f2b2",
    "qualification-audit-summary.json": "5d99035bb3800fab4edcd7b21534d98f215f1a1411317999905677a81d5ae901",
    "independent-recovery-audit.json": "b276c885da5b821192ce454c6117c6fce6d7300df1164331d4d9c81b71ebbb5e",
    "configuration-qualification-01/report.json": "bce0c05b8f13e6858ecd14d024364450cc08fd90f8adabb55d5c1323c0944a89",
    "baseline-binding.json": "d701ad5c2d101ed389614083b386324c092182dcf19cb4f4bf0777e232d3c37a",
    "configuration/configuration-ready.json": "fb4a2e8eab0bfafb0c272c4c3e259cd1d68dffbaa479796854a73a1100fcc947",
    "configuration/hepta-runtime-x230-glibc.sh": "7814b30921098756eb97624ee93876b538b11ce5dc3093dc52bd0e6c9335b525",
    "configuration/allocator-policy.json": "2f0ba167b73ea00b684d0f0f56f6e8d66832bd6bd72db848d89b6c8ca646a3ac",
    "configuration/wrapper-validation.json": "0d56f71802b5fe92e4188e2e9a4e3950afdb870e1fba8b93d9751c49d1657603",
    "configuration/loader-precedence.json": "2b21e5d5b00a2590b96a0a456764e3f4691822a456754284b8544cbd1090d1b0",
    "independent-audit-tools/environment-selftest-01.json": "0d82f2ee23f0bd5a8c92f431d7a403b413ca097b4ab0a7c53d392d15758f85fa",
    "independent-audit-tools/allocator-tooling-review.json": "8c87efb5b5aaa0e347bcc3f8beaa61d7c66d21011daf006550a41367b30f7cbb",
    "independent-audit-tools/frontier-assessment-before-r15.json": "bb406ff39275ab5698d7221831e583fde8d678d2c5d5a9d26545662e27faa463",
    "independent-audit-tools/performance-attempt-01/execution.json": "d89a3f457b3bd98d2f8f96c84a5784fc76b79e9b3c83835dd465b52df2cf71d2",
}
INPUT = {}
def read_bound(rel):
    p = ROOT / rel
    b = p.read_bytes()
    sha = hashlib.sha256(b).hexdigest()
    assert sha == EXPECTED[rel], (rel, sha, EXPECTED[rel])
    INPUT[str(p)] = {"sha256": sha, "bytes": len(b)}
    return json.loads(b) if rel.endswith(".json") else b.decode()

values = {k: read_bound(k) for k in EXPECTED}
d = values["performance-report-data.json"]
a = values["independent-performance-audit.json"]
q = values["qualification-audit-summary.json"]
r = values["independent-recovery-audit.json"]
configq = values["configuration-qualification-01/report.json"]
for obj in (d, a, q, r, configq):
    assert obj["success"] is True
assert a["performance_report_data"]["sha256"] == EXPECTED["performance-report-data.json"]
assert d["candidate_allocator_environment"] == {"MALLOC_ARENA_MAX": "1"}
assert q["source_input_count"] == 219 and q["source_tested_after_current_equal"] is True
assert q["compiler_invocations"] == 0 and q["rust_source_modified"] is False
assert {k:q["tests"][k] for k in ("passed","failed","ignored","selected","retries")} == {
    "passed":1637,"failed":0,"ignored":33,"selected":1670,"retries":0}
assert q["allocator_observation_counts"] == {"verified":1647,"unavailable_process_exited":0}
assert r["counts"]["hosts"] == 6 and r["counts"]["native_replies"] == 90
assert r["counts"]["ssh_probes"] == 36 and r["counts"]["automatic_rpc_retries"] == 0
assert r["successful_cancel_concurrency"]["observed_peak_overlap"] == 6
assert len(d["negative_directional_results"]) == 75
for name in ("cancel_r14_r15","cancel_r11_r15"):
    assert len(d[name]["cells"]) == 4
    for c in d[name]["cells"]:
        for arm in ("A","B"):
            assert c[arm]["mixed_calls"] == 432
            assert c[arm]["cancel_calls"] == 384 and c[arm]["host_list_calls"] == 48
            assert len(c[arm]["vmhwm_kib_samples"]) == 2
            assert len(c[arm]["vmrss_after_kib_samples"]) == 2
for name in ("native_r14_r15","native_r11_r15"):
    assert [c["concurrency"] for c in d[name]["cells"]] == [1,4,8]
    for c in d[name]["cells"]:
        assert c["A"]["calls"] == 192 and c["B"]["calls"] == 192
assert d["proof_totals"] == {
    "unique_live_controller_generations":48,
    "cancel_full_response_hashes_and_semantics":7488,
    "native_hash_only_calls":3024,
    "native_full_transport_envelopes_rehashed":0,
}

def h(path):
    b = path.read_bytes()
    return {"path":str(path),"sha256":hashlib.sha256(b).hexdigest(),"bytes":len(b)}

def num(x, digits=4):
    assert isinstance(x,(int,float)) and math.isfinite(x)
    return f"{x:,.{digits}f}"

def pct(x):
    assert math.isfinite(x)
    return f"{x:+.2f}%"

def ints(xs):
    return " / ".join(num(x,0) for x in xs)

def table(headers, rows):
    def esc(x):
        return str(x).replace("|",r"\|").replace("\n"," ")
    return "\n".join([
        "| " + " | ".join(map(esc,headers)) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
        *["| " + " | ".join(map(esc,row)) + " |" for row in rows],
    ]) + "\n"

def case(c):
    return f"w{c['workers']}; {c['receipt_bytes']:,} B"

def title(name):
    return "R14 default → R14 + arena1（同一二进制）" if "r14" in name else "R11 default → R14 + arena1（代码与配置合并）"

def pair_table(cells,m1,l1,m2,l2,key=case,digits1=4,digits2=4):
    rows=[]
    for c in cells:
        rows.append([key(c),num(c["A"][m1],digits1),num(c["B"][m1],digits1),
                     pct(c["change_percent"][m1]),
                     num(c["A"][m2],digits2),num(c["B"][m2],digits2),
                     pct(c["change_percent"][m2])])
    return table(["场景",f"A {l1}",f"B {l1}","Δ B/A",f"A {l2}",f"B {l2}","Δ B/A"],rows)

chunks = [
"# R15 独立性能结果",
"",
"本文件直接从冻结的 performance-report-data.json 格式化；不重新运行测量或原分析器。所有显示值都只在最后一步四舍五入，完整精度以 JSON 为准。",
"",
f"数据 SHA256：{EXPECTED['performance-report-data.json']}。独立审计 SHA256：{EXPECTED['independent-performance-audit.json']}。",
"",
"## 比较、分母与范围",
"",
"A/B 为每个实验自己的基线/候选，执行顺序为 ABBA，各臂两个新进程。R14 对照使用完全相同的已资格二进制；R11 对照同时包含代码与配置差异。不同 campaign 的结果不相加、不相乘、不混池。",
"",
"每个 cancel campaign 共 16 个 controller、3,456 次 measured RPC、288 次 warmup RPC。每个 worker/receipt 场景、每一臂汇总 432 次 measured RPC（384 次预期的 wrong-host cancel 拒绝 + 48 次 host_list）。CPU ms/RPC = 两进程 measured CPU 秒之和 × 1000 / 432；RPC/s = 432 / 两进程 measured wall 秒之和。warmup 不进入这两个分母。",
"",
"大 receipt 精确为 4,194,272 字节，小 receipt 为 1,024 字节。cancel fixture 走完整验证和预期拒绝入口，但不 append 成功取消意图、不执行远端取消，因此不能把该速率称为成功取消吞吐。",
"",
"分位数对单个 campaign、场景、臂和工具的原始 measured 延迟合并后取 nearest rank ceil(p×N)，不是平均各进程 p95。host_list N=48，p95 为第 46 个，p99 为第 48 个（最大值）；cancel N=384，p95 为第 365 个，p99 为第 381 个。",
"",
"VmHWM 是整个 child 自 exec 起的高水位，包含初始化和 warmup；RSS-before/after 是 measured 前后的点采样，RSS-after 不代表 idle 后或峰值。下表中位数来自两个新进程，样本对同时保留。",
"",
"每个 native campaign 共 1,152 次 measured、288 次 warmup、72 次 preflight/restart 验证，合计 1,512 次。每个 C/臂为两个 first-controller 各 96 次 measured，共 N=192；p95 为第 183 个，p99 为第 191 个。CPU 与速率同样用 pooled 分子和 wall 分母。四次 first-controller 和四次 restart 共 8 次 live 环境观察。",
"",
"所有 Δ 是 (B/A−1)×100%。速率变大为有利方向，CPU、延迟及内存变小为有利方向；仅两个进程/臂，不宣称统计显著性。",
"",
]
for name in ("cancel_r14_r15","cancel_r11_r15"):
    cs=d[name]["cells"]
    chunks += [f"## Cancel：{title(name)}","",
               "A = clean allocator default；B = 仅注入 MALLOC_ARENA_MAX=1。每行/臂为上述 432 次 measured RPC。","",
               "### CPU 与混合 RPC 速率","",
               pair_table(cs,"cpu_ms_per_mixed_rpc","CPU ms/RPC","mixed_rpc_per_second","RPC/s"),"",
               "### host_list 尾延迟（ms；N=48/臂，p99=max）","",
               pair_table(cs,"host_list_p95_ms","p95 ms","host_list_p99_ms","p99 ms"),"",
               "### cancel 拒绝尾延迟（ms；N=384/臂）","",
               pair_table(cs,"cancel_p95_ms","p95 ms","cancel_p99_ms","p99 ms"),"",
               "### 整 child 内存中位数（KiB；2 个进程/臂）","",
               pair_table(cs,"vmhwm_kib_median","VmHWM KiB","vmrss_after_kib_median","RSS-after KiB",digits1=0,digits2=0),"",
               "### 内存样本对与计算分子",""]
    rows=[]
    for c in cs:
        for arm in ("A","B"):
            v=c[arm]
            rows.append([case(c),arm,ints(v["vmhwm_kib_samples"]),ints(v["vmrss_before_kib_samples"]),
                         ints(v["vmrss_after_kib_samples"]),num(v["cpu_seconds"],6),num(v["wall_seconds"],9)])
    chunks += [table(["场景","臂","VmHWM 样本 KiB","RSS-before 样本 KiB","RSS-after 样本 KiB","CPU 合计 s","wall 合计 s"],rows),""]
for name in ("native_r14_r15","native_r11_r15"):
    v=d[name]; cs=v["cells"]
    chunks += [f"## Native：{title(name)}","",
               "A = clean allocator default；B = MALLOC_ARENA_MAX=1。每行 C/臂为 192 次 measured native status/read 调用；不含 warmup 和 preflight/restart。","",
               pair_table(cs,"cpu_ms_per_call","CPU ms/call","calls_per_second","calls/s",key=lambda c:f"C{c['concurrency']}"),"",
               pair_table(cs,"p95_ms","p95 ms","p99_ms","p99 ms",key=lambda c:f"C{c['concurrency']}"),"",
               "### Native controller 内存范围（KiB）","",
               "first-controller 的内存覆盖 preflight、全部 C1/C4/C8 和 warmup，不可归属于某一个 C。restart-controller 是另一组进程，仅用于重启验证，单列。采样 RSS 峰值是采样下界；VmHWM 来自该进程状态。",""]
    rows=[]
    for phase,label in (("whole_controller_memory","first-controller，全 C"),("restart_controller_memory","restart-controller")):
        for arm in ("A","B"):
            m=v[phase][arm]
            hs=[s["controller_vmhwm_kib"] for s in m["samples"]]
            rs=[s["sampled_controller_rss_peak_kib"] for s in m["samples"]]
            rows.append([label,arm,ints(hs),num(m["controller_vmhwm_kib_median"],0),
                         ints(rs),num(m["sampled_rss_peak_kib_median"],0)])
    chunks += [table(["范围","臂","VmHWM 两样本","VmHWM 中位数","采样 RSS-peak 两样本","RSS-peak 中位数"],rows),""]
    rows=[]
    for phase,label in (("whole_controller_memory_comparison","first-controller，全 C"),("restart_controller_memory_comparison","restart-controller")):
        m=v[phase]
        rows.append([label,pct(m["controller_vmhwm_kib_median"]["change_percent"]),pct(m["sampled_rss_peak_kib_median"]["change_percent"])])
    chunks += [table(["范围","VmHWM 中位数 Δ","RSS-peak 中位数 Δ"],rows),""]
    c8=cs[-1]
    rows=[]
    for arm in ("A","B"):
        m=c8[arm]
        rows.append([arm," / ".join(num(x,6) for x in m["per_process_calls_per_second"]),
                     " / ".join(num(x,6) for x in m["per_process_cpu_ms_per_call"]),
                     " / ".join(num(x,4) for x in m["per_process_p99_ms"])])
    chunks += ["### C8 两轮分布（每进程 96 次 measured）","",
               table(["臂","两轮 calls/s","两轮 CPU ms/call","两轮 p99 ms（N=96，均为本轮 max）"],rows),""]
    errors={}
    for e in v["resource_metric_errors_preserved"]:
        for k,n in e["error_counts"].items():errors[k]=errors.get(k,0)+n
    chunks += [f"资源采样保留的错误计数：{json.dumps(errors,ensure_ascii=False,sort_keys=True)}。这些是原始 FD 采样权限错误，不能伪装为 FD=0；CPU/RSS 可用字段仍保留。tree RSS/FD 为非同时的部分进程和，采样 tree CPU 不作性能 CPU 分子。",""]

chunks += ["## 全部方向性负面记录","",
           "以下 75 项完整来自独立审计的 negative_directional_results。它们是指标方向记录，不是 75 个独立故障；例如 host_list 的 p99 和 max 重复描述同一尾样本。没有丢弃 CPU/吞吐/尾延迟/内存的任何已列负方向，也没有把方向变化声明为统计显著。",""]
rows=[]
for n in d["negative_directional_results"]:
    key=f"C{n['concurrency']}" if "concurrency" in n else f"w{n['workers']}; {n['receipt_bytes']:,} B"
    rows.append([n["campaign"],key,n["metric"],num(n["baseline"],6),num(n["candidate"],6),pct(n["change_percent"])])
chunks += [table(["Campaign","场景","指标（单位见字段名）","A","B","Δ B/A"],rows),"",
           "## 可独立验证的范围","",
           "独立复算核验 48 个唯一 PID/start generation，7,488 条完整 cancel 响应的原始哈希与语义，3,024 次 native 调用的已有哈希/DTO/count/状态。native observation 原报告没有保存完整 transport response envelope，因此完整 native envelope 独立重哈希数为 0。六机恢复使用另一套完整原始响应证据，不能借此补称 observation envelope 已验证。","",
           "原始 CPU/wall 差值和 latency 样本可检查、重算聚合，但原始单调时钟两端未完整保留，不能声称重新构建每个时钟区间。所有原始浮点值已检查 finite；两组负向数据和资源采样错误均保留。",""]
performance_md="\n".join(chunks).rstrip()+"\n"

c8=d["native_r14_r15"]["cells"][-1]
old8=d["native_r11_r15"]["cells"][-1]
large={name:[c for c in d[name]["cells"] if c["receipt_bytes"]>1024] for name in ("cancel_r14_r15","cancel_r11_r15")}
frontier={
    "schema":"hepta-r15-post-formal-frontier-decision/v1",
    "success":True,
    "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "decision_kind":"engineering recommendation after independent audit; not an absolute optimum proof",
    "recommendation":"Adopt the opt-in X230/glibc arena1 profile for the qualified R14 binary and stop this optimization round.",
    "formal_candidate_qualified":True,
    "source_changed_in_r15":False,
    "global_optimum_proven":False,
    "pareto_optimum_proven":False,
    "prep4_formally_measured":False,
    "automatic_new_workload_authorized_or_started":False,
    "input_bindings":INPUT,
    "candidate_sha256":d["candidate_sha256"],
    "allocator_environment":{"MALLOC_ARENA_MAX":"1"},
    "preparation_permits":2,
    "publication_permits":8,
    "native_same_binary_c8":c8,
    "native_r11_to_final_c8":old8,
    "large_receipt_cells":large,
    "all_negative_directional_results":d["negative_directional_results"],
    "negative_directional_count":75,
    "evidence_and_inference":{
        "facts":[
            "Same-binary large-receipt HWM medians decrease by 72.66% and 70.07%; measured RSS-after medians decrease by 78.52% and 81.30%.",
            "Same-binary C8 pooled rate is -1.1091%, CPU/call +0.8658%, p95 +2.9182%, p99 +9.1306%; both B rates and CPU values lie inside the A two-process range.",
            "R11-to-final C8 pooled rate is +2.1813%, CPU/call -2.7143%, p95 -0.9115%, p99 -5.9296%.",
            "Same-binary small w1 CPU is +6.4935%, rate -6.0302%; large w2 CPU +2.5962%, rate -3.7490%; large host-list p95 increases 35.8414%/22.2291%.",
            "R11-to-final small w2 host-list p99 rises 244.8353% and cancel p99 266.9693%; large w1 HWM remains 32.8253% above R11 and CPU 11.1992% above R11.",
            "R14's prior R13 comparison traded CPU/RPC reductions of 30.8280%/28.1410% for mixed-rate reductions of 14.3295%/19.4542%; R15 allocator evidence does not erase that historical tradeoff.",
            "R14 large-refusal CPU/wall ratios were approximately 1.968/1.956 after prep2, versus 3.321/3.380 before; build evidence reports four logical CPUs on this X230.",
        ],
        "inferences":[
            "The finite C8 observations do not provide coherent evidence of a material additional allocator-contention throughput/CPU penalty, so a new arena2 full matrix is not justified solely by the p99 fluctuation.",
            "Preserving arena1 avoids a new Rust worker-pool lifecycle while obtaining the large memory benefit. Tail costs remain an explicit acceptance tradeoff.",
            "Two physical cores and observed CPU utilization make prep4 an unproven tradeoff rather than an obvious free gain; SMT or successful-path I/O overlap could still benefit in a different workload.",
        ],
    },
    "frontier":[
        {"option":"arena2","action":"defer","reason":"No coherent material same-binary C8 CPU/rate penalty; revisit only for a reproducible target workload or an explicit tail SLO that current profile misses."},
        {"option":"prep2 to prep4","action":"unmeasured, do not expand matrix merely to enumerate","reason":"Could gain SMT or fsync overlap on successful cancellation, but current refusal fixture does not establish that need and more large allocations can increase HWM, CPU and host-list latency."},
        {"option":"fixed dedicated preparation workers","action":"defer","reason":"Additional queue/handoff, initialization, panic propagation and graceful-shutdown proof required. Proposed outer spawn_blocking wrapper would retain runtime waiting semantics, but adds waiting threads; no implementation or performance claim."},
        {"option":"cross-call pin cache or skip content rehash","action":"exclude without contract redesign","reason":"Phase-boundary mutation detection needs actual content validation; inode/mtime/metadata cannot provide equivalent proof."},
        {"option":"allocation-free escaped JSON parser","action":"separate correctness project","reason":"Current ValidatedJobString already discards the decoded value via Visitor; removing scratch allocations needs Unicode, escape, error and refusal equivalence evidence."},
        {"option":"remote snapshot protocol rewrite","action":"separate protocol project","reason":"Needs independently specified consistency, restart and failure semantics."},
        {"option":"weaken fsync, intent ownership or ACK interpretation","action":"not an allowed performance trade","reason":"Would change persistence/cancellation contracts."},
    ],
    "scope_limits":[
        "Two processes per arm/case, no statistical significance or universal workload guarantee.",
        "Wrong-host local receipt benchmark does not measure successful cancel append/remote throughput.",
        "Live successful cancellation overlap is C6, not a successful-cancel C8 capacity benchmark.",
        "No host reboot, power loss, WAN partition, external-effect exactly-once or ownership-transfer experiment.",
        "No new arena2/prep4 run is requested by this decision.",
    ],
}

doc_head=[
"# X230 优化 R15：固定 R14 代码，验证 glibc arena1 执行配置",
"",
"日期：2026-11-03 UTC。状态：R15 配置资格、两组本地性能、两组 native 性能、六机恢复以及三份独立审计均已完成；本文是基于冻结证据生成的发布初稿。推荐把 arena1 作为本次已测 X230/glibc 环境的可选启动配置。本轮没有新的 Rust 修改或编译。",
"",
"## 结论与取舍",
"",
"同一个已资格 R14 二进制，加入 MALLOC_ARENA_MAX=1 后，4,194,272 字节 escaped receipt 的 VmHWM 中位数在 workers=1/2 下分别从 106,338/102,650 KiB 降到 29,070/30,720 KiB（−72.66%/−70.07%），结束时 RSS 从 106,338/102,650 KiB 降到 22,838/19,196 KiB（−78.52%/−81.30%）。",
"",
"这个内存收益带有明确成本。同一二进制下，大 receipt 的 mixed RPC rate 为 +0.48%/−3.75%，CPU/RPC 为 −1.88%/+2.60%，host_list p95 为 +35.84%/+22.23%；小 receipt workers=1 的 CPU/RPC +6.49%、rate −6.03%。因此不能把 R15 写成所有指标同时提升。",
"",
"R11→最终配置是代码与配置的合并结果：大 receipt workers=1 的 rate +68.62%、host_list p95 −91.88%，但 CPU/RPC +11.20%、VmHWM +32.83%、RSS-after +41.43%；workers=2 的 rate −6.33%、CPU/RPC +6.85%、host_list p95 −82.29%，VmHWM −10.32% 而 RSS-after +6.34%。小 receipt workers=2 出现 89.2773 ms 的 host_list p99 和 87.3614 ms 的 cancel p99，分别比该 R11 对照高 244.84%/266.97%，完整保留。",
"",
"native 同二进制 C8 的 rate −1.11%、CPU/call +0.87%、p95 +2.92%、p99 +9.13%；两次 B 的 rate 和 CPU 都处于两次 A 的观测范围内。R11→最终 C8 的 rate +2.18%、CPU/call −2.71%、p95 −0.91%、p99 −5.93%。这些有限样本没有给出需要立即扩大 arena2 矩阵的明确额外争用证据，尾延迟负向仍须按实际 SLO 判断。",
"",
"## 代码、二进制与配置绑定",
"",
"R15 直接复用 R14 已冻结的 219 个编译输入、3 个 release 产物和 5 个 retained test executables。独立资格审计重新核对测试时、资格结束时和当前源码完全相同。R15 编译调用为 0，Rust 源码修改为 false。",
"",
]
binding_rows=[
    ["R14 source-map.json（219 项）",q["source_map_sha256"]],
    ["R14 implementation-ready.json",values["baseline-binding.json"]["implementation_ready_sha256"]],
    ["R14 qualification report",q["reused_r14_qualification_report_sha256"]],
    ["R15 baseline-binding.json",EXPECTED["baseline-binding.json"]],
    ["src/mcp/runtime/jobs.rs",q["jobs_rs_sha256"]],
]
for name,v in q["release_binaries"].items():binding_rows.append([name,v["sha256"]])
binding_rows += [
    ["R11 baseline hepta-runtime","660d64674fe3422006c0c2a82bc31f3f36edf19baf6613df7cdce51e8f3f8e4c"],
    ["configuration/hepta-runtime-x230-glibc.sh",EXPECTED["configuration/hepta-runtime-x230-glibc.sh"]],
    ["configuration/allocator-policy.json",EXPECTED["configuration/allocator-policy.json"]],
    ["configuration/configuration-ready.json",EXPECTED["configuration/configuration-ready.json"]],
]
doc_head += [table(["绑定对象","SHA256"],binding_rows),"",
"继承的 R14 取消路径仍有 8 个 publication slots 与独立 2 个 preparation permits。两个 permit 在异步侧取得后一起移入 spawn_blocking；prep 覆盖实际 prepare+append，随着真实闭包退出释放，不延伸到 remote/completion。已提交队列工作在调用者取消后仍保有实际工作与 guard 的所有权；尚未提交的等待者被取消时释放已持有的 publication slot。prep=2 限制大分配的物理准备并行，不把后续远端 continuation 限制成 2。",
"",
"## 资格与环境可归因性",
"",
table(["检查","已验证结果"],[
    ["隔离测试","1,637 passed / 0 failed / 33 ignored / 1,670 selected；0 retries；身份与状态相对 R14 未改变"],
    ["真实子进程 allocator 环境","1,647 verified / 0 unavailable_process_exited"],
    ["wrapper 自检","15 项；包含继承、冲突、空值、精确 tunable 匹配、参数/PID 保留、stdout 安静及错误退出"],
    ["loader 实测","3 项 fresh loader 观察；glibc 2.39 的 GLIBC_TUNABLES arena key 优先于 MALLOC_ARENA_MAX"],
    ["driver 环境自检","7 项；最小环境清理及记录/核验逻辑"],
    ["performance 环境绑定","32 个 cancel + 16 个 native generation，共 48 个实际 PID/start 绑定"],
    ["recovery 环境绑定","3 个 controller generation 的实际环境均验证"],
]),"",
"正式性能 driver 对基线和候选都先清除全部 MALLOC_* 与 GLIBC_TUNABLES。A 保持 clean default，B 显式只注入 MALLOC_ARENA_MAX=1；以 binary SHA256 + allocator environment 生成 configuration fingerprint，并在 initialize 后读取 /proc/PID/environ，同时绑定 PID/start ticks 防止误读 PID 复用。native 每轮初始与 restart 都验证，4 轮合计 8 次；恢复 3 次 controller 启动均验证。held SSH-agent 身份保持不变，未更改远端 workload 环境或全局服务配置。",
"",
"隔离测试包含多个不同 executable，顶层 allocator metadata 的 binary_sha256 为 null；它本身不能充当单一二进制绑定。独立审计通过 inventory、每条精确测试命令与其 executable SHA、测试前后哈希完成逐产物绑定。短命进程若已经退出只能记 unavailable_process_exited，不能冒充 live 环境验证或重跑以获得快照；本次实际为 0 unavailable。",
"",
"保留的关键并发测试：","",
]
for t in q["tests"]["required_pool_tests_passed"]:doc_head.append("- "+t)
doc_head += ["",
"## 为什么选择 arena1",
"",
"R14 prep=2 解决了大准备工作的 CPU 并发放大，却不保证所有大分配只落到两个永久线程。独立诊断使用同一个 qualified R14 runtime，观察到各设置均约 19–20 个线程峰值、idle 后 10 个线程；glibc 默认配置下的大量保留映射与线程退出后 RSS 不回落相符。",
"",
"两组限定诊断的顺序为 default/2/2/default 和 1/4/4/1，每个 fresh child 为 2 warmup waves + 24 measured waves + 12 s idle。诊断每个 child 的 234 次混合 RPC 包含 warmup；CPU 区间是 ready→warmup+load 完成，不能与正式排除 warmup 的 CPU/RPC 混用。后台证据归档 I/O 可重叠，所以没有诊断吞吐结论。",
"",
table(["诊断设置","CPU 秒均值（2 个 child）","整 child HWM KiB 均值","12 s idle RSS KiB 均值"],[
    ["default","6.225","102,028","102,028"],
    ["arena1","6.315","30,788","17,244"],
    ["arena2","6.375","39,014","17,476"],
    ["arena4","6.340","52,988","36,424"],
]),"",
"arena1 的诊断 HWM 最低、idle RSS 与 arena2 接近；跨 campaign CPU 均值仅描述方向，其中 arena1 相对 default +1.45% 仍保留。smaps 中的 64 MiB 保留映射形状只是 allocator arena 的启发式线索，不能当作直接枚举 malloc arena。诊断独立汇总核验 1,872 条完整响应和 24 个 smaps 文件，SHA 为 053996e41ebb0b29d9e76f92ed381bb7af0c9db5a22298ae2d92cb6803586020。正式 R15 ABBA 才提供以下配置对照。",
"",
"## 完整正式性能表",
"",
]
doc_tail=[
"",
"## 多机、持久化与故障恢复",
"",
"同一已资格 runtime + arena1 在 ai395、mac、main、pocket4、rog、x230 六个受控主机上完成恢复场景。独立恢复审计核验 90 个完整 native reply 文件、36 次 SSH probes 的 72 个 stdout/stderr 文件、150 个内嵌远端工件，共 224,885 字节内嵌内容，重算 6 个原始 controller record hash。12 次 cancel 调用、6 个新启动和 12 次 same-key lookup 均在原始证据内，自动 RPC 重试和额外 terminal polling 均为 0。",
"",
"本轮受控故障为 SIGKILL 自己的 controller 与自己的 ROG SSH master，并确认 master generation 被替换；未修改网络或服务。恢复链保留 controller crash 后 running、transport 重建后 running、live concurrent cancel、terminal status/read、terminal 后重复 cancel、same-key reuse 以及再次重启后的 terminal 证据。六机 marker 证明这些 fixture 的一次执行，不能外推成任意分布式外部效果的 exactly-once 保证。",
"",
"live successful cancel 实测最大重叠为 C6，六次调用启动时间跨度 2.0280 ms；这是六机活任务取消的重叠证据，不是成功取消 C8 的吞吐基准。Linux 的 cancel ACK 为 stop_requested，Mac 为 term_sent；ACK 中 termination_confirmed=false，单独的 ACK 不能证明已停止。终止结论来自后续 status、exit 与 witness 等终态证据。Linux 使用 pidfd；Mac 的身份检查为账户/PID-start best effort，边界仍保留。",
"",
"R15 没有改变 intent append、fsync、receipt 验证、phase-boundary pin 内容重哈希、publication 所有权或重启恢复协议。release 的 panic=abort 不能用测试构建里的 unwind/JoinError 行为替代：本次 SIGKILL 恢复验证的是外部硬中断后的持久化状态，不能宣称测试了每个 panic 发生点。",
"",
"本轮未做主机重启、真实断电、WAN partition、所有权迁移或外部业务效果去重实验，也没有因成功恢复而声称这些场景已获证明。",
"",
"## 配置使用与调用者覆盖",
"",
"launcher 是 opt-in，只限定已测 X230/glibc 2.39 的证据范围。它检查 Linux/GNU libc 和绝对 executable 路径，然后 exec 原二进制；无后台 supervisor、无 stdout banner，错误写 stderr。它不逐次重新 hash 二进制，部署前的产物绑定由资格/launch gate 负责。",
"",
"~~~sh",
"tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \\",
"  /absolute/path/to/hepta-runtime mcp \\",
"  --runtime-config /absolute/path/to/runtime-config.json",
"~~~",
"",
"只有调用者未设置 MALLOC_ARENA_MAX、也没有精确的 colon-delimited glibc.malloc.arena_max= tunable 时，wrapper 才注入默认 1。显式 MALLOC_ARENA_MAX（包括空/无效值）原样保留；显式 arena tunable 阻止默认注入；其他 GLIBC_TUNABLES 原样保留并可与默认 1 共存。两种控制都存在时保留两者，由 loader 决定有效值。本机 fresh loader 证据显示 tunable 优先。该行为不修改登录环境、系统服务或远端配置。",
"",
"~~~sh",
"MALLOC_ARENA_MAX=2 tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \\",
"  /absolute/path/to/hepta-runtime mcp --runtime-config /absolute/path/to/runtime-config.json",
"~~~",
"",
"上例是显式覆盖用法，不代表 arena2 已通过 R15 正式矩阵。正式 driver 直接 exec 相同二进制并设置 clean env，以避免 wrapper 的调用者继承策略污染配置归因；因此 caller override 后不能继续宣称与 arena1 对照环境相同。",
"",
"configuration/README.md、configuration-ready.json、baseline-binding.json 以及 frontier-assessment-before-r15.json 中的 candidate/pending 状态是运行前冻结记录，保留历史原文与 SHA。当前资格结论来自本文件和终态三份独立审计，不能回改历史 ready 来伪造事前已资格。",
"",
"## 本轮停止边界",
"",
"本轮建议停止在 R14 prep=2/publication=8 + opt-in arena1。依据是已测大分配 RSS 保留显著降低，完整资格与六机恢复通过，且 native C8 未呈现明确额外 CPU/吞吐争用；这是有限证据下的工程选择，不是绝对最优或已证明的 Pareto 最优。",
"",
"R14 先前的 R13 对照仍保留 CPU/RPC −30.83%/−28.14% 与 rate −14.33%/−19.45% 的交换，不能用 R15 内存收益掩盖。该大拒绝场景在 prep2 下 CPU/wall 约 1.968/1.956，之前约 3.321/3.380。X230 两物理核与四逻辑核并不证明 prep4 没有机会；SMT 或成功路径的 I/O/fsync overlap 可能受益，但本轮没有正式测 prep4。",
"",
"继续 prep4 会增加同时的大 buffer、allocator/scheduler 竞争，并可能给回 CPU 和 host_list 响应性收益。已有 wrong-host fixture 未证明成功取消 I/O 是下一瓶颈，native status/read 又不取得 cancel preparation semaphore，不能把 prep4 当作修复 native C8 的直接手段。只有实际目标 workload 或明确 SLO 提供具体理由时，才应做定向实验。",
"",
"arena2 也留作目标化选择：若其他分配模式出现可重复且跨两轮一致的额外 CPU/rate 成本，或明确尾延迟 SLO 失败，再做同二进制的限定比较。当前单个 p99 负向不足以证明锁争用，不能为了穷举参数扩矩阵。另一方面，当前尾延迟成本是真实观测，不能以样本有限为由删除。",
"",
table(["尚未推进的优化","边界和原因"],[
    ["固定两条 preparation 专用线程","arena1 已解决主要保留问题；新线程池增加交接、部分初始化、panic 传播、排队取消与 graceful shutdown 证明。外层保留 spawn_blocking 可维持 runtime 等待真实工作的语义，但仍多两层交接/等待线程，未实现、未测。"],
    ["跨调用 pin 缓存或省略内容重哈希","会改变 phase-boundary 变更检测契约；metadata/inode/mtime 不能等价证明内容不变。"],
    ["无分配 escaped JSON parser","当前 ValidatedJobString 已用 Visitor 丢弃 decoded text；进一步移除 scratch/read buffer 需要独立的 Unicode、escape、错误与拒绝语义证据。"],
    ["更深 remote snapshot 协议重写","需要新的 snapshot 一致性、恢复与故障协议，超出本轮低风险修改边界。"],
    ["减弱 fsync、intent ownership 或把 ACK 当终止","不接受以变更持久化/取消契约来制造性能改善。"],
]),"",
"## 冻结证据与复算",
"",
"下列相对路径以 R15 证据根目录为准；审计均顶层 success=true。表格直接由冻结 JSON 派生，原始测量、失败/负面方向、历史候选记录和审计工具一并留存。独立性能 auditor 只读取已完成结果，未运行新 workload；一次执行、0 automatic retries。",
"",
table(["证据","SHA256"],[
    ["qualification-audit-summary.json",EXPECTED["qualification-audit-summary.json"]],
    ["independent-performance-audit.json",EXPECTED["independent-performance-audit.json"]],
    ["independent-recovery-audit.json",EXPECTED["independent-recovery-audit.json"]],
    ["performance-report-data.json",EXPECTED["performance-report-data.json"]],
    ["independent-audit-tools/audit_performance_r15.py",d["auditor_sha256"]],
    ["independent-audit-tools/performance-attempt-01/execution.json",EXPECTED["independent-audit-tools/performance-attempt-01/execution.json"]],
    ["independent-audit-tools/allocator-tooling-review.json",EXPECTED["independent-audit-tools/allocator-tooling-review.json"]],
    ["configuration/wrapper-validation.json",EXPECTED["configuration/wrapper-validation.json"]],
    ["configuration/loader-precedence.json",EXPECTED["configuration/loader-precedence.json"]],
    ["independent-audit-tools/environment-selftest-01.json",EXPECTED["independent-audit-tools/environment-selftest-01.json"]],
]),"",
"证据归档发布信息：ARCHIVE_PENDING",
"",
]
full_doc="\n".join(doc_head)+performance_md.replace("# R15 独立性能结果\n","### 表格来源\n",1)+"\n".join(doc_tail)

readme="""# X230 / glibc R15 execution profile

**Current qualification:** completed on the recorded X230/glibc 2.39 host. The frozen R14 runtime plus the opt-in arena1 profile passed 1,637 tests, with 0 failed and 33 ignored out of 1,670 selected; 1,647 actual allocator-environment observations were verified and none was unavailable. The two local comparisons, two native comparisons, six-host recovery, and independent qualification/performance/recovery audits all succeeded.

See [the complete R15 report](../../../../docs/X230_OPTIMIZATION_20261103_R15.md) for all measurements, regressions, evidence hashes, and limits. R15 adds no Rust changes and performs no new compilation; it reuses the qualified R14 source and artifacts.

## Launcher

The wrapper is [configuration/hepta-runtime-x230-glibc.sh](configuration/hepta-runtime-x230-glibc.sh).

~~~sh
tools/x230/20261103/r15/configuration/hepta-runtime-x230-glibc.sh \\
  /absolute/path/to/hepta-runtime mcp \\
  --runtime-config /absolute/path/to/runtime-config.json
~~~

When neither explicit MALLOC_ARENA_MAX nor an exact glibc.malloc.arena_max tunable is present, it defaults MALLOC_ARENA_MAX to 1. Caller controls, including empty values, are preserved; GNU libc resolves conflicting controls. The wrapper validates Linux/glibc and the absolute executable, writes no stdout banner, then execs the runtime without a supervisor.

The formal drivers deliberately bypass this inheritance-aware wrapper and set clean child environments. Their same-binary comparison binds binary SHA256, allocator environment, PID/start generation, and actual post-exec /proc observations. An explicit caller override therefore falls outside the tested arena1 profile.

## Evidence and historical state

configuration/README.md and configuration/configuration-ready.json are immutable preparation-time records and still describe a candidate. Their hashes are retained. This README and the final report provide the post-measurement qualification outcome without rewriting prior evidence.

The large-receipt HWM benefit has CPU, throughput, and tail-latency tradeoffs; the complete report retains every negative directional result. Native observation full transport envelopes were not retained and are not claimed to have been independently rehashed. Live successful cancellation overlap was C6; it is not a successful-cancel C8 throughput proof. No power-loss, reboot, WAN-partition, or universal exactly-once claim is made.

The current decision stops at a validated engineering tradeoff. Prep4 remains unmeasured, and neither an absolute nor a Pareto optimum is claimed.
"""

outputs={
    "performance-results.md":performance_md,
    "independent-audit-tools/frontier-decision-after-r15.json":json.dumps(frontier,ensure_ascii=False,indent=2,sort_keys=True,allow_nan=False)+"\n",
    "publication-r15/docs/X230_OPTIMIZATION_20261103_R15.md":full_doc,
    "publication-r15/tools/x230/20261103/r15/README.md":readme,
}
receipt_rel="independent-audit-tools/performance-report-rendering.json"
for rel in [*outputs,receipt_rel]:
    assert not (ROOT/rel).exists(), ("output_already_exists",rel)
assert full_doc.count("ARCHIVE_PENDING")==1
assert "configuration/hepta-runtime-x230-glibc.sh" in readme
assert "../../../../docs/X230_OPTIMIZATION_20261103_R15.md" in readme
# Recheck frozen inputs immediately before writing derived files.
for p,info in INPUT.items():
    assert hashlib.sha256(Path(p).read_bytes()).hexdigest()==info["sha256"]
written={}
for rel,text in outputs.items():
    p=ROOT/rel
    p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("x",encoding="utf-8",newline="\n") as f:f.write(text)
    written[rel]=h(p)
receipt={
    "schema":"hepta-r15-performance-report-rendering/v1",
    "success":True,
    "created_utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),
    "script":h(Path(__file__)),
    "input_bindings":INPUT,
    "outputs":written,
    "validated_cancel_cells":8,
    "validated_native_cells":6,
    "negative_directional_rows_rendered":75,
    "archive_placeholders":1,
    "workloads_started":0,
    "compiler_invocations":0,
    "source_modified":False,
    "historical_evidence_modified":False,
}
rp=ROOT/receipt_rel
with rp.open("x",encoding="utf-8",newline="\n") as f:
    json.dump(receipt,f,ensure_ascii=False,indent=2,sort_keys=True,allow_nan=False)
    f.write("\n")
print(json.dumps({"success":True,"outputs":written,"receipt":h(rp),
                  "negative_rows":75,"draft_archive_placeholders":1},sort_keys=True))
