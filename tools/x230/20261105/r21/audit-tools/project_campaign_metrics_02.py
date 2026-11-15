#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Project already-replayed R21 evidence without executing any workload/auditor."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':')) + '\n').encode()


def dump(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False) + '\n').encode()


def change(ratio):
    return None if ratio is None else 100 * (ratio - 1)


def fmt(value, digits=3):
    return '—' if value is None else f'{value:.{digits}f}'


def percent(value):
    return '—' if value is None else f'{value:+.3f}%'


def utc(value):
    return datetime.datetime.fromtimestamp(value, datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--extracted-root', type=Path, required=True)
    parser.add_argument('--replay-report', type=Path, required=True)
    parser.add_argument('--output-root', type=Path, required=True)
    args = parser.parse_args()
    root, replay_path, out = args.extracted_root.absolute(), args.replay_report.absolute(), args.output_root.absolute()
    assert not out.exists()
    inputs = {}

    def read(path, expected=None):
        raw = path.read_bytes()
        identity = {'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)}
        if expected is not None:
            assert identity['sha256'] == expected
        if str(path) in inputs:
            assert inputs[str(path)] == identity
        inputs[str(path)] = identity
        return raw

    manifest = json.loads(read(root / '_export-manifest.json', '3317d1cc0fbe9c264dc7969e58061dfc8dc635569e3ecafe3754b538a52ba8fd'))
    replay = json.loads(read(replay_path, '9e149837a638bddf40d77c6d4e370f8d2c3f5946a91e373ce92b18d7da119666'))
    assert replay['passed'] is True and replay['all_original_payloads_unchanged'] is True
    assert len(replay['audits']) == 7 and all(a['passed'] and a['equals_original_analysis'] for a in replay['audits'])
    assert replay['native_regression_screen_passed'] is False

    def member(name):
        row = manifest['files'][name]
        raw = read(root / name, row['sha256'])
        assert len(raw) == row['bytes']
        return raw

    def source(name):
        return json.loads(member(name))

    def analyzed(filename):
        binding = next(a['output'] for a in replay['audits'] if Path(a['output']['path']).name == filename)
        raw = read(replay_path.parent / filename, binding['sha256'])
        assert len(raw) == binding['bytes']
        return json.loads(raw)

    campaign = source('r21/campaign-control-01/report.json')
    native = source('r21/native-observation-01/report.json')
    native_analysis = analyzed('native.json')
    boundary = source('r21/native-boundary-01/report.json')
    boundary_analysis = analyzed('boundary.json')
    lifecycle = analyzed('lifecycle-summary.json')
    assert replay['native_metrics'] == campaign['native_metrics']
    assert replay['lifecycle'] == lifecycle
    assert lifecycle == source('r21/lifecycle-abba-01/summary.json')
    assert native_analysis == source('r21/native-observation-01/independent-summary.json')
    assert boundary_analysis == source('r21/native-boundary-01/independent-summary.json')
    out.mkdir(mode=0o700, parents=True)
    outputs = []

    def write(name, raw):
        path = out / name
        with path.open('xb') as stream:
            stream.write(raw)
        outputs.append({'path': str(path), 'bytes': len(raw), 'sha256': sha(raw)})

    maxima = []
    for arm in 'AB':
        candidates = [(r, ci, c, ri, row) for r in native['rounds'] if r['version'] == arm
                      for ci, c in enumerate(r['cells']) if c['concurrency'] == 1
                      for ri, row in enumerate(c['rows'])]
        r, ci, cell, ri, row = max(candidates, key=lambda x: x[4]['elapsed_ms'])
        directory = f"r21/native-observation-01/round-{r['index']}-{arm}/first"
        reference = row['rpc']['transport_response']
        frame_member = directory + '/' + reference['file']
        frame_file = member(frame_member)
        frame = frame_file[reference['offset']:reference['offset'] + reference['bytes']]
        assert len(frame) == reference['bytes'] and sha(frame) == reference['sha256']
        entries = [json.loads(line) for line in member(directory + '/transport-responses.index.jsonl').splitlines()]
        assert entries[reference['sequence']] == {k: v for k, v in reference.items() if k != 'file'}
        assert json.loads(frame)['id'] == row['rpc']['request_id']
        assert sha(canonical(json.loads(frame))) == row['response_sha256']
        request_args = {'host': row['host'], 'job_id': row['job_id']}
        if row['tool'] == 'process_read':
            request_args.update(stdout_offset=0, stderr_offset=0, limit=16384)
        request = canonical({'jsonrpc': '2.0', 'id': row['rpc']['request_id'], 'method': 'tools/call',
                             'params': {'name': row['tool'], 'arguments': request_args}})
        assert sha(request) == row['rpc']['request_sha256'] and len(request) == row['rpc']['request_bytes']
        write('c1-max-' + arm + '.frame.json', frame)
        maxima.append({'arm': arm, 'round': r['index'], 'row': row,
                       'source_json_pointer': f"/rounds/{r['index']}/cells/{ci}/rows/{ri}",
                       'canonical_row_sha256': sha(canonical(row)), 'start_utc_from_recorded_unix': utc(row['start_unix']),
                       'frame_archive_member': frame_member, 'frame_file_identity': manifest['files'][frame_member],
                       'frame_offset': reference['offset'], 'frame_bytes': len(frame), 'frame_sha256': sha(frame),
                       'request_hash_reconstructed_with_original_canonical_rule': True,
                       'request_body_was_not_separately_wire_captured': True,
                       'retained_in_original_statistics': True, 'cause_inferred': False})

    cells = []
    for r in native['rounds']:
        for cell in r['cells']:
            keys = ('concurrency', 'calls', 'seconds', 'successful_rps', 'controller_cpu_seconds',
                    'controller_cpu_ms_per_call', 'p50_ms', 'p95_ms', 'p99_ms', 'max_ms', 'raw_timing')
            item = {'round': r['index'], 'arm': r['version'], **{k: cell[k] for k in keys}}
            item['first_call_start_unix'] = min(row['start_unix'] for row in cell['rows'])
            item['last_call_start_unix'] = max(row['start_unix'] for row in cell['rows'])
            item['first_call_start_utc'] = utc(item['first_call_start_unix'])
            item['last_call_start_utc'] = utc(item['last_call_start_unix'])
            cells.append(item)

    def resources(value):
        keys = ('peaks', 'metric_samples', 'error_counts', 'samples', 'sample_interval_seconds',
                'first_sample_monotonic_ns', 'last_sample_monotonic_ns', 'trace', 'limitations',
                'sampled_cpu_seconds_by_scope', 'tree_samples_are_not_simultaneous_or_complete',
                'sampled_tree_cpu_is_partial_lifetime_accumulation',
                'sampled_tree_cpu_delta_has_endpoint_error_of_either_sign',
                'zero_without_metric_samples_is_unavailable', 'sampler_error')
        return {k: value[k] for k in keys if k in value}

    native_resources = [{'round': r['round'], 'arm': r['version'], 'phase': r['phase'],
                         'observations': resources(r['observations'])} for r in native_analysis['resources']]
    hwm = {}
    for phase in ('shutdown', 'restart_shutdown'):
        arms = {arm: [r['observations']['peaks']['controller_hwm_kib'] for r in native_resources
                      if r['arm'] == arm and r['phase'] == phase] for arm in 'AB'}
        hwm[phase] = {'A_rounds_0_3_kib': arms['A'], 'B_rounds_1_2_kib': arms['B'],
                      'A_mean_kib': sum(arms['A']) / 2, 'B_mean_kib': sum(arms['B']) / 2,
                      'mean_difference_kib': (sum(arms['B']) - sum(arms['A'])) / 2,
                      'mean_change_percent': change(sum(arms['B']) / sum(arms['A'])),
                      'scope': 'Two process-lifetime sampled VmHWM maxima per arm; descriptive only, not per-call allocation or cluster RSS.'}

    phase_windows, lifecycle_resources = [], []
    for round_ in lifecycle['rounds']:
        prefix = 'r21/lifecycle-abba-01/' + round_['directory']
        report = source(prefix + '/report.json')
        for phase in round_['phase_rows']:
            name = prefix + '/phase-' + phase['phase'] + '.json'
            original = source(name)
            phase_windows.append({'round': round_['index'], 'arm': round_['arm'], 'phase': phase['phase'],
                                  'archive_member': name, 'metrics': phase,
                                  'original_timing_and_counters': {k: original[k] for k in (
                                      'start_monotonic_ns', 'end_monotonic_ns', 'controller_before',
                                      'controller_after', 'counter_before', 'counter_after')}})
        for key, value in report.items():
            if isinstance(value, dict) and isinstance(value.get('resources'), dict):
                lifecycle_resources.append({'round': round_['index'], 'arm': round_['arm'],
                                            'phase': key, 'observations': resources(value['resources'])})

    phase_comparisons = []
    for item in lifecycle['phase_comparisons']:
        copy = json.loads(json.dumps(item))
        for value in copy['metrics'].values():
            value['change_percent_b_vs_a_mean'] = change(value['B_over_A_mean'])
            value['adjacent_change_percent_b_vs_a'] = [change(v) for v in value.get('adjacent_B_over_A', [None, None])]
        phase_comparisons.append(copy)

    bursts = []
    for original, audit in zip(boundary['bursts'], boundary_analysis['bursts']):
        burst = original['burst']
        assert burst['burst_index'] == audit['burst']
        assert burst['classified'] == audit['classified']
        bursts.append({**audit, 'completion_rps': burst['completion_rps'], 'successful_rps': burst['successful_rps'],
                       'controller_cpu_seconds': burst['controller_cpu_seconds'], 'raw_timing': burst['raw_timing'],
                       'sampled_resources_before': resources(burst['sampled_resources_before']),
                       'sampled_resources_after': resources(burst['sampled_resources_after'])})

    stages = []
    for stage in campaign['stages']:
        projected = {key: stage[key] for key in ('name', 'start_monotonic_ns', 'end_monotonic_ns', 'seconds',
                                                'returncode', 'pre_gate_passed', 'post_gate_passed', 'waited_and_reaped')}
        for point in ('before', 'after'):
            snap = stage[point]
            selected = {key: value for key, value in snap['values'].items()
                        if key == '/proc/loadavg' or 'cpufreq/' in key or '/thermal/' in key or '/hwmon/' in key}
            projected[point] = {'utc': snap['utc'], 'monotonic_ns': snap['monotonic_ns'], 'raw_selected_values': selected,
                                'scope': 'Original stage-boundary observations, not per-arm/per-call frequency or causal evidence.'}
        stages.append(projected)

    result = {
        'schema': 'hepta-r21-closed-campaign-metrics-projection/v1', 'passed_projection': True,
        'source_replay_passed': True, 'source_audits': 7, 'native_regression_screen_passed': False,
        'adoption_decision_made_here': False, 'network_requests': 0, 'workloads_or_auditors_run_here': False,
        'native_counts': replay['native_counts'], 'native_metrics': replay['native_metrics'],
        'native_regression_screen': replay['native_regression_screen'], 'native_round_cells': cells,
        'native_c1_maxima': maxima, 'native_resources': native_resources, 'native_controller_hwm': hwm,
        'boundary_counts': boundary_analysis['counts'], 'boundary_bursts': bursts,
        'boundary_total_calls': boundary_analysis['total_tool_calls'],
        'boundary_post_drain_calls': boundary_analysis['post_drain_calls'],
        'boundary_scope': boundary_analysis['limitations'],
        'lifecycle_counts': {key: lifecycle[key] for key in ('round_count', 'total_new_starts', 'total_same_key_lookups', 'total_cancellations')},
        'lifecycle_actual_native_calls_by_round': [r['native_calls'] for r in lifecycle['rounds']],
        'lifecycle_actual_ssh_calls_by_round': [r['independent_ssh_calls'] for r in lifecycle['rounds']],
        'lifecycle_phase_comparisons': phase_comparisons, 'lifecycle_phase_windows': phase_windows,
        'lifecycle_resources': lifecycle_resources, 'lifecycle_scope': lifecycle['scope'],
        'outer_stages': stages, 'measurement_scope': replay['measurement_scope'],
        'io_scope': 'No per-call disk I/O improvement is quantified. Archive/log/response byte counts are evidence sizes; /proc/stat snapshots are machine counters, not per-operation disk-byte measurements.',
        'interpretation': 'One finite ABBA with two samples per arm. Original aggregate gates rejected R21; this does not establish a necessary causal regression from the code, a noise explanation, or global optimality. No samples were removed.',
        'inputs': list(inputs.values()), 'projection_tool_sha256': sha(Path(__file__).read_bytes()),
    }
    for row in inputs.values():
        raw = Path(row['path']).read_bytes()
        assert len(raw) == row['bytes'] and sha(raw) == row['sha256']
    result['all_projection_inputs_unchanged'] = True
    write('metrics-01.json', dump(result))
    write('c1-max-identities-01.json', dump({'schema': 'hepta-r21-c1-max-identities/v1', 'source_report': manifest['files']['r21/native-observation-01/report.json'], 'observations': maxima, 'cause_inferred': False, 'samples_removed': 0}))

    lines = ['# R21 六机完整原始数据复算后的指标', '',
             '七个冻结离线审计入口全部通过，重算结果与原始汇总精确相等。原回归筛选仍为 **false**：C1 吞吐和 p95、C8 p95 未通过；C16 两个门通过，但其 p99 数值仍高于本轮 A。这里不作采用决定，不解释代码或环境因果，不剔除样本。', '',
             '## Native status/read：合并口径', '',
             '共 2,304 个计时调用、288 个 warmup、72 个预检/重启调用。后两类不进入性能分母。每档每 arm 为 384 个计时调用；吞吐使用总调用数除以该 arm 两轮窗口之和，分位数使用合并原始延迟的 nearest-rank。CPU 为同步读取的同 PID/start-ticks controller utime+stime，排除 SSH 与远端 CPU。', '',
             '| 并发 | calls/s A → B | CPU ms/call A → B | p50 ms A → B | p95 ms A → B | p99 ms A → B |',
             '|---|---|---|---|---|---|']
    for item in replay['native_metrics']['cases']:
        a, b, delta = item['aggregate']['arms']['A'], item['aggregate']['arms']['B'], item['aggregate']['change_percent']
        fields = []
        for key in ('calls_per_second', 'controller_cpu_ms_per_call', 'p50_ms', 'p95_ms', 'p99_ms'):
            fields.append(f"{fmt(a[key])} → {fmt(b[key])} ({percent(delta[key])})")
        lines.append('| C' + str(item['concurrency']) + ' | ' + ' | '.join(fields) + ' |')
    lines += ['', '门槛固定为每个并发档 B/A 吞吐 ≥ 0.95、p95 ≤ 1.10。p99、CPU 和相邻配对会完整报告，但不是补设的门。', '',
              '## Native 相邻配对与 arm 内跨度', '',
              '| 并发 | 配对 | 吞吐变化 | CPU/call 变化 | p50 变化 | p95 变化 | p99 变化 |', '|---|---|---|---|---|---|---|']
    for item in replay['native_metrics']['cases']:
        for pair in item['adjacent_pairs']:
            values = pair['change_percent_b_vs_a']
            lines.append(f"| C{item['concurrency']} | B{pair['candidate_round']}/A{pair['baseline_round']} | " + ' | '.join(percent(values[k]) for k in ('calls_per_second', 'controller_cpu_ms_per_call', 'p50_ms', 'p95_ms', 'p99_ms')) + ' |')
    lines += ['', '| 并发 | A 两轮 calls/s（0、3） | B 两轮 calls/s（1、2） | A max/min 跨度 | B max/min 跨度 |', '|---|---|---|---|---|']
    for item in replay['native_metrics']['cases']:
        a,b=item['aggregate']['arms']['A'],item['aggregate']['arms']['B']
        lines.append(f"| C{item['concurrency']} | " + ', '.join(fmt(v) for v in a['round_calls_per_second']) + ' | ' + ', '.join(fmt(v) for v in b['round_calls_per_second']) + f" | {fmt(a['round_rate_max_min_spread_percent'])}% | {fmt(b['round_rate_max_min_spread_percent'])}% |")
    lines += ['', '这些配对和跨度是原样描述，不代替合并门槛，也不能据此推断噪声来源。原始 12 个计时窗口、CPU 前后计数、所有 44 个 lifecycle phase 时钟与 CPU 计数保存在 metrics-01.json，并绑定来源文件。', '',
              '## C1 最大延迟调用', '']
    for item in maxima:
        row=item['row']
        lines.append(f"- {item['arm']} round {item['round']}：{row['host']} / {row['tool']}，{row['elapsed_ms']:.6f} ms；开始 {item['start_utc_from_recorded_unix']}；RPC id {row['rpc']['request_id']}，job `{row['job_id']}`。")
        lines.append(f"  原帧 `{item['frame_archive_member']}`，offset {item['frame_offset']}，{item['frame_bytes']} B，SHA256 `{item['frame_sha256']}`。")
    lines += ['', '两次均为 okay=true、automatic_retry=false。已提取对应原帧，全部样本仍在原统计中；没有从长尾定位推断网络、频率或代码原因。', '',
              '## 生命周期：11 个 C6 phase 的 wall time', '',
              '每 phase 完成 6 个 host；时间包含该 phase 的确认、原有有界轮询与独立 SSH 检查。原 aggregator 的 phase 比较是两轮算术均值，不与 native 的汇总吞吐公式混用。A 列顺序 0、3；B 列顺序 1、2。两配对分别 B1/A0、B2/A3。', '',
              '| phase | A 秒（0、3） | B 秒（1、2） | 均值变化 | 配对 1 | 配对 2 |', '|---|---|---|---|---|---|']
    for item in phase_comparisons:
        v=item['metrics']['wall_seconds'];pairs=v['adjacent_change_percent_b_vs_a']
        lines.append(f"| {item['phase']} | " + ', '.join(fmt(x,6) for x in v['A']) + ' | ' + ', '.join(fmt(x,6) for x in v['B']) + f" | {percent(v['change_percent_b_vs_a_mean'])} | {percent(pairs[0])} | {percent(pairs[1])} |")
    lines += ['', '## 生命周期：同 controller phase CPU', '',
              '单位为整段 phase 的 controller CPU 秒；不是远端 Python helper CPU，也不是六机 CPU 总和。计数在 phase 前后读取并包围整个窗口；prepare 没有活跃 controller，所以为不可用。该机器原计数为 100 ticks/s，短 phase 的 0.01 秒量化需要保留。每 native call 的原值也在 JSON 中。', '',
              '| phase | A CPU 秒（0、3） | B CPU 秒（1、2） | 均值变化 | 配对 1 | 配对 2 |', '|---|---|---|---|---|---|']
    for item in phase_comparisons:
        v=item['metrics']['controller_cpu_seconds'];pairs=v['adjacent_change_percent_b_vs_a']
        lines.append(f"| {item['phase']} | " + ', '.join(fmt(x,3) for x in v['A']) + ' | ' + ', '.join(fmt(x,3) for x in v['B']) + f" | {percent(v['change_percent_b_vs_a_mean'])} | {percent(pairs[0])} | {percent(pairs[1])} |")
    lines += ['', '实际合计 24 个新 job、48 次同 key 查询、48 次取消；四轮各有 90 个 native calls 和 36 个独立 SSH calls。这是本次实际计数，没有将 90 设成通用轮询不变量。一次 ABBA、每 arm 两样本，不能据这些 phase 均值宣称最大持续启动吞吐或统计显著的整体提升。', '',
              '## C32 边界：成功和拒绝分开', '',
              '| burst | 窗口秒 | 成功 / capacity refusal / other | 全完成 calls/s | 成功 calls/s | 拒绝 calls/s | controller CPU ms/attempt |', '|---|---|---|---|---|---|---|']
    for b in bursts:
        counts=b['counts']
        lines.append(f"| {b['burst']} | {fmt(b['seconds'],9)} | {counts['success']} / {counts['capacity_rejection']} / {counts['other_error']} | {fmt(b['completion_rps'])} | {fmt(b['successful_rps'])} | {fmt(b['classified']['capacity_rejection']['rate_per_second'])} | {fmt(b['controller_cpu_ms_per_attempt'],4)} |")
    lines += ['', '总计 32 成功、32 capacity refusal、0 other error；两 burst 均完成 drain/recovery，另有 96 次计划的 post-drain 观测。32 个 pending 客户端 RPC 不代表 32 个内部 pool identities：exact pool identity peak 未观测到，不据此推断内部同时准入 16。拒绝不算成功吞吐，CPU/attempt 也不能按成功/拒绝类归因。', '',
              '## RSS、FD 与观测范围', '',
              '| round / arm | controller 阶段 | sampled VmHWM KiB | sampled controller RSS max KiB | sampled tree RSS max KiB | sampled controller FD max |', '|---|---|---|---|---|---|']
    for r in native_resources:
        p=r['observations']['peaks']
        lines.append(f"| {r['round']} / {r['arm']} | {r['phase']} | {p['controller_hwm_kib']} | {p['controller_rss_kib']} | {p['tree_rss_kib']} | {p['controller_fd']} |")
    main_hwm=hwm['shutdown']
    lines += ['', f"主 controller VmHWM 两轮均值 A={fmt(main_hwm['A_mean_kib'],1)} KiB，B={fmt(main_hwm['B_mean_kib'],1)} KiB，差 {fmt(main_hwm['mean_difference_kib'],1)} KiB（{percent(main_hwm['mean_change_percent'])}）。这组数据没有建立 RSS 节省。", '',
              '100 ms 采样可能漏掉短命或重父进程，tree RSS 非同时求和且可能重复计共享页。PID 消失、权限不足、字段缺失等原错误计数及 trace 身份均保留在 JSON 和完整 raw 中；不可把缺失当零。重启 controller 单列，不混入主 controller 的两个样本。没有量化每调用磁盘 I/O 节省，日志/归档/返回字节数只表示证据或输出大小。', '',
              '## 原运行时间与机器快照', '',
              '| stage | 原 wall 秒 | before UTC | after UTC | loadavg 前 → 后（1/5/15 分钟） |', '|---|---|---|---|---|']
    for stage in stages:
        loads=[' / '.join(stage[p]['raw_selected_values']['/proc/loadavg'].split()[:3]) for p in ('before','after')]
        lines.append(f"| {stage['name']} | {fmt(stage['seconds'],6)} | {stage['before']['utc']} | {stage['after']['utc']} | {loads[0]} → {loads[1]} |")
    native_stage=stages[0]
    freqs=[[native_stage[p]['raw_selected_values'][f'/sys/devices/system/cpu/cpu{i}/cpufreq/scaling_cur_freq'].strip() for i in range(4)] for p in ('before','after')]
    lines += ['', 'Native 阶段边界的 cpu0..3 scaling_cur_freq 原值（kHz）：前 `'+', '.join(freqs[0])+'`，后 `'+', '.join(freqs[1])+'`。它们是两个时间点的快照，不是整个窗口的平均频率，也不对应任一 arm 的因果证据；全部原阶段前后频率、governor、温度值保留在 JSON。', '',
              '## 证据身份与复算边界', '',
              '- 原归档：5,204,365 B，SHA256 `f899f7a4140154db2bf74641c9e64d768852b9b072ca67c5a8d3ab50648c1b26`；5,379 payload + manifest。',
              '- 原 campaign report：SHA256 `d4f7fbe92f16aaa6a16c9ed4dc11d522dcb7ebadc29234db7c6096b63819bb4c`。',
              '- 完整离线 replay：SHA256 `9e149837a638bddf40d77c6d4e370f8d2c3f5946a91e373ce92b18d7da119666`；7 个入口全部成功且与原 summary 相等。',
              '- 9 个精确 ELF 省略正文，仅核对归档中的远端完整 hash/stamp 与资格证明；这不是本地 ELF 机器码复核。Mac holder 是独立包，未假装包含在本归档。',
              '- 本投影只读取已复算证据、补充定位原帧和展示单位；未启动负载、未新增审计轮次、未改门、未作来源因果判断。', '']
    write('METRICS.md', ('\n'.join(lines)).encode())
    receipt = {'schema': 'hepta-r21-campaign-metrics-projection-receipt/v1', 'passed': True,
               'inputs_unchanged': True, 'input_count': len(inputs), 'source_audits': 7,
               'projection_tool_sha256': sha(Path(__file__).read_bytes()), 'outputs': outputs,
               'network_requests': 0, 'workloads_or_auditors_run': False}
    with (out / 'receipt.json').open('xb') as stream:
        stream.write(dump(receipt))
    print(json.dumps(receipt, sort_keys=True))


if __name__ == '__main__':
    main()
