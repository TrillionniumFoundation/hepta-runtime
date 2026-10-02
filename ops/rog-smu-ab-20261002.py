#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Bounded Strix Halo SMU A/B qualification for the dedicated ROG runner."""
import csv
import json
import os
import pathlib
import re
import statistics
import subprocess
import threading
import time
from datetime import datetime

ROOT = pathlib.Path('/home/qian-qi/rog-ai-smu-ab')
BENCH = pathlib.Path('/home/qian-qi/pocket4-gfx1150-bench/gfx1151_bench')
RYZENADJ = pathlib.Path('/usr/local/src/RyzenAdj/build/ryzenadj')
APPLY = pathlib.Path('/usr/local/sbin/rog-ai-smu-apply')
PRODUCTION = pathlib.Path('/usr/local/sbin/rog-ai-production-profile')
LATCH = pathlib.Path('/var/lib/rog-ai-production/safe-latch')
FAULT_RE = re.compile(
    r'amdgpu.*\b(reset|timeout|fault|wedged)\b|hardware error|mce:|thermal.*critical',
    re.I,
)
EXPECTED = {
    'baseline': (70.0, 95.0),
    'apu90': (90.0, 95.0),
    'apu120': (120.0, 95.0),
    'co-neg5': (70.0, 95.0),
    'co-neg10': (70.0, 95.0),
    'co-neg15': (70.0, 95.0),
    'combined-neg5': (120.0, 95.0),
    'combined-neg10': (120.0, 95.0),
    'thermal100': (70.0, 100.0),
}


def read(path, default=''):
    try:
        return pathlib.Path(path).read_text(errors='replace').strip()
    except OSError:
        return default


def run(argv, **kwargs):
    return subprocess.run(
        [str(x) for x in argv], text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, **kwargs)


def sudo(*argv, check=True):
    return run(['/usr/bin/sudo', '-n', *argv], check=check)


def is_latched():
    return sudo('/usr/bin/test', '-e', str(LATCH), check=False).returncode == 0


def find_hwmon(name):
    for root in pathlib.Path('/sys/class/hwmon').glob('hwmon*'):
        if read(root / 'name') == name:
            return root
    raise RuntimeError(f'missing hwmon {name}')


def smu_info():
    p = sudo(str(RYZENADJ), '--info', check=False)
    text = p.stdout + p.stderr
    if p.returncode:
        raise RuntimeError(f'ryzenadj info failed rc={p.returncode}: {text[-1000:]}')
    return text


def info_values(text):
    result = {}
    for line in text.splitlines():
        m = re.match(r'\|\s*(.*?)\s*\|\s*([-+]?\d+(?:\.\d+)?|nan)\s*\|', line)
        if not m:
            continue
        try:
            result[m.group(1).strip()] = float(m.group(2))
        except ValueError:
            result[m.group(1).strip()] = None
    return result


def snapshot(cpu, gpu, fans):
    freqs = []
    for p in pathlib.Path('/sys/devices/system/cpu/cpufreq').glob('policy*/scaling_cur_freq'):
        try:
            freqs.append(int(read(p)))
        except ValueError:
            pass
    try:
        gpu_freq = float(read(gpu / 'freq1_input')) / 1_000_000
    except ValueError:
        gpu_freq = None
    return {
        'time': datetime.now().astimezone().isoformat(),
        'mono': time.monotonic(),
        'cpu_mC': int(read(cpu / 'temp1_input', '0') or 0),
        'gpu_mC': int(read(gpu / 'temp1_input', '0') or 0),
        'pkg_uW': int(read(gpu / 'power1_average', '0') or 0),
        'gpu_busy': int(read('/sys/class/drm/card1/device/gpu_busy_percent', '0') or 0),
        'gpu_freq_MHz': gpu_freq,
        'cpu_avg_kHz': statistics.fmean(freqs) if freqs else None,
        'fan1_rpm': int(read(fans / 'fan1_input', '0') or 0),
        'fan2_rpm': int(read(fans / 'fan2_input', '0') or 0),
        'battery_status': read('/sys/class/power_supply/BAT0/status'),
        'battery_uW': int(read('/sys/class/power_supply/BAT0/power_now', '0') or 0),
    }


def telemetry(stop, path, cpu, gpu, fans):
    first = snapshot(cpu, gpu, fans)
    with path.open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=list(first))
        writer.writeheader()
        writer.writerow(first)
        out.flush()
        while not stop.wait(0.5):
            writer.writerow(snapshot(cpu, gpu, fans))
            out.flush()


def parse_bench(text):
    def one(pattern):
        match = re.search(pattern, text)
        return float(match.group(1)) if match else None
    return {
        'copy_GBps': one(r'hip_global_copy_GBps=([0-9.]+)'),
        'rocwmma_TFLOPs': one(r'rocwmma_TFLOPs_fp16_f32=([0-9.]+)'),
        'copy_ms': one(r'hip_global_copy_ms=([0-9.]+)'),
        'rocwmma_ms': one(r'rocwmma_ms=([0-9.]+)'),
    }


def kernel_faults(since_epoch):
    p = sudo('/usr/bin/journalctl', '-k', '-b', '--since', f'@{int(since_epoch)}',
             '--no-pager', check=False)
    return [line for line in p.stdout.splitlines() if FAULT_RE.search(line)]


def stats(rows, field, scale=1.0):
    values = []
    for row in rows:
        try:
            values.append(float(row[field]) / scale)
        except (ValueError, TypeError, KeyError):
            pass
    if not values:
        return None
    return {'mean': statistics.fmean(values), 'min': min(values),
            'max': max(values), 'n': len(values)}


def restore():
    if is_latched():
        sudo(str(APPLY), 'safe', check=False)
    else:
        sudo(str(PRODUCTION), check=False)


def validate_applied(profile, values):
    apu, temp = EXPECTED[profile]
    required = {
        'STAPM LIMIT': 120.0,
        'PPT LIMIT FAST': 120.0,
        'PPT LIMIT SLOW': 120.0,
        'PPT LIMIT APU': apu,
        'THM LIMIT CORE': temp,
    }
    return {key: {'expected': expected, 'actual': values.get(key),
                  'match': values.get(key) == expected}
            for key, expected in required.items()}


def run_stage(profile, label, loops):
    if is_latched():
        raise RuntimeError('safety latch present before stage')
    stamp = datetime.now().astimezone().strftime('%Y%m%dT%H%M%S%z')
    out = ROOT / f'{stamp}-{label}-{profile}'
    out.mkdir(parents=True)
    cpu = find_hwmon('k10temp')
    gpu = find_hwmon('amdgpu')
    fans = find_hwmon('asus')
    start_epoch = time.time()
    summary = {'label': label, 'profile': profile, 'loops_requested': loops,
               'started_at': datetime.now().astimezone().isoformat(), 'out': str(out)}
    stop = threading.Event()
    thread = None
    try:
        (out / 'pre-info.txt').write_text(smu_info())
        applied = sudo(str(APPLY), profile, check=False)
        (out / 'apply.stdout').write_text(applied.stdout)
        (out / 'apply.stderr').write_text(applied.stderr)
        summary['apply_rc'] = applied.returncode
        if applied.returncode:
            raise RuntimeError(f'profile apply failed rc={applied.returncode}')
        time.sleep(1)
        applied_info = smu_info()
        (out / 'applied-info.txt').write_text(applied_info)
        summary['applied'] = info_values(applied_info)
        summary['readback'] = validate_applied(profile, summary['applied'])
        if not all(item['match'] for item in summary['readback'].values()):
            raise RuntimeError(f'profile readback mismatch: {summary["readback"]}')
        thread = threading.Thread(target=telemetry,
                                  args=(stop, out / 'telemetry.csv', cpu, gpu, fans),
                                  daemon=True)
        thread.start()
        results = []
        env = os.environ.copy()
        env['LD_LIBRARY_PATH'] = '/opt/rocm/lib:/opt/rocm/lib64'
        for index in range(loops):
            begun = time.perf_counter()
            p = run([str(BENCH)], env=env, timeout=30)
            item = {'iteration': index + 1, 'rc': p.returncode,
                    'wall_s': time.perf_counter() - begun, **parse_bench(p.stdout)}
            results.append(item)
            with (out / 'bench.log').open('a') as log:
                log.write(f'--- iteration {index + 1} rc={p.returncode} ---\n')
                log.write(p.stdout)
                log.write(p.stderr)
            if p.returncode or is_latched():
                break
        summary['bench'] = results
        stop.set()
        thread.join(timeout=3)
        thread = None
        post_info = smu_info()
        (out / 'post-info.txt').write_text(post_info)
        summary['post'] = info_values(post_info)
        faults = kernel_faults(start_epoch)
        (out / 'kernel-faults.txt').write_text('\n'.join(faults) + ('\n' if faults else ''))
        summary['kernel_faults'] = faults
        summary['latched'] = is_latched()
        rows = list(csv.DictReader((out / 'telemetry.csv').open()))
        summary['telemetry'] = {
            'cpu_C': stats(rows, 'cpu_mC', 1000),
            'gpu_C': stats(rows, 'gpu_mC', 1000),
            'package_W': stats(rows, 'pkg_uW', 1_000_000),
            'gpu_busy_pct': stats(rows, 'gpu_busy'),
            'gpu_freq_MHz': stats(rows, 'gpu_freq_MHz'),
            'cpu_avg_MHz': stats(rows, 'cpu_avg_kHz', 1000),
            'fan1_rpm': stats(rows, 'fan1_rpm'),
            'fan2_rpm': stats(rows, 'fan2_rpm'),
            'battery_W': stats(rows, 'battery_uW', 1_000_000),
            'battery_states': sorted({row['battery_status'] for row in rows}),
        }
        successful = [item for item in results if item['rc'] == 0]
        for key in ('copy_GBps', 'rocwmma_TFLOPs', 'wall_s'):
            values = [item[key] for item in successful if item.get(key) is not None]
            summary[key] = ({'mean': statistics.fmean(values), 'min': min(values),
                             'max': max(values), 'n': len(values)} if values else None)
        unsafe_temp = ((summary['telemetry']['cpu_C'] or {}).get('max', 0) >= 97 or
                       (summary['telemetry']['gpu_C'] or {}).get('max', 0) >= 99)
        discharged = 'Discharging' in summary['telemetry']['battery_states']
        summary['status'] = ('passed' if len(successful) == loops and not faults and
                             not summary['latched'] and not unsafe_temp and not discharged
                             else 'rejected')
        summary['unsafe_temp'] = unsafe_temp
        summary['battery_discharged'] = discharged
    except Exception as exc:
        summary['status'] = 'failed'
        summary['error'] = repr(exc)
    finally:
        if thread is not None:
            stop.set()
            thread.join(timeout=3)
        restore()
        summary['finished_at'] = datetime.now().astimezone().isoformat()
        (out / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, sort_keys=True), flush=True)
    return summary


def adjacent_delta(stages, index):
    candidate = stages[index]
    refs = []
    for neighbor in (index - 1, index + 1):
        if 0 <= neighbor < len(stages) and stages[neighbor]['profile'] == 'baseline':
            value = stages[neighbor].get('rocwmma_TFLOPs')
            if value:
                refs.append(value['mean'])
    current = candidate.get('rocwmma_TFLOPs')
    if not refs or not current:
        return None
    baseline = statistics.fmean(refs)
    return {'baseline': baseline, 'candidate': current['mean'],
            'percent': (current['mean'] / baseline - 1) * 100}


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    assert pathlib.Path('/sys/class/dmi/id/board_name').read_text().strip() == 'GZ302EA'
    assert BENCH.is_file() and RYZENADJ.is_file() and APPLY.is_file()
    assert run(['/usr/bin/systemctl', 'is-active', 'rog-ai-safety-monitor.service']).stdout.strip() == 'active'
    assert not is_latched()
    assert read('/sys/kernel/ryzen_smu_drv/drv_version') == '0.1.7'
    canary = run_stage('baseline', 'canary', 5)
    if canary['status'] != 'passed':
        raise SystemExit('baseline canary failed')
    sequence = [
        ('baseline', 'A0'), ('apu90', 'B-apu90'), ('baseline', 'A1'),
        ('apu120', 'C-apu120'), ('baseline', 'A2'),
        ('co-neg5', 'D-co5'), ('baseline', 'A3'),
        ('co-neg10', 'E-co10'), ('baseline', 'A4'),
        ('co-neg15', 'F-co15'), ('baseline', 'A5'),
        ('combined-neg5', 'G-combined5'), ('baseline', 'A6'),
        ('combined-neg10', 'H-combined10'), ('baseline', 'A7'),
        ('thermal100', 'I-thermal100'), ('baseline', 'A8'),
    ]
    stages = []
    for profile, label in sequence:
        result = run_stage(profile, label, 20)
        stages.append(result)
        if result['status'] == 'failed' or result.get('kernel_faults') or result.get('latched'):
            break
        time.sleep(1)
    comparisons = []
    for index, stage in enumerate(stages):
        if stage['profile'] != 'baseline':
            comparisons.append({'label': stage['label'], 'profile': stage['profile'],
                                'status': stage['status'],
                                'delta': adjacent_delta(stages, index),
                                'cpu_max_C': (stage.get('telemetry', {}).get('cpu_C') or {}).get('max'),
                                'gpu_max_C': (stage.get('telemetry', {}).get('gpu_C') or {}).get('max'),
                                'package_mean_W': (stage.get('telemetry', {}).get('package_W') or {}).get('mean')})
    accepted = [item for item in comparisons
                if item['status'] == 'passed' and item['delta'] is not None]
    accepted.sort(key=lambda item: item['delta']['percent'], reverse=True)
    matrix = {'at': datetime.now().astimezone().isoformat(), 'canary': canary,
              'stages': stages, 'comparisons': comparisons,
              'best_screened': accepted[0] if accepted else None}
    out = ROOT / 'matrix-20261002.json'
    out.write_text(json.dumps(matrix, indent=2) + '\n')
    print('MATRIX_RESULT=' + json.dumps({'comparisons': comparisons,
                                         'best_screened': matrix['best_screened']},
                                        sort_keys=True), flush=True)
    restore()
    if is_latched() or kernel_faults(time.time() - 900):
        raise SystemExit('safety or kernel fault gate failed')


if __name__ == '__main__':
    main()
