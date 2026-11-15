"""Execute the reviewed offline Python gates without editing the repository."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import subprocess
import time

import yaml

ROOT = Path('/workspace/scratch/d72683e5e62a/hepta-runtime')
OUT = Path(__file__).resolve().parent
SELECTED = {
    'ci.yml': {
        'Descriptor-relative file safety',
        'Frozen REA local mapping checks',
        'REA qualification evidence regressions',
        'Control-plane regression',
        'X230 qualification evidence regressions',
        'Unbounded ingress and collector regressions',
    },
    'cloud-compute.yml': {
        'Router regression suite', 'Colab regression suite', 'Kaggle regression suite',
    },
    'runtime-capacity-shadow.yml': {'Original behavior', 'Optimized Python behavior'},
}


def utc():
    return datetime.now(timezone.utc).isoformat()


def identity():
    head, tree = subprocess.check_output(
        ['git', 'rev-parse', 'HEAD', 'HEAD^{tree}'], cwd=ROOT, text=True).splitlines()
    status = subprocess.check_output(
        ['git', 'status', '--short'], cwd=ROOT, text=True).splitlines()
    return {'commit': head, 'tree': tree, 'worktree_status': status}


def discover():
    commands = []
    workflow_hashes = {}
    for workflow, selected in SELECTED.items():
        path = ROOT / '.github/workflows' / workflow
        workflow_hashes[workflow] = hashlib.sha256(path.read_bytes()).hexdigest()
        document = yaml.load(path.read_text(), Loader=yaml.BaseLoader)
        found = set()
        for job_name, job in document['jobs'].items():
            if job_name == 'runtime-merge-ci':
                continue
            for step in job.get('steps', []):
                if step.get('name') not in selected:
                    continue
                found.add(step['name'])
                for line in step['run'].strip().splitlines():
                    if line.strip() == 'set -euo pipefail':
                        continue
                    argv = shlex.split(line)
                    assert argv[0] in ('python3', '/usr/bin/python3'), argv
                    assert not any(x in line for x in (' | ', ' && ', ';')), line
                    executable = str(Path(shutil.which(argv[0])).resolve())
                    commands.append({
                        'index': len(commands) + 1,
                        'workflow': workflow, 'job': job_name, 'step': step['name'],
                        'argv': argv,
                        'cwd': str(ROOT / step.get('working-directory', '.')),
                        'interpreter_resolved': executable,
                        'interpreter_version': subprocess.check_output(
                            [argv[0], '--version'], text=True).strip(),
                    })
        assert found == selected, (workflow, selected - found)
    return commands, workflow_hashes


def parse_counts(log):
    matches = list(re.finditer(r'^Ran (\d+) tests? in ([0-9.]+)s$', log, re.M))
    if not matches:
        return None
    match = matches[-1]
    result = {'run': int(match.group(1)), 'reported_seconds': float(match.group(2))}
    ending = log[match.end():]
    for label in ('failures', 'errors', 'skipped', 'expected failures', 'unexpected successes'):
        found = re.search(r'\b' + re.escape(label) + r'=(\d+)', ending)
        result[label.replace(' ', '_')] = int(found.group(1)) if found else 0
    result['passed'] = result['run'] - sum(result[label] for label in (
        'failures', 'errors', 'skipped', 'expected_failures', 'unexpected_successes'))
    result['failure_headers'] = re.findall(r'^(?:FAIL|ERROR): .+$', log, re.M)
    result['skip_lines'] = re.findall(r'^.*\.\.\. skipped .*$', log, re.M)
    return result


def execute(command):
    record = dict(command)
    record['source_start'] = identity()
    record['started_utc'] = utc()
    stem = f"{command['index']:02d}-" + re.sub(r'[^a-z0-9]+', '-', command['step'].lower()).strip('-')
    log_path = OUT / (stem + '.log')
    record['log_path'] = str(log_path)
    start = time.monotonic()
    environment = dict(os.environ)
    environment['PYTHONDONTWRITEBYTECODE'] = '1'
    record['environment_changes'] = {'PYTHONDONTWRITEBYTECODE': '1'}
    record['timeout_seconds'] = 600
    with log_path.open('w') as log:
        log.write(json.dumps({'command': shlex.join(command['argv']), 'cwd': command['cwd'],
                              'source_start': record['source_start'],
                              'started_utc': record['started_utc']}, sort_keys=True) + '\n\n')
        log.flush()
        process = subprocess.Popen(command['argv'], cwd=command['cwd'], env=environment,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        record['owned_command_pid'] = process.pid
        record['timed_out'] = False
        try:
            record['exit_code'] = process.wait(timeout=600)
        except subprocess.TimeoutExpired:
            record['timed_out'] = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            record['exit_code'] = process.returncode
        record['elapsed_seconds'] = round(time.monotonic() - start, 3)
    record['finished_utc'] = utc()
    record['source_end'] = identity()
    record['source_identity_unchanged_during_command'] = record['source_start'] == record['source_end']
    output = log_path.read_text(errors='replace')
    record['unittest'] = parse_counts(output)
    record['log_sha256'] = hashlib.sha256(log_path.read_bytes()).hexdigest()
    record['status'] = 'PASS' if record['exit_code'] == 0 and not record['timed_out'] else 'FAIL'
    (OUT / (stem + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps({'index': record['index'], 'status': record['status'],
                      'step': record['step'], 'argv': command['argv'],
                      'seconds': record['elapsed_seconds'], 'unittest': record['unittest']},
                     sort_keys=True), flush=True)
    return record


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / 'summary.json').exists() or (OUT / 'manifest.json').exists():
        raise SystemExit('Refusing to overwrite an existing validation run')
    commands, workflow_hashes = discover()
    manifest = {'started_utc': utc(), 'source_start': identity(),
                'workflow_sha256': workflow_hashes,
                'runner_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                'parallel_commands': 2,
                'scope': 'Reviewed CI offline Python/unit gates; no release integration, live host, cloud submission, or HIA qualification commands',
                'commands': commands}
    (OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'started': manifest['started_utc'], 'source': manifest['source_start'],
                      'commands': len(commands)}, sort_keys=True), flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(execute, command) for command in commands]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda value: value['index'])
    totals = {name: sum((result['unittest'] or {}).get(name, 0) for result in results)
              for name in ('run', 'passed', 'failures', 'errors', 'skipped',
                           'expected_failures', 'unexpected_successes')}
    summary = {'source_start': manifest['source_start'], 'source_end': identity(),
               'started_utc': manifest['started_utc'], 'finished_utc': utc(),
               'command_count': len(results),
               'commands_passed': sum(result['status'] == 'PASS' for result in results),
               'commands_failed': sum(result['status'] != 'PASS' for result in results),
               'unittest_execution_counts': totals,
               'counting_note': 'Counts are test executions. CI repeats ledger tests inside discovery; capacity shadow deliberately runs normal and optimized modes.',
               'results': results}
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({key: value for key, value in summary.items() if key != 'results'},
                     sort_keys=True), flush=True)


if __name__ == '__main__':
    main()
