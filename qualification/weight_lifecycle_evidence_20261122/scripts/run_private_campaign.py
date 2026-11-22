#!/usr/bin/env python3
"""Execute real pinned checkpoints through the native canonical lifecycle worker.

This is engineering qualification on previously exposed fixed tasks, not model
selection or a new confirmation experiment. Every attempt and cost is retained.
"""
import argparse
import ctypes
import gzip
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time

CUTS = ['capture_complete','prepared','publish_intent','publish_effect','published',
        'verify_intent','evaluation_started','baseline_complete','verify_effect',
        'verified','accepted','restore_intent','restore_effect','restored','complete']
MAX_CPU = 180.0
MAX_WALL = 900.0
MAX_WORKER_CPU = 20
MAX_WORKER_WALL = 60
LIBC = ctypes.CDLL(None, use_errno=True)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': digest(data)}


def pinned(value):
    data = Path(value['path']).read_bytes()
    assert len(data) == value['bytes'] and digest(data) == value['sha256'], value['path']
    return data


def save(path, value):
    with open(path, 'x', encoding='utf-8') as file:
        json.dump(value, file, ensure_ascii=False, indent=2)
        file.write('\n')
        file.flush()
        os.fsync(file.fileno())


def usage():
    child = resource.getrusage(resource.RUSAGE_CHILDREN)
    own = resource.getrusage(resource.RUSAGE_SELF)
    return {'child_cpu': child.ru_utime + child.ru_stime,
            'supervisor_cpu': own.ru_utime + own.ru_stime,
            'child_peak_rss_kib': child.ru_maxrss}


def live_tree_cpu(pid):
    """Observed Linux tree ticks, including already reaped descendant CPU.

    This is a bounded polling observation, not an atomic kernel tree quota.
    Final successful qualification still requires exact aggregate RUSAGE <= cap.
    """
    pending = [(pid, None)]
    seen = set()
    ticks = 0
    while pending:
        current, expected_parent = pending.pop()
        if current in seen:
            continue
        if len(seen) >= 32:
            raise RuntimeError('owned process tree exceeds declared inventory bound')
        seen.add(current)
        try:
            fields = Path(f'/proc/{current}/stat').read_text().rsplit(')', 1)[1].split()
            if expected_parent is not None and int(fields[1]) != expected_parent:
                continue
            # utime, stime, cutime, cstime: a reaped parser must not disappear
            # from monitoring while its lifecycle parent remains alive.
            ticks += sum(int(fields[i]) for i in [11,12,13,14])
            tasks = list(Path(f'/proc/{current}/task').iterdir())
            if len(tasks) > 128:
                raise RuntimeError('owned thread inventory exceeds declared bound')
            children = set()
            for task in tasks:
                try:
                    children.update(int(child) for child in (task/'children').read_text().split())
                except FileNotFoundError:
                    pass
            pending.extend((child,current) for child in children)
        except FileNotFoundError:
            # A process may exit between read-only observations. It will be
            # included by the next parent sample or the final exact wait usage.
            continue
    return ticks/os.sysconf('SC_CLK_TCK')


def reap_owned_group(pgid):
    """Bounded cleanup of children only in our dedicated process group."""
    rows = []
    deadline = time.monotonic()+5
    while True:
        try:
            pid, status, consumed = os.wait4(-pgid, os.WNOHANG)
        except ChildProcessError:
            return rows, True
        if not pid:
            if time.monotonic() >= deadline:
                return rows, False
            try:
                os.killpg(pgid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            time.sleep(.01)
            continue
        rows.append({'pid':pid,'returncode':os.waitstatus_to_exitcode(status),
                     'cpu_seconds':consumed.ru_utime+consumed.ru_stime,
                     'peak_rss_kib':consumed.ru_maxrss})


def ready_json(path):
    # A create-only marker can be visible between open and write_all. Wait only
    # for that bounded construction interval while retaining the worker deadline.
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def limits(cpu, inheritable_hard=None):
    parent_pid = os.getpid()
    def apply():
        # This signal belongs only to the process we are creating. Arm it before
        # exec and close the parent-death race; a new session must not orphan it.
        if LIBC.prctl(1, signal.SIGKILL, 0, 0, 0) != 0 or os.getppid() != parent_pid:
            os._exit(126)
        signal.signal(signal.SIGXCPU, signal.SIG_DFL)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, inheritable_hard or cpu))
        resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    return apply


def owned_supervisor(argv):
    """Dedicated private child used only to test death of a worker's supervisor."""
    receipt = Path(argv[0])
    cpu = int(argv[1])
    if not 1 <= cpu <= MAX_WORKER_CPU:
        raise ValueError('bounded owned child CPU reservation required')
    command = argv[2:]
    process = subprocess.Popen(command, preexec_fn=limits(cpu))
    try:
        # The default SIGXCPU soft limit already constrains this Python supervisor
        # during startup. Its higher inherited hard limit exists only to permit the
        # child's distinct reservation; after spawning it, lower our own hard cap.
        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        save(receipt, {'supervisor_pid': os.getpid(), 'worker_pid': process.pid,
                       'process_group': os.getpgrp(), 'command': command})
        returncode = process.wait(timeout=MAX_WORKER_WALL)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    raise SystemExit(returncode if returncode >= 0 else 128-returncode)


def inspect(root):
    root = Path(root)
    request = json.loads((root / 'REQUEST.json').read_text())
    source = (root / 'source.safetensors').read_bytes()
    assert digest(source) == request['source_bridge']['sha256']
    artifacts = []
    store = root / 'owner-state/weight-artifacts-v1'
    if store.exists():
        for directory in sorted(store.iterdir()):
            assert directory.name.startswith('wa1_'), str(directory)
            manifest = json.loads((directory / 'manifest.json').read_text())
            identity = dict(manifest)
            identity.pop('artifact_id')
            calculated = 'wa1_' + digest(json.dumps(identity, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode())
            assert directory.name == manifest['artifact_id'] == calculated
            model = (directory / 'model.safetensors').read_bytes()
            assert digest(model) == manifest['target_sha256']
            assert len(model) == manifest['patch']['source_size_bytes'] == len(source)
            if manifest['kind'] == 'restore':
                assert model == source
            artifacts.append({'artifact_id': directory.name, 'kind': manifest['kind'], 'sha256': digest(model), 'bytes': len(model)})
    records = sorted((root / 'journal').rglob('record-*.json'))
    assert records
    prior = None
    for index, path in enumerate(records):
        raw = path.read_bytes()
        record = json.loads(raw)
        assert record['sequence'] == index and record['previous_sha256'] == prior
        prior = digest(raw)
        if record['acceptance_sha256'] is not None:
            assert record['evaluation']['passed'] is True
            assert digest(json.dumps(record['evaluation'], separators=(',', ':'), ensure_ascii=False).encode()) == record['acceptance_sha256']
    assert record['stage'] == 'Complete'
    assert record['intent']['source_sha256'] == digest(source)
    if record['publication'] is None:
        assert record['decision'] == 'KeptOriginal' and artifacts == []
    else:
        assert sorted(x['kind'] for x in artifacts) == ['patch', 'restore']
        assert record['restoration']['content_sha256'] == digest(source)
    evaluation = None
    if record['evaluation'] is not None:
        raw = (root / 'EVALUATION.json').read_bytes()
        assert digest(raw) == record['evaluation']['result_sha256']
        evaluation = json.loads(raw)
        assert evaluation['candidate_sha256'] == record['intent']['candidate_sha256']
        assert evaluation['evaluator_sha256'] == record['intent']['evaluator_sha256']
        assert evaluation['passed'] == record['evaluation']['passed']
        for task in evaluation['tasks']:
            data = (root / task['filename']).read_bytes()
            assert len(data) == task['bytes'] and digest(data) == task['sha256']
            full = json.loads(data)
            assert full['gain'] == task['gain']
            for which in ['baseline', 'candidate']:
                policy = full[which]['policy']
                assert abs(policy['terminal_mass'] - 1) <= 2e-10
                assert abs(policy['pdi_residual']) <= 2e-10
                assert abs(policy['utility'] - policy['expected_terminal_reward'] + policy['expected_expense']) <= 2e-10
        actual = evaluation['primary_gain'] > request['policy']['minimum_gain'] and all(
            item['gain'] >= -request['policy']['maximum_preservation_loss'] for item in evaluation['tasks'][1:])
        assert actual == evaluation['passed']
    started = sorted(root.glob('*.DP_STARTED.json'))
    completed = sorted(root.glob('*.DP_COMPLETED.json'))
    for path in completed:
        assert json.loads(path.read_text())['actual_completed_policy_dps'] == 1
    assert len(completed) <= len(started)
    return {'decision': record['decision'], 'record_sha256': prior, 'source_sha256': digest(source),
            'artifacts': artifacts, 'evaluation_passed': evaluation['passed'] if evaluation else None,
            'known_completed_policy_dps': len(completed), 'started_without_completion_record': len(started)-len(completed),
            'journal_files': {str(p.relative_to(root)): digest(p.read_bytes()) for p in records}}


def inspect_next_task(root, request_pin, binary_sha):
    request = json.loads(pinned(request_pin))
    prepared = json.loads((root/'PREPARED.json').read_text())
    result = json.loads((root/'next-task.json').read_text())
    assert result['mode'] == 'next-task'
    assert result['request_sha256'] == request_pin['sha256']
    assert result['worker_binary_sha256'] == binary_sha
    assert result['record']['stage'] == 'Complete'
    assert result['record']['intent'] == prepared['intent']
    assert result['evaluator_calls_this_process'] == 0
    assert result['full_policy_dps_this_process'] == 1
    assert result['owner_calls_this_process'] == []
    next_task = result['next_task']
    source_sha = request['source_bridge']['sha256']
    assert next_task['model_sha256'] == source_sha
    assert next_task['snapshot_sha256'] == prepared['snapshot_sha256']
    restoration = result['record']['restoration']
    actual_path = root/'owner-state/weight-artifacts-v1'/restoration['artifact_id']/'model.safetensors' if restoration else root/'source.safetensors'
    assert next_task['actual_model_path'] == str(actual_path)
    actual = actual_path.read_bytes()
    assert digest(actual) == source_sha and actual == (root/'source.safetensors').read_bytes()
    full = next_task['actual_next_task_full_policy']
    assert full['model_sha256'] == source_sha
    assert full['public'] == request['policy']['next_task']
    assert full['full_native_graphs'] == full['full_policy_dps'] == 1
    assert abs(full['policy']['pdi_residual']) <= 2e-10
    assert abs(full['policy']['terminal_mass']-1) <= 2e-10
    assert abs(full['policy']['utility']-full['policy']['expected_terminal_reward']+full['policy']['expected_expense']) <= 2e-10
    return {'actual_model_path':str(actual_path),'model_sha256':source_sha,'full_model_bytes':len(actual),
            'snapshot_sha256':next_task['snapshot_sha256'],'full_policy_dps':1,
            'evaluator_calls':0,'fresh_original_source_equivalence':True,'utility':full['policy']['utility']}


class Campaign:
    def __init__(self, binary, output):
        self.binary = binary
        self.output = output
        self.started = time.monotonic()
        self.deadline = self.started + MAX_WALL
        self.initial_usage = usage()
        self.invocations = []
        self.open_process_groups = set()
        if LIBC.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'campaign PR_SET_CHILD_SUBREAPER failed')

    def guard(self, owned_roots=(), per_tree_limit=None):
        elapsed = time.monotonic()-self.started
        consumed = usage()['child_cpu']-self.initial_usage['child_cpu']
        # Roots are disjoint, still-owned and unreaped. Their reaped descendants
        # are included in cutime/cstime, and live parser children are traversed.
        observed = [live_tree_cpu(pid) for pid in owned_roots if pid is not None]
        if per_tree_limit is not None and any(value >= per_tree_limit for value in observed):
            raise RuntimeError('observed lifecycle process tree CPU reservation exhausted')
        consumed += sum(observed)
        if elapsed >= MAX_WALL or consumed >= MAX_CPU:
            raise RuntimeError('declared campaign aggregate resource budget exhausted')
        return math.floor(MAX_CPU-consumed)

    def worker(self, request, root, mode, name, cut='', expected_error=None):
        before = usage()
        remaining = self.guard()
        if remaining < 1:
            raise RuntimeError('declared campaign resource budget exhausted')
        command = [str(self.binary), mode, request['path'], request['sha256'], str(root), name+'.json']
        if cut:
            command.append(cut)
        log = self.output / f'process-{len(self.invocations):03}'
        began = time.monotonic()
        deadline = min(self.deadline, began+MAX_WORKER_WALL)
        reserved_cpu = min(MAX_WORKER_CPU, remaining)
        with open(str(log)+'.stdout', 'xb') as stdout, open(str(log)+'.stderr', 'xb') as stderr:
            process = subprocess.Popen(command, stdout=stdout, stderr=stderr, start_new_session=True,
                                       preexec_fn=limits(reserved_cpu))
            self.open_process_groups.add(process.pid)
            killed = False
            exception = None
            try:
                if cut:
                    marker = root / 'CUT_REACHED.json'
                    reached = ready_json(marker)
                    while reached is None:
                        if process.poll() is not None:
                            raise RuntimeError(f'worker exited before cut {cut}: {process.returncode}')
                        self.guard([process.pid], reserved_cpu)
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f'cut {cut} not reached')
                        time.sleep(.01)
                        reached = ready_json(marker)
                    assert reached['phase'] == cut and reached['pid'] == process.pid
                    os.kill(process.pid, signal.SIGKILL)
                    killed = True
                # One deadline covers marker observation and subsequent wait;
                # the wait cannot grant another full per-worker time allowance.
                while process.poll() is None:
                    self.guard([process.pid], reserved_cpu)
                    if time.monotonic() >= deadline:
                        raise TimeoutError('worker or aggregate wall deadline reached')
                    time.sleep(.01)
                returncode = process.returncode
            except BaseException as error:
                exception = repr(error)
                raise
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                group_cleanup, accounting_complete = reap_owned_group(process.pid)
                if accounting_complete:
                    self.open_process_groups.discard(process.pid)
                after = usage()
                item = {'command':command,'pid':process.pid,'returncode':process.returncode,'sigkill_sent':killed,
                        'cut':cut or None,'expected_error':expected_error,'exception':exception,
                        'wall_seconds':time.monotonic()-began,
                        'child_cpu_seconds':after['child_cpu']-before['child_cpu'],
                        'supervisor_cpu_seconds':after['supervisor_cpu']-before['supervisor_cpu'],
                        'children_peak_rss_kib':after['child_peak_rss_kib'],
                        'reserved_tree_cpu_seconds':reserved_cpu,
                        'adopted_group_cleanup':group_cleanup,
                        'child_cpu_accounting_complete':accounting_complete,
                        'cpu_scope':'lifecycle CLI and reaped canonical parser descendants'}
                save(Path(str(log)+'.json'), item)
                self.invocations.append(item)
                if not accounting_complete:
                    raise RuntimeError('owned parser descendants not fully reaped; cost is a lower bound')
                if item['child_cpu_seconds'] > reserved_cpu or item['wall_seconds'] > MAX_WORKER_WALL:
                    raise RuntimeError('observed lifecycle tree exceeded its per-invocation reservation')
        if cut:
            assert returncode == -signal.SIGKILL
        elif expected_error:
            assert returncode != 0
            text = Path(str(log)+'.stderr').read_text()+Path(str(log)+'.stdout').read_text()
            assert expected_error in text, (expected_error, text)
            assert not (root / (name+'.json')).exists()
        else:
            assert returncode == 0, (command, Path(str(log)+'.stderr').read_text())
        self.guard()
        return item

    def supervisor_death(self, request, root):
        before = usage()
        remaining = self.guard()
        if remaining < 2:
            raise RuntimeError('declared campaign resource budget exhausted')
        # Reserve disjoint CPU allowances. The supervisor starts with soft=1 and
        # default SIGXCPU, retaining only enough hard-limit headroom to spawn the
        # worker. It lowers its own hard limit to 1 immediately after that spawn.
        helper_cpu = 1
        worker_cpu = min(MAX_WORKER_CPU, remaining-helper_cpu)
        # Adopt this supervisor's child after killing the supervisor, so the
        # actual kernel exit status and resource usage can be observed and reaped.
        if LIBC.prctl(36, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), 'PR_SET_CHILD_SUBREAPER failed')
        command = [str(self.binary), 'run', request['path'], request['sha256'],
                   str(root), 'unreachable.json', 'baseline_complete']
        log = self.output / f'process-{len(self.invocations):03}'
        receipt = Path(str(log)+'.supervisor.json')
        supervisor_command = [sys.executable, str(Path(__file__).resolve()),
                              '--owned-supervisor', str(receipt), str(worker_cpu), *command]
        began = time.monotonic()
        deadline = min(self.deadline, began+MAX_WORKER_WALL)
        worker_pid = None
        worker_status = None
        worker_usage = None
        group_cleanup = []
        accounting_complete = True
        sent = False
        exception = None
        with open(str(log)+'.stdout', 'xb') as stdout, open(str(log)+'.stderr', 'xb') as stderr:
            supervisor = subprocess.Popen(supervisor_command, stdout=stdout, stderr=stderr,
                                          start_new_session=True,
                                          preexec_fn=limits(helper_cpu, max(helper_cpu, worker_cpu)))
            self.open_process_groups.add(supervisor.pid)
            try:
                marker = root/'CUT_REACHED.json'
                identity, reached = ready_json(receipt), ready_json(marker)
                while identity is None or reached is None:
                    if supervisor.poll() is not None:
                        raise RuntimeError(f'owned supervisor exited early: {supervisor.returncode}')
                    if identity is not None:
                        worker_pid = identity['worker_pid']
                    self.guard([supervisor.pid], helper_cpu+worker_cpu)
                    if time.monotonic() >= deadline:
                        raise TimeoutError('supervisor death boundary not reached')
                    time.sleep(.01)
                    identity, reached = ready_json(receipt), ready_json(marker)
                worker_pid = identity['worker_pid']
                assert identity['supervisor_pid'] == supervisor.pid
                assert identity['process_group'] == supervisor.pid
                assert reached == {'phase': 'baseline_complete', 'pid': worker_pid}
                supervisor.kill()
                sent = True
                assert supervisor.wait(timeout=max(.001, min(5, deadline-time.monotonic()))) == -signal.SIGKILL
                reap_deadline = min(deadline, time.monotonic()+5)
                while worker_status is None:
                    pid, status, consumed = os.wait4(worker_pid, os.WNOHANG)
                    if pid:
                        worker_status, worker_usage = status, consumed
                        break
                    self.guard([worker_pid], worker_cpu)
                    if time.monotonic() >= reap_deadline:
                        raise TimeoutError('worker survived supervisor death')
                    time.sleep(.01)
                assert os.WIFSIGNALED(worker_status) and os.WTERMSIG(worker_status) == signal.SIGKILL
            except BaseException as error:
                exception = repr(error)
                raise
            finally:
                if supervisor.poll() is None:
                    supervisor.kill()
                    supervisor.wait(timeout=5)
                identity = ready_json(receipt)
                if worker_pid is None and identity is not None:
                    worker_pid = identity['worker_pid']
                if worker_pid is not None and worker_status is None:
                    try:
                        pid, status, consumed = os.wait4(worker_pid, os.WNOHANG)
                        if not pid:
                            # A live unreaped child is still owned by this study;
                            # no arbitrary process or system service is targeted.
                            os.kill(worker_pid, signal.SIGKILL)
                        else:
                            worker_status, worker_usage = status, consumed
                    except ChildProcessError:
                        pass
                # A supervisor can fail after spawn but before its receipt. As
                # subreaper, collect only children in our newly created process
                # group, even if their PID was never reported. This also brings
                # their real CPU into RUSAGE_CHILDREN instead of silently losing it.
                group_cleanup, accounting_complete = reap_owned_group(supervisor.pid)
                if accounting_complete:
                    self.open_process_groups.discard(supervisor.pid)
                after = usage()
                item = {'command': command, 'pid': worker_pid,
                        'returncode': os.waitstatus_to_exitcode(worker_status) if worker_status is not None else None,
                        'supervisor_command': supervisor_command, 'supervisor_pid': supervisor.pid,
                        'supervisor_returncode': supervisor.returncode, 'supervisor_sigkill_sent': sent,
                        'sigkill_sent': False, 'parent_death_sigkill_observed': sent and exception is None,
                        'cut': 'baseline_complete', 'exception': exception,
                        'wall_seconds': time.monotonic()-began,
                        'child_cpu_seconds': after['child_cpu']-before['child_cpu'],
                        'worker_cpu_seconds': worker_usage.ru_utime+worker_usage.ru_stime if worker_usage else None,
                        'supervisor_cpu_seconds': after['supervisor_cpu']-before['supervisor_cpu'],
                        'children_peak_rss_kib': after['child_peak_rss_kib'],
                        'reserved_helper_cpu_seconds': helper_cpu,
                        'reserved_worker_cpu_seconds': worker_cpu,
                        'supervisor_startup_limit': 'soft=1/default SIGXCPU; hard permits child reservation, then lowered to 1 after spawn',
                        'child_cpu_scope': 'RUSAGE of reaped worker and private Python supervisor; completeness flag controls interpretation'}
                item['adopted_group_cleanup'] = group_cleanup
                item['child_cpu_accounting_complete'] = accounting_complete
                save(Path(str(log)+'.json'), item)
                self.invocations.append(item)
                if not accounting_complete:
                    raise RuntimeError('owned process group could not be fully reaped; cost is a lower bound')
                if item['child_cpu_seconds'] > helper_cpu+worker_cpu or item['wall_seconds'] > MAX_WORKER_WALL:
                    raise RuntimeError('observed worker plus supervisor exceeded its reservation')
        self.guard()
        return item


def main():
    parser = argparse.ArgumentParser()
    for name in ['binary', 'binary-sha', 'input-manifest', 'input-sha', 'output', 'features', 'source']:
        parser.add_argument('--'+name, required=True)
    args = parser.parse_args()
    binary = Path(args.binary).resolve()
    assert pin(binary)['sha256'] == args.binary_sha
    manifest = Path(args.input_manifest).resolve()
    raw = manifest.read_bytes()
    assert digest(raw) == args.input_sha
    inputs = json.loads(raw)
    for case in inputs['cases']:
        for key in ['request','old_graph','expected_primary','expected_keep']:
            pinned(case[key])
    output = Path(args.output).resolve()
    output.mkdir(mode=0o700)
    cases_dir = output / 'cases'
    cases_dir.mkdir(mode=0o700)
    negatives = output / 'negative-inputs'
    negatives.mkdir(mode=0o700)
    fit11 = next(c for c in inputs['cases'] if c['fit']==11 and c['label']=='accept')
    base_request = json.loads(pinned(fit11['request']))
    wrong_public = json.loads(json.dumps(base_request))
    wrong_public['policy']['primary']['id'] += '-unbound'
    save(negatives/'wrong-primary.json', wrong_public)
    wrong_program = json.loads(pinned(base_request['program']))
    wrong_program['snapshot_sha256'] = '0'*64
    save(negatives/'wrong-program.json', wrong_program)
    wrong_request = json.loads(json.dumps(base_request))
    wrong_request['program'] = pin(negatives/'wrong-program.json')
    save(negatives/'wrong-program-request.json', wrong_request)
    fifo = negatives/'request.fifo'
    os.mkfifo(fifo, 0o600)
    protocol = {'schema':'hepta.lifecycle-real-checkpoint-campaign.v1','source_commit':args.source,
                'binary':pin(binary),'features':args.features,'input_manifest':pin(manifest),
                'script':pin(Path(__file__)),'cuts':CUTS,'normal_cases':inputs['cases'],
                'max_child_cpu_seconds':MAX_CPU,'max_wall_seconds':MAX_WALL,
                'per_worker_cpu_seconds':MAX_WORKER_CPU,'per_worker_wall_seconds':MAX_WORKER_WALL,
                'per_worker_address_space_bytes':2*1024**3,
                'negative_input_pins':[pin(negatives/'wrong-primary.json'),pin(negatives/'wrong-program-request.json')],
                'negative_cases':['stale_request_digest','wrong_primary','stale_program_snapshot','fifo_request',
                                  'missing_evaluation','corrupt_task_evidence','missing_restore','corrupt_candidate'],
                'model_selection':False,'production_adoption':False,'power_loss_tested':False,
                'partial_initial_capture_covered':False,'whole_worker_includes_evaluator':True}
    protocol['private_child_parent_death_control'] = {
        'mechanism': 'Linux PR_SET_PDEATHSIG(SIGKILL) with before-exec parent-pid race check',
        'test': 'kill private Python supervisor at real worker baseline_complete; observe adopted worker SIGKILL, recover, next-task',
        'public_job_owner_qualification_transferred': False}
    protocol['aggregate_budget_enforcement'] = {
        'wall': 'one monotonic campaign deadline; each worker shares that deadline and its own 60 s deadline',
        'cpu': 'per-process kernel limits plus bounded live process-tree polling (including cutime/cstime and live parser descendants), disjoint helper reservation, and exact final RUSAGE_CHILDREN gate; not a kernel whole-tree quota',
        'overrun': 'termination and measurement overhead are retained; any observed aggregate overrun fails qualification'}
    protocol['process_count_scope'] = '105 planned lifecycle CLI invocations exclude canonical descriptor-parser reentry processes; their CPU is included, not imputed zero'
    save(output/'PROTOCOL_FROZEN.json', protocol)
    campaign = Campaign(binary, output)
    records = []
    error = None
    try:
        for case in inputs['cases']:
            root = cases_dir / f'normal-{case["fit"]}-{case["label"]}'
            ran = campaign.worker(case['request'], root, 'run', 'normal')
            result = json.loads((root/'normal.json').read_text())
            assert result['evaluator_calls_this_process'] == 1 and result['restoration_exact']
            checked = inspect(root)
            if case['label']=='accept': assert checked['decision']=='ResearchAcceptedRestored'
            if case['label']=='reject': assert checked['decision']=='ResearchRejectedRestored'
            evaluation = json.loads((root/'EVALUATION.json').read_text())
            primary = json.loads((root/evaluation['tasks'][0]['filename']).read_text())
            for which, expected_key in [('baseline','expected_keep'),('candidate','expected_primary')]:
                expected = json.loads(gzip.decompress(pinned(case[expected_key])))['summary']['metrics']
                for metric in ['utility','optimal_utility','expected_terminal_reward','expected_expense',
                               'continuation_gap_contribution','terminal_gap_contribution','terminal_mass']:
                    assert abs(primary[which]['policy'][metric]-expected[metric]) <= 2e-10, (case['fit'],which,metric)
            before = checked['journal_files']
            next_run = campaign.worker(case['request'], root, 'next-task', 'next-task')
            next_checked = inspect_next_task(root, case['request'], args.binary_sha)
            assert inspect(root)['journal_files']==before
            records.append({'kind':'normal','fit':case['fit'],'label':case['label'],'run':ran,'next_task':next_run,'inspection':checked,
                            'next_task_inspection':next_checked,
                            'old_python_primary_aggregate_comparison':'PASS; no state-order equivalence asserted'})
            save(output/f'CASE_{len(records):03}.json', records[-1])
        for boundary in CUTS:
            root = cases_dir / ('cut-'+boundary)
            stopped = campaign.worker(fit11['request'],root,'run','unreachable',cut=boundary)
            recovered = campaign.worker(fit11['request'],root,'recover','recovered')
            actual = json.loads((root/'recovered.json').read_text())
            expected = 'KeptOriginal' if boundary in ['capture_complete','prepared'] else 'ResearchAcceptedRestored' if boundary=='complete' else 'InterruptedRestored'
            assert actual['record']['decision']==expected and actual['evaluator_calls_this_process']==0
            checked = inspect(root)
            again = campaign.worker(fit11['request'],root,'recover','recovered-again')
            assert inspect(root)==checked
            final = json.loads((root/'recovered-again.json').read_text())
            assert final['record']==actual['record'] and final['owner_calls_this_process']==[]
            next_run = campaign.worker(fit11['request'],root,'next-task','next-task')
            next_checked = inspect_next_task(root, fit11['request'], args.binary_sha)
            assert inspect(root)['journal_files']==checked['journal_files']
            records.append({'kind':'cut','boundary':boundary,'killed':stopped,'recovered':recovered,'again':again,'next_task':next_run,
                            'inspection':checked,'next_task_inspection':next_checked})
            save(output/f'CASE_{len(records):03}.json', records[-1])
        root = cases_dir/'supervisor-death'
        stopped = campaign.supervisor_death(fit11['request'], root)
        recovered = campaign.worker(fit11['request'], root, 'recover', 'recovered')
        checked = inspect(root)
        assert checked['decision'] == 'InterruptedRestored'
        assert checked['known_completed_policy_dps'] == 1
        next_run = campaign.worker(fit11['request'], root, 'next-task', 'next-task')
        next_checked = inspect_next_task(root, fit11['request'], args.binary_sha)
        assert inspect(root)['journal_files'] == checked['journal_files']
        records.append({'kind':'supervisor_death','stopped':stopped,'recovered':recovered,
                        'next_task':next_run,'inspection':checked,'next_task_inspection':next_checked})
        save(output/f'CASE_{len(records):03}.json', records[-1])
        invalids = [
            ('stale-request',dict(fit11['request'],sha256='0'*64),'request byte identity mismatch'),
            ('wrong-primary',pin(negatives/'wrong-primary.json'),'primary task differs'),
            ('stale-program',pin(negatives/'wrong-program-request.json'),'program provenance or source binding mismatch'),
            ('fifo-request',{'path':str(fifo),'sha256':'0'*64},'bounded regular file required')]
        for label,request,error_text in invalids:
            root=cases_dir/('negative-'+label)
            ran=campaign.worker(request,root,'run','must-not-exist',expected_error=error_text)
            assert not root.exists()
            records.append({'kind':'negative_input','label':label,'process':ran,'no_owner_or_model_effect':True})
            save(output/f'CASE_{len(records):03}.json',records[-1])
        for label,boundary in [('missing-evaluation','verified'),('corrupt-task','accepted'),
                               ('missing-restore','restored'),('corrupt-candidate','published')]:
            root=cases_dir/('negative-'+label)
            stopped=campaign.worker(fit11['request'],root,'run','unreachable',cut=boundary)
            if label=='missing-evaluation':
                (root/'EVALUATION.json').unlink()
                expected='No such file or directory'
            elif label=='corrupt-task':
                path=root/'TASK_00.json';data=path.read_bytes();path.write_bytes(data[:-1]+bytes([data[-1]^1]))
                expected='retained full task evidence is missing or changed'
            else:
                wanted='restore' if label=='missing-restore' else 'patch'
                artifact=next(p for p in (root/'owner-state/weight-artifacts-v1').iterdir() if json.loads((p/'manifest.json').read_text())['kind']==wanted)
                path=artifact/'model.safetensors'
                if label=='missing-restore': path.unlink();expected='No such file or directory'
                else:
                    data=path.read_bytes();path.write_bytes(data[:-1]+bytes([data[-1]^1]));expected='canonical artifact content differs'
            refused=campaign.worker(fit11['request'],root,'recover','must-not-exist',expected_error=expected)
            latest=sorted((root/'journal').rglob('record-*.json'))[-1]
            record=json.loads(latest.read_text())
            assert record['stage']!='Complete' and digest((root/'source.safetensors').read_bytes())==record['intent']['source_sha256']
            records.append({'kind':'negative_recovery','label':label,'killed':stopped,'refusal':refused,'retained_stage':record['stage'],
                            'source_unchanged':True,'false_complete_prevented':True})
            save(output/f'CASE_{len(records):03}.json',records[-1])
        status='PASS'
    except BaseException as exc:
        status='FAILED_OR_UNKNOWN'
        error=repr(exc)
    after=usage()
    started_dp = sorted(cases_dir.rglob('*.DP_STARTED.json'))
    completed_dp = sorted(cases_dir.rglob('*.DP_COMPLETED.json'))
    if len(completed_dp) > len(started_dp):
        status, error = 'FAILED_OR_UNKNOWN', 'more DP completion records than start records'
    final_wall = time.monotonic()-campaign.started
    final_child_cpu = after['child_cpu']-campaign.initial_usage['child_cpu']
    if final_child_cpu > MAX_CPU or final_wall > MAX_WALL:
        status = 'FAILED_OR_UNKNOWN'
        error = repr({'prior_error':error,'aggregate_budget_exceeded':True,
                      'child_cpu_seconds':final_child_cpu,'wall_seconds':final_wall})
    all_reaped = not campaign.open_process_groups and all(
        item.get('child_cpu_accounting_complete',False) for item in campaign.invocations)
    if not all_reaped:
        status = 'FAILED_OR_UNKNOWN'
        error = repr({'prior_error':error,'unreaped_owned_process_groups':sorted(campaign.open_process_groups),
                      'cost_is_lower_bound':True})
    result={'schema':'hepta.lifecycle-real-checkpoint-results.v1','status':status,'error':error,
            'protocol_sha256':pin(output/'PROTOCOL_FROZEN.json')['sha256'],'cases':records,
            'worker_processes':len(campaign.invocations),'actual_sigkills':sum(x['sigkill_sent'] for x in campaign.invocations),
            'lifecycle_cli_invocations':len(campaign.invocations),
            'internal_parser_processes_included_in_invocation_count':False,
            'all_owned_descendants_reaped':all_reaped,
            'unreaped_owned_process_groups':sorted(campaign.open_process_groups),
            'confirmed_lifecycle_cli_processes':sum(item['pid'] is not None for item in campaign.invocations),
            'invocations_with_unconfirmed_lifecycle_pid':sum(item['pid'] is None for item in campaign.invocations),
            'private_supervisors_killed':sum(x.get('supervisor_sigkill_sent',False) for x in campaign.invocations),
            'workers_killed_on_parent_death':sum(x.get('parent_death_sigkill_observed',False) for x in campaign.invocations),
            'normal_cases_completed':sum(x['kind']=='normal' for x in records),
            'cut_cases_completed':sum(x['kind']=='cut' for x in records),
            'negative_cases_completed':sum(x['kind'].startswith('negative') for x in records),
            'child_cpu_seconds':final_child_cpu,
            'supervisor_cpu_seconds':after['supervisor_cpu']-campaign.initial_usage['supervisor_cpu'],
            'children_peak_rss_kib':after['child_peak_rss_kib'],'wall_seconds':final_wall,
            'aggregate_budget_passed':final_child_cpu<=MAX_CPU and final_wall<=MAX_WALL,
            'durable_policy_dp_totals_after_all_cases':{
                'started_records':len(started_dp),'completed_records':len(completed_dp),
                'started_without_completion_record':len(started_dp)-len(completed_dp),
                'includes_next_task_and_negative_recovery_runs':True,
                'unrecorded_completion_is_unknown_not_zero':True},
            'new_model_quality_comparison':False,'production_adoption':False}
    save(output/'RESULTS.json',result)
    print(json.dumps({k:v for k,v in result.items() if k!='cases'}))
    if status!='PASS':raise SystemExit(1)


if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--owned-supervisor':
        owned_supervisor(sys.argv[2:])
    else:
        main()
