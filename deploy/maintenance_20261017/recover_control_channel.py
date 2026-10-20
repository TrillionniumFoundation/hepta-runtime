#!/usr/bin/env python3
"""Restore the previously active tunnel only after the exact cutover has ended.

No native/frontend changes, effect requests, credential reads, or state recovery.
--check-only prints the same bounded diagnostic without starting any service.
"""
import argparse
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import time

ROOT = Path('/home/qian-qi/.local/state/hepta-runtime-optimization-20261017-0940')
RECEIPT = ROOT / 'native-cutover-v1-apply.json'
CUTOVER = 'hepta-runtime-native-cutover-20261017-0940.service'
TIMER = 'hepta-runtime-native-cutover-20261017-0940.timer'
TUNNEL = 'hepta-openai-full-operator.service'
OPERATOR = 'hepta-runtime-operator.service'
FRONT = 'hepta-computer-http-unlimited.service'
BUSY = {'active', 'activating', 'deactivating', 'reloading'}
UNIT_FIELDS = ('Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'Result', 'ExecMainStatus', 'Requires', 'Wants', 'BindsTo', 'PartOf', 'Job')
TIMER_FIELDS = ('NextElapseUSecRealtime', 'NextElapseUSecMonotonic')


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, 'receipt contains duplicate JSON keys')
        value[key] = item
    return value


def read_receipt():
    fd = os.open(RECEIPT, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid()
                and not before.st_mode & 0o077 and before.st_nlink == 1 and before.st_size <= 8 * 1024 * 1024,
                'receipt file identity or size is invalid')
        raw = stream.read(8 * 1024 * 1024 + 1)
        stamp = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        require(len(raw) == before.st_size and stamp(before) == stamp(os.fstat(stream.fileno())) == stamp(RECEIPT.lstat()),
                'receipt changed during read; no service action taken')
    value = json.loads(raw, object_pairs_hook=unique_object)
    require(isinstance(value, dict) and value.get('schema') == 'hepta-native-rollout-v1'
            and value.get('mode') == 'apply' and type(value.get('passed')) is bool
            and isinstance(value.get('calls'), list) and isinstance(value.get('events'), list), 'receipt schema is invalid')
    require(all(isinstance(item, dict) for item in value['calls'] + value['events']), 'receipt checkpoints have invalid structure')
    require(not (value['passed'] and 'rolled_back' in value)
            and not (value.get('activated') is True and not value['passed']), 'receipt outcome fields contradict each other')
    if 'finished_utc' in value:
        require(isinstance(value['finished_utc'], str) and bool(value['finished_utc']), 'receipt finished_utc is invalid')
        for key in ('started_utc', 'finished_utc'):
            parsed = datetime.datetime.fromisoformat(value[key].replace('Z', '+00:00'))
            require(parsed.tzinfo is not None and parsed.utcoffset() == datetime.timedelta(0), 'receipt timestamps are not valid UTC')
    return value, hashlib.sha256(raw).hexdigest()


def unit_status(name):
    fields = UNIT_FIELDS + (TIMER_FIELDS if name == TIMER else ())
    result = subprocess.run(['systemctl', '--user', 'show', name, *['--property=' + k for k in fields]],
                            capture_output=True, text=True, timeout=10)
    require(result.returncode == 0, 'systemctl status could not be read: ' + name)
    value = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
    allowed_loads = ('loaded', 'not-found') if name in (CUTOVER, TIMER) else ('loaded',)
    require(value.get('Id') == name and value.get('LoadState') in allowed_loads
            and (name == TIMER or value.get('MainPID', '').isdigit()), 'unit is missing or status is incomplete: ' + name)
    if name in (CUTOVER, TIMER, TUNNEL, OPERATOR, FRONT):
        # Job= is a real zero-job observation; a missing property is not.
        job = value.get('Job')
        require(job is not None and (job == '' or (job.isascii() and job.isdigit())),
                ('cutover' if name == CUTOVER else 'timer' if name == TIMER else 'control unit')
                + ' pending-job evidence is unavailable')
    if name in (TUNNEL, OPERATOR, FRONT):
        graph_fields = ('Requires', 'Wants', 'BindsTo')
        require(all(key in value for key in graph_fields),
                'control service dependency evidence is incomplete: ' + name)
        require(all(len(value[key]) <= 600 for key in graph_fields),
                'control service dependency evidence is oversized: ' + name)
    if name == TIMER:
        if value['LoadState'] == 'loaded':
            require(all(key in value for key in TIMER_FIELDS), 'timer next-elapse evidence is unavailable')
    return {key: value.get(key, '')[:600] for key in fields}


def running_tunnel_dependencies(tunnel):
    """Avoid pulling in operator/frontend or unrelated services during recovery.

    This is an observed admission check, not an atomic service-state lease.
    """
    actual = {dependency for field in ('Requires', 'Wants', 'BindsTo')
              for dependency in tunnel[field].split() if dependency.endswith('.service')}
    require(actual == {OPERATOR, FRONT},
            'tunnel service dependencies differ from the reviewed operator/frontend graph')
    observed = {}
    for name in (OPERATOR, FRONT):
        value = unit_status(name)
        require(value['ActiveState'] == 'active' and value['SubState'] == 'running'
                and int(value['MainPID']) > 0 and value['Job'] in ('', '0'),
                'tunnel dependency is not stably running: ' + name)
        observed[name] = value
    return observed


def timer_quiet(status):
    if status['ActiveState'] in BUSY or status['Job'] not in ('', '0'):
        return False
    require(status['ActiveState'] in ('inactive', 'failed') and status['SubState'] in ('dead', 'failed'),
            'cutover timer end state is uncertain')
    if status['LoadState'] == 'not-found':
        require(status['ActiveState'] == 'inactive' and status['SubState'] == 'dead',
                'missing cutover timer has contradictory state')
        return True
    # systemd formats the monotonic USEC_INFINITY sentinel as "infinity";
    # the realtime timestamp has its own empty/no-deadline representation.
    return (status['NextElapseUSecRealtime'] in ('', '0', 'n/a')
            and status['NextElapseUSecMonotonic'] in ('', '0', 'n/a', 'infinity'))


def summary(value):
    result = {key: value.get(key) for key in ('started_utc', 'finished_utc', 'preflight_passed', 'passed', 'activated', 'rolled_back')}
    result['calls_count'] = len(value['calls'])
    result['rollback_errors_count'] = len(value.get('rollback_errors', []))
    bounded = lambda item: item[:180] if isinstance(item, str) else item if type(item) in (bool, int, float) or item is None else '[invalid checkpoint value]'
    result['last_calls'] = [{key: bounded(call.get(key)) for key in ('call_id', 'phase', 'state', 'ok', 'elapsed_seconds')}
                            for call in value['calls'][-3:] if isinstance(call, dict)]
    result['last_events'] = []
    for item in value['events'][-6:]:
        if not isinstance(item, dict):
            continue
        projected = {key: bounded(item.get(key)) for key in ('phase', 'at_utc', 'unit', 'error_type') if key in item}
        command = item.get('command', [])
        if isinstance(command, list) and command[:2] == ['systemctl', '--user'] and len(command) >= 3:
            projected['systemctl_action'] = bounded(command[2])
            if len(command) > 3 and isinstance(command[3], str) and command[3].endswith('.service'):
                projected['systemctl_unit'] = bounded(command[3])
        result['last_events'].append(projected)
    return result


def eligible(value, status):
    if status['ActiveState'] in BUSY or 'finished_utc' not in value:
        return False
    if status['Job'] not in ('', '0'):
        return False
    require(status['ActiveState'] in ('inactive', 'failed') and int(status['MainPID']) == 0, 'cutover end state is uncertain')
    if status['LoadState'] == 'not-found':
        require(status['ActiveState'] == 'inactive' and status['SubState'] == 'dead',
                'missing cutover unit has contradictory state')
    if value['passed']:
        require(value.get('activated') is True, 'successful receipt lacks activation outcome')
        if status['LoadState'] == 'loaded':
            require(status['Result'] == 'success' and status['ExecMainStatus'] == '0',
                    'successful receipt contradicts cutover exit status')
    else:
        require(any(isinstance(e, dict) and e.get('phase') == 'failure' for e in value['events']), 'finished failure lacks a handled failure record')
        if 'rolled_back' in value:
            errors = value.get('rollback_errors')
            require(type(value['rolled_back']) is bool and isinstance(errors, list)
                    and value['rolled_back'] == (not errors), 'rollback receipt fields contradict each other')
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true')
    options = parser.parse_args()
    report = {'schema': 'hepta-control-channel-recovery-v1', 'service_action': 'none',
              'cutover_unit': CUTOVER, 'tunnel_unit': TUNNEL, 'receipt_path': str(RECEIPT),
              'external_mcp_verified': False}
    guard = None
    try:
        value, receipt_sha = read_receipt()
        status = unit_status(CUTOVER)
        report.update(receipt=summary(value), receipt_sha256=receipt_sha, cutover_status=status,
                      cutover_exit_evidence='loaded_unit_properties' if status['LoadState'] == 'loaded'
                      else 'unavailable_transient_unit_garbage_collected')
        if not eligible(value, status):
            report['decision'] = ('cutover_job_pending_no_service_changes'
                                  if status['Job'] not in ('', '0')
                                  else 'cutover_running_or_receipt_unfinished_no_service_changes'); return 0
        guard = os.open(ROOT / '.native-rollout-20261017.lock', os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            report['decision'] = 'rollout_lock_still_held_no_service_changes'; return 0
        current, current_sha = read_receipt()
        require(current_sha == receipt_sha, 'receipt changed before recovery; no service action taken')
        status = unit_status(CUTOVER)
        report['cutover_status'] = status
        report['cutover_exit_evidence'] = ('loaded_unit_properties' if status['LoadState'] == 'loaded'
                                           else 'unavailable_transient_unit_garbage_collected')
        if not eligible(current, status):
            report['decision'] = ('cutover_job_pending_no_service_changes'
                                  if status['Job'] not in ('', '0')
                                  else 'cutover_became_busy_no_service_changes'); return 0
        if status['LoadState'] == 'not-found':
            timer = unit_status(TIMER); report['cutover_timer_status'] = timer
            if not timer_quiet(timer):
                report['decision'] = 'cutover_timer_busy_or_pending_no_service_changes'; return 0
            report['cutover_end_evidence'] = 'finished_receipt_rechecked_under_rollout_lock_with_quiet_timer'
        tunnel = unit_status(TUNNEL); report['tunnel_before'] = tunnel
        if tunnel['ActiveState'] == 'active':
            require(tunnel['SubState'] == 'running' and int(tunnel['MainPID']) > 0, 'tunnel active state is not a running process')
            report['decision'] = 'tunnel_already_active_external_reconnect_must_be_verified'; return 0
        if tunnel['Job'] not in ('', '0'):
            report['decision'] = 'tunnel_job_pending_no_service_changes'; return 0
        if tunnel['ActiveState'] not in ('inactive', 'failed'):
            report['decision'] = 'tunnel_transition_in_progress_no_service_changes'; return 0
        require(int(tunnel['MainPID']) == 0, 'inactive tunnel still reports a live MainPID')
        report['ready_dependencies'] = running_tunnel_dependencies(tunnel)
        if options.check_only:
            report['decision'] = 'eligible_to_start_original_tunnel_check_only'; return 0
        report['service_action'] = 'start_original_tunnel_requested_once'
        result = subprocess.run(['systemctl', '--user', 'start', TUNNEL], capture_output=True, text=True, timeout=45)
        require(result.returncode == 0, 'tunnel start returned an error; no retry was submitted')
        deadline = time.monotonic() + 20
        while True:
            tunnel = unit_status(TUNNEL); report['tunnel_after'] = tunnel
            if tunnel['ActiveState'] == 'active' and tunnel['SubState'] == 'running' and int(tunnel['MainPID']) > 0:
                report['decision'] = 'original_tunnel_active_external_poll_still_needs_observation'; return 0
            require(time.monotonic() < deadline, 'tunnel did not become active within the observation deadline')
            time.sleep(0.5)
    except Exception as error:
        report.update(decision='read_only_failure' if report['service_action'] == 'none' else 'start_result_unconfirmed_no_retry',
                      error_type=type(error).__name__, error='systemctl observation or start timed out; no retry submitted' if isinstance(error, subprocess.TimeoutExpired) else str(error)[:700])
        return 1
    finally:
        if guard is not None:
            os.close(guard)
        print(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2), flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
