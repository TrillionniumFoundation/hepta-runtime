#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Birth-fenced, per-field Linux process samples with an append-only error log.

Sampling is always incomplete: short-lived or undiscovered descendants can be
missed, fields are not an atomic OS snapshot, and denied metrics are unknown.
One inaccessible field never discards another readable field on a process whose
birth identity still matches. This module grants no process-control authority.
"""
from collections import Counter
import hashlib
import json
import math
import os
from pathlib import Path
import threading
import time


class LinuxProc:
    def stat(self, pid):
        fields = Path(f'/proc/{pid}/stat').read_text().rsplit(') ', 1)[1].split()
        if fields[0] == 'Z':
            raise ProcessLookupError(pid)
        return (int(fields[19]),
                (int(fields[11]) + int(fields[12])) / os.sysconf('SC_CLK_TCK'),
                int(fields[1]))

    def status(self, pid):
        raw = dict(line.split(':', 1) for line in Path(f'/proc/{pid}/status').read_text().splitlines()
                   if ':' in line)
        return {'rss_kib': int(raw['VmRSS'].split()[0]),
                'hwm_kib': int(raw['VmHWM'].split()[0]),
                'threads': int(raw['Threads'].strip())}

    def fd_count(self, pid):
        return len(list(Path(f'/proc/{pid}/fd').iterdir()))

    def children(self, pid):
        children = set()
        errors = []
        for task in Path(f'/proc/{pid}/task').iterdir():
            try:
                children.update(map(int, (task / 'children').read_text().split()))
            except OSError as error:
                # Keep other readable task lists while recording incomplete discovery.
                errors.append(error)
        return sorted(children), errors

    def master(self, pid):
        args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
        comm = Path(f'/proc/{pid}/comm').read_text().strip()
        return (comm == 'ssh' and b'-N' in args and b'-n' in args
                and b'-G' not in args and b'ControlMaster=yes' in args)


class Resources:
    """Compatible observation-driver sampler; construct via factory below."""
    def __init__(self, pid, error_path, *, proc=None, start=True):
        self.pid = pid
        self.proc = proc if proc is not None else LinuxProc()
        self.birth = self.proc.stat(pid)[0]
        self.error_path = Path(error_path)
        descriptor = os.open(self.error_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                             os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        self.error_stream = os.fdopen(descriptor, 'wb')
        self.error_hash = hashlib.sha256()
        self.error_log_sha256 = self.error_hash.hexdigest()
        self.error_bytes = 0
        self.error_rows_written = 0
        self.error_log_finalized = False
        self.error_log_failure = None
        self.error_log_in_progress = False
        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        # Log writes/finalization can block in the kernel. Snapshot and stop
        # never take this lock, and no file I/O is performed under self.lock.
        self.log_lock = threading.Lock()
        self.thread_start_lock = threading.Lock()
        self.origin = time.monotonic()
        self.next_timeline = self.origin
        self.samples = 0
        self.seen = {}
        self.errors = []
        self.error_count = 0
        self.error_counts = Counter()
        self.coverage = Counter()
        self.timeline = []
        self.timeline_capped = False
        self.master_generations = {}
        self.root_identity_lost = False
        self.peaks = {key: None for key in ['controller_rss_kib', 'controller_hwm_kib',
                      'controller_fd', 'tree_rss_kib', 'tree_fd', 'descendants']}
        self.thread = threading.Thread(target=self.run, daemon=True)
        if start:
            self.thread.start()

    def record_error(self, pid, born, stage, error):
        with self.log_lock:
            message = str(error)
            with self.lock:
                row = {'sequence': self.error_count, 'seconds': time.monotonic() - self.origin,
                       'pid': pid, 'birth_ticks': born, 'stage': stage,
                       'error_type': type(error).__name__, 'errno': getattr(error, 'errno', None),
                       'message': message[:300], 'message_truncated': len(message) > 300}
                self.error_count += 1
                self.error_counts[stage + ':' + row['error_type']] += 1
                if len(self.errors) < 32:
                    self.errors.append(row['error_type'] + ': ' + row['message'])
                if self.error_log_failure is not None:
                    return
                if self.error_log_finalized:
                    self.error_log_failure = 'RuntimeError: error arrived after log finalization'
                    return
                self.error_log_in_progress = True
            raw = (json.dumps(row, sort_keys=True, separators=(',', ':')) + '\n').encode()
            try:
                if self.error_stream.write(raw) != len(raw):
                    raise OSError('incomplete sampler error-log write')
                self.error_stream.flush()
            except (OSError, ValueError) as failure:
                with self.lock:
                    self.error_log_failure = type(failure).__name__ + ': ' + str(failure)[:300]
                    self.error_log_in_progress = False
            else:
                self.error_hash.update(raw)
                with self.lock:
                    self.error_log_sha256 = self.error_hash.hexdigest()
                    self.error_bytes += len(raw)
                    self.error_rows_written += 1
                    self.error_log_in_progress = False

    def lose_root(self):
        with self.lock:
            self.root_identity_lost = True
        self.stop_event.set()

    def parent_matches(self, pid, born, ppid, parent, stage):
        expected_pid, expected_birth = parent
        if ppid != expected_pid:
            self.record_error(pid, born, stage, RuntimeError('discovered child parent changed'))
            return False
        anchors = [(expected_pid, expected_birth)]
        if expected_pid != self.pid:
            anchors.append((self.pid, self.birth))
        for anchor_pid, anchor_birth in anchors:
            try:
                current_birth = self.proc.stat(anchor_pid)[0]
                if current_birth != anchor_birth:
                    raise RuntimeError('discovered parent or root birth changed')
            except Exception as error:
                if anchor_pid == self.pid:
                    self.lose_root()
                self.record_error(pid, born, stage, error)
                return False
        return True

    def update_peak(self, name, value):
        # Caller holds the short-lived state lock. Unknown is never zero.
        if value is not None:
            previous = self.peaks[name]
            self.peaks[name] = value if previous is None else max(previous, value)

    def sample_once(self):
        pending = [(self.pid, None)]
        visited = set()
        totals = {'rss': 0, 'fd': 0, 'threads': 0, 'masters': 0}
        accepted = 0
        controller_accepted = False
        fields_seen = Counter()
        fields_attempted = Counter()
        controller = {'rss_kib': None, 'fd': None, 'threads': None}
        first_error = self.error_count
        while pending and not self.root_identity_lost:
            pid, parent = pending.pop()
            if pid in visited:
                continue
            visited.add(pid)
            try:
                born, cpu, ppid = self.proc.stat(pid)
            except Exception as error:
                self.record_error(pid, None, 'identity_before', error)
                if pid == self.pid:
                    self.lose_root()
                continue
            if pid == self.pid and born != self.birth:
                self.lose_root()
                self.record_error(pid, born, 'root_identity', RuntimeError('root PID birth changed'))
                break
            if parent is not None and not self.parent_matches(pid, born, ppid, parent, 'parent_before'):
                continue
            values = {}
            for field, read in [('status', self.proc.status), ('fd', self.proc.fd_count),
                                ('children', self.proc.children), ('master', self.proc.master)]:
                fields_attempted[field] += 1
                try:
                    values[field] = read(pid)
                    if field == 'children':
                        values[field], child_errors = values[field]
                        values['children_partial'] = bool(child_errors)
                        for error in child_errors:
                            self.record_error(pid, born, 'children_task', error)
                except Exception as error:
                    self.record_error(pid, born, field, error)
            try:
                after_born, after_cpu, after_ppid = self.proc.stat(pid)
                if after_born != born:
                    raise RuntimeError('PID birth changed before sample acceptance')
            except Exception as error:
                self.record_error(pid, born, 'identity_after', error)
                if pid == self.pid:
                    # No further traversal may be rooted in a different process.
                    self.lose_root()
                continue
            if parent is not None and not self.parent_matches(
                    pid, born, after_ppid, parent, 'parent_after'):
                continue
            accepted += 1
            controller_accepted = controller_accepted or pid == self.pid
            fields_seen['identity'] += 1
            with self.lock:
                self.seen[(pid, born)] = max(cpu, after_cpu, self.seen.get((pid, born), 0))
            if 'children' in values:
                pending.extend((child, (pid, born)) for child in values['children'])
                fields_seen['children'] += 1
                fields_seen['children_partial'] += int(values['children_partial'])
            if 'status' in values:
                status = values['status']
                totals['rss'] += status['rss_kib']
                totals['threads'] += status['threads']
                fields_seen['status'] += 1
                if pid == self.pid:
                    controller.update(rss_kib=status['rss_kib'], threads=status['threads'])
                    with self.lock:
                        for key, value in [('controller_rss_kib', status['rss_kib']),
                                           ('controller_hwm_kib', status['hwm_kib'])]:
                            self.update_peak(key, value)
            if 'fd' in values:
                totals['fd'] += values['fd']
                fields_seen['fd'] += 1
                if pid == self.pid:
                    controller['fd'] = values['fd']
                    with self.lock:
                        self.update_peak('controller_fd', values['fd'])
            if 'master' in values:
                fields_seen['master'] += 1
                if values['master']:
                    totals['masters'] += 1
                    with self.lock:
                        key = (pid, born)
                        if key not in self.master_generations:
                            self.master_generations[key] = {'generation': len(self.master_generations),
                                'first_seen_seconds': time.monotonic() - self.origin,
                                'last_seen_seconds': time.monotonic() - self.origin, 'samples': 0}
                        record = self.master_generations[key]
                        record['last_seen_seconds'] = time.monotonic() - self.origin
                        record['samples'] += 1
        now = time.monotonic()
        with self.lock:
            self.samples += 1
            self.coverage.update({'attempted_process_samples': len(visited),
                                 'accepted_process_samples': accepted})
            self.coverage.update({key + '_process_samples': value for key, value in fields_seen.items()})
            self.coverage.update({key + '_attempted_reads': value
                                  for key, value in fields_attempted.items()})
            tree_rss = totals['rss'] if fields_seen['status'] else None
            tree_fd = totals['fd'] if fields_seen['fd'] else None
            tree_threads = totals['threads'] if fields_seen['status'] else None
            observed_masters = totals['masters'] if fields_seen['master'] else None
            descendants = (max(0, accepted - int(controller_accepted))
                           if fields_seen['children'] else None)
            for key, value in [('tree_rss_kib', tree_rss), ('tree_fd', tree_fd),
                               ('descendants', descendants)]:
                self.update_peak(key, value)
            if now >= self.next_timeline:
                if len(self.timeline) < 1800:
                    self.timeline.append({'seconds': now - self.origin, 'controller': controller,
                        'tree_rss_kib': tree_rss, 'tree_fd': tree_fd,
                        'tree_threads': tree_threads, 'observed_master_count': observed_masters,
                        'observed_master_generations': len(self.master_generations),
                        'attempted_processes': len(visited), 'accepted_processes': accepted,
                        'readable_fields': dict(fields_seen), 'attempted_fields': dict(fields_attempted),
                        'sample_errors': self.error_count - first_error})
                else:
                    self.timeline_capped = True
                self.next_timeline = now + 1.0

    def run(self):
        try:
            while not self.stop_event.is_set():
                try:
                    self.sample_once()
                except Exception as error:
                    self.record_error(self.pid, self.birth, 'sampler', error)
                self.stop_event.wait(.1)
        finally:
            self.finalize_log()

    def finalize_log(self):
        with self.log_lock:
            if self.error_stream.closed:
                return
            with self.lock:
                self.error_log_in_progress = True
            finalized = False
            failure_message = None
            try:
                self.error_stream.flush()
                os.fsync(self.error_stream.fileno())
                self.error_stream.close()
                directory = os.open(self.error_path.parent, os.O_DIRECTORY | os.O_RDONLY |
                                    os.O_CLOEXEC)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
                finalized = True
            except (OSError, ValueError) as failure:
                failure_message = type(failure).__name__ + ': ' + str(failure)[:300]
            finally:
                try:
                    self.error_stream.close()
                except (OSError, ValueError) as failure:
                    finalized = False
                    if failure_message is None:
                        failure_message = type(failure).__name__ + ': ' + str(failure)[:300]
                with self.lock:
                    self.error_log_finalized = finalized
                    if self.error_log_failure is None:
                        self.error_log_failure = failure_message
                    self.error_log_in_progress = False

    def snapshot(self):
        with self.lock:
            return {'samples': self.samples, 'peaks': dict(self.peaks),
                'sampled_tree_cpu_seconds': sum(self.seen.values()) if self.seen else None,
                'sampled_process_generations': len(self.seen), 'errors': list(self.errors),
                'error_count': self.error_count, 'error_counts_by_field': dict(self.error_counts),
                'error_preview_limit': 32, 'error_message_limit': 300, 'error_log': str(self.error_path),
                'error_log_sha256': self.error_log_sha256, 'error_log_bytes': self.error_bytes,
                'error_log_hash_scope': 'successfully flushed complete rows',
                'error_log_rows_written': self.error_rows_written,
                'error_log_in_progress': self.error_log_in_progress,
                'error_log_complete': (self.error_log_finalized and self.error_log_failure is None
                                       and self.error_rows_written == self.error_count),
                'error_log_finalized': self.error_log_finalized, 'error_log_failure': self.error_log_failure,
                'root_identity_lost': self.root_identity_lost, 'field_coverage': dict(self.coverage),
                'sample_interval_seconds': .1, 'sampled_peaks_and_tree_cpu_are_lower_bounds': False,
                'sampled_tree_aggregates_are_non_atomic_estimates': True,
                'cpu_sum_uses_lifetime_counters_for_observed_generations': True,
                'cpu_delta_is_not_an_exact_interval_measurement': True,
                'timeline': list(self.timeline), 'timeline_capped': self.timeline_capped,
                'timeline_interval_seconds': 1.0, 'timeline_is_sampled_lower_bound': False,
                'observed_master_generations': [dict(v) for v in self.master_generations.values()],
                'master_classifier': 'descendant ssh with -N, -n, ControlMaster=yes, no -G; sampled only',
                'missing_fields_are_unknown': True, 'metrics_are_not_atomic': True,
                'descendant_parent_pid_and_birth_rechecked': True,
                'ancestry_observations_are_not_atomic': True}

    def stop(self, join_timeout=5):
        if not math.isfinite(join_timeout) or join_timeout < 0:
            raise ValueError('sampler join timeout must be finite and nonnegative')
        self.stop_event.set()
        # Manual/fake samples also finalize on this worker. A blocked fsync
        # must not turn the nominally bounded caller into the log's I/O owner.
        with self.thread_start_lock:
            if self.thread.ident is None:
                self.thread.start()
        self.thread.join(join_timeout)
        stopped = not self.thread.is_alive()
        value = self.snapshot()
        value['sampler_thread_stopped'] = stopped
        return value


def factory(output):
    """Make one fresh error log per controller without mutating frozen helpers."""
    sequence = 0
    def create(pid):
        nonlocal sequence
        sequence += 1
        return Resources(pid, Path(output) / f'resource-errors-{sequence:03d}.jsonl')
    return create
