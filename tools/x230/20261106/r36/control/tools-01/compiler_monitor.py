"""Bounded 1 Hz compiler metadata sampling; no argv, signals or hot-loop output."""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import threading
import time


@dataclass(frozen=True)
class Limits:
    period_ns: int = 1_000_000_000
    maximum_lateness_ns: int = 750_000_000
    maximum_start_gap_ns: int = 2_000_000_000
    maximum_scan_ns: int = 500_000_000
    maximum_duration_ns: int = 2_400_000_000_000
    maximum_samples: int = 2403
    maximum_serialized_sample_bytes: int = 8 * 1024 * 1024
    maximum_compiler_records: int = 8192
    maximum_process_directories_per_scan: int = 16384
    maximum_error_records: int = 64
    maximum_cpu_seconds_per_wall_second: float = 0.02
    ready_timeout_seconds: float = 5.0
    join_timeout_seconds: float = 10.0


FROZEN_LIMITS = Limits()


def reader_from_pinned_source(path, expected_sha256, maximum_process_directories=16384):
    path = Path(path)
    if path.resolve(strict=True) != path:
        raise ValueError('compiler metadata helper source identity differs')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
                before.st_nlink != 1 or not 0 < before.st_size <= 65536):
            raise ValueError('compiler metadata helper descriptor is not bounded owned source')
        raw = stream.read(65537)
        after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    current = path.lstat()
    if (path.resolve(strict=True) != path or len(raw) != after.st_size or
            any(getattr(before, key) != getattr(after, key) or getattr(after, key) != getattr(current, key) for key in fields) or
            hashlib.sha256(raw).hexdigest() != expected_sha256):
        raise ValueError('compiler metadata helper source changed during checked read')
    module = {'__name__': '_hepta_private_compiler_metadata', '__file__': str(path)}
    exec(compile(raw, str(path), 'exec'), module)

    def snapshot():
        return module['compiler_snapshot'](maximum_process_directories=maximum_process_directories)
    return snapshot


class CompilerMonitor:
    def __init__(self, snapshot, *, limits=FROZEN_LIMITS, clock=time.monotonic_ns,
                 cpu_clock=time.thread_time_ns):
        self.snapshot, self.limits = snapshot, limits
        self.clock, self.cpu_clock = clock, cpu_clock
        self.stop_event, self.ready_event = threading.Event(), threading.Event()
        self.lock = threading.Lock()
        self.samples, self.errors = [], []
        self.errors_dropped = self.sample_bytes = self.compiler_records = 0
        self.thread = None
        self.started_ns = self.finished_ns = self.cpu_ns = self.native_thread_id = None
        self.missed_slots = 0
        self.joined = False

    def error(self, reason):
        with self.lock:
            if len(self.errors) < self.limits.maximum_error_records:
                self.errors.append(reason)
            else:
                self.errors_dropped += 1

    def sample(self, kind, slot, scheduled_ns):
        start, cpu_start = self.clock(), self.cpu_clock()
        value, failure = None, None
        try:
            value = self.snapshot()
        except BaseException as error:
            failure = type(error).__name__ + ': ' + str(error)[:512]
        cpu_end, end = self.cpu_clock(), self.clock()
        row = {'kind': kind, 'slot': slot, 'scheduled_monotonic_ns': scheduled_ns,
               'started_monotonic_ns': start, 'finished_monotonic_ns': end,
               'thread_cpu_ns': cpu_end - cpu_start, 'snapshot': value, 'error': failure}
        if end < start or cpu_end < cpu_start:
            self.error('nonmonotonic sample wall or thread CPU clock')
        if end - start > self.limits.maximum_scan_ns:
            self.error('compiler scan exceeded frozen wall duration')
        if scheduled_ns is not None and not 0 <= start - scheduled_ns <= self.limits.maximum_lateness_ns:
            self.error('compiler sample outside frozen schedule lateness window')
        if self.samples and start - self.samples[-1]['started_monotonic_ns'] > self.limits.maximum_start_gap_ns:
            self.error('compiler sample gap exceeded frozen maximum')
        if failure is not None:
            self.error('compiler metadata sampling raised an exception')
        else:
            try:
                if value['schema'] != 'hepta-compiler-state-sample/v1' or not 1 <= value['enumerated_process_directories'] <= self.limits.maximum_process_directories_per_scan:
                    raise ValueError('metadata schema or process inventory missing')
                if not start <= value['started_monotonic_ns'] <= value['finished_monotonic_ns'] <= end:
                    raise ValueError('metadata clock does not fit sample')
                if value['cmdline_or_environment_read'] is not False or value['signals_sent'] != 0:
                    raise ValueError('metadata reader scope changed')
                if value['blocking_records'] or value['quiescent'] is not True:
                    self.error('observed live compiler or unproved compiler metadata')
                if any(record.get('reason') for record in value['records']):
                    self.error('compiler metadata race, disappearance or read failure observed')
                self.compiler_records += len(value['records'])
            except (KeyError, TypeError, ValueError) as error:
                self.error('invalid compiler metadata sample: ' + str(error)[:160])
        encoded_size = len(json.dumps(row, separators=(',', ':'), allow_nan=False).encode())
        if (len(self.samples) >= self.limits.maximum_samples or
                self.sample_bytes + encoded_size > self.limits.maximum_serialized_sample_bytes or
                self.compiler_records > self.limits.maximum_compiler_records):
            self.error('bounded compiler ledger exhausted; sample was not retained')
            return False
        with self.lock:
            self.samples.append(row)
            self.sample_bytes += encoded_size
        return True

    def _run(self):
        cpu_started = self.cpu_clock()
        self.started_ns = self.clock()
        self.native_thread_id = threading.get_native_id()
        try:
            if not self.sample('periodic', 0, self.started_ns): return
            self.ready_event.set()
            slot = 1
            while not self.stop_event.is_set():
                scheduled = self.started_ns + slot * self.limits.period_ns
                delay = (scheduled - self.clock()) / 1e9
                if delay > 0 and self.stop_event.wait(delay): break
                if self.stop_event.is_set(): break
                if self.clock() - self.started_ns > self.limits.maximum_duration_ns:
                    self.error('compiler monitor exceeded frozen duration')
                    return
                if not self.sample('periodic', slot, scheduled): return
                slot += 1
                next_slot = (self.clock() - self.started_ns) // self.limits.period_ns + 1
                if next_slot > slot:
                    self.missed_slots += next_slot - slot
                    self.error('scheduled compiler samples were missed; no catch-up normalization')
                    slot = next_slot
            # If stop races a due tick, explicitly attribute the final scan to
            # that still-required slot. Its original lateness bound still applies.
            scheduled = self.started_ns + slot * self.limits.period_ns
            due = self.clock() >= scheduled
            self.sample('final', slot if due else None, scheduled if due else None)
        except BaseException as error:
            self.error('monitor thread failed: ' + type(error).__name__ + ': ' + str(error)[:512])
        finally:
            self.finished_ns = self.clock()
            self.cpu_ns = self.cpu_clock() - cpu_started
            self.ready_event.set()

    def start(self):
        if self.thread is not None: raise ValueError('monitor cannot be restarted')
        # A daemon thread cannot outlive this wrapper process. Successful
        # evidence still requires a real complete join; a failed join is invalid.
        self.thread = threading.Thread(target=self._run, name='hepta-compiler-monitor', daemon=True)
        self.thread.start()
        if not self.ready_event.wait(self.limits.ready_timeout_seconds):
            self.error('compiler monitor initial sample readiness timed out')
        with self.lock:
            return bool(self.samples) and not self.errors and self.thread.is_alive()

    def stop(self, parent_start_ns, parent_end_ns):
        self.stop_event.set()
        if self.thread is not None:
            self.thread.join(self.limits.join_timeout_seconds)
            self.joined = not self.thread.is_alive()
        if not self.joined: self.error('compiler monitor did not completely join')
        with self.lock:
            samples = list(self.samples)
            errors = list(self.errors)
        wall_ns = None if self.started_ns is None or self.finished_ns is None else self.finished_ns - self.started_ns
        cpu_ratio = None if not wall_ns or self.cpu_ns is None or self.cpu_ns < 0 else self.cpu_ns / wall_ns
        covers_parent = bool(samples and parent_start_ns is not None and parent_end_ns is not None and
                             samples[0]['finished_monotonic_ns'] <= parent_start_ns <= parent_end_ns <= samples[-1]['started_monotonic_ns'] and
                             samples[-1]['kind'] == 'final' and self.finished_ns is not None and self.finished_ns >= parent_end_ns)
        if not covers_parent: errors.append('monitor did not cover original parent entry through final cleanup return')
        if wall_ns is None or not 0 <= wall_ns <= self.limits.maximum_duration_ns:
            errors.append('compiler monitor total duration exceeded frozen bound or was unavailable')
        if cpu_ratio is None or cpu_ratio > self.limits.maximum_cpu_seconds_per_wall_second:
            errors.append('monitor thread CPU cost exceeded frozen bound or was unavailable')
        if self.missed_slots: errors.append('compiler monitor missed scheduled samples')
        if self.errors_dropped: errors.append('compiler monitor error ledger overflowed')
        due_slots = None
        observed_due_slots = []
        if self.started_ns is not None and parent_end_ns is not None and parent_end_ns >= self.started_ns:
            due_slots = (parent_end_ns - self.started_ns) // self.limits.period_ns + 1
            observed_due_slots = [row['slot'] for row in samples if row['slot'] is not None and
                                  row['scheduled_monotonic_ns'] <= parent_end_ns]
            if due_slots > self.limits.maximum_samples or observed_due_slots != list(range(due_slots)):
                errors.append('required scheduled slots through parent end are missing, duplicated or out of order')
        else:
            errors.append('required compiler sampling schedule could not be established')
        return {'schema': 'hepta-bounded-compiler-monitor/v1', 'passed': not errors and self.joined,
                'limits': asdict(self.limits), 'parent_started_monotonic_ns': parent_start_ns,
                'parent_finished_monotonic_ns': parent_end_ns, 'monitor_started_monotonic_ns': self.started_ns,
                'monitor_finished_monotonic_ns': self.finished_ns, 'native_thread_id': self.native_thread_id,
                'thread_joined': self.joined, 'thread_cpu_ns': self.cpu_ns, 'wall_ns': wall_ns,
                'thread_cpu_seconds_per_wall_second': cpu_ratio, 'covers_parent_lifecycle': covers_parent,
                'sample_count': len(samples), 'serialized_sample_bytes': self.sample_bytes,
                'compiler_records': self.compiler_records, 'missed_scheduled_slots': self.missed_slots,
                'required_slots_through_parent_end': due_slots, 'observed_required_slots': observed_due_slots,
                'errors': errors, 'errors_dropped': self.errors_dropped, 'samples': samples,
                'hot_loop_file_writes': 0, 'signals_sent': 0, 'argv_or_environment_read': False,
                'statement_scope': '1 Hz metadata samples only; absence between observations is not proved'}
