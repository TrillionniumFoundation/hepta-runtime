#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Deterministic sampler permission, identity, partial-discovery and log checks."""
import errno
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest import mock
from resource_sampler import Resources


class FakeProc:
    def __init__(self):
        self.stat_reads = {}
        self.fail_field = None
        self.change_pid = None
        self.partial_children = False
        self.parents = {10: 1, 20: 10, 30: 20}
        self.birth_overrides = {}
        self.fail_all_fields = set()
        self.fail_root_stat = False
        self.field_reads = []

    def stat(self, pid):
        self.stat_reads[pid] = self.stat_reads.get(pid, 0) + 1
        if self.fail_root_stat and pid == 10:
            raise PermissionError(errno.EACCES, 'synthetic denied identity')
        threshold = 3 if pid == 10 else 2
        born = pid * 100 + int(pid == self.change_pid and self.stat_reads[pid] >= threshold)
        return self.birth_overrides.get(pid, born), float(pid), self.parents[pid]

    def status(self, pid):
        self.field_reads.append(('status', pid))
        if 'status' in self.fail_all_fields or (self.fail_field == 'status' and pid == 20):
            raise PermissionError(errno.EACCES, 'synthetic denied status')
        return {'rss_kib': pid, 'hwm_kib': pid + 1, 'threads': 1}

    def fd_count(self, pid):
        self.field_reads.append(('fd', pid))
        if 'fd' in self.fail_all_fields or (self.fail_field == 'fd' and pid == 20):
            raise PermissionError(errno.EACCES, 'synthetic denied fd directory')
        return pid // 10

    def children(self, pid):
        self.field_reads.append(('children', pid))
        if 'children' in self.fail_all_fields or (self.fail_field == 'children' and pid == 20):
            raise PermissionError(errno.EACCES, 'synthetic denied task directory')
        children = {10: [20], 20: [30], 30: []}[pid]
        errors = [FileNotFoundError(errno.ENOENT, 'synthetic vanished task')] if (
            self.partial_children and pid == 20) else []
        return children, errors

    def master(self, pid):
        self.field_reads.append(('master', pid))
        if 'master' in self.fail_all_fields:
            raise PermissionError(errno.EACCES, 'synthetic denied master identity')
        return pid == 30


class BlockingFlush:
    def __init__(self, stream):
        self.stream = stream
        self.entered = threading.Event()
        self.release = threading.Event()

    @property
    def closed(self):
        return self.stream.closed

    def write(self, raw):
        return self.stream.write(raw)

    def flush(self):
        self.entered.set()
        if not self.release.wait(5):
            raise TimeoutError('controlled flush barrier was not released')
        self.stream.flush()

    def fileno(self):
        return self.stream.fileno()

    def close(self):
        self.stream.close()


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='hepta-a27-sampler-unit-')
        self.path = Path(self.directory.name) / 'errors.jsonl'
        self.proc = FakeProc()
        self.sampler = None

    def create(self):
        self.sampler = Resources(10, self.path, proc=self.proc, start=False)
        return self.sampler

    def tearDown(self):
        if self.sampler is not None:
            self.sampler.stop()
        self.directory.cleanup()

    def test_fd_permission_does_not_discard_status_cpu_or_descendants(self):
        self.proc.fail_field = 'fd'
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['peaks']['tree_rss_kib'], 60)
        self.assertEqual(row['peaks']['tree_fd'], 4)
        self.assertEqual(row['sampled_tree_cpu_seconds'], 60)
        self.assertEqual(row['sampled_process_generations'], 3)
        self.assertEqual(row['error_count'], 1)
        self.assertEqual(row['field_coverage']['fd_process_samples'], 2)
        self.assertEqual(row['field_coverage']['status_process_samples'], 3)
        self.assertTrue(row['sampled_tree_aggregates_are_non_atomic_estimates'])
        self.assertFalse(row['sampled_peaks_and_tree_cpu_are_lower_bounds'])

    def test_status_permission_does_not_discard_fd_or_cpu(self):
        self.proc.fail_field = 'status'
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['peaks']['tree_rss_kib'], 40)
        self.assertEqual(row['peaks']['tree_fd'], 6)
        self.assertEqual(row['sampled_process_generations'], 3)
        self.assertEqual(row['field_coverage']['status_process_samples'], 2)

    def test_changed_descendant_birth_discards_its_fields_and_discovery(self):
        self.proc.change_pid = 20
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['peaks']['tree_rss_kib'], 10)
        self.assertEqual(row['sampled_process_generations'], 1)
        self.assertNotIn(30, self.proc.stat_reads)
        self.assertEqual(row['error_counts_by_field'], {'identity_after:RuntimeError': 1})

    def test_changed_root_birth_stops_traversal_and_rejects_all_its_fields(self):
        self.proc.change_pid = 10
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertTrue(row['root_identity_lost'])
        self.assertTrue(sampler.stop_event.is_set())
        self.assertEqual(row['sampled_process_generations'], 0)
        self.assertIsNone(row['peaks']['tree_rss_kib'])
        self.assertNotIn(20, self.proc.stat_reads)

    def test_partial_task_scan_retains_discovered_children_with_error(self):
        self.proc.partial_children = True
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['sampled_process_generations'], 3)
        self.assertEqual(row['field_coverage']['children_partial_process_samples'], 1)
        self.assertEqual(row['error_counts_by_field'], {'children_task:FileNotFoundError': 1})

    def test_all_errors_persist_after_the_preview_limit(self):
        self.proc.fail_field = 'fd'
        sampler = self.create()
        for _ in range(40):
            sampler.sample_once()
        row = sampler.stop()
        raw = self.path.read_bytes()
        errors = [json.loads(line) for line in raw.splitlines()]
        self.assertEqual(len(row['errors']), 32)
        self.assertEqual(row['error_count'], 40)
        self.assertEqual(len(errors), 40)
        self.assertEqual([r['sequence'] for r in errors], list(range(40)))
        self.assertEqual(row['error_log_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(row['error_log_bytes'], len(raw))
        self.assertTrue(row['error_log_finalized'])
        self.assertTrue(row['error_log_complete'])
        self.assertEqual(row['error_log_rows_written'], 40)
        self.assertIsNone(row['error_log_failure'])

    def test_existing_error_log_is_never_overwritten(self):
        self.path.write_bytes(b'preserve-this')
        with self.assertRaises(FileExistsError):
            Resources(10, self.path, proc=self.proc, start=False)
        self.assertEqual(self.path.read_bytes(), b'preserve-this')

    def test_unobserved_metrics_and_cpu_are_unknown_before_any_samples(self):
        row = self.create().stop()
        self.assertTrue(all(value is None for value in row['peaks'].values()))
        self.assertIsNone(row['sampled_tree_cpu_seconds'])
        self.assertEqual(row['samples'], 0)
        self.assertEqual(row['field_coverage'], {})
        self.assertTrue(row['error_log_complete'])

    def test_denied_fields_remain_unknown_with_explicit_attempted_coverage(self):
        self.proc.fail_all_fields = {'status', 'fd', 'master'}
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        for key in ('controller_rss_kib', 'controller_hwm_kib', 'controller_fd',
                    'tree_rss_kib', 'tree_fd'):
            self.assertIsNone(row['peaks'][key])
        self.assertEqual(row['sampled_tree_cpu_seconds'], 60)
        self.assertEqual(row['field_coverage']['identity_process_samples'], 3)
        for field in ('status', 'fd', 'master'):
            self.assertEqual(row['field_coverage'][field + '_attempted_reads'], 3)
            self.assertEqual(row['field_coverage'].get(field + '_process_samples', 0), 0)
        point = row['timeline'][0]
        for key in ('tree_rss_kib', 'tree_fd', 'tree_threads', 'observed_master_count'):
            self.assertIsNone(point[key])
        self.assertEqual(row['error_count'], 9)

    def test_missing_root_identity_stops_and_does_not_fabricate_zero_cpu(self):
        sampler = self.create()
        self.proc.fail_root_stat = True
        sampler.sample_once()
        row = sampler.stop()
        self.assertTrue(row['root_identity_lost'])
        self.assertIsNone(row['sampled_tree_cpu_seconds'])
        self.assertTrue(all(value is None for value in row['peaks'].values()))
        self.assertEqual(self.proc.field_reads, [])

    def test_pid_reused_after_discovery_before_first_stat_is_not_a_descendant(self):
        # The parent has a stale children list. This replacement has a stable
        # birth throughout sampling, so before/after birth alone would accept it.
        self.proc.parents[20] = 999
        self.proc.birth_overrides[20] = 900020
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['sampled_process_generations'], 1)
        self.assertEqual(row['peaks']['tree_rss_kib'], 10)
        self.assertNotIn(20, [pid for _, pid in self.proc.field_reads])
        self.assertNotIn(30, self.proc.stat_reads)
        self.assertEqual(row['error_counts_by_field'], {'parent_before:RuntimeError': 1})

    def test_child_reparented_during_reads_is_rejected_at_acceptance(self):
        original_status = self.proc.status

        def changing_status(pid):
            value = original_status(pid)
            if pid == 20:
                self.proc.parents[pid] = 999
            return value

        self.proc.status = changing_status
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['sampled_process_generations'], 1)
        self.assertEqual(row['peaks']['tree_rss_kib'], 10)
        self.assertNotIn(30, self.proc.stat_reads)
        self.assertEqual(row['error_counts_by_field'], {'parent_after:RuntimeError': 1})

    def test_root_birth_change_before_descendant_fields_stops_discovery(self):
        original_stat = self.proc.stat

        def changing_stat(pid):
            value = original_stat(pid)
            if pid == 20:
                self.proc.birth_overrides[10] = 900010
            return value

        self.proc.stat = changing_stat
        sampler = self.create()
        sampler.sample_once()
        row = sampler.stop()
        self.assertTrue(row['root_identity_lost'])
        self.assertEqual(row['sampled_process_generations'], 1)
        self.assertNotIn(20, [pid for _, pid in self.proc.field_reads])
        self.assertNotIn(30, self.proc.stat_reads)

    def test_stop_times_out_without_waiting_for_blocked_log_flush_or_closing_it(self):
        self.proc.fail_field = 'fd'
        sampler = self.create()
        blocked = BlockingFlush(sampler.error_stream)
        sampler.error_stream = blocked
        sampler.thread.start()
        try:
            self.assertTrue(blocked.entered.wait(2))
            started = time.monotonic()
            row = sampler.stop(join_timeout=.02)
            self.assertLess(time.monotonic() - started, 1)
            self.assertFalse(row['sampler_thread_stopped'])
            self.assertTrue(row['error_log_in_progress'])
            self.assertFalse(row['error_log_finalized'])
            self.assertFalse(row['error_log_complete'])
            self.assertFalse(blocked.closed)
            self.assertEqual(row['error_count'], 1)
            self.assertEqual(row['error_log_rows_written'], 0)
        finally:
            blocked.release.set()
            final = sampler.stop(join_timeout=2)
        self.assertTrue(final['sampler_thread_stopped'])
        self.assertTrue(final['error_log_complete'])
        rows = [json.loads(line) for line in self.path.read_text().splitlines()]
        self.assertEqual(len(rows), final['error_count'])
        self.assertEqual([row['sequence'] for row in rows], list(range(len(rows))))

    def test_stop_times_out_while_final_fsync_is_blocked_without_closing_log(self):
        sampler = self.create()
        entered = threading.Event()
        release = threading.Event()
        original_fsync = os.fsync

        def blocked_fsync(fd):
            entered.set()
            if not release.wait(5):
                raise TimeoutError('controlled fsync barrier was not released')
            original_fsync(fd)

        with mock.patch('resource_sampler.os.fsync', side_effect=blocked_fsync):
            sampler.stop_event.set()
            sampler.thread.start()
            try:
                self.assertTrue(entered.wait(2))
                started = time.monotonic()
                row = sampler.stop(join_timeout=.02)
                self.assertLess(time.monotonic() - started, 1)
                self.assertFalse(row['sampler_thread_stopped'])
                self.assertTrue(row['error_log_in_progress'])
                self.assertFalse(row['error_log_finalized'])
                self.assertFalse(sampler.error_stream.closed)
            finally:
                release.set()
                final = sampler.stop(join_timeout=2)
        self.assertTrue(final['sampler_thread_stopped'])
        self.assertTrue(final['error_log_complete'])

    def test_error_log_write_failure_cannot_claim_all_errors_were_preserved(self):
        self.proc.fail_field = 'fd'
        sampler = self.create()
        with mock.patch.object(sampler.error_stream, 'write',
                               side_effect=OSError(errno.ENOSPC, 'synthetic log full')):
            for _ in range(3):
                sampler.sample_once()
        row = sampler.stop()
        self.assertEqual(row['error_count'], 3)
        self.assertEqual(row['error_log_rows_written'], 0)
        self.assertEqual(row['error_log_bytes'], 0)
        self.assertIsNotNone(row['error_log_failure'])
        self.assertFalse(row['error_log_complete'])
        self.assertEqual(self.path.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main(verbosity=2)
