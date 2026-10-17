#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real private-file pagination, cursor integrity and refusal regressions."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "deploy"))
import runtime_registry_page as P


class RegistryPageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hepta-job-pages-")
        self.base = Path(self.tmp.name)
        self.old, self.new = self.base / "old", self.base / "new"
        for root in (self.old, self.new):
            root.mkdir(mode=0o700)
            (root / "jobs").mkdir(mode=0o700)
        self.pager = P.RuntimeRegistryPager(self.old, self.new)

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, root, number, host="main", **changes):
        identity = f"1a14-{number:x}-1"
        record = {"id": identity, "host": host, "created_unix_ms": number,
                  "execution_mode": "operator", "launch_state": "launched",
                  "args": ["PRIVATE_ARG_NEVER_RETURNED"], "remote_job_dir": "/private/work"}
        record.update(changes)
        path = root / "jobs" / (identity + ".json")
        path.write_text(json.dumps(record), encoding="utf-8")
        path.chmod(0o600)
        return path

    def first_cursor(self):
        self.write(self.old, 1)
        self.write(self.new, 2)
        return self.pager.page({"limit": 1})["next_cursor"]

    def test_two_owners_exact_five_fields_and_complete_continuation(self):
        for root, number in ((self.new, 4), (self.old, 1), (self.new, 3), (self.old, 2)):
            self.write(root, number)
        first = self.pager.page({"limit": 2})
        self.assertEqual(first["total"], 4)
        self.assertFalse(first["inventory_complete"])
        self.assertTrue(first["has_more"])
        self.assertEqual(len(first["jobs"]), 2)
        self.assertRegex(first["next_cursor"], P.CURSOR)
        second = self.pager.page({"limit": 2, "cursor": first["next_cursor"]})
        self.assertEqual(second["snapshot_id"], first["snapshot_id"])
        self.assertTrue(second["inventory_complete"])
        self.assertFalse(second["has_more"])
        self.assertIsNone(second["next_cursor"])
        rows = first["jobs"] + second["jobs"]
        self.assertEqual([row["id"] for row in rows], sorted(row["id"] for row in rows))
        self.assertEqual({row["owner"] for row in rows}, {"legacy", "native"})
        self.assertTrue(all(set(row) == {"owner", "id", "host", "created_unix_ms",
                                         "execution_mode", "launch_state"} for row in rows))
        self.assertNotIn("PRIVATE_ARG", json.dumps([first, second]))
        self.assertNotIn("/private/work", json.dumps([first, second]))

    def test_empty_registry_is_complete(self):
        page = self.pager.page({})
        self.assertEqual(page["jobs"], [])
        self.assertEqual(page["total"], 0)
        self.assertTrue(page["inventory_complete"])
        self.assertIsNone(page["next_cursor"])

    def test_filtered_host_and_native_serde_defaults(self):
        path = self.write(self.old, 1, "rog")
        record = json.loads(path.read_text())
        del record["execution_mode"], record["launch_state"]
        path.write_text(json.dumps(record))
        self.write(self.new, 2, "main")
        result = self.pager.page({"host": "rog"})
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["jobs"][0]["execution_mode"], "isolated")
        self.assertEqual(result["jobs"][0]["launch_state"], "launched")

    def test_opaque_cursor_rejects_host_filter_change(self):
        cursor = self.first_cursor()
        with self.assertRaisesRegex(P.UnsafeProvenance, "snapshot_expired_or_cursor_invalid"):
            self.pager.page({"host": "main", "cursor": cursor})

    def test_frozen_cursor_ignores_added_member_until_a_new_first_page(self):
        cursor = self.first_cursor()
        self.write(self.new, 3)
        page = self.pager.page({"cursor": cursor})
        self.assertEqual(page["total"], 2)
        self.assertEqual([row["id"] for row in page["jobs"]], ["1a14-2-1"])
        self.assertEqual(self.pager.page({})["total"], 3)

    def test_frozen_cursor_keeps_initial_metadata_after_member_removal(self):
        cursor = self.first_cursor()
        (self.new / "jobs" / "1a14-2-1.json").unlink()
        page = self.pager.page({"cursor": cursor})
        self.assertEqual(page["total"], 2)
        self.assertEqual([row["id"] for row in page["jobs"]], ["1a14-2-1"])
        self.assertFalse(page["status_authoritative"])

    def test_frozen_cursor_keeps_initial_projection_after_metadata_change(self):
        cursor = self.first_cursor()
        self.write(self.new, 2, args=["CHANGED_PRIVATE_ARG"], launch_state="changed")
        with mock.patch.object(self.pager, "_collect", side_effect=AssertionError("no rescan")):
            page = self.pager.page({"cursor": cursor})
        self.assertEqual(page["jobs"][0]["launch_state"], "launched")
        self.assertNotIn("CHANGED_PRIVATE_ARG", repr(self.pager._snapshots))
        self.assertNotIn("PRIVATE_ARG_NEVER_RETURNED", repr(self.pager._snapshots))
        self.assertNotIn("/private/work", repr(self.pager._snapshots))

    def test_opaque_cursor_rejects_root_replacement(self):
        cursor = self.first_cursor()
        self.old.rename(self.base / "original-held")
        self.old.mkdir(mode=0o700)
        (self.old / "jobs").mkdir(mode=0o700)
        self.write(self.old, 1)
        with self.assertRaisesRegex(P.UnsafeProvenance, "root_or_directory_changed"):
            self.pager.page({"cursor": cursor})

    def test_opaque_cursor_rejects_forgery_and_process_restart(self):
        cursor = self.first_cursor()
        forged = cursor[:-1] + ("A" if cursor[-1] != "A" else "B")
        for pager, value in ((self.pager, forged),
                             (P.RuntimeRegistryPager(self.old, self.new), cursor)):
            with self.assertRaisesRegex(P.UnsafeProvenance, "snapshot_expired_or_cursor_invalid"):
                pager.page({"cursor": value})

    def test_cursor_retry_returns_identical_page(self):
        cursor = self.first_cursor()
        self.assertEqual(self.pager.page({"cursor": cursor}), self.pager.page({"cursor": cursor}))

    def test_frozen_snapshot_expires_and_recreation_cannot_resurrect_old_cursor(self):
        now = [100.0]
        self.pager._clock = lambda: now[0]
        cursor = self.first_cursor()
        now[0] += P.SNAPSHOT_TTL_SECONDS
        with self.assertRaisesRegex(P.UnsafeProvenance, "snapshot_expired_or_cursor_invalid"):
            self.pager.page({"cursor": cursor})
        fresh = self.pager.page({"limit": 1})
        self.assertNotEqual(fresh["next_cursor"], cursor)
        with self.assertRaises(P.UnsafeProvenance):
            self.pager.page({"cursor": cursor})

    def test_bounded_snapshot_cache_evicts_whole_old_snapshots_without_truncating_rows(self):
        oldest = self.first_cursor()
        for _ in range(P.MAX_SNAPSHOTS):
            latest = self.pager.page({"limit": 1})
        self.assertLessEqual(len(self.pager._snapshots), P.MAX_SNAPSHOTS)
        with self.assertRaises(P.UnsafeProvenance):
            self.pager.page({"cursor": oldest})
        self.assertEqual(self.pager.page({"cursor": latest["next_cursor"]})["total"], 2)
        with mock.patch.object(P, "MAX_SNAPSHOT_CACHE_BYTES", 1):
            with self.assertRaisesRegex(P.UnsafeProvenance, "snapshot_cache_bound"):
                self.pager.page({})
        with mock.patch.object(P, "MAX_SNAPSHOT_CACHE_ROWS", 1):
            with self.assertRaisesRegex(P.UnsafeProvenance, "snapshot_cache_bound"):
                self.pager.page({})

    def test_active_cursor_fairness_under_other_snapshot_churn(self):
        # A client paging continuously should not be evicted solely by
        # unrelated first-page inventory requests, within the finite cache cap.
        cursor = self.first_cursor()
        expected = self.pager.page({"cursor": cursor})["jobs"]
        for _ in range(P.MAX_SNAPSHOTS + 4):
            self.pager.page({"limit": 1})  # another short-lived reader
            current = self.pager.page({"cursor": cursor})
            self.assertEqual(current["jobs"], expected)
            self.assertLessEqual(len(self.pager._snapshots), P.MAX_SNAPSHOTS)

    def test_returned_projection_cannot_mutate_cached_frozen_rows(self):
        self.write(self.old, 1)
        self.write(self.new, 2)
        first = self.pager.page({"limit": 1})
        first["jobs"][0]["id"] = "mutated-by-caller"
        self.assertEqual(self.pager._snapshots[0]["rows"][0]["id"], "1a14-1-1")
        self.assertEqual(self.pager.page({"cursor": first["next_cursor"]})["jobs"][0]["id"], "1a14-2-1")

    def test_invalid_arguments_and_shape_refuse(self):
        invalid = [None, [], {"limit": 0}, {"limit": 129}, {"limit": True},
                   {"host": "unconfigured"}, {"host": []}, {"cursor": "../path"},
                   {"cursor": 5}, {"after_job_id": "1a14-1-1"}, {"limit": None}]
        for arguments in invalid:
            with self.subTest(arguments=arguments), self.assertRaises(P.UnsafeProvenance):
                self.pager.page(arguments)

    def test_no_symlinks_hardlinks_or_nonprivate_record(self):
        path = self.write(self.old, 1)
        other = self.write(self.new, 2)
        path.unlink()
        path.symlink_to(other)
        with self.assertRaises(OSError):
            self.pager.page({})
        path.unlink()
        os.link(other, path)
        with self.assertRaises(P.UnsafeProvenance):
            self.pager.page({})
        path.unlink()
        path = self.write(self.old, 1)
        path.chmod(0o644)
        with self.assertRaises(P.UnsafeProvenance):
            self.pager.page({})

    def test_duplicate_json_key_and_owner_collision_refuse(self):
        path = self.write(self.old, 1)
        path.write_text('{"id":"1a14-1-1","host":"main","host":"rog"}')
        with self.assertRaises(P.UnsafeProvenance):
            self.pager.page({})
        self.write(self.old, 1)
        self.write(self.new, 1)
        with self.assertRaisesRegex(P.UnsafeProvenance, "collision"):
            self.pager.page({})

    def test_wrong_identity_and_projection_refuse(self):
        for changes in ({"id": "1a14-8-1"}, {"host": "unknown"},
                        {"created_unix_ms": True}, {"created_unix_ms": -1},
                        {"created_unix_ms": 2 ** 128}, {"execution_mode": "invented"},
                        {"launch_state": {}}):
            with self.subTest(changes=changes):
                self.write(self.old, 1, **changes)
                with self.assertRaises(P.UnsafeProvenance):
                    self.pager.page({})

    def test_missing_or_alias_registry_roots_refuse(self):
        with self.assertRaises(P.UnsafeProvenance):
            P.RuntimeRegistryPager(self.old, self.old / ".." / "old")
        with self.assertRaises(P.UnsafeProvenance):
            P.RuntimeRegistryPager("relative", self.new)
        (self.old / "jobs").rmdir()
        with self.assertRaises(OSError):
            self.pager.page({})

    def test_row_byte_budget_continues_without_dropping_rows(self):
        for number in range(1, 5):
            self.write(self.old, number, launch_state="x" * 20000)
        first = self.pager.page({})
        self.assertLessEqual(len(P.canonical(first["jobs"])), P.MAX_PAGE_ROW_BYTES)
        self.assertEqual(len(first["jobs"]), 3)
        second = self.pager.page({"cursor": first["next_cursor"]})
        self.assertEqual(len(second["jobs"]), 1)
        self.assertTrue(second["inventory_complete"])

    def test_oversize_single_row_and_scan_bounds_refuse(self):
        self.write(self.old, 1, launch_state="x" * P.MAX_PAGE_ROW_BYTES)
        with self.assertRaisesRegex(P.UnsafeProvenance, "single_row_byte_bound"):
            self.pager.page({})
        self.write(self.old, 1)
        with mock.patch.object(P, "MAX_TOTAL_METADATA_BYTES", 1):
            with self.assertRaisesRegex(P.UnsafeProvenance, "source_byte_bound"):
                self.pager.page({})
        self.write(self.new, 2)
        with mock.patch.object(P, "MAX_JOB_ROWS", 1):
            with self.assertRaisesRegex(P.UnsafeProvenance, "bound"):
                self.pager.page({})

    def test_complete_mcp_result_and_escaping_count_toward_wire_budget(self):
        for number in range(1, 9):
            self.write(self.old, number, launch_state='"\\\n' * 3000)
        cursor, found = None, []
        while True:
            page = self.pager.page({} if cursor is None else {"cursor": cursor})
            wire = {"jsonrpc": "2.0", "id": "x" * 128, "result": {
                "content": [{"type": "text", "text": P.canonical(page).decode("utf-8")}],
                "isError": False}}
            self.assertLessEqual(len(P.canonical(wire)), 64 * 1024)
            found.extend(row["id"] for row in page["jobs"])
            if not page["has_more"]:
                break
            cursor = page["next_cursor"]
        self.assertEqual(len(found), 8)
        self.assertEqual(len(set(found)), 8)

    def test_record_mutation_during_scan_refuses_whole_page(self):
        first = self.write(self.old, 1)
        self.write(self.new, 2)
        original = P._private_record
        def race(base, name, budget):
            result = original(base, name, budget)
            if name == "1a14-2-1.json":
                first.write_text(first.read_text() + " ")
            return result
        with mock.patch.object(P, "_private_record", side_effect=race):
            with self.assertRaisesRegex(P.UnsafeProvenance, "record_changed"):
                self.pager.page({})

    def test_large_real_two_owner_registry_fully_discoverable(self):
        # 6000 records exceed the older all-host pretty-JSON inventory budget.
        # Job creation continues while a frozen observation is fully enumerated.
        expected = set()
        for number in range(6000):
            root = self.old if number % 2 else self.new
            path = self.write(root, number, host=sorted(P.HOSTS)[number % len(P.HOSTS)])
            expected.add(path.stem)
        arguments, found, snapshots = {}, [], set()
        for iteration in range(48):
            page = self.pager.page(arguments)
            self.assertEqual(page["total"], 6000)
            self.assertLessEqual(page["returned"], 128)
            self.assertLessEqual(len(P.canonical(page["jobs"])), 64 * 1024)
            snapshots.add(page["snapshot_id"])
            found.extend(row["id"] for row in page["jobs"])
            if not page["has_more"]:
                self.assertTrue(page["inventory_complete"])
                break
            self.assertFalse(page["inventory_complete"])
            arguments = {"cursor": page["next_cursor"]}
            self.write(self.new, 7000 + iteration)
        else:
            self.fail("bounded complete inventory never reached EOF")
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(len(found), len(set(found)))
        self.assertEqual(set(found), expected)


    def test_first_page_reobserves_after_one_new_job_membership_race(self):
        self.write(self.old, 1)
        self.write(self.new, 2)
        real_collect = self.pager._collect
        attempts = []
        def once(host):
            attempts.append(host)
            if len(attempts) == 1:
                # A V4 job arrived during an earlier scan: no truncated page
                # may escape, and the final scan must contain that job.
                self.write(self.old, 3)
                raise P.UnsafeProvenance("registry_page_membership_changed")
            return real_collect(host)
        with mock.patch.object(self.pager, "_collect", side_effect=once):
            first = self.pager.page({"limit": 1})
        self.assertEqual(len(attempts), 2)
        self.assertEqual(first["total"], 3)
        self.assertEqual(first["returned"], 1)
        ids = {first["jobs"][0]["id"]}
        while first["has_more"]:
            first = self.pager.page({"cursor": first["next_cursor"]})
            ids.update(x["id"] for x in first["jobs"])
        self.assertEqual(ids, {"1a14-1-1", "1a14-2-1", "1a14-3-1"})

    def test_perpetual_membership_race_has_strict_bounded_refusal(self):
        self.write(self.old, 1)
        with mock.patch.object(
            self.pager, "_collect",
            side_effect=P.UnsafeProvenance("registry_page_membership_changed"),
        ) as scan:
            with self.assertRaisesRegex(P.UnsafeProvenance, "membership_changed"):
                self.pager.page({})
        self.assertEqual(scan.call_count, P.MAX_INITIAL_MEMBERSHIP_SCANS)
        self.assertEqual(self.pager._snapshots, [])

    def test_changed_original_record_never_gets_automatic_rescan(self):
        self.write(self.old, 1)
        with mock.patch.object(
            self.pager, "_collect",
            side_effect=P.UnsafeProvenance("registry_page_record_changed"),
        ) as scan:
            with self.assertRaisesRegex(P.UnsafeProvenance, "record_changed"):
                self.pager.page({})
        self.assertEqual(scan.call_count, 1)
        self.assertEqual(self.pager._snapshots, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
