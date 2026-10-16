"""Adversarial regression for side-effect-free Hepta capacity planning."""
import copy
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "deploy"))
from runtime_capacity import CapacityError, plan

NOW = 1_000_000_000
ALIASES = ["ai395", "rog", "mac", "main", "pocket4", "x230"]


def host(name="ai395", **override):
    h = dict(name=name, reachable=True, observed_ms=NOW,
             cpu_free_milli=8000, mem_free_mib=32768,
             slots_free=4, slots_reserved=0,
             temp_c=45, max_temp_c=85, gpu_mem_free_mib=24000,
             gpu_busy_percent=0, tags=["gpu", "linux"])
    h.update(override)
    return h


def task(ident="job-1", **override):
    t = dict(id=ident, cpu_milli=1000, mem_mib=1024,
             gpu_mem_mib=4096, priority=5, queued_ms=NOW,
             allowed_hosts=["ai395", "rog"])
    t.update(override)
    return t


def run(hosts=None, tasks=None, inventory_complete=True):
    return plan([host()] if hosts is None else hosts,
                [task()] if tasks is None else tasks,
                NOW, ALIASES, inventory_complete)


class CapacityTests(unittest.TestCase):
    def test_gpu_task_allocates_known_host(self):
        self.assertEqual(run()["admitted"], [{"id": "job-1", "host": "ai395"}])

    def test_busy_rog_never_receives_gpu_work(self):
        value = run([host("rog", gpu_busy_percent=100), host()])
        self.assertEqual(value["admitted"][0]["host"], "ai395")

    def test_two_busy_gpus_defer(self):
        value = run([host("rog", gpu_busy_percent=100),
                     host(gpu_busy_percent=100)])
        self.assertEqual(value["deferred"][0]["reason"], "capacity_exhausted")

    def test_hot_machine_skipped(self):
        value = run([host("rog", temp_c=90), host()])
        self.assertEqual(value["admitted"][0]["host"], "ai395")

    def test_stale_telemetry_rejected(self):
        value = run([host(observed_ms=NOW - 30001)])
        self.assertEqual(value["deferred"][0]["reason"], "telemetry_unavailable")

    def test_future_clock_rejected(self):
        value = run([host(observed_ms=NOW + 1)])
        self.assertEqual(value["deferred"][0]["reason"], "telemetry_unavailable")

    def test_unknown_host_rejected(self):
        with self.assertRaises(CapacityError):
            run([host("unknown")])

    def test_unknown_task_allowlist_rejected(self):
        with self.assertRaises(CapacityError):
            run(tasks=[task(allowed_hosts=["unknown"])])

    def test_duplicate_hosts_rejected(self):
        with self.assertRaises(CapacityError):
            run([host(), host()])

    def test_duplicate_jobs_rejected(self):
        with self.assertRaises(CapacityError):
            run(tasks=[task(), task()])

    def test_host_affinity_enforced(self):
        t = task(allowed_hosts=["pocket4"], gpu_mem_mib=0)
        out = run([host("ai395"), host("pocket4", tags=["linux"])], [t])
        self.assertEqual(out["admitted"][0]["host"], "pocket4")

    def test_no_migration_across_disallowed_hosts(self):
        t = task(allowed_hosts=["pocket4"])
        out = run([host("ai395")], [t])
        self.assertEqual(out["admitted"], [])
        self.assertEqual(out["deferred"][0]["reason"], "no_permitted_host")

    def test_explicit_exclusion_overrides_allowlist(self):
        t = task(excluded_hosts=["ai395"])
        out = run([host("ai395"), host("rog")], [t])
        self.assertEqual(out["admitted"][0]["host"], "rog")

    def test_cpu_only_without_gpu_telemetry(self):
        t = task(allowed_hosts=["mac"], gpu_mem_mib=0)
        out = run([host("mac", gpu_busy_percent=None,
                        gpu_mem_free_mib=None)], [t])
        self.assertEqual(out["admitted"][0]["host"], "mac")

    def test_gpu_requires_both_memory_and_busy_evidence(self):
        for override in ({"gpu_busy_percent": None},
                         {"gpu_mem_free_mib": None},
                         {"gpu_mem_free_mib": 100}):
            self.assertEqual(run([host(**override)])["admitted"], [])

    def test_slot_reservation_is_respected(self):
        h = host(slots_free=2, slots_reserved=1)
        out = run([h], [task("a"), task("b")])
        self.assertEqual(len(out["admitted"]), 1)
        self.assertEqual(len(out["deferred"]), 1)

    def test_cpu_budget_and_mem_budget_are_reserved_once(self):
        out = run([host(cpu_free_milli=1500, mem_free_mib=1800)],
                  [task("a", gpu_mem_mib=0), task("b", gpu_mem_mib=0)])
        self.assertEqual([x["id"] for x in out["admitted"]], ["a"])
        self.assertEqual(out["deferred"][0]["id"], "b")

    def test_gpu_memory_is_reserved_once(self):
        out = run([host(gpu_mem_free_mib=7000)],
                  [task("a"), task("b")])
        self.assertEqual([x["id"] for x in out["admitted"]], ["a"])

    def test_priority_precedes_input_order(self):
        out = run([host(slots_free=1)],
                  [task("low", priority=0), task("high", priority=9)])
        self.assertEqual(out["admitted"][0]["id"], "high")

    def test_wait_aging_prevents_same_priority_starvation(self):
        older = task("older", priority=5, queued_ms=NOW - 360000)
        newer = task("newer", priority=6)
        out = run([host(slots_free=1)], [newer, older])
        self.assertEqual(out["admitted"][0]["id"], "older")

    def test_low_priority_eventually_competes_without_starvation(self):
        older = task("very-old", priority=0, queued_ms=NOW - 20 * 60 * 1000)
        newer = task("new-high", priority=9)
        out = run([host(slots_free=1)], [newer, older])
        self.assertEqual(out["admitted"][0]["id"], "very-old")

    def test_locality_preference_over_empty_slots(self):
        h = [host("rog", slots_free=8), host(slots_free=1)]
        t = task(data_local_hosts=["ai395"])
        self.assertEqual(run(h, [t])["admitted"][0]["host"], "ai395")

    def test_unknown_critical_fields_fail_closed(self):
        with self.assertRaises(CapacityError):
            run(tasks=[task(untrusted_effect="yes")])
        with self.assertRaises(CapacityError):
            run([host(execute_as_root=True)])

    def test_bool_not_accepted_for_integer(self):
        with self.assertRaises(CapacityError):
            run(tasks=[task(cpu_milli=True)])

    def test_negative_resource_rejected(self):
        with self.assertRaises(CapacityError):
            run(tasks=[task(gpu_mem_mib=-1)])

    def test_inventory_incomplete_refused(self):
        with self.assertRaises(CapacityError):
            run(inventory_complete=False)

    def test_stable_digest_no_mutation(self):
        hosts = [host(), host("rog")]
        tasks = [task("a"), task("b")]
        original_hosts, original_tasks = copy.deepcopy(hosts), copy.deepcopy(tasks)
        first, second = run(hosts, tasks), run(hosts, tasks)
        self.assertEqual(first, second)
        self.assertEqual(hosts, original_hosts)
        self.assertEqual(tasks, original_tasks)
        self.assertFalse(first["side_effects"])
        self.assertEqual(len(first["plan_sha256"]), 64)

    def test_bounded_large_batch(self):
        h = [host(name, slots_free=512, cpu_free_milli=1_000_000,
                  mem_free_mib=1_000_000, gpu_mem_free_mib=1_000_000)
             for name in ALIASES]
        t = [task(str(i), allowed_hosts=ALIASES, gpu_mem_mib=0)
             for i in range(2048)]
        out = run(h, t)
        self.assertEqual(len(out["admitted"]), 2048)
        self.assertEqual(len(set(x["id"] for x in out["admitted"])), 2048)

    def test_bad_telemetry_type_refused(self):
        with self.assertRaises(CapacityError):
            run([host(temp_c=45.5)])


if __name__ == "__main__":
    unittest.main()
