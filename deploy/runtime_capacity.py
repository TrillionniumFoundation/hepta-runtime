"""Read-only deterministic capacity planning for configured Hepta hosts.

This module never starts, migrates, cancels, or reserves real processes.
The caller must revalidate resources and task ownership before dispatch.
"""
import hashlib
import json

MAX_HOSTS = 64
MAX_TASKS = 4096
MAX_AGE_MS = 30_000
AGE_STEP_MS = 120_000

HOST_FIELDS = frozenset({
    "name", "reachable", "observed_ms", "cpu_free_milli", "mem_free_mib",
    "slots_free", "slots_reserved", "temp_c", "max_temp_c", "gpu_mem_free_mib",
    "gpu_busy_percent", "tags",
})
TASK_FIELDS = frozenset({
    "id", "cpu_milli", "mem_mib", "gpu_mem_mib", "priority", "queued_ms",
    "allowed_hosts", "excluded_hosts", "required_tags", "data_local_hosts",
})


class CapacityError(ValueError):
    """Malformed or incomplete planning input; no partial plan is returned."""


def _integer(value, name, low=0, high=10**12):
    if type(value) is not int or not low <= value <= high:
        raise CapacityError(f"{name}: expected integer in [{low},{high}]")
    return value


def _names(value, name, allow_empty=True):
    if type(value) is not list or (not allow_empty and not value):
        raise CapacityError(f"{name}: expected nonempty list" if not allow_empty
                            else f"{name}: expected list")
    if any(type(x) is not str or not x or len(x) > 128 for x in value):
        raise CapacityError(f"{name}: invalid element")
    if len(set(value)) != len(value):
        raise CapacityError(f"{name}: duplicate element")
    return value


def _shape(value, fields, name):
    if type(value) is not dict or set(value) - fields:
        raise CapacityError(f"{name}: unknown fields or wrong type")


def plan(hosts, tasks, now_ms, configured_hosts, inventory_complete):
    """Return an effect-free plan; all host names are controlled aliases."""
    _integer(now_ms, "now_ms", 1)
    if inventory_complete is not True:
        raise CapacityError("configured host inventory is incomplete")
    allowed = set(_names(configured_hosts, "configured_hosts", False))
    if type(hosts) is not list or not 0 < len(hosts) <= MAX_HOSTS:
        raise CapacityError("hosts: invalid count")
    if type(tasks) is not list or len(tasks) > MAX_TASKS:
        raise CapacityError("tasks: invalid count")
    pool = {}
    for h in hosts:
        _shape(h, HOST_FIELDS, "host")
        required = ("name", "reachable", "observed_ms", "cpu_free_milli",
                    "mem_free_mib", "slots_free", "slots_reserved",
                    "temp_c", "max_temp_c", "tags")
        if any(k not in h for k in required):
            raise CapacityError("host: missing required telemetry")
        name = h["name"]
        if type(name) is not str or name not in allowed or name in pool:
            raise CapacityError("host: unknown or duplicate configured alias")
        if type(h["reachable"]) is not bool:
            raise CapacityError("host: reachable must be bool")
        for key in ("observed_ms", "cpu_free_milli", "mem_free_mib",
                    "slots_free", "slots_reserved", "temp_c", "max_temp_c"):
            _integer(h[key], f"host.{key}")
        if h["slots_reserved"] > h["slots_free"]:
            raise CapacityError("host: reserved slots exceed availability")
        for key in ("gpu_mem_free_mib", "gpu_busy_percent"):
            if key in h and h[key] is not None:
                _integer(h[key], f"host.{key}", 0, 100 if "percent" in key else 10**12)
        pool[name] = dict(h)
        pool[name]["tags"] = set(_names(h["tags"], "host.tags"))
        pool[name]["slots_free"] -= h["slots_reserved"]

    queued = []
    ids = set()
    for i, t in enumerate(tasks):
        _shape(t, TASK_FIELDS, "task")
        required = ("id", "cpu_milli", "mem_mib", "gpu_mem_mib", "priority",
                    "queued_ms", "allowed_hosts")
        if any(k not in t for k in required):
            raise CapacityError("task: missing required fields")
        ident = t["id"]
        if type(ident) is not str or not ident or len(ident) > 128 or ident in ids:
            raise CapacityError("task: invalid or duplicate identity")
        ids.add(ident)
        for key in ("cpu_milli", "mem_mib", "gpu_mem_mib", "priority", "queued_ms"):
            _integer(t[key], f"task.{key}", 0, 9 if key == "priority" else 10**12)
        if t["queued_ms"] > now_ms:
            raise CapacityError("task: future queue timestamp")
        for key in ("allowed_hosts", "excluded_hosts", "required_tags",
                    "data_local_hosts"):
            _names(t.get(key, []), f"task.{key}", key != "allowed_hosts")
        if any(n not in allowed for n in t["allowed_hosts"] +
               t.get("excluded_hosts", []) + t.get("data_local_hosts", [])):
            raise CapacityError("task: unconfigured host alias")
        if not t["cpu_milli"] and not t["mem_mib"] and not t["gpu_mem_mib"]:
            raise CapacityError("task: no declared resource requirement")
        age = min(9, (now_ms - t["queued_ms"]) // AGE_STEP_MS)
        queued.append((-(min(9, t["priority"] + age)), t["queued_ms"], i, t))
    queued.sort(key=lambda item: (item[0], item[1], item[2]))

    admitted, deferred = [], []
    for _, _, _, t in queued:
        permitted = set(t["allowed_hosts"]) - set(t.get("excluded_hosts", []))
        eligible = [h for name, h in pool.items()
                    if name in permitted and
                    set(t.get("required_tags", [])).issubset(h["tags"])]
        fresh = [h for h in eligible if h["reachable"] and
                 0 <= now_ms - h["observed_ms"] <= MAX_AGE_MS]
        candidates = []
        for h in fresh:
            if h["temp_c"] >= h["max_temp_c"] or h["slots_free"] <= 0:
                continue
            if h["cpu_free_milli"] < t["cpu_milli"] or h["mem_free_mib"] < t["mem_mib"]:
                continue
            if t["gpu_mem_mib"]:
                busy, free = h.get("gpu_busy_percent"), h.get("gpu_mem_free_mib")
                if busy is None or free is None or busy >= 95 or free < t["gpu_mem_mib"]:
                    continue
            locality = 0 if h["name"] in t.get("data_local_hosts", []) else 1
            candidates.append(((locality, -h["slots_free"], h["temp_c"], h["name"]), h))
        if not candidates:
            reason = ("no_permitted_host" if not eligible else
                      "telemetry_unavailable" if not fresh else "capacity_exhausted")
            deferred.append({"id": t["id"], "reason": reason})
            continue
        h = min(candidates, key=lambda x: x[0])[1]
        h["cpu_free_milli"] -= t["cpu_milli"]
        h["mem_free_mib"] -= t["mem_mib"]
        h["slots_free"] -= 1
        if t["gpu_mem_mib"]:
            h["gpu_mem_free_mib"] -= t["gpu_mem_mib"]
        admitted.append({"id": t["id"], "host": h["name"]})
    result = {"schema": "hepta-capacity-shadow-v1", "admitted": admitted,
              "deferred": deferred, "side_effects": False}
    canonical = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["plan_sha256"] = hashlib.sha256(canonical).hexdigest()
    return result
