# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Bounded read-only service observations with explicit manager scope.

An exact unit name is not globally unique: the system and login-user managers
have independent namespaces. Never equate a failed probe with an absent unit.
"""
import json
import os
import stat
import subprocess
import sys
import time

PROPERTIES = (
    "LoadState", "ActiveState", "SubState", "UnitFileState", "Result",
    "MainPID", "ExecMainStatus", "Description", "InvocationID",
)
LOAD_STATES = {"stub", "loaded", "not-found", "bad-setting", "error", "merged", "masked"}
MAX_PROBE_SECONDS = 3.0
TOTAL_SECONDS = 15.0


def bounded_text(value, limit=512):
    return value.encode("utf-8", "replace")[:limit].decode("utf-8", "ignore")


def user_environment():
    """Address only the current login UID, never an inherited foreign bus."""
    env = os.environ.copy()
    root = "/run/user/" + str(os.getuid())
    info = os.lstat(root)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise OSError("current login runtime directory unavailable")
    env["XDG_RUNTIME_DIR"] = root
    env["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=" + root + "/bus"
    return env


def probe(name, scope, deadline):
    observation = {"scope": scope, "exit_code": None, "properties": {},
                   "stderr": "", "observation_complete": False,
                   "properties_truncated": [], "stderr_truncated": False}
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        observation["error"] = "budget_exhausted"
        return observation
    argv = ["systemctl"] + (["--user"] if scope == "user" else [])
    argv += ["show", "--no-pager", "--property=" + ",".join(PROPERTIES), "--", name]
    try:
        env = user_environment() if scope == "user" else None
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=min(MAX_PROBE_SECONDS, remaining), env=env)
        observation["exit_code"] = p.returncode
        observation["stderr"] = bounded_text(p.stderr).strip()
        observation["stderr_truncated"] = len(p.stderr.encode("utf-8", "replace")) > 512
        values = {}
        for line in p.stdout.splitlines():
            key, sep, value = line.partition("=")
            if sep and key in PROPERTIES:
                limit = 512 if key == "Description" else 128
                values[key] = bounded_text(value, limit)
                if len(value.encode("utf-8", "replace")) > limit:
                    observation["properties_truncated"].append(key)
        observation["properties"] = values
        observation["observation_complete"] = (
            p.returncode == 0 and values.get("LoadState") in LOAD_STATES
        )
        if not observation["observation_complete"]:
            observation["error"] = "manager_query_failed_or_incomplete"
    except subprocess.TimeoutExpired:
        observation["error"] = "manager_query_timeout"
    except (OSError, UnicodeError):
        observation["error"] = "manager_unavailable"
    return observation


def inspect_linux_service(name, deadline):
    observations = [probe(name, scope, deadline) for scope in ("system", "user")]
    present = [o for o in observations if o["observation_complete"]
               and o["properties"]["LoadState"] != "not-found"]
    complete = all(o["observation_complete"] for o in observations)
    result = {"name": name, "scope": None, "exit_code": None, "properties": {},
              "stderr": "", "observations": observations,
              "resolution_complete": complete}
    if len(present) == 1:
        selected = present[0]
        for field in ("scope", "exit_code", "properties", "stderr"):
            result[field] = selected[field]
        result["properties_truncated"] = selected.get("properties_truncated", [])
        result["stderr_truncated"] = selected.get("stderr_truncated", False)
        result["resolution"] = "unique" if complete else "present_other_scope_unknown"
    elif len(present) > 1:
        result["resolution"] = "ambiguous"
    elif complete:
        result.update(resolution="not_found", exit_code=0,
                      properties={"LoadState": "not-found"})
    else:
        result["resolution"] = "unknown"
    return result


def main():
    request = json.load(sys.stdin)
    deadline = time.monotonic() + TOTAL_SECONDS
    result = []
    if request["platform"] == "linux":
        result = [inspect_linux_service(name, deadline) for name in request["services"]]
    else:
        # Preserve the pre-existing launchd system-domain behavior. Do not claim
        # this observation covers the separate GUI/user launchd domains.
        for name in request["services"]:
            remaining = deadline - time.monotonic()
            row = {"name": name, "scope": "system", "scopes_checked": ["system"],
                   "resolution": "system_domain_only", "exit_code": None,
                   "stdout": "", "stderr": "", "observation_complete": False}
            if remaining <= 0:
                row["error"] = "budget_exhausted"
            else:
                try:
                    p = subprocess.run(["launchctl", "print", "system/" + name],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       text=True, timeout=min(MAX_PROBE_SECONDS, remaining))
                    row.update(exit_code=p.returncode, stdout=p.stdout[-65536:],
                               stderr=p.stderr[:2048].strip(), observation_complete=p.returncode == 0)
                except subprocess.TimeoutExpired:
                    row["error"] = "manager_query_timeout"
                except (OSError, UnicodeError):
                    row["error"] = "manager_unavailable"
            result.append(row)
    print(json.dumps({"services": result}, sort_keys=True))


if __name__ == "__main__":
    main()
