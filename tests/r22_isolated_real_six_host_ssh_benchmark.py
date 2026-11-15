#!/usr/bin/env python3
"""R22 isolated real-host SSH A/B: disposable target states and /usr/bin/true only."""
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
from r22_isolated_six_alias_ssh_benchmark import run_once

HOSTS = ("main", "pocket4", "rog", "mac", "x230", "ai395")
PREFIX = "hepta-r22-physical-ssh-test-"

def installed_hosts():
    pid = int(subprocess.check_output(["systemctl", "--user", "show",
             "hepta-runtime-operator.service", "--value", "--property=MainPID"],
             text=True, timeout=6).strip())
    if pid <= 1:
        raise RuntimeError("actual operator unit missing")
    argv = [part.decode() for part in Path(f"/proc/{pid}/cmdline").read_bytes()
            .split(b"\0") if part]
    try:
        config_path = argv[argv.index("--runtime-config") + 1]
    except (ValueError, IndexError) as error:
        raise RuntimeError("operator runtime configuration path unavailable") from error
    data = json.loads(Path(config_path).read_text())
    hosts = data.get("hosts")
    if type(hosts) is not dict or not set(HOSTS).issubset(hosts):
        raise RuntimeError("configured six-host inventory unavailable")
    return hosts

def ssh_readonly_or_fixture(target, command, timeout=18):
    if not re.fullmatch(r"[A-Za-z0-9_.:@+-]{1,220}", target) or target.startswith("-"):
        raise RuntimeError("untrusted SSH configured alias")
    process = subprocess.run([
        "ssh", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
        "-o", "StrictHostKeyChecking=yes", "-o", "ForwardAgent=no",
        target, "python3 -c " + shlex.quote(command),
    ], capture_output=True, text=True, timeout=timeout, check=False)
    if process.returncode != 0:
        raise RuntimeError("configured host SSH fixture command failed")
    return process.stdout.strip()

def remote_make(target):
    code = (
        "import tempfile,os,json;"
        "p=os.path.realpath(tempfile.mkdtemp(prefix=" + repr(PREFIX) + "));"
        "os.chmod(p,0o700);"
        "print(json.dumps({'path':p,'owner':os.getuid()}))"
    )
    value = json.loads(ssh_readonly_or_fixture(target, code))
    path = value.get("path")
    if not isinstance(path, str) or not os.path.isabs(path) or not Path(path).name.startswith(PREFIX):
        raise RuntimeError("temporary remote root identity unavailable")
    return path

def remote_cleanup(target, path):
    code = (
        "import os,stat,shutil;"
        "p=" + repr(path) + ";"
        "q=os.path.realpath(p);"
        "s=os.lstat(p);"
        "assert q==p and os.path.basename(p).startswith(" + repr(PREFIX) + ");"
        "assert stat.S_ISDIR(s.st_mode) and s.st_uid==os.getuid() and not stat.S_ISLNK(s.st_mode);"
        "shutil.rmtree(p)"
    )
    ssh_readonly_or_fixture(target, code)

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--baseline", required=True, type=Path)
    p.add_argument("--candidate", required=True, type=Path)
    p.add_argument("--count", type=int, choices=(1, 6), default=1)
    p.add_argument("--seed-count", type=int, default=3000)
    p.add_argument("--reverse-order", action="store_true")
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    if not 0 <= args.seed_count <= 8000:
        p.error("seed count out of bounded range")
    args.out.mkdir(mode=0o700, parents=True, exist_ok=True)
    actual = installed_hosts()
    cases = [("baseline", args.baseline), ("candidate", args.candidate)]
    if args.reverse_order:
        cases.reverse()
    names = HOSTS[:args.count]
    reports = []
    for label, binary in cases:
        remote_roots = {}
        host_overrides = {}
        try:
            for name in names:
                original = actual[name]
                target = original["ssh_target"]
                platform = original["platform"]
                if platform not in ("linux", "macos"):
                    raise RuntimeError("unsupported platform")
                remote_path = remote_make(target)
                remote_roots[name] = remote_path
                host_overrides[name] = {
                    "ssh_target": target, "platform": platform,
                    "execution_mode": "operator",
                    "remote_state_dir": remote_path,
                    "allow_execute": True, "allow_pty": False,
                    "allow_write": False, "allow_job_network": True,
                    "allow_detached_fallback": bool(original.get(
                        "allow_detached_fallback", platform == "macos")),
                }
            result = run_once(binary, label, names, args.seed_count, args.out,
                              host_overrides=host_overrides)
            result["remote_roots_provisioned"] = len(remote_roots)
            result["remote_cleanup_complete"] = False
            if "failure" not in result:
                for name, path in remote_roots.items():
                    remote_cleanup(actual[name]["ssh_target"], path)
                result["remote_cleanup_complete"] = True
            (args.out / f"{label}-physical-result.json").write_text(
                json.dumps(result, sort_keys=True, indent=2))
            reports.append(result)
            if "failure" in result:
                break
        except Exception as error:
            report = {
                "label": label, "failure": type(error).__name__ + ": " + str(error)[:180],
                "remote_roots_provisioned": len(remote_roots),
                "remote_cleanup_complete": False,
                "production_routing_changed": False,
            }
            # Unknown/started jobs must be reconciled; never delete on uncertain outcome.
            (args.out / f"{label}-physical-error.json").write_text(
                json.dumps(report, sort_keys=True, indent=2))
            reports.append(report)
            break
    print(json.dumps(reports, indent=2))
    if len(reports) != 2 or any("failure" in r or not r.get("remote_cleanup_complete")
                               for r in reports):
        raise SystemExit(1)

if __name__ == "__main__":
    main()
