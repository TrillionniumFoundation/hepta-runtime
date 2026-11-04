#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Hold configured identities in an owned agent for one foreground X230 campaign.

Run on the existing Mac operator account. No key bytes or complete environments
are copied into evidence. The child agent and forwarded SSH session are owned
by this invocation; other agents, masters and services are never signalled.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-script", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    if not 60 <= args.timeout_seconds <= 7200:
        raise ValueError("campaign timeout must be bounded from 60 to 7200 seconds")
    source = args.remote_script.read_bytes()
    args.out.mkdir(mode=0o700)
    report = {
        "schema": "hepta-x230-held-agent-campaign/v1",
        "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "remote_script_sha256": hashlib.sha256(source).hexdigest(),
        "timeout_seconds": args.timeout_seconds,
        "automatic_ssh_retries": 0,
        "services_modified": False,
    }
    plist = plistlib.loads(Path(
        "/Users/qianqi/Library/LaunchAgents/org.trillionnium.hepta.runtime-controller.plist"
    ).read_bytes())
    arguments = plist["ProgramArguments"]
    cfg = json.loads(Path(arguments[arguments.index("--runtime-config") + 1]).read_text())
    hosts = cfg["hosts"]
    targets = ["x230-ts", "main"]
    names = {"ai395", "desktop", "mac", "main", "pocket4", "rog", "x230"}
    if isinstance(hosts, dict):
        targets.extend(hosts[name]["ssh_target"] for name in sorted(names) if name in hosts)
    else:
        targets.extend(item["ssh_target"] for item in hosts if item.get("name") in names)
    keys = []
    for target in dict.fromkeys(targets):
        result = subprocess.run(["/usr/bin/ssh", "-G", target], capture_output=True,
                                text=True, timeout=10, check=True)
        for line in result.stdout.splitlines():
            name, _, value = line.partition(" ")
            if name == "identityfile" and value != "none":
                key = Path(os.path.expanduser(value.replace("%d", str(Path.home()))))
                if key.is_file() and str(key) not in keys:
                    keys.append(str(key))
    if not keys:
        raise RuntimeError("existing SSH configuration has no usable local identity files")
    report["configured_target_count"] = len(set(targets))
    report["configured_identity_count"] = len(keys)
    try:
        with tempfile.TemporaryDirectory(prefix="hr16a-", dir="/tmp") as temporary:
            socket = Path(temporary) / "agent.sock"
            agent = subprocess.Popen(["/usr/bin/ssh-agent", "-D", "-a", str(socket)],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                for _ in range(100):
                    if socket.exists():
                        break
                    if agent.poll() is not None:
                        raise RuntimeError("owned SSH agent exited before creating its socket")
                    time.sleep(.02)
                identity = socket.lstat()
                if not stat.S_ISSOCK(identity.st_mode) or identity.st_uid != os.geteuid():
                    raise RuntimeError("owned agent socket identity differs")
                environment = dict(os.environ, SSH_AUTH_SOCK=str(socket), SSH_ASKPASS_REQUIRE="never")
                returns = []
                for key in keys:
                    result = subprocess.run(
                        ["/usr/bin/ssh-add", "-q", "-t", str(args.timeout_seconds + 120), key],
                        env=environment, stdin=subprocess.DEVNULL, capture_output=True, timeout=10)
                    returns.append(result.returncode)
                report["identity_load_returncodes"] = returns
                if not all(value == 0 for value in returns):
                    raise RuntimeError("a configured identity failed noninteractive loading")
                print(json.dumps({"phase": "owned_agent_ready", "identity_count": len(keys),
                                  "automatic_ssh_retries": 0}), flush=True)
                started_ns = time.monotonic_ns()
                with (args.out / "forwarded.stdout").open("xb") as stdout, \
                        (args.out / "forwarded.stderr").open("xb") as stderr:
                    result = subprocess.run(
                        ["/usr/bin/ssh", "-A", "-T", "-o", "BatchMode=yes", "-o",
                         "ConnectTimeout=10", "-o", "StrictHostKeyChecking=yes", "x230-ts",
                         "/usr/bin/python3", "-B", "-"],
                        input=source, env=environment, stdout=stdout, stderr=stderr,
                        timeout=args.timeout_seconds)
                report["remote_returncode"] = result.returncode
                report["foreground_seconds"] = (time.monotonic_ns() - started_ns) / 1e9
            finally:
                agent.terminate()
                try:
                    agent.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    agent.kill()
                    agent.wait(timeout=5)
                report["owned_agent_reaped"] = agent.poll() is not None
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)[:1000]}
    finally:
        report["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        for name in ("forwarded.stdout", "forwarded.stderr"):
            path = args.out / name
            if path.exists():
                raw = path.read_bytes()
                report[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
        report["passed"] = report.get("remote_returncode") == 0 and "error" not in report
        with (args.out / "report.json").open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
        print(json.dumps(report), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
