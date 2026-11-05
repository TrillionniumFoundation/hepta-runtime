#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Mac-owned temporary SSH agent and one foreground R18 recovery connection.

Configured key material stays on the Mac. No key bytes, full environment or SSH
configuration dump is retained. Only this invocation's agent and foreground SSH
child are signalled. Every failure is retained and no connection is retried.
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
import sys
import tempfile
import time
import traceback

sys.dont_write_bytecode = True


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-script", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=int, default=3600)
    args = parser.parse_args()
    if sys.platform != "darwin" or os.geteuid() == 0:
        raise RuntimeError("the agent holder must run as the existing non-root Mac operator")
    if not 60 <= args.timeout_seconds <= 7200:
        raise ValueError("foreground timeout must be bounded from 60 to 7200 seconds")
    source = args.remote_script.read_bytes()
    source_sha = hashlib.sha256(source).hexdigest()
    output = args.out.absolute()
    if output.resolve() != output:
        raise ValueError("Mac evidence output must be a fresh direct directory")
    output.mkdir(mode=0o700)
    (output / "remote-script.py").write_bytes(source)
    report = {"schema": "hepta-x230-r18-held-agent-recovery/v1", "started_utc": utc(),
              "holder_script_sha256": sha(Path(__file__)), "remote_script_sha256": source_sha,
              "timeout_seconds": args.timeout_seconds, "automatic_ssh_retries": 0,
              "services_modified": False, "remote_returncode": None, "passed": False,
              "identity_loads": [], "key_bytes_retained": False, "complete_environment_retained": False,
              "ssh_configuration_dump_retained": False}

    def evidence(path):
        return {"file": path.name, "bytes": path.stat().st_size, "sha256": sha(path)}

    def save():
        temporary = output / "report.next"
        with temporary.open("x") as stream:
            json.dump(report, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output / "report.json")

    try:
        save()
        plist_path = Path("/Users/qianqi/Library/LaunchAgents/org.trillionnium.hepta.runtime-controller.plist")
        arguments = plistlib.loads(plist_path.read_bytes())["ProgramArguments"]
        config_path = Path(arguments[arguments.index("--runtime-config") + 1])
        hosts = json.loads(config_path.read_bytes())["hosts"]
        targets = ["x230-ts", "main"]
        names = {"ai395", "desktop", "mac", "main", "pocket4", "rog", "x230"}
        if isinstance(hosts, dict):
            targets.extend(hosts[name]["ssh_target"] for name in sorted(names) if name in hosts)
        else:
            targets.extend(item["ssh_target"] for item in hosts if item.get("name") in names)
        keys = []
        discovery = []
        for index, target in enumerate(dict.fromkeys(targets)):
            # stdout is used only to select configured IdentityFile paths, never
            # persisted as a raw config. Any error stderr is retained verbatim.
            result = subprocess.run(["/usr/bin/ssh", "-G", target], capture_output=True, timeout=10)
            stderr = output / f"identity-discovery-{index:02d}.stderr"
            stderr.write_bytes(result.stderr)
            discovery.append({"index": index, "returncode": result.returncode, "stderr": evidence(stderr)})
            if result.returncode != 0:
                raise RuntimeError("configured SSH identity discovery failed; see retained stderr")
            for line in result.stdout.decode().splitlines():
                name, _, value = line.partition(" ")
                if name == "identityfile" and value != "none":
                    path = Path(os.path.expanduser(value.replace("%d", str(Path.home()))))
                    if path.is_file() and str(path) not in keys:
                        keys.append(str(path))
        report["identity_discovery"] = discovery
        report["configured_target_count"] = len(set(targets))
        report["configured_identity_count"] = len(keys)
        if not keys:
            raise RuntimeError("existing SSH configuration has no usable local identity files")
        save()
        with tempfile.TemporaryDirectory(prefix="hr18a-", dir="/tmp") as temporary:
            socket = Path(temporary) / "agent.sock"
            with (output / "owned-agent.stderr").open("xb") as agent_stderr:
                agent = subprocess.Popen(["/usr/bin/ssh-agent", "-D", "-a", str(socket)],
                                         stdout=subprocess.DEVNULL, stderr=agent_stderr)
                report["owned_agent_pid"] = agent.pid
                try:
                    for _ in range(100):
                        if socket.exists():
                            break
                        if agent.poll() is not None:
                            raise RuntimeError("owned SSH agent exited before creating its socket")
                        time.sleep(.02)
                    identity = socket.lstat()
                    if not stat.S_ISSOCK(identity.st_mode) or identity.st_uid != os.geteuid():
                        raise RuntimeError("owned SSH agent socket identity differs")
                    environment = dict(os.environ, SSH_AUTH_SOCK=str(socket), SSH_ASKPASS_REQUIRE="never")
                    for index, key in enumerate(keys):
                        row = {"index": index, "ttl_seconds": args.timeout_seconds + 120,
                               "start_monotonic_ns": time.monotonic_ns(), "returncode": None}
                        report["identity_loads"].append(row)
                        with (output / f"identity-load-{index:02d}.stdout").open("xb") as stdout, \
                                (output / f"identity-load-{index:02d}.stderr").open("xb") as stderr:
                            loaded = subprocess.run(["/usr/bin/ssh-add", "-q", "-t", str(args.timeout_seconds + 120), key],
                                                    env=environment, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, timeout=10)
                        row["end_monotonic_ns"] = time.monotonic_ns()
                        row["returncode"] = loaded.returncode
                        for stream in ("stdout", "stderr"):
                            row[stream] = evidence(output / f"identity-load-{index:02d}.{stream}")
                        save()
                        if loaded.returncode != 0:
                            raise RuntimeError("a configured identity failed noninteractive loading; original stderr retained")
                    command = ["/usr/bin/ssh", "-A", "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                               "-o", "StrictHostKeyChecking=yes", "-o", "ControlMaster=no", "-o", "ControlPath=none",
                               "-o", "ControlPersist=no", "x230-ts", "/usr/bin/python3", "-B", "-",
                               "--launcher-sha256", source_sha]
                    report["foreground_argv"] = command
                    report["foreground_start_monotonic_ns"] = time.monotonic_ns()
                    save()
                    print(json.dumps({"phase": "owned_agent_ready", "identity_count": len(keys), "remote_script_sha256": source_sha}), flush=True)
                    with (output / "forwarded.stdout").open("xb") as stdout, (output / "forwarded.stderr").open("xb") as stderr:
                        connection = subprocess.Popen(command, stdin=subprocess.PIPE, env=environment, stdout=stdout, stderr=stderr)
                        report["foreground_pid"] = connection.pid
                        try:
                            connection.communicate(input=source, timeout=args.timeout_seconds)
                        except subprocess.TimeoutExpired:
                            report["foreground_timed_out"] = True
                            report["remote_completion_unknown"] = True
                            connection.kill()  # Only the exact foreground SSH child owned here.
                            connection.communicate(timeout=10)
                            raise
                        finally:
                            report["remote_returncode"] = connection.returncode
                            report["foreground_end_monotonic_ns"] = time.monotonic_ns()
                            report["foreground_seconds"] = (report["foreground_end_monotonic_ns"] - report["foreground_start_monotonic_ns"]) / 1e9
                finally:
                    if agent.poll() is None:
                        agent.terminate()
                    try:
                        agent.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        agent.kill()
                        agent.wait(timeout=5)
                    report["owned_agent_reaped"] = agent.poll() is not None
                    report["owned_agent_returncode"] = agent.returncode
        report["passed"] = report["remote_returncode"] == 0
        if not report["passed"]:
            report["error"] = {"type": "RemoteCampaignFailed", "reason": "remote campaign exited nonzero; see unmodified forwarded stdout/stderr"}
    except BaseException as error:
        report["error"] = {"type": type(error).__name__, "reason": str(error)}
        (output / "holder.error.txt").write_text(traceback.format_exc())
    finally:
        report["finished_utc"] = utc()
        report["log_files"] = [evidence(path) for path in sorted(output.iterdir()) if path.is_file()
                               and path.name not in {"report.json", "report.next"}]
        report["passed"] = report["passed"] and "error" not in report and report.get("owned_agent_reaped") is True
        save()
        print(json.dumps({"passed": report["passed"], "remote_returncode": report["remote_returncode"],
                          "owned_agent_reaped": report.get("owned_agent_reaped"), "report": str(output / "report.json")}), flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
