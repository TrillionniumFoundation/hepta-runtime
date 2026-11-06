#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""One read-only SSH challenge using the frozen D1 profile and current forwarded agent."""
import argparse, hashlib, json, os, re, stat, subprocess, sys
from pathlib import Path

PROFILE = Path("/home/qian/hepta-runtime-phase-cost-20261106-d1/c1-observation-01/profile/profile.json")
PROFILE_SHA = "ed680dc1613e4aea4de99336d21009c73e71554694edbe23f9dc3a433b586e89"
ALIAS = "hepta-native-test-v7-pocket4"
CHALLENGE = b"HEPTA_R36_POCKET4_READONLY_OK\n"

def checked(path, expected):
    path = Path(path)
    if not path.is_absolute(): raise ValueError("nonabsolute input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= 2**21:
            raise ValueError("input type or size")
        raw = stream.read(2**21 + 1)
        after = os.fstat(stream.fileno())
    stamp = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    if stamp(before) != stamp(after) or stamp(after) != stamp(path.lstat()):
        raise ValueError("input changed")
    if len(raw) != before.st_size or hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("input SHA mismatch")
    return raw

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--launcher-sha256", required=True)
args = parser.parse_args()
report = {"schema": "hepta-pocket4-readonly-ssh-probe/v1", "alias": ALIAS,
          "attempts": 0, "timeout_seconds": 10, "cleanup_timeout_seconds": 2,
          "timed_out": False, "passed": False, "phase": "profile"}
child = None
try:
    if not re.fullmatch("[0-9a-f]{64}", args.launcher_sha256): raise ValueError("launcher hash")
    report["launcher_sha256_from_holder"] = args.launcher_sha256
    profile = json.loads(checked(PROFILE, PROFILE_SHA))
    if profile["schema"] != "hepta-observation-ssh-pool/v1": raise ValueError("profile schema")
    for name in ("ssh_config", "known_hosts"):
        report["phase"] = name
        checked(profile[name], profile[name + "_sha256"])
    report["phase"] = "ssh_and_shell"
    checked("/usr/bin/ssh", profile["ssh_sha256"])
    checked(Path("/bin/sh").resolve(strict=True), profile["shell_sha256"])
    report["frozen_input_hashes_verified_before"] = True
    report["phase"] = "forwarded_agent"
    agent = os.environ["SSH_AUTH_SOCK"]
    if not Path(agent).is_absolute() or not stat.S_ISSOCK(os.stat(agent).st_mode):
        raise ValueError("forwarded agent unavailable")
    options = [
        ("BatchMode", "yes"), ("ConnectTimeout", "8"), ("ConnectionAttempts", "1"),
        ("StrictHostKeyChecking", "yes"), ("ForwardAgent", "no"), ("ForwardX11", "no"),
        ("ClearAllForwardings", "yes"), ("PermitLocalCommand", "no"), ("RemoteCommand", "none"),
        ("ForkAfterAuthentication", "no"), ("ControlPersist", "no"), ("ProxyJump", "none"),
        ("ProxyUseFdpass", "no"), ("IdentityFile", "none"), ("CertificateFile", "none"),
        ("PreferredAuthentications", "publickey"), ("PubkeyAuthentication", "yes"),
        ("PasswordAuthentication", "no"), ("KbdInteractiveAuthentication", "no"),
        ("GSSAPIAuthentication", "no"), ("HostbasedAuthentication", "no"), ("PKCS11Provider", "none"),
        ("SecurityKeyProvider", "internal"), ("AddKeysToAgent", "no"), ("UpdateHostKeys", "no"),
        ("KnownHostsCommand", "none"), ("VerifyHostKeyDNS", "no"), ("CheckHostIP", "no"),
        ("CanonicalizeHostname", "no"), ("GlobalKnownHostsFile", "/dev/null"),
        ("IdentityAgent", agent), ("UserKnownHostsFile", profile["known_hosts"]),
        ("ControlPath", "none"), ("ControlMaster", "no"), ("ProxyCommand", "none")]
    command = ["/usr/bin/ssh", "-F", profile["ssh_config"], "-T"]
    for key, value in options: command.extend(["-o", key + "=" + value])
    command.extend(["--", ALIAS, "printf '%s\\n' 'HEPTA_R36_POCKET4_READONLY_OK'"])
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "SHELL": "/bin/sh", "SSH_AUTH_SOCK": agent}
    report["phase"] = "ssh"; report["attempts"] = 1
    child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, env=environment, start_new_session=True)
    try: stdout, stderr = child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        report["timed_out"] = True; child.kill()
        stdout, stderr = child.communicate(timeout=2)
    low = stderr.decode("utf-8", "replace").lower()
    needles = ("timed out", "no route to host", "network is unreachable", "connection refused",
               "permission denied", "host key verification failed", "remote host identification has changed",
               "could not resolve hostname", "agent refused operation", "connection reset", "connection closed")
    report.update(exit_code=child.returncode, challenge_matches=stdout == CHALLENGE,
                  stdout_bytes=len(stdout), stderr_bytes=len(stderr), stderr_sha256=hashlib.sha256(stderr).hexdigest(),
                  redacted_stderr_reasons=[x for x in needles if x in low] or (["unclassified_redacted"] if stderr else []))
    report["passed"] = child.returncode == 0 and stdout == CHALLENGE and not report["timed_out"]
except Exception as error:
    report.update(error_type=type(error).__name__, errno=getattr(error, "errno", None))
finally:
    if child is not None and child.poll() is None:
        child.kill()
        try: child.wait(timeout=2)
        except subprocess.TimeoutExpired: report["cleanup_unknown"] = True
    report["owned_child_reaped"] = child.returncode is not None if child is not None else None
    print(json.dumps(report, sort_keys=True), flush=True)
sys.exit(0 if report["passed"] else 1)
