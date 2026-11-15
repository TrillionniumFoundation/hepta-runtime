"""Real Linux process regressions for the CI-only browser owner."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


HERE = Path(__file__).resolve().parent
CHROME = r'''
import ctypes, os, signal, sys, threading, time
from pathlib import Path
profile, ready, mode = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
child = os.fork()
if child:
    os._exit(0)
os.setsid()
if mode in ("ignore-term", "threaded-ignore-term"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
directory = profile / "Default"
directory.mkdir()
(directory / "still-writing").write_text(str(time.monotonic_ns()))
ready.with_suffix(".tmp").write_text(str(os.getpid()))
ready.with_suffix(".tmp").replace(ready)
def write_forever():
    while True:
        (directory / "still-writing").write_text(str(time.monotonic_ns()))
        time.sleep(0.005)
if mode == "threaded-ignore-term":
    threading.Thread(target=write_forever).start()
    libc = ctypes.CDLL(None)
    libc.pthread_exit.argtypes = [ctypes.c_void_p]
    libc.pthread_exit(None)
else:
    write_forever()
'''
PROBE = r'''
import sys, time
from pathlib import Path
ready, release, observed = map(Path, sys.argv[1:4])
status, leader = sys.argv[4:6]
deadline = time.monotonic() + 5
while not ready.exists() or not release.exists():
    if time.monotonic() >= deadline:
        raise RuntimeError("Fixture handshake timed out")
    time.sleep(0.005)
while True:
    state = Path(f"/proc/{leader}/stat").read_text().rsplit(")", 1)[1].split()[0]
    if state == "Z":
        break
    if time.monotonic() >= deadline:
        raise RuntimeError("Early-exited leader was not retained")
    time.sleep(0.005)
observed.write_text(state)
if status == "hang":
    time.sleep(60)
else:
    raise SystemExit(int(status))
'''
DRIVER = r'''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import rea_browser_session as session
config = json.loads(Path(sys.argv[2]).read_text())
if config["stale_snapshot"]:
    actual_children = session.OwnedProcesses.children
    injected = False
    def one_pre_adoption_snapshot(self):
        global injected
        children = actual_children(self)
        leaders = {process.pid for process in self.processes}
        roots = [(pid, state) for pid, state in children if pid in leaders]
        orphan_is_live = any(pid not in leaders and state not in ("Z", "X")
                             for pid, state in children)
        if not injected and len(roots) == 3 and orphan_is_live and all(state == "Z" for _, state in roots):
            # Emulate a procfs PID list sampled before reparenting, followed
            # by stat reads after the leaders died. The orphan is real.
            injected = True
            (Path(config["evidence"]) / "stale-snapshot-injected").write_text("once")
            return roots
        return children
    session.OwnedProcesses.children = one_pre_adoption_snapshot
if config["cleanup_failure"]:
    def refuse_removal(_path):
        raise PermissionError("injected profile removal failure")
    session.shutil.rmtree = refuse_removal
raise SystemExit(session.run_session(
    Path(config["profile"]), Path(config["evidence"]), config["chrome"],
    config["http"], config["probe"], term_seconds=0.15, kill_seconds=1.0))
'''
SENTINEL = r'''
import sys, time
from pathlib import Path
path = Path(sys.argv[1])
while True:
    path.write_text(str(time.monotonic_ns()))
    time.sleep(0.005)
'''


class BrowserSessionTests(unittest.TestCase):
    def wait_for(self, predicate, process):
        deadline = time.monotonic() + 5
        while not predicate():
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(f"Owner exited before handshake: {process.returncode}\n{stdout}\n{stderr}")
            if time.monotonic() >= deadline:
                self.fail("Fixture handshake timed out")
            time.sleep(0.005)

    def exercise(self, *, mode="ignore-term", status="0", cleanup_failure=False,
                 cancel=False, stale_snapshot=False):
        with tempfile.TemporaryDirectory(prefix="rea-browser-owner-") as root:
            root = Path(root)
            evidence, profile = root / "evidence", root / "profile"
            evidence.mkdir()
            ready, release, observed = root / "child-ready", root / "release", root / "probe-observed"
            heartbeat = root / "unrelated-heartbeat"
            config = {"profile": str(profile), "evidence": str(evidence),
                      "cleanup_failure": cleanup_failure,
                      "stale_snapshot": stale_snapshot,
                      "chrome": [sys.executable, "-c", CHROME, str(profile), str(ready), mode],
                      "http": [sys.executable, "-c", "import time; time.sleep(60)"],
                      "probe": [sys.executable, "-c", PROBE, str(ready), str(release),
                                str(observed), status]}
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config))
            # This sibling is deliberately outside the owner's child trees.
            sentinel = subprocess.Popen([sys.executable, "-c", SENTINEL, str(heartbeat)],
                                        start_new_session=True)
            owner = subprocess.Popen([sys.executable, "-B", "-c", DRIVER, str(HERE), str(config_path)],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                     start_new_session=True)
            child_fd = None
            try:
                self.wait_for(lambda: ready.exists() and heartbeat.exists(), owner)
                child_pid = int(ready.read_text())
                # A stable handle lets fixture failure cleanup avoid PID reuse.
                child_fd = os.pidfd_open(child_pid)
                before = heartbeat.read_text()
                self.assertTrue((profile / "Default" / "still-writing").exists())
                if mode == "threaded-ignore-term":
                    def leader_is_zombie():
                        return Path(f"/proc/{child_pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z"
                    self.wait_for(leader_is_zombie, owner)
                    written = (profile / "Default" / "still-writing").read_text()
                    self.wait_for(lambda: (profile / "Default" / "still-writing").read_text()
                                  not in ("", written), owner)
                release.write_text("ready")
                self.wait_for(observed.exists, owner)
                self.assertEqual(observed.read_text(), "Z")
                if cancel:
                    owner.send_signal(signal.SIGTERM)
                stdout, stderr = owner.communicate(timeout=6)
                report = json.loads((evidence / "process-cleanup.json").read_text())
                self.assertEqual(report["owner_pid"], owner.pid)
                self.assertEqual(report["remaining_live_children"], [])
                self.assertIn(child_pid, report["reaped_pids"])
                self.assertFalse(Path(f"/proc/{child_pid}").exists(), stderr)
                self.assertEqual(len(report["owned_sessions"]), 3)
                for item in report["owned_sessions"]:
                    self.assertEqual(item["pid"], item["pgid"])
                    self.assertEqual(item["pid"], item["sid"])
                    self.assertIn(item["pid"], report["reaped_pids"])
                    self.assertFalse(Path(f"/proc/{item['pid']}").exists())
                self.assertTrue(report["term_used"])
                self.assertEqual(report["escalated_to_kill"], mode != "term")
                expected_probe = 143 if cancel else int(status)
                expected_exit = expected_probe or (1 if cleanup_failure else 0)
                self.assertEqual(report["probe_exit_status"], expected_probe)
                self.assertEqual(report["cleanup_exit_status"], int(cleanup_failure))
                self.assertEqual(report["final_exit_status"], expected_exit)
                self.assertEqual(owner.returncode, expected_exit, stdout + stderr)
                self.assertEqual(profile.exists(), cleanup_failure)
                self.assertEqual(report["profile_removed"], not cleanup_failure)
                if stale_snapshot:
                    self.assertEqual((evidence / "stale-snapshot-injected").read_text(), "once")
                if cleanup_failure:
                    self.assertIn("injected profile removal failure", report["cleanup_error"])
                else:
                    self.assertIsNone(report["cleanup_error"])
                self.assertIsNone(sentinel.poll(), "Unrelated sentinel was killed")
                self.wait_for(lambda: heartbeat.read_text() not in ("", before), sentinel)
                print(json.dumps({"case": self.id(), "result": "PASS", "cleanup": report}, sort_keys=True))
            finally:
                if owner.poll() is None:
                    owner.terminate()
                    try:
                        owner.communicate(timeout=4)
                    except subprocess.TimeoutExpired:
                        owner.kill()
                        owner.communicate()
                else:
                    owner.communicate()
                if child_fd is not None:
                    try:
                        signal.pidfd_send_signal(child_fd, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    os.close(child_fd)
                sentinel.terminate()
                sentinel.wait(timeout=3)

    def test_exited_parent_session_escaping_writer_is_killed_and_reaped(self):
        self.exercise()

    def test_term_cooperative_orphan_needs_no_kill(self):
        self.exercise(mode="term")

    def test_new_orphan_after_dead_snapshot_is_signaled_before_reap(self):
        self.exercise(stale_snapshot=True)

    def test_zombie_thread_leader_with_live_writer_is_not_treated_as_dead(self):
        self.exercise(mode="threaded-ignore-term")

    def test_probe_failure_is_preserved_after_cleanup(self):
        self.exercise(status="37")

    def test_probe_failure_wins_over_removal_failure(self):
        self.exercise(status="37", cleanup_failure=True)

    def test_removal_failure_turns_probe_success_into_failure(self):
        self.exercise(cleanup_failure=True)

    def test_cancellation_cleans_descendants_and_retains_signal_status(self):
        self.exercise(status="hang", cancel=True)


if __name__ == "__main__":
    unittest.main()
