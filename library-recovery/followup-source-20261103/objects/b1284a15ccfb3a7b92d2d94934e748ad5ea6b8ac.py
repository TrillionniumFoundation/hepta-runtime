"""Focused real-POSIX reproduction of P3 exit-zero orphan bug and new group fence."""
import os, sys, tempfile, subprocess, signal, time, unittest
from pathlib import Path


def spawn_closed_pipes_descendant(cwd: Path):
    code = (
        "import sys,subprocess,pathlib\n"
        "p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(20)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
        "pathlib.Path('child.pid').write_text(str(p.pid))\n"
    )
    p = subprocess.Popen([sys.executable,'-c',code], cwd=cwd, stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         start_new_session=True)
    output = p.communicate(timeout=5)[0]
    return p, output


def local_group_fence(proc):
    """Exact branch logic extracted from PR source for a focused test."""
    failures = []
    try:
        os.killpg(proc.pid, 0)
    except ProcessLookupError:
        pass
    except PermissionError:
        failures.append('cannot attest command process-group termination')
    else:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        failures.append('process-group descendants remain after command exit')
    return failures


class GroupExitRegression(unittest.TestCase):
    def test_closed_pipes_parent_exit_zero_yet_descendant_alive(self):
        with tempfile.TemporaryDirectory() as d:
            p, output = spawn_closed_pipes_descendant(Path(d))
            child_pid = int((Path(d)/'child.pid').read_text())
            try:
                self.assertEqual(p.returncode, 0)
                self.assertEqual(output, b'')
                # Old validator's returncode-and-output-only rule is wrong:
                old_admitted = p.returncode == 0 and output == b''
                self.assertTrue(old_admitted)
                failures = local_group_fence(p)
                self.assertEqual(failures,['process-group descendants remain after command exit'])
            finally:
                try: os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError: pass

    def test_clean_command_has_no_remaining_group(self):
        with tempfile.TemporaryDirectory() as d:
            p=subprocess.Popen([sys.executable,'-c','print(2)'],cwd=d,
                               stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                               start_new_session=True)
            output=p.communicate(timeout=5)[0]
            self.assertEqual(p.returncode,0)
            self.assertEqual(output,b'2\n')
            self.assertEqual(local_group_fence(p),[])

    def test_nonzero_parent_not_considered_success(self):
        with tempfile.TemporaryDirectory() as d:
            p=subprocess.Popen([sys.executable,'-c','raise SystemExit(9)'],cwd=d,
                               stdout=subprocess.PIPE,stderr=subprocess.STDOUT,
                               start_new_session=True)
            p.communicate(timeout=5)
            self.assertEqual(p.returncode,9)
            self.assertEqual(local_group_fence(p),[])

if __name__=='__main__': unittest.main(verbosity=2)
