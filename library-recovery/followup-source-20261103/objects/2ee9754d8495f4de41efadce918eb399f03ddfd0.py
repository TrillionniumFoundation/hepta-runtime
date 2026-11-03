import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('hepta_local_gate.py')


def git(path, *args):
    return subprocess.check_output(['git', '-C', str(path), *args], text=True).strip()


class GateTests(unittest.TestCase):
    def call(self, repo, sha, output):
        process = subprocess.run([
            sys.executable, str(SCRIPT), '--repo', str(repo),
            '--expected-head', sha, '--kind', 'hepta-runtime', '--out', str(output)
        ], text=True, capture_output=True, check=False)
        return process, json.loads(output.read_text())

    def test_missing_checkout_denies_without_fake_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            process, data = self.call(root / 'not-mounted', 'f' * 40, root / 'receipt.json')
            self.assertEqual(process.returncode, 2)
            self.assertEqual(data['reason'], 'local-worktree-missing')
            self.assertFalse(data['production_qualified'])

    def test_head_mismatch_clean_and_dirty_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            git(repo, 'config', 'user.email', 'tests@example.invalid')
            git(repo, 'config', 'user.name', 'Test')
            (repo / 'Cargo.toml').write_text('[package]\nname="probe"\nversion="0.1.0"\nedition="2021"\n')
            (repo / 'Cargo.lock').write_text('version = 3\n')
            git(repo, 'add', '--all')
            git(repo, 'commit', '-q', '-m', 'fixture')
            sha = git(repo, 'rev-parse', 'HEAD')
            p, data = self.call(repo, 'f'*40, root / 'mismatch.json')
            self.assertEqual(p.returncode, 2)
            self.assertEqual(data['reason'], 'exact-source-head-mismatch')
            (repo / 'added.txt').write_text('untracked')
            p, data = self.call(repo, sha, root / 'dirty.json')
            self.assertEqual(p.returncode, 2)
            self.assertEqual(data['reason'], 'worktree-not-clean')
            (repo / 'added.txt').unlink()
            p, data = self.call(repo, sha, root / 'clean.json')
            self.assertEqual(p.returncode, 2)
            self.assertEqual(data['reason'], 'rust-compiler-or-cargo-unavailable')
            self.assertTrue(data['source_exact'])
            self.assertTrue(data['worktree_clean'])
            self.assertFalse(data['production_qualified'])

    def test_refuses_to_write_receipt_into_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            receipt = repo / 'should-not-exist.json'
            command = [sys.executable, str(SCRIPT), '--repo', str(repo),
                       '--expected-head', 'e' * 40, '--kind', 'hepta-runtime',
                       '--out', str(receipt)]
            process = subprocess.run(command, text=True, capture_output=True)
            self.assertEqual(process.returncode, 2)
            self.assertFalse(receipt.exists())

    def test_unqualified_environment_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / 'repo'
            repo.mkdir()
            git(repo, 'init', '-q')
            sha = 'e' * 40
            old = os.environ.get('RUSTC_WRAPPER')
            os.environ['RUSTC_WRAPPER'] = '/tmp/untrusted-wrapper'
            try:
                p, data = self.call(repo, sha, root / 'env.json')
            finally:
                if old is None:
                    os.environ.pop('RUSTC_WRAPPER', None)
                else:
                    os.environ['RUSTC_WRAPPER'] = old
            self.assertEqual(p.returncode, 2)
            self.assertEqual(data['reason'], 'unqualified-executable-or-toolchain-environment')
            self.assertIn('RUSTC_WRAPPER', data['blocked_injected_environment_keys'])


if __name__ == '__main__':
    unittest.main()
