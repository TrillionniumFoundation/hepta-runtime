"""Isolated actual-Git regression oracle for runtime P3 PR #42 (not a checkout test)."""
from __future__ import annotations
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

EXEC = frozenset((
    'core.fsmonitor','core.hookspath','core.worktree','core.sshcommand',
    'core.gitproxy','core.pager','core.editor','core.attributesfile',
    'core.alternaterefscommand','diff.external','credential.helper',
    'gpg.program','sequence.editor','extensions.partialclone',
))

def executable_key(key):
    return (key in EXEC or key.startswith(('alias.','pager.'))
        or (key.startswith('filter.') and key.endswith(('.clean','.smudge','.process')))
        or (key.startswith('diff.') and key.endswith(('.command','.textconv')))
        or (key.startswith('merge.') and key.endswith('.driver'))
        or (key.startswith('credential.') and key.endswith('.helper')))

def checked_git(repo, *args):
    # This is a separate reference harness, not imported from PR #42.
    q=subprocess.run(('git','config','--includes','--null','--list'),cwd=repo,
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=10)
    assert len(q.stdout)<=256*1024
    keys=[v.partition(b'\n')[0].decode('ascii').lower() for v in q.stdout.split(b'\0') if v]
    blocked=sorted({k for k in keys if executable_key(k)})
    if blocked:
        raise RuntimeError('unreviewed executable Git configuration keys: '+','.join(blocked))
    return subprocess.run(('git','-c','core.hooksPath=/dev/null',*args),cwd=repo,
              capture_output=True,check=True)

class TestP3GitConfig(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.repo=Path(self.temp.name)
        self.cmd('init','-q'); self.cmd('config','user.name','Test User')
        self.cmd('config','user.email','example@invalid.test')
        (self.repo/'fixture.txt').write_text('stable\n'); self.cmd('add','fixture.txt')
        self.cmd('commit','-qm','fixture')
    def cmd(self,*args):
        return subprocess.run(('git',*args),cwd=self.repo,capture_output=True,check=True)
    def test_normal_repo_source_queries_pass(self):
        self.assertEqual(checked_git(self.repo,'rev-parse','HEAD').stdout.strip(),self.cmd('rev-parse','HEAD').stdout.strip())
        self.assertTrue(checked_git(self.repo,'ls-files','-v').stdout.startswith(b'H '))
    def test_original_executable_fsmonitor_reproduced(self):
        marker=self.repo/'unsafe-marker'
        f=self.repo/'fsmonitor.sh';f.write_text('#!/bin/sh\nprintf attacked > "'+str(marker)+'"\n');f.chmod(0o755)
        self.cmd('config','core.fsmonitor',str(f))
        self.assertFalse(marker.exists())
        self.cmd('-c','core.hooksPath=/dev/null','ls-files','-v')
        self.assertTrue(marker.exists(),'real Git fsmonitor must demonstrate original bypass')
        marker.unlink()
        with self.assertRaisesRegex(RuntimeError,'core.fsmonitor'):
            checked_git(self.repo,'ls-files','-v')
        self.assertFalse(marker.exists(),'patched preflight must refuse before execution')
    def test_checkout_filter_refusal(self):
        self.cmd('config','filter.example.smudge','sh -c \'printf attacked\'')
        with self.assertRaisesRegex(RuntimeError,'filter.example.smudge'):
            checked_git(self.repo,'worktree','add','--detach',str(self.repo.parent/'nonexistent'), 'HEAD')
    def test_merge_driver_refusal(self):
        self.cmd('config','merge.ours.driver','/tmp/unreviewed')
        with self.assertRaisesRegex(RuntimeError,'merge.ours.driver'):
            checked_git(self.repo,'rev-parse','HEAD')
    def test_credential_helper_refusal(self):
        self.cmd('config','credential.helper','!echo SECRET_VALUE')
        with self.assertRaisesRegex(RuntimeError,'credential.helper') as e:
            checked_git(self.repo,'rev-parse','HEAD')
        self.assertNotIn('SECRET_VALUE',str(e.exception))
    def test_included_config_refusal(self):
        extra=self.repo/'custom.ini';extra.write_text('[core]\n  fsmonitor = /tmp/unreviewed\n')
        self.cmd('config','include.path',str(extra))
        with self.assertRaisesRegex(RuntimeError,'core.fsmonitor'):
            checked_git(self.repo,'ls-files','-v')
    def test_alias_refusal(self):
        self.cmd('config','alias.unsafe','!touch /tmp/unsafe')
        with self.assertRaisesRegex(RuntimeError,'alias.unsafe'):
            checked_git(self.repo,'rev-parse','HEAD')
    def test_safe_nonexecutable_config_accepted(self):
        self.cmd('config','core.quotePath','true')
        self.assertTrue(checked_git(self.repo,'rev-parse','HEAD').stdout.strip())

if __name__=='__main__':unittest.main()
