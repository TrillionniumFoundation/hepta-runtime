#!/usr/bin/env python3
"""Disposable POSIX negative/positive controls for Hepta remote cwd isolation."""
import os, pathlib, shlex, subprocess, tempfile, json, sys

def build_pty_guard(cwd, roots):
    code=f"cd {shlex.quote(cwd)} && "
    if roots:
        code += "cwd_physical=$(pwd -P) || exit 125; cwd_guard=0; "
        for root in roots:
            code += f"root_physical=$(cd {shlex.quote(root)} && pwd -P) || exit 125; "
            code += 'if [ "$root_physical" = / ]; then cwd_guard=1; else '
            code += 'case "$cwd_physical" in "$root_physical"|"$root_physical"/*) cwd_guard=1;; esac; fi; '
        code += '[ "$cwd_guard" = 1 ] || exit 126; '
    return code + 'exec env /bin/pwd'

def native_process_preflight(cwd, roots):
    if not isinstance(roots, list) or any(not isinstance(root, str) or not os.path.isabs(root) for root in roots):
        raise PermissionError('missing or invalid remote cwd policy')
    if roots and not cwd:
        raise PermissionError('cwd required by remote execution policy')
    if cwd:
        os.chdir(cwd)
    actual = os.getcwd()
    if roots:
        physical_roots = [os.path.realpath(root) for root in roots]
        if not any(os.path.commonpath([actual,root])==root for root in physical_roots):
            raise PermissionError('cwd resolves outside allowed execution roots')
    return subprocess.check_output(['/bin/pwd'], cwd=None, text=True).strip()

def run():
    rows=[]
    with tempfile.TemporaryDirectory(prefix='hepta-cwd-gate-') as tmp:
        root=pathlib.Path(tmp); allowed=root/'allowed'; outside=root/'outside'
        allowed.mkdir(); outside.mkdir(); (allowed/'safe').mkdir()
        (allowed/'escape').symlink_to(outside,target_is_directory=True)
        cases=[('safe child',allowed/'safe',True),('same root',allowed,True),('symlink escape',allowed/'escape',False),('sibling outside',outside,False)]
        for label,target,should_allow in cases:
            shell = subprocess.run(['sh','-c',build_pty_guard(str(target),[str(allowed)])],capture_output=True,text=True)
            direct = subprocess.run([sys.executable,'-c','import sys;sys.path.insert(0,sys.argv[1]);from hepta_cwd_policy_repro import native_process_preflight;print(native_process_preflight(sys.argv[2],[sys.argv[3]]))', '/mnt/data',str(target),str(allowed)],capture_output=True,text=True)
            assert (shell.returncode==0)==should_allow,(label,'pty',shell.stdout,shell.stderr,shell.returncode)
            assert (direct.returncode==0)==should_allow,(label,'process',direct.stdout,direct.stderr,direct.returncode)
            rows.append({'case':label,'expected':should_allow,'pty_guard_admitted':shell.returncode==0,'process_guard_admitted':direct.returncode==0})
        for label in ['missing cwd']:
            direct=subprocess.run([sys.executable,'-c','import sys;sys.path.insert(0,sys.argv[1]);from hepta_cwd_policy_repro import native_process_preflight;native_process_preflight(None,[sys.argv[2]])', '/mnt/data',str(allowed)],capture_output=True,text=True)
            assert direct.returncode != 0
            rows.append({'case':label,'expected':False,'pty_guard_admitted':False,'process_guard_admitted':False})
    print(json.dumps({'pass':True,'cases':rows},indent=2))

if __name__=='__main__':run()
