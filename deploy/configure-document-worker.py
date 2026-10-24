#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Stage the existing user's document interpreter, with explicit version-checked updates.
Never restarts a service, broadens roots, or changes another application's settings.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import secrets
import subprocess


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--python',required=True);ap.add_argument('--check-only',action='store_true');ap.add_argument('--out',required=True)
    ap.add_argument('--require-formats',action='store_true')
    ap.add_argument('--expected-current-sha256',help='Required to replace an existing different interpreter setting; stale values fail without a write')
    a=ap.parse_args();interpreter=pathlib.Path(a.python)
    if os.geteuid()==0:raise RuntimeError('configure this user service as its normal owner')
    if not interpreter.is_absolute() or any(c in str(interpreter) for c in ('\n','\r','\0','"')):raise RuntimeError('absolute interpreter path required')
    packages=['pypdf','python-docx','Pillow','openpyxl','reportlab','lxml']
    if a.require_formats:packages+=['weasyprint','formulas','xlrd','markdown-it-py']
    code='import importlib.metadata,json;print(json.dumps({x:importlib.metadata.version(x) for x in '+repr(packages)+'}))'
    result=subprocess.run([str(interpreter),'-I','-c',code],check=True,text=True,capture_output=True,timeout=20,env={**os.environ,'OPENBLAS_NUM_THREADS':'1','OMP_NUM_THREADS':'1'})
    versions=json.loads(result.stdout)
    home=pathlib.Path.home();unit=home/'.config/systemd/user/hepta-runtime-operator.service'
    if not unit.is_file():raise RuntimeError('existing operator user service required')
    path=unit.parent/(unit.name+'.d')/'50-native-documents.conf'
    if path.is_symlink():raise RuntimeError('document-worker drop-in must not be a symlink')
    content=('[Service]\nEnvironment="HEPTA_RUNTIME_DOCUMENT_PYTHON='+str(interpreter).replace('%','%%')+'"\n').encode()
    previous=path.read_bytes() if path.exists() else None
    previous_sha=hashlib.sha256(previous).hexdigest() if previous is not None else 'absent'
    if a.expected_current_sha256 is not None:
        if not re.fullmatch('[0-9a-f]{64}',a.expected_current_sha256) or previous_sha!=a.expected_current_sha256:
            raise RuntimeError('document-worker configuration changed; no write applied')
    if previous is not None and previous!=content and a.expected_current_sha256 is None:
        raise RuntimeError('a different parser setting exists; an exact expected-current-sha256 is required')
    report={'interpreter':str(interpreter),'dependencies':versions,'drop_in':str(path),'service_restarted':False,'staged':False,
            'previous_sha256':previous_sha,'new_sha256':hashlib.sha256(content).hexdigest(),'formats_verified':a.require_formats}
    if not a.check_only:
        path.parent.mkdir(mode=0o700,exist_ok=True)
        if previous!=content:
            temp=path.with_name(path.name+'.new-'+secrets.token_hex(8))
            try:
                fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
                current=path.read_bytes() if path.exists() else None
                if path.is_symlink() or current!=previous:raise RuntimeError('parser setting changed before publication')
                if previous is None:
                    os.link(temp,path,follow_symlinks=False);temp.unlink()
                else:os.replace(temp,path)
                fd=os.open(path.parent,os.O_RDONLY)
                try:os.fsync(fd)
                finally:os.close(fd)
            finally:
                if temp.exists():temp.unlink()
        report['staged']=True
    pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
