#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Stage an explicit interpreter setting for the existing user runtime only.
Does not restart services, modify file-access roots, or change other applications.
"""
import argparse
import json
import os
import pathlib
import subprocess


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--python',required=True);ap.add_argument('--check-only',action='store_true');ap.add_argument('--out',required=True)
    a=ap.parse_args();interpreter=pathlib.Path(a.python)
    if os.geteuid()==0:raise RuntimeError('configure this user service as its normal owner')
    if not interpreter.is_absolute() or any(c in str(interpreter) for c in ('\n','\r','\0','"')):raise RuntimeError('absolute interpreter path required')
    code="import importlib.metadata,json; print(json.dumps({x:importlib.metadata.version(x) for x in ['pypdf','python-docx','Pillow','openpyxl','reportlab','lxml']}))"
    result=subprocess.run([str(interpreter),'-I','-c',code],check=True,text=True,capture_output=True,timeout=15)
    versions=json.loads(result.stdout)
    home=pathlib.Path.home();unit=home/'.config/systemd/user/hepta-runtime-operator.service'
    if not unit.is_file():raise RuntimeError('existing operator user service required')
    path=unit.parent/(unit.name+'.d')/'50-native-documents.conf'
    content='[Service]\nEnvironment="HEPTA_RUNTIME_DOCUMENT_PYTHON='+str(interpreter).replace('%','%%')+'"\n'
    report={'interpreter':str(interpreter),'dependencies':versions,'drop_in':str(path),'service_restarted':False,'staged':False}
    if not a.check_only:
        path.parent.mkdir(mode=0o700,exist_ok=True)
        if path.exists() and path.read_text()!=content:raise RuntimeError('a different document-worker configuration already exists; nothing overwritten')
        if not path.exists():
            fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream:stream.write(content);stream.flush();os.fsync(stream.fileno())
        report['staged']=True
    pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':main()
