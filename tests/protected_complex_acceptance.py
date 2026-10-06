#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual native MCP protected-PDF and complex-workbook qualification on target files.
Only new disposable fixtures; synthetic credentials go through stdin, not argv/logs.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import tempfile
import time
import zipfile
from lxml import etree
from runtime_http_acceptance import Client
from pdf_security_prototype_tests import signed_fixture,D

NS={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'};T='{'+NS['s']+'}'


def complex_workbook():
 data=D.create_bytes('xlsx',{'Data':[[2,3,'=SUM(Values)*Rate','=A1+$H$1',None,None,None,10],[4,5,None,'=A2+$H$1'],[None,None,'=A1:B2*2',None,None,'=D4+1']], 'Other':[['=Rate',"='Data'!Rate",'=DATE(1904,1,1)','=YEAR(C1)']]})
 with zipfile.ZipFile(io.BytesIO(data)) as z:parts={n:z.read(n) for n in z.namelist()}
 book=etree.fromstring(parts['xl/workbook.xml']);book.find('s:workbookPr',NS).set('date1904','1')
 names=book.find('s:definedNames',NS)
 if names is None:names=etree.SubElement(book,T+'definedNames')
 for name,scope,text in [('Rate',None,'2'),('Rate','0','3'),('Values',None,"'Data'!$A$1:$B$1")]:
  entry=etree.SubElement(names,T+'definedName',name=name);entry.text=text
  if scope is not None:entry.set('localSheetId',scope)
 parts['xl/workbook.xml']=etree.tostring(book)
 sheet=etree.fromstring(parts['xl/worksheets/sheet1.xml'])
 for coord in ('D1','D2'):
  f=sheet.find(".//s:c[@r='"+coord+"']/s:f",NS);f.set('t','shared');f.set('si','0')
  if coord=='D1':f.set('ref','D1:D2')
  else:f.text=None
 f=sheet.find(".//s:c[@r='C3']/s:f",NS);f.set('t','array');f.set('ref','C3:D4')
 parts['xl/worksheets/sheet1.xml']=etree.tostring(sheet)
 out=io.BytesIO()
 with zipfile.ZipFile(out,'w') as z:
  for name,value in parts.items():z.writestr(name,value)
 return out.getvalue()


def main():
 ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--parser',required=True);ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True);ap.add_argument('--url');ap.add_argument('--token-file');ap.add_argument('--host',default='operator');a=ap.parse_args()
 report={'complete':False,'checks':[],'ssh_target':a.ssh_target,'installed_endpoint':bool(a.url),'binary_sha256':hashlib.file_digest(open(a.binary,'rb'),'sha256').hexdigest()}
 def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
 def passed(label):report['checks'].append(label);save();print('PASS '+label,flush=True)
 root_path='/tmp/hepta-protected-native-'+secrets.token_hex(12)
 user=secrets.token_urlsafe(24);owner=secrets.token_urlsafe(24)
 code="import json,pathlib,os,sys;q=json.load(sys.stdin);r=pathlib.Path(q['root']);r.mkdir(mode=0o700);r=r.resolve()\nfor key in ('user','owner'):\n f=os.open(r/(key+'.secret'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)\n with os.fdopen(f,'w') as s:s.write(q[key])\nprint(json.dumps({'root':str(r),'platform':'macos' if sys.platform=='darwin' else 'linux'}))"
 setup=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],input=json.dumps({'root':root_path,'user':user,'owner':owner}),text=True,capture_output=True,timeout=20)
 if setup.returncode:raise RuntimeError('private fixture setup failed: '+setup.stderr[-400:])
 target=json.loads(setup.stdout);root_path=target['root'];report['fixture_directory']=root_path
 with tempfile.TemporaryDirectory(prefix='hepta-protected-controller-') as directory:
  folder=pathlib.Path(directory);(folder/'workspace').mkdir();token=secrets.token_hex(32);(folder/'token').write_text(token);(folder/'token').chmod(0o600)
  host={'ssh_target':a.ssh_target,'platform':target['platform'],'execution_mode':'operator','remote_state_dir':root_path+'/state','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[root_path],'allowed_write_path_prefixes':[root_path]}
  (folder/'config.json').write_text(json.dumps({'state_dir':str(folder/'state'),'controller_workspace_roots':[str(folder/'workspace')],'hosts':{a.host:host}}))
  with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
  controller=None;c=None
  if not a.url:
   with (folder/'runtime.log').open('w') as log:controller=subprocess.Popen([a.binary,'mcp','--path',str(folder/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(folder/'config.json'),'--auth-token-file',str(folder/'token')],env={**os.environ,'HEPTA_RUNTIME_DOCUMENT_PYTHON':a.parser},stdin=subprocess.DEVNULL,stdout=log,stderr=log)
  try:
   for _ in range(100):
    if controller and controller.poll() is not None:raise RuntimeError((folder/'runtime.log').read_text()[-1000:])
    try:c=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
    except (OSError,RuntimeError):time.sleep(.1)
   if c is None:raise RuntimeError('native controller unavailable')
   def call(name,params,denied=False):
    value=c.call(name,{'host':a.host,**params},denied=denied)
    assert user not in str(value) and owner not in str(value),'secret leaked into response'
    return value
   schema=next(t['inputSchema'] for t in c.rpc('tools/list',{})['tools'] if t['name']=='pdf_security')
   assert not {'password','owner_password','user_password','roots','remote','file_helper'}&schema['properties'].keys()
   passed('protected-PDF schema exposes owned password file references, not raw secret or authority overrides')
   def put(name,data):
    path=root_path+'/'+name;call('binary_write',{'path':path,'expected_version':'absent','data_base64':base64.b64encode(data).decode()});return path,hashlib.sha256(data).hexdigest()
   source,pdf_sha=put('source.pdf',D.create_bytes('pdf','# Protected fixture\nOriginal 中文'))
   encrypted=root_path+'/encrypted.pdf'
   value=call('pdf_security',{'path':source,'expected_sha256':pdf_sha,'action':'encrypt_copy','output_path':encrypted,'output_expected_sha256':'absent','output_user_password_file':root_path+'/user.secret','output_owner_password_file':root_path+'/owner.secret'})
   assert value['output_encrypted'] and value['source_unchanged'];encrypted_sha=value['sha256']
   info=call('pdf_security',{'path':encrypted,'expected_sha256':encrypted_sha,'action':'inspect','password_file':root_path+'/user.secret'});assert info['encrypted'] and info['page_count']==1
   call('pdf_security',{'path':encrypted,'expected_sha256':encrypted_sha,'action':'decrypt_copy','password_file':root_path+'/user.secret','output_path':root_path+'/denied.pdf','output_expected_sha256':'absent'},denied=True)
   clear=call('pdf_security',{'path':encrypted,'expected_sha256':encrypted_sha,'action':'decrypt_copy','password_file':root_path+'/owner.secret','output_path':root_path+'/clear.pdf','output_expected_sha256':'absent'})
   assert clear['source_unchanged'] and not clear['output_encrypted']
   assert 'Protected fixture' in str(call('document_read',{'path':root_path+'/clear.pdf'}))
   assert call('file_info',{'path':encrypted})['sha256']==encrypted_sha
   passed('AES-256 copy, real user/owner authentication split and owner-authorized clear copy preserve originals')
   signed_bytes=signed_fixture(D.create_bytes('pdf','# Signed synthetic fixture'))
   signed,signed_sha=put('signed.pdf',signed_bytes)
   verified=call('pdf_security',{'path':signed,'expected_sha256':signed_sha,'action':'inspect'})
   assert verified['signatures'][0]['integrity']=='valid' and verified['current_revision_fully_signed'] and not verified['certificate_trust_evaluated']
   appended=call('pdf_security',{'path':signed,'expected_sha256':signed_sha,'action':'append_metadata','output_path':root_path+'/appended.pdf','output_expected_sha256':'absent','allow_unsigned_revision':True,'title':'Explicit unsigned continuation'})
   assert appended['original_bytes_are_prefix'] and not appended['new_revision_is_signed'] and appended['output_signatures']['signatures'][0]['integrity']=='valid' and not appended['output_signatures']['current_revision_fully_signed']
   assert call('file_info',{'path':signed})['sha256']==signed_sha
   tampered,tampered_sha=put('tampered.pdf',signed_bytes.replace(b'FixtureOriginal',b'FixtureTampered'))
   assert call('pdf_security',{'path':tampered,'expected_sha256':tampered_sha,'action':'inspect'})['signatures'][0]['integrity']=='invalid'
   passed('real detached CMS integrity, tamper detection and unsigned incremental revision are distinguished')
   workbook=complex_workbook();path,sha=put('complex.xlsx',workbook)
   calculated=call('worksheet_recalculate',{'path':path,'expected_sha256':sha});assert calculated['workbook_date_system']=='1904' and calculated['fixed_array_count']==1
   for sheet,region,expected in [('Data','C1:C1',[[15]]),('Data','D1:D2',[[12],[14]]),('Data','C3:D4',[[4,6],[8,10]]),('Data','F3:F3',[[11]]),('Other','A1:D1',[[2,3,0,1904]])]:
    actual=call('document_read',{'path':path,'sheet':sheet,'range':region,'cached_values':True})['rows'];assert actual==expected,(sheet,region,actual)
   read=call('binary_read',{'path':path,'limit':65536});assert read['eof'];raw=base64.b64decode(read['data_base64'])
   assert hashlib.sha256(raw).hexdigest()==calculated['sha256']
   with zipfile.ZipFile(io.BytesIO(workbook)) as z,zipfile.ZipFile(io.BytesIO(raw)) as after:
    for name in z.namelist():
     if name not in calculated['changed_parts']:assert z.read(name)==after.read(name)
    before_forms=[etree.tostring(x) for x in etree.fromstring(z.read('xl/worksheets/sheet1.xml')).findall('.//s:f',NS)]
    after_forms=[etree.tostring(x) for x in etree.fromstring(after.read('xl/worksheets/sheet1.xml')).findall('.//s:f',NS)];assert before_forms==after_forms
   report['calculation_evidence']={k:calculated[k] for k in ['formula_count','calculated_cell_count','fixed_array_count','workbook_date_system']}
   passed('native scoped names, shared formulas, fixed 2x2 arrays and 1904 calendar caches are correct without formula/package loss')
   report.update(complete=True,passed=len(report['checks']),real_user_secrets_used=False,certificate_trust_claimed=False);save()
  finally:
   if controller:controller.terminate();controller.wait(timeout=20)
   # Destroy only the two synthetic private password files; original test documents/evidence stay.
   cleanup="import pathlib;r=pathlib.Path("+repr(root_path)+");[(r/name).unlink(missing_ok=True) for name in ('user.secret','owner.secret')]"
   subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=6',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(cleanup)],capture_output=True,timeout=15)
   save()


if __name__=='__main__':main()
