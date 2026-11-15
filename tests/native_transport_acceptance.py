#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual SSH/authenticated MCP binary, remote document and page/range edit checks.
Only unique disposable target paths; no service, account, sudo or cloud changes.
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
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--parser',required=True)
    ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True)
    ap.add_argument('--url');ap.add_argument('--token-file');ap.add_argument('--host',default='operator')
    a=ap.parse_args();key=secrets.token_hex(12);target='/tmp/hepta-native-transport-'+key;controller=None
    report={'checks':[],'complete':False,'ssh_target':a.ssh_target,'binary_sha256':hashlib.file_digest(open(a.binary,'rb'),'sha256').hexdigest(),'installed_endpoint':bool(a.url)}
    def passed(name):
        report['checks'].append(name);pathlib.Path(a.out).write_text(json.dumps(report,indent=2));print('PASS',name,flush=True)
    code="import pathlib,json,sys;p=pathlib.Path("+repr(target)+");p.mkdir(mode=0o700);print(json.dumps({'path':str(p.resolve()),'platform':'linux' if sys.platform=='linux' else 'macos'}))"
    p=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=8',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],text=True,capture_output=True,timeout=20)
    if p.returncode:raise RuntimeError(p.stderr)
    meta=json.loads(p.stdout);target=meta['path'];report['target_directory']=target
    with tempfile.TemporaryDirectory(prefix='hepta-native-controller-') as tmp:
        work=pathlib.Path(tmp);(work/'workspace').mkdir();token=secrets.token_hex(32);(work/'token').write_text(token);(work/'token').chmod(0o600)
        host={'ssh_target':a.ssh_target,'platform':meta['platform'],'execution_mode':'operator','remote_state_dir':target+'/jobs','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[target],'allowed_write_path_prefixes':[target]}
        config={'state_dir':str(work/'state'),'controller_workspace_roots':[str(work/'workspace')],'hosts':{a.host:host,'isolated':{**host,'execution_mode':'isolated'}}};(work/'config.json').write_text(json.dumps(config))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        if not a.url:
            with (work/'controller.log').open('w') as log:
                controller=subprocess.Popen([a.binary,'mcp','--path',str(work/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(work/'config.json'),'--auth-token-file',str(work/'token')],env={**os.environ,'HEPTA_RUNTIME_DOCUMENT_PYTHON':a.parser},stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            c=None
            for _ in range(100):
                if controller and controller.poll() is not None:raise RuntimeError((work/'controller.log').read_text()[-2000:])
                try:c=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
                except (OSError,RuntimeError):time.sleep(.1)
            if c is None:raise RuntimeError('MCP unavailable')
            tools={t['name']:t for t in c.rpc('tools/list',{})['tools']}
            required={'file_info','binary_read','binary_write','binary_upload','document_read','document_write','document_edit','image_read','pdf_edit','worksheet_edit'}
            assert required<=tools.keys()
            for name in required:assert not {'ssh_target','roots','remote','file_helper','python'} & tools[name]['inputSchema']['properties'].keys()
            passed('native tools discovered with no hidden authority override fields')
            path=target+'/all-bytes.bin';data=bytes(range(256))*257+'中文\x00'.encode()
            result=c.call('binary_write',{'host':a.host,'path':path,'expected_version':'absent','data_base64':base64.b64encode(data).decode()})
            info=c.call('file_info',{'host':a.host,'path':path});assert info['sha256']==hashlib.sha256(data).hexdigest()
            offset=0;all_data=b''
            while offset<len(data):
                part=c.call('binary_read',{'host':a.host,'path':path,'offset':offset,'limit':16384,'expected_version':info['version']})
                raw=base64.b64decode(part['data_base64'],validate=True);assert hashlib.sha256(raw).hexdigest()==part['chunk_sha256']
                all_data+=raw;offset=part['next_offset']
            assert all_data==data
            c.call('binary_write',{'host':a.host,'path':path,'expected_version':'absent','data_base64':'Tk8='},denied=True)
            c.call('binary_read',{'host':a.host,'path':path,'expected_version':'STALE'},denied=True)
            if not a.url:
                c.call('binary_read',{'host':'isolated','path':path},denied=True)
                c.call('binary_read',{'host':a.host,'path':'/etc/hosts'},denied=True)
            passed('exact binary bytes, SHA256, byte cursor and authority/version rejection')
            large=bytes(range(256))*(20*1024)+b'END';large_path=target+'/large.bin';upload='upload-'+key
            for offset in range(0,len(large),1024*1024):
                args={'host':a.host,'path':large_path,'action':'chunk','upload_id':upload,'expected_version':'absent','offset':offset,'data_base64':base64.b64encode(large[offset:offset+1024*1024]).decode()}
                c.call('binary_upload',args)
                if offset==0:c.call('binary_upload',args)
            commit={'host':a.host,'path':large_path,'action':'commit','upload_id':upload,'size':len(large),'sha256':hashlib.sha256(large).hexdigest()}
            committed=c.call('binary_upload',commit);again=c.call('binary_upload',commit)
            assert again['reused'] and committed['version']==again['version']
            assert c.call('file_info',{'host':a.host,'path':large_path})['sha256']==commit['sha256']
            assert not c.call('binary_upload',{'host':a.host,'path':large_path,'action':'abort','upload_id':upload})['aborted']
            passed('over-5-MiB staged upload, exact total hash and once-only commit replay')
            doc=target+'/remote.docx'
            create=c.call('document_write',{'host':a.host,'path':doc,'format':'docx','content':'# Remote 标题\nOld paragraph','expected_sha256':'absent'})
            outline=c.call('document_read',{'host':a.host,'path':doc});assert 'Old paragraph' in str(outline)
            edit=c.call('document_edit',{'host':a.host,'path':doc,'expected_sha256':create['sha256'],'old_xml':'Old paragraph','new_xml':'Updated paragraph'})
            assert edit['unselected_zip_payloads_preserved'] and edit['host']==a.host
            assert 'Updated paragraph' in str(c.call('document_read',{'host':a.host,'path':doc}))
            c.call('document_edit',{'host':a.host,'path':doc,'expected_sha256':create['sha256'],'old_xml':'Updated','new_xml':'NO'},denied=True)
            passed('native remote DOCX create/read/XML edit with stale-source rejection')
            from PIL import Image
            out=io.BytesIO();Image.new('RGB',(80,40),(23,121,210)).save(out,'PNG');image=target+'/original.png'
            c.call('binary_write',{'host':a.host,'path':image,'expected_version':'absent','data_base64':base64.b64encode(out.getvalue()).decode()})
            native=c.rpc('tools/call',{'name':'image_read','arguments':{'host':a.host,'path':image}})
            assert not native.get('isError');blocks=native['content'];meta=json.loads(blocks[0]['text']);assert meta['width']==80 and meta['host']==a.host
            assert blocks[1]['type']=='image';Image.open(io.BytesIO(base64.b64decode(blocks[1]['data']))).verify()
            passed('remote original-image transfer and native MCP image content')
            pdf=target+'/source.pdf';output=target+'/edited.pdf'
            created=c.call('document_write',{'host':a.host,'path':pdf,'format':'pdf','content':'# Original\nHello 中文\n<!-- pagebreak -->\n# Last','expected_sha256':'absent'})
            edited=c.call('pdf_edit',{'host':a.host,'path':pdf,'expected_sha256':created['sha256'],'output_path':output,'output_expected_sha256':'absent','operations':[{'type':'delete','page_indexes':[0]},{'type':'insert','page_index':0,'markdown':'# Inserted\nNew 中文'}]})
            assert edited['page_count']==2 and edited['source_unchanged']
            native=c.rpc('tools/call',{'name':'document_read','arguments':{'host':a.host,'path':output,'render':True,'length':2}})
            assert not native.get('isError');blocks=native['content'];meta=json.loads(blocks[0]['text'])
            assert 'Inserted' in meta['pages'][0]['text'] and 'Last' in meta['pages'][1]['text']
            assert len(blocks)==3 and all(x['type']=='image' for x in blocks[1:])
            for i,block in enumerate(blocks[1:]):
                image_data=base64.b64decode(block['data']);Image.open(io.BytesIO(image_data)).verify()
                if a.ssh_target=='localhost':
                    preview=pathlib.Path(a.out).with_name(pathlib.Path(a.out).stem+f'-page-{i}.jpg');preview.write_bytes(image_data)
            assert c.call('file_info',{'host':a.host,'path':pdf})['sha256']==created['sha256']
            passed('native remote PDF insert/delete, source preservation and actual page-image content')
            sheet=target+'/sheet.xlsx'
            created=c.call('document_write',{'host':a.host,'path':sheet,'format':'xlsx','content':{'Data':[['A','B'],[2,3],[4,'=SUM(A2:A3)']]},'expected_sha256':'absent'})
            edited=c.call('worksheet_edit',{'host':a.host,'path':sheet,'expected_sha256':created['sha256'],'sheet':'Data','range':'D5:E6','values':[['中文',7],[True,'=SUM(A2:A3)']]})
            assert edited['formula_caches_invalidated'] and not edited['formulas_recalculated']
            read=c.call('document_read',{'host':a.host,'path':sheet,'sheet':'Data','range':'D5:E6'})
            assert read['rows']==[['中文',7],[True,'=SUM(A2:A3)']]
            c.call('worksheet_edit',{'host':a.host,'path':sheet,'expected_sha256':created['sha256'],'sheet':'Data','range':'A1:A1','values':[['NO']]},denied=True)
            passed('remote worksheet range edit preserves formulas and invalidates stale caches')
            report.update(complete=True,passed=len(report['checks']),cloud_tested=False,recalculation_tested=False)
            pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('ALL_PASS',report['passed'],flush=True)
        finally:
            if controller is not None:controller.terminate();controller.wait(timeout=20)


if __name__=='__main__':main()
