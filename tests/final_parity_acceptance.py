#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Actual authenticated MCP rich formats, calculations and target metadata preservation.
Only disposable files; never changes account policy, business processes or DC.
"""
import argparse,base64,hashlib,io,json,os,pathlib,secrets,shlex,socket,subprocess,tempfile,time
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--parser',required=True);ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True);ap.add_argument('--host',default='operator');ap.add_argument('--url');ap.add_argument('--token-file');a=ap.parse_args()
    report={'checks':[],'complete':False,'ssh_target':a.ssh_target,'installed_endpoint':bool(a.url),'binary_sha256':hashlib.file_digest(open(a.binary,'rb'),'sha256').hexdigest()}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(name):report['checks'].append(name);save();print('PASS',name,flush=True)
    def ssh(code):
        p=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ForwardAgent=no','-o','ConnectTimeout=6',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=25)
        if p.returncode:raise RuntimeError(p.stderr)
        return json.loads(p.stdout)
    target='/tmp/hepta-final-parity-'+secrets.token_hex(12)
    meta=ssh("import pathlib,json,sys;p=pathlib.Path("+repr(target)+");p.mkdir(mode=0o700);print(json.dumps({'path':str(p.resolve()),'platform':'macos' if sys.platform=='darwin' else 'linux'}))");target=meta['path'];report['target_directory']=target
    with tempfile.TemporaryDirectory(prefix='hepta-final-controller-') as tmp:
        folder=pathlib.Path(tmp);workspace=folder/'workspace';workspace.mkdir();token=secrets.token_hex(32);(folder/'token').write_text(token);(folder/'token').chmod(0o600)
        host={'ssh_target':a.ssh_target,'platform':meta['platform'],'execution_mode':'operator','remote_state_dir':target+'/state','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[target],'allowed_write_path_prefixes':[target]}
        config={'state_dir':str(folder/'state'),'controller_workspace_roots':[str(workspace)],'hosts':{a.host:host}}
        (folder/'config.json').write_text(json.dumps(config))
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        controller=None
        if not a.url:
            with (folder/'controller.log').open('w') as log:
                controller=subprocess.Popen([a.binary,'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}','--runtime-config',str(folder/'config.json'),'--auth-token-file',str(folder/'token')],env={**os.environ,'HEPTA_RUNTIME_DOCUMENT_PYTHON':a.parser},stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            client=None
            for _ in range(100):
                if controller and controller.poll() is not None:raise RuntimeError((folder/'controller.log').read_text())
                try:client=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
                except (OSError,RuntimeError):time.sleep(.1)
            if client is None:raise RuntimeError('MCP unavailable')
            def call(name,params,denied=False):return client.call(name,{'host':a.host,**params},denied=denied)
            tools={x['name']:x for x in client.rpc('tools/list',{})['tools']}
            assert {'document_render','worksheet_recalculate'}<=tools.keys()
            for name in ('document_render','worksheet_recalculate'):assert not {'python','roots','file_helper','remote'} & tools[name]['inputSchema']['properties'].keys()
            passed('rich-format and calculation tools are native, typed and authority-bound')
            file=target+'/metadata.bin';call('binary_write',{'path':file,'data_base64':base64.b64encode(b'OLD').decode(),'expected_version':'absent'})
            def set_metadata(path):
                code="import os,sys,subprocess,json;p="+repr(path)+";os.chmod(p,0o640)\nif sys.platform=='darwin':\n subprocess.run(['/usr/bin/xattr','-w','com.hepta.fixture','opaque-value',p],check=True);subprocess.run(['/bin/chmod','+a','everyone allow read',p],check=True)\nelse:\n os.setxattr(p,'user.hepta.fixture',b'opaque\\0value');subprocess.run(['/usr/bin/setfacl','-m','u:65534:r--',p],check=True)\nprint(json.dumps({'fixture_metadata_applied':True}))"
                return ssh(code)
            set_metadata(file);before=call('file_info',{'path':file})
            call('binary_write',{'path':file,'data_base64':base64.b64encode(b'NEW').decode(),'expected_version':before['version']});after=call('file_info',{'path':file})
            assert before['metadata']==after['metadata'] and after['sha256']==hashlib.sha256(b'NEW').hexdigest()
            report['metadata_evidence']=after['metadata'];passed('native target ACL/xattrs/ownership/mode preserved through binary replacement')
            doc=target+'/metadata.docx';created=call('document_write',{'path':doc,'format':'docx','content':'# Title\nOld text','expected_sha256':'absent'});set_metadata(doc)
            before=call('file_info',{'path':doc});call('document_edit',{'path':doc,'expected_sha256':before['sha256'],'old_xml':'Old text','new_xml':'New text'})
            after=call('file_info',{'path':doc});assert before['metadata']==after['metadata'];assert 'New text' in str(call('document_read',{'path':doc}))
            passed('native remote document edit preserves the same target metadata')
            import xlwt
            book=xlwt.Workbook();sheet=book.add_sheet('Legacy');sheet.write(0,0,'中文');sheet.write(0,1,42);sheet.write(1,0,True);memory=io.BytesIO();book.save(memory)
            xls=target+'/legacy.xls';call('binary_write',{'path':xls,'data_base64':base64.b64encode(memory.getvalue()).decode(),'expected_version':'absent'})
            read=call('document_read',{'path':xls,'sheet':'0','range':'A1:B2'});assert read['rows'][0]==['中文',42.0] and read['formula_source_available'] is False
            passed('legacy XLS read returns real Unicode/scalar stored values without execution')
            xlsx=target+'/calculate.xlsx';created=call('document_write',{'path':xlsx,'format':'xlsx','content':{'Data':[[2,3],[4,'=SUM(A1:A2)']],'Other':[['=Data!B2*2','=IF(Data!B2=6,"ok","bad")']]},'expected_sha256':'absent'})
            result=call('worksheet_recalculate',{'path':xlsx,'expected_sha256':created['sha256']});assert result['formulas_recalculated'] and result['formula_count']==3
            values=call('document_read',{'path':xlsx,'sheet':'Other','range':'A1:B1','cached_values':True});assert values['rows']==[[12,'ok']]
            formulas=call('document_read',{'path':xlsx,'sheet':'Other','range':'A1:B1'});assert formulas['rows'][0][0]=='=Data!B2*2'
            call('worksheet_recalculate',{'path':xlsx,'expected_sha256':created['sha256']},denied=True)
            passed('real cross-sheet calculation writes correct caches and preserves formula text')
            from PIL import Image
            memory=io.BytesIO();Image.new('RGB',(80,40),(12,110,190)).save(memory,'PNG');asset=target+'/asset.png';payload=memory.getvalue()
            call('binary_write',{'path':asset,'expected_version':'absent','data_base64':base64.b64encode(payload).decode()})
            pdf=target+'/rich.pdf';content='<h1>Hepta Runtime 中文</h1><p class="box">HTML + CSS + SVG</p><img src="asset:picture"><svg width="130" height="50"><rect width="130" height="50" fill="#246"/></svg><div style="page-break-before:always"></div><h2>Second page</h2><table><tr><td>Metadata</td><td>Preserved</td></tr></table>'
            rendered=call('document_render',{'path':pdf,'input_format':'html','content':content,'css':'.box{border:2px solid #369;padding:8px;background:#eef}','assets':[{'name':'picture','path':asset,'sha256':hashlib.sha256(payload).hexdigest()}],'expected_sha256':'absent'})
            assert rendered['page_count']==2 and not rendered['network_resources_fetched']
            native=client.rpc('tools/call',{'name':'document_read','arguments':{'host':a.host,'path':pdf,'render':True,'length':2}})
            assert not native.get('isError');blocks=native['content'];assert len(blocks)==3
            text=json.loads(blocks[0]['text']);assert 'HTML + CSS + SVG' in text['pages'][0]['text']
            for index,block in enumerate(blocks[1:]):
                data=base64.b64decode(block['data']);Image.open(io.BytesIO(data)).verify()
                if a.ssh_target=='localhost':pathlib.Path(a.out).with_name(pathlib.Path(a.out).stem+f'-page-{index}.jpg').write_bytes(data)
            passed('HTML/CSS/inline-SVG and SHA-bound image assets render into two native PDF page images')
            call('document_render',{'path':target+'/blocked.pdf','input_format':'html','content':'<img src="https://example.invalid/no.png">','expected_sha256':'absent'},denied=True)
            call('file_info',{'path':target+'/blocked.pdf'},denied=True)
            report.update({'complete':True,'passed':len(report['checks']),'no_chatgpt_binding':True});save();print('FINAL_PARITY_PASS',report['passed'],flush=True)
        finally:
            if controller is not None:controller.terminate();controller.wait(timeout=20)


if __name__=='__main__':main()
