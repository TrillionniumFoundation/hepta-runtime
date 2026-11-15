#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real native MCP policy actions on disposable target documents and public anchors.
Uses synthetic signing keys only in memory; no keys are transferred to target hosts.
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
from pdf_policy_tests import certified_fixture


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--parser',required=True);ap.add_argument('--ssh-target',required=True);ap.add_argument('--out',required=True)
    ap.add_argument('--url');ap.add_argument('--token-file');ap.add_argument('--host',default='operator');a=ap.parse_args()
    with open(a.binary,'rb') as f:sha=hashlib.file_digest(f,'sha256').hexdigest()
    report={'complete':False,'checks':[],'binary_sha256':sha,'ssh_target':a.ssh_target,'installed_endpoint':bool(a.url),'real_signing_material_accessed':False}
    def save():pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    def passed(label):report['checks'].append(label);save();print('PASS '+label,flush=True)
    target='/tmp/hepta-policy-native-'+secrets.token_hex(12)
    code='import pathlib,json,sys;p=pathlib.Path('+repr(target)+');p.mkdir(mode=0o700);print(json.dumps({"root":str(p.resolve()),"platform":"macos" if sys.platform=="darwin" else "linux"}))'
    setup=subprocess.run(['ssh','-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes','-o','ConnectTimeout=8',a.ssh_target,'/usr/bin/python3 -c '+shlex.quote(code)],capture_output=True,text=True,timeout=20)
    if setup.returncode:raise RuntimeError(setup.stderr[-600:])
    selected=json.loads(setup.stdout);target=selected['root'];report['target_directory']=target
    with tempfile.TemporaryDirectory(prefix='hepta-policy-controller-') as directory:
        root=pathlib.Path(directory);(root/'workspace').mkdir();token=secrets.token_hex(32);(root/'token').write_text(token);(root/'token').chmod(0o600)
        host={'ssh_target':a.ssh_target,'platform':selected['platform'],'execution_mode':'operator','remote_state_dir':target+'/runtime','allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[target],'allowed_write_path_prefixes':[target]}
        (root/'config.json').write_text(json.dumps({'state_dir':str(root/'state'),'controller_workspace_roots':[str(root/'workspace')],'hosts':{a.host:host}}))
        with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
        controller=None
        if not a.url:
            with (root/'runtime.log').open('w') as log:
                controller=subprocess.Popen([a.binary,'mcp','--path',str(root/'workspace'),'--bind',f'127.0.0.1:{port}','--runtime-config',str(root/'config.json'),'--auth-token-file',str(root/'token')],env={**os.environ,'HEPTA_RUNTIME_DOCUMENT_PYTHON':a.parser},stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        try:
            c=None
            for _ in range(100):
                if controller and controller.poll() is not None:raise RuntimeError((root/'runtime.log').read_text()[-1000:])
                try:c=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
                except (OSError,RuntimeError):time.sleep(.1)
            if c is None:raise RuntimeError('MCP did not become ready')
            def call(name,args,denied=False):return c.call(name,{'host':a.host,**args},denied=denied)
            schema=next(t['inputSchema'] for t in c.rpc('tools/list',{})['tools'] if t['name']=='pdf_security')
            assert 'form_values' in schema['properties'] and not {'signing_key','private_key','allow_network','roots'}&schema['properties'].keys()
            passed('native PDF policy schema exposes form data but no signing keys or network/authority override')
            def put(name,data):
                path=target+'/'+name
                call('binary_write',{'path':path,'expected_version':'absent','data_base64':base64.b64encode(data).decode()})
                return path,hashlib.sha256(data).hexdigest()
            data,cert=certified_fixture();source,source_sha=put('certified.pdf',data);trust,trust_sha=put('root.pem',cert)
            request={'path':source,'expected_sha256':source_sha,'trust_store_file':trust,'trust_store_sha256':trust_sha}
            inspected=call('pdf_security',{**request,'action':'validate_policy'})
            assert inspected['all_present_signature_policies_pass'] and inspected['signature_policies'][0]['docmdp_permission']==2
            assert not inspected['revocation_evaluated'] and inspected['signature_policies'][0]['certificate_chain_valid']
            passed('actual CMS integrity, caller-anchor chain and certification policy are separately verified')
            result=call('pdf_security',{**request,'action':'fill_form_copy','form_values':{'Editable':'Approved 42'},'allow_unsigned_revision':True,'output_path':target+'/filled.pdf','output_expected_sha256':'absent'})
            assert result['source_unchanged'] and not result['new_revision_is_signed'] and result['output_policy']['all_present_signature_policies_pass']
            part=call('binary_read',{'path':target+'/filled.pdf','limit':262144});assert part['eof'];filled=base64.b64decode(part['data_base64']);assert filled.startswith(data)
            from pypdf import PdfReader
            assert PdfReader(io.BytesIO(filled)).get_form_text_fields()=={'Editable':'Approved 42','Locked':'Keep'}
            rendered=c.rpc('tools/call',{'name':'document_read','arguments':{'host':a.host,'path':target+'/filled.pdf','render':True,'length':1}})
            assert not rendered.get('isError');images=[x for x in rendered['content'] if x['type']=='image'];assert len(images)==1
            if a.ssh_target=='localhost':pathlib.Path(a.out).with_suffix('.jpg').write_bytes(base64.b64decode(images[0]['data']))
            assert call('file_info',{'path':source})['sha256']==source_sha
            passed('permitted form-only derived revision retains signature prefix, actual form values and rendered page')
            for name,permission,locked,values in [('nochanges',1,False,{'Editable':'No'}),('fieldlock',2,True,{'Locked':'No'})]:
                original,cert=certified_fixture(permission=permission,locked=locked);path,sha=put(name+'.pdf',original);anchor,digest=put(name+'.pem',cert)
                call('pdf_security',{'path':path,'expected_sha256':sha,'action':'fill_form_copy','form_values':values,'allow_unsigned_revision':True,'output_path':target+'/'+name+'-denied.pdf','output_expected_sha256':'absent','trust_store_file':anchor,'trust_store_sha256':digest},denied=True)
                call('file_info',{'path':target+'/'+name+'-denied.pdf'},denied=True)
                assert call('file_info',{'path':path})['sha256']==sha
                passed(name+' policy refuses prohibited editing without publishing or changing the original')
            from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
            from pyhanko.pdf_utils import generic
            writer=IncrementalPdfFileWriter(io.BytesIO(data));ref,_=writer.find_page_for_modification(0);page=ref.get_object();page[generic.pdf_name('/MediaBox')]=generic.ArrayObject([generic.NumberObject(x) for x in (0,0,600,900)]);writer.mark_update(ref)
            stream=io.BytesIO();writer.write(stream);bad,bad_sha=put('page-modified.pdf',stream.getvalue())
            assessed=call('pdf_security',{**request,'path':bad,'expected_sha256':bad_sha,'action':'validate_policy'})
            assert assessed['signature_integrity']['signatures'][0]['integrity']=='valid' and not assessed['all_present_signature_policies_pass']
            passed('forbidden page change is detected even while original detached CMS byte integrity remains valid')
            call('pdf_security',{**request,'action':'validate_policy','trust_store_sha256':'0'*64},denied=True)
            _,other=certified_fixture();other_path,other_sha=put('unrelated.pem',other)
            call('pdf_security',{**request,'action':'fill_form_copy','trust_store_file':other_path,'trust_store_sha256':other_sha,'form_values':{'Editable':'No'},'allow_unsigned_revision':True,'output_path':target+'/wrong-root.pdf','output_expected_sha256':'absent'},denied=True)
            passed('stale trust material and an unrelated root cannot authorize publication')
            report.update(complete=True,passed=len(report['checks']),old_signature_signs_filled_values=False,cloud_binding_used=False)
            save();print('PDF_POLICY_NATIVE_PASS',report['passed'],flush=True)
        finally:
            if controller is not None:controller.terminate();controller.wait(timeout=20)
            save()


if __name__=='__main__':main()
