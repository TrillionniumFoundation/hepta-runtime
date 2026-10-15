#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real authenticated MCP native-document qualification on disposable local files."""
import argparse
import base64
import hashlib
import io
import json
import os
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time
import zipfile
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--binary',required=True);ap.add_argument('--parser',required=True);ap.add_argument('--out',required=True);ap.add_argument('--keep-fixtures',action='store_true');ap.add_argument('--url');ap.add_argument('--token-file')
    a=ap.parse_args();report={'checks':[],'complete':False,'scope':'controller-local native documents and images','binary_sha256':hashlib.file_digest(open(a.binary,'rb'),'sha256').hexdigest()}
    def passed(name):
        report['checks'].append(name);pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('PASS',name,flush=True)
    folder=pathlib.Path(tempfile.mkdtemp(prefix='hepta-document-mcp-'));workspace=folder/'workspace';workspace.mkdir()
    token=secrets.token_hex(32);(folder/'token').write_text(token);(folder/'token').chmod(0o600)
    config={'state_dir':str(folder/'state'),'controller_workspace_roots':[str(workspace)],'hosts':{'operator':{'ssh_target':'localhost','execution_mode':'operator','remote_state_dir':str(folder/'target'),'allow_execute':True,'allow_pty':True,'allow_write':True,'allow_job_network':True,'allow_detached_fallback':True,'allowed_read_path_prefixes':[str(workspace)],'allowed_write_path_prefixes':[str(workspace)]}}}
    (folder/'config.json').write_text(json.dumps(config))
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env={**os.environ,'HEPTA_RUNTIME_DOCUMENT_PYTHON':a.parser}
    controller=None
    if not a.url:
      with (folder/'controller.log').open('w') as log:
        controller=subprocess.Popen([a.binary,'mcp','--path',str(workspace),'--bind',f'127.0.0.1:{port}','--runtime-config',str(folder/'config.json'),'--auth-token-file',str(folder/'token')],env=env,stdin=subprocess.DEVNULL,stdout=log,stderr=log)
    try:
        client=None
        for _ in range(100):
            if controller is not None and controller.poll() is not None:raise RuntimeError((folder/'controller.log').read_text())
            try:client=Client(a.url or f'http://127.0.0.1:{port}/mcp',pathlib.Path(a.token_file).read_text().strip() if a.url else token);break
            except (OSError,RuntimeError):time.sleep(.1)
        if client is None:raise RuntimeError('canary endpoint unavailable')
        tools={x['name']:x for x in client.rpc('tools/list',{})['tools']}
        assert {'document_read','document_write','document_edit','image_read'}<=tools.keys()
        assert 'roots' not in tools['document_read']['inputSchema']['properties']
        passed('authenticated native tool discovery without caller authority overrides')
        path=workspace/'sample.docx'
        created=client.call('document_write',{'path':str(path),'format':'docx','content':'# 测试标题\nOld paragraph\nUnchanged paragraph','expected_sha256':'absent'})
        outline=client.call('document_read',{'path':str(path)})
        assert 'Old paragraph' in str(outline) and created['sha256']==hashlib.sha256(path.read_bytes()).hexdigest()
        passed('native DOCX create and text-bearing outline with verified output SHA256')
        xml=client.call('document_read',{'path':str(path),'xml_part':'word/document.xml','offset':1,'length':100})
        assert '<w:t>Old paragraph</w:t>' in '\n'.join(xml['lines'])
        with zipfile.ZipFile(path) as z:before={name:z.read(name) for name in z.namelist()}
        changed=client.call('document_edit',{'path':str(path),'expected_sha256':created['sha256'],'old_xml':'<w:t>Old paragraph</w:t>','new_xml':'<w:t>New paragraph</w:t>','expected_replacements':1})
        with zipfile.ZipFile(path) as z:
            assert all(z.read(name)==data for name,data in before.items() if name!='word/document.xml')
        assert changed['unselected_zip_payloads_preserved']
        passed('native DOCX XML edit preserves every unselected package payload')
        client.call('document_edit',{'path':str(path),'expected_sha256':created['sha256'],'old_xml':'New paragraph','new_xml':'BAD'},denied=True)
        client.call('document_edit',{'path':str(path),'expected_sha256':changed['sha256'],'old_xml':'<w:t>New paragraph</w:t>','new_xml':'<w:t>bad'},denied=True)
        assert hashlib.sha256(path.read_bytes()).hexdigest()==changed['sha256']
        passed('stale version and malformed XML rejected without changing the document')
        from PIL import Image
        image=workspace/'fixture.png';Image.new('RGB',(96,48),(20,140,200)).save(image)
        native=client.rpc('tools/call',{'name':'image_read','arguments':{'path':str(image)}})
        assert not native.get('isError')
        blocks=native['content'];metadata=json.loads(blocks[0]['text'])
        assert metadata['width']==96 and blocks[1]['type']=='image' and blocks[1]['mimeType']=='image/jpeg'
        Image.open(io.BytesIO(base64.b64decode(blocks[1]['data']))).verify()
        (workspace/'image-preview.jpg').write_bytes(base64.b64decode(blocks[1]['data']))
        passed('native MCP image content, dimensions and valid preview encoding')
        pdf=workspace/'sample.pdf'
        created=client.call('document_write',{'path':str(pdf),'format':'pdf','content':'# First page\nHello 中文\n<!-- pagebreak -->\n# Second page\nWorld','expected_sha256':'absent'})
        native=client.rpc('tools/call',{'name':'document_read','arguments':{'path':str(pdf),'render':True,'offset':0,'length':2}})
        assert not native.get('isError');blocks=native['content'];info=json.loads(blocks[0]['text'])
        assert info['page_count']==2 and len(blocks)==3 and all(b['type']=='image' for b in blocks[1:])
        assert 'First page' in info['pages'][0]['text'] and 'Second page' in info['pages'][1]['text']
        for index,block in enumerate(blocks[1:]):
            data=base64.b64decode(block['data']);Image.open(io.BytesIO(data)).verify();(workspace/f'pdf-page-{index}.jpg').write_bytes(data)
        passed('native PDF creation, page text and two rendered MCP page images')
        xlsx=workspace/'sample.xlsx'
        client.call('document_write',{'path':str(xlsx),'format':'xlsx','content':{'Sheet1':[['Name','Value'],['A',2],['B',3],['Total','=SUM(B2:B3)']]},'expected_sha256':'absent'})
        rows=client.call('document_read',{'path':str(xlsx),'sheet':'Sheet1','range':'A1:B4'})
        assert rows['rows'][3][1]=='=SUM(B2:B3)' and rows['formulas_recalculated'] is False
        passed('native XLSX create and bounded formula-preserving range read')
        outside=folder/'outside.pdf';outside.write_bytes(pdf.read_bytes())
        if not a.url:
            client.call('document_read',{'path':str(outside)},denied=True)
        else:
            client.call('document_write',{'path':str(workspace/'..'/'invalid.docx'),'format':'docx','content':'invalid traversal','expected_sha256':'absent'},denied=True)
        client.call('document_write',{'path':str(pdf),'format':'pdf','content':'BAD','expected_sha256':'absent'},denied=True)
        assert hashlib.sha256(pdf.read_bytes()).hexdigest()==created['sha256']
        passed('configured local-root and create-only guards remain enforced')
        report.update({'complete':True,'passed':len(report['checks']),'fixture_workspace':str(workspace),'parser':a.parser,'installed_endpoint':bool(a.url),'remote_document_scope_tested':False,'full_dc_document_contract_equivalence':False})
        pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('ALL_PASS',report['passed'],flush=True)
    finally:
        if controller is not None:controller.terminate();controller.wait(timeout=15)
        if not a.keep_fixtures:
            import shutil;shutil.rmtree(folder)


if __name__=='__main__':main()
