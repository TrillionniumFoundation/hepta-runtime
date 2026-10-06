#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Reconcile the exact disposable fixtures left by a recorded SSH timeout.
No new upload identity, blind document rewrite, or business path is permitted.
"""
import argparse
import base64
import hashlib
import json
import pathlib
import re
import sys
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--matrix',required=True);ap.add_argument('--out',required=True);a=ap.parse_args()
    m=json.loads(pathlib.Path(a.matrix).read_text());conf=pathlib.Path.home()/'.config/hepta-runtime-operator'
    c=Client('http://127.0.0.1:8790/mcp',(conf/'token').read_text().strip())
    x=next(r for r in m['results'] if r['host']=='x230');assert x['native']['exit_code']!=0
    path=x['native']['report']['target_directory']
    match=re.fullmatch(r'/tmp/hepta-native-transport-([0-9a-f]{24})',path)
    if not match:raise ValueError('not the recorded disposable native-test path')
    data=bytes(range(256))*(20*1024)+b'END';expected=hashlib.sha256(data).hexdigest();dest=path+'/large.bin'
    info=c.rpc('tools/call',{'name':'file_info','arguments':{'host':'x230','path':dest}})
    already=False
    if info.get('isError'):
        text=' '.join(b.get('text','') for b in info['content'])
        if 'No such file' not in text:raise RuntimeError(text)
        for offset in range(0,len(data),1024*1024):
            result=c.call('binary_upload',{'host':'x230','path':dest,'action':'chunk','upload_id':'upload-'+match.group(1),
                    'offset':offset,'expected_version':'absent','data_base64':base64.b64encode(data[offset:offset+1024*1024]).decode()})
            assert result['next_offset']==min(len(data),offset+1024*1024)
        result=c.call('binary_upload',{'host':'x230','path':dest,'action':'commit','upload_id':'upload-'+match.group(1),'size':len(data),'sha256':expected})
        assert result['sha256']==expected
    else:
        result=json.loads(next(b['text'] for b in info['content'] if b['type']=='text'))
        assert result['size']==len(data) and result['sha256']==expected
        already=True
    final=c.call('file_info',{'host':'x230','path':dest});assert final['sha256']==expected and final['size']==len(data)
    ai=next(r for r in m['results'] if r['host']=='ai395');assert ai['native']['exit_code']!=0
    ai_path=ai['native']['report']['target_directory']
    if not re.fullmatch(r'/tmp/hepta-native-transport-[0-9a-f]{24}',ai_path):raise ValueError('unexpected AI395 fixture path')
    read=c.call('document_read',{'host':'ai395','path':ai_path+'/remote.docx'})
    assert 'Updated paragraph' in str(read)
    report={'complete':True,'original_matrix_sha256':hashlib.sha256(pathlib.Path(a.matrix).read_bytes()).hexdigest(),
            'x230_same_upload_identity':True,'x230_upload_id':'upload-'+match.group(1),'x230_destination':dest,
            'x230_already_published_before_recovery':already,'x230_final_size':len(data),'x230_final_sha256':expected,
            'ai395_timed_out_read_reconciled':True,'ai395_existing_edit_read_without_rewrite':True,
            'new_business_commands_started':False,'only_recorded_disposable_fixtures_touched':True}
    pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n')
    print('TRANSPORT_RECONCILIATION_PASS same upload identity, complete hash, existing DOCX read')


if __name__=='__main__':main()
