#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Check the actual installed MCP's 1904 TEXT correction using disposable files.
No worker imports or direct evaluation; every create/read/write/calculate goes
through the authenticated native endpoint. OOXML flag setup is byte-bound.
"""
import argparse
import base64
import hashlib
import io
import json
import pathlib
import tempfile
import zipfile
from runtime_http_acceptance import Client


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--url',required=True);ap.add_argument('--token-file',required=True);ap.add_argument('--host',default='main');ap.add_argument('--out',required=True);a=ap.parse_args()
    client=Client(a.url,pathlib.Path(a.token_file).read_text().strip())
    def call(name,args):return client.call(name,{'host':a.host,**args})
    formulas=[['=DATE(2026,10,6)','=TEXT(A1,"yyyy-mm-dd")','=TEXT(123.4,"0.00")','=TEXT(A1,"[>=45000]yyyy-mm-dd;0.00")','=TEXT(0.5,"hh:mm")','=VALUE("2026-10-06")','=VALUE("12:00")','=VALUE("12 PM")','=VALUE("12 AM")']]
    with tempfile.TemporaryDirectory(prefix='hepta-installed-calendar-') as tmp:
        path=str(pathlib.Path(tmp)/'calendar1904.xlsx')
        call('document_write',{'path':path,'format':'xlsx','content':{'Data':formulas},'expected_sha256':'absent'})
        raw=call('binary_read',{'path':path,'limit':65536});assert raw['eof']
        original=base64.b64decode(raw['data_base64'])
        with zipfile.ZipFile(io.BytesIO(original)) as z:parts={n:z.read(n) for n in z.namelist()}
        old=parts['xl/workbook.xml'];assert b'<workbookPr/>' in old
        parts['xl/workbook.xml']=old.replace(b'<workbookPr/>',b'<workbookPr date1904="1"/>')
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as z:
            for name,data in parts.items():z.writestr(name,data)
        changed=out.getvalue()
        written=call('binary_write',{'path':path,'expected_version':raw['version'],'data_base64':base64.b64encode(changed).decode()})
        assert written['sha256']==hashlib.sha256(changed).hexdigest()
        calc=call('worksheet_recalculate',{'path':path,'expected_sha256':written['sha256']})
        assert calc['workbook_date_system']=='1904' and calc['formulas_recalculated']
        cached=call('document_read',{'path':path,'sheet':'Data','range':'A1:I1','cached_values':True})['rows']
        assert cached==[[44839,'2026-10-06','123.40','44839.00','12:00',44839,0.5,0.5,0]],cached
        retained=call('document_read',{'path':path,'sheet':'Data','range':'A1:I1'})['rows'];assert retained==formulas
        next_path=str(pathlib.Path(tmp)/'calendar1900.xlsx')
        created=call('document_write',{'path':next_path,'format':'xlsx','content':{'Data':formulas},'expected_sha256':'absent'})
        call('worksheet_recalculate',{'path':next_path,'expected_sha256':created['sha256']})
        normal=call('document_read',{'path':next_path,'sheet':'Data','range':'A1:I1','cached_values':True})['rows']
        assert normal==[[46301,'2026-10-06','123.40','2026-10-06','12:00',46301,0.5,0.5,0]],normal
        report={'complete':True,'scope':'installed authenticated MCP create, byte-bound calendar setup, calculate and cached/formula reads','date1904_values':cached,'date1900_values':normal,'formula_text_preserved':True,'conditional_format_branch_uses_original_serial':True,'numeric_and_time_formats_not_offset':True,'no_business_document_touched':True,'value_time_has_no_ambient_date':True,'value_date_matches_workbook_epoch':True}
        pathlib.Path(a.out).write_text(json.dumps(report,indent=2)+'\n');print('INSTALLED_CALENDAR_TEXT_PASS '+json.dumps(report))


if __name__=='__main__':main()
