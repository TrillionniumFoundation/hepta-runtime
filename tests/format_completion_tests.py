#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real rich-PDF, XLS and cache-only formula fixtures; no office process or URLs."""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import pathlib
import tempfile
import unittest
import zipfile

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('format_worker',ROOT/'src/mcp/runtime/document_local.py')
D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)


class Completion(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-formats-test-');self.root=pathlib.Path(self.temp.name).resolve()
    def tearDown(self):
        result=self._outcome.result
        failed=any(test is self for test,_ in result.failures+result.errors)
        artifacts=os.environ.get('HEPTA_TEST_ARTIFACTS_DIR')
        if failed and artifacts:
            target=pathlib.Path(artifacts)/self._testMethodName
            shutil.copytree(self.root,target,dirs_exist_ok=True)
        self.temp.cleanup()
    def call(self,op,**params):
        q={'op':op,'roots':[str(self.root)],**params}
        blocks=D.main(q);return json.loads(blocks[0]['text']),blocks
    def render(self,content,input_format='html',**extra):
        return self.call('render_rich',path=str(self.root/'render.pdf'),input_format=input_format,content=content,
                         expected_sha256='absent',assets=[],**extra)
    def workbook(self,contents):
        p=self.root/'book.xlsx';p.write_bytes(D.create_bytes('xlsx',contents));return p
    def calculate(self,p):
        return self.call('worksheet_recalculate',path=str(p),expected_sha256=hashlib.sha256(p.read_bytes()).hexdigest())
    def test_rich_html_css_inline_svg_and_pagebreak(self):
        content='<html><body><h1>Rich 中文</h1><p class="box">Styled document</p><svg width="100" height="40"><rect width="100" height="40" fill="blue"/></svg><div style="page-break-before:always"></div><h2>Second page</h2><table><tr><td>A</td><td>B</td></tr></table></body></html>'
        result,_=self.render(content,css='.box{border:2px solid #126;padding:8px;background:#eef} h1{color:#126}')
        self.assertEqual(result['page_count'],2);self.assertFalse(result['network_resources_fetched'])
        parsed,blocks=self.call('read',path=result['path'],render=True,length=2)
        self.assertEqual(len(blocks),3);self.assertIn('Styled document',parsed['pages'][0]['text']);self.assertIn('Second page',parsed['pages'][1]['text'])
    def test_markdown_tables_and_code_render(self):
        result,_=self.render('# Markdown\n\n|Name|Value|\n|---|---|\n|Alpha|42|\n\n```text\nconsole output\n```',input_format='markdown')
        parsed,_=self.call('read',path=result['path'])
        self.assertIn('Alpha',str(parsed));self.assertIn('console output',str(parsed))
    def test_declared_asset_is_fingerprint_bound(self):
        from PIL import Image
        p=self.root/'asset.png';Image.new('RGB',(40,20),(11,80,120)).save(p)
        asset={'name':'diagram','path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
        result,_=self.call('render_rich',path=str(self.root/'assets.pdf'),input_format='html',content='<img src="asset:diagram"><p>Asset page</p>',expected_sha256='absent',assets=[asset])
        self.assertEqual(len(result['asset_fingerprints']),1)
        with self.assertRaises(ValueError):self.call('render_rich',path=str(self.root/'wrong.pdf'),input_format='html',content='<img src="asset:diagram">',expected_sha256='absent',assets=[{**asset,'sha256':'0'*64}])
        self.assertFalse((self.root/'wrong.pdf').exists())
    def test_external_and_undeclared_resource_fails_without_output(self):
        for content in ['<img src="https://example.invalid/x.png">','<img src="file:///etc/passwd">','<style>@import url("https://example.invalid/a.css");</style><p>No</p>','<svg width="100" height="20"><image href="https://example.invalid/x.png"/></svg>','<img src="asset:missing">']:
            with self.assertRaises(Exception):self.render(content)
            self.assertFalse((self.root/'render.pdf').exists())
    def test_active_html_and_existing_destination_rejected(self):
        for content in ['<script>alert(1)</script>','<iframe src="file:///etc/passwd"></iframe>','<p onclick="x">No</p>']:
            with self.assertRaises(ValueError):self.render(content)
        path=self.root/'render.pdf';path.write_bytes(b'keep')
        with self.assertRaises(ValueError):self.render('<p>No overwrite</p>')
        self.assertEqual(path.read_bytes(),b'keep')
    def test_legacy_xls_reads_unicode_dates_values_not_macros(self):
        import datetime,xlwt
        path=self.root/'legacy.xls';b=xlwt.Workbook();s=b.add_sheet('Legacy');s.write(0,0,'中文');s.write(0,1,42);s.write(1,0,True);s.write(1,1,datetime.datetime(2026,10,6),xlwt.easyxf(num_format_str='YYYY-MM-DD'));b.save(str(path))
        sha=hashlib.sha256(path.read_bytes()).hexdigest()
        result,_=self.call('read',path=str(path),sheet='0',range='A1:B2')
        self.assertEqual(result['rows'][0],['中文',42.0]);self.assertTrue(result['rows'][1][0]);self.assertIn('2026-10-06',result['rows'][1][1])
        self.assertFalse(result['formula_source_available']);self.assertFalse(result['formulas_recalculated']);self.assertEqual(sha,hashlib.sha256(path.read_bytes()).hexdigest())
    def test_recalculation_updates_dependent_cross_sheet_caches_and_keeps_formulas(self):
        path=self.workbook({'Data':[['A','B'],[2,3],[4,'=SUM(A2:A3)'],['Test','=IF(B3=6,"ok","bad")']], 'Other Sheet':[["=Data!B3*2",'=SUM(Data!A2:A3)+1']]})
        with zipfile.ZipFile(path) as z:before={n:z.read(n) for n in z.namelist()}
        result,_=self.calculate(path);self.assertTrue(result['formulas_recalculated']);self.assertEqual(result['formula_count'],4)
        formula,_=self.call('read',path=str(path),sheet='Data',range='B3:B4');self.assertEqual(formula['rows'],[['=SUM(A2:A3)'],['=IF(B3=6,"ok","bad")']])
        cached,_=self.call('read',path=str(path),sheet='Data',range='B3:B4',cached_values=True);self.assertEqual(cached['rows'],[[6],['ok']])
        other,_=self.call('read',path=str(path),sheet='Other Sheet',range='A1:B1',cached_values=True);self.assertEqual(other['rows'],[[12,7]])
        with zipfile.ZipFile(path) as z:
            for name,data in before.items():
                if name not in result['changed_parts']:self.assertEqual(z.read(name),data)
    def test_boolean_blank_and_error_results_are_explicit(self):
        path=self.workbook({'Sheet1':[[2,None,'=SUM(A1:B1)','=COUNT(A1:B1)','=A1>1','=1/0']]})
        result,_=self.calculate(path)
        cached,_=self.call('read',path=str(path),range='C1:F1',cached_values=True)
        self.assertEqual(cached['rows'],[[2,1,True,'#DIV/0!']]);self.assertEqual(result['formula_error_count'],1)
    def test_cycles_external_dynamic_unknown_formula_fail_without_write(self):
        cases=[{'S':[['=B1','=A1']]},{'S':[['=WEBSERVICE("https://example.invalid")']]},{'S':[['=INDIRECT("A2")']]},{'S':[['=NOT_A_FUNCTION(1)']]},{'S':[["='[external.xlsx]S'!A1"]]}]
        for contents in cases:
            path=self.workbook(contents);before=path.read_bytes()
            with self.assertRaises(ValueError):self.calculate(path)
            self.assertEqual(path.read_bytes(),before)
    def test_stale_calculation_and_shared_formulas_fail_closed(self):
        path=self.workbook({'S':[[2,'=A1+1']]});before=path.read_bytes()
        with self.assertRaises(ValueError):self.call('worksheet_recalculate',path=str(path),expected_sha256='0'*64)
        self.assertEqual(path.read_bytes(),before)
        with zipfile.ZipFile(path) as z:parts={n:z.read(n) for n in z.namelist()}
        part='xl/worksheets/sheet1.xml';parts[part]=parts[part].replace(b'<f>',b'<f t="shared" si="0">')
        with zipfile.ZipFile(path,'w') as z:
            for n,data in parts.items():z.writestr(n,data)
        before=path.read_bytes()
        with self.assertRaises(ValueError):self.calculate(path)
        self.assertEqual(path.read_bytes(),before)

    def test_literal_error_text_is_not_an_excel_error_cell(self):
        from lxml import etree
        path=self.workbook({'S':[['=1/0','=IFERROR(A1,7)','=A1+1','=SUM(A1)','=\"#N/A\"','=IFERROR(E1,9)']]})
        result,_=self.calculate(path)
        with zipfile.ZipFile(path) as z:tree=etree.fromstring(z.read('xl/worksheets/sheet1.xml'))
        ns={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
        cells={c.get('r'):c for c in tree.findall('.//s:c',ns)}
        self.assertEqual(cells['A1'].get('t'),'e')
        self.assertEqual(cells['E1'].get('t'),'str')
        self.assertEqual(cells['F1'].get('t'),'str')
        self.assertEqual(result['formula_error_count'],3)
        self.assertEqual(cells['B1'].find('s:v',ns).text,'7')


    def test_1904_date_system_is_not_recalculated_with_1900_semantics(self):
        path=self.workbook({'S':[['=DATE(2026,10,6)']]})
        with zipfile.ZipFile(path) as z:parts={n:z.read(n) for n in z.namelist()}
        parts['xl/workbook.xml']=parts['xl/workbook.xml'].replace(b'<workbookPr/>',b'<workbookPr date1904="1"/>')
        with zipfile.ZipFile(path,'w') as z:
            for n,data in parts.items():z.writestr(n,data)
        before=path.read_bytes()
        with self.assertRaisesRegex(ValueError,'1904'):self.calculate(path)
        self.assertEqual(before,path.read_bytes())



if __name__=='__main__':unittest.main(verbosity=2)
