#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native PDF edit and remote transaction tests using disposable documents."""
import hashlib
import importlib.util
import json
import pathlib
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'src/mcp/runtime'/file)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
DOC=module('extended_doc','document_local.py')
BINARY=module('extended_binary','binary_file.py')


class ExtendedDocuments(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-extended-doc-')
        self.root=pathlib.Path(self.temp.name).resolve()
        self.source=self.root/'source.pdf';self.output=self.root/'output.pdf'
        self.source.write_bytes(DOC.create_bytes('pdf','# FIRST\nOriginal 中文\n<!-- pagebreak -->\n# LAST'))
        self.sha=hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.remote_original=DOC.remote_call

    def tearDown(self):
        DOC.remote_call=self.remote_original;self.temp.cleanup()

    def edit(self,operations,**values):
        q={'roots':[str(self.root)],'op':'pdf_edit','path':str(self.source),'expected_sha256':self.sha,
           'output_path':str(self.output),'output_expected_sha256':'absent','operations':operations,**values}
        return json.loads(DOC.main(q)[0]['text'])

    def test_pdf_insert_delete_preserves_source_and_renders(self):
        result=self.edit([{'type':'delete','page_indexes':[0]},
                          {'type':'insert','page_index':0,'markdown':'# INSERTED\nNew 中文'}])
        self.assertEqual(result['page_count'],2);self.assertTrue(result['source_unchanged'])
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.sha)
        blocks=DOC.main({'roots':[str(self.root)],'op':'read','path':str(self.output),'render':True,'length':2})
        self.assertEqual(len(blocks),3)
        info=json.loads(blocks[0]['text'])
        self.assertIn('INSERTED',info['pages'][0]['text']);self.assertIn('LAST',info['pages'][1]['text'])
        self.assertFalse(result['page_deletion_is_secure_redaction'])

    def test_pdf_source_file_insert_requires_source_hash(self):
        part=self.root/'part.pdf';part.write_bytes(DOC.create_bytes('pdf','# SOURCE_PART'))
        op={'type':'insert','page_index':1,'source_path':str(part),'source_sha256':hashlib.sha256(part.read_bytes()).hexdigest()}
        self.edit([op])
        pages=DOC.main({'roots':[str(self.root)],'op':'read','path':str(self.output),'length':3})
        self.assertIn('SOURCE_PART',json.loads(pages[0]['text'])['pages'][1]['text'])
        with self.assertRaises(ValueError):self.edit([{**op,'source_sha256':'0'*64}],output_path=str(self.root/'wrong.pdf'))

    def test_invalid_pdf_requests_preserve_every_file(self):
        for op in ({'type':'delete','page_indexes':[99]}, {'type':'delete','page_indexes':[0,0]},
                   {'type':'delete','page_indexes':[0,1]}, {'type':'insert','page_index':99,'markdown':'Wrong'}):
            with self.assertRaises(ValueError):self.edit([op])
            self.assertFalse(self.output.exists())
        with self.assertRaises(ValueError):self.edit([{'type':'delete','page_indexes':[0]}],output_path=str(self.source))
        with self.assertRaises(ValueError):self.edit([{'type':'delete','page_indexes':[0]}],expected_sha256='0'*64)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.sha)

    def test_create_only_output_cannot_replace_existing_document(self):
        self.output.write_bytes(b'KEEP_EXISTING')
        with self.assertRaises(ValueError):self.edit([{'type':'delete','page_indexes':[0]}])
        self.assertEqual(self.output.read_bytes(),b'KEEP_EXISTING')

    def remote(self):
        def direct(q,op,path,**fields):return BINARY.main({'root':str(self.root),'path':path,'op':op,**fields})
        DOC.remote_call=direct
        return {'host':'test','remote':{'read_roots':[str(self.root)],'write_roots':[str(self.root)]},'file_helper':'fixed-test-helper'}

    def test_remote_docx_create_read_edit_transaction(self):
        transport=self.remote();path=self.root/'remote.docx'
        base={**transport,'path':str(path)}
        created=json.loads(DOC.main({**base,'op':'write','format':'docx','content':'# Header\nOld text','expected_sha256':'absent'})[0]['text'])
        self.assertEqual(created['path'],str(path));self.assertIn('publication_version',created)
        outline=DOC.main({**base,'op':'read'})
        self.assertIn('Old text',str(outline))
        changed=DOC.main({**base,'op':'edit_docx','expected_sha256':created['sha256'],'old_xml':'Old text','new_xml':'Changed text'})
        self.assertEqual(json.loads(changed[0]['text'])['host'],'test')
        self.assertIn('Changed text',str(DOC.main({**base,'op':'read'})))
        with self.assertRaises(ValueError):DOC.main({**base,'op':'edit_docx','expected_sha256':created['sha256'],'old_xml':'Changed','new_xml':'NO'})

    def test_remote_pdf_transaction_uses_distinct_output(self):
        result=self.edit([{'type':'delete','page_indexes':[0]}],**self.remote())
        self.assertEqual(result['path'],str(self.output));self.assertEqual(result['source_path'],str(self.source))
        self.assertEqual(result['page_count'],1)
        self.assertEqual(hashlib.sha256(self.source.read_bytes()).hexdigest(),self.sha)

    def test_remote_pdf_second_source_is_transferred_and_bound(self):
        part=self.root/'second.pdf';part.write_bytes(DOC.create_bytes('pdf','# REMOTE_PART'))
        result=self.edit([{'type':'insert','page_index':1,'source_path':str(part),'source_sha256':hashlib.sha256(part.read_bytes()).hexdigest()}],**self.remote())
        self.assertEqual(result['page_count'],3)
        self.assertIn('REMOTE_PART',str(DOC.main({**self.remote(),'op':'read','path':str(self.output),'length':3})))


    def test_worksheet_edit_preserves_unselected_parts_and_styles(self):
        import io,zipfile
        path=self.root/'cells.xlsx'
        path.write_bytes(DOC.create_bytes('xlsx',{'Data':[['Name','Value'],['A',2],['Total','=B2*2']],'Other':[['KEEP']]}))
        with zipfile.ZipFile(path) as z:before={n:z.read(n) for n in z.namelist()}
        sha=hashlib.sha256(path.read_bytes()).hexdigest()
        result=json.loads(DOC.main({'op':'worksheet_edit','roots':[str(self.root)],'path':str(path),'expected_sha256':sha,
            'sheet':'Data','range':'D7:E8','values':[[' leading spaces ',7],[True,'=SUM(B2:B3)']]})[0]['text'])
        self.assertTrue(result['formula_caches_invalidated']);self.assertFalse(result['formulas_recalculated'])
        with zipfile.ZipFile(path) as z:
            for name,payload in before.items():
                if name not in result['changed_parts']:self.assertEqual(z.read(name),payload,name)
        read=json.loads(DOC.main({'op':'read','roots':[str(self.root)],'path':str(path),'sheet':'Data','range':'D7:E8'})[0]['text'])
        self.assertEqual(read['rows'],[[' leading spaces ',7],[True,'=SUM(B2:B3)']])
        cached=json.loads(DOC.main({'op':'read','roots':[str(self.root)],'path':str(path),'sheet':'Data','range':'E8:E8','cached_values':True})[0]['text'])
        self.assertEqual(cached['rows'],[[None]])

    def test_remote_worksheet_edit_and_stale_write_rejection(self):
        path=self.root/'remote.xlsx';path.write_bytes(DOC.create_bytes('xlsx',{'Sheet1':[[1,2]]}))
        sha=hashlib.sha256(path.read_bytes()).hexdigest()
        q={**self.remote(),'op':'worksheet_edit','path':str(path),'expected_sha256':sha,'sheet':'0','range':'A1:B1','values':[[3,4]]}
        result=json.loads(DOC.main(q)[0]['text']);self.assertIn('publication_version',result)
        read=json.loads(DOC.main({**self.remote(),'op':'read','path':str(path),'sheet':'0','range':'A1:B1'})[0]['text'])
        self.assertEqual(read['rows'],[[3,4]])
        with self.assertRaises(ValueError):DOC.main(q)

    def test_invalid_worksheet_ranges_and_merges_leave_source_unchanged(self):
        import io,zipfile
        path=self.root/'merge.xlsx';path.write_bytes(DOC.create_bytes('xlsx',{'Data':[[1,2],[3,4]]}))
        sha=hashlib.sha256(path.read_bytes()).hexdigest()
        q={'op':'worksheet_edit','roots':[str(self.root)],'path':str(path),'expected_sha256':sha,'sheet':'Data','range':'A1:B1','values':[[8,9]]}
        for extra in ({'range':'A0:B1'},{'values':[[1]]},{'sheet':'missing'},{'range':'B1:A1'}):
            with self.assertRaises((ValueError,TypeError)):DOC.main({**q,**extra})
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),sha)
        with zipfile.ZipFile(path) as z:
            data={n:z.read(n) for n in z.namelist()}
        name='xl/worksheets/sheet1.xml';data[name]=data[name].replace(b'</worksheet>',b'<mergeCells count="1"><mergeCell ref="A1:B1"/></mergeCells></worksheet>')
        with zipfile.ZipFile(path,'w') as z:
            for name,payload in data.items():z.writestr(name,payload)
        sha=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):DOC.main({**q,'expected_sha256':sha})
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),sha)


if __name__=='__main__':unittest.main(verbosity=2)
