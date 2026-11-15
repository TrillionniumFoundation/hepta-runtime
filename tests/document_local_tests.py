#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Native document fixture tests. No network, arbitrary commands or production files."""
import base64
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile

HELPER=pathlib.Path(__file__).resolve().parents[1]/'src/mcp/runtime/document_local.py'


class Documents(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-native-doc-test-')
        self.root=pathlib.Path(self.temp.name)/'work';self.root.mkdir()

    def tearDown(self):self.temp.cleanup()

    def call(self,op,path,fail=False,**data):
        q={'op':op,'path':str(path),'roots':[str(self.root)],**data}
        p=subprocess.run([sys.executable,'-I',str(HELPER)],input=json.dumps(q),text=True,capture_output=True,timeout=45)
        if fail:
            self.assertNotEqual(p.returncode,0,p.stdout);return p.stderr
        self.assertEqual(p.returncode,0,p.stderr)
        content=json.loads(p.stdout)
        return json.loads(content[0]['text']),content[1:]

    def create(self,name,fmt,content):
        path=self.root/name
        result,_=self.call('write',path,format=fmt,content=content,expected_sha256='absent')
        return path,result

    def test_docx_outline_and_precise_edit_preserve_other_parts(self):
        path,created=self.create('source.docx','docx','# 标题\nOld body\nFinal line')
        outline,_=self.call('read',path)
        self.assertIn('Old body',str(outline))
        with zipfile.ZipFile(path) as z:before={n:z.read(n) for n in z.namelist()}
        edited,_=self.call('edit_docx',path,expected_sha256=created['sha256'],old_xml='<w:t>Old body</w:t>',new_xml='<w:t>New body</w:t>',expected_replacements=1)
        self.assertTrue(edited['unselected_zip_payloads_preserved'])
        with zipfile.ZipFile(path) as z:
            for name,data in before.items():
                if name!='word/document.xml':self.assertEqual(z.read(name),data,name)
        self.assertIn('New body',str(self.call('read',path)[0]))

    def test_docx_xml_view_and_bad_xml_leave_file_unchanged(self):
        path,created=self.create('source.docx','docx','Old')
        xml,_=self.call('read',path,xml_part='word/document.xml',offset=1,length=80)
        self.assertIn('<w:t>Old</w:t>','\n'.join(xml['lines']))
        self.call('edit_docx',path,fail=True,expected_sha256=created['sha256'],old_xml='<w:t>Old</w:t>',new_xml='<w:t>broken')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),created['sha256'])

    def test_stale_hash_and_create_only_are_rejected(self):
        path,created=self.create('source.docx','docx','original')
        self.call('write',path,fail=True,format='docx',content='overwrite',expected_sha256='absent')
        self.call('edit_docx',path,fail=True,expected_sha256='0'*64,old_xml='original',new_xml='replacement')
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),created['sha256'])

    def test_pdf_pages_render_native_image_and_preserve_source(self):
        path,created=self.create('source.pdf','pdf','# First\nHello 中文\n<!-- pagebreak -->\n# Second\nWorld')
        info,images=self.call('read',path,offset=0,length=2,render=True)
        self.assertEqual(info['page_count'],2)
        self.assertIn('First',info['pages'][0]['text']);self.assertIn('Second',info['pages'][1]['text'])
        self.assertEqual(len(images),2)
        from PIL import Image
        for img in images:
            self.assertEqual(img['type'],'image');self.assertEqual(img['mimeType'],'image/jpeg')
            Image.open(io.BytesIO(base64.b64decode(img['data']))).verify()
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),created['sha256'])

    def test_image_read_returns_native_content_and_dimensions(self):
        from PIL import Image
        path=self.root/'fixture.png';Image.new('RGB',(64,32),(10,120,210)).save(path)
        before=path.read_bytes();info,images=self.call('image_read',path)
        self.assertEqual((info['width'],info['height']),(64,32));self.assertEqual(images[0]['type'],'image')
        self.assertEqual(path.read_bytes(),before)

    def test_xlsx_creation_and_formula_read(self):
        path,_=self.create('source.xlsx','xlsx',{'Inputs':[['Name','Value'],['A',2],['B',3],['Total','=SUM(B2:B3)']]})
        info,_=self.call('read',path,sheet='Inputs',range='A1:B4')
        self.assertEqual(info['rows'][3][1],'=SUM(B2:B3)');self.assertFalse(info['formulas_recalculated'])
        self.call('read',path,fail=True,range='A1:XFD1048576')

    def test_policy_escape_and_outside_symlink_rejected(self):
        outside=pathlib.Path(self.temp.name)/'outside.pdf';outside.write_bytes(b'%PDF-secret')
        self.call('read',outside,fail=True)
        link=self.root/'link.pdf';link.symlink_to(outside)
        self.call('read',link,fail=True)
        self.call('write',self.root/'..'/'outside.docx',fail=True,format='docx',content='x',expected_sha256='absent')

    def test_fifo_read_fails_without_waiting(self):
        path=self.root/'pipe.pdf';os.mkfifo(path)
        self.call('read',path,fail=True)

    def test_invalid_package_and_xml_entity_rejected(self):
        path=self.root/'bad.docx'
        with zipfile.ZipFile(path,'w') as z:z.writestr('word/document.xml','<!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]><x>&x;</x>')
        self.assertIn('XML declarations',self.call('read',path,fail=True))

    def test_output_extension_and_unknown_format_rejected(self):
        self.call('write',self.root/'a.txt',fail=True,format='docx',content='x',expected_sha256='absent')
        self.assertFalse((self.root/'a.txt').exists())

    def test_expected_match_count_is_exact(self):
        path,created=self.create('a.docx','docx','same\nsame')
        self.call('edit_docx',path,fail=True,expected_sha256=created['sha256'],old_xml='<w:t>same</w:t>',new_xml='<w:t>new</w:t>',expected_replacements=1)
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(),created['sha256'])
        result,_=self.call('edit_docx',path,expected_sha256=created['sha256'],old_xml='<w:t>same</w:t>',new_xml='<w:t>new</w:t>',expected_replacements=2)
        self.assertNotEqual(result['sha256'],created['sha256'])


if __name__=='__main__':unittest.main(verbosity=2)
