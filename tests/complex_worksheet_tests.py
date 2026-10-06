#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Real OOXML fixtures for scoped names, shared/fixed arrays and 1904 calendars.
Sources retain formula encoding and unselected ZIP payloads; no Excel/office process.
"""
import hashlib
import importlib.util
import io
import json
import pathlib
import tempfile
import unittest
import zipfile
from lxml import etree

ROOT=pathlib.Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('complex_docs',ROOT/'src/mcp/runtime/document_local.py');D=importlib.util.module_from_spec(spec);spec.loader.exec_module(D)
NS={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main'};TAG='{'+NS['s']+'}'


class ComplexWorksheet(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='hepta-complex-');self.root=pathlib.Path(self.temp.name).resolve();self.path=self.root/'test.xlsx'
    def tearDown(self):self.temp.cleanup()
    def create(self,sheets):self.path.write_bytes(D.create_bytes('xlsx',sheets))
    def patch(self,fn):
        with zipfile.ZipFile(self.path) as z:parts={n:z.read(n) for n in z.namelist()}
        fn(parts)
        with zipfile.ZipFile(self.path,'w') as z:
            for n,data in parts.items():z.writestr(n,data)
    def names(self,values):
        def edit(parts):
            tree=etree.fromstring(parts['xl/workbook.xml']);section=tree.find('s:definedNames',NS)
            if section is None:section=etree.SubElement(tree,TAG+'definedNames')
            for name,scope,value in values:
                args={'name':name}
                if scope is not None:args['localSheetId']=str(scope)
                etree.SubElement(section,TAG+'definedName',**args).text=value
            parts['xl/workbook.xml']=etree.tostring(tree)
        self.patch(edit)
    def calculate(self):
        q={'op':'worksheet_recalculate','path':str(self.path),'roots':[str(self.root)],'expected_sha256':hashlib.sha256(self.path.read_bytes()).hexdigest()}
        return json.loads(D.main(q)[0]['text'])
    def values(self,sheet='Data',region='A1:E5'):
        return json.loads(D.main({'op':'read','path':str(self.path),'roots':[str(self.root)],'sheet':sheet,'range':region,'cached_values':True})[0]['text'])['rows']
    def test_scoped_names_shadow_global_and_keep_name_xml(self):
        self.create({'Data':[[2,3,'=SUM(Values)*Rate','=Rate']], 'Other':[['=Rate',"='Data'!Rate"]]})
        self.names([('Values',None,"'Data'!$A$1:$B$1"),('Rate',None,'2'),('Rate',0,'3')])
        with zipfile.ZipFile(self.path) as z:before=etree.fromstring(z.read('xl/workbook.xml')).find('s:definedNames',NS)
        result=self.calculate();self.assertEqual(result['defined_names_available'],3)
        self.assertEqual(self.values(region='C1:D1'),[[15,3]]);self.assertEqual(self.values('Other','A1:B1'),[[2,3]])
        with zipfile.ZipFile(self.path) as z:after=etree.fromstring(z.read('xl/workbook.xml')).find('s:definedNames',NS)
        self.assertEqual(etree.tostring(before),etree.tostring(after))
    def test_name_constants_and_nested_absolute_ranges(self):
        self.create({'Data':[[5,7,'=Total+Offset','=Label']]})
        self.names([('Total',None,'SUM(Items)'),('Items',None,"Data!$A$1:$B$1"),('Offset',None,'4'),('Label',None,'"literal text"')])
        self.calculate();self.assertEqual(self.values(region='C1:D1'),[[16,'literal text']])
    def test_shared_formula_relative_translation_keeps_original_xml(self):
        self.create({'Data':[[2,'=A1+$D$1',None,10],[3,'=A2+$D$1'],[4,'=A3+$D$1']]})
        def change(parts):
            key='xl/worksheets/sheet1.xml';tree=etree.fromstring(parts[key])
            for index,f in enumerate(tree.findall('.//s:f',NS)):
                f.set('t','shared');f.set('si','0')
                if index==0:f.set('ref','B1:B3')
                else:f.text=None
            parts[key]=etree.tostring(tree)
        self.patch(change)
        with zipfile.ZipFile(self.path) as z:before=[etree.tostring(x) for x in etree.fromstring(z.read('xl/worksheets/sheet1.xml')).findall('.//s:f',NS)]
        self.calculate();self.assertEqual(self.values(region='B1:B3'),[[12],[13],[14]])
        with zipfile.ZipFile(self.path) as z:after=[etree.tostring(x) for x in etree.fromstring(z.read('xl/worksheets/sheet1.xml')).findall('.//s:f',NS)]
        self.assertEqual(before,after)
    def test_fixed_array_result_and_dependent_cell_cache(self):
        self.create({'Data':[[1,2,'=A1:B2*2',None,'=D2+1'],[3,4]]})
        def change(parts):
            key='xl/worksheets/sheet1.xml';tree=etree.fromstring(parts[key]);f=tree.find(".//s:c[@r='C1']/s:f",NS);f.set('t','array');f.set('ref','C1:D2');parts[key]=etree.tostring(tree)
        self.patch(change);result=self.calculate()
        self.assertEqual(result['fixed_array_count'],1);self.assertEqual(result['calculated_cell_count'],5)
        self.assertEqual(self.values(region='C1:D2'),[[2,4],[6,8]]);self.assertEqual(self.values(region='E1:E1'),[[9]])
    def test_fixed_array_shape_mismatch_leaves_source_unchanged(self):
        self.create({'Data':[[1,2,'=A1:B2*2'],[3,4]]})
        def change(parts):
            key='xl/worksheets/sheet1.xml';tree=etree.fromstring(parts[key]);f=tree.find('.//s:f',NS);f.set('t','array');f.set('ref','C1:C2');parts[key]=etree.tostring(tree)
        self.patch(change);before=self.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'shape'):self.calculate()
        self.assertEqual(before,self.path.read_bytes())
    def test_1904_epoch_calendar_roundtrip_and_engine_isolation(self):
        self.create({'Data':[['=DATE(1904,1,1)','=YEAR(A1)','=MONTH(A1)','=DAY(A1)','=EDATE(A1,1)'],['=DATE(2026,10,6)','=YEAR(A2)','=EOMONTH(A1,0)','=DAYS(E1,A1)']]})
        self.patch(lambda parts:parts.__setitem__('xl/workbook.xml',parts['xl/workbook.xml'].replace(b'<workbookPr/>',b'<workbookPr date1904="1"/>')))
        result=self.calculate();self.assertEqual(result['workbook_date_system'],'1904')
        self.assertEqual(self.values(region='A1:E1'),[[0,1904,1,1,31]])
        self.assertEqual(self.values(region='B2:D2'),[[2026,30,31]])
        self.create({'Data':[['=DATE(1904,1,1)']]});self.calculate();self.assertEqual(self.values(region='A1:A1'),[[1462]])
    def test_relative_cyclic_external_names_fail_without_write(self):
        cases=[[('Name1',None,'A1')],[('Name1',None,'Name2'),('Name2',None,'Name1')],[('Name1',None,"'[outside.xlsx]Data'!$A$1")]]
        for names in cases:
            self.create({'Data':[[2,'=Name1']]});self.names(names);before=self.path.read_bytes()
            with self.assertRaises(ValueError):self.calculate()
            self.assertEqual(before,self.path.read_bytes())
    def test_dangling_shared_formula_has_no_silent_zero_cache(self):
        self.create({'Data':[[1,'=A1*2']]})
        def change(parts):
            key='xl/worksheets/sheet1.xml';tree=etree.fromstring(parts[key]);f=tree.find('.//s:f',NS);f.set('t','shared');f.set('si','7');f.text=None;parts[key]=etree.tostring(tree)
        self.patch(change);before=self.path.read_bytes()
        with self.assertRaisesRegex(ValueError,'master missing'):self.calculate()
        self.assertEqual(before,self.path.read_bytes())

    def test_1904_text_uses_original_branch_and_correct_calendar(self):
        self.create({'Data':[['=DATE(2026,10,6)','=TEXT(A1,"yyyy-mm-dd")','=TEXT(123.4,"0.00")','=TEXT(A1,"[>=45000]yyyy-mm-dd;0.00")','=TEXT(0.5,"hh:mm")']]})
        self.patch(lambda parts:parts.__setitem__('xl/workbook.xml',parts['xl/workbook.xml'].replace(b'<workbookPr/>',b'<workbookPr date1904="1"/>')))
        self.calculate()
        self.assertEqual(self.values(region='A1:E1'),[[44839,'2026-10-06','123.40','44839.00','12:00']])
        self.create({'Data':[['=TEXT(DATE(2026,10,6),"yyyy-mm-dd")']]})
        self.calculate();self.assertEqual(self.values(region='A1:A1'),[['2026-10-06']])



if __name__=='__main__':unittest.main(verbosity=2)
