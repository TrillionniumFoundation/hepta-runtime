# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bounded, offline Excel-formula evaluation with OOXML cache-only publication.
Never loads linked workbooks, executes macros, invokes office software or imports
caller functions. Unsupported/ambiguous references fail before any write.
"""
import hashlib
import io
import json
import math
import pathlib
import re
import zipfile


def calculate_worksheet_package(q):
    import formulas
    from formulas.tokens.operand import XlError
    import numpy as np
    from lxml import etree
    path=checked(q,q['path']);data,sha=read_bytes(path)
    if path.suffix.lower() not in ('.xlsx','.xlsm') or q['expected_sha256']!=sha:
        raise ValueError('calculation requires current XLSX/XLSM source SHA256')
    ns={'s':'http://schemas.openxmlformats.org/spreadsheetml/2006/main','r':'http://schemas.openxmlformats.org/officeDocument/2006/relationships'}
    tag='{'+ns['s']+'}';parser=etree.XMLParser(resolve_entities=False,no_network=True)
    def parse(payload):
        if re.search(br'<!\s*(DOCTYPE|ENTITY)',payload,re.I):raise ValueError('XML declarations rejected')
        return etree.fromstring(payload,parser=parser)
    def colnum(value):
        out=0
        for char in value:out=out*26+ord(char)-64
        return out
    def colname(value):
        result=''
        while value:value,r=divmod(value-1,26);result=chr(65+r)+result
        return result
    with safe_zip(data) as package:
        names=package.namelist()
        if any(n.startswith(('xl/externalLinks/','_xmlsignatures/')) for n in names):
            raise ValueError('external links and signed workbook calculation are unsupported')
        book=parse(package.read('xl/workbook.xml'));rels=parse(package.read('xl/_rels/workbook.xml.rels'))
        properties=book.find('s:workbookPr',ns)
        if properties is not None and properties.get('date1904','0').lower() in ('1','true'):
            raise ValueError('1904 workbook date-system recalculation is not qualified; no caches published')
        if book.find('s:definedNames',ns) is not None and len(book.find('s:definedNames',ns)):
            raise ValueError('named-range calculation requires separately qualified name resolution')
        targets={e.get('Id'):e.get('Target') for e in rels if e.get('TargetMode')!='External'}
        strings=[]
        if 'xl/sharedStrings.xml' in names:
            strings=[''.join(e.itertext()) for e in parse(package.read('xl/sharedStrings.xml'))]
        sheets={};cells={};expressions={};trees={};nodes={}
        for sheet in book.find('s:sheets',ns):
            name=sheet.get('name');normalized=name.upper()
            if normalized in sheets:raise ValueError('ambiguous sheet names')
            target=targets[sheet.get('{'+ns['r']+'}id')]
            target=target.lstrip('/') if target.startswith('/') else 'xl/'+target
            if '..' in target.split('/') or not target.startswith('xl/worksheets/'):
                raise ValueError('unsupported worksheet relationship')
            tree=parse(package.read(target));trees[target]=tree;sheets[normalized]=(name,target)
            for cell in tree.findall('.//s:sheetData/s:row/s:c',ns):
                coord=cell.get('r','').upper()
                if not re.fullmatch(r'[A-Z]{1,3}[1-9][0-9]{0,6}',coord):raise ValueError('invalid worksheet coordinate')
                key=(normalized,coord)
                if key in nodes:raise ValueError('duplicate cell coordinates')
                nodes[key]=cell;f=cell.find('s:f',ns);v=cell.find('s:v',ns);kind=cell.get('t')
                if f is not None:
                    if f.get('t') not in (None,'normal') or f.get('ref'):
                        raise ValueError('shared/array/data-table formulas are not qualified')
                    expressions[key]='='+str(f.text or '')
                elif kind=='s':cells[key]=strings[int(v.text)] if v is not None else ''
                elif kind=='inlineStr':cells[key]=''.join(cell.find('s:is',ns).itertext())
                elif kind=='b':cells[key]=v is not None and v.text=='1'
                elif kind=='e':raise ValueError('input error cells need explicit repair before calculation')
                elif kind=='str':cells[key]=v.text if v is not None else ''
                elif v is None or v.text is None:cells[key]=None
                else:cells[key]=float(v.text)
            if len(nodes)>100000:raise ValueError('worksheet cell budget exceeded')
        if not 1<=len(expressions)<=5000:raise ValueError('recalculation requires 1..5000 formula cells')
        compiled={};evaluated={};visiting=set();range_work=[0];errors=[]
        forbidden={'INDIRECT','OFFSET','WEBSERVICE','FILTERXML','RTD','DDE','CALL','REGISTER','REGISTER.ID','EXEC','SQL.REQUEST','NOW','TODAY','RAND','RANDBETWEEN','RANDARRAY','CELL','INFO'}
        functions=formulas.get_functions()
        for key,expression in expressions.items():
            if len(expression)>8192:raise ValueError('formula size limit exceeded')
            lexical=re.sub(r'"(?:[^"]|"")*"','""',expression)
            if any(c in lexical for c in ('[',']','|')):raise ValueError('external or structured formula references are not qualified')
            called={n.upper() for n in re.findall(r'([A-Za-z_][A-Za-z0-9_.]*)\s*\(',lexical)}
            if called & forbidden:raise ValueError('dynamic, external or volatile formula function is not qualified')
            if any(n not in functions for n in called):raise ValueError('unsupported formula function; no caches published')
            try:compiled[key]=formulas.Parser().ast(expression)[1].compile()
            except Exception as error:raise ValueError('formula parser rejected '+key[0]+'!'+key[1]) from error
        pattern=re.compile(r"(?:(?:'((?:[^']|'')+)'|([^!]+))!)?(\$?[A-Z]+\$?[1-9][0-9]*)(?::(\$?[A-Z]+\$?[1-9][0-9]*))?$")
        def dependency(reference,current_sheet):
            if not isinstance(reference,str):raise ValueError('non-cell formula dependency unsupported')
            match=pattern.fullmatch(reference)
            if not match:raise ValueError('unsupported formula dependency: '+reference[:128])
            sheet=(match[1].replace("''", "'") if match[1] else match[2] or current_sheet).upper()
            if sheet not in sheets:raise ValueError('unknown formula sheet')
            first=match[3].replace('$','');last=(match[4] or match[3]).replace('$','')
            c1,r1=re.fullmatch(r'([A-Z]+)([0-9]+)',first).groups();c2,r2=re.fullmatch(r'([A-Z]+)([0-9]+)',last).groups()
            c1,c2,r1,r2=colnum(c1),colnum(c2),int(r1),int(r2)
            if r2<r1 or c2<c1 or r2>1048576 or c2>16384:raise ValueError('formula range invalid')
            size=(r2-r1+1)*(c2-c1+1);range_work[0]+=size
            if size>50000 or range_work[0]>500000:raise ValueError('calculation dependency budget exceeded')
            values=[[evaluate((sheet,colname(c)+str(r))) for c in range(c1,c2+1)] for r in range(r1,r2+1)]
            return np.array(values,dtype=object)
        def evaluate(key):
            if key in evaluated:return evaluated[key]
            if key not in expressions:return cells.get(key,None)
            if key in visiting:raise ValueError('circular formula reference; original unchanged')
            if len(visiting)>128:raise ValueError('formula dependency depth exceeded')
            visiting.add(key)
            try:
                function=compiled[key];inputs=[dependency(ref,key[0]) for ref in function.inputs]
                value=function(*inputs)
                array=np.asarray(value,dtype=object)
                if array.size!=1:raise ValueError('spilling/array formula results are not qualified')
                result=array.reshape(-1)[0]
                if isinstance(result,np.generic):result=result.item()
                if isinstance(result,(int,float)) and not isinstance(result,bool):
                    if not math.isfinite(result):raise ValueError('nonfinite calculation result')
                    result=float(result)
                elif result is None:result=0.0
                elif not isinstance(result,(bool,str)):
                    # Excel error tokens are explicit cache errors, not successful numeric values.
                    text=str(result)
                    if text in ('#DIV/0!','#VALUE!','#REF!','#NAME?','#N/A','#NUM!','#NULL!'):result=text
                    else:raise ValueError('unsupported calculation result type')
                evaluated[key]=result
                return result
            finally:visiting.remove(key)
        for key in expressions:evaluate(key)
        changed=set()
        for key,value in evaluated.items():
            node=nodes[key];changed.add(sheets[key[0]][1])
            for old in list(node.findall('s:v',ns)):node.remove(old)
            node.attrib.pop('t',None)
            if isinstance(value,bool):node.set('t','b');text='1' if value else '0'
            elif isinstance(value,str):
                is_error=isinstance(value,XlError)
                node.set('t','e' if is_error else 'str');text=str(value)
                if is_error:errors.append({'sheet':sheets[key[0]][0],'cell':key[1],'error':str(value)})
            else:text=format(value,'.15g')
            etree.SubElement(node,tag+'v').text=text
        replacements={n:etree.tostring(trees[n],encoding='UTF-8',xml_declaration=True) for n in changed}
        # The cached results are complete for this accepted model. Retain native
        # recalculation-on-open so Excel can apply its own engine if available.
        calc=book.find('s:calcPr',ns)
        if calc is None:calc=etree.SubElement(book,tag+'calcPr')
        calc.set('fullCalcOnLoad','1')
        replacements['xl/workbook.xml']=etree.tostring(book,encoding='UTF-8',xml_declaration=True)
        out=io.BytesIO()
        with zipfile.ZipFile(out,'w') as writer:
            writer.comment=package.comment
            for info in package.infolist():writer.writestr(info,replacements.get(info.filename,package.read(info)))
    result=publish(q,str(path),out.getvalue(),sha)
    result.update({'calculation_engine':'formulas','engine_version':formulas.__version__,'formulas_recalculated':True,
                   'formula_count':len(evaluated),'formula_error_count':len(errors),'formula_errors':errors[:100],
                   'formula_text_preserved':True,'unselected_zip_payloads_preserved':True,'changed_parts':sorted(replacements),
                   'external_workbooks_loaded':False,'macros_executed':False,'excel_engine_identity_claimed':False,'workbook_date_system':'1900'})
    return [{'type':'text','text':json.dumps(result)}]
