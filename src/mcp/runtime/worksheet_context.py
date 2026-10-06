# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Resolve workbook-scoped names/shared formulas and isolate 1904 calendar functions.
Formula XML is never rewritten. Only a compiled expression receives expansion.
No external workbook, dynamic name, macro, or caller-defined function is loaded.
"""
import contextlib
import re

_CELL=r'\$?[A-Za-z]{1,3}\$?[1-9][0-9]*'
_REGION=re.compile(r'(?:(?:\'((?:[^\']|\'\')+)\'|([^!]+))!)?('+_CELL+r')(?::('+_CELL+r'))?$')


def context_names(book,sheet_names,ns):
    names={};section=book.find('s:definedNames',ns)
    if section is None:return names
    for item in section:
        name=item.get('name','').upper();scope=item.get('localSheetId')
        if not name or name.startswith('_XLNM.'):continue
        if scope is not None:
            if not scope.isdigit() or int(scope)>=len(sheet_names):raise ValueError('invalid defined-name scope')
            scope=sheet_names[int(scope)].upper()
        key=(scope,name)
        if key in names:raise ValueError('duplicate defined name in the same scope')
        value=(item.text or '').strip()
        if len(value)>8192 or item.get('function') in ('1','true') or item.get('vbProcedure') in ('1','true'):
            raise ValueError('executable or oversized defined names are unsupported')
        names[key]=value.removeprefix('=')
    return names


def expand_workbook_names(expression,current_sheet,names,depth=0,visiting=None):
    from openpyxl.formula.tokenizer import Tokenizer
    if depth>32:raise ValueError('defined-name expansion depth exceeded')
    visiting=set() if visiting is None else visiting
    result=[]
    for token in Tokenizer(expression).items:
        value=token.value
        if token.type=='OPERAND' and token.subtype=='RANGE' and not _REGION.fullmatch(value):
            scope=current_sheet.upper();raw=value
            if '!' in value:
                qualifier,raw=value.rsplit('!',1)
                scope=(qualifier[1:-1].replace("''","'") if qualifier.startswith("'") and qualifier.endswith("'") else qualifier).upper()
            key=(scope,raw.upper()) if (scope,raw.upper()) in names else (None,raw.upper())
            if key not in names:raise ValueError('undefined or unsupported workbook name: '+value[:100])
            if key in visiting:raise ValueError('circular workbook name')
            definition=names[key]
            # Relative names depend on an active-cell anchor not present in the request.
            for part in Tokenizer('='+definition).items:
                match=_REGION.fullmatch(part.value) if part.type=='OPERAND' and part.subtype=='RANGE' else None
                if match and any(not re.fullmatch(r'\$[A-Za-z]+\$[1-9][0-9]*',ref) for ref in (match[3],match[4]) if ref):
                    raise ValueError('relative defined-name reference needs explicit origin')
            visiting.add(key)
            try:expanded=expand_workbook_names('='+definition,scope,names,depth+1,visiting)[1:]
            finally:visiting.remove(key)
            # Qualified names keep their defining worksheet for otherwise unqualified refs.
            pieces=[]
            for part in Tokenizer('='+expanded).items:
                if part.type=='OPERAND' and part.subtype=='RANGE' and _REGION.fullmatch(part.value) and '!' not in part.value:
                    pieces.append("'"+scope.replace("'","''")+"'!"+part.value)
                else:pieces.append(part.value)
            value='('+''.join(pieces)+')'
        result.append(value)
    out='='+''.join(result)
    if len(out)>32768:raise ValueError('expanded formula exceeds limit')
    return out


def worksheet_formula_context(tree,sheet,ns):
    from openpyxl.formula.translate import Translator
    from openpyxl.utils.cell import range_boundaries,coordinate_to_tuple,get_column_letter
    masters={};pending=[];expressions={};arrays={};owners={}
    for cell in tree.findall('.//s:sheetData/s:row/s:c',ns):
        f=cell.find('s:f',ns)
        if f is None:continue
        coord=cell.get('r','').upper();kind=f.get('t','normal')
        if kind=='shared':
            si=f.get('si')
            if si is None or not si.isdigit():raise ValueError('shared formula index missing')
            pending.append((coord,si))
            if f.text:
                if si in masters or not f.get('ref'):raise ValueError('shared formula master is ambiguous')
                bounds=range_boundaries(f.get('ref'));masters[si]=(coord,'='+f.text,bounds)
        elif kind=='array':
            if not f.text or not f.get('ref'):raise ValueError('array formula needs a declared fixed range')
            c1,r1,c2,r2=range_boundaries(f.get('ref'))
            if not all(isinstance(v,int) and v>0 for v in (c1,r1,c2,r2)) or c1>c2 or r1>r2 or (c2-c1+1)*(r2-r1+1)>5000:
                raise ValueError('array result range exceeds bounds')
            if coordinate_to_tuple(coord)!=(r1,c1):raise ValueError('array anchor must be the top-left result cell')
            keys=[(sheet,get_column_letter(c)+str(r)) for r in range(r1,r2+1) for c in range(c1,c2+1)]
            if any(key in owners for key in keys):raise ValueError('overlapping array formula ranges')
            anchor=(sheet,coord);arrays[anchor]=(r2-r1+1,c2-c1+1,keys)
            for key in keys:owners[key]=anchor
            expressions[anchor]='='+f.text
        elif kind=='normal' and not f.get('ref'):
            if not f.text:raise ValueError('empty formula')
            expressions[(sheet,coord)]='='+f.text
        else:raise ValueError('data-table or unsupported formula encoding')
    for coord,si in pending:
        if si not in masters:raise ValueError('shared formula master missing')
        origin,formula,bounds=masters[si];c1,r1,c2,r2=bounds;r,c=coordinate_to_tuple(coord)
        if not all(isinstance(v,int) for v in bounds) or not c1<=c<=c2 or not r1<=r<=r2:raise ValueError('shared formula cell outside declared range')
        expressions[(sheet,coord)]=Translator(formula,origin=origin).translate_formula(coord)
    for key,owner in owners.items():
        if key!=owner and key in expressions:raise ValueError('array output overlaps another formula')
    return expressions,arrays,owners


@contextlib.contextmanager
def workbook_calendar(date1904):
    if not date1904:
        yield;return
    import numpy as np
    import formulas
    from formulas.tokens.operand import XlError
    functions=formulas.get_functions();original={}
    # Shift serial-date arguments/results only, not durations, years or text.
    contracts={'DATE':((),True),'DATEVALUE':((),True),'DAY':((0,),False),'MONTH':((0,),False),'YEAR':((0,),False),
      'WEEKDAY':((0,),False),'WEEKNUM':((0,),False),'ISOWEEKNUM':((0,),False),'_XLFN.ISOWEEKNUM':((0,),False),
      'DATEDIF':((0,1),False),'EDATE':((0,),True),'EOMONTH':((0,),True),'YEARFRAC':((0,1),False),
      'DAYS':((0,1),False),'_XLFN.DAYS':((0,1),False),'DAYS360':((0,1),False),'_XLFN.DAYS360':((0,1),False),
      'NETWORKDAYS':((0,1,2),False),'NETWORKDAYS.INTL':((0,1,3),False),
      'WORKDAY':((0,2),True),'WORKDAY.INTL':((0,3),True)}
    def shift(value,delta):
        def one(x):
            if isinstance(x,XlError):return x
            if isinstance(x,(int,float,np.number)) and not isinstance(x,(bool,np.bool_)):return x+delta
            return x
        array=np.asarray(value,dtype=object)
        result=np.empty(array.shape,dtype=object)
        for index in np.ndindex(array.shape):result[index]=one(array[index])
        return result.item() if result.ndim==0 else result
    def wrap(function,indexes,out):
        def invoke(*args,**kwargs):
            values=list(args)
            for index in indexes:
                if index<len(values):values[index]=shift(values[index],1462)
            result=function(*values,**kwargs)
            return shift(result,-1462) if out else result
        return invoke
    try:
        for name,(indexes,out) in contracts.items():
            if name in functions:
                f=functions[name];original[name]=f
                if isinstance(f,dict):functions[name]={**f,'function':wrap(f['function'],indexes,out)}
                else:functions[name]=wrap(f,indexes,out)
        yield
    finally:
        functions.update(original)
