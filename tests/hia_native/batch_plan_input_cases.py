"""Inputs only for the native typed-parameter/Editable-to-Planner bridge."""
import importlib.util
import json
from pathlib import Path


def cases():
    path=Path(__file__).with_name('batch_edit_params_oracle')/'cases.py'
    spec=importlib.util.spec_from_file_location('_batch_input_typed_cases',path)
    typed=importlib.util.module_from_spec(spec);spec.loader.exec_module(typed)
    texts=['','\n','\r','\r\n','a\r','a\r\n','a\r\r\n\n',
           '甲\x00\r\n乙\n尾','a\u2028b\u2029c\x85d\x0be\x0cf','\n\n\n']
    index=0
    for row in list(typed.iter_cases())+list(typed.extra_cases()):
        if row['domain']!='typed-object':continue
        raw=row.get('raw_json')
        if raw is None:raw=json.dumps(row['value'],ensure_ascii=False,separators=(',',':'),allow_nan=False)
        yield {'case_id':index,'name':'typed/'+row['name'],'raw_json':raw,
               'original_raw':texts[index%len(texts)],'planner':row['name'] in {
                   'empty-operations','minimal-insert','minimal-replace','operation-count-50',
                   'operation-count-51','typed-4097-operations','content-over8m','path-over8m'}}
        index+=1
    good={'operation':'insert','start':0,'content':'新\x00\r\n'}
    focused=[]
    for n,raw in enumerate(texts):
        focused.append((f'line-ending-{n}',{'path':'\x00/中文😀\\\"\n','operations':[good]},raw,True))
    for n,length in enumerate([0,1,127,128,129,16383,16384,16385]):
        focused.append((f'uleb-line-{length}',{'path':'p','operations':[good]},'a'*length+'\r\r\n尾\r',n<4))
    endpoints=[None,False,True,[],{},[None,True,'x'],{'z':[-0.0,1.5],'a':'\x00'},
               0,-1,9223372036854775807,-9223372036854775808,
               9223372036854775808,18446744073709551615,1.0,-0.0,1e-7,1e20,
               '', '1:00','\u3000+1:aB\u00a0','\ud7ff\ue000\U0010ffff']
    for n,endpoint in enumerate(endpoints):
        focused.append((f'endpoint-kind-{n}',{'path':'p','operations':[
            {**good,'start':endpoint,'end':endpoints[(n+3)%len(endpoints)]},
            {**good,'operation':'replace','start':endpoint,'content':['a','b']}]},'a\r\r\n\n尾',True))
    for depth in [17,100]:
        nested=False
        for _ in range(depth):nested=[nested]
        focused.append((f'deep-endpoint-{depth}',{'path':'p','operations':[{**good,'start':nested}]},'a\n',False))
    focused.append(('endpoint-over8m',{'path':'p','operations':[{**good,'start':'x'*(8388608+1)}]},'a\n',False))
    focused.append(('empty-lines-65537',{'path':'p','operations':[good]},'\n'*65537,False))
    focused.append(('original-over8m',{'path':'p','operations':[good]},'a'*(8388608+1)+'\r\r\n尾\r',False))
    scalars=''.join(chr(cp) for cp in range(0x110000) if not 0xd800<=cp<=0xdfff)
    focused.append(('all-unicode-original',{'path':'p','operations':[good]},scalars,False))
    focused.append(('all-unicode-path-content',{'path':scalars,'operations':[{**good,'content':scalars}]},'a\r\r\n',False))
    for name,value,raw,planner in focused:
        yield {'case_id':index,'name':'bridge/'+name,'raw_json':json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False),
               'original_raw':raw,'planner':planner}
        index+=1
