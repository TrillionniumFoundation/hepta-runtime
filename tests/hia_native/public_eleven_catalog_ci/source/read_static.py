"""Read every complete mutable byte, including retained and dirty state."""
import json
from pathlib import Path
import struct
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
from read_static_build import build_check

def verify(source,build,output):
    sources,proof=c.source_check(source);builds,modules=build_check(build,source)
    r=c.BASE.Reader(output);report=r.document('result.json');cases=c.cases(source)
    assert report['schema']=='hepta.runtime.catalog-eleven-static-native.v1' and report['status']=='PASS'
    assert report['source_profile']==c.pin((source/'source-profile.json').read_bytes())
    assert report['public_all_configuration_qualified'] is False and report['whole_runtime_replaced'] is False
    assert len(report['records'])==len(cases)
    assert report['actual_native_calls']==sum(2 if case['paired']else 1 for case in cases)
    assets=[(source/f'native/catalog-mode-{mode}.bin').read_bytes()for mode in (0,1)]
    compressed=(source/'native/catalog-common.lzss').read_bytes();packed=compressed+b'\0'*((-len(compressed))%8)
    previous=None;rows=[];old_lists={}
    for ordinal,(case,row) in enumerate(zip(cases,report['records'],strict=True)):
        assert row['case']==case['name']
        assert [x['owner']for x in row['calls']]==(['catalog-nine','catalog-eleven']if case['paired']else ['catalog-eleven'])
        complete=[]
        for call in row['calls']:
            assert call['output_capacity']==case['output_capacity'] and call['workspace_capacity']==case['workspace_capacity']
            out,work=c.BASE.read_call(r,call,case['wire'],f"case-{ordinal:03d}-{call['owner']}")
            complete.append((call['code'],out,work))
        if case['outcome']=='retained':
            assert complete[0]==complete[1],('retained complete buffer changed',case['name'])
        else:
            code,out,work=complete[-1]
            before_out,before_work=previous if case['group'] and previous else (b'\xa7'*len(out),b'\x59'*len(work))
            mode=struct.unpack_from('<Q',case['wire'],16)[0]
            if case['outcome']=='invalid':
                assert code==0xffffffff and out==before_out and work==before_work
            elif len(out)<32:
                assert code==0xfffffffe and out==before_out and work==before_work
            elif len(work)<proof['workspace_required']:
                assert code==0xffffffd0
                assert out[:32]==b'HGRWS002'+struct.pack('<3Q',1,proof['workspace_required'],0)
                assert out[32:]==before_out[32:] and work==before_work
            elif len(out)<32+len(assets[mode]):
                assert code==0xffffffd0
                assert out[:32]==b'HGRWS002'+struct.pack('<3Q',2,32+len(assets[mode]),0)
                assert out[32:]==before_out[32:] and work==before_work
            else:
                assert code==32
                assert out[:32]==b'HRCATR02'+struct.pack('<3Q',0,len(assets[mode]),0)
                assert out[32:32+len(assets[mode])]==assets[mode]
                assert out[32+len(assets[mode]):]==before_out[32+len(assets[mode]):]
                assert work==packed+before_work[len(packed):]
                if case['outcome']=='baseline-list':
                    old_code,old_out,old_work=complete[0];assert old_code==32 and old_out[:8]==b'HRCATR02'
                    old_size=struct.unpack_from('<Q',old_out,16)[0]
                    old=old_out[32:32+old_size]
                    assert old_out[32+old_size:]==b'\xa7'*(len(old_out)-32-old_size)
                    assert old_work==b'\x59'*len(old_work)
                    old_lists[mode]=old
            if case['group']:previous=(out,work)
        rows.append({'case':case['name'],'calls':len(complete)})
    assert set(old_lists)=={0,1}
    changes=[]
    for mode in (0,1):
        old=json.loads(b'{"id":0'+old_lists[mode])['result']
        new=json.loads(b'{"id":0'+assets[mode])['result']
        assert len(old['tools'])==9 and len(new['tools'])==11
        existing={x['name']:x for x in old['tools']};now={x['name']:x for x in new['tools']}
        assert set(now)-set(existing)=={'batch_edit','weight_bellman_plan'}
        differences=[{'tool':name,'before':existing[name],'after':now[name]}for name in existing if existing[name]!=now[name]]
        fields={key:{'before':old.get(key),'after':new.get(key)}for key in set(old)|set(new)if key!='tools'and old.get(key)!=new.get(key)}
        changes.append({'mode':mode,'retained_tool_field_differences':differences,'result_field_differences':fields,
            'old_order':[x['name']for x in old['tools']],'new_order':[x['name']for x in new['tools']]})
    return {'status':'COMPLETE_STATIC_NATIVE_READONLY_PASS','cases':len(cases),'actual_native_calls':report['actual_native_calls'],
        'retained_non_list_operations':18,'list_modes':2,'current_target_differences':changes,
        'source_files':sources.files,'build_files':builds.files,'native_files':r.files,'case_rows':rows,
        'modules':modules,'process_launches':0,'public_all_configuration_qualified':False,'whole_runtime_replaced':False}
