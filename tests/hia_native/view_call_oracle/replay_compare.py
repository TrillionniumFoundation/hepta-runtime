"""Compare complete native captures with separately executed Rust originals.

This file only decodes private result formats. It implements neither filesystem
view semantics, endpoint selection, caching, nor Rust diagnostic formatting.
"""
from __future__ import annotations
import gzip,importlib.util,json,struct
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def sibling(name):
    spec=importlib.util.spec_from_file_location('_view_replay_'+name,ROOT/(name+'.py'))
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
cases=sibling('cases');wide=sibling('wide_endpoint_case')
def captured(root,relative):
    if type(relative) is not str:raise AssertionError('native artifact path must be text')
    path=Path(relative)
    if path.is_absolute() or '..' in path.parts:raise AssertionError('native artifact escaped corpus')
    path=(root/path).resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():raise AssertionError('missing native artifact')
    with gzip.open(path,'rb') as stream:return stream.read()
def read_rows(path):
    rows={}
    for encoded in path.read_bytes().split(b'\n'):
        if not encoded:continue
        row=json.loads(encoded);cid=row['case_id'];assert type(cid) is int and cid not in rows;rows[cid]=row
    return rows
def compare_case(corpus,native,original,expected_input):
    meta,blobs=original['metadata'],original['blobs'];cid=meta['case_id']
    assert native['case_id']==cid and captured(corpus,native['input_path'])==expected_input
    counts=dict(body_bytes=0,cache_bytes=0,read_snapshot_bytes=0,base_bytes=0,cancelled_base_bytes=0)
    outcome=meta['outcome'];cancelled=bool(outcome.get('cancelled'))
    assert type(native['cancelled']) is bool and native['cancelled']==cancelled
    body=captured(corpus,native['body_path'])
    if cancelled:
        assert body==b'' and outcome['publication_bytes']==0
        before=meta['before_cancel'];expected_base=blobs[before['blob']] if before['ok'] else before['error'].encode()
        base_status=0 if before['ok'] else 1;counts['cancelled_base_bytes']=len(expected_base)
    else:
        assert type(native['ok']) is bool and native['ok']==outcome['ok']
        assert body==blobs[outcome['blob']],(cid,'complete visible body')
        counts['body_bytes']=len(body);base_status=0 if outcome['ok'] else 1
        if outcome['ok']:
            assert meta['rendered']['ok'] is True;expected_base=blobs[meta['rendered']['blob']]
        else:expected_base=body
    assert native['after_render_status']==base_status
    assert captured(corpus,native['after_render_path'])==expected_base,(cid,'complete after-render base')
    counts['base_bytes']=len(expected_base)
    for name in ('cache_before','cache_after'):
        assert len(native[name])==len(meta[name])
        for actual,ref in zip(native[name],meta[name]):
            assert actual['path_hex']==ref['path_hex'] and type(actual['present']) is bool and actual['present']==ref['present']
            if ref['present']:
                raw=captured(corpus,actual['content_path']);assert raw==blobs[ref['blob']]
                counts['cache_bytes']+=len(raw)
            else:assert actual.get('content_path') is None
    expected_io=[row for row in meta['events'] if row['kind']=='io'];assert len(native['io'])==len(expected_io)
    for actual,ref in zip(native['io'],expected_io):
        assert actual['event']==ref['event'] and type(actual['occurrence']) is int and actual['occurrence']==ref['occurrence']
        result=ref['result']
        for key in ('ok','value','size','is_file','is_dir','error'):
            if key in result:assert type(actual[key]) is type(result[key]) and actual[key]==result[key]
        if 'snapshot_blob' in result:
            raw=captured(corpus,actual['snapshot_path']);assert raw==blobs[result['snapshot_blob']]
            counts['read_snapshot_bytes']+=len(raw)
    return counts

def compare_native(corpus,output):
    rows=read_rows(corpus/'native-cases.jsonl');assert set(rows)==set(range(58))
    totals=dict(body_bytes=0,cache_bytes=0,read_snapshot_bytes=0,base_bytes=0,cancelled_base_bytes=0)
    with (output/'original.stdout').open('rb') as stream:
        originals=cases.read_records(stream,cases.OUTPUT_MAGIC)
        for request in cases.iter_cases():
            original=next(originals);cid=request['metadata']['case_id'];assert original['metadata']['case_id']==cid
            counts=compare_case(corpus,rows[cid],original,cases.encode_cases([request]))
            for key,value in counts.items():totals[key]+=value
        assert next(originals,None) is None
    return dict(cases=58,public_prelude_cases=56,private_raw_path_cases=2,compared=totals,
        every_input_byte_equal=True,every_visible_body_byte_equal=True,every_after_render_base_byte_equal=True,
        every_cache_probe_byte_equal=True,every_logical_io_observation_equal=True)

def compare_wide(corpus,output):
    rows=read_rows(corpus/'native-cases.jsonl');assert set(rows)=={wide.CASE_ID}
    with (output/'wide.stdout').open('rb') as stream:
        originals=cases.read_records(stream,cases.OUTPUT_MAGIC);original=next(originals)
        assert original['metadata']['case_id']==wide.CASE_ID and next(originals,None) is None
    result=compare_case(corpus,rows[wide.CASE_ID],original,wide.original_input())
    assert result['body_bytes']>16<<20 and rows[wide.CASE_ID]['ok'] is False
    assert [event['event'] for event in rows[wide.CASE_ID]['io']]==['exists','is_dir']
    assert captured(corpus,'arguments.bin.gz')==wide.arguments()
    return dict(cases=1,ordinary_58_cases_counted=0,every_input_byte_equal=True,
        every_visible_body_byte_equal=True,every_after_render_base_byte_equal=True,
        every_cache_probe_byte_equal=True,every_logical_io_observation_equal=True,compared=result)

def endpoint(raw,value):
    if value is None:assert raw==b'';return
    assert raw[:8]==b'HIAEP001' and len(raw)>=32
    tag,length,number=struct.unpack_from('<3Q',raw,8);assert len(raw)==32+length
    if type(value) is str:assert tag==2 and number==0 and raw[32:]==value.encode()
    elif type(value) is int and -(1<<63)<=value<(1<<63):assert (tag,length,number)==(0,0,value&((1<<64)-1))
    elif type(value) in (int,float):assert (tag,length,number)==(1,0,0)
    else:assert tag==3 and number==0 and json.loads(raw[32:])==value

def typed_projection(raw,typed):
    assert len(raw)>=96 and raw[:8]==b'HVPRR001'
    status,flags,pathlen,startlen,endlen,patternlen,contentlen,context,depth,presence,errorlen=struct.unpack_from('<11Q',raw,8)
    if typed['ok'] is False:
        assert status==1 and raw[16:88]==bytes(72) and errorlen==len(raw)-96
        assert raw[96:]==typed['error'].encode('utf-8');return
    assert typed['ok'] is True and status==0 and errorlen==0;value=typed['value']
    assert flags==sum(bit for field,bit in [('full',4),('regex',8),('include_hidden',16)] if value[field] is True)
    assert presence==sum(bit for field,bit in [('context',1),('max_depth',2),('pattern',4),('content',8),('full',16),('regex',32),('include_hidden',64)] if value[field] is not None)
    assert context==(value['context'] or 0) and depth==(value['max_depth'] or 0)
    at=96;assert raw[at:at+pathlen]==value['path'].encode();at+=pathlen
    endpoint(raw[at:at+startlen],value['start']);at+=startlen
    endpoint(raw[at:at+endlen],value['end']);at+=endlen
    assert raw[at:at+patternlen]==(value['pattern'] or '').encode();at+=patternlen
    assert raw[at:at+contentlen]==(value['content'] or '').encode();at+=contentlen
    assert at==len(raw)

def argument_literal(encoded):
    text=encoded.decode();at=text.index('"arguments":')+len('"arguments":')
    _,end=json.JSONDecoder().raw_decode(text,at);return text[at:end].encode()

def compare_params(corpus,output):
    rows=read_rows(corpus/'semantic-cases.jsonl');required=set(range(24))|set(range(200,239));assert set(rows)==required
    successful=errors=diagnostic_bytes=projection_bytes=0
    for input_name,reference_name,identifiers in [('sdk-input.jsonl','sdk.stdout',set(range(24))),
                                               ('parameter-input.jsonl','parameter.stdout',set(range(200,239)))]:
        references=read_rows(output/reference_name);seen=set()
        for encoded in (output/input_name).read_bytes().split(b'\n'):
            if not encoded:continue
            request=json.loads(encoded);cid=request['case_id']
            if cid not in identifiers:continue
            original=references[cid];native=rows[cid];assert request['name']==original['name']==native['name']
            assert bytes.fromhex(native['input_hex'])==argument_literal(encoded)
            assert len(original['handler_observations'])==1
            typed=original['handler_observations'][0]['typed'];actual=bytes.fromhex(native['output_hex'])
            typed_projection(actual,typed);projection_bytes+=len(actual)
            if typed['ok']:successful+=1
            else:errors+=1;diagnostic_bytes+=len(typed['error'].encode())
            seen.add(cid)
        assert seen==identifiers
    return dict(cases=len(rows),formal_sdk_typed_cases=24,additional_typed_cases=39,
        typed_successful=successful,typed_errors=errors,complete_diagnostic_bytes=diagnostic_bytes,
        complete_projection_bytes=projection_bytes,every_input_byte_equal=True,
        every_original_typed_value_equal=True,every_original_diagnostic_byte_equal=True,
        actual_sdk_parameters_router_claimed=False)
