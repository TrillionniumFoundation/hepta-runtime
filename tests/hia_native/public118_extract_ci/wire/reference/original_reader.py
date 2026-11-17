"""Pure complete original process, registry and private observation reader."""
from pathlib import Path
import hashlib,io,json,struct,tarfile,tomllib

def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def get(raw,at):return struct.unpack_from('<Q',raw,at)[0]
def read(path):return json.loads(path.read_bytes())
def packets(raw):
    at=0;result=[]
    while at<len(raw):
        assert len(raw)-at>=8;size=get(raw,at);at+=8
        assert size<=len(raw)-at;result.append(raw[at:at+size]);at+=size
    assert at==len(raw);return result
def source(package):
    package=package.resolve(strict=True);manifest=read(package/'package-manifest.json')
    actual={p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    assert actual==set(manifest['files'])|{'package-manifest.json'}
    for name,expected in manifest['files'].items():
        relative=Path(name);assert not relative.is_absolute() and '..' not in relative.parts
        path=package/relative;assert not path.is_symlink() and path.resolve()==path and pin(path.read_bytes())==expected,name
    return pin((package/'package-manifest.json').read_bytes())

def verify_original(package,original):
    report=read(original/'original.json');assert report['status']=='ACTUAL_ORIGINAL_HANDLER_OBSERVED' and report['case_count']==683
    assert report['source_manifest']==source(package)
    assert report['original_source_sha256']=='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
    assert report['native_executed'] is False and report['whole_runtime_replaced'] is False and report['public_handler_qualified'] is False
    for p in (package/'reference').rglob('*'):
        if p.is_file():assert p.read_bytes()==(original/'reference'/p.relative_to(package/'reference')).read_bytes()
    assert source(original/'recipe-source')==source(package)
    assert pin((original/'original-plan').read_bytes())==report['binary']
    for name,limit in [('rustc-version',30),('cargo-version',30),('cargo-build',300),('cargo-metadata',120),('params-original',60),('original',60)]:
        process=read(original/'processes'/(name+'.json'))
        assert process['started'] is True and process['timed_out'] is False and process['returncode']==0
        assert process['pid']==process['pgid'] and process['pid']>0 and process['parent_pid']>0
        assert process['timeout_seconds']==limit and 0<=process['elapsed_ns']<=(limit+1)*1000000000
        for suffix in ('stdout','stderr'):
            raw=(original/'processes'/(name+'.'+suffix)).read_bytes();assert pin(raw)=={key:process[suffix][key] for key in ('bytes','sha256')}
    assert (original/'processes/rustc-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
    lock=tomllib.loads((original/'reference/full_plan/Cargo.lock').read_text())
    locked={(p['name'],p['version']):p for p in lock['package'] if 'source' in p};registry=read(original/'registry.json')
    metadata=read(original/'processes/cargo-metadata.stdout');seen=set();total_source_files=0
    for package_row in metadata['packages']:
        if package_row['source'] is None:assert package_row['name']=='hia-bellman-call-reference';continue
        key=package_row['name'],package_row['version'];assert key not in seen;seen.add(key)
        item=locked[key];name=key[0]+'-'+key[1];raw=(original/'registry'/(name+'.crate')).read_bytes()
        assert pin(raw)==registry[name]['archive'] and pin(raw)['sha256']==item['checksum'] and package_row['source']==item['source']
        expected=read(original/'registry'/(name+'.source.json'));actual={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
            for member in t:
                if member.isdir():continue
                assert member.isfile() and member.name.startswith(name+'/')
                relative=member.name[len(name)+1:];assert relative not in actual and '..' not in Path(relative).parts
                actual[relative]=pin(t.extractfile(member).read())
        assert actual==expected and len(actual)==registry[name]['actual_source_files'];total_source_files+=len(actual)
    assert seen==set(locked) and len(registry)==report['registry_packages']==132
    inputs=(original/'original.stdin').read_bytes();assert pin(inputs)==report['complete_input']
    raw_inputs=packets(inputs);frozen_inputs=read(package/'reference/params/corpus-domain.json')['cases'];assert len(raw_inputs)==len(frozen_inputs)==683
    for raw,frozen in zip(raw_inputs,frozen_inputs):assert pin(raw)=={key:frozen[key] for key in ('bytes','sha256')}
    typed_report=read(original/'typed/original.json')
    assert typed_report['status']=='ORIGINAL_OBSERVED_NATIVE_REQUIRED' and typed_report['case_count']==683
    assert typed_report['successful_typed']==401 and typed_report['typed_errors']==282
    assert typed_report['source_manifest']==source(package) and typed_report['original_source_sha256']==report['original_source_sha256']
    assert typed_report['native_qualified'] is False and typed_report['whole_runtime_replaced'] is False and typed_report['public_handler_qualified'] is False
    assert pin((original/'original-params').read_bytes())==typed_report['binary']
    typed=(original/'typed/original.stdout').read_bytes();assert typed==(original/'processes/params-original.stdout').read_bytes()
    assert pin(typed)==typed_report['complete_output']==read(package/'domain.json')['original_output']
    assert (original/'typed/original.stdin').read_bytes()==inputs and pin(inputs)==typed_report['complete_input']
    typed_records=packets(typed);domain_rows=read(package/'domain.json')['cases']
    assert len(typed_records)==len(typed_report['cases'])==len(domain_rows)==683
    for frame,row,declared,raw_input in zip(typed_records,typed_report['cases'],domain_rows,raw_inputs):
        assert frame[:8]==b'HBPOR001'
        status,canonical_length,body_length,count,r0,r1,r2=struct.unpack_from('<7Q',frame,8)
        assert (r0,r1,r2)==(0,0,0) and len(frame)==64+canonical_length+body_length
        canonical=frame[64:64+canonical_length];body=frame[64+canonical_length:]
        assert status==row['status']==declared['status'] and count==row['states']==declared['states']
        assert (row['group'],row['name'])==(declared['group'],declared['name'])
        assert pin(raw_input)==row['raw'] and pin(canonical)==row['canonical']==declared['canonical'] and pin(body)==row['body']==declared['body']
    baseline=(package/'reference/params_observer_baseline.rs').read_text()
    params=(package/'reference/full_plan/params.rs').read_text()
    assert params[params.index('fn word('):]==baseline[baseline.index('fn word('):]
    assert '#[path = "../weight_bellman.rs"]\nmod original;\nuse original::{BellmanAction, BellmanPlanParams};' in params
    data=(original/'processes/original.stdout').read_bytes();assert pin(data)==report['complete_output']
    records=packets(data);domain=read(package/'domain.json');assert len(records)==len(report['cases'])==len(domain['cases'])==683
    counts={0:0,1:0,2:0}
    for index,(frame,row,declared) in enumerate(zip(records,report['cases'],domain['cases'])):
        assert frame[:8]==b'HBCOR001' and get(frame,48)==index and get(frame,56)==0
        status,canonical_length,text_length,before,after=struct.unpack_from('<5Q',frame,8)
        assert len(frame)==64+canonical_length+text_length and before<=after
        canonical=frame[64:64+canonical_length];text=frame[64+canonical_length:]
        assert (row['index'],row['group'],row['name'])==(index,declared['group'],declared['name'])
        assert pin(canonical)==declared['canonical']==row['canonical'] and pin(text)==row['text']
        assert status==row['status'] and row['before_ns']==before and row['after_ns']==after
        if status==0:
            value=json.loads(text);assert 0<=value['native_operation_wall_seconds']<=(after-before)/1e9
        else:text.decode('utf-8')
        counts[status]+=1
    assert counts=={0:301,1:282,2:100}
    return dict(cases=683,success_json=301,typed_errors=282,business_errors=100,registry_packages=132,
        complete_registry_source_files=total_source_files,complete_original_typed_cases=683,complete_typed_output=typed_report['complete_output'],original_timing_physically_bounded=True,
        original_complete_output=report['complete_output'],full_error_bytes_read=True)
