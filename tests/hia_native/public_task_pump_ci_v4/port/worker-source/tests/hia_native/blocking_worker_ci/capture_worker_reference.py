"""Fresh locked original plan futures and owned worker-lifetime observations."""
from __future__ import annotations
import argparse,hashlib,io,json,os,sys,tarfile,tomllib
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_writer_trace import run,put,sha

BASE='tests/hia_native/blocking_worker_ci'
ORIGINAL='tests/hia_native/blocking_worker/reference/weight_bellman.rs'
ORIGINAL_SHA='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'

def environment(work):
    env=dict(os.environ)
    for key in list(env):
        if key in {'RUSTFLAGS','RUSTDOCFLAGS','RUSTC','RUSTDOC','RUSTC_WRAPPER','RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET',
                   'CARGO_BUILD_RUSTC','CARGO_BUILD_RUSTDOC','CARGO_BUILD_RUSTC_WRAPPER','CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER','CARGO_BUILD_TARGET_DIR'} or (
                key.startswith('CARGO_') and (key.endswith('RUSTFLAGS') or key.endswith('RUSTDOCFLAGS') or key.endswith('_LINKER') or key.endswith('_RUNNER'))):
            del env[key]
    env.update(RUSTUP_TOOLCHAIN='1.95.0',CARGO_HOME=str(work/'cargo-home'),CARGO_TARGET_DIR=str(work/'target'),
               CARGO_ENCODED_RUSTFLAGS='',CARGO_ENCODED_RUSTDOCFLAGS='',PYTHONDONTWRITEBYTECODE='1',PYTHONHASHSEED='0')
    return env

def build(source,output,pins):
    for name,pin in pins['files'].items():
        raw=(source/name).read_bytes();assert len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],name
        put(output/'source'/name,raw)
    assert sha((output/'source'/ORIGINAL).read_bytes())==ORIGINAL_SHA
    work=output.parent/(output.name+'-build-work');work.mkdir(mode=0o700);env=environment(work)
    run(output,'rustc-version',['rustc','--version','--verbose'],env,limit=30)
    assert (output/'processes/rustc-version.stdout').read_bytes().startswith(b'rustc 1.95.0 ')
    run(output,'cargo-version',['cargo','--version'],env,limit=30)
    manifest=output/'source'/BASE/'worker-reference/Cargo.toml';lock=manifest.with_name('Cargo.lock');lock_raw=lock.read_bytes()
    run(output,'cargo-build',['cargo','build','--locked','--manifest-path',str(manifest)],env,limit=300)
    assert lock.read_bytes()==lock_raw
    run(output,'cargo-metadata',['cargo','metadata','--locked','--format-version','1','--manifest-path',str(manifest)],env,limit=120)
    metadata=json.loads((output/'processes/cargo-metadata.stdout').read_bytes())
    locked={(p['name'],p['version']):p for p in tomllib.loads(lock_raw.decode())['package'] if 'source' in p};registry={}
    for package in metadata['packages']:
        if package['source'] is None:
            assert package['name']=='hia-bellman-worker-reference';continue
        name=package['name']+'-'+package['version'];pin=locked[(package['name'],package['version'])]
        candidates=list((work/'cargo-home/registry/cache').glob('*/'+name+'.crate'));assert len(candidates)==1
        raw=candidates[0].read_bytes();assert sha(raw)==pin['checksum'] and package['source']==pin['source']
        actual=Path(package['manifest_path']).parent;rows={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as tar:
            for member in tar:
                if member.isdir():continue
                assert member.isfile() and member.name.startswith(name+'/')
                relative=member.name[len(name)+1:];assert '..' not in Path(relative).parts and relative not in rows
                data=tar.extractfile(member).read();assert (actual/relative).read_bytes()==data
                rows[relative]={'bytes':len(data),'sha256':sha(data)}
        put(output/'registry'/(name+'.crate'),raw);put(output/'registry'/(name+'.source.json'),rows)
        registry[name]={'archive_bytes':len(raw),'sha256':sha(raw),'actual_source_files':len(rows)}
    assert set(registry)=={name+'-'+version for name,version in locked}
    put(output/'registry.json',registry)
    generated=list((work/'target/debug/build').glob('hia-bellman-worker-reference-*/out/original_bellman_with_observer.rs'));assert len(generated)==1
    original=(output/'source'/ORIGINAL).read_bytes();observer=(manifest.parent/'trace_access.rs').read_bytes()
    assert generated[0].read_bytes()==original+b'\n'+observer
    assert generated[0].with_name('weight_bellman.rs').read_bytes()==original
    old_observer=(output/'source'/BASE/'tracer/trace_access.rs').read_bytes();old_function=old_observer[old_observer.index(b'pub fn trace_canonical_writer'):]
    assert observer.count(old_function)==1
    for name in ['original_bellman_with_observer.rs','weight_bellman.rs','module.rs']:put(output/'generated'/name,generated[0].with_name(name).read_bytes())
    binary=work/'target/debug/hia-bellman-worker-reference';actual=output/'original-worker';put(actual,binary.read_bytes());actual.chmod(0o500)
    return actual,env,registry

def replay(output,binary,env,mode,inputs=b''):
    put(output/(mode+'.inputs'),inputs)
    process=run(output,mode,[str(binary),mode],env,limit=60,stdin=inputs)
    observer=json.loads((output/('processes/'+mode+'.stderr')).read_bytes())
    assert observer=={'pid':process['pid'],'parent_pid':process['parent_pid'],'pgid':process['pgid']}
    return [json.loads(line) for line in (output/('processes/'+mode+'.stdout')).read_bytes().splitlines()]

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-root',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    source=a.source_root.resolve(strict=True);output=a.output.resolve();output.mkdir(mode=0o700)
    raw=(source/BASE/'worker-reference-pins.json').read_bytes();pins=json.loads(raw)
    put(output/'worker-reference-pins.json',raw)
    binary,env,registry=build(source,output,pins)
    sys.path.insert(0,str(output/'source/tests/hia_native/blocking_worker'))
    sys.path.insert(0,str(output/'source/tests/hia_native/blocking_worker/reference'))
    from worker_cases import graph_cases,original_graphs,duration_cases,lines
    from qualify_bellman import ERRORS
    graphs=original_graphs();actual=replay(output,binary,env,'ordinary',lines(graphs))
    assert len(actual)==len(graphs)==363
    successes=refusals=0
    for index,(declared,result) in enumerate(zip(graphs,actual)):
        assert result['index']==index and result['name']==declared['name'] and result['available_before']==result['available_after']==2
        assert result['after_ns']>=result['before_ns']
        if declared['expected_error_code'] is None:
            assert result['kind']==0;value=json.loads(result['text']);assert len(value)==36
            assert 0<=value['native_operation_wall_seconds']<=(result['after_ns']-result['before_ns'])/1e9
            successes+=1
        else:
            assert result['kind']==1 and result['text']==ERRORS[declared['expected_error_code']]
            refusals+=1
    durations=replay(output,binary,env,'duration',lines(duration_cases()));assert len(durations)==len(duration_cases())
    for ns,row in zip(duration_cases(),durations):assert row['nanoseconds']==ns
    life=replay(output,binary,env,'lifecycle');assert len(life)==1;life=life[0]
    assert life['queued_permits']==life['after_cancel_permits']==0 and life['drained_permits']==2 and life['cancelled'] is True
    assert life['third_before']==life['third_after']=='native Bellman planning capacity exhausted; no work admitted'
    assert json.loads(life['surviving_result'])['states'][0]['value']==2
    retained=replay(output,binary,env,'retained');assert len(retained)==1;retained=retained[0]
    assert retained['ready_count']==40 and retained['final_permits']==2
    assert [x['index'] for x in retained['results']]==list(reversed(range(40)))
    for row in retained['results']:assert json.loads(row['text'])['states'][0]['value']==row['index']+.25
    queue=replay(output,binary,env,'queue-hold');assert len(queue)==1;queue=queue[0]
    assert queue['after_ns']-queue['before_ns']>=30000000000 and queue['held_permits']==1 and queue['final_permits']==2
    assert json.loads(queue['result'])['native_operation_wall_seconds']<30
    for mode,writer,message in [('core-deadline',False,'Bellman planning exceeded its 30-second compute deadline'),
                                ('writer-deadline',True,'Bellman canonical serialization exceeded its deadline')]:
        rows=replay(output,binary,env,mode);assert len(rows)==1;row=rows[0]
        assert row['writer'] is writer and row['message']==message and row['accepted_bytes']==0
        assert row['accepted_sha256']==sha(b'') and row['original_source_sha256']==ORIGINAL_SHA
    trace_inputs=(output/'source'/BASE/'writer-cases.jsonl').read_bytes();trace=replay(output,binary,env,'writer-trace',trace_inputs)
    assert len(trace)==6
    fragment_counts=[]
    for index,row in enumerate(trace):
        assert row['index']==index;t=row['trace'];fragments=[bytes.fromhex(x) for x in t['write_calls']];canonical=bytes.fromhex(t['canonical_hex'])
        assert b''.join(fragments)==canonical and len(canonical)==t['canonical_bytes'] and sha(canonical)==t['request_sha256']
        assert t['original_source_sha256']==ORIGINAL_SHA and t['observer_changes_original_write_body'] is False
        fragment_counts.append(len(fragments))
    assert fragment_counts==[8,27,111,153,42,111]
    result={'schema':'hepta.runtime.bellman-worker.original-development.v1','status':'ACTUAL_REFERENCE_CAPTURED',
            'source_pins_sha256':sha(raw),'source_commit':os.environ.get('GITHUB_SHA'),'binary_sha256':sha(binary.read_bytes()),
            'graph_cases':363,'graph_successes':successes,'graph_refusals':refusals,'duration_cases':len(durations),
            'registry_packages':len(registry),'writer_calls':sum(fragment_counts),'source_functions_modified':False,
            'native_executed':False,'full_worker_qualified':False,'public_handler_qualified':False}
    put(output/'RESULT.json',result);print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
