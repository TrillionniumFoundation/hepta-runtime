"""Build and qualify the private slot57 port, or only reread its exact evidence.

The worker dependency is a five-image checked-byte successor to the retained qualified baseline.
This recipe performs no Rust replay and makes no public SDK scheduling claim.
"""
import argparse,hashlib,json,os,pathlib,stat,sys
sys.dont_write_bytecode=True
HERE=pathlib.Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from read_port import read,doc,sha,verify as verify_port
from port_build_evidence import verify_build
from port_reader_controls import verify_controls as verify_port_controls
from read_engine_edges import verify as verify_engine
from engine_reader_controls import verify_controls as verify_engine_controls

WORKER_PIN='6b5983d351b380b53f5838dc7ca8adac523d6c95ac12df51c3f975faf60d53c2'

def encoded(value):return (json.dumps(value,sort_keys=True,indent=2)+'\n').encode()
def file_pin(path):
    assert stat.S_ISREG(path.lstat().st_mode)
    with path.open('rb') as stream:h=hashlib.file_digest(stream,'sha256').hexdigest()
    return {'bytes':path.stat().st_size,'sha256':h}
def files(root):
    result={}
    def visit(folder):
        assert stat.S_ISDIR(folder.lstat().st_mode)
        for path in sorted(folder.iterdir()):
            mode=path.lstat().st_mode
            if stat.S_ISDIR(mode):visit(path)
            else:assert stat.S_ISREG(mode);result[path.relative_to(root).as_posix()]=file_pin(path)
    visit(root);return result
def source_evidence(package,pins):
    raw=read(package/'PACKAGE.json');assert sha(raw)==pins
    value=json.loads(raw);assert value['schema']=='hepta.runtime.bellman-public-port-source.v1'
    actual=files(package);assert set(actual)==set(value['files'])|{'PACKAGE.json'}
    assert {k:v for k,v in actual.items() if k!='PACKAGE.json'}==value['files']
    assert value['worker_source_pins_sha256']==WORKER_PIN and value['public_handler_qualified'] is False
    assert sha(read(package/'worker-source/tests/hia_native/blocking_worker/worker-source-pins.json'))==WORKER_PIN
    return {'package_sha256':pins,'source_files':len(value['files']),'worker_source_pins_sha256':WORKER_PIN}

def commands(context):
    package=pathlib.Path(context['package']);out=pathlib.Path(context['capture']);py=[context['python'],'-I','-S','-B']
    result={
      'portable-build':(py+[str(package/'recipe/build_port.py'),'--package',str(package),'--hepta',context['hepta'],'--worker-build',context['worker_build'],'--output',str(out/'build-v3')],180),
      'portable-pack':(py+[str(package/'recipe/pack_port.py'),'--package',str(package),'--hepta',context['hepta'],'--build',str(out/'build-v3')],180),
      'engine-fixture':(py+[str(package/'recipe/build_engine_fixture.py'),'--package',str(package),'--output',str(out/'engine-fixture-v1')],60),
    }
    for script,build,name in [('lifecycle_port.py',out/'build-v3','lifecycle-v1'),('engine_edges.py',out,'engine-edges-v1')]:
        result[name+'-supervisor']=(py+[str(package/'recipe/run_owned.py'),'--script',str(package/'recipe'/script),'--build',str(build),'--output',str(out/name)],65)
    result['port-reader-controls']=(py+[str(package/'recipe/port_reader_controls.py'),'--run',str(out/'lifecycle-v1'),'--build',str(out/'build-v3'),'--output',str(out/'controls-v4')],180)
    result['engine-reader-controls']=(py+[str(package/'recipe/engine_reader_controls.py'),'--build',str(out/'build-v3'),'--fixture',str(out/'engine-fixture-v1'),'--run',str(out/'engine-edges-v1'),'--overlay',str(package/'engine-overlay'),'--author',str(package/'authoring/author_engine_overlay.py'),'--output',str(out/'engine-controls-v1')],60)
    return result

def verify(package,capture,worker_build,pins,*,compare_report=True):
    sources=source_evidence(package,pins);context=doc(capture/'recipe.json')
    assert context['schema']=='hepta.runtime.bellman-public-port-recipe.v1' and context['package_sha256']==pins
    assert context['capture_mode'] in ('single-recipe-process','composed-owned-processes')
    assert context['fresh_rust_replayed'] is False and context['public_handler_qualified'] is False
    sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker'))
    from worker_common import process_evidence
    plan=commands(context)
    assert {p.name for p in (capture/'processes').iterdir()}=={name+'.'+suffix for name in plan for suffix in ('json','stdout','stderr')}
    receipts={}
    for name,(command,limit) in plan.items():
        row=process_evidence(capture,name,command,limit);assert row['cwd']==context['capture']
        if context['capture_mode']=='single-recipe-process':assert row['parent_pid']==context['producer_pid']
        assert read(capture/'processes'/(name+'.stderr'))==b'';receipts[name]=row
    built=verify_build(capture/'build-v3',package/'source',worker_build,package/'worker-source')
    component=doc(capture/'build-v3/component.json')
    assert json.loads(read(capture/'processes/portable-build.stdout'))=={k:v for k,v in component.items() if k!='members'}
    assert json.loads(read(capture/'processes/portable-pack.stdout'))==doc(capture/'build-v3/pack.receipt.json')
    assert json.loads(read(capture/'processes/engine-fixture.stdout'))==doc(capture/'engine-fixture-v1/BUILD.json')['images']
    for name in ('lifecycle-v1','engine-edges-v1'):
        inner=doc(capture/name/'process.json');assert inner['parent_pid']==receipts[name+'-supervisor']['pid']
        assert json.loads(read(capture/'processes'/(name+'-supervisor.stdout')))==inner
    native=verify_port(capture/'build-v3',capture/'lifecycle-v1/capture')
    engine=verify_engine(capture/'build-v3',capture/'engine-fixture-v1',capture/'engine-edges-v1',package/'engine-overlay',package/'authoring/author_engine_overlay.py')
    controls=verify_port_controls(capture/'lifecycle-v1',capture/'build-v3',capture/'controls-v4')
    engine_controls=verify_engine_controls(capture/'build-v3',capture/'engine-fixture-v1',capture/'engine-edges-v1',package/'engine-overlay',package/'authoring/author_engine_overlay.py',capture/'engine-controls-v1')
    for label,folder,omit in [('port-reader-controls','controls-v4',{'run_files','build_files','refusals','processes'}),('engine-reader-controls','engine-controls-v1',{'run_files','fixture_files','refusals'})]:
        expected={k:v for k,v in doc(capture/folder/'RESULT.json').items() if k not in omit}
        assert json.loads(read(capture/'processes'/(label+'.stdout')))==expected
    expected_entries={'build-v3','engine-fixture-v1','lifecycle-v1','engine-edges-v1','controls-v4','engine-controls-v1','processes','recipe.json','QUALIFICATION.json'}
    actual_entries={p.name for p in capture.iterdir()}
    assert actual_entries==(expected_entries if compare_report else expected_entries-{'QUALIFICATION.json'})
    result={'schema':'hepta.runtime.bellman-public-port-qualification.v1','status':'PRIVATE_SHARED_PORT_PASS','sources':sources,'build':built,'lifecycle':native,'engine_edges':engine,'port_reader_controls':controls,'engine_reader_controls':engine_controls,'runtime_hia_images':8,'new_runtime_images':3,'baseline_qualified_worker_images':5,'unchanged_baseline_worker_images':2,'checked_byte_successor_worker_images':3,'fresh_rust_replayed':False,'native_or_rust_executed_by_reader':False,'public_handler_qualified':False,'public_request_scheduler_qualified':False,'whole_runtime_replaced':False}
    if compare_report:assert read(capture/'QUALIFICATION.json')==encoded(result)
    return result

def main():
    p=argparse.ArgumentParser()
    for name in ('package','capture','worker-build'):p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--package-sha256',required=True);p.add_argument('--hepta',type=pathlib.Path)
    p.add_argument('--phase',choices=('all','verify'),required=True);a=p.parse_args()
    package=a.package.resolve();capture=a.capture.resolve();worker=a.worker_build.resolve();source_evidence(package,a.package_sha256)
    if a.phase=='verify':print(json.dumps(verify(package,capture,worker,a.package_sha256),sort_keys=True));return
    assert a.hepta is not None and not capture.exists();capture.mkdir()
    context={'schema':'hepta.runtime.bellman-public-port-recipe.v1','capture_mode':'single-recipe-process','producer_pid':os.getpid(),'package':str(package),'capture':str(capture),'worker_build':str(worker),'hepta':str(a.hepta.resolve()),'python':sys.executable,'package_sha256':a.package_sha256,'fresh_rust_replayed':False,'public_handler_qualified':False}
    (capture/'recipe.json').write_bytes(encoded(context))
    sys.path.insert(0,str(package/'worker-source/tests/hia_native/blocking_worker_ci'))
    from capture_writer_trace import run
    for label,(command,limit) in commands(context).items():run(capture,label,command,dict(os.environ),limit=limit)
    result=verify(package,capture,worker,a.package_sha256,compare_report=False)
    (capture/'QUALIFICATION.json').write_bytes(encoded(result));print(json.dumps(result,sort_keys=True))
if __name__=='__main__':main()
