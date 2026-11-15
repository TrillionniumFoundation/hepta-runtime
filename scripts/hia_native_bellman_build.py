"""Source-pinned build and full private Bellman qualification on the dev host.

--skip-rust produces explicitly incomplete local-only evidence. No deployment,
production selector, public handler or original runtime source is changed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

ORIGINAL_SHA256='254de61b7a169ab0a01583feb9562051fa9d477d89d98683263c52ea5545a4a7'
HERE=Path(__file__).resolve().parent
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def run(command,folder,label,**kwargs):
    start=time.monotonic()
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=180,**kwargs)
    (folder/(label+'.stdout')).write_bytes(result.stdout)
    (folder/(label+'.stderr')).write_bytes(result.stderr)
    row={'command':list(map(str,command)),'exit_code':result.returncode,'wall_seconds':time.monotonic()-start,
         'stdout_sha256':hashlib.sha256(result.stdout).hexdigest(),'stderr_sha256':hashlib.sha256(result.stderr).hexdigest()}
    (folder/(label+'.json')).write_text(json.dumps(row,indent=2)+'\n')
    if result.returncode:raise RuntimeError('required process failed: '+label)
    return result,row

def helper_graphs(hepta,arithmetic,bellman):
    sys.path.insert(0,str(hepta))
    from hepta.hia_agent_assembly import assemble_program
    a=assemble_program(arithmetic.read_bytes()).as_dict()
    b=assemble_program(bellman.read_bytes()).as_dict()
    left=a['functions'][1:];right=b['functions'][5:]
    assert len(left)==len(right)==14
    def normalize(rows,start):
        mapping={'f'+str(i+start):'helper'+str(i)for i in range(14)}
        def visit(v):
            if isinstance(v,dict):return {k:(mapping[x] if k in ('name','function')and isinstance(x,str)and x in mapping else visit(x))for k,x in v.items()}
            if isinstance(v,list):return [visit(x)for x in v]
            return v
        return visit(rows)
    normalized=normalize(left,1)
    assert normalized==normalize(right,5),'arithmetic helper graph differs in Bellman'
    for document in (a,b):
        assert not document.get('exports')
        for f in document['functions']:
            assert len(f['blocks'])<=256
            assert max(len(block['params'])for block in f['blocks'])<=16
            for block in f['blocks']:
                for op in block['ops']:assert not op['op'].startswith(('float.','foreign.','ffi.'))
    return hashlib.sha256(json.dumps(normalized,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--hepta',type=Path,required=True);p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--sources',type=Path,default=HERE);p.add_argument('--drivers',type=Path,default=HERE)
    p.add_argument('--original',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--bootstrap-from',type=Path);p.add_argument('--skip-rust',action='store_true')
    a=p.parse_args()
    for field in ('hepta','runtime','sources','drivers','original','output'):
        setattr(a,field,getattr(a,field).resolve())
    if a.bootstrap_from:a.bootstrap_from=a.bootstrap_from.resolve()
    a.output.mkdir();sys.dont_write_bytecode=True
    assert sha(a.original)==ORIGINAL_SHA256,'latest original Bellman source differs'
    files={name:sha(a.sources/name)for name in ('finite_binary64.hepta','bellman_core.hepta')}
    helper_sha=helper_graphs(a.hepta,a.sources/'finite_binary64.hepta',a.sources/'bellman_core.hepta')
    build=a.output/'build'
    if a.bootstrap_from:
        (build/'bootstrap').mkdir(parents=True)
        for name in ('B1.image.bin','B2.image.bin','B3.image.bin','bootstrap.json'):
            shutil.copyfile(a.bootstrap_from/name,build/'bootstrap'/name)
    sys.path.insert(0,str(a.runtime/'scripts'))
    from hia_native_build import NativeBuild
    builder=NativeBuild(a.hepta,build)
    arithmetic=builder.compile('finite-binary64',a.sources/'finite_binary64.hepta',standalone='filter')
    bellman=builder.compile('bellman-core',a.sources/'bellman_core.hepta',standalone='filter')
    processes=[]
    for label,manifest,script in [('arithmetic',arithmetic,'qualify_binary64.py'),('bellman',bellman,'qualify_bellman.py'),
                                  ('signed-zero',bellman,'qualify_signed_zero.py')]:
        _,row=run([sys.executable,str(a.drivers/script),'--runtime',str(a.runtime),'--manifest',str(manifest),
            '--output',str(a.output/label)],a.output,label+'-qualification');processes.append(row)
    _,row=run([sys.executable,str(a.drivers/'make_bellman_oracle.py'),'--original',str(a.original),
        '--output',str(a.output/'original')],a.output,'original-extraction');processes.append(row)
    if not a.skip_rust:
        version,row=run(['rustc','+1.95.0','--version'],a.output,'rust-version');processes.append(row)
        assert version.stdout.startswith(b'rustc 1.95.0 '),'reference compiler differs'
        original=a.output/'original'/'bellman_original_oracle.rs'
        expected=b''.join((a.output/name/'native.bin').read_bytes()for name in ('bellman','signed-zero'))
        inputs=b''.join((a.output/name/'inputs.bin').read_bytes()for name in ('bellman','signed-zero'))
        for label,flags in [('debug',[]),('optimized',['-O'])]:
            binary=a.output/'original'/('oracle-'+label)
            _,row=run(['rustc','+1.95.0','--edition=2021',*flags,str(original),'-o',str(binary)],a.output,'rust-build-'+label);processes.append(row)
            result,row=run([str(binary)],a.output,'rust-replay-'+label,input=inputs);processes.append(row)
            assert result.stdout==expected,'complete original/native stream differs: '+label
    sys.path.insert(0,str(a.drivers))
    from qualify_bellman import corpus,pack_graph,reference
    metadata=json.loads(bellman.read_bytes());elf=bellman.parent/metadata['standalone']['path']
    for name,graph,error in corpus():
        if name not in ('original-known','original-ties','original-maximum-4096'):continue
        result,row=run([str(elf)],a.output,'static-'+name,input=pack_graph(graph));processes.append(row)
        assert not result.stderr and result.stdout==reference(graph),'static process result differs'
    assert sha(a.original)==ORIGINAL_SHA256
    assert files=={name:sha(a.sources/name)for name in files},'HIA source changed during qualification'
    report={'schema':'hepta.runtime.hia-bellman-private-qualification.v1',
        'status':'LOCAL_NATIVE_ONLY'if a.skip_rust else 'PASS',
        'whole_handler_replaced':False,'production_activated':False,'old_stack_removal_qualified':False,
        'original_source_sha256':ORIGINAL_SHA256,'hia_source_sha256':files,'shared_helper_graph_sha256':helper_sha,
        'native_manifests':{str(path.relative_to(a.output)):sha(path)for path in (arithmetic,bellman)},
        'original_replay_completed':not a.skip_rust,'processes':processes}
    (a.output/'REPORT.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report))
if __name__=='__main__':main()
