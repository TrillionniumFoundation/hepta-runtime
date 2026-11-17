"""Freeze and assemble source only. Never execute a generated native image."""
from pathlib import Path
import argparse,base64,hashlib,importlib.util,json,os,stat,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
PIN=lambda b:{'bytes':len(b),'sha256':SHA(b)}
ENC=lambda v:(json.dumps(v,sort_keys=True,indent=2)+'\n').encode()
def put(path,raw):
    assert not path.exists(),path
    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
def inspect(root,exclude=()):
    result={}
    for p in sorted(root.rglob('*')):
        assert not p.is_symlink(),p
        if p.is_file() and p.relative_to(root).as_posix() not in exclude:
            assert stat.S_ISREG(p.stat().st_mode),p
            result[p.relative_to(root).as_posix()]={**PIN(p.read_bytes()),'mode':stat.S_IMODE(p.stat().st_mode)}
    return result
def process(cmd,root,name):
    start=time.monotonic()
    try:
        q=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60,check=False)
        outcome={'returncode':q.returncode,'timed_out':False};out,err=q.stdout,q.stderr
    except subprocess.TimeoutExpired as e:
        outcome={'returncode':None,'timed_out':True};out,err=e.stdout or b'',e.stderr or b''
    put(root/(name+'.stdout'),out);put(root/(name+'.stderr'),err)
    receipt={'command':cmd,'elapsed_seconds':time.monotonic()-start,'budget_seconds':60,
        **outcome,'stdout':PIN(out),'stderr':PIN(err)}
    put(root/(name+'.json'),ENC(receipt))
    assert outcome=={'returncode':0,'timed_out':False},receipt
    return out
def main(args):
    package=args.package.resolve(strict=True);output=args.output.resolve()
    assert not output.exists();output.mkdir(parents=True)
    profile=(package/'SOURCE_PROFILE.json').read_bytes()
    assert SHA(profile)==args.manifest_sha256
    declaration=json.loads(profile)
    assert inspect(package,('SOURCE_PROFILE.json',))==declaration['files']
    put(output/'SOURCE_PROFILE.json',profile)
    hepta=args.hepta.resolve(strict=True);installed=args.installed_source.resolve(strict=True)
    assert process(['git','-C',str(hepta),'rev-parse','HEAD'],output,'hepta-head').strip()==b'd3e2c90173cf733e42b299d0c4274df4b593a12f'
    assert process(['git','-C',str(hepta),'rev-parse','HEAD^{tree}'],output,'hepta-tree').strip()==b'8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
    spec=importlib.util.spec_from_file_location('extract_wait_author',package/'author.py')
    author=importlib.util.module_from_spec(spec);spec.loader.exec_module(author)
    result=author.apply(installed,hepta,output/'source')
    put(output/'SOURCE_ROWS.json',ENC(result['source_rows']))
    put(output/'AUTHOR_RESULT.json',ENC(result))
    sys.path.insert(0,str(output/'source/scripts'))
    spec=importlib.util.spec_from_file_location('extract_wait_build',output/'source/scripts/public_nine_build.py')
    builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
    assemblies=[]
    for name,fixture,journal,trace in [('production',False,False,False),('private',True,False,False),('trace',False,True,True)]:
        raw=builder.adapter_source(output/'source',private_fixture=fixture,
            private_pump_fixture=journal,private_pump_trace=trace).encode()
        src=output/'assembly'/(name+'.S');obj=output/'assembly'/(name+'.o')
        put(src,raw)
        process(['as','--64','-o',str(obj),str(src)],output/'assembly',name+'-assemble')
        undefined=process(['nm','-u',str(obj)],output/'assembly',name+'-undefined')
        assert not undefined.strip(),undefined.decode(errors='replace')
        assemblies.append({'name':name,'source':PIN(raw),'object':PIN(obj.read_bytes()),
            'generated_image_executions':0})
    summary={'status':'SOURCE_AND_THREE_BOUNDARIES_ASSEMBLED_PASS',
        'source_files':result['source_files'],'source_binding_sha256':result['source_binding_sha256'],
        'changed_runtime_source_files':len(result['changed_files']),'assemblies':assemblies,
        'native_or_rust_semantic_executions':0,'budgets':{'process':60,'job_minutes':15},
        'public_wait_qualified':False,'full_async_qualified':False,'whole_runtime_replaced':False}
    put(output/'RESULT.json',ENC(summary))
    for name in ['native/runtime_mcp_composition.json','native/runtime_mcp_extract_wait_composition.json',
                 'native/runtime_mcp_sources.json']:
        raw=(output/'source'/name).read_bytes()
        chunks=[raw[i:i+3072] for i in range(0,len(raw),3072)]
        for i,part in enumerate(chunks):
            print('WAIT_SOURCE_EXPORT '+json.dumps({'path':name,'index':i,'count':len(chunks),
                **PIN(raw),'part':base64.b64encode(part).decode()},sort_keys=True),flush=True)
    raw=(output/'SOURCE_ROWS.json').read_bytes()
    chunks=[raw[i:i+3072] for i in range(0,len(raw),3072)]
    for i,part in enumerate(chunks):
        print('WAIT_SOURCE_EXPORT '+json.dumps({'path':'SOURCE_ROWS.json','index':i,'count':len(chunks),
            **PIN(raw),'part':base64.b64encode(part).decode()},sort_keys=True),flush=True)
    put(output/'MANIFEST.json',ENC({'schema':'hepta.complete-source-capture.v1','files':inspect(output)}))
    check=json.loads((output/'MANIFEST.json').read_bytes())
    assert inspect(output,('MANIFEST.json',))==check['files']
    print(json.dumps(summary,sort_keys=True),flush=True)
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--package',type=Path,required=True)
    p.add_argument('--installed-source',type=Path,required=True)
    p.add_argument('--hepta',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--manifest-sha256',required=True);args=p.parse_args()
    try:main(args)
    except BaseException as e:
        if args.output.exists() and not (args.output/'FAILURE.json').exists():
            (args.output/'FAILURE.json').write_bytes(ENC({'status':'FAIL','type':type(e).__name__,
                'error':str(e),'traceback':traceback.format_exc(),'semantic_executions':0}))
        raise
