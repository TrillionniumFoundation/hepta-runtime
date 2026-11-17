"""Qualify the single HIA zeroing helper with complete real buffers in fixed CI budgets."""
from pathlib import Path
import argparse,ast,hashlib,json,os,re,shutil,signal,stat,subprocess,sys,time,traceback
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'base'))
import source_check,restore,archive_stream,read_only_guard
import author,cases,capture,read_pairs
from retained_pairs import pin,save
def put(path,value):path.parent.mkdir(parents=True,exist_ok=True);path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def source_admit(profile):
    raw=(ROOT/'PACKAGE.json').read_bytes();assert hashlib.sha256(raw).hexdigest()==profile
    rows=json.loads(raw)['files'];assert {p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file()}==set(rows)|{'PACKAGE.json'}
    for name,row in rows.items():
        path=ROOT/name;assert pin(path)=={k:row[k] for k in ('bytes','sha256')} and not path.is_symlink() and stat.S_IMODE(path.stat().st_mode)==0o644
        if name.endswith('.py'):ast.parse(path.read_text())
    return source_check.check(ROOT/'base','e2cdde0e66a38d4bf0b313c1f764b5bcf73e77c9fbf0ef6796b08d1ce09f15c4')
def command(folder,label,argv):
    started=time.monotonic();timed=False
    try:
        p=subprocess.run(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=60);code=p.returncode;stdout=p.stdout;stderr=p.stderr
    except subprocess.TimeoutExpired as e:timed=True;code=None;stdout=e.stdout or b'';stderr=e.stderr or b''
    (folder/(label+'.stdout')).write_bytes(stdout);(folder/(label+'.stderr')).write_bytes(stderr)
    put(folder/(label+'.json'),{'argv':argv,'exit_code':code,'timed_out':timed,'deadline_seconds':60,'elapsed_seconds':time.monotonic()-started,'stdout':pin(folder/(label+'.stdout')),'stderr':pin(folder/(label+'.stderr'))})
    assert code==0 and not timed,(label,code)
def restore_inputs(inputs,out):
    retained=out/'retained';retained.mkdir()
    for role in ('native','native-proof'):
        restore.artifact_meta(inputs,role,restore.CONFIG[role]);shutil.copy2(inputs/(role+'.json'),retained/(role+'.artifact.json'))
    report=archive_stream.archive(inputs/'native.zip',restore.CONFIG['native'],read_pairs.choose_native,output=retained/'native');put(out/'FULL_NATIVE_ARCHIVE_READ.json',report)
    shutil.copy2(inputs/'native-proof.zip',retained/'native-proof.zip');restore.proof_extract(retained/'native-proof.zip',retained/'native-proof');put(out/'RETAINED_NATIVE_PROOF.json',restore.proof_verify(retained/'native-proof.zip',retained/'native-proof'))
    return retained/'native'
def compile_images(base,hepta,out):
    sys.path.insert(0,str(hepta));sys.path.insert(0,str(base/'ci-package/graph/source/scripts'))
    import hia_native_build as native
    before=(ROOT/'before.hepta').read_bytes();after=(ROOT/'candidate.hepta').read_bytes();fast=(ROOT/'zero_helper.txt').read_bytes()
    assert (base/'ci-package/graph/source/native/caller_authority.hepta').read_bytes()==before
    put(out/'SOURCE_REPRODUCTION.json',author.verify(before,after,fast))
    generated=out/'generated';generated.mkdir()
    probe=(ROOT/'probe_entry.txt').read_bytes();sources={'before-owner':ROOT/'before.hepta','after-owner':ROOT/'candidate.hepta'}
    for side,raw in (('before',before),('after',after)):
        m=list(re.finditer(rb'fn f0\([\s\S]*?\nend\n',raw));assert len(m)==1
        a,b=m[0].span();value=raw[:a]+probe+raw[b:];path=generated/(side+'-helper.hepta');path.write_bytes(value)
        from hepta.hia_agent_assembly import assemble_program
        one=assemble_program(raw).as_dict();two=assemble_program(value).as_dict();assert one['functions'][1:]==two['functions'][1:]
        sources[side+'-helper']=path
    target=out/'build';target.mkdir();shutil.copytree(base/'instances/bootstrap',target/'bootstrap');build=native.NativeBuild(hepta,target);compiler=build.bootstrap()
    compiler_pin=pin(compiler);assert compiler_pin=={'bytes':673413,'sha256':'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'}
    old=base/'production/build/modules/public-task-batch-extract-authority/manifest.json';old_md=json.loads(old.read_bytes())
    assert old_md['source_sha256']==author.BEFORE and old_md['image_sha256']=='795da0a7234853e9e1afbf8f993321a2f12aa86f16c06a6374a1913473693417'
    manifests={'before-owner':old};compiles={}
    for name in ('after-owner','before-helper','after-helper'):
        manifest=build.compile('clear-'+name,sources[name],standalone=None);manifests[name]=manifest
        compiles[name]={'receipt':(manifest.parent/'module.receipt.json').relative_to(out).as_posix(),'manifest':manifest.relative_to(out).as_posix()}
    images={};folder=out/'images';folder.mkdir()
    for name,manifest in manifests.items():
        md=json.loads(manifest.read_bytes());original=manifest.parent/md['image'];image=folder/(name+'.image.bin');shutil.copy2(original,image)
        src=folder/(name+'.hepta');shutil.copy2(sources[name],src)
        assert pin(image)['sha256']==md['image_sha256'] and pin(src)['sha256']==md['source_sha256']
        images[name]={'path':image.relative_to(out).as_posix(),'pin':pin(image),'source':src.relative_to(out).as_posix(),'source_pin':pin(src)}
    observer=out/'observer';observer.mkdir();command(observer,'assemble',['as','--64','-o',str(observer/'observer.o'),str(ROOT/'observer.S')]);command(observer,'link',['ld','-m','elf_x86_64','-z','noexecstack','-o',str(observer/'observer.elf'),str(observer/'observer.o')])
    result={'compiler':compiler_pin,'dependency':build.identity,'fresh_leaf_compiles':3,'retained_owner_images':1,'images':images,'compiles':compiles,'observer':pin(observer/'observer.elf')};put(out/'BUILD.json',result);return result

def run_pairs(out,build):
    domain=cases.domain();put(out/'DOMAIN.json',domain)
    report={'status':'RUNNING','domain':pin(out/'DOMAIN.json'),'pairs':[],'lane_seconds':180,'per_exchange_seconds':60,'whole_public_domain_qualified':False}
    put(out/'PAIRS.json',report);root=out/'pairs';root.mkdir();before=time.monotonic()
    assert signal.getitimer(signal.ITIMER_REAL)==(0.0,0.0);previous=signal.getsignal(signal.SIGALRM)
    def expire(signum,frame):
        signal.setitimer(signal.ITIMER_REAL,0);raise TimeoutError('unchanged whole 180 second native comparison lane')
    signal.signal(signal.SIGALRM,expire);signal.setitimer(signal.ITIMER_REAL,180)
    try:
        for item in domain['cases']:
            i=item['index'];spec=item['spec'];folder=root/f'{i:03d}';folder.mkdir();data=cases.inputs(spec)
            row={'index':i,'spec':spec,'initial':{name:save(folder,'initial-'+name+'.gz',raw) for name,raw in zip(('input','output','workspace'),data,strict=True)},'sides':[]}
            for side in ('before','after'):
                image=out/build['images'][side+'-'+spec['kind']]['path'];row['sides'].append(capture.invoke(folder,side,image,out/'observer/observer.elf',data))
            put(folder/'CASE.json',row);report['pairs'].append(row);put(out/'PAIRS.json',report)
        report['status']='COMPLETE_OWNER_CLEAR_PAIRS_CAPTURED'
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error)});raise
    finally:
        signal.setitimer(signal.ITIMER_REAL,0);signal.signal(signal.SIGALRM,previous);report['elapsed_seconds']=time.monotonic()-before;put(out/'PAIRS.json',report)
    assert report['elapsed_seconds']<180
def main():
    p=argparse.ArgumentParser()
    for name in ('input','hepta','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--profile',required=True);a=p.parse_args();assert os.environ.get('GITHUB_ACTIONS')=='true'
    admitted=source_admit(a.profile);out=a.output.resolve();out.mkdir(exist_ok=False);shutil.copytree(ROOT,out/'source')
    report={'status':'RUNNING','source_commit':os.environ['GITHUB_SHA'],'run_id':os.environ['GITHUB_RUN_ID'],'source_profile':a.profile,'source_admission':admitted,'runtime_rust_executions':0,'full_public_domain_qualified':False,'old_production_owner_recompiled':False}
    put(out/'RUN.json',report)
    try:
        base=restore_inputs(a.input.resolve(),out);build=compile_images(base,a.hepta.resolve(strict=True),out);run_pairs(out,build)
        guard=read_only_guard.guarded(lambda:read_pairs.read(out,ROOT),roots=[out,ROOT],foreign_path='/proc/self/status');put(out/'READONLY.json',guard)
        import controls
        controlfolder=out.parent/(out.name+'-controls');checks=controls.run(out,ROOT,controlfolder);shutil.move(str(controlfolder),str(out/'reader-controls'));report['controls']=checks;report['paired_read']=guard['evidence'];report['status']='CALLER_CLEAR_SOURCE_AND_COMPLETE_BUFFERS_PASS'
        print(json.dumps({'status':report['status'],'source':report['source_commit'],'after':guard['evidence']['image_after'],'pairs':35,'actual_native_calls':70,'traps':guard['evidence']['actual_trap_pairs'],'metrics':guard['evidence']['metrics']},sort_keys=True))
    except BaseException as error:
        report.update(status='FAIL',failure={'type':type(error).__name__,'message':str(error),'traceback':traceback.format_exc()});raise
    finally:put(out/'RUN.json',report)
if __name__=='__main__':main()
