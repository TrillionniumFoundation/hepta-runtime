"""Four distinct physical Rust evidence refusals; never execute a reference."""
from pathlib import Path
import hashlib,json,shutil,stat
from common import files,pin,put,require
import read_reference
def cases(build):
    archives=sorted((build/'registry-archives').glob('*.crate'))
    require(archives,'full retained registry archives')
    return [('compiled-source','project/src/original_extract_dispatch.rs','tail'),
        ('reference-binary','bin/hepta-batch-sdk-current-original-oracle','tail'),
        ('registry-archive',archives[0].relative_to(build).as_posix(),'tail'),
        ('fresh-claim','BUILD.json','fresh')]
def inventory(build):
    return {n:{**row,'mode':stat.S_IMODE((build/n).stat().st_mode)} for n,row in files(build).items()}
def mutation(raw,kind):
    if kind=='tail':
        require(raw,'nonempty physical control input');return raw[:-1]+bytes([raw[-1]^1])
    data=json.loads(raw);require(data['fresh_original_build'] is True,'actual fresh original claim')
    data['fresh_original_build']=False;return (json.dumps(data,indent=2,sort_keys=True)+'\n').encode()
def rejection(clone,source):
    try:read_reference.original(clone,source)
    except (ValueError,AssertionError) as error:return {'type':type(error).__name__,'message':str(error)}
    raise ValueError('physical reference mutation accepted')
def create(build,source,root):
    build,source,root=Path(build),Path(source),Path(root);root.mkdir()
    before=inventory(build);put(root/'source-inventory.json',before);rows=[]
    for name,path,kind in cases(build):
        case=root/name;clone=case/'tree';clone.mkdir(parents=True)
        for n,row in before.items():
            dst=clone/n;dst.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(build/n,dst);dst.chmod(row['mode'])
        dst=clone/path;mode=stat.S_IMODE(dst.stat().st_mode);raw=mutation(dst.read_bytes(),kind)
        try:dst.chmod(mode|stat.S_IWUSR);dst.write_bytes(raw)
        finally:dst.chmod(mode)
        row={'name':name,'path':path,'kind':kind,'before':before[path],'after':{**pin(dst),'mode':mode},'rejection':rejection(clone,source),'native_or_rust_executed':False}
        put(case/'rejection.json',row);rows.append(row)
    require(inventory(build)==before,'original bytes or modes changed during controls')
    report={'status':'PHYSICAL_REFERENCE_CONTROLS_PASS','refusals':4,'cases':rows,'native_or_rust_executed':False,'controls_write_owned_clones':True}
    put(root/'report.json',report);return report
def verify(build,source,root):
    before=inventory(build);require(json.loads((root/'source-inventory.json').read_bytes())==before,'original reference changed')
    rows=[]
    for name,path,kind in cases(build):
        clone=root/name/'tree';actual=inventory(clone);wanted=dict(before);raw=mutation((build/path).read_bytes(),kind)
        wanted[path]={**wanted[path],'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
        require(actual==wanted and (clone/path).read_bytes()==raw,'complete physical reference clone '+name)
        row={'name':name,'path':path,'kind':kind,'before':before[path],'after':wanted[path],'rejection':rejection(clone,source),'native_or_rust_executed':False}
        require(json.loads((root/name/'rejection.json').read_bytes())==row,'actual reference rejection differs '+name);rows.append(row)
    require({p.name for p in root.iterdir()}=={'source-inventory.json','report.json',*(c[0] for c in cases(build))},'complete reference control inventory')
    report={'status':'PHYSICAL_REFERENCE_CONTROLS_PASS','refusals':4,'cases':rows,'native_or_rust_executed':False,'controls_write_owned_clones':True}
    require(json.loads((root/'report.json').read_bytes())==report,'complete reference control report')
    return report
