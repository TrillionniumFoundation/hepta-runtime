"""Eight physical rehashed refusals; verification never reconstructs a clone."""
import argparse
import gzip
import json
from pathlib import Path
import shutil
import sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
import static_common as c
import read_static
from read_static_build import build_check
sys.path.insert(0,str(ROOT/'pipeline'))
import read_projection

LABELS=('static-input','static-output','static-workspace-tail','missing-case',
        'source-rehashed-profile','compiler-rehashed-stdout','projection-input','projection-sdk-output')

def inventory(output):
    source=output/'source'
    sources,_=c.source_check(source)
    static=read_static.verify(source,output/'static-build',output/'static-native')
    projection=read_projection.verify(source/'pipeline',output/'projection-build',output/'projection-native')
    return {'source':sources.files,'static-build':static['build_files'],'static-native':static['native_files'],
        'projection-build':projection['build_files'],'projection-native':projection['native_files']}

def selected(label):
    return ('source','projection-build','projection-native') if label.startswith('projection-') else ('source','static-build','static-native')

def admit(clone,label):
    if label.startswith('projection-'):
        return read_projection.verify(clone/'source/pipeline',clone/'projection-build',clone/'projection-native')
    return read_static.verify(clone/'source',clone/'static-build',clone/'static-native')

def mutation(label,read):
    """Return the exact complete after bytes; no files are changed here."""
    changed={}
    def doc(path):return json.loads(read(path))
    def full(path):return gzip.decompress(read(path))
    def compressed(path,raw):changed[path]=gzip.compress(raw,compresslevel=1,mtime=0)
    if label in ('static-input','static-output','static-workspace-tail','missing-case'):
        report=doc('static-native/result.json')
        if label=='missing-case':report['records'].pop()
        else:
            row=report['records'][0 if label=='static-input'else 18]['calls'][-1]
            suffix={'static-input':'input','static-output':'output','static-workspace-tail':'workspace'}[label]
            path='static-native/'+row['prefix']+'.'+suffix+'.gz';raw=bytearray(full(path))
            at=0 if label=='static-input'else (37 if label=='static-output'else len(raw)-1)
            raw[at]^=1;raw=bytes(raw);compressed(path,raw);row[suffix+'_sha256']=c.sha(raw)
        changed['static-native/result.json']=c.encoded(report)
    elif label=='source-rehashed-profile':
        path='source/native/runtime_mcp_catalog_eleven.hepta';raw=read(path)+b'\n'
        changed[path]=raw;profile=doc('source/source-profile.json')
        profile['files']['native/runtime_mcp_catalog_eleven.hepta']=c.pin(raw)
        changed['source/source-profile.json']=c.encoded(profile)
    elif label=='compiler-rehashed-stdout':
        path='static-build/modules/catalog-nine/module.stdout.log';value=doc(path)
        value['native_elapsed_ns']+=1;changed[path]=c.encoded(value)
    elif label=='projection-input':
        report=doc('projection-native/result.json');row=report['shapes'][0]['policy_calls'][0]
        path='projection-native/'+row['prefix']+'.input.gz';raw=bytearray(full(path));raw[-1]^=1
        compressed(path,bytes(raw));row['input_sha256']=c.sha(raw)
        changed['projection-native/result.json']=c.encoded(report)
    else:
        assert label=='projection-sdk-output'
        report=doc('projection-native/result.json');row=report['shapes'][2]['sdk'][1]['call']
        path='projection-native/'+row['prefix']+'.output.gz';raw=bytearray(full(path))
        at=raw.index(b'batch_edit');raw[at]=ord('c');raw=bytes(raw)
        compressed(path,raw);row['output_sha256']=c.sha(raw)
        changed['projection-native/'+row['prefix']+'.json']=raw[64:row['code']]
        changed['projection-native/result.json']=c.encoded(report)
    return changed

def refusal(clone,label):
    try:admit(clone,label)
    except (ValueError,AssertionError,KeyError,RuntimeError,OSError)as error:
        return {'label':label,'error_type':type(error).__name__,'message':str(error)or type(error).__name__}
    raise AssertionError('mutated physical evidence was admitted: '+label)

def run(output,controls):
    originals=inventory(output);controls.mkdir(parents=True,exist_ok=False);rows=[]
    def read(path):return (output/path).read_bytes()
    for label in LABELS:
        clone=controls/label;clone.mkdir()
        for role in selected(label):
            for name,expected in originals[role].items():
                raw=(output/role/name).read_bytes();assert c.pin(raw)==expected
                path=clone/role/name;path.parent.mkdir(parents=True,exist_ok=True);c.put(path,raw)
        changes=mutation(label,read)
        for name,raw in changes.items():(clone/name).write_bytes(raw)
        result=refusal(clone,label)
        result['changed_files']={name:c.pin(raw)for name,raw in changes.items()}
        c.put(clone/'refusal.json',result);rows.append(result)
    result={'schema':'hepta.runtime.catalog-eleven-physical-controls.v1','status':'PASS','refusals':8,
        'native_executions':0,'rust_executions':0,'independent_regular_file_copies':True,'rows':rows}
    c.put(controls/'result.json',result)
    return verify(output,controls)

def verify(output,controls):
    originals=inventory(output);r=c.BASE.Reader(controls);report=r.document('result.json')
    assert report['schema']=='hepta.runtime.catalog-eleven-physical-controls.v1' and report['status']=='PASS'
    assert report['refusals']==8 and report['native_executions']==report['rust_executions']==0
    assert report['independent_regular_file_copies']is True and [row['label']for row in report['rows']]==list(LABELS)
    for label,row in zip(LABELS,report['rows'],strict=True):
        changes=mutation(label,lambda name:(output/name).read_bytes())
        clone=controls/label
        assert r.document(label+'/refusal.json')==row
        assert row['changed_files']=={name:c.pin(raw)for name,raw in changes.items()}
        all_names={role+'/'+name for role in selected(label)for name in originals[role]}
        actual={path.relative_to(clone).as_posix()for path in clone.rglob('*')if path.is_file()}
        assert actual==all_names|{'refusal.json'}
        for name in sorted(all_names):
            role,relative=name.split('/',1)
            expected=changes.get(name)
            if expected is None:
                expected=(output/name).read_bytes();assert c.pin(expected)==originals[role][relative]
            assert r.raw(label+'/'+name)==expected
        assert refusal(clone,label)=={key:row[key]for key in ('label','error_type','message')}
    return {'status':'EIGHT_PHYSICAL_REHASHED_REFUSALS_PASS','refusals':8,'semantic_process_launches':0,
        'tree_writes':False,'files':r.files}

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--controls',type=Path,required=True)
    a=p.parse_args();result=run(a.output.resolve(strict=True),a.controls.absolute())
    print(json.dumps({k:v for k,v in result.items()if k!='files'},sort_keys=True))
