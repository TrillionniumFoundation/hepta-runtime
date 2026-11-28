"""Reject physically altered shadow compilation, corpus and completion evidence."""
from pathlib import Path
import argparse,hashlib,json,os,shutil,sys,tempfile,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'scripts'))
import hia_native_execution_qualification as q

def replacement(path,raw):
    temporary=path.with_name(path.name+'.mutated')
    with temporary.open('xb') as stream:stream.write(raw)
    os.replace(temporary,path)

def main():
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,default=ROOT);p.add_argument('--hepta',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--corpus',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    for key in ('core','json','errors','controller'):p.add_argument('--'+key+'-stdout',type=Path,required=True)
    a=p.parse_args();root=a.runtime.resolve(strict=True);bundle=a.manifest.resolve(strict=True);corpus=a.corpus.resolve(strict=True)
    output=a.output.resolve();output.mkdir(parents=True,exist_ok=False,mode=0o700);started=time.monotonic()
    stdout=dict(zip(q.TESTS,(a.core_stdout.resolve(strict=True),a.json_stdout.resolve(strict=True),a.errors_stdout.resolve(strict=True),a.controller_stdout.resolve(strict=True))))
    baseline=q.checked_native(bundle,corpus,source_root=root,hepta=a.hepta,stdout=stdout)
    original_output=bundle.parents[3];manifest_relative=bundle.relative_to(original_output);corpus_relative=corpus.relative_to(original_output)
    def snapshot(parent):
        sources=parent/'source';observed=parent/'evidence'
        for name in baseline['source_pins']:
            dest=sources/name;dest.parent.mkdir(parents=True,exist_ok=True);os.link(root/name,dest)
        for name in baseline['artifact_sha256']:
            dest=observed/name;dest.parent.mkdir(parents=True,exist_ok=True);os.link(original_output/name,dest)
        return sources,observed
    mutations=[
      ('missing-stdout',None),('empty-stdout-set',None),
      ('stdout-report','stdout'),('core-cases','core/native-corpus.json'),
      ('json-accepted','json/native-corpus.json'),('missing-error-category','errors/result.json'),
      ('missing-controller-controls','controller/result.json'),('controller-output-truncated','controller/outputs.hex.gz'),
      ('core-output-truncated','core/native-output.hex.gz'),('json-input-truncated','json/requests.hex.gz'),
      ('error-observations-truncated','errors/observations.jsonl.gz'),('unexpected-error','errors/mismatches.json'),
      ('missing-call-trace','controller/call-trace.json'),('bundle-activation','bundle'),
      ('source-altered','source'),('image-altered','image'),('compiled-receipt','receipt'),
      ('executable-altered','elf'),('packer-receipt','packer'),('native-manifest-profile','profile')]
    refusals=[]
    # Place immutable hard-link snapshots beside the qualification output, on
    # its actual filesystem. Every mutation atomically replaces its own link.
    with tempfile.TemporaryDirectory(prefix='execution-evidence-',dir=original_output.parent) as temp:
        for index,(label,target) in enumerate(mutations):
            parent=Path(temp)/str(index);sources,observed=snapshot(parent)
            cloned_bundle=observed/manifest_relative;cloned_corpus=observed/corpus_relative
            cloned_stdout={name:observed/path.relative_to(original_output) for name,path in stdout.items()}
            if target is None:
                if label=='missing-stdout':cloned_stdout.pop(q.TESTS[0])
                else:cloned_stdout={}
            elif target=='source':
                path=sources/'native/execution_shadow.hepta';replacement(path,path.read_bytes()+b'\n')
            elif target=='stdout':replacement(cloned_stdout[q.TESTS[0]],b'{}\n')
            elif target in ('bundle','image','receipt','elf','packer','profile'):
                bundle_doc=json.loads(cloned_bundle.read_bytes());member=bundle_doc['members']['core'];build=cloned_bundle.parents[2]
                path=build/member['manifest'];meta=json.loads(path.read_bytes())
                if target=='bundle':bundle_doc['production_activated']=True;replacement(cloned_bundle,q.json_bytes(bundle_doc))
                elif target=='image':
                    path=path.parent/meta['image'];data=bytearray(path.read_bytes());data[-1]^=1;replacement(path,data)
                elif target=='elf':
                    path=path.parent/meta['standalone']['path'];data=bytearray(path.read_bytes());data[-1]^=1;replacement(path,data)
                elif target=='profile':meta['workspace_capacity']=65536;replacement(path,q.json_bytes(meta))
                else:
                    path=path.parent/('module.receipt.json' if target=='receipt' else 'pack.receipt.json')
                    data=json.loads(path.read_bytes());data['source_unchanged']=False;replacement(path,q.json_bytes(data))
            else:
                path=cloned_corpus/target
                if label.endswith('truncated'):replacement(path,path.read_bytes()[:-5])
                elif label=='unexpected-error':replacement(path,b'[{}]\n')
                elif label=='missing-call-trace':replacement(path,b'[]\n')
                else:
                    data=json.loads(path.read_bytes())
                    if label=='core-cases':data['cases']-=1
                    elif label=='json-accepted':data['accepted']-=1
                    elif label=='missing-error-category':data['counts'].pop('typed_error')
                    else:data['receipt_controls']=[]
                    replacement(path,q.json_bytes(data))
            try:q.checked_native(cloned_bundle,cloned_corpus,source_root=sources,hepta=a.hepta,stdout=cloned_stdout)
            except (ValueError,KeyError,OSError,EOFError) as error:refusals.append({'label':label,'refused':True,'reason':str(error)})
            else:raise AssertionError('altered evidence admitted: '+label)
    after=q.checked_native(bundle,corpus,source_root=root,hepta=a.hepta,stdout=stdout)
    q.exact(after,baseline,'evidence controls changed immutable original bytes')
    report={'schema':'hepta.runtime.execution-evidence-controls.v1','status':'PASS','accepted':1,'refusals':len(refusals),
            'controls':refusals,'source_pins':q.source_pins(root),'native_calls_added':0,'rust_calls_added':0,
            'baseline_sha256':q.sha(q.json_bytes(baseline)),'elapsed_seconds':time.monotonic()-started,
            'production_activated':False,'whole_runtime_replaced':False}
    (output/'result.json').write_bytes(q.json_bytes(report));print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
