"""Source-bound fresh execution of the full native atomic-write kernel corpus."""
from __future__ import annotations
import argparse,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[1]
for p in (HERE,ROOT/'scripts'):
    if str(p) not in sys.path:sys.path.insert(0,str(p))
from atomic_write_kernel import run
from hia_native_atomic_write_build import inspect_bundle,obj,exact,file_record

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--manifest',type=Path,default=os.environ.get('HIA_ATOMIC_MANIFEST'))
    p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if not a.manifest:p.error('qualified native atomic manifest is required')
    before=inspect_bundle(a.manifest)
    metadata=obj(a.manifest);binary=a.manifest.parent/metadata['executable']
    result=run(binary,a.output)
    exact(inspect_bundle(a.manifest),before,'atomic artifact changed during kernel qualification')
    result['artifact_evidence']=before
    result['wrapper_source']=file_record(__file__)
    (a.output/'result.json').write_text(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n')
    print(json.dumps({k:v for k,v in result.items() if k!='observations'},sort_keys=True))

if __name__=='__main__':main()
