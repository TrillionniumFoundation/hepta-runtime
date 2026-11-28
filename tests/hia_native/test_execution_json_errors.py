"""Compare actual canonical-Value parameter errors to retained original execution."""
from pathlib import Path
import argparse,gzip,hashlib,json,struct,sys,time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/hia_native'));sys.path.insert(0,str(ROOT/'scripts'))
from execution_json_cases import cases
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def invoke(session,wire):
    try:
        data=session.invoke(wire);return len(data),data
    except (NativeRejected,NativeCapacityError) as error:return error.code,b''

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',required=True,type=Path);parser.add_argument('--serde-manifest',required=True,type=Path);parser.add_argument('--original',required=True,type=Path);parser.add_argument('--output',required=True,type=Path);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(mode=0o700,parents=True,exist_ok=False);start=time.monotonic();observations=[];mismatches=[];counts={'value_invalid':0,'typed_success':0,'typed_error':0};errors=set()
    meta=json.loads(args.manifest.read_bytes());assert meta['source_sha256']==sha(ROOT/'native/execution_json.hepta')
    with NativeModule(args.manifest,manifest_sha256=sha(args.manifest)) as native,NativeModule(args.serde_manifest,manifest_sha256=sha(args.serde_manifest)) as values:
      with native.session(output_capacity=8<<20,workspace_capacity=32<<20) as ns,values.session(output_capacity=16<<20,workspace_capacity=256<<20) as vs,gzip.open(args.original,'rb') as original:
        for index,((label,kind,raw),line) in enumerate(zip(cases(),original,strict=True)):
            observed=json.loads(line)
            if kind<10:continue
            vc,canonical=invoke(vs,struct.pack('<8s2Q',b'HSJVAL01',1,len(raw))+raw)
            category='value_invalid';wanted=b'';result=b'';code=vc
            if vc==0xffffffff:
                match=not observed['accepted'] and observed['category'] in ('Syntax','Eof')
            else:
                assert vc<0xfffffffc,(label,index,hex(vc))
                code,result=invoke(ns,struct.pack('<8s3Q',b'HXSJSN01',2,kind%10,len(canonical))+canonical)
                if observed['accepted']:
                    category='typed_success';wanted=bytes.fromhex(observed['value']['packet']) if kind%10<=2 else observed['value']['canonical'].encode()
                else:
                    category='typed_error';errors.add(observed['error']);message=observed['error'].encode();wanted=b'HXSERR01'+struct.pack('<Q',len(message))+message
                    assert observed['category']=='Data' and observed['line']==observed['column']==0
                match=code==len(wanted) and result==wanted
            counts[category]+=1
            observations.append({'index':index,'label':label,'kind':kind,'category':category,'matches':match,'native_code':code,'output_sha256':hashlib.sha256(result).hexdigest()})
            if not match:
                mismatches.append({'index':index,'label':label,'kind':kind,'native_code':code,'wanted':wanted[:8192].decode(errors='replace'),'observed':result[:8192].decode(errors='replace'),'canonical':canonical[:8192].decode(errors='replace')})
    with gzip.open(out/'observations.jsonl.gz','wb') as f:
        for row in observations:f.write((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode())
    (out/'mismatches.json').write_text(json.dumps(mismatches,sort_keys=True,indent=2)+'\n')
    report={'status':'PASS' if not mismatches else 'FAIL','cases':sum(counts.values()),'counts':counts,'unique_original_errors':len(errors),'mismatches':len(mismatches),'source_sha256':meta['source_sha256'],'image_sha256':meta['image_sha256'],'original_output_gzip_sha256':sha(args.original),'elapsed_seconds':time.monotonic()-start,'production_activated':False}
    (out/'result.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))
    if mismatches:print(json.dumps(mismatches[:12],ensure_ascii=True),file=sys.stderr)
    assert not mismatches

if __name__=='__main__':main()
