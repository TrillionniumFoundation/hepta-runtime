"""Execute typed HIA admission and Value joins; export every original replay row."""
from pathlib import Path
import argparse, gzip, hashlib, json, os, struct, subprocess, sys, time
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'tests/hia_native'))
sys.path.insert(0,str(ROOT/'scripts'))
from execution_json_cases import cases
from execution_shadow_cases import fixture,record,packet
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError

def framed(kind,raw):return struct.pack('<8s3Q',b'HXSJSN01',1,kind,len(raw))+raw
def value_frame(raw):return struct.pack('<8s2Q',b'HSJVAL01',1,len(raw))+raw
def identity(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def invoke(session,wire):
    try:
        output=session.invoke(wire);return len(output),output
    except (NativeRejected,NativeCapacityError) as error:return error.code,b''

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--serde-manifest',type=Path,required=True);parser.add_argument('--core-manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False,mode=0o700)
    meta=json.loads(args.manifest.read_bytes());assert meta['source_sha256']==identity(ROOT/'native/execution_json.hepta')
    start=time.monotonic();counts={};input_hash=hashlib.sha256();output_hash=hashlib.sha256();input_bytes=output_bytes=total=accepted=joins=0;native_calls=value_calls=0
    with NativeModule(args.manifest,manifest_sha256=identity(args.manifest)) as native,NativeModule(args.serde_manifest,manifest_sha256=identity(args.serde_manifest)) as values,NativeModule(args.core_manifest,manifest_sha256=identity(args.core_manifest)) as core:
      with native.session(output_capacity=8<<20,workspace_capacity=32<<20) as ns,values.session(output_capacity=16<<20,workspace_capacity=256<<20) as vs,core.session(output_capacity=16384,workspace_capacity=65536) as cs,gzip.open(out/'requests.hex.gz','wb') as request_file,gzip.open(out/'native-output.hex.gz','wb') as output_file,gzip.open(out/'row-identities.jsonl.gz','wb') as row_file:
        for label,kind,raw in cases():
            request=(str(kind)+' '+raw.hex()+'\n').encode();request_file.write(request);input_hash.update(request);input_bytes+=len(request)
            admitted=raw;code=0
            if kind>=10:
                code,admitted=invoke(vs,value_frame(raw));value_calls+=1
            if code<0xfffffffc:
                code,output=invoke(ns,framed(kind%10,admitted));native_calls+=1
            else:output=b''
            assert code!=0xfffffffe,(label,total,'unexpected capacity refusal')
            assert code==0xffffffff or code==len(output),(label,total,hex(code))
            if code!=0xffffffff:
                accepted+=1
                if kind%10<=2:
                    assert output[:8]==b'HXSREC01'
                    joined=cs.invoke(output);assert joined[:8]==b'HXSRSL01';joins+=1
                else:json.loads(output)
            row=f'{code:08x}:'.encode()+output.hex().encode()+b'\n';output_file.write(row);output_hash.update(row);output_bytes+=len(row)
            row_file.write((json.dumps({'index':total,'label':label,'kind':kind,'input_sha256':hashlib.sha256(request).hexdigest(),'output_sha256':hashlib.sha256(row).hexdigest(),'code':code},sort_keys=True,separators=(',',':'))+'\n').encode())
            counts[label]=counts.get(label,0)+1;total+=1
      ordinary=json.dumps({'record':record(fixture())},separators=(',',':')).encode();wire=framed(1,ordinary);expected=packet(fixture());refused=0
      bad=[wire[:n] for n in range(32)]+[wire+b'x']
      for offset,value in [(0,0),(8,0),(8,3),(16,0),(16,7),(24,len(ordinary)+1),(24,2**64-1)]:
          data=bytearray(wire);struct.pack_into('<Q',data,offset,value);bad.append(bytes(data))
      for data in bad:
          code,output,_=native.invoke_raw(data,output_capacity=16384,workspace_capacity=65536,output_fill=0xa6,workspace_fill=0x5a)
          assert code==0xffffffff and output==b'\xa6'*16384;refused+=1
      capacities=0
      for size in (0,1,len(expected)-1):
          code,output,_=native.invoke_raw(wire,output_capacity=size,workspace_capacity=65536,output_fill=0xa6,workspace_fill=0x5a)
          assert code==0xfffffffe and output==b'\xa6'*size;capacities+=1
      for size in (0,1,65535):
          code,output,_=native.invoke_raw(wire,output_capacity=16384,workspace_capacity=size,output_fill=0xa6,workspace_fill=0x5a)
          assert code==0xfffffffe and output==b'\xa6'*16384;capacities+=1
      assert native.invoke(wire,output_capacity=len(expected),workspace_capacity=65536)==expected
      elf=args.manifest.parent/meta['standalone']['path'];assert identity(elf)==meta['standalone']['sha256'];elf_records=[]
      for kind,raw,wanted in [(1,ordinary,expected),(2,json.dumps(record(fixture()),separators=(',',':')).encode(),expected),(3,json.dumps(record(fixture())['record']['binding'],separators=(',',':')).encode(),None),(4,b'{"file_read":null}',b'"file_read"'),(5,b'"current"',b'"current"'),(6,b'["not_granted"]',b'{"state":"not_granted"}')]:
          if wanted is None:wanted=raw
          process=subprocess.run([str(elf)],input=framed(kind,raw),capture_output=True,env={'PATH':''},timeout=5)
          assert process.returncode==0 and not process.stderr and process.stdout==wanted
          elf_records.append({'kind':kind,'exit_code':0,'stdout_sha256':hashlib.sha256(process.stdout).hexdigest()})
    report={'schema':'hepta.runtime.execution-json-native-corpus.v1','status':'NATIVE_COMPLETE_RUST_REPLAY_REQUIRED','cases':total,'accepted':accepted,'counts':counts,'actual_typed_native_calls':native_calls,'actual_value_native_calls':value_calls,'actual_core_joins':joins,'framing_refusals':refused,'capacity_refusals':capacities,'actual_elf_requests':len(elf_records),'elf':elf_records,'input_raw_sha256':input_hash.hexdigest(),'input_raw_bytes':input_bytes,'output_raw_sha256':output_hash.hexdigest(),'output_raw_bytes':output_bytes,'source_sha256':meta['source_sha256'],'image_sha256':meta['image_sha256'],'elapsed_seconds':time.monotonic()-start,'production_activated':False,'error_message_equality_qualified':False}
    report['files']={p.name:{'bytes':p.stat().st_size,'sha256':identity(p)} for p in out.iterdir()}
    (out/'native-corpus.json').write_text(json.dumps(report,sort_keys=True,indent=2)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
