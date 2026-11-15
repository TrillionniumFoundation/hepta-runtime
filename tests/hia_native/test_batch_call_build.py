"""Actual fixed-image packer and source-contract rejection controls."""
from pathlib import Path
import argparse,ctypes,gzip,hashlib,json,shutil,struct,sys

def sha(raw):return hashlib.sha256(raw).hexdigest()
def dump(path,value):path.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
def pin(path):return {'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--source',type=Path,required=True)
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();root=args.source.resolve();out=args.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(root/'scripts'))
    from hia_native_loader import NativeModule
    import hia_native_batch_call_build as builder
    manifest=args.manifest.resolve();meta=json.loads(manifest.read_bytes())
    frame=(manifest.parent/'packer.input.bin').read_bytes()
    expected=(manifest.parent/'packer.output.bin').read_bytes()
    packer=manifest.parent/meta['packer_manifest']
    assert sha(packer.read_bytes())==meta['packer_manifest_sha256']
    assert sha(expected)==meta['elf_sha256']
    identity={'source':str(root),'manifest':str(manifest),'manifest_pin':pin(manifest),
              'test_source':str(Path(__file__).resolve()),'test_pin':pin(Path(__file__)),
              'builder_pin':pin(root/'scripts/hia_native_batch_call_build.py'),
              'loader_pin':pin(root/'scripts/hia_native_loader.py'),
              'packer_manifest_pin':pin(packer),'composition_pin':pin(root/builder.PACKER_PROOF)}
    dump(out/'IDENTITY.json',identity)
    rows=[];failures=[];offset=0
    stream=gzip.GzipFile(filename=str(out/'complete.bin.gz'),mode='wb',compresslevel=1,mtime=0)
    index=(out/'index.jsonl').open('wb')
    def patch(data,at,value):
        result=bytearray(data);struct.pack_into('<Q',result,at,value);return bytes(result)
    with NativeModule(packer,manifest_sha256=sha(packer.read_bytes())) as module:
        def call(label,data,capacity,work,code):
            nonlocal offset
            before_o=b'\xa5'*capacity;before_w=b'\x6d'*work
            with module.session(workspace_capacity=work,output_capacity=capacity) as session:
                ctypes.memset(session._workspace,0x6d,work)
                ctypes.memset(session._output,0xa5,capacity)
                actual,after_o,after_w=session.invoke_raw(data)
            header=struct.pack('<8Q',len(rows),actual,len(data),capacity,work,0,0,0)
            digest=hashlib.sha256();size=0
            for raw in (header,data,before_o,before_w,after_o,after_w):
                stream.write(raw);digest.update(raw);size+=len(raw)
            row={'label':label,'offset':offset,'bytes':size,'sha256':digest.hexdigest(),
                 'return_code':actual,'expected_return':code}
            offset+=size;rows.append(row)
            index.write(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n')
            if actual!=code:failures.append({'label':label,'reason':'return code'})
            if code==len(expected):
                if after_o!=expected+b'\xa5'*(capacity-len(expected)):
                    failures.append({'label':label,'reason':'full ELF or output tail'})
                if after_w!=bytes(160)+b'\x6d'*(work-160):
                    failures.append({'label':label,'reason':'successful private scratch/tail'})
            elif after_o!=before_o:
                failures.append({'label':label,'reason':'refused packing changed output'})
        invalid=0xffffffff;capacity=0xfffffffe;n=len(expected)
        call('exact',frame,n,160,n)
        call('spare-borrow-tails',frame,n+31,191,n)
        call('short-header',frame[:191],n,160,invalid)
        call('wrong-magic',b'BADFRAME'+frame[8:],n,160,invalid)
        for label,at,value in [('prefix-extent',8,meta['prefix_bytes']+1),('image-count',16,19),
                               ('table',24,meta['table_offset']+8),('zero-image',32,0),
                               ('oversized-image',32,(1<<64)-1)]:
            call(label,patch(frame,at,value),n,160,invalid)
        changed=bytearray(frame);changed[192+100]^=1
        call('changed-prefix',bytes(changed),n,160,invalid)
        call('trailing-frame-byte',frame+b'\0',n,160,invalid)
        call('short-output',frame,n-1,160,capacity)
        call('zero-output',frame,0,160,capacity)
        call('short-workspace',frame,n,159,capacity)
    stream.close();index.close()
    prefix=(manifest.parent/'prefix.bin').read_bytes()
    baseline=out/'contracts'/'baseline';baseline.mkdir(parents=True)
    proof=json.loads((root/builder.PACKER_PROOF).read_bytes())
    files=[*builder.SOURCES,builder.PACKER_PROOF,'native/batch_call_packer.hepta',
           *[item['source'] for item in proof['imports']]]
    for name in files:
        target=baseline/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(root/name,target)
    original={name:pin(baseline/name) for name in files}
    assert builder.validate_packer(baseline,prefix,meta['table_offset'])==proof['boundary']
    contracts=[]
    def changed_contract(label,change):
        private=out/'contracts'/label;shutil.copytree(baseline,private);change(private)
        rejected=False;error=None
        try:builder.validate_packer(private,prefix,meta['table_offset'])
        except (ValueError,KeyError,TypeError) as exc:rejected=True;error=str(exc)
        contracts.append({'label':label,'rejected':rejected,'error':error,
                          'source_pins':{name:pin(private/name) for name in files}})
        if not rejected:failures.append({'label':label,'reason':'changed contract accepted'})
    def append_file(name):
        def mutate(private):
            path=private/name;path.write_bytes(path.read_bytes()+b'\n')
        return mutate
    def patch_proof(key,value):
        def mutate(private):
            path=private/builder.PACKER_PROOF;value0=json.loads(path.read_bytes())
            value0['boundary'][key]=value;dump(path,value0)
        return mutate
    changed_contract('assembly-source',append_file(builder.SOURCES[0]))
    changed_contract('packer-source',append_file('native/batch_call_packer.hepta'))
    changed_contract('imported-source',append_file(proof['imports'][0]['source']))
    changed_contract('prefix-pin',patch_proof('prefix_sha256','0'*64))
    changed_contract('table-offset',patch_proof('table_offset',meta['table_offset']+8))
    changed_contract('slot-routing',patch_proof('slots',list(reversed(builder.SLOTS))))
    assert original=={name:pin(baseline/name) for name in files}
    dump(out/'contracts.json',{'controls':contracts,'baseline_pins':original})
    assert identity['builder_pin']==pin(root/'scripts/hia_native_batch_call_build.py')
    assert identity['composition_pin']==pin(root/builder.PACKER_PROOF)
    result={'status':'FAIL' if failures else 'PASS','test_groups':2,'native_packer_calls':len(rows),
            'source_contract_refusals':len(contracts),'complete_uncompressed_bytes':offset,
            'failures':failures,'original_rust_executions':0,'batch_semantic_cases_added':0}
    dump(out/'RESULT.json',result);print(json.dumps(result),flush=True)
    return bool(failures)

if __name__=='__main__':raise SystemExit(main())
