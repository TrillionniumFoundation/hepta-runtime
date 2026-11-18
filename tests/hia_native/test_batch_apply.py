"""Native conflict/duplicate/application owner with complete original replay streams."""
from __future__ import annotations
import argparse,collections,ctypes,gzip,hashlib,itertools,json,os,random,struct,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(Path(__file__).parent))
import batch_apply_reference as model
from batch_apply_harness import NativeApply,INVALID,CAPACITY,CHILD,sha,META
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_batch_apply_build import inspect_bundle
from hia_native_batch_apply_qualification import source_contract,execution_source_pins

def cases():
    yield 'empty_trailing_line',b'a',[(1,1,0,b'\r')],0
    yield 'literal_cr_normalization',b'\r',[(1,1,0,b'X')],2
    raw=b'one\ntwo\r\nthree\nlast'
    operations=[(1,anchor,0,b'new') for anchor in range(5)]
    operations += [(2,start,end,b'changed') for start in range(1,5) for end in range(start,5)]
    for index,pair in enumerate(itertools.product(operations,repeat=2)):
        yield 'ordered_conflict_pairs',raw,list(pair),index%3
    for rows in [operations,operations[::-1],[operations[6],operations[0],operations[7]],[(1,0,0,b''),(1,0,0,b'x')]]:
        yield 'first_conflict_priority',raw,rows,0
    texts=[b''.join(values) for count in range(4) for values in itertools.product([b'a',b'\r',b'\n'],repeat=count)]
    texts += [b'a\r\r\nb\r\n',b'a\r\nb\nc',b'\r\r', 'é😀\r\n漢\nlast'.encode()]
    contents=[b'',b'x',b'x\n',b'\r',b'\n',b'x\r\r\ny\r','é😀\n'.encode()]
    for ti,raw in enumerate(texts):
        count=len(model.Editable(raw).lines)
        for pos in range(count+1):
            for ci,content in enumerate(contents):
                yield 'line_endings_insert',raw,[(1,pos,0,content)],(ti+ci+pos)%3
        for start in range(1,count+1):
            for end in range(start,count+1):
                for ci,content in enumerate(contents):
                    yield 'line_endings_replace',raw,[(2,start,end,content)],(ti+ci+start+end)%3
    values=['',' ', '\t','\u3000','}',']',')','};','];;,,',');;,','} ;','});','}),','x','é','😀','x\0y','x\x01y','"\\','\x7f','\u0301','A\u0301','\u200d','\u2028','\u2060','\ufffe','\U0010ffff']
    values += [chr(v)+'};,;'+chr(v) for v in map(ord,model.WHITESPACE) if v not in (10,13)]
    # Every printability interval boundary is represented in actual duplicate text.
    samples=[chr(cp) for start,end,flag in model.RANGES for cp in (start,end) if flag!=16 and cp not in (10,13)]
    values += [''.join(samples[i:i+97]) for i in range(0,len(samples),97)]
    for index,value in enumerate(values):
        data=value.encode()
        raw=data+b'\nCENTER\n'+data+b'\n'
        for ops in [[(2,2,2,data)],[(2,2,2,b'NEW\n'+data)],[(1,0,0,data)],[(1,0,0,data+b'\nCENTER\nTAIL')],[(1,2,0,data)]]:
            yield 'duplicate_and_noise_domains',raw,ops,index%3
    for raw in [b'a\nb\nc\nd\ne\nf\n',b'a\r\nb\r\nc\r\nd\r\ne\r\nf']:
        entries=[(2,2,3,b'X\nY\nZ'),(2,5,5,b''),(1,3,0,b'I'),(1,0,0,b'HEAD'),(1,6,0,b'TAIL\n')]
        for rows in itertools.permutations(entries):yield 'reverse_apply_and_delta_anchors',raw,list(rows),2
    for index,(raw,ops) in enumerate(model.generated(12000)):
        yield 'ordered_random',raw,ops,index%3
    raw=b''.join(f'original-{n}\r\n'.encode() for n in range(50))
    for mode in range(3):
        yield 'all_fifty_replacements',raw,[(2,n+1,n+1,f'changed-{n}'.encode()) for n in range(50)],mode
        yield 'all_fifty_insertions',raw,[(1,n,0,f'new-{n}\r\n'.encode()) for n in range(50)],mode

def invalid_frames():
    wire=model.packet(b'a\nb',[(2,1,1,b'x')])
    for n in range(112):yield wire[:n]
    yield b'BADACT01'+wire[8:]
    for offset,value in [(8,3),(16,1<<63),(24,0),(32,1),(40,1),(48,1),(56,1),(64+3,0),(64+3+8,1),(64+3+16,0),(64+3+16,51),(64+3+24,0),(64+3+32,1),(64+3+40,1),(64+3+48,1),(64+3+56,3),(64+3+64,1),(64+3+72,0),(64+3+80,3),(64+3+88,1<<63)]:
        value_wire=bytearray(wire);struct.pack_into('<Q',value_wire,offset,value);yield bytes(value_wire)
    yield wire+b'\0';yield wire[:-1]
    yield model.packet(b'\xff',[(1,0,0,b'a')])
    yield model.packet(b'a',[(1,0,0,b'\xff')])
    yield model.packet(b'a',[(1,2,0,b'x')])
    yield model.packet(b'a\nb',[(2,2,1,b'x')])
    yield model.packet(b'a',[(2,0,1,b'x')])

def large_cases():
    limit=5<<20
    raw=b'\n'*limit
    ops=[(2,1,1,b'x')]
    body=b'x'+raw
    response=struct.pack('<8s9Q',b'HBAPLR01',0,1,1,1,limit,len(body),len(body),len(body),0)+body
    yield 'full_file_dense_empty_lines',model.packet(raw,ops),response
    raw=b'A'*(limit-4)+'😀'.encode()
    ops=[(2,1,1,'é'.encode())]
    body='é'.encode()
    response=struct.pack('<8s9Q',b'HBAPLR01',0,1,1,0,1,len(body),len(body),2*len(body),0)+body+body
    yield 'full_file_single_unicode_line',model.packet(raw,ops,2),response
    text=b'\x01'*(limit-2);raw=text+b'\nX';ops=[(2,2,2,text)]
    error=('Duplicate line detected in operation 0: content\'s first line repeats 1:'+model.line_hash(text)+' ("'+'\\u{1}'*len(text)+'"), the line just before the range "2:'+model.line_hash(b'X')+'"-"2:'+model.line_hash(b'X')+'". Give only the replacement lines, not surrounding context; use str_replace if the repeat is intended.').encode()
    response=struct.pack('<8s9Q',b'HBAPLR01',1,0,1,0,2,len(raw),len(raw),0,len(error))+error
    yield 'full_file_escaped_duplicate_diagnostic',model.packet(raw,ops),response
    raw=(b'a'*((limit-100)//50)+b'\r\n')*50
    raw+=b'b'*(limit-len(raw))
    ops=[(1,n,0,bytes([65+n%26])*(limit-1)+b'\n') for n in range(50)]
    # One line per content keeps original resource use finite while combining
    # the complete 50-operation and 5 MiB file/content byte boundaries.
    # This fixed fixture has fifty CRLF lines and one unterminated tail. Each
    # distinct insertion precedes its corresponding original line. Build that
    # closed-form expectation without Python walking all 250 MiB one byte at a
    # time; the actual original Rust owner independently replays every byte.
    line=b'a'*((limit-100)//50)
    body=b''.join(content[:-1]+b'\r\n'+line+b'\r\n' for _,_,_,content in ops)+raw[-30:]
    response=struct.pack('<8s9Q',b'HBAPLR01',0,50,2,0,101,len(body)-100,len(body),len(body),0)+body
    wire=model.packet(raw,ops)
    del body,ops,raw
    yield 'full_fifty_five_mib_contents',wire,response

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle',type=Path,default=os.environ.get('HIA_APPLY_BUNDLE'))
    parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_APPLY_MANIFEST'))
    parser.add_argument('--editable',type=Path,default=os.environ.get('HIA_APPLY_EDITABLE_MANIFEST'))
    parser.add_argument('--editable-source',type=Path,default=os.environ.get('HIA_APPLY_EDITABLE_SOURCE'))
    parser.add_argument('--corpus',type=Path,default=os.environ.get('HIA_APPLY_CORPUS_DIR'))
    parser.add_argument('--development-small',action='store_true')
    parser.add_argument('--result',type=Path)
    args=parser.parse_args();bundle=None
    closure=source_contract(reference=model.RUNTIME)
    pins=execution_source_pins(reference=model.RUNTIME)
    if args.bundle:
        bundle=inspect_bundle(args.bundle,source_root=ROOT,reference_root=model.RUNTIME)
        args.manifest=bundle['manifests'][4];args.editable=bundle['manifests'][5]
        args.editable_source=ROOT/'native/editable_content.hepta'
    assert args.manifest and args.editable
    n=NativeApply(args.manifest,args.editable,editable_source=args.editable_source);counts=collections.Counter();start=time.monotonic();rows=[];controls=[]
    req=out=None
    if args.corpus:
        args.corpus.mkdir(exist_ok=False);req=gzip.open(args.corpus/'requests.bin.gz','wb');out=gzip.open(args.corpus/'native-output.bin.gz','wb');req.write(b'HBAREQ01');out.write(b'HBARES01')
    request_digest=hashlib.sha256(b'HBAREQ01');output_digest=hashlib.sha256(b'HBARES01');request_bytes=output_bytes=8
    def actual(domain,wire,expected):
        nonlocal request_bytes,output_bytes
        class Sink:
            def __init__(self):self.position=-1
            def write(self,value):
                if self.position==-1:
                    assert value==struct.pack('<Q',len(expected));self.position=0
                else:
                    assert value==memoryview(expected)[self.position:self.position+len(value)],(domain,self.position)
                    self.position+=len(value)
                output_digest.update(value)
                if out:out.write(value)
        sink=Sink()
        result=n.invoke(wire,len(expected),sink=sink);assert result['code']==len(expected) and sink.position==len(expected),(domain,wire[:256].hex(),result,expected[:256])
        counts[domain]+=1
        request_prefix=struct.pack('<Q',len(wire));request_digest.update(request_prefix);request_digest.update(wire);request_bytes+=8+len(wire);output_bytes+=8+len(expected)
        if req:req.write(request_prefix);req.write(wire)
        rows.append({'ordinal':len(rows),'domain':domain,'input_bytes':len(wire),'input_sha256':sha(wire),'output_bytes':len(expected),'output_sha256':result['output_sha256'],'controller_calls':1+len(result['trace']),'editable_calls':len(result['trace']),'trace':result['trace'],'workspace_capacity':result['workspace_capacity'],'leaf_workspace_capacity':result['leaf_workspace_capacity'],'cleared_prefix_bytes':result['cleared_prefix_bytes'],'input_unchanged':result['input_unchanged'],'guards_unchanged':result['guards_unchanged'],'output_tail_unchanged':result['output_tail_unchanged']})
    def control(domain,wire,result):
        row={key:value for key,value in result.items() if key not in ('output','prefix')}
        row.update({'ordinal':len(controls),'domain':domain,'input_hex':wire.hex(),'output_hex':result['output'].hex(),
            'input_sha256':sha(wire),'controller_calls':1+len(result['trace']),'editable_calls':len(result['trace'])})
        controls.append(row)
    try:
        for domain,raw,ops,mode in cases():actual(domain,model.packet(raw,ops,mode),model.response(raw,ops,mode))
        if not args.development_small:
            for domain,wire,expected in large_cases():
                boundary_start=time.monotonic()
                print(json.dumps({'phase':'large_case_started','domain':domain,'input_bytes':len(wire),'output_bytes':len(expected)}),file=sys.stderr,flush=True)
                actual(domain,wire,expected)
                print(json.dumps({'phase':'large_case_passed','domain':domain,'elapsed_seconds':time.monotonic()-boundary_start}),file=sys.stderr,flush=True)
        for wire in invalid_frames():
            result=n.invoke(wire,1024);assert result['code']==INVALID,(wire[:256].hex(),result);counts['invalid_frames']+=1;control('invalid_frames',wire,result)
        wire=model.packet(b'a\nb',[(1,1,0,b'new')],2);expected=model.response(b'a\nb',[(1,1,0,b'new')],2)
        for cap,workspace,leaf in [(0,None,None),(79,None,None),(len(expected)-1,None,None),(len(expected),META+255,None),(len(expected),META+256,None),(len(expected),None,259)]:
            result=n.invoke(wire,cap,workspace=workspace,leaf_workspace=leaf);assert result['code']==CAPACITY,(cap,workspace,leaf,result);counts['capacity_refusals']+=1;control('capacity_refusals',wire,result)
    finally:
        if req:req.close();out.close()
        n.close()
    result={'schema':'hepta.runtime.batch-apply-native.v1','status':'PASS','development_small':args.development_small,'elapsed_seconds':time.monotonic()-start,'groups':dict(counts),'counts':n.counts,'original_replay_cases':len(rows),'loaded_artifacts':n.loaded,'source_sha256':sha((ROOT/'native/batch_apply.hepta').read_bytes()),'requests_sha256':request_digest.hexdigest(),'requests_bytes':request_bytes,'native_output_sha256':output_digest.hexdigest(),'native_output_bytes':output_bytes,'rows':rows,'controls':controls}
    result['bundle_sha256']=bundle['manifest_sha256'] if bundle else None
    result['source_contract']=closure
    assert execution_source_pins(reference=model.RUNTIME)==pins
    result['execution_source_pins']=pins
    if args.corpus:
        result['corpus_files']={name:{'bytes':(args.corpus/name).stat().st_size,'sha256':sha((args.corpus/name).read_bytes())} for name in ('requests.bin.gz','native-output.bin.gz')}
        (args.corpus/'native-corpus.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    if args.result:args.result.write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('rows','controls')},sort_keys=True))

if __name__=='__main__':main()
