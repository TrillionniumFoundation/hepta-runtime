"""Original builder budget comes from real native states and edges, not estimates."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import argparse,hashlib,json,random,struct,time
from regex_parser_fixture import ROOT,ParserFixture,request
from regex_hir_fixture import HirFixture
from regex_nfa_fixture import NfaFixture
sha=lambda b:hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True,type=Path);p.add_argument('--manifest',type=Path);p.add_argument('--shards',type=int,default=1);p.add_argument('--shard',type=int,default=0);a=p.parse_args()
    assert 1<=a.shards<=16 and 0<=a.shard<a.shards
    a.output.mkdir(parents=True,exist_ok=False)
    old=data('hir');oldcasesraw=(old/'cases.json').read_bytes()
    assert sha(oldcasesraw)=='ba88c41ec4b2bbc60b58c1194af4574f60affe601fb0db5297a03b1fc7619d16'
    oldcases=json.loads(oldcasesraw)
    rng=random.Random(0x4e4641);indices=sorted(set(range(0,min(len(oldcases),500)))|set(rng.sample(range(len(oldcases)),1200)))
    cases=[oldcases[i]for i in indices];hirs=[None]*len(indices);positions={index:at for at,index in enumerate(indices)}
    digest=hashlib.sha256();rows=0
    with (old/'native-output.txt').open('rb')as source:
        for index,line in enumerate(source):
            digest.update(line);rows+=1
            if index in positions and line.startswith(b'00000000:'):
                hirs[positions[index]]=bytes.fromhex(line.rstrip(b'\n').split(b':')[1].decode())
    assert rows==len(oldcases) and digest.hexdigest()=='b5b1b239e3bb762e734996440f18498238d14b57dbe57c9fd710dc12b37b22f2'
    del oldcasesraw,oldcases,positions
    patterns=['','a','ab','abc|abcd|ab','foo|foobar|fo','zapper|z|zap','abc|abcdef|ab|abcyz',r'\w',r'\W',r'\d',r'\s',r'\p{Any}',r'\p{Greek}',r'(?i:α|β)',r'(?-u:[a-z])','a*','a+','a?','(?:a?)*','(?:a*)*','(?:a?){0,2}','a{0,2}','a{2,4}','a{3,}','(?:ab|[cd]){3,7}',r'(?m:^a$)',r'(?mR:^a$)',r'\b{start}\w+\b{end-half}',r'[\u{D7FF}-\u{E001}]',')|foo(?:',')|(?:']
    for n in [327672,327673,327674,327675,327676]:patterns+=['a{'+str(n)+'}']
    for n in [1,2,3,10,90,200,201,202,500]:patterns += [r'\w{'+str(n)+'}',r'[ab]{'+str(n)+'}']
    for pattern in patterns:
        for wrapped in [False,True]:cases.append({'pattern':pattern,'wrapped':wrapped});hirs.append(None)
    started=time.monotonic();requests=[];outputs=[];successes=syntax=too_big=boundary=0;details=[];case_indices=[]
    with ParserFixture()as parser,HirFixture()as hir,NfaFixture(manifest=a.manifest,output_capacity=64,workspace_capacity=128<<20)as nfa:
        for i,(case,tree)in enumerate(zip(cases,hirs)):
            if i%a.shards!=a.shard:continue
            if tree is None:
                code,raw=parser.invoke(request(case['pattern'],case['wrapped']))
                if code==0:code,tree=hir.invoke(raw)
                if code!=0:assert code==0xfffffffd;tree=None
            raw=case['pattern'].encode()
            for reverse in [False,True]:
                case_indices.append(i*2+int(reverse))
                op=9+int(reverse)+2*int(case['wrapped']);requests.append((b'HREGX001'+struct.pack('<QQQ',op,len(raw),0)+raw).hex().encode()+b'\n')
                if tree is None:code=1;result=b'';syntax+=1
                else:
                    code,result=nfa.invoke(tree,reverse)
                    if code==0:
                        cost=struct.unpack_from('<Q',result,24)[0];details.append({'case':len(outputs),'cost':cost,'states':struct.unpack_from('<Q',result,8)[0],'heap':struct.unpack_from('<Q',result,16)[0]});result=struct.pack('<Q',cost);successes+=1
                        if i<50 or i>=len(cases)-2*len(patterns):
                            self_code,self_out=nfa.invoke(tree,reverse,limit=cost);assert self_code==0 and self_out[24:32]==result
                            self_code,self_out=nfa.invoke(tree,reverse,limit=cost-1);assert (self_code,self_out)==(0xfffffffd,b'');boundary+=2
                    elif code==0xfffffffd:code=2;result=struct.pack('<Q',10485760);too_big+=1
                    else:raise AssertionError((i,case,reverse,hex(code)))
                outputs.append(f'{code:08x}:'.encode()+result.hex().encode()+b'\n')
        calls=nfa.calls;parser_calls=parser.calls;hir_calls=hir.calls
    requests=b''.join(requests);outputs=b''.join(outputs)
    reference_requests=data('nfa/requests.hex').read_bytes().splitlines(keepends=True);reference_outputs=data('nfa/native-output.txt').read_bytes().splitlines(keepends=True)
    assert len(reference_requests)==len(reference_outputs)==3584
    assert requests==b''.join(reference_requests[index]for index in case_indices)
    assert outputs==b''.join(reference_outputs[index]for index in case_indices)
    (a.output/'requests.hex').write_bytes(requests);(a.output/'native-output.txt').write_bytes(outputs);(a.output/'details.json').write_text(json.dumps(details,indent=2)+'\n')
    index_bytes=(json.dumps(case_indices,separators=(',',':'))+'\n').encode();(a.output/'case-indices.json').write_bytes(index_bytes)
    report={'schema':'hepta.runtime.regex-nfa-native-corpus.v1','status':'PASS','cases':len(outputs.splitlines()),'shard':a.shard,'shards':a.shards,'complete_domain_cases':len(cases)*2,'case_indices_sha256':sha(index_bytes),'successes':successes,'syntax_errors':syntax,'size_errors':too_big,'boundary_native_calls':boundary,'native_calls':calls,'parser_calls':parser_calls,'hir_calls':hir_calls,'elapsed':time.monotonic()-started,'requests_sha256':sha(requests),'requests_bytes':len(requests),'native_output_sha256':sha(outputs),'native_output_bytes':len(outputs),'source_sha256':{name:sha((ROOT/name).read_bytes())for name in ['native/regex_nfa.hepta','native/regex_hir.hepta','native/regex_syntax.hepta','native/regex_unicode_data.hepta','tests/hia_native/regex_nfa_cases.py','tests/hia_native/regex_nfa_fixture.py']}}
    (a.output/'native-corpus.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
