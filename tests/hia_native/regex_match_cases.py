"""Every result uses native syntax, HIR, forward/reverse NFA and matching."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import argparse,hashlib,itertools,json,random,struct,time
from regex_parser_fixture import ROOT,ParserFixture,request
from regex_hir_fixture import HirFixture
from regex_nfa_fixture import NfaFixture
from regex_match_fixture import MatchFixture
sha=lambda b:hashlib.sha256(b).hexdigest()

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',default=artifact('match-corpus'),type=Path);a=p.parse_args();a.output.mkdir(exist_ok=False,parents=True)
    patterns=['','a','b','abc','ab|abc','foo|foobar|fo','zapper|z|zap','a|b|abc','a*','a+','a?','a{0,2}','a{2,4}','a{2,}','(?:a?)*','(?:a*)*','(a){0}(b)','(?<n>a)(b)','^a$','(?m:^a$)','(?mR:^a$)','(?s:.)','(?-u:.)',r'\p{Any}',r'\w',r'\W',r'\d+',r'\s*',r'(?i:αβ|ſK)',r'[a-z&&[^aeiou]]+',r'[\p{Greek}~~[α-ω]]+',r'(?i:[kſ--[s]])',r'[\u{D7FF}-\u{E001}]',r'\x00+',')|foo(?:',')|(?:','[','a{3,2}','(?u-u:a)',r'\p{NotAProperty}']
    looks=[r'\A',r'\z','^','$',r'\b',r'\B',r'\b{start}',r'\b{end}',r'\b{start-half}',r'\b{end-half}']
    for look in looks:
        for flags in ['', '(?-u)', '(?m)', '(?mR)']:
            for body in [look,look+'.*','.*'+look,look+r'\w'+look]:patterns.append(flags+body)
    rng=random.Random(0x4d41544348);atoms=['a','b','α','é',r'\w',r'\d',r'\s','[ab]','[^ab]','.',r'\p{Greek}',r'[a&&b]']
    for _ in range(240):
        left,right=rng.choice(atoms),rng.choice(atoms);op=rng.randrange(5)
        if op==0:pattern=left+right
        elif op==1:pattern='(?:'+left+'|'+right+')'+rng.choice(['*','+','?','{0,3}','{2,4}'])
        elif op==2:pattern='(?i:'+left+right+')'
        elif op==3:pattern='('+left+')?('+right+')*'
        else:pattern='(?:'+left+'{0,2}){1,3}'+right
        patterns.append(pattern)
    patterns=list(dict.fromkeys(patterns))
    hays=['','a','b','abc','aaa','aab','ba','bb','aba','foo','foobar','fo','zapper','z','zap',' αβ ','αβ','é','e\u0301','\u200c','_','2','😊','\0','\r','\n','a\r\n','a\r','\na\n','\r\na\r\n','ſK','Ks']
    hays += [''.join(p)for n in range(2,5)for p in itertools.product('ab',repeat=n)]
    alphabet=['a','b','α','é','\u0301','_','2','😊','\u200c','\r','\n','\0']
    hays += [''.join(rng.choice(alphabet)for _ in range(rng.randrange(1,10)))for _ in range(28)]
    hays=list(dict.fromkeys(hays));requests=[];outputs=[];syntax=big=success=positive=0;started=time.monotonic()
    with ParserFixture()as parser,HirFixture()as hir,NfaFixture(output_capacity=64<<20,workspace_capacity=128<<20)as nfa,MatchFixture()as match:
        for pattern in patterns:
            for wrapped in [False,True]:
                code,tree=parser.invoke(request(pattern,wrapped));graph=None;caps=0
                if code==0:
                    code,tree=hir.invoke(tree)
                    if code==0:
                        caps=struct.unpack_from('<Q',tree,16)[0]+1
                        code,graph=nfa.invoke(tree,graph=True)
                        if code==0:code,_=nfa.invoke(tree,reverse=True)
                        if code==0:status=0
                        else:assert code==0xfffffffd;status=2
                    else:assert code==0xfffffffd;status=1
                else:assert code==0xfffffffd;status=1
                for hay in hays:
                    raw=pattern.encode();text=hay.encode();requests.append((b'HREGX001'+struct.pack('<QQQ',1 if wrapped else 2,len(raw),len(text))+raw+text).hex().encode()+b'\n')
                    if status==0:
                        c,result=match.match(graph,text);assert c==0,(pattern,wrapped,hay,hex(c));matched=int.from_bytes(result,'little');assert matched in [0,1]
                        result=struct.pack('<QQ',caps,matched);success+=1;positive+=matched
                    elif status==1:result=b'';syntax+=1
                    else:result=struct.pack('<Q',10485760);big+=1
                    outputs.append(f'{status:08x}:'.encode()+result.hex().encode()+b'\n')
        calls={'parser_calls':parser.calls,'hir_calls':hir.calls,'nfa_calls':nfa.calls,'match_calls':match.calls,'data_calls':parser.children+hir.children+match.children}
    case_count=len(outputs);requests=b''.join(requests);outputs=b''.join(outputs)
    assert requests==data('match/requests.hex').read_bytes()
    assert outputs==data('match/native-output.txt').read_bytes()
    (a.output/'requests.hex').write_bytes(requests);(a.output/'native-output.txt').write_bytes(outputs)
    report={'schema':'hepta.runtime.regex-match-native-corpus.v1','status':'PASS','cases':case_count,'patterns':len(patterns),'haystacks':len(hays),'successes':success,'positive':positive,'syntax_errors':syntax,'size_errors':big,**calls,'elapsed':time.monotonic()-started,'requests_sha256':sha(requests),'requests_bytes':len(requests),'native_output_sha256':sha(outputs),'native_output_bytes':len(outputs),'source_sha256':{name:sha((ROOT/name).read_bytes())for name in ['native/regex_match.hepta','native/regex_nfa.hepta','native/regex_hir.hepta','native/regex_syntax.hepta','native/regex_unicode_data.hepta','tests/hia_native/regex_match_cases.py','tests/hia_native/regex_nfa_fixture.py','tests/hia_native/regex_match_fixture.py']}}
    (a.output/'native-corpus.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True))

if __name__=='__main__':main()
