"""Six fixed HIA images, actual syscalls and original Regex result corpus."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import hashlib,json,os,struct,subprocess,time,unittest
ROOT=Path(__file__).resolve().parents[2]
ART=artifact('pipeline')
sha=lambda b:hashlib.sha256(b).hexdigest()
RESULTS={'elf_requests':0,'processes':0,'original_comparisons':0}

def wire(pattern,hay=b'',op=2):
    if isinstance(pattern,str):pattern=pattern.encode()
    if isinstance(hay,str):hay=hay.encode()
    return b'HRGEX001'+struct.pack('<QQQ',op,len(pattern),len(hay))+pattern+hay

def run(requests,timeout=120):
    p=executable_manifest('regex');m=json.loads(p.read_bytes());exe=p.parent/m['executable'];assert sha(exe.read_bytes())==m['executable_sha256']
    raw=b''.join(struct.pack('<Q',len(x))+x for x in requests)
    result=subprocess.run([str(exe)],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=ROOT,timeout=timeout)
    RESULTS['processes']+=1;RESULTS['elf_requests']+=len(requests)
    assert result.returncode==0 and result.stderr==b'',(result.returncode,result.stderr)
    parsed=[];at=0
    while at<len(result.stdout):
        code,size=struct.unpack_from('<QQ',result.stdout,at);at+=16
        assert size<=len(result.stdout)-at;body=result.stdout[at:at+size];at+=size;parsed.append((code,body))
    assert len(parsed)==len(requests)
    return parsed,raw,result.stdout

def result(status,captures=0,matched=0):return 0,b'HRGREX01'+struct.pack('<QQQ',status,captures,matched)

class RegexElfTests(unittest.TestCase):
    def test_complete_original_wrapped_domain(self):
        corpus=data('match');meta=json.loads((corpus/'native-corpus.json').read_bytes());proof=json.loads((data('proof/match.json')).read_bytes())
        self.assertEqual(proof['status'],'PASS');self.assertEqual(proof['native_output_sha256'],meta['native_output_sha256'])
        requests=(corpus/'requests.hex').read_bytes();output=(corpus/'native-output.txt').read_bytes();self.assertEqual(sha(requests),meta['requests_sha256']);self.assertEqual(sha(output),meta['native_output_sha256'])
        frames=[];wanted=[]
        for req,answer in zip(requests.splitlines(),output.splitlines()):
            raw=bytes.fromhex(req.decode());op,n,h=struct.unpack_from('<QQQ',raw,8)
            if op!=1:continue
            frames.append(wire(raw[32:32+n],raw[32+n:]));code,payload=answer.split(b':');payload=bytes.fromhex(payload.decode());status=int(code,16)
            if status==0:wanted.append(result(0,*struct.unpack('<QQ',payload)))
            else:wanted.append(result(status))
        actual,stdin,stdout=run(frames);self.assertEqual(actual,wanted)
        RESULTS['original_comparisons']+=len(actual)
        for name,stream in [('elf.stdin',stdin),('elf.stdout',stdout)]:
            (ART/name).write_bytes(stream);RESULTS[name]={'bytes':len(stream),'sha256':sha(stream)}

    def test_cache_and_error_recovery(self):
        frames=[wire('a','a'),wire('a','b'),wire('a','',1),wire('b','b'),wire('a','a'),wire('[',''),wire('a','a'),wire('abc','abc'),wire('abd','abc'),wire('abc','abc')]
        wanted=[result(0,1,1),result(0,1,0),result(0,1,0),result(0,1,1),result(0,1,1),result(1),result(0,1,1),result(0,1,1),result(0,1,0),result(0,1,1)]
        self.assertEqual(run(frames)[0],wanted)

    def test_framing_atomic_refusals(self):
        good=wire('a','a');bad=[b'',good[:31],b'NOFORMAT'+good[8:],good[:-1],good+b'x',wire(b'\xff','a'),wire('a',b'\xff'),wire('a','x',1)]
        for at,value in [(8,0),(8,3),(16,67108865),(24,67108865),(16,(1<<64)-1),(24,(1<<64)-1)]:
            b=bytearray(good);struct.pack_into('<Q',b,at,value);bad.append(bytes(b))
        frames=[good]
        for b in bad:frames.extend([b,good])
        actual,_,_=run(frames);self.assertEqual(actual[0],result(0,1,1))
        for i in range(len(bad)):
            self.assertEqual(actual[1+i*2],(0xffffffff,b''));self.assertEqual(actual[2+i*2],result(0,1,1))
        RESULTS['abi_refusals']=len(bad)

    def test_exact_nfa_limit_and_recovery(self):
        frames=[wire('a{327674}','',1),wire('a{327675}','',1),wire('a','a'),wire(r'\w{500}','',1),wire('a','a')]
        wanted=[result(0,1,0),result(2),result(0,1,1),result(2),result(0,1,1)]
        self.assertEqual(run(frames)[0],wanted)
        RESULTS['observed_original_budget_boundaries']=3

if __name__=='__main__':
    ART.mkdir(exist_ok=False);start=time.monotonic();suite=unittest.defaultTestLoader.loadTestsFromTestCase(RegexElfTests);r=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'hepta.runtime.regex-actual-elf-controls.v1','status':'PASS'if r.wasSuccessful()else'FAIL','tests_run':r.testsRun,'elapsed':time.monotonic()-start,**RESULTS,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes())for p in [Path(__file__),ROOT/'scripts/regex_pipeline_adapter.S',ROOT/'scripts/build_regex_probe.py',ROOT/'native/regex_pipeline_packer.hepta',ROOT/'native/regex_controller.hepta',ROOT/'native/regex_syntax.hepta',ROOT/'native/regex_hir.hepta',ROOT/'native/regex_nfa.hepta',ROOT/'native/regex_match.hepta',ROOT/'native/regex_unicode_data.hepta']},'composition_manifest_sha256':sha((executable_manifest('regex')).read_bytes()),'configuration_owner_wired':False,'unconstrained_regex_resources_closed':False}
    (ART/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if r.wasSuccessful()else 1)
