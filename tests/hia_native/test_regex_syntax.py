"""Actual HIA parser calls and syscall-only ELF, with independent Rust corpus."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import ctypes,hashlib,json,os,struct,subprocess,time,unittest,tempfile
from regex_parser_fixture import ROOT,ParserFixture,request
from regex_unicode_fixture import NativeRejected
sha=lambda b:hashlib.sha256(b).hexdigest()
RESULTS={'native_calls':0,'child_calls':0,'elf_requests':0,'processes':0,'receipt_refusals':0,'framing_refusals':0,'capacity_refusals':0}
ART=artifact('syntax')

def observed(f,wire):
    calls,children=f.calls,f.children
    result=f.invoke(wire)
    RESULTS['native_calls']+=f.calls-calls;RESULTS['child_calls']+=f.children-children
    return result

def invoke_elf(wire):
    path=executable_manifest('syntax');meta=json.loads(path.read_bytes());binary=path.parent/meta['executable'];assert sha(binary.read_bytes())==meta['executable_sha256']
    result=subprocess.run([str(binary)],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=ROOT,timeout=120)
    RESULTS['processes']+=1
    return result

class SyntaxNativeTests(unittest.TestCase):
    def test_actual_elf_corpus(self):
        corpus=data('syntax');meta=json.loads((corpus/'native-corpus.json').read_bytes());original=json.loads((data('proof/syntax.json')).read_bytes())
        self.assertEqual(original['status'],'PASS');self.assertEqual(original['native_output_sha256'],meta['native_output_sha256'])
        requests=(corpus/'requests.hex').read_bytes();expected=(corpus/'native-output.txt').read_bytes()
        self.assertEqual(sha(requests),meta['requests_sha256']);self.assertEqual(sha(expected),meta['native_output_sha256'])
        stream=bytearray()
        for line in requests.splitlines():
            raw=bytes.fromhex(line.decode());wrapped=int.from_bytes(raw[8:16],'little')==6
            wire=request(raw[32:],wrapped);stream.extend(struct.pack('<Q',len(wire)));stream.extend(wire)
        result=invoke_elf(stream);self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        at=0;rows=[]
        while at<len(result.stdout):
            code,n=struct.unpack_from('<QQ',result.stdout,at);at+=16
            self.assertLessEqual(n,len(result.stdout)-at)
            body=result.stdout[at:at+n];at+=n
            if code==0xfffffffd:code=1
            rows.append(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
        self.assertEqual(len(rows),meta['cases']);self.assertEqual(b''.join(rows),expected)
        RESULTS['elf_requests']+=len(rows)
        (ART/'requests.hex').write_bytes(requests)
        (ART/'native-output.txt').write_bytes(b''.join(rows))
        for name,raw in [('elf.stdin',bytes(stream)),('elf.stdout',result.stdout),('elf.stderr',result.stderr)]:
            (ART/name).write_bytes(raw);RESULTS[name]={'bytes':len(raw),'sha256':sha(raw)}

    def test_capacity_atomicity(self):
        wire=request(r'(?<group>\p{script=Greek}|[a-z&&[^q]]){2,7}',True)
        with ParserFixture()as f:
            code,expected=observed(f,wire);self.assertEqual(code,0)
        for capacity in [0,1,63,len(expected)-1,len(expected),len(expected)+1]:
            with ParserFixture(output_capacity=capacity)as f:
                address=ctypes.addressof(f.session._output);ctypes.memset(address,0x9b,capacity)
                code,raw=observed(f,wire)
                if capacity<len(expected):
                    self.assertEqual((code,raw),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(address,capacity),b'\x9b'*capacity);RESULTS['capacity_refusals']+=1
                else:self.assertEqual((code,raw),(0,expected))
        with ParserFixture(workspace_capacity=1310720+len(wire)-24+319)as f:
            self.assertEqual(observed(f,wire)[0],0xfffffffe);RESULTS['capacity_refusals']+=1

    def test_malformed_and_recovery(self):
        correct=request('a')
        wires=[b'',b'HRGAST01',correct[:23],b'NOFORMAT'+correct[8:],correct[:-1],correct+b'a',request(b'\xff'),request(b'\xc0\x80'),request(b'\xed\xa0\x80'),request(b'\xf4\x90\x80\x80')]
        for mode in [0,3,0xffffffffffffffff]:wires.append(correct[:8]+struct.pack('<Q',mode)+correct[16:])
        for n in [0,2,0xffffffffffffffff]:wires.append(correct[:16]+struct.pack('<Q',n)+correct[24:])
        with ParserFixture(output_capacity=4096)as f:
            for wire in wires:
                address=ctypes.addressof(f.session._output);ctypes.memset(address,0xa7,4096)
                self.assertEqual(observed(f,wire),(0xffffffff,b''));self.assertEqual(ctypes.string_at(address,4096),b'\xa7'*4096);RESULTS['framing_refusals']+=1
            for pattern in ['[]','[a-','(?<a>x)(?<a>y)','a{4294967296}','('*251+'a'+')'*251]:self.assertEqual(observed(f,request(pattern))[0],0xfffffffd)
            self.assertEqual(observed(f,correct)[0],0)

    def test_receipt_validation(self):
        wire=request('abc')
        for field in range(14):
            with ParserFixture(output_capacity=1024)as f:
                try:f.session.invoke(wire)
                except NativeRejected as e:self.assertEqual(e.code,0xffffffe0)
                else:self.fail('expected data continuation')
                RESULTS['native_calls']+=1
                address=ctypes.addressof(f.session._workspace);footer=f.constants['WORKSPACE_BYTES']-256
                payload=f.data.invoke(b'HRGDAT01',output_capacity=f.constants['ASSET_BYTES'],workspace_capacity=f.data_meta['workspace_bytes']);RESULTS['child_calls']+=1
                ctypes.memmove(address+8192,payload,len(payload));ctypes.memmove(address+footer+80,struct.pack('<QQQQ',len(payload),1,1,0),32)
                at=address+footer+field*8;value=struct.unpack('<Q',ctypes.string_at(at,8))[0];ctypes.memmove(at,struct.pack('<Q',value^1),8)
                out=ctypes.addressof(f.session._output);ctypes.memset(out,0x8f,1024)
                self.assertEqual(observed(f,wire),(0xffffffff,b''));self.assertEqual(ctypes.string_at(out,1024),b'\x8f'*1024);RESULTS['receipt_refusals']+=1

    def test_transport_refusals(self):
        for wire in [b'\x01',struct.pack('<Q',20)+b'x',struct.pack('<Q',67108889)]:
            result=invoke_elf(wire);self.assertEqual(result.returncode,74);self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'')
        result=invoke_elf(b'');self.assertEqual(result.returncode,0);self.assertEqual(result.stdout,b'')

    def test_full_pattern_bound(self):
        with ParserFixture(output_capacity=1024)as f:
            code,expected=observed(f,request('(?x)#a'));self.assertEqual(code,0)
        meta=json.loads((executable_manifest('syntax')).read_bytes());binary=executable('syntax')
        digest=hashlib.sha256();digest.update(b'(?x)#')
        with tempfile.TemporaryFile()as input_file:
            input_file.write(struct.pack('<Q',67108864+24)+b'HRGAST01'+struct.pack('<QQ',2,67108864)+b'(?x)#')
            remaining=67108864-5;chunk=b'a'*65536
            while remaining:
                raw=chunk[:min(remaining,len(chunk))];input_file.write(raw);digest.update(raw);remaining-=len(raw)
            input_file.seek(0)
            result=subprocess.run([str(binary)],stdin=input_file,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=ROOT,timeout=120)
        RESULTS['processes']+=1;RESULTS['elf_requests']+=1
        self.assertEqual((result.returncode,result.stderr),(0,b''));self.assertEqual(result.stdout,struct.pack('<QQ',0,len(expected))+expected)
        RESULTS['full_pattern']={'pattern_bytes':67108864,'pattern_sha256':digest.hexdigest(),'result_sha256':sha(expected),'result_hex':expected.hex(),'actual_elf':True}
        # Oversize admission precedes workspace use; this avoids allocating a
        # second 256 MiB private arena just to check the unchanged size boundary.
        with ParserFixture(output_capacity=0,workspace_capacity=0)as f:
            self.assertEqual(observed(f,request(b'a'*67108865)),(0xfffffffc,b''))

if __name__=='__main__':
    ART.mkdir(exist_ok=False);started=time.monotonic();suite=unittest.defaultTestLoader.loadTestsFromTestCase(SyntaxNativeTests);result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'hepta.runtime.regex-syntax-native-controls.v1','status':'PASS'if result.wasSuccessful()else'FAIL','tests_run':result.testsRun,'elapsed':time.monotonic()-started,**RESULTS,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes())for p in [Path(__file__),ROOT/'tests/hia_native/regex_parser_fixture.py',ROOT/'tests/hia_native/regex_unicode_fixture.py',ROOT/'native/regex_syntax.hepta',ROOT/'native/regex_unicode_data.hepta',ROOT/'scripts/regex_syntax_adapter.S',ROOT/'scripts/build_regex_probe.py']},'composition_manifest_sha256':sha((executable_manifest('syntax')).read_bytes()),'regex_compiler_closed':False}
    (ART/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if result.wasSuccessful()else 1)
