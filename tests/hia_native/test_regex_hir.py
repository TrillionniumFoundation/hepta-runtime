"""Real HIA HIR calls and static ELF; Rust projection bytes are retained."""
from pathlib import Path
import sys,shutil
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,data,artifact
import ctypes,hashlib,json,struct,subprocess,tempfile,time,unittest
from regex_hir_fixture import ROOT,HirFixture
from regex_parser_fixture import ParserFixture,request
from regex_unicode_fixture import NativeRejected
sha=lambda b:hashlib.sha256(b).hexdigest()
ART=artifact('hir')
COUNTS={'native_calls':0,'data_calls':0,'parser_calls':0,'elf_requests':0,'processes':0,'receipt_refusals':0,'framing_refusals':0,'capacity_refusals':0}

def ast(pattern,wrapped=False):
    with ParserFixture(output_capacity=8<<20,workspace_capacity=32<<20)as f:
        code,body=f.invoke(request(pattern,wrapped));COUNTS['parser_calls']+=f.calls
        assert code==0
        return body

def observed(f,wire):
    calls,children=f.calls,f.children;result=f.invoke(wire)
    COUNTS['native_calls']+=f.calls-calls;COUNTS['data_calls']+=f.children-children
    return result

def executable():
    p=executable_manifest('hir');m=json.loads(p.read_bytes());binary=p.parent/m['executable']
    assert sha(binary.read_bytes())==m['executable_sha256']
    return binary

def run_elf(wire):
    result=subprocess.run([str(executable())],input=wire,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=ROOT,timeout=120)
    COUNTS['processes']+=1;return result

class HirNativeTests(unittest.TestCase):
    def test_actual_elf_original_corpus(self):
        corpus=data('hir');meta=json.loads((corpus/'native-corpus.json').read_bytes());proof=json.loads((data('proof/hir.json')).read_bytes())
        self.assertEqual(proof['status'],'PASS');self.assertEqual(proof['native_output_sha256'],meta['native_output_sha256'])
        requests=(corpus/'requests.hex').read_bytes();expected=(corpus/'native-output.txt').read_bytes()
        self.assertEqual(sha(requests),meta['requests_sha256']);self.assertEqual(sha(expected),meta['native_output_sha256'])
        wanted=[];positions=[];complete=[];digest=hashlib.sha256();input_bytes=0
        with tempfile.TemporaryFile()as stream:
            with ParserFixture(output_capacity=8<<20,workspace_capacity=32<<20)as f:
                for line,row in zip(requests.splitlines(),expected.splitlines(keepends=True)):
                    raw=bytes.fromhex(line.decode());wrapped=int.from_bytes(raw[8:16],'little')==8
                    code,body=f.invoke(request(raw[32:],wrapped))
                    if code==0:
                        wire=struct.pack('<Q',len(body))+body;stream.write(wire);digest.update(wire);input_bytes+=len(wire);wanted.append(row);positions.append(len(complete));complete.append(None)
                    else:self.assertEqual((code,row),(0xfffffffd,b'00000001:\n'));complete.append(b'00000001:\n')
                COUNTS['parser_calls']+=f.calls
            stream.seek(0)
            with (ART/'elf.stdin').open('wb')as retained:shutil.copyfileobj(stream,retained)
            stream.seek(0)
            result=subprocess.run([str(executable())],stdin=stream,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},cwd=ROOT,timeout=120)
        COUNTS['processes']+=1;self.assertEqual((result.returncode,result.stderr),(0,b''))
        at=0;rows=[]
        while at<len(result.stdout):
            code,n=struct.unpack_from('<QQ',result.stdout,at);at+=16
            self.assertLessEqual(n,len(result.stdout)-at);body=result.stdout[at:at+n];at+=n
            if code==0xfffffffd:code=1
            rows.append(f'{code:08x}:'.encode()+body.hex().encode()+b'\n')
        self.assertEqual(len(rows),meta['successes']+meta['hir_errors']);self.assertEqual(rows,wanted)
        for index,row in zip(positions,rows,strict=True):complete[index]=row
        self.assertEqual(b''.join(complete),expected)
        (ART/'requests.hex').write_bytes(requests)
        (ART/'native-output.txt').write_bytes(b''.join(complete))
        (ART/'elf-case-indices.json').write_text(json.dumps(positions,separators=(',',':'))+'\n')
        COUNTS['elf_requests']+=len(rows)
        (ART/'elf.stdout').write_bytes(result.stdout);(ART/'elf.stderr').write_bytes(result.stderr)
        COUNTS['elf.stdin']={'bytes':input_bytes,'sha256':digest.hexdigest()};COUNTS['elf.stdout']={'bytes':len(result.stdout),'sha256':sha(result.stdout)}

    def test_capacity_atomicity(self):
        wire=ast(r'(?<group>\p{script=Greek}|[a-z&&[^q]]){2,7}',True)
        with HirFixture()as f:code,expected=observed(f,wire);self.assertEqual(code,0)
        for capacity in [0,1,63,len(expected)-1,len(expected),len(expected)+1]:
            with HirFixture(output_capacity=capacity,workspace_capacity=2<<20)as f:
                address=ctypes.addressof(f.session._output);ctypes.memset(address,0x9b,capacity);code,raw=observed(f,wire)
                if capacity<len(expected):
                    self.assertEqual((code,raw),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(address,capacity),b'\x9b'*capacity);COUNTS['capacity_refusals']+=1
                else:self.assertEqual((code,raw),(0,expected))
        with HirFixture(output_capacity=0,workspace_capacity=1048576+383)as f:
            self.assertEqual(observed(f,wire)[0],0xfffffffe);COUNTS['capacity_refusals']+=1
        with HirFixture(output_capacity=4096,workspace_capacity=1048576+384)as f:
            address=ctypes.addressof(f.session._output);ctypes.memset(address,0x9b,4096)
            self.assertEqual(observed(f,wire),(0xfffffffc,b''));self.assertEqual(ctypes.string_at(address,4096),b'\x9b'*4096)
            COUNTS['resource_refusals']=1

    def test_malformed_and_recovery(self):
        literal=ast('a');group=ast('(a)');repeat=ast('a{2,4}');cls=ast('[a-z]')
        wires=[b'',literal[:127],literal+b'x',b'NOFORMAT'+literal[8:]]
        for at,value in [(8,0),(8,1<<63),(16,1<<32),(24,251),(32,1),(40,1),(48,1),(56,1),(64,21),(72,1),(80,0xd800),(88,2),(96,1),(104,1),(112,1),(120,251)]:
            b=bytearray(literal);struct.pack_into('<Q',b,at,value);wires.append(bytes(b))
        for original,at,value in [(group,72,0),(group,72,2),(group,88,128),(repeat,80,1<<32),(repeat,88,1),(repeat,96,2),(cls,80,2),(cls,128+80-64,ord('z')+1)]:
            b=bytearray(original);struct.pack_into('<Q',b,at,value);wires.append(bytes(b))
        with HirFixture(output_capacity=4096,workspace_capacity=2<<20)as f:
            for i,wire in enumerate(wires):
                address=ctypes.addressof(f.session._output);ctypes.memset(address,0xa7,4096)
                self.assertEqual(observed(f,wire),(0xffffffff,b''),i);self.assertEqual(ctypes.string_at(address,4096),b'\xa7'*4096);COUNTS['framing_refusals']+=1
            self.assertEqual(observed(f,literal)[0],0)

    def test_receipt_validation(self):
        wire=ast('abc')
        for field in range(14):
            with HirFixture(output_capacity=1024,workspace_capacity=2<<20)as f:
                try:f.session.invoke(wire)
                except NativeRejected as e:self.assertEqual(e.code,0xffffffe0)
                else:self.fail('expected data continuation')
                COUNTS['native_calls']+=1
                address=ctypes.addressof(f.session._workspace);footer=f.constants['WORKSPACE_BYTES']-256
                payload=f.data.invoke(b'HRGDAT01',output_capacity=f.constants['ASSET_BYTES'],workspace_capacity=f.data_meta['workspace_bytes']);COUNTS['data_calls']+=1
                ctypes.memmove(address+8192,payload,len(payload));ctypes.memmove(address+footer+80,struct.pack('<QQQQ',len(payload),1,1,0),32)
                at=address+footer+field*8;value=struct.unpack('<Q',ctypes.string_at(at,8))[0];ctypes.memmove(at,struct.pack('<Q',value^1),8)
                output=ctypes.addressof(f.session._output);ctypes.memset(output,0x8f,1024)
                self.assertEqual(observed(f,wire),(0xffffffff,b''));self.assertEqual(ctypes.string_at(output,1024),b'\x8f'*1024);COUNTS['receipt_refusals']+=1

    def test_transport_refusals(self):
        for wire in [b'\x01',struct.pack('<Q',20)+b'x',struct.pack('<Q',134217729)]:
            result=run_elf(wire);self.assertEqual((result.returncode,result.stdout,result.stderr),(74,b'',b''))
        result=run_elf(b'');self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))

if __name__=='__main__':
    ART.mkdir(exist_ok=False);started=time.monotonic();suite=unittest.defaultTestLoader.loadTestsFromTestCase(HirNativeTests);result=unittest.TextTestRunner(verbosity=2).run(suite)
    report={'schema':'hepta.runtime.regex-hir-native-controls.v1','status':'PASS'if result.wasSuccessful()else'FAIL','tests_run':result.testsRun,'elapsed':time.monotonic()-started,**COUNTS,'source_sha256':{str(p.relative_to(ROOT)):sha(p.read_bytes())for p in [Path(__file__),ROOT/'tests/hia_native/regex_hir_fixture.py',ROOT/'tests/hia_native/regex_parser_fixture.py',ROOT/'tests/hia_native/regex_unicode_fixture.py',ROOT/'native/regex_hir.hepta',ROOT/'native/regex_syntax.hepta',ROOT/'native/regex_unicode_data.hepta',ROOT/'scripts/regex_hir_adapter.S',ROOT/'scripts/build_regex_probe.py']},'composition_manifest_sha256':sha((executable_manifest('hir')).read_bytes()),'regex_compiler_closed':False}
    (ART/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if result.wasSuccessful()else 1)
