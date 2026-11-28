"""Native graph admission, atomic output and explicitly synthetic ack controls."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import collections,ctypes,hashlib,json,struct,sys,time,unittest
from regex_unicode_fixture import ROOT,NativeModule,NativeRejected,NativeCapacityError
from regex_parser_fixture import ParserFixture,request
from regex_hir_fixture import HirFixture
from regex_nfa_fixture import NfaFixture
from regex_match_fixture import MatchFixture
sha=lambda raw:hashlib.sha256(raw).hexdigest()
ART=artifact('controls');COUNTS=collections.Counter()

def actual(session,wire):
    COUNTS['native_entries']+=1
    try:return 0,session.invoke(wire)
    except NativeRejected as error:return error.code,b''
    except NativeCapacityError:return 0xfffffffe,b''
def word(address,at,value):ctypes.memmove(address+at,struct.pack('<Q',value),8)
def read(address,at):return struct.unpack('<Q',ctypes.string_at(address+at,8))[0]
def change(wire,at,value):
    out=bytearray(wire);struct.pack_into('<Q',out,at,value);return bytes(out)
def tree(pattern):
    with ParserFixture()as parser,HirFixture()as hir:
        code,ast=parser.invoke(request(pattern,False));assert code==0
        code,result=hir.invoke(ast);assert code==0
        COUNTS['setup_parser_entries']+=parser.calls;COUNTS['setup_hir_entries']+=hir.calls
        return ast,result
def module(name):
    path=module_manifest(name)
    return NativeModule(path,manifest_sha256=sha(path.read_bytes()))

class RegexControls(unittest.TestCase):
    def test_01_nfa_admission_and_capacity(self):
        ast,hir=tree('a')
        wire=b'HRGNFI01'+struct.pack('<3Q',0,10485760,1)+hir
        bad=[b'',wire[:191],wire+b'x',b'BADMAGIC'+wire[8:]]
        for at,value in [(8,2),(16,10485761),(24,2),(40,0),(40,1<<63),(56,1025),(64,2),(72,262144),(80,1),(88,1),(96,9),(104,1),(136,1<<63),(144,1<<63),(168,4),(176,262144),(184,262144)]:bad.append(change(wire,at,value))
        with module('regex_nfa')as owner:
            with owner.session(output_capacity=4096,workspace_capacity=32<<20)as session:
                address=ctypes.addressof(session._output)
                for index,raw in enumerate(bad):
                    ctypes.memset(address,0xa7,4096)
                    self.assertEqual(actual(session,raw),(0xffffffff,b''),index)
                    self.assertEqual(ctypes.string_at(address,4096),b'\xa7'*4096);COUNTS['nfa_invalid_refusals']+=1
                code,expected=actual(session,wire);self.assertEqual(code,0)
            for capacity in [0,1,63,len(expected)-1,len(expected),len(expected)+1]:
                with owner.session(output_capacity=capacity,workspace_capacity=32<<20)as session:
                    address=ctypes.addressof(session._output);ctypes.memset(address,0xc3,capacity)
                    code,out=actual(session,wire)
                    if capacity<len(expected):
                        self.assertEqual((code,out),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(address,capacity),b'\xc3'*capacity);COUNTS['nfa_capacity_refusals']+=1
                    else:self.assertEqual((code,out),(0,expected));self.assertEqual(ctypes.string_at(address+len(expected),capacity-len(expected)),b'\xc3'*(capacity-len(expected)))
            for work in [0,1048576,2097152]:
                with owner.session(output_capacity=64,workspace_capacity=work)as session:
                    address=ctypes.addressof(session._output);ctypes.memset(address,0xc3,64)
                    self.assertEqual(actual(session,wire),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(address,64),b'\xc3'*64);COUNTS['nfa_capacity_refusals']+=1

    def test_02_match_graphs_and_utf8(self):
        _,hir=tree(r'(?<group>a|bc)*\b\p{Greek}')
        with NfaFixture(output_capacity=1<<20,workspace_capacity=32<<20)as compiler:
            code,graph=compiler.invoke(hir,graph=True);self.assertEqual(code,0);COUNTS['setup_nfa_entries']+=compiler.calls
        wire=b'HRGMAT01'+struct.pack('<2Q',len(graph),2)+graph+'α'.encode()
        count=struct.unpack_from('<Q',graph,8)[0]
        bad=[b'',wire[:151],wire+b'x',b'BADMAGIC'+wire[8:],wire[:-2]+b'\xc0\x80']
        for at,value in [(8,127),(8,len(graph)+1),(16,1),(32,0),(32,327681),(40,1<<63),(48,10485761),(56,count),(64,count),(72,count),(80,1),(88,10),(88+48,1),(88+56,1)]:bad.append(change(wire,at,value))
        for i in range(count):
            at=88+i*64;kind=struct.unpack_from('<Q',wire,at)[0]
            if kind in [0,1,3,4,5]:bad.append(change(wire,at+24,count))
            if kind==1:bad.append(change(wire,at+16,256))
            if kind==3:bad.append(change(wire,at+8,3))
            edges=struct.unpack_from('<Q',wire,at+40)[0]
            if edges:
                edge=24+struct.unpack_from('<Q',wire,at+32)[0]
                bad.append(change(wire,edge+16,count));bad.append(change(wire,at+40,1<<63))
        with MatchFixture()as fixture:
            address=ctypes.addressof(fixture.session._output)
            for index,raw in enumerate(bad):
                ctypes.memset(address,0xb4,8)
                code,out=fixture.invoke(raw);self.assertEqual((code,out),(0xffffffff,b''),index)
                self.assertEqual(ctypes.string_at(address,8),b'\xb4'*8);COUNTS['matcher_invalid_refusals']+=1
            code,out=fixture.invoke(wire);self.assertEqual((code,out),(0,struct.pack('<Q',1)))
            COUNTS['matcher_entries']+=fixture.calls;COUNTS['matcher_data_calls']+=fixture.children
        for cap in [0,7]:
            with MatchFixture(output_capacity=cap)as fixture:
                address=ctypes.addressof(fixture.session._output);ctypes.memset(address,0xb4,cap)
                self.assertEqual(fixture.invoke(wire),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(address,cap),b'\xb4'*cap);COUNTS['matcher_capacity_refusals']+=1

    def test_03_controller_receipts(self):
        ast,_=tree('a')
        wire=b'HRGEX001'+struct.pack('<3Q',1,1,0)+b'a'
        with module('regex_controller')as owner:
            with owner.session(output_capacity=32,workspace_capacity=256<<20)as session:
                address=ctypes.addressof(session._workspace);out=ctypes.addressof(session._output);footer=(256<<20)-256
                for field in range(15):
                    word(address,0,0);ctypes.memset(out,0xd6,32)
                    self.assertEqual(actual(session,wire),(0xffffffe0,b''))
                    sequence=read(address,footer+8);destination=read(address,footer+56)
                    ctypes.memmove(address+destination,ast,len(ast));ctypes.memmove(address+footer+80,struct.pack('<4Q',len(ast),sequence,1,0),32)
                    at=footer+field*8;old=read(address,at)
                    word(address,at,(1<<32) if field==10 else old^1)
                    self.assertEqual(actual(session,wire),(0xffffffff,b''),field);self.assertEqual(ctypes.string_at(out,32),b'\xd6'*32)
                    word(address,at,old);self.assertEqual(actual(session,wire),(0xffffffe0,b''));self.assertEqual(read(address,footer+16),12)
                    COUNTS['controller_corrupt_receipts']+=1
                for child_code,status in [(0xfffffffd,1),(0xfffffffe,3),(0xfffffffc,3)]:
                    word(address,0,0);self.assertEqual(actual(session,wire)[0],0xffffffe0)
                    sequence=read(address,footer+8);ctypes.memmove(address+footer+80,struct.pack('<4Q',child_code,sequence,1,0),32)
                    self.assertEqual(actual(session,wire),(0,b'HRGREX01'+struct.pack('<3Q',status,0,0)))
                    self.assertEqual(read(address,8),0);COUNTS['controller_domain_statuses']+=1
            for cap in [0,31]:
                with owner.session(output_capacity=cap,workspace_capacity=0)as session:
                    self.assertEqual(actual(session,wire),(0xfffffffe,b''));COUNTS['controller_capacity_refusals']+=1

    def test_04_config_receipts_and_capacity(self):
        path=module_manifest('json')
        value={'state_dir':'/s','hosts':{'h':{'ssh_target':'h','remote_state_dir':'/r','privileged_actions':{'a':{'executable':'/x','allow_extra_args':True,'extra_arg_patterns':['a']}}}}}
        raw=json.dumps(value,separators=(',',':')).encode()
        with NativeModule(path,manifest_sha256=sha(path.read_bytes()))as parser:
            arena=parser.invoke(b'HRCFGJ01'+struct.pack('<4Q',2,100,2,len(raw))+b'/s'+raw,output_capacity=4096,workspace_capacity=1<<20)
        wire=b'HRCFGV01'+struct.pack('<2Q',1,len(arena))+arena
        with module('validation')as owner:
            with owner.session(output_capacity=256,workspace_capacity=256<<20)as session:
                address=ctypes.addressof(session._workspace);out=ctypes.addressof(session._output);footer=(256<<20)-256
                def begin():
                    word(address,81920,0);ctypes.memset(out,0xe5,256)
                    self.assertEqual(actual(session,wire),(0xffffffe0,b''))
                    sequence=read(address,footer+8)
                    ctypes.memmove(address+122880,b'HRGREX01'+struct.pack('<3Q',0,1,0),32)
                    ctypes.memmove(address+footer+80,struct.pack('<4Q',32,sequence,1,0),32)
                for field in range(15):
                    begin();at=footer+field*8;old=read(address,at);word(address,at,old^1)
                    self.assertEqual(actual(session,wire),(0xffffffff,b''));self.assertEqual(ctypes.string_at(out,256),b'\xe5'*256)
                    word(address,at,old);self.assertEqual(actual(session,wire),(0,b'HRCFGR01'+bytes(24)))
                    COUNTS['config_corrupt_receipts']+=1
                for offset,value in [(0,0),(8,4),(16,0),(24,1)]:
                    begin();word(address,122880+offset,value)
                    self.assertEqual(actual(session,wire),(0xffffffff,b''));self.assertEqual(ctypes.string_at(out,256),b'\xe5'*256);COUNTS['config_corrupt_envelopes']+=1
                for status in [1,2,3]:
                    begin();ctypes.memmove(address+122880,b'HRGREX01'+struct.pack('<3Q',status,0,0),32)
                    code,result=actual(session,wire)
                    if status==3:self.assertEqual((code,result),(0xfffffffe,b''));self.assertEqual(ctypes.string_at(out,256),b'\xe5'*256)
                    else:self.assertEqual((code,result[32:]),(0,b'host `h` privileged action `a` has invalid argument regex'))
                    self.assertEqual(read(address,81928),0);COUNTS['config_domain_statuses']+=1
                    self.assertEqual(actual(session,wire)[0],0xffffffe0);COUNTS['config_failed_request_recoveries']+=1

if __name__=='__main__':
    ART.mkdir(exist_ok=False);start=time.monotonic()
    sources=[Path(__file__),*[ROOT/'native'/n for n in ['regex_nfa.hepta','regex_match.hepta','regex_controller.hepta','config_validation.hepta']]]
    before={str(p.relative_to(ROOT)):sha(p.read_bytes())for p in sources}
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(RegexControls))
    unchanged=all(sha((ROOT/n).read_bytes())==digest for n,digest in before.items())
    report={'schema':'hepta.runtime.regex-internal-controls.v1','status':'PASS'if result.wasSuccessful()and unchanged else'FAIL','tests_run':result.testsRun,'elapsed':time.monotonic()-start,'counts':dict(COUNTS),'source_sha256':before,'source_unchanged':unchanged,'synthetic_acknowledgements_explicit':True}
    (ART/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n');print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['status']=='PASS'else 1)
