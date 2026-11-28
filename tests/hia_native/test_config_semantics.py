"""Native RuntimeConfig validation, public projections and exact policy identity.

The retained reference is the observed unchanged Rust closure, compiled with
the original versions/checksums. Regex-dependent validation executes the fixed
seven-image HIA child chain; the old four pending cases now require exact results.
"""
from pathlib import Path
import argparse,collections,ctypes,gzip,hashlib,json,os,struct,subprocess,sys,time,unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
from hia_native_loader import NativeModule,NativeRejected,NativeCapacityError
from config_regex_session import NativeValidator
from config_semantics_cases import cases,base,variants

sha=lambda raw:hashlib.sha256(raw).hexdigest()
COUNTS=collections.Counter()
MANIFESTS={}
VALIDATION_ELF=None
ORIGINAL_OUTPUT_SHA='f749e18917afe6cc798749dd09418bd0682bec2dde92863c4548b26a4f583cbc'
REQUEST_SHA='b817774c48233e843a9b7b5f3f1577a0306846946694ca9f6be1c4e0517ddee2'

def request(value,default=b'/default-state'):
    raw=json.dumps(value,ensure_ascii=False,separators=(',',':')).encode()
    return b'HRCFGJ01'+struct.pack('<4Q',2,100,len(default),len(raw))+default+raw

def frame(arena,operation=1,identity=False):
    return (b'HRCFGI01' if identity else b'HRCFGV01')+struct.pack('<2Q',operation,len(arena))+arena

class ConfigSemantics(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.modules={}
        for name,p in MANIFESTS.items():
            m=NativeModule(p,manifest_sha256=sha(p.read_bytes()))
            assert m.metadata['source_sha256']==sha((ROOT/'native'/('config_'+name+'.hepta')).read_bytes())
            cls.modules[name]=m
        cls.parser=cls.modules['json'].session(output_capacity=16<<20,workspace_capacity=32<<20)
        cls.validation=NativeValidator(VALIDATION_ELF,ROOT)
        cls.identity=cls.modules['identity'].session(output_capacity=16<<20,workspace_capacity=32<<20)
    @classmethod
    def tearDownClass(cls):
        for s in [cls.parser,cls.validation,cls.identity]:s.close()
        for m in cls.modules.values():m.close()
    def call(self,session,wire):
        COUNTS['native_calls']+=1
        return session.invoke(wire)
    def raw(self,name,wire,output=4096,workspace=None):
        COUNTS['native_calls']+=1
        if name!='validation' or workspace is not None:
            return self.modules[name].invoke_raw(wire,output_capacity=output,workspace_capacity=1<<20 if workspace is None else workspace,output_fill=0xa5,workspace_fill=0x5a)
        # The continuation owns the declared 256 MiB carrier. These controls
        # inspect the complete output but never consume a full workspace copy.
        with self.modules[name].session(output_capacity=output,workspace_capacity=256<<20)as session:
            ctypes.memset(ctypes.addressof(session._workspace),0x5a,256<<20)
            ctypes.memset(ctypes.addressof(session._output),0xa5,output)
            try:code=len(session.invoke(wire))
            except(NativeRejected,NativeCapacityError)as error:code=error.code
            return code,ctypes.string_at(ctypes.addressof(session._output),output),b''
    def arena(self,value,default=b'/default-state'):
        return self.call(self.parser,request(value,default))
    def result(self,arena,op):
        out=self.call(self.validation,frame(arena,op));magic,status,code,n=struct.unpack_from('<8s3Q',out)
        self.assertEqual(magic,b'HRCFGR01');self.assertEqual(n,len(out)-32)
        return status,code,out[32:]
    def test_01_complete_observed_reference_domain(self):
        rows=cases();raw_requests=''.join(w.hex()+'\n' for _,w in rows).encode()
        expected=gzip.decompress((ROOT/'tests/hia_native/config_runtime_original_output.txt.gz').read_bytes())
        self.assertEqual(sha(expected),ORIGINAL_OUTPUT_SHA);self.assertEqual(len(rows),2063)
        self.assertEqual(sha(raw_requests),REQUEST_SHA)
        outputs=[];pending=[]
        for index,((category,wire),reference) in enumerate(zip(rows,expected.splitlines(),strict=True)):
            rc,rp=reference.decode().split(':',1);op=struct.unpack_from('<Q',wire,8)[0]
            parse=bytearray(wire);struct.pack_into('<Q',parse,8,2)
            try:arena=self.call(self.parser,bytes(parse))
            except NativeRejected as error:
                self.assertEqual(error.code,0xffffffff);self.assertEqual(rc,'ffffffff')
                outputs.append('ffffffff:\n');COUNTS['original_typed_refusals']+=1;continue
            if op==4:
                digest=self.call(self.identity,frame(arena,1,True));self.assertEqual((rc,digest.hex()),('00000000',rp))
                canonical=self.call(self.identity,frame(arena,2,True))
                self.assertEqual(hashlib.sha256(canonical).digest(),digest)
                outputs.append('00000000:'+digest.hex()+'\n');COUNTS['original_digest_cases']+=1
            else:
                status,code,payload=self.result(arena,op)
                self.assertIn(status,[0,1])
                self.assertEqual((f'{status:08x}',payload.hex()),(rc,rp),(index,category))
                outputs.append(f'{status:08x}:'+payload.hex()+'\n')
                COUNTS['original_semantic_cases']+=1
                if index in [450,451,452,454]:COUNTS['previous_regex_dependency_cases_closed']+=1
        self.assertEqual(pending,[])
        folder=os.environ.get('HIA_CONFIG_SEMANTICS_CORPUS_DIR')
        if folder:
            folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
            out=''.join(outputs).encode();(folder/'requests.hex').write_bytes(raw_requests);(folder/'native-output.txt').write_bytes(out)
            meta={'schema':'hepta.runtime.config-semantics-corpus.v1','cases':len(rows),
                  'requests_file':'requests.hex','requests_sha256':sha(raw_requests),'requests_bytes':len(raw_requests),
                  'native_output_file':'native-output.txt','native_output_sha256':sha(out),'native_output_bytes':len(out),
                  'explicit_incomplete_regex_indices':pending,'original_output_sha256':ORIGINAL_OUTPUT_SHA,
                  'manifests':{n:sha(p.read_bytes()) for n,p in MANIFESTS.items()},
                  'sources':{n:m.metadata['source_sha256'] for n,m in self.modules.items()}}
            (folder/'native-corpus.json').write_text(json.dumps(meta,indent=2,sort_keys=True)+'\n')
    def test_02_exact_capacity_and_atomic_refusals(self):
        arena=self.arena(variants()['all'])
        for name,op in [('validation',1),('validation',2),('validation',3),('identity',1),('identity',2)]:
            wire=frame(arena,op,name=='identity');session=self.identity if name=='identity' else self.validation
            expected=self.call(session,wire)
            for capacity in [0,len(expected)-1,len(expected),len(expected)+1]:
                code,out,work=self.raw(name,wire,output=capacity)
                if capacity<len(expected):self.assertEqual(code,0xfffffffe);self.assertEqual(out,b'\xa5'*capacity)
                else:self.assertEqual(code,len(expected));self.assertEqual(out[:code],expected);self.assertEqual(out[code:],b'\xa5'*(capacity-code))
        for name in ['validation','identity']:
            wire=frame(arena,1,name=='identity')
            for worksize in [0,31,4095,32767]:
                code,out,_=self.raw(name,wire,output=4096,workspace=worksize)
                self.assertEqual(code,0xfffffffe);self.assertEqual(out,b'\xa5'*4096)
    def test_03_untrusted_arena_admission(self):
        arena=self.arena(base());root=struct.unpack_from('<Q',arena,16)[0]
        corrupt=[]
        for index in [0,7,8,16,24,32,40,120,root,root+16,root+24]:
            value=bytearray(arena);value[index]^=0xff;corrupt.append(bytes(value))
        corrupt += [arena[:n] for n in [0,1,7,127,128,len(arena)-1]]
        for name in ['validation','identity']:
            for value in corrupt:
                code,out,_=self.raw(name,frame(value,1,name=='identity'),output=64)
                self.assertEqual(code,0xffffffff);self.assertEqual(out,b'\xa5'*64)
            with self.modules[name].session(output_capacity=4096,workspace_capacity=(256<<20 if name=='validation'else 1<<20)) as session:
                for _ in range(3):
                    with self.assertRaises(NativeRejected):self.call(session,frame(corrupt[0],1,name=='identity'))
                    self.call(session,frame(arena,1,name=='identity'))
    def test_04_non_utf8_state_digest_is_deferred(self):
        value=base();del value['state_dir'];arena=self.arena(value,b'/raw-\xff-state')
        self.assertEqual(self.result(arena,1),(0,0,b''))
        self.assertEqual(self.result(arena,2)[0],0);self.assertEqual(self.result(arena,3)[0],0)
        for op in [1,2]:
            code,out,_=self.raw('identity',frame(arena,op,True),output=4096)
            self.assertEqual(code,0xfffffffd);self.assertEqual(out,b'\xa5'*4096)
    def test_05_private_policy_never_enters_public_projection(self):
        value=base();host=value['hosts']['h'];host['privileged_actions']={'public-action':{'executable':'/SECRET_PROGRAM','fixed_args':['SECRET_ARG']}}
        a=self.arena(value);before=[self.result(a,op)[2] for op in [2,3]]
        value['state_dir']='/OTHER_SECRET_STATE';value['controller_workspace_roots']=['/OTHER_SECRET_WORK'];host['ssh_target']='OTHER_SECRET_TARGET';host['remote_state_dir']='/OTHER_SECRET_REMOTE'
        host['privileged_actions']['public-action']['executable']='/OTHER_SECRET_PROGRAM';host['privileged_actions']['public-action']['fixed_args']=['OTHER_SECRET_ARG']
        b=self.arena(value);after=[self.result(b,op)[2] for op in [2,3]]
        self.assertEqual(before,after)
        for output in after:self.assertNotIn(b'SECRET',output);self.assertNotIn(b'sha256',output);self.assertNotIn(b'ssh_target',output)
        self.assertNotEqual(self.call(self.identity,frame(a,1,True)),self.call(self.identity,frame(b,1,True)))
        host['ssh_target']='-SECRET_BAD_TARGET';bad=self.arena(value)
        self.assertEqual(self.result(bad,3)[2],b'effective runtime configuration is unavailable')
    def test_06_real_static_elf_outputs(self):
        arena=self.arena(variants()['all'])
        for name,op in [('validation',1),('validation',2),('validation',3),('identity',1),('identity',2)]:
            m=self.modules[name]
            if name=='validation':
                meta=json.loads(VALIDATION_ELF.read_bytes());binary=VALIDATION_ELF.parent/meta['executable']
                self.assertFalse(meta['runtime_python_required']);self.assertFalse(meta['runtime_libc_required']);self.assertEqual(sha(binary.read_bytes()),meta['executable_sha256'])
            else:
                meta=m.metadata['standalone'];binary=MANIFESTS[name].parent/meta['path']
                self.assertFalse(meta['runtime_python_required']);self.assertFalse(meta['runtime_libc_required']);self.assertEqual(sha(binary.read_bytes()),meta['sha256'])
            wire=frame(arena,op,name=='identity');session=self.identity if name=='identity' else self.validation
            expected=self.call(session,wire)
            proc=subprocess.run([str(binary)],input=(struct.pack('<Q',len(wire))+wire if name=='validation'else wire),capture_output=True,env={'PATH':'','LC_ALL':'C'},timeout=10)
            if name=='validation':
                self.assertGreaterEqual(len(proc.stdout),16);code,n=struct.unpack_from('<2Q',proc.stdout);self.assertEqual((code,n),(0,len(proc.stdout)-16));proc.stdout=proc.stdout[16:]
            self.assertEqual((proc.returncode,proc.stdout,proc.stderr),(0,expected,b''));COUNTS['real_static_elf_runs']+=1

def main():
    global VALIDATION_ELF
    parser=argparse.ArgumentParser()
    parser.add_argument('--validation-elf-manifest',type=Path,default=os.environ.get('HIA_CONFIG_VALIDATION_ELF_MANIFEST'))
    for name in ['json','validation','identity']:
        parser.add_argument('--'+name+'-manifest',type=Path,default=os.environ.get('HIA_CONFIG_'+name.upper()+'_MANIFEST'))
    args=parser.parse_args()
    assert args.validation_elf_manifest,'compiled validation chain required'
    VALIDATION_ELF=args.validation_elf_manifest.resolve(strict=True)
    for name in ['json','validation','identity']:
        value=getattr(args,name+'_manifest');assert value,'compiled manifests required';MANIFESTS[name]=value.resolve()
    start=time.monotonic();result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigSemantics))
    print(json.dumps({'schema':'hepta.runtime.config-semantics-native-tests.v1','status':'PASS' if result.wasSuccessful() else 'FAIL',
                     'test_groups':result.testsRun,'counts':dict(COUNTS),'elapsed_seconds':time.monotonic()-start,
                     'complete_config_owner':False,'regex_compilation_closed':False,'os_installation_closed':False,
                     'manifests':{n:sha(p.read_bytes()) for n,p in MANIFESTS.items()},'validation_elf_manifest_sha256':sha(VALIDATION_ELF.read_bytes())},sort_keys=True),flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)

if __name__=='__main__':main()
