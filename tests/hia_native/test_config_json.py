"""Actual HIA RuntimeConfig serde closure; no host JSON decoder executes the owner."""
from pathlib import Path
import argparse,collections,ctypes,hashlib,json,os,struct,subprocess,sys,time,unittest
ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'tests')]
from hia_native_loader import NativeModule,NativeRejected
from config_typed_cases import cases,wire,sample,encoded

REQUEST_SHA='87a619c1f79f22d4e8f5074856d0e49ed4fd475bf2809deb91e79d492f65b7c1'
OUTPUT_SHA='7d72f4df20f45a0b2317782dec628048360a79b724d008231d5f6a46439fb9f7'
sha=lambda value:hashlib.sha256(value).hexdigest()
COUNTS=collections.Counter()
MANIFEST=None

class ConfigJson(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module=NativeModule(MANIFEST,manifest_sha256=sha(MANIFEST.read_bytes()))
        cls.source=sha((ROOT/'native/config_json.hepta').read_bytes())
        assert cls.module.metadata['source_sha256']==cls.source
    @classmethod
    def tearDownClass(cls):cls.module.close()
    def invoke(self,session,request):
        COUNTS['native_calls']+=1
        try:
            out=session.invoke(request)
            return len(out),out
        except NativeRejected as error:
            return error.code,b''
    def raw(self,request,output=32768,workspace=65536,fill=0xA5):
        COUNTS['native_calls']+=1
        return self.module.invoke_raw(request,output_capacity=output,workspace_capacity=workspace,output_fill=fill,workspace_fill=0x5a)
    def test_01_complete_original_typed_domain(self):
        rows=cases();requests=''.join(w.hex()+'\n' for _,w in rows).encode()
        self.assertEqual(len(rows),6491);self.assertEqual(sha(requests),REQUEST_SHA)
        output=[]
        with self.module.session(output_capacity=2<<20,workspace_capacity=4<<20) as session:
            for category,request in rows:
                code,raw=self.invoke(session,request)
                output.append(f'{code:08x}:'+raw.hex()+'\n')
        output=''.join(output).encode();self.assertEqual(sha(output),OUTPUT_SHA)
        self.assertEqual(len(output),2946846)
        COUNTS['original_domain_cases']+=6491
        folder=os.environ.get('HIA_CONFIG_JSON_CORPUS_DIR')
        if folder:
            folder=Path(folder);folder.mkdir(parents=True,exist_ok=False)
            (folder/'requests.hex').write_bytes(requests)
            (folder/'native-output.txt').write_bytes(output)
            metadata={'schema':'hepta.runtime.config-json-corpus.v1','cases':6491,
                'categories':dict(collections.Counter(c for c,_ in rows)),
                'requests_file':'requests.hex','requests_sha256':sha(requests),'requests_bytes':len(requests),
                'native_output_file':'native-output.txt','native_output_sha256':sha(output),'native_output_bytes':len(output),
                'source_sha256':self.source,'manifest_sha256':sha(MANIFEST.read_bytes()),
                'image_sha256':self.module.metadata['image_sha256']}
            (folder/'native-corpus.json').write_text(json.dumps(metadata,indent=2,sort_keys=True)+'\n')
    def test_02_self_contained_arena_and_padding(self):
        for kind in (100,101,103,105,107,108):
            request=bytearray(wire(kind,encoded(sample(kind))));struct.pack_into('<Q',request,8,2);request=bytes(request)
            code,a,_=self.raw(request,output=100000,workspace=1<<20,fill=0xa5)
            self.assertLess(code,0xffff0000);a=a[:code]
            COUNTS['native_calls']+=1
            code2,b,_=self.module.invoke_raw(request,output_capacity=100000,workspace_capacity=1<<20,output_fill=0x39,workspace_fill=0xc3)
            self.assertEqual((code,a),(code2,b[:code2]))
            self.assertEqual(a[:8],b'HRCFGA01');size,root,schema=struct.unpack_from('<3Q',a,8)
            self.assertEqual((size,schema),(len(a),kind));self.assertGreaterEqual(root,128)
            seen=set();pending=[root]
            while pending:
                node=pending.pop();self.assertNotIn(node,seen);seen.add(node)
                self.assertLessEqual(node+64,len(a));ty,nxt,first,count,at,n,kat,kn=struct.unpack_from('<8Q',a,node)
                if ty in (1,6,7):self.assertLessEqual(at+n,len(a))
                if kn:self.assertLessEqual(kat+kn,len(a))
                if first:pending.append(first)
                if nxt:pending.append(nxt)
            # Every referenced byte is part of the owned result, never the input/workspace address.
            self.assertGreater(len(seen),1)
    def test_03_refusal_and_output_atomicity(self):
        good=wire(100,b'{}');bad=[good[:n] for n in range(40)]
        for offset in (0,7,8,16,24,32):
            changed=bytearray(good);changed[offset]^=0xff;bad.append(bytes(changed))
        bad += [wire(100,b'{'),wire(100,b'{"hosts":null}'),wire(100,b'{}x'),wire(100,b'[]]')]
        for request in bad:
            code,out,_=self.raw(request,output=64)
            self.assertEqual(code,0xffffffff)
            self.assertEqual(out,b'\xa5'*64)
        code,out,_=self.raw(wire(100,b'{}',b'/\xff'),output=1024)
        self.assertEqual(code,0xfffffffd);self.assertEqual(out,b'\xa5'*1024)
        for cap,work in [(0,65536),(1,65536),(65536,65535),(65536,0)]:
            code,out,_=self.raw(good,output=cap,workspace=work)
            self.assertEqual(code,0xfffffffe);self.assertEqual(out,b'\xa5'*cap)
    def test_04_exact_capacity_and_persistent_recovery(self):
        request=wire(100,encoded(sample(100)))
        with self.module.session(output_capacity=1<<20,workspace_capacity=2<<20) as session:
            code,expected=self.invoke(session,request);self.assertEqual(code,len(expected))
            for _ in range(4):
                rejected,_=self.invoke(session,wire(100,b'{"hosts":null}'))
                self.assertEqual(rejected,0xffffffff)
                self.assertEqual(self.invoke(session,request),(code,expected))
                small=self.invoke(session,wire(100,b'{}'))
                self.assertEqual(small[1],b'{"state_dir":"/trusted/\xe4\xb8\xad/state","controller_workspace_roots":[],"hosts":{}}')
        for capacity in [len(expected)-1,len(expected),len(expected)+1]:
            got,out,_=self.raw(request,output=capacity,workspace=2<<20)
            if capacity<len(expected):
                self.assertEqual(got,0xfffffffe);self.assertEqual(out,b'\xa5'*capacity)
            else:
                self.assertEqual(got,len(expected));self.assertEqual(out[:got],expected)
    def test_05_real_static_elf(self):
        standalone=self.module.metadata['standalone'];binary=MANIFEST.parent/standalone['path']
        self.assertEqual(sha(binary.read_bytes()),standalone['sha256'])
        self.assertFalse(standalone['runtime_python_required']);self.assertFalse(standalone['runtime_libc_required'])
        inputs=[wire(100,b'{}'),wire(100,encoded(sample(100))),wire(103,encoded(sample(103,False))),
                wire(3,b'18446744073709551615'),wire(1,encoded('\0\n中😀')),wire(12,b'{"jadx":null}')]
        with self.module.session(output_capacity=2<<20,workspace_capacity=4<<20) as session:
            for request in inputs:
                expected=self.invoke(session,request)[1]
                actual=subprocess.run([str(binary)],input=request,capture_output=True,env={'PATH':''},timeout=10)
                self.assertEqual(actual.returncode,0);self.assertEqual(actual.stderr,b'');self.assertEqual(actual.stdout,expected)
                COUNTS['real_elf_runs']+=1

def main():
    global MANIFEST
    parser=argparse.ArgumentParser();parser.add_argument('--manifest',type=Path,default=os.environ.get('HIA_CONFIG_JSON_MANIFEST'))
    args,rest=parser.parse_known_args();assert args.manifest,'compiled manifest required'
    MANIFEST=args.manifest.resolve();start=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ConfigJson))
    summary={'schema':'hepta.runtime.config-json-native-tests.v1','status':'PASS' if result.wasSuccessful() else 'FAIL',
             'test_groups':result.testsRun,'counts':dict(COUNTS),'elapsed_seconds':time.monotonic()-start,
             'manifest_sha256':sha(MANIFEST.read_bytes()),'source_sha256':sha((ROOT/'native/config_json.hepta').read_bytes()),
             'complete_config_installation':False,'production_activated':False}
    print(json.dumps(summary,sort_keys=True),flush=True)
    raise SystemExit(0 if result.wasSuccessful() else 1)
if __name__=='__main__':main()
