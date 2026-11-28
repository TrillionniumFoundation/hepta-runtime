"""Execute native HMAC/HKDF and private operation bindings with independent references.

The fixture tokens and keys are synthetic. No test authenticates a bearer or
activates result retention, nonce custody, AEAD, HTTP or the operation ledger.
"""
from pathlib import Path
import copy
import gzip
import hashlib
import hmac
import json
import os
import random
import struct
import subprocess
import sys
import unittest

ROOT=Path(os.environ.get('HIA_REFERENCE_RUNTIME',Path(__file__).resolve().parents[2]))
SOURCE_ROOT=Path(os.environ.get('HIA_KDF_SOURCE_ROOT',ROOT))
sys.path.insert(0,str(ROOT/'scripts'))
from hia_native_loader import NativeModule
INVALID=0xffffffff
CAPACITY=0xfffffffe
BOUND=0xfffffffd
COUNTS={'native_calls':0,'standard_reference_cases':0,'original_binding_cases':0,
        'exact_capacity_reference_cases':0,'capacity_refusal_cases':0,'elf_requests':0}
CORPUS=[]
PREFIX=b'hepta-runtime/native-operation/'
SALT=PREFIX+b'crypto/extract/v1'
DOMAINS=[PREFIX+value for value in [b'result-aead/v1',b'request-binding/v1',b'idempotency-binding/v1',b'private-policy-binding/v1']]
RECORD_SALT=PREFIX+b'record-key/extract/v1'
RECORD_DOMAIN=PREFIX+b'record-key/expand/v1'

def frame(op,a=b'',b=b'',c=b'',size=32):
    return b'HRKDF001'+struct.pack('<6Q',op,0,len(a),len(b),len(c),size)+a+b+c

def mac(key,value):return hmac.digest(key,value,'sha256')

def expand(prk,info,size):
    previous=b'';out=b''
    for number in range(1,(size+31)//32+1):
        previous=mac(prk,previous+info+bytes([number]));out+=previous
    return out[:size]

def reference(op,a,b,c,size):
    if op in (1,2):return mac(a,b)
    if op==3:return expand(a,b,size)
    if op==4:return expand(mac(a,b),c,size)
    if op==5:return b''.join(expand(mac(SALT,a),domain,32) for domain in DOMAINS)
    if op in (6,7,8):
        domain=DOMAINS[op-5]
        return mac(a,len(domain).to_bytes(4,'big')+domain+len(b).to_bytes(8,'big')+b).hex().encode()
    if op==9:return expand(mac(RECORD_SALT,a),RECORD_DOMAIN+b+c,32)
    raise AssertionError(op)

class KdfTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest=Path(os.environ['HIA_KDF_MANIFEST'])
        cls.module=NativeModule(cls.manifest,manifest_sha256=hashlib.sha256(cls.manifest.read_bytes()).hexdigest())
        cls.proof=json.loads((SOURCE_ROOT/'native/operation_kdf_composition.json').read_text())
        assert hashlib.sha256((SOURCE_ROOT/'native/operation_kdf.hepta').read_bytes()).hexdigest()==cls.proof['source_sha256']==cls.module.metadata['source_sha256']
        original=(ROOT/cls.proof['original_source']).read_bytes()
        assert hashlib.sha256(original).hexdigest()==cls.proof['original_source_sha256']
        cls.reference_sources={name:hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()
            for name in ['oracle_operation_kdf.rs','kdf_oracle/Cargo.toml','kdf_oracle/Cargo.lock',
                         'kdf_oracle/build.rs','kdf_oracle/original_access.rs']}
        codec=(ROOT/cls.proof['import_source']).read_bytes()
        assert hashlib.sha256(codec).hexdigest()==cls.proof['import_source_sha256']
        sys.path.insert(0,os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        old={f['name']:f for f in assemble_program(codec).as_dict()['functions']}
        new={f['name']:f for f in assemble_program((SOURCE_ROOT/'native/operation_kdf.hepta').read_bytes()).as_dict()['functions']}
        reverse={v:k for k,v in cls.proof['relocation'].items()}
        for name,destination in cls.proof['relocation'].items():
            value=copy.deepcopy(new[destination]);value['name']=name
            for block in value['blocks']:
                for op in block['ops']:
                    if op['op']=='call':op['attrs']['function']=reverse[op['attrs']['function']]
            assert value==old[name]
            canonical=json.dumps(value,sort_keys=True,separators=(',',':')).encode()
            assert hashlib.sha256(canonical).hexdigest()==cls.proof['imported_functions_sha256'][name]

    @classmethod
    def tearDownClass(cls):
        cls.module.close()
        for name,digest in cls.reference_sources.items():
            assert hashlib.sha256((Path(__file__).parent/name).read_bytes()).hexdigest()==digest
        if os.environ.get('HIA_KDF_CORPUS_DIR'):
            folder=Path(os.environ['HIA_KDF_CORPUS_DIR']);folder.mkdir(parents=True,exist_ok=False)
            raw=b''.join(json.dumps(row,sort_keys=True,separators=(',',':')).encode()+b'\n' for row in CORPUS)
            packed=gzip.compress(raw,mtime=0);(folder/'kdf_cases.jsonl.gz').write_bytes(packed)
            metadata={'schema':'hepta.runtime.native-operation-kdf-corpus.v1','counts':COUNTS,
                'source_sha256':cls.module.metadata['source_sha256'],'image_sha256':cls.module.metadata['image_sha256'],
                'original_source_sha256':cls.proof['original_source_sha256'],
                'oracle_sources_sha256':cls.reference_sources,
                'native_output_sha256':hashlib.sha256(''.join(str(row['code'])+':'+row['output_hex']+'\n' for row in CORPUS).encode()).hexdigest(),
                'composition_sha256':hashlib.sha256((SOURCE_ROOT/'native/operation_kdf_composition.json').read_bytes()).hexdigest(),
                'corpus':{'file':'kdf_cases.jsonl.gz','gzip_sha256':hashlib.sha256(packed).hexdigest(),
                          'raw_sha256':hashlib.sha256(raw).hexdigest(),'raw_bytes':len(raw),'cases':len(CORPUS)}}
            (folder/'native-corpus.json').write_text(json.dumps(metadata,sort_keys=True,indent=2)+'\n')

    def raw(self,raw,*,want=None,error=None,capacity=None,workspace=2061,export=True):
        if capacity is None:capacity=17+len(want or b'')
        code,out,work=self.module.invoke_raw(raw,output_capacity=capacity,workspace_capacity=workspace,
                                            output_fill=0xa5,workspace_fill=0x5a)
        COUNTS['native_calls']+=1
        if error is not None:
            self.assertEqual(code,error);self.assertEqual(out,b'\xa5'*capacity);self.assertEqual(work,b'\x5a'*workspace)
            if error==CAPACITY:COUNTS['capacity_refusal_cases']+=1
            value=b''
        else:
            self.assertEqual(code,len(want));value=out[:code];self.assertEqual(value,want)
            self.assertEqual(out[code:],b'\xa5'*(capacity-code))
            self.assertEqual(work[:2048],bytes(2048),'secret-bearing workspace must be wiped before success')
            self.assertEqual(work[2048:],b'\x5a'*(workspace-2048))
        if export:
            CORPUS.append({'input_hex':raw.hex(),'code':code,'output_hex':value.hex()})
        return value

    def call(self,op,a=b'',b=b'',c=b'',size=32,want=None):
        expected=reference(op,a,b,c,size)
        if want is not None:self.assertEqual(expected,want)
        COUNTS['standard_reference_cases' if op<=4 else 'original_binding_cases']+=1
        return self.raw(frame(op,a,b,c,size),want=expected)

    def test_rfc4231_and_rfc5869_vectors(self):
        vectors=[(b'\x0b'*20,b'Hi There','b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7'),
                 (b'Jefe',b'what do ya want for nothing?','5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843'),
                 (b'\xaa'*20,b'\xdd'*50,'773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe'),
                 (bytes(range(1,26)),b'\xcd'*50,'82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b')]
        for key,data,digest in vectors:self.call(1,key,data,want=bytes.fromhex(digest))
        vectors=[(bytes(range(13)),b'\x0b'*22,bytes(range(240,250)),42,
                  '077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5',
                  '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),
                 (bytes(range(96,176)),bytes(range(80)),bytes(range(176,256)),82,
                  '06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244',
                  'b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87'),
                 (b'',b'\x0b'*22,b'',42,'19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04',
                  '8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8')]
        for salt,ikm,info,size,prk,okm in vectors:
            derived=self.call(2,salt,ikm,want=bytes.fromhex(prk))
            self.call(3,derived,info,size=size,want=bytes.fromhex(okm))
            self.call(4,salt,ikm,info,size=size,want=bytes.fromhex(okm))

    def test_hmac_block_and_key_boundaries(self):
        sizes=[0,1,31,32,55,56,63,64,65,119,120,127,128,129,255,256,4095,4096]
        for key_size in [0,1,31,32,63,64,65,127,128,131,4096]:
            key=bytes((i*29+17)&255 for i in range(key_size))
            for size in sizes:
                data=bytes((i*73+11)&255 for i in range(size))
                self.call(1,key,data)
        large=bytes(range(256))*4096
        for key,data in [(large,b''),(large,b'abc'),(b'k'*65,large),(large,large)]:self.call(1,key,data)
        rng=random.Random(0x484d4143)
        for _ in range(180):self.call(1,rng.randbytes(rng.randrange(200)),rng.randbytes(rng.randrange(4097)))

    def test_extract_expand_and_maximum_counter(self):
        rng=random.Random(0x484b4446)
        for info_size in [0,1,31,32,55,56,63,64,65,128]:
            info=rng.randbytes(info_size)
            for size in [0,1,31,32,33,63,64,65,255,256,8160]:
                self.call(3,rng.randbytes(32),info,size=size)
        for _ in range(120):
            salt=rng.randbytes(rng.randrange(200));ikm=rng.randbytes(rng.randrange(4097))
            info=rng.randbytes(rng.randrange(200));size=rng.randrange(513)
            prk=self.call(2,salt,ikm)
            combined=self.call(4,salt,ikm,info,size=size)
            self.assertEqual(self.call(3,prk,info,size=size),combined)
        large=bytes(range(256))*4096
        self.call(4,large,large,b'info',size=32)
        self.call(3,b'p'*32,large,size=32)

    def test_original_key_domains_and_binding_frames(self):
        rng=random.Random(0x4f504b44)
        for size in [32,33,63,64,65,127,128,4095,4096]:
            token=bytes(rng.randrange(33,127) for _ in range(size))
            derived=self.call(5,token,size=128)
            self.assertEqual(len(set(derived[i:i+32] for i in range(0,128,32))),4)
            for op in (6,7,8):
                key=derived[(op-5)*32:(op-4)*32]
                for count in [1,31,32,55,56,63,64,65,127,128]:
                    self.call(op,key,rng.randbytes(count),size=64)
            for operation,ledger in [(b'a'*64,b'b'*64),(b'0'*64,b'f'*64),
                                     (rng.randbytes(32).hex().encode(),rng.randbytes(32).hex().encode())]:
                self.call(9,derived[:32],operation,ledger,size=32)
        for op in (6,8):self.call(op,b'k'*32,b'b'*(1<<20),size=64)
        for _ in range(80):
            key=rng.randbytes(32);data=rng.randbytes(rng.randrange(1,129))
            self.call(rng.choice([6,7,8]),key,data,size=64)

    def test_admission_and_capacity_preserve_all_buffers(self):
        valid=frame(1,b'key',b'message')
        for n in range(56):self.raw(valid[:n],error=INVALID)
        for at in range(8):
            altered=bytearray(valid);altered[at]^=1;self.raw(bytes(altered),error=INVALID)
        for op in [0,10,1<<63,(1<<64)-1]:self.raw(frame(op),error=INVALID)
        for at,value in [(16,1),(16,(1<<64)-1),(24,(1<<20)+1),(32,(1<<20)+1),
                         (40,(1<<20)+1),(48,8161),(24,(1<<64)-1),(48,(1<<64)-1)]:
            bad=bytearray(valid);struct.pack_into('<Q',bad,at,value)
            self.raw(bytes(bad),error=INVALID if at==16 else BOUND)
        for raw in [valid+b'x',valid[:-1],frame(1,b'',b'',b'x'),frame(2,size=0),
                    frame(3,b'p'*31),frame(3,b'p'*33),frame(3,b'p'*32,b'',b'extra'),
                    frame(5,b't'*31,size=128),frame(5,b't'*4097,size=128),
                    frame(5,b't'*32,b'extra',size=128),frame(5,b't'*32,size=32),
                    *[frame(5,b't'*31+bytes([value]),size=128) for value in [0,9,10,13,32,127,128,255]],
                    frame(6,b'k'*31,b'value',size=64),frame(6,b'k'*32,b'',size=64),
                    frame(7,b'k'*32,b'x'*129,size=64),frame(8,b'k'*32,b'x',b'extra',64),
                    frame(9,b'k'*32,b'a'*63,b'b'*64),frame(9,b'k'*32,b'A'*64,b'b'*64),
                    frame(9,b'k'*32,b'a'*64,b'z'*64)]:self.raw(raw,error=INVALID)
        for op,a,b,c,size in [(1,b'k',b'v',b'',32),(2,b'',b'',b'',32),
                               (3,b'p'*32,b'',b'',8160),(4,b'',b'',b'',1),
                               (5,b't'*32,b'',b'',128),(6,b'k'*32,b'v',b'',64),
                               (9,b'k'*32,b'a'*64,b'b'*64,32)]:
            raw=frame(op,a,b,c,size)
            self.raw(raw,error=CAPACITY,capacity=size-1,export=False)
            self.raw(raw,error=CAPACITY,capacity=size,workspace=2047,export=False)
            self.raw(raw,want=reference(op,a,b,c,size),capacity=size,workspace=2048)
            COUNTS['exact_capacity_reference_cases']+=1

    def test_standalone_filter_without_runtime_libraries(self):
        metadata=self.module.metadata
        executable=self.manifest.parent/metadata['standalone']['path']
        self.assertEqual(hashlib.sha256(executable.read_bytes()).hexdigest(),metadata['standalone']['sha256'])
        for op,a,b,c,size in [(1,b'k',b'v',b'',32),(4,b'salt',b'ikm',b'info',65),
                              (5,b't'*32,b'',b'',128),(6,b'k'*32,b'v',b'',64),
                              (9,b'k'*32,b'a'*64,b'b'*64,32)]:
            run=subprocess.run([str(executable)],input=frame(op,a,b,c,size),capture_output=True,
                               env={'PATH':'','LANG':'C'},timeout=10)
            self.assertEqual((run.returncode,run.stdout,run.stderr),(0,reference(op,a,b,c,size),b''))
            COUNTS['elf_requests']+=1

if __name__=='__main__':
    run=unittest.main(exit=False,verbosity=2)
    print(json.dumps({'status':'PASS' if run.result.wasSuccessful() else 'FAIL','counts':COUNTS},sort_keys=True))
    raise SystemExit(0 if run.result.wasSuccessful() else 1)
