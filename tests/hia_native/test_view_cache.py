"""Actual native persistent ViewCache transitions; no semantic fallback."""
from __future__ import annotations
import argparse
import ast
import copy
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = Path(os.environ.get('HIA_REFERENCE_RUNTIME', ROOT))
sys.path.insert(0, str(REFERENCE / 'scripts'))
from hia_native_loader import NativeModule

LIMIT = 1 << 20
INVALID, CAPACITY, STATE = 0xffffffff, 0xfffffffe, 0xfffffffd
CALLS = {'native_image_calls': 0, 'native_elf_requests': 0, 'original_operations': 0,
         'lifecycle_operations': 0, 'poison_injections': 0, 'view_plan_adapters': 0,
         'frame_refusals': 0, 'capacity_refusals': 0, 'state_refusals': 0,
         'view_image_calls': 0, 'reference_rows': 0}
CORPUS = None
SID = 0

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def packet(op, key=b'', a=b'', b=b'', flags=0):
    return struct.pack('<8s5Q', b'HVCACH01', op, flags, len(key), len(a), len(b)) + key + a + b

def response(value=None):
    return struct.pack('<8s3Q', b'HVCAR001', int(value is not None), len(value or b''), 0) + (value or b'')

def words(raw):
    magic, op, flags, kn, an, bn = struct.unpack_from('<8s5Q', raw)
    assert magic == b'HVCACH01' and len(raw) == 48 + kn + an + bn
    a = 48 + kn
    b = a + an
    return op, flags, raw[48:a], raw[a:b], raw[b:]

class Model:
    """Independent standard-library expectation; original Rust is mandatory separately."""
    def __init__(self):
        self.entries = {}
        self.poisoned = False
        self.active = False

    def apply(self, raw):
        op, flags, key, a, b = words(raw)
        if op == 0:
            assert not self.active
            self.active = True
            self.poisoned = False
            self.entries.clear()
        elif op == 10:
            self.active = False
            self.poisoned = False
            self.entries.clear()
        elif op == 9:
            self.poisoned = True
        elif not self.poisoned and flags != 2:
            if op == 1:
                return response(self.entries.get(key))
            if op == 2:
                self.set(key, a)
            elif op == 3:
                self.entries.pop(key, None)
            elif op == 4:
                prefix = key.rstrip(b'/') + b'/'
                self.entries = {k: v for k, v in self.entries.items()
                                if k != key and not k.startswith(prefix)}
            elif op == 5:
                self.entries.clear()
            elif op == 6:
                self.set(key, a.replace(b'\r\n', b'\n'))
            elif op == 7:
                if self.entries.get(key) == a.replace(b'\r\n', b'\n'):
                    self.set(key, b.replace(b'\r\n', b'\n'))
                else:
                    self.entries.pop(key, None)
            elif op == 8:
                action, size = struct.unpack_from('<2Q', a, 24)
                text = struct.unpack_from('<Q', a, 16)[0]
                if action == 1:
                    self.set(key, a[128 + text:128 + text + size])
                elif action == 2:
                    self.entries.pop(key, None)
        return response()

    def set(self, key, value):
        if len(value) > LIMIT:
            self.entries.pop(key, None)
        else:
            self.entries[key] = value

def export_row(sid, wire, actual, domain):
    op = words(wire)[0]
    CALLS['reference_rows'] += 1
    key = ('lifecycle_operations' if op in (0, 10) else 'poison_injections' if op == 9
           else 'view_plan_adapters' if op == 8 else 'original_operations')
    CALLS[key] += 1
    if CORPUS:
        CORPUS['requests'].write(struct.pack('<II', sid, len(wire)) + wire)
        CORPUS['outputs'].write(struct.pack('<I', len(actual)) + actual)
        CORPUS['domains'].write(json.dumps({'ordinal': CALLS['reference_rows'], 'session': sid,
                    'operation': op, 'execution': domain, 'classification': key}, sort_keys=True).encode() + b'\n')

class Session:
    def __init__(self, module, *, workspace=1 << 18, output=LIMIT + 32):
        global SID
        SID += 1
        self.sid = SID
        self.native = module.session(workspace_capacity=workspace, output_capacity=output)
        self.model = Model()
        self.do(packet(0))

    def do(self, wire):
        expected = self.model.apply(wire)
        actual = self.native.invoke(wire)
        CALLS['native_image_calls'] += 1
        assert actual == expected, (words(wire)[:3], len(actual), len(expected))
        export_row(self.sid, wire, actual, 'native-image')
        return actual

    def refuse(self, wire, code):
        capacity = self.native.workspace_capacity
        before = self.native._workspace.raw[:capacity]
        ctypes.memset(self.native._output, 0xa5, self.native.output_capacity)
        actual, out, work = self.native.invoke_raw(wire)
        CALLS['native_image_calls'] += 1
        assert actual == code, (actual, code)
        assert work == before and out == b'\xa5' * len(out)
        CALLS[{INVALID: 'frame_refusals', CAPACITY: 'capacity_refusals', STATE: 'state_refusals'}[code]] += 1

    def inspect(self):
        raw = self.native._workspace.raw[:self.native.workspace_capacity]
        assert raw[:8] == b'HVCSTA01'
        version, used, count, poison, *reserved = struct.unpack_from('<7Q', raw, 8)
        assert version == 1 and not any(reserved) and poison == self.model.poisoned
        entries = {}
        at = 64
        while at < used:
            kn, vn = struct.unpack_from('<2Q', raw, at)
            at += 16
            key, value = raw[at:at + kn], raw[at + kn:at + kn + vn]
            assert key not in entries and vn <= LIMIT
            entries[key] = value
            at += kn + vn
        assert at == used and count == len(entries) and entries == self.model.entries
        assert not any(raw[used:]), 'retired or unowned payload retained in private tail'

    def close(self):
        if self.model.active:
            self.do(packet(10))
            assert not any(self.native._workspace.raw[:self.native.workspace_capacity])
        self.native.close()

class ViewCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        path = Path(os.environ['HIA_CACHE_MANIFEST'])
        cls.manifest = json.loads(path.read_bytes())
        assert cls.manifest['source_sha256'] == sha((ROOT / 'native/view_cache.hepta').read_bytes())
        cls.module = NativeModule(path, manifest_sha256=sha(path.read_bytes()))
        cls.source_closure()
        cls.image_binding = cls.composition_closure()

    @classmethod
    def tearDownClass(cls):
        cls.module.close()

    @classmethod
    def source_closure(cls):
        hepta = Path(os.environ['HIA_HEPTA_DIR'])
        sys.path.insert(0, str(hepta))
        from hepta.hia_agent_assembly import assemble_program
        proof = json.loads((ROOT / 'native/view_cache_composition.json').read_bytes())
        raw = (ROOT / 'native/view_cache.hepta').read_bytes()
        assert proof['source_sha256'] == sha(raw)
        actual = {f['name']: f for f in assemble_program(raw).as_dict()['functions']}
        for item in proof['imports']:
            source = (REFERENCE / item['path']).read_bytes()
            assert sha(source) == item['sha256']
            original = {f['name']: f for f in assemble_program(source).as_dict()['functions']}
            reverse = {new: old for old, new in item['function_relocation'].items()}
            for old, new in item['function_relocation'].items():
                fn = copy.deepcopy(actual[new])
                fn['name'] = old
                for block in fn['blocks']:
                    for ins in block['ops']:
                        if ins['op'] == 'call':
                            ins['attrs']['function'] = reverse[ins['attrs']['function']]
                assert fn == original[old]
        for relative, pin in proof['original_sources'].items():
            source = (REFERENCE / relative).read_bytes()
            assert sha(source) == pin['sha256']
            assert hashlib.sha1(b'blob ' + str(len(source)).encode() + b'\0' + source).hexdigest() == pin['blob']
        assert sha((REFERENCE / 'native/view_render.hepta').read_bytes()) == proof['view_plan_source_sha256']
        sys.path.insert(0,str(Path(__file__).parent))
        from view_cache_oracle_source import oracle_source
        assert (ROOT/'tests/hia_native/oracle_view_cache.rs').read_text() == oracle_source(REFERENCE)

    @classmethod
    def composition_closure(cls):
        from hia_native_scope_qualification import embedded_images
        path=Path(os.environ['HIA_CACHE_ELF_MANIFEST'])
        raw=path.read_bytes();meta=json.loads(raw)
        proof=json.loads((ROOT/'native/view_cache_composition.json').read_bytes())
        assert meta['compiler_commit']==cls.manifest['compiler_commit']
        assert meta['compiler_sha256']==cls.manifest['compiler_sha256']
        assert meta['packer']['source_sha256']==proof['packer_source_sha256']
        expected=[{'id':0,'name':'view-cache-hex-fixture','flags':1,'call_mask':2,
                   'input_capacity':8<<20,'output_capacity':8<<20,'workspace_capacity':16<<20,
                   'source_sha256':proof['transport_source_sha256']},
                  {'id':1,'name':'view-cache','flags':0,'call_mask':0,
                   'input_capacity':8<<20,'output_capacity':LIMIT+32,'workspace_capacity':8<<20,
                   'source_sha256':proof['source_sha256']}]
        assert meta['profile']==expected and len(meta['members'])==2
        images=[]
        for i,row in enumerate(meta['members']):
            assert row['manifest']==f'module_{i:02d}.json'
            child_path=path.parent/row['manifest'];child_raw=child_path.read_bytes()
            assert sha(child_raw)==row['manifest_sha256']
            child=json.loads(child_raw)
            assert child['source_sha256']==expected[i]['source_sha256']==row['source_sha256']
            assert child['compiler_commit']==meta['compiler_commit']
            assert child['compiler_sha256']==meta['compiler_sha256']
            admitted=NativeModule(child_path,manifest_sha256=sha(child_raw));admitted.close()
            image=(child_path.parent/child['image']).read_bytes()
            assert sha(image)==child['image_sha256']==row['image_sha256']
            images.append(image)
        assert sha(images[1])==cls.manifest['image_sha256']
        elf=(path.parent/meta['executable']).read_bytes()
        assert sha(elf)==meta['executable_sha256']
        binding=embedded_images(elf,expected,images)
        return {'manifest_sha256':sha(raw),'executable_sha256':sha(elf),'images':list(map(sha,images)),
                'source_profile':expected,'embedded_table':binding}

    def test_01_raw_and_once_normalization(self):
        s = Session(self.module)
        keys = [b'', b'/', b'key\0tail', '汉字/é'.encode(), 'e\u0301'.encode(), b'host:22/path']
        values = [b'', b'\n', b'\r', b'\r\n', b'\r\r\n', b'\r\n\r', b'one\r\ntwo\n', '🙂\r\n'.encode()]
        for key in keys:
            s.do(packet(1, key))
            for value in values:
                s.do(packet(2, key, value))
                s.do(packet(1, key))
                s.do(packet(7, key, value, b'raw-cache-before-may-not-match', flags=1))
                s.do(packet(1, key))
                s.do(packet(6, key, value, flags=1))
                s.do(packet(1, key))
                s.do(packet(7, key, value, b'new\r\n\r\r\n', flags=1))
                s.do(packet(1, key))
                s.do(packet(7, key, b'stale', b'should-not-cache', flags=1))
                s.do(packet(1, key))
        s.inspect()
        s.close()

    def test_02_subtree_and_owned_clear(self):
        s = Session(self.module)
        keys = [b'', b'/', b'//', b'///x', b'old', b'old/', b'old//', b'old/a', b'old2',
                b'old2/a', b'old\\x', b'/old', b'/old/a', b'host:22/old/a',
                'old∕a'.encode(), '目录/子'.encode(), '目录2/子'.encode()]
        for target in keys:
            s.do(packet(5))
            for key in keys:
                s.do(packet(2, key, key))
            s.do(packet(4, target))
            for key in keys:
                s.do(packet(1, key))
            s.inspect()
        other = Session(self.module)
        other.do(packet(2, b'old', b'other-session'))
        s.do(packet(5))
        other.do(packet(1, b'old'))
        other.inspect()
        other.close()
        s.close()

    def test_03_context_and_mutex_poison(self):
        s = Session(self.module)
        s.do(packet(2, b'x', b'raw\r\n'))
        for op, a, b in [(1,b'',b''),(2,b'ignored',b''),(3,b'',b''),(4,b'',b''),
                         (6,b'ignored',b''),(7,b'raw\r\n',b'ignored')]:
            s.do(packet(op, b'x', a, b, flags=2))
            s.do(packet(1, b'x'))
        s.do(packet(9))
        for flags in (0, 1, 2):
            for op, a, b in [(1,b'',b''),(2,b'ignored',b''),(3,b'',b''),(4,b'',b'')]:
                s.do(packet(op,b'x',a,b,flags=flags))
        s.do(packet(5))
        s.do(packet(6,b'x',b'ignored',flags=1))
        s.do(packet(7,b'x',b'raw\r\n',b'ignored',flags=1))
        s.inspect()
        s.close()

    def test_04_inclusive_entry_limit_no_lru(self):
        s = Session(self.module, workspace=8 << 20)
        for i, value in enumerate([b'x' * (LIMIT - 1), b'\xc3\xa9' * (LIMIT // 2),
                                   b'\r\n' * LIMIT, b'\r\r\n' * (LIMIT // 2)]):
            key = str(i).encode()
            s.do(packet(6,key,value,flags=1))
            s.do(packet(1,key))
        s.inspect()
        for i in range(4):
            s.do(packet(1,str(i).encode()))
        for op, value in [(2,b'x'*(LIMIT+1)),(6,b'\r\n'*LIMIT+b'x')]:
            s.do(packet(op,b'0',value,flags=int(op==6)))
            s.do(packet(1,b'0'))
            s.do(packet(1,b'1'))
            s.do(packet(2,b'0',b'small'))
        s.do(packet(7,b'0',b'small',b'\r\n'*LIMIT+b'x',flags=1))
        s.do(packet(1,b'0'))
        s.do(packet(5))
        for i in range(1500):
            key = ('file/%04d' % i).encode()
            s.do(packet(2,key,bytes([65+(i%26)])))
        for i in (0,1,1023,1024,1499):
            s.do(packet(1,('file/%04d'%i).encode()))
        s.inspect()
        s.close()

    def test_05_random_state_sequences(self):
        rng = random.Random(0xCACE01)
        s = Session(self.module)
        keys = [b'', b'/', b'old', b'old/', b'old/x', b'old2'] + [f'k/{i}'.encode() for i in range(40)]
        values = [b'', b'a', b'\r\n', b'\r\r\n', b'a\nb', b'a\r\nb', '值🙂'.encode()]
        for i in range(3000):
            key = rng.choice(keys)
            op = rng.choice([1,2,2,3,4,5,6,7,7])
            flags = rng.choice([1,1,2]) if op in (6,7) else rng.choice([0,0,1,2])
            a = rng.choice(values) if op in (2,6,7) else b''
            if op == 7 and key in s.model.entries and rng.randrange(2):
                a = s.model.entries[key].replace(b'\n',b'\r\n')
            b = rng.choice(values) if op == 7 else b''
            if op == 5:
                flags, key = 0, b''
            s.do(packet(op,key,a,b,flags))
            if i % 17 == 0:
                for k in keys:
                    s.do(packet(1,k))
                s.inspect()
        s.close()

    def test_06_refusal_atomicity_and_growth(self):
        s = Session(self.module,workspace=128,output=128)
        s.do(packet(2,b'x',b'payload'))
        for wire in [b'',b'HVCACH01',packet(1,b'x')+b'x',packet(11),packet(6,b'x',b'a'),
                     packet(0,b'x'),packet(1,b'\xff'),packet(2,b'x',b'\xc0\x80'),
                     packet(7,b'x',b'payload',b'\xed\xa0\x80',1),packet(2,b'x',b'a',flags=3)]:
            s.refuse(wire,INVALID)
        s.refuse(packet(0),STATE)
        s.refuse(packet(2,b'x',b'z'*48),CAPACITY)
        s.refuse(packet(2,b'y',b'z'*32),CAPACITY)
        s.do(packet(1,b'x'))
        # A replacement is admitted against final size, not transient old+new size.
        s.do(packet(2,b'x',b'z'*47))
        s.inspect()
        s.do(packet(3,b'x'))
        s.do(packet(2,b'y',b'z'*47))
        s.inspect()
        # Relocation demonstrates offsets only; actual allocation/growth is external.
        grown = self.module.session(workspace_capacity=512,output_capacity=128)
        ctypes.memmove(grown._workspace,s.native._workspace,128)
        old = s.native
        s.native = grown
        old.close()
        s.do(packet(1,b'y'))
        s.do(packet(2,b'x',b'newly-available-capacity'))
        s.inspect()
        saved = s.native._workspace.raw[:512]
        for offset, value in [(0,0),(8,2),(16,513),(24,999),(32,2),(40,1),(64,2**64-1),(72,LIMIT+1)]:
            ctypes.memmove(s.native._workspace,saved,512)
            ctypes.memmove(ctypes.addressof(s.native._workspace)+offset,struct.pack('<Q',value),8)
            s.refuse(packet(1,b'y'),STATE)
        ctypes.memmove(s.native._workspace,saved,512)
        s.close()
        for ocap,wcap in [(31,64),(32,63),(0,0)]:
            code,out,work=self.module.invoke_raw(packet(0),output_capacity=ocap,workspace_capacity=wcap,
                                                  output_fill=0xa5,workspace_fill=0)
            CALLS['native_image_calls']+=1
            CALLS['capacity_refusals']+=1
            self.assertEqual((code,out,work),(CAPACITY,b'\xa5'*ocap,bytes(wcap)))
        s=Session(self.module,workspace=256,output=32)
        s.do(packet(2,b'x',b'nonempty'))
        s.refuse(packet(1,b'x'),CAPACITY)
        s.inspect()
        s.close()

    def test_07_view_plan_application(self):
        path=Path(os.environ['HIA_VIEW_MANIFEST'])
        meta=json.loads(path.read_bytes())
        self.assertEqual(meta['source_sha256'],sha((REFERENCE/'native/view_render.hepta').read_bytes()))
        self.__class__.view_binding={key:meta[key] for key in
            ['compiler_commit','compiler_sha256','source_sha256','image_sha256']}
        self.__class__.view_binding['manifest_sha256']=sha(path.read_bytes())
        view=NativeModule(path,manifest_sha256=sha(path.read_bytes()))
        s=Session(self.module,workspace=4<<20)
        def render(body, previous=b'', flags=8, op=1):
            wire=struct.pack('<8s11Q',b'HVIEW001',op,flags,0,0,0,len(body),len(previous),0,len(body),0,0)+body+previous
            result=view.invoke(wire,output_capacity=3<<20,workspace_capacity=32<<20)
            CALLS['view_image_calls']+=1
            return result
        for body in [b'',b'a\r\r\n',b'hello\r\nworld',b'x'*(LIMIT+1)]:
            previous=s.model.entries.get(b'file',b'')
            flags=8 | (16 if b'file' in s.model.entries else 0)
            prepared=render(body,previous,flags)
            s.do(packet(8,b'file',prepared))
            s.do(packet(1,b'file'))
            # Render sees the pre-update snapshot, as required by the view contract.
            rendered=render(body,previous,flags,2)
            self.assertEqual(rendered[24:40],prepared[24:40])
        s.do(packet(8,b'file',render(b'no-context',flags=0)))
        s.inspect()
        # A real prepare plan may mutate cache before an unrelated later capacity refusal.
        prior=s.model.entries.get(b'file',b'')
        prepared=render(b'cached-before-render-refusal',prior)
        s.do(packet(8,b'file',prepared))
        wire=struct.pack('<8s11Q',b'HVIEW001',2,8,0,0,0,1,0,0,1,0,0)+b'x'
        code,_,_=view.invoke_raw(wire,output_capacity=0,workspace_capacity=32<<20)
        CALLS['view_image_calls']+=1
        self.assertEqual(code,CAPACITY)
        s.do(packet(1,b'file'))
        # This is an actual original semantic result-size refusal, with a
        # cacheable body; the prior cache update must remain committed.
        body=b'\n'*900000
        prepared=render(body,flags=12)
        s.do(packet(8,b'file',prepared))
        refused=render(body,flags=12,op=2)
        self.assertEqual(struct.unpack_from('<Q',refused,8)[0],1)
        self.assertEqual(struct.unpack_from('<Q',refused,88)[0],7)
        self.assertEqual(struct.unpack_from('<Q',refused,24)[0],1)
        s.do(packet(1,b'file'))
        s.do(packet(8,b'file',refused))
        s.do(packet(1,b'file'))
        for offset,value in [(0,0),(24,3),(32,2**64-1),(80,4),(88,8),(112,1),(120,1)]:
            changed=bytearray(prepared);struct.pack_into('<Q',changed,offset,value)
            s.refuse(packet(8,b'file',bytes(changed)),INVALID)
        s.close()
        view.close()

    def test_08_real_persistent_elf(self):
        global SID
        path=Path(os.environ['HIA_CACHE_ELF_MANIFEST'])
        meta=json.loads(path.read_bytes())
        elf=path.parent/'native-local-read.elf'
        self.assertEqual(sha(elf.read_bytes()),meta['executable_sha256'])
        self.assertEqual(meta['profile'][1]['source_sha256'],sha((ROOT/'native/view_cache.hepta').read_bytes()))
        sequence=[packet(0),packet(1,b'x'),packet(6,b'x',b'a\r\r\n',flags=1),packet(1,b'x'),
                  packet(7,b'x',b'a\r\r\n',b'b\r\n',flags=1),packet(1,b'x')]
        for i in range(48):
            sequence += [packet(2,('dir/%d'%i).encode(),('value%d'%i).encode())]
        sequence += [packet(4,b'dir//'),packet(1,b'dir/0'),packet(1,b'x'),packet(9),
                     packet(2,b'x',b'ignored'),packet(1,b'x'),packet(5),packet(10),packet(0),
                     packet(2,b'fresh',b''),packet(1,b'fresh'),packet(10)]
        result=subprocess.run([str(elf),'--local-read-profile','/cache-fixture'],input=b''.join(v.hex().encode()+b'\n' for v in sequence),
                              stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,env={'PATH':'','LANG':'C'})
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        lines=result.stdout.splitlines()
        self.assertEqual(len(lines),len(sequence))
        model=Model();SID+=1
        for wire,line in zip(sequence,lines,strict=True):
            code,data=line.split(b':',1)
            actual=bytes.fromhex(data.decode())
            self.assertEqual(int(code,16),len(actual))
            self.assertEqual(actual,model.apply(wire))
            CALLS['native_elf_requests']+=1
            export_row(SID,wire,actual,'native-elf')

def main():
    global CORPUS
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--result',type=Path)
    args,unittest_args=parser.parse_known_args()
    destination=os.environ.get('HIA_CACHE_CORPUS_DIR')
    if destination:
        directory=Path(destination);directory.mkdir(exist_ok=False,parents=True)
        CORPUS={'requests':gzip.open(directory/'requests.bin.gz','wb'),
                'outputs':gzip.open(directory/'native-output.bin.gz','wb'),
                'domains':gzip.open(directory/'domains.jsonl.gz','wb')}
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ViewCacheTests))
    if CORPUS:
        for f in CORPUS.values(): f.close()
    report={'schema':'hepta.runtime.view-cache-test.v1','status':'PASS' if result.wasSuccessful() else 'FAIL',
            'test_groups':result.testsRun,'counts':CALLS,'source_sha256':sha((ROOT/'native/view_cache.hepta').read_bytes()),
            'test_sha256':sha(Path(__file__).read_bytes()),
            'composition_sha256':sha((ROOT/'native/view_cache_composition.json').read_bytes())}
    if hasattr(ViewCacheTests,'manifest'):
        report['native_module']={key:ViewCacheTests.manifest[key] for key in
            ['compiler_commit','compiler_sha256','source_sha256','image_sha256']}
    if hasattr(ViewCacheTests,'image_binding'):
        report['composition']=ViewCacheTests.image_binding
    if hasattr(ViewCacheTests,'view_binding'):
        report['view_module']=ViewCacheTests.view_binding
    if destination:
        files={}
        for name in ['requests.bin.gz','native-output.bin.gz','domains.jsonl.gz']:
            raw=(directory/name).read_bytes();plain=gzip.decompress(raw)
            files[name]={'gzip_sha256':sha(raw),'gzip_bytes':len(raw),'raw_sha256':sha(plain),'raw_bytes':len(plain)}
        report['files']=files
        report['oracle_sha256']=sha((ROOT/'tests/hia_native/oracle_view_cache.rs').read_bytes())
        (directory/'native-corpus.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    if args.result:
        args.result.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))
    return 0 if result.wasSuccessful() else 1

if __name__=='__main__':
    raise SystemExit(main())
