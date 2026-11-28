"""Native admission for the exact privileged entropy composition.

These are actual HIA packer calls, independent of the Python build driver.
The embedded-ELF controls also rehash mutated manifests, so a stale file digest
alone cannot make a changed image/table/prefix pass the source-owned profile.
"""
from pathlib import Path
import copy
import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest

HERE=Path(__file__).resolve().parent
ROOT=Path(os.environ.get('HIA_SCOPE_OS_SOURCE_ROOT',HERE.parents[1]))
sys.path.insert(0,str(ROOT/'scripts'))
sys.path.insert(0,str(HERE))
from hia_native_loader import NativeModule
from scope_os_support import inspect_scope_os

COUNTS={'native_packer_calls':0,'successful_packings':0,'native_admission_refusals':0,
        'native_capacity_refusals':0,'rehashed_elf_refusals':0,'exact_imported_functions':0}


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


class ScopeOsPackerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path=Path(os.environ['HIA_SCOPE_OS_MANIFEST'])
        cls.meta=json.loads(cls.path.read_bytes())
        cls.artifact=inspect_scope_os(cls.path,ROOT)
        cls.profile=json.loads((ROOT/'native/scope_os_profile.json').read_bytes())
        cls.proof=json.loads((ROOT/'native/scope_os_packer_provenance.json').read_bytes())
        p=cls.path.parent/cls.meta['packer']['manifest']
        cls.packer=NativeModule(p,manifest_sha256=sha(p.read_bytes()))
        assert cls.packer.metadata['source_sha256']==cls.proof['source_sha256']
        cls.executable=(cls.path.parent/cls.meta['executable']).read_bytes()
        wire=bytearray(b'HIABND01'+struct.pack('<3Q',8,0,0));cls.rows=[]
        for index,row in enumerate(cls.profile['members']):
            p=cls.path.parent/cls.meta['members'][index]['manifest']
            metadata=json.loads(p.read_bytes());image=(p.parent/metadata['image']).read_bytes()
            assert sha(image)==row['image_sha256']
            cls.rows.append(len(wire))
            wire+=struct.pack('<8Q',len(image),row['input_capacity'],row['output_capacity'],row['workspace_capacity'],
                              row['flags'],row['call_mask'],0,0)
            wire+=bytes.fromhex(row['source_sha256']+row['image_sha256'])+image
        cls.wire=bytes(wire)
        assert len(wire)==cls.meta['frame_bytes'] and sha(wire)==cls.meta['frame_sha256']

    @classmethod
    def tearDownClass(cls):
        cls.packer.close()

    def call(self,wire,code=None,output=None,work=4096):
        capacity=len(self.executable) if output is None else output
        actual,buf,_=self.packer.invoke_raw(wire,output_capacity=capacity,workspace_capacity=work,output_fill=0xa5,workspace_fill=0x5a)
        COUNTS['native_packer_calls']+=1
        self.assertEqual(actual,len(self.executable) if code is None else code)
        if code is None:
            self.assertEqual(buf[:actual],self.executable)
            self.assertEqual(buf[actual:],b'\xa5'*(capacity-actual))
            COUNTS['successful_packings']+=1
        else:
            self.assertEqual(buf,b'\xa5'*capacity,'refused packer published partial executable bytes')
            COUNTS['native_capacity_refusals' if code==0xfffffffe else 'native_admission_refusals']+=1

    def altered(self,index,word,value):
        wire=bytearray(self.wire);struct.pack_into('<Q',wire,self.rows[index]+word*8,value);return bytes(wire)

    def test_exact_profile_reproducible_and_capacity_admission(self):
        self.call(self.wire)
        self.call(self.wire,output=len(self.executable)+19)
        self.call(self.wire,0xfffffffe,output=len(self.executable)-1)
        self.call(self.wire,0xfffffffe,work=4095)

    def test_closed_flags_slots_masks_and_all_declared_capacities(self):
        for value in (2,5,6,7,8,15,(1<<64)-1):
            self.call(self.altered(7,4,value),0xffffffff)
        self.call(self.altered(6,4,4),0xffffffff)
        for index,row in enumerate(self.profile['members']):
            for word,key in ((1,'input_capacity'),(2,'output_capacity'),(3,'workspace_capacity'),(5,'call_mask')):
                self.call(self.altered(index,word,row[key]+1),0xffffffff)
            self.call(self.altered(index,6,1),0xffffffff)
            self.call(self.altered(index,7,1),0xffffffff)

    def test_every_privileged_image_and_both_identity_tags_are_bound(self):
        for index,row in enumerate(self.profile['members']):
            at=self.rows[index]
            for tag in (64,96):
                wire=bytearray(self.wire);wire[at+tag]^=1
                self.call(bytes(wire),0xffffffff)
            wire=bytearray(self.wire);wire[at+128+row['image_bytes']//2]^=1
            self.call(bytes(wire),0xffffffff)
            wire[at+96:at+128]=hashlib.sha256(wire[at+128:at+128+row['image_bytes']]).digest()
            self.call(bytes(wire),0xffffffff)

    def test_header_framing_and_complete_image_spans(self):
        for size in (0,7,31,32,self.rows[7]+127,len(self.wire)-1):
            self.call(self.wire[:size],0xffffffff)
        self.call(self.wire+b'\0',0xffffffff)
        for offset,value in ((8,7),(8,9),(16,1),(24,1)):
            wire=bytearray(self.wire);struct.pack_into('<Q',wire,offset,value)
            self.call(bytes(wire),0xffffffff)

    def test_sha_ownership_is_exact_function_relocation(self):
        sys.path.insert(0,os.environ['HIA_HEPTA_DIR'])
        from hepta.hia_agent_assembly import assemble_program
        source=(ROOT/self.proof['sha_owner']).read_bytes()
        self.assertEqual(sha(source),self.proof['sha_owner_sha256'])
        original={f['name']:f for f in assemble_program(source).as_dict()['functions']}
        current={f['name']:f for f in assemble_program((ROOT/'native/composition_packer.hepta').read_bytes()).as_dict()['functions']}
        reverse={new:old for old,new in self.proof['sha_relocation'].items()}
        for name,destination in self.proof['sha_relocation'].items():
            function=copy.deepcopy(current[destination]);function['name']=name
            for block in function['blocks']:
                for op in block['ops']:
                    if op['op']=='call':op['attrs']['function']=reverse[op['attrs']['function']]
            self.assertEqual(function,original[name])
            self.assertEqual(sha(json.dumps(function,sort_keys=True,separators=(',',':')).encode()),
                             self.proof['sha_original_functions_sha256'][name])
            COUNTS['exact_imported_functions']+=1

    def test_rehashed_elf_mutations_cannot_change_fixed_authority(self):
        at=self.proof['metadata_offset']
        offsets=[176,self.proof['metadata_hole'],at+8,at+24,at+40]
        for index,row in enumerate(self.artifact['layout']):
            offsets.extend((at+64+index*128+32,at+64+index*128+48,at+64+index*128+56,row['image_offset']))
        with tempfile.TemporaryDirectory(prefix='hepta-owned-scope-layout-') as temporary:
            directory=Path(temporary)
            for offset in offsets:
                raw=bytearray(self.executable);raw[offset]^=1
                metadata=copy.deepcopy(self.meta);metadata['executable_sha256']=sha(raw)
                (directory/metadata['executable']).write_bytes(raw)
                (directory/'manifest.json').write_text(json.dumps(metadata))
                with self.assertRaises(AssertionError):inspect_scope_os(directory/'manifest.json',ROOT)
                COUNTS['rehashed_elf_refusals']+=1


if __name__=='__main__':
    outcome=unittest.main(exit=False,verbosity=2)
    expected={'native_packer_calls':103,'successful_packings':2,'native_admission_refusals':99,
              'native_capacity_refusals':2,'rehashed_elf_refusals':37,'exact_imported_functions':7}
    ok=(outcome.result.wasSuccessful() and outcome.result.testsRun==6 and not outcome.result.skipped
        and not outcome.result.expectedFailures and not outcome.result.unexpectedSuccesses and COUNTS==expected)
    proof={'schema':'hepta.runtime.scope-os-packer-test.v1','status':'PASS' if ok else 'FAIL',
           'tests_run':outcome.result.testsRun,'failures':len(outcome.result.failures),'errors':len(outcome.result.errors),
           'skipped':len(outcome.result.skipped),'counts':COUNTS,'expected_counts':expected,
           'source_sha256':sha((ROOT/'native/composition_packer.hepta').read_bytes()),
           'test_sha256':sha(Path(__file__).read_bytes()),'artifact':getattr(ScopeOsPackerTests,'artifact',None)}
    target=os.environ.get('HIA_SCOPE_OS_PACKER_RESULT')
    if target:
        path=Path(target);assert not path.exists();path.write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n')
    print(json.dumps(proof,sort_keys=True))
    raise SystemExit(0 if ok else 1)
