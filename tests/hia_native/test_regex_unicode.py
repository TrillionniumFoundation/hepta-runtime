"""Native controls and real static-ELF parity for the Unicode dependency."""
from __future__ import annotations
import ctypes
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import random
import struct
import subprocess
import sys
import time
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_unicode_fixture import ROOT,UnicodeFixture,request,sha,NativeModule,NativeRejected
from regex_unicode_projection import merge_points

COUNTS={'direct_calls':0,'elf_queries':0,'receipt_refusals':0,'abi_refusals':0,
        'capacity_refusals':0,'capture_predicate_cases':0,'actual_processes':0}


def observe(fixture,wire):
    before=fixture.calls
    code,raw=fixture.invoke(wire)
    COUNTS['direct_calls']+=fixture.calls-before
    return code,raw


class UnicodeNative(unittest.TestCase):
    def test_01_immutable_data_factory_actual_elf_and_exact_buffers(self):
        path=module_manifest('regex_unicode_data')
        meta=json.loads(path.read_bytes())
        expected=(data('unicode-asset.bin')).read_bytes()
        work=json.loads((ROOT/'native/regex_unicode_data_composition.json').read_bytes())['workspace_bytes']
        with NativeModule(path,manifest_sha256=sha(path.read_bytes()))as module:
            self.assertEqual(module.invoke(b'HRGDAT01',output_capacity=len(expected),workspace_capacity=work),expected)
            COUNTS['direct_calls']+=1
            for output_capacity,workspace_capacity in [(len(expected)-1,work),(len(expected),work-1),(0,0)]:
                code,out,w=module.invoke_raw(b'HRGDAT01',output_capacity=output_capacity,
                                           workspace_capacity=workspace_capacity,output_fill=0x37,workspace_fill=0x49)
                self.assertEqual(code,0xFFFFFFFE);self.assertEqual(out,b'7'*output_capacity)
                self.assertEqual(w,b'I'*workspace_capacity)
                COUNTS['direct_calls']+=1;COUNTS['capacity_refusals']+=1
            for wire in [b'',b'HRGDAT0',b'HRGDAT00',b'HRGDAT01\x00']:
                code,out,w=module.invoke_raw(wire,output_capacity=31,workspace_capacity=47,output_fill=0x37,workspace_fill=0x49)
                self.assertEqual(code,0xFFFFFFFF);self.assertEqual(out,b'7'*31);self.assertEqual(w,b'I'*47)
                COUNTS['direct_calls']+=1;COUNTS['abi_refusals']+=1
        executable=path.parent/meta['standalone']['path']
        result=subprocess.run([str(executable)],input=b'HRGDAT01',stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},timeout=5)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,expected,b''))
        COUNTS['actual_processes']+=1

    def test_02_entire_corpus_in_one_actual_two_image_process(self):
        manifest=executable_manifest('unicode')
        metadata=json.loads(manifest.read_bytes())
        executable=manifest.parent/metadata['executable']
        self.assertEqual(sha(executable.read_bytes()),metadata['executable_sha256'])
        rows=json.loads((data('unicode/cases.json')).read_bytes())
        wires=[bytes.fromhex(row['native'])for row in rows]
        transport=b''.join(struct.pack('<Q',len(wire))+wire for wire in wires)
        result=subprocess.run([str(executable)],input=transport,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},timeout=15)
        self.assertEqual(result.returncode,0);self.assertEqual(result.stderr,b'')
        output=result.stdout;at=0;projected=[]
        for row in rows:
            self.assertLessEqual(at+16,len(output))
            code,length=struct.unpack_from('<QQ',output,at);at+=16
            raw=output[at:at+length];at+=length;self.assertEqual(len(raw),length)
            if row['kind']=='fold':
                self.assertEqual(code,0)
                count=struct.unpack_from('<Q',raw)[0]
                self.assertEqual(length,8+count*8)
                raw=merge_points(list(struct.unpack_from('<'+'Q'*count,raw,8))+[row['point']])
            elif code!=0:
                self.assertEqual(code,0xFFFFFFFD);code=1
            projected.append(f'{code:08x}:'.encode()+raw.hex().encode()+b'\n')
            COUNTS['elf_queries']+=1
        self.assertEqual(at,len(output))
        self.assertEqual(b''.join(projected),(data('unicode/native-output.txt')).read_bytes())
        evidence=artifact('unicode');evidence.mkdir(exist_ok=True)
        (evidence/'elf.stdin.bin').write_bytes(transport)
        (evidence/'elf.stdout.bin').write_bytes(output)
        (evidence/'elf.stderr').write_bytes(result.stderr)
        (evidence/'requests.hex').write_bytes(data('unicode/requests.hex').read_bytes())
        (evidence/'native-output.txt').write_bytes(b''.join(projected))
        COUNTS['actual_processes']+=1

    def test_03_capture_name_predicates_actual_rust_ranges(self):
        raw=bytes.fromhex((data('capture-predicates.txt')).read_bytes().splitlines()[-1].split(b':')[1].decode())
        words=struct.unpack('<'+'Q'*(len(raw)//8),raw);at=3;groups=[];points={0,1,127,128,0xD7FF,0xE000,0x10FFFF}
        for _ in range(2):
            count=words[at];at+=1
            rows=[tuple(words[at+i*2:at+i*2+2])for i in range(count)];groups.append(rows);at+=count*2
            for a,b in rows:
                for point in [a-1,a,a+1,b-1,b,b+1,(a+b)//2]:
                    if 0<=point<=0x10FFFF and not 0xD800<=point<=0xDFFF:points.add(point)
        rng=random.Random(0xA43856)
        for _ in range(4096):
            point=rng.randrange(0x110000)
            if not 0xD800<=point<=0xDFFF:points.add(point)
        with UnicodeFixture()as fixture:
            for point in sorted(points):
                code,answer=observe(fixture,request(5,struct.pack('<Q',point)))
                self.assertEqual(code,0)
                expected=tuple(int(any(a<=point<=b for a,b in rows))for rows in groups)
                self.assertEqual(struct.unpack('<QQ',answer),expected,point)
                COUNTS['capture_predicate_cases']+=1

    def test_04_query_abi_failures_leave_output_unchanged(self):
        wires=[b'',b'HRGUNI01',b'HRGUNI00'+bytes(24),request(0),request(6),request(1,b'Greek',b'X'),
               request(3,b''),request(3,b'D'),request(4,b''),request(4,bytes(9)),
               request(5,struct.pack('<Q',0xD800)),request(4,struct.pack('<Q',0x110000)),
               request(1,b'\xff'),request(1,b'\xc0\x80'),request(2,b'gc',b'\xed\xa0\x80')]
        valid=request(1,b'ASCII')
        for at,value in [(16,2**64-1),(24,2**64-1),(16,0),(24,1)]:
            wire=bytearray(valid);struct.pack_into('<Q',wire,at,value);wires.append(bytes(wire))
        with UnicodeFixture()as fixture:
            code,expected=observe(fixture,valid);self.assertEqual(code,0)
            for wire in wires:
                before=fixture.session._output.raw
                code,raw=observe(fixture,wire)
                self.assertEqual((code,raw),(0xFFFFFFFF,b''))
                self.assertEqual(fixture.session._output.raw,before)
                COUNTS['abi_refusals']+=1
            self.assertEqual(observe(fixture,valid),(0,expected))

    def test_05_capacity_refuses_before_output_publication(self):
        with UnicodeFixture(output_capacity=23)as fixture:
            before=fixture.session._output.raw[:fixture.session.output_capacity]
            self.assertEqual(observe(fixture,request(1,b'ASCII')),(0xFFFFFFFE,b''))
            self.assertEqual(fixture.session._output.raw[:fixture.session.output_capacity],before)
            COUNTS['capacity_refusals']+=1
            self.assertEqual(observe(fixture,request(4,struct.pack('<Q',0))), (0,bytes(8)))
        with UnicodeFixture(output_capacity=15)as fixture:
            before=fixture.session._output.raw[:fixture.session.output_capacity]
            self.assertEqual(observe(fixture,request(5,struct.pack('<Q',65))),(0xFFFFFFFE,b''))
            self.assertEqual(fixture.session._output.raw[:fixture.session.output_capacity],before)
            COUNTS['capacity_refusals']+=1
        with UnicodeFixture(output_capacity=24)as fixture:
            self.assertEqual(observe(fixture,request(1,b'ASCII')),(0,struct.pack('<QQQ',1,0,127)))

    def test_06_every_used_child_receipt_word(self):
        asset=(data('unicode-asset.bin')).read_bytes()
        for field in range(14):
            fixture=UnicodeFixture()
            with fixture:
                session=fixture.session;wire=request(1,b'ASCII')
                with self.assertRaises(NativeRejected)as caught:session.invoke(wire)
                self.assertEqual(caught.exception.code,0xFFFFFFE0)
                address=ctypes.addressof(session._workspace);footer=fixture.constants['WORKSPACE_BYTES']-256
                ctypes.memmove(address+fixture.constants['ASSET'],asset,len(asset))
                ctypes.memmove(address+footer+80,struct.pack('<QQQQ',len(asset),1,1,0),32)
                ptr=ctypes.c_uint64.from_address(address+footer+field*8);ptr.value^=1
                before=session._output.raw
                with self.assertRaises(NativeRejected)as caught:session.invoke(wire)
                self.assertEqual(caught.exception.code,0xFFFFFFFF)
                self.assertEqual(session._output.raw,before)
                self.assertEqual(ctypes.c_uint64.from_address(address+8).value,1)
                COUNTS['direct_calls']+=2;COUNTS['receipt_refusals']+=1

    def test_07_transport_truncation_and_oversize(self):
        path=executable('unicode')
        for payload in [b'\x01',struct.pack('<Q',8)+b'HRG',struct.pack('<Q',(8<<20)+1)]:
            result=subprocess.run([str(path)],input=payload,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env={'PATH':''},timeout=5)
            self.assertEqual(result.returncode,74);self.assertEqual(result.stdout,b'')
            COUNTS['actual_processes']+=1


if __name__=='__main__':
    start=time.monotonic()
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(UnicodeNative))
    report={'schema':'hepta.runtime.regex-unicode-native-controls.v1','status':'PASS' if result.wasSuccessful()else'FAIL',
            'groups':result.testsRun,'elapsed':time.monotonic()-start,**COUNTS,
            'test_source_sha256':sha(Path(__file__).read_bytes()),
            'native_source_sha256':{p.name:sha(p.read_bytes())for p in (ROOT/'native').glob('*.hepta')},
            'actual_original_report_sha256':sha((data('proof/unicode.json')).read_bytes()),
            'composition_manifest_sha256':sha((executable_manifest('unicode')).read_bytes()),
            'regex_compiler_closed':False,'runtime_python_required':False}
    folder=artifact('unicode');folder.mkdir(exist_ok=True)
    for name in ['elf.stdin.bin','elf.stdout.bin','elf.stderr']:
        path=folder/name
        if path.exists():report[name]={'bytes':path.stat().st_size,'sha256':sha(path.read_bytes())}
    (folder/'result.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
