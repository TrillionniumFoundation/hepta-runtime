"""Meaningful negative evidence controls; no application/compiler execution."""
from pathlib import Path
import copy
import json
import shutil
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from common import PACK,WORD,UNBASE,SHA,inputs,source_evidence,pin
from read_capture import parent_request,publication,INVALID,GROW,records,read_controls


class ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _,data=inputs();cls.data=data
        cls.ready=[(UNBASE(s['request']),UNBASE(s['actual_result']))for row in data['plan_cases']for s in row['stages']if s['eligible']]
        fixture=ROOT/'inputs/reader-controls-original'
        origin=json.loads((fixture/'ORIGIN.json').read_bytes())
        for name,identity in origin['actual_files'].items():
            if pin(fixture/name)!=identity:raise AssertionError('actual retained control fixture changed')
        cls.control_rows=json.loads((fixture/'RESULTS.json').read_bytes())
        cls.control_native,cls.control_summary=records(fixture)

    def test_01_all_nineteen_actual_ready_packets_match_typed_and_root_bytes(self):
        self.assertEqual(len(self.ready),19)
        for request,ready in self.ready:
            typed_size=WORD(request,24);typed=request[48:48+typed_size];feedback=request[48+typed_size:]
            fields=[];at=256
            for offset in range(88,152,8):
                size=WORD(typed,offset);fields.append(typed[at:at+size]);at+=size
            expected=[feedback[32:],fields[1],fields[3],fields[2]]
            packet=parent_request(ready)
            self.assertEqual(packet[:96],b'HBPWQ001'+PACK(1,0,1,*map(len,expected),1,0,0,sum(map(len,expected))))
            self.assertEqual(packet[96:],b''.join(expected))

    def test_02_every_ready_header_semantic_is_required(self):
        ready=self.ready[0][1]
        for offset,value in [(0,0),(8,1),(16,2),(24,1),(32,2),(40,0),(48,1),(56,(1<<64)-1)]:
            changed=bytearray(ready);struct.pack_into('<Q',changed,offset,value)
            with self.subTest(offset=offset),self.assertRaises(ValueError):parent_request(bytes(changed))

    def test_03_nonstring_missing_extra_duplicate_fields_are_refused(self):
        template=json.loads(self.ready[0][1][64:])
        payloads=[]
        for field in ('root','path','expected_version','data_base64'):
            changed=dict(template);changed[field]=None;payloads.append(json.dumps(changed).encode())
            changed=dict(template);del changed[field];payloads.append(json.dumps(changed).encode())
        changed=dict(template);changed['fd']=4;payloads.append(json.dumps(changed).encode())
        payloads.append(self.ready[0][1][64:-1]+b',"op":"write"}')
        for payload in payloads:
            ready=b'HBPLR001'+PACK(3,3,0,3,1,0,len(payload))+payload
            with self.assertRaises(ValueError):parent_request(ready)

    def test_04_empty_version_is_present_and_raw_nul_utf8_are_kept(self):
        value=dict(op='write',root='//目录',path='//目录/a\0b',expected_version='',data_base64='not!base64\0')
        payload=json.dumps(value,separators=(',',':'),ensure_ascii=False).encode()
        packet=parent_request(b'HBPLR001'+PACK(3,3,0,3,1,0,len(payload))+payload)
        self.assertEqual(WORD(packet,48),0);self.assertEqual(WORD(packet,64),1)
        self.assertEqual(packet[96:],''.join(value[k]for k in ('root','path','expected_version','data_base64')).encode())

    def test_05_refusal_may_not_mutate_any_owned_byte(self):
        before=bytes(256);out=b'\xa5'*64
        self.assertEqual(publication(8,INVALID,out,before,before),b'')
        with self.assertRaises(ValueError):publication(8,INVALID,b'\0'+out[1:],before,before)
        with self.assertRaises(ValueError):publication(8,INVALID,out,before,b'\1'+before[1:])

    def test_06_growth_preserves_workspace_tail_and_increases_capacity(self):
        before=bytes(256);frame=b'HGRWS002'+PACK(1,512,0)+b'\xa5'*32
        self.assertEqual(publication(8,GROW,frame,before,before),frame[:32])
        for out,after in [(frame[:-1]+b'\0',before),(frame,b'\1'+before[1:]),(b'HGRWS002'+PACK(1,256,0)+b'\xa5'*32,before)]:
            with self.assertRaises(ValueError):publication(8,GROW,out,before,after)

    def test_07_complete_source_detects_added_and_modified_application_inputs(self):
        original=source_evidence()
        with tempfile.TemporaryDirectory(prefix='binary-adapter-source-control-')as path:
            copied=Path(path)/'source';shutil.copytree(ROOT,copied)
            self.assertEqual(source_evidence(copied),original)
            target=copied/'native/binary_write_adapter.hepta';raw=target.read_bytes();target.write_bytes(raw+b'\n')
            with self.assertRaises(ValueError):source_evidence(copied)
            target.write_bytes(raw);(copied/'undeclared.hepta').write_bytes(b'')
            with self.assertRaises(ValueError):source_evidence(copied)

    def test_08_all_retained_actual_controls_pass_strict_independent_contracts(self):
        used,counts=read_controls(self.control_rows,self.control_native,self.data)
        self.assertEqual(used,set(self.control_native))
        self.assertEqual(counts,dict(private_refusal_controls=50,actual_child_mismatch_controls=2,lifecycle_controls=1,control_cases=53))
        self.assertEqual(self.control_summary['calls'],85)

    def test_09_every_named_refusal_rejects_a_different_valid_refusal_packet(self):
        # Model an integrity-checked journal carrying another actual refusal.
        # Hash integrity alone cannot establish which named condition was run.
        alternatives={row['name']:self.control_native[row['calls'][0]][1]
            for row in self.control_rows if row['name']in('magic','command-zero')}
        for row in self.control_rows:
            if row['kind']!='private-invalid':continue
            native=copy.deepcopy(self.control_native);call=row['calls'][0]
            metadata,wire,frame=native[call]
            replacement=alternatives['command-zero'if row['name']=='magic'else'magic']
            self.assertNotEqual(wire,replacement)
            metadata.update(input_bytes=len(replacement),input_sha256=SHA(replacement))
            native[call]=(metadata,replacement,frame)
            with self.subTest(name=row['name']),self.assertRaises(ValueError):
                read_controls(self.control_rows,native,self.data)

    def test_10_mutable_return_capacity_workspace_and_identity_are_not_authority(self):
        for field,value in [('output_capacity',65),('workspace_capacity',257),
            ('before_sha256','0'*64),('case_id',0),('label','command-zero')]:
            native=copy.deepcopy(self.control_native)
            row=next(row for row in self.control_rows if row['name']=='magic')
            native[row['calls'][0]][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):read_controls(self.control_rows,native,self.data)
        rows=copy.deepcopy(self.control_rows);native=copy.deepcopy(self.control_native)
        rows[0]['expected_code']=INVALID;native[rows[0]['calls'][0]][0]['return_code']=INVALID
        with self.assertRaises(ValueError):read_controls(rows,native,self.data)

    def test_11_name_kind_and_actual_child_class_cannot_be_relabelled(self):
        for name,key,value in [('magic','kind','lifecycle'),
            ('whole-json-mismatch','expected_detail',1),('actual-planner-utf8-rejection','expected_detail',2)]:
            rows=copy.deepcopy(self.control_rows)
            next(row for row in rows if row['name']==name)[key]=value
            with self.subTest(name=name),self.assertRaises(ValueError):read_controls(rows,self.control_native,self.data)

    def test_12_all_lifecycle_event_permutations_fail(self):
        for index in range(15):
            rows=copy.deepcopy(self.control_rows);events=rows[-1]['events']
            events[index],events[index+1]=events[index+1],events[index]
            with self.subTest(index=index),self.assertRaises(ValueError):read_controls(rows,self.control_native,self.data)

    def test_13_stale_busy_and_duplicate_requests_require_their_exact_sequence(self):
        events=self.control_rows[-1]['events']
        for event in events:
            if not event.get('expected_invalid'):continue
            native=copy.deepcopy(self.control_native);call=event['calls'][0]
            metadata,wire,frame=native[call]
            changed=bytearray(wire);struct.pack_into('<Q',changed,16,WORD(wire,16)+37)
            metadata['input_sha256']=SHA(changed)
            native[call]=(metadata,bytes(changed),frame)
            with self.subTest(name=event['name']),self.assertRaises(ValueError):
                read_controls(self.control_rows,native,self.data)

    def test_14_lifecycle_must_retain_context_and_exact_actual_growth(self):
        event=next(e for e in self.control_rows[-1]['events']if e['name']=='valid-resume-after-output-shrink')
        for field,value in [('context',98765),('output_capacity',65),('workspace_capacity',781)]:
            native=copy.deepcopy(self.control_native);native[event['calls'][0]][0][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):read_controls(self.control_rows,native,self.data)
        rows=copy.deepcopy(self.control_rows)
        event=next(e for e in rows[-1]['events']if e['name']=='valid-resume-after-output-shrink')
        event['calls']=event['calls'][1:]
        with self.assertRaises(ValueError):read_controls(rows,self.control_native,self.data)


if __name__=='__main__':unittest.main()
