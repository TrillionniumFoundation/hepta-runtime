#!/usr/bin/env python3
"""Small independent rejection controls; these do not execute an application."""
import ast
import copy
import gzip
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from evidence_common import decode,encoded,source_evidence
from buffer_store import Writer,Reader
from read_parent_capture import final_frame,same


class ParentDataControls(unittest.TestCase):
    def test_complete_binary_error_and_reserved_extent_rejections(self):
        message=b"absolute non-traversing file path required"
        error=b"HBRDS001"+struct.pack("<7Q",3,1,1,0,len(message),0,len(message))+message
        frame=b"HBPWR001"+struct.pack("<7Q",3,7,0,0,0,0,len(error))+error
        self.assertEqual(final_frame(frame),dict(ok=False,error=dict(type="ValueError",errno=None,
            filename=None,filename2=None,message=message.decode())))
        cases=[]
        for at in range(24,56):
            value=bytearray(frame);value[at]=1;cases.append(bytes(value))
        for at in(0,8,56,64,72,88,104,112,120):
            value=bytearray(frame);value[at]^=0x80;cases.append(bytes(value))
        cases.extend((frame[:-1],frame+b"x",frame[:63]))
        for value in cases:
            with self.subTest(sha256=hashlib.sha256(value).hexdigest()),self.assertRaises((ValueError,struct.error,UnicodeDecodeError)):
                final_frame(value)

    def test_whole_buffer_rejects_missing_changed_typed_and_extra_blocks(self):
        with tempfile.TemporaryDirectory()as temporary:
            root=Path(temporary)/"blocks";writer=Writer(root)
            value=bytes(range(256))*512+b"tail";row=writer.put(value)
            reader=Reader(root);self.assertEqual(reader.get(row),value);reader.finish()
            for field,bad in(("bytes",True),("bytes",len(value)-1),("sha256","0"*64),("blocks",row["blocks"][:-1])):
                changed=copy.deepcopy(row);changed[field]=bad
                with self.subTest(field=field),self.assertRaises(ValueError):Reader(root).get(changed)
            block=root/(row["blocks"][0]+".gz");original=block.read_bytes()
            block.write_bytes(gzip.compress(b"changed",mtime=0))
            with self.assertRaises(ValueError):Reader(root).get(row)
            block.write_bytes(original);block.unlink()
            with self.assertRaises(FileNotFoundError):Reader(root).get(row)
            block.write_bytes(original)
            extra=root/("f"*64+".gz");extra.write_bytes(gzip.compress(b"extra",mtime=0))
            reader=Reader(root);reader.get(row)
            with self.assertRaises(ValueError):reader.finish()

    def test_reader_import_and_execution_closure_is_data_only(self):
        modules=("read_parent_capture","read_parent_build","read_retry_capture","read_kernel","buffer_store","protocol","evidence_common")
        forbidden={"parent_capture","retry_capture","reference_worker","kernel_trace","carrier","hia_native_loader", "hia_native_build",
                   "ctypes","subprocess","importlib","multiprocessing"}
        names=set()
        for module in modules:
            tree=ast.parse((ROOT/"scripts"/(module+".py")).read_bytes())
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):names.update(item.name.split(".")[0]for item in node.names)
                elif isinstance(node,ast.ImportFrom):names.add((node.module or"").split(".")[0])
                elif isinstance(node,ast.Call)and isinstance(node.func,ast.Name):
                    self.assertNotIn(node.func.id,{"eval","exec","compile","__import__"})
        self.assertFalse(names&forbidden)
        for left,right in((True,1),(False,0),({"x":1},{"x":True})):
            with self.assertRaises(ValueError):same(left,right,"typed complete data")
        for raw in(b'{"x":1,"x":1}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):decode(raw)

    def test_source_and_original_domain_are_complete_and_fixed(self):
        identity=source_evidence(ROOT)
        self.assertGreater(identity["files"],40)
        domain=decode((ROOT/"DOMAIN.json").read_bytes())
        self.assertEqual((domain["case_count"],len(domain["cases"])),(256,256))
        self.assertEqual([item["id"]for item in domain["cases"]],list(range(256)))
        self.assertEqual(len({item["name"]for item in domain["cases"]}),256)
        self.assertEqual(sum(not(item["fault_plans"]or item["descriptor_actor"]or item["nofile"])for item in domain["cases"]),224)
        self.assertEqual(domain["retry_lanes"],["original-1","original-2","native-observed"])
        self.assertEqual([item["retry_phase"]for item in domain["retry_controls"]],[2,4])
        self.assertEqual(domain["limits"],dict(exchange_seconds=60,case_seconds=180,whole_capture_seconds=1800,cleanup_seconds=5,
            input_bytes=128<<20,output_bytes=128<<20,workspace_bytes=256<<20))
        self.assertEqual(hashlib.sha256((ROOT/"reference/binary_file.py").read_bytes()).hexdigest(),
            "c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12")


if __name__=="__main__":unittest.main(verbosity=2)
