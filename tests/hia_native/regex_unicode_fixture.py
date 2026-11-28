"""Explicit test-only child-call fixture; every semantic operation executes HIA."""
from __future__ import annotations
import ctypes
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import struct
import sys

ROOT=Path(__file__).resolve().parents[2]
COMMON=ROOT
sys.path.insert(0,str(COMMON/'scripts'))
from hia_native_loader import NativeModule, NativeRejected, NativeCapacityError


def sha(raw):return hashlib.sha256(raw).hexdigest()


def request(operation,left=b'',right=b''):
    return b'HRGUNI01'+struct.pack('<QQQ',operation,len(left),len(right))+left+right


class UnicodeFixture:
    def __init__(self,output_capacity=65536):
        self.query_path=module_manifest('regex_unicode')
        self.data_path=module_manifest('regex_unicode_data')
        self.query=NativeModule(self.query_path,manifest_sha256=sha(self.query_path.read_bytes()))
        self.data=NativeModule(self.data_path,manifest_sha256=sha(self.data_path.read_bytes()))
        self.constants=json.loads((ROOT/'native/regex_unicode_composition.json').read_bytes())['constants']
        self.data_meta=json.loads((ROOT/'native/regex_unicode_data_composition.json').read_bytes())
        self.session=self.query.session(output_capacity=output_capacity,workspace_capacity=self.constants['WORKSPACE_BYTES'])
        self.calls=0;self.children=0

    def invoke(self,wire):
        for _ in range(2):
            self.calls+=1
            try:
                return 0,self.session.invoke(wire)
            except NativeCapacityError:
                return 0xFFFFFFFE,b''
            except NativeRejected as error:
                if error.code!=0xFFFFFFE0:return error.code,b''
                footer=self.constants['WORKSPACE_BYTES']-256
                address=ctypes.addressof(self.session._workspace)
                words=struct.unpack('<15Q',ctypes.string_at(address+footer,120))
                assert words==(
                    int.from_bytes(b'HIACAL01','little'),1,11,2,256,8,2,
                    self.constants['ASSET'],self.constants['ASSET_BYTES'],0,0,0,0,0,0)
                child_wire=ctypes.string_at(address+256,8)
                result=self.data.invoke(child_wire,output_capacity=self.constants['ASSET_BYTES'],
                                        workspace_capacity=self.data_meta['workspace_bytes'])
                self.children+=1
                assert len(result)==self.constants['ASSET_BYTES']
                ctypes.memmove(address+self.constants['ASSET'],result,len(result))
                ctypes.memmove(address+footer+80,struct.pack('<QQQQ',len(result),1,1,0),32)
        raise AssertionError('native query did not finish its one-child continuation')

    def close(self):
        self.session.close();self.query.close();self.data.close()

    def __enter__(self):return self
    def __exit__(self,*args):self.close()
