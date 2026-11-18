"""Explicit native syntax/data child-call fixture, with no host parsing."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import json
import struct
from regex_unicode_fixture import ROOT,UnicodeFixture,NativeModule,sha


def request(pattern,wrapped=False):
    if isinstance(pattern,str):pattern=pattern.encode('utf-8')
    return b'HRGAST01'+struct.pack('<QQ',1 if wrapped else 2,len(pattern))+pattern


class ParserFixture(UnicodeFixture):
    def __init__(self,output_capacity=8<<20,workspace_capacity=16<<20,manifest=None):
        self.query_path=Path(manifest) if manifest else module_manifest('regex_syntax')
        self.data_path=module_manifest('regex_unicode_data')
        self.query=NativeModule(self.query_path,manifest_sha256=sha(self.query_path.read_bytes()))
        self.data=NativeModule(self.data_path,manifest_sha256=sha(self.data_path.read_bytes()))
        self.constants=json.loads((ROOT/'native/regex_syntax_composition.json').read_bytes())['constants']
        self.constants['WORKSPACE_BYTES']=workspace_capacity
        self.data_meta=json.loads((ROOT/'native/regex_unicode_data_composition.json').read_bytes())
        self.session=self.query.session(output_capacity=output_capacity,workspace_capacity=workspace_capacity)
        self.calls=0;self.children=0
