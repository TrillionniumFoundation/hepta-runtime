"""Actual HIA NFA Boolean matcher with fixed Unicode-data child."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import json,struct
from regex_unicode_fixture import ROOT,UnicodeFixture,NativeModule,sha

class MatchFixture(UnicodeFixture):
    def __init__(self,output_capacity=8,workspace_capacity=32<<20,manifest=None):
        self.query_path=Path(manifest)if manifest else module_manifest('regex_match')
        self.data_path=module_manifest('regex_unicode_data')
        self.query=NativeModule(self.query_path,manifest_sha256=sha(self.query_path.read_bytes()))
        self.data=NativeModule(self.data_path,manifest_sha256=sha(self.data_path.read_bytes()))
        self.constants=json.loads((ROOT/'native/regex_match_composition.json').read_bytes())['constants'];self.constants['WORKSPACE_BYTES']=workspace_capacity
        self.data_meta=json.loads((ROOT/'native/regex_unicode_data_composition.json').read_bytes())
        self.session=self.query.session(output_capacity=output_capacity,workspace_capacity=workspace_capacity);self.calls=0;self.children=0
    def match(self,nfa,hay):
        if isinstance(hay,str):hay=hay.encode()
        return self.invoke(b'HRGMAT01'+struct.pack('<QQ',len(nfa),len(hay))+nfa+hay)
