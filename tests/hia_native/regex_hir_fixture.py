"""Actual HIA HIR/data composition with explicitly checked fixed child spans."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import json
from regex_unicode_fixture import ROOT,UnicodeFixture,NativeModule,sha

class HirFixture(UnicodeFixture):
    def __init__(self,output_capacity=8<<20,workspace_capacity=32<<20,manifest=None):
        self.query_path=Path(manifest)if manifest else module_manifest('regex_hir')
        self.data_path=module_manifest('regex_unicode_data')
        self.query=NativeModule(self.query_path,manifest_sha256=sha(self.query_path.read_bytes()))
        self.data=NativeModule(self.data_path,manifest_sha256=sha(self.data_path.read_bytes()))
        self.constants=json.loads((ROOT/'native/regex_hir_composition.json').read_bytes())['constants'];self.constants['WORKSPACE_BYTES']=workspace_capacity
        self.data_meta=json.loads((ROOT/'native/regex_unicode_data_composition.json').read_bytes())
        self.session=self.query.session(output_capacity=output_capacity,workspace_capacity=workspace_capacity);self.calls=0;self.children=0
