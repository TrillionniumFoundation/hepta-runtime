"""Fixed HIA NFA byte-memory ABI. Python is a test driver only."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent))
from regex_test_context import module_manifest,executable_manifest,executable,data,artifact
import struct
from regex_unicode_fixture import ROOT,NativeModule,NativeRejected,sha

class NfaFixture:
    def __init__(self,output_capacity=8<<20,workspace_capacity=128<<20,manifest=None):
        self.path=Path(manifest)if manifest else module_manifest('regex_nfa')
        self.module=NativeModule(self.path,manifest_sha256=sha(self.path.read_bytes()))
        self.session=self.module.session(output_capacity=output_capacity,workspace_capacity=workspace_capacity);self.calls=0
    def __enter__(self):return self
    def __exit__(self,*args):self.session.__exit__(*args);self.module.__exit__(*args)
    def invoke(self,hir,reverse=False,limit=10485760,graph=False):
        self.calls+=1
        wire=b'HRGNFI01'+struct.pack('<QQQ',reverse,limit,graph)+hir
        try:return 0,self.session.invoke(wire)
        except NativeRejected as e:return e.code,b''
