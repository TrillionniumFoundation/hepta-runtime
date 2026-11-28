"""Mechanical native continuation delivery for the new protocol owner."""
from pathlib import Path
import json
from frontend_native import Engine as BaselineEngine,State,word,CALL,GROW,DELIVERY
from hia_native_loader import NativeModule

class Engine(BaselineEngine):
    def __init__(self,root,events,owned):
        super().__init__(root,events)
        self.controller_row=json.loads((Path(owned)/'evidence/controller-module.json').read_bytes())
        self.modules['controller']=NativeModule(Path(owned)/self.controller_row['path'],manifest_sha256=self.controller_row['sha256'])
        self.members['controller']=self.controller_row
        self.states['controller']=State('controller',self.modules['controller'],events,workspace=4096,output=32)

    def new_session(self):
        super().new_session()
        if 'controller' in self.modules:
            self.states['controller']=State('controller',self.modules['controller'],self.events,workspace=4096,output=32)

    def run(self,name,wire,protocol_bridge=False):
        if name!='protocol':return super().run(name,wire,protocol_bridge=False)
        state=self.states['controller'];completed={}
        for step in range(128):
            code,raw=state.call(wire)
            if code==GROW:
                assert raw[:8]==b'HGRWS002';state.resize(word(raw,8),word(raw,16));continue
            if code!=CALL:return code,raw
            action=raw;assert action[:8]==b'HRQPCA01'
            sequence=word(action,8);target=word(action,16)
            child_wire=state.read(word(action,32),word(action,40))
            if sequence not in completed:
                assert word(action,24)==0
                child={0:'message',1:'request',2:'bridge',3:'protocol'}[target]
                completed[sequence]=super().run(child,child_wire)
            else:assert word(action,24)==1
            child_code,child_raw=completed[sequence]
            state.put(320,sequence);state.put(352,len(child_raw))
            if len(child_raw)>word(action,56):state.put(328,DELIVERY);continue
            state.write(word(action,48),child_raw);state.put(328,child_code)
        raise AssertionError('ordinary native controller continuation bound')
