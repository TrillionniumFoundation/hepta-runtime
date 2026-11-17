"""Actual two-HIA record I/O execution; Python supplies only owned syscall effects and observations."""
from pathlib import Path
import argparse
import ctypes as C
import gzip
import json
import os
import struct
import sys
import time
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path[:0]=[str(ROOT),str(ROOT/'scripts')]
from common import encoded, loads, pin, read, require, source
from protocol import (INVALID,CAPACITY,cases,initial,response,acknowledgement,semantic,word,put)
from abi_controls import initial_controls,acknowledgement_controls
from effects import Effects
from fixture import setup,snapshot,retire
from hia_native import NativeModule

HEADER=struct.Struct('<9Q')
GUARD=16

class Capture:
    def __init__(self,directory,modules):
        self.directory=directory;self.modules=modules;self.rows=[]
        self.raw=(directory/'buffers.bin.gz').open('xb')
        self.stream=gzip.GzipFile(filename='',mode='wb',compresslevel=1,fileobj=self.raw,mtime=0)
        self.stream.write(b'AIOLOG01')
        self.closed=False
    def call(self,module,wire,output,workspace,case,step,probe=None):
        require(type(output) is int and output>=0,'exact output capacity')
        raw_in=wire+b'\xc3'*GUARD
        raw_out=b'\xa5'*(output+GUARD)
        raw_work=workspace+b'\x5a'*GUARD
        i=C.create_string_buffer(raw_in,len(raw_in))
        o=C.create_string_buffer(raw_out,len(raw_out))
        w=C.create_string_buffer(raw_work,len(raw_work))
        before=(i.raw,o.raw,w.raw)
        started=time.monotonic_ns()
        result=int(self.modules[module]._entry(C.addressof(i),len(wire),C.addressof(o),output,
                                               C.addressof(w),len(workspace)))
        elapsed=time.monotonic_ns()-started
        after=(i.raw,o.raw,w.raw)
        index=len(self.rows)
        self.stream.write(b'AIOCAL01'+HEADER.pack(index,case,step,module,result,len(wire),output,
                                                  len(workspace),int(probe is not None)))
        for raw in before+after:self.stream.write(raw)
        row=dict(index=index,case=case,step=step,module=module,result=result,probe=probe,
                 input_bytes=len(wire),output_capacity=output,workspace_capacity=len(workspace),
                 elapsed_ns=elapsed,before=[pin(v) for v in before],after=[pin(v) for v in after])
        self.rows.append(row)
        require(after[0]==before[0] and after[1][output:]==b'\xa5'*GUARD
                and after[2][len(workspace):]==b'\x5a'*GUARD,'all actual borrowed guards preserved')
        if probe is not None:
            require(result==probe['expected'] and after[1:]==before[1:],
                    'actual rejection preserves every output/workspace byte: '+probe['name'])
        return result,after[1][:output],after[2][:len(workspace)],index
    def probes(self,rows,workspace,case,step,prefix):
        for name,wire,out_size,work_size,writes,expected in rows:
            work=bytearray((workspace+b'\x79'*max(0,work_size-len(workspace)))[:work_size])
            for at,value in writes:put(work,at,value)
            self.call(0,wire,out_size,bytes(work),case,step,
                dict(name=prefix+'/'+name,expected=expected,writes=writes))
    def close(self,success):
        if self.closed:return
        self.closed=True
        try:
            if success:self.stream.write(b'AIOEND01'+struct.pack('<Q',len(self.rows)))
        finally:
            try:self.stream.close()
            finally:self.raw.close()
            (self.directory/'INVOCATIONS.json').write_bytes(encoded(self.rows))

def run(build,output,fixture):
    identity=source();domain=cases(ROOT)
    output.mkdir(parents=True,exist_ok=False)
    setup(fixture,domain)
    paths=[build/'modules'/name/'manifest.json' for name in ('audit-record-io','audit-json')]
    modules=[]
    capture=None;effect_file=None;observations=[];controls_seen=set();success=False
    try:
        for path in paths:modules.append(NativeModule(path,manifest_sha256=pin(read(path))['sha256']))
        capture=Capture(output,modules)
        effect_file=(output/'effects.jsonl').open('xb')
        control_wire=initial(0,0,domain[0]['steps'][0])
        capture.probes(initial_controls(control_wire,8192,32768),bytes(32768),0,0,'initial')
        for case_index,case in enumerate(domain):
            folder=fixture/('case-%04d'%case_index)
            work=bytes(32768)
            current_step=0
            def journal(value):
                value=dict(case=case_index,step=current_step,**value)
                effect_file.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n')
            transport=Effects(folder,journal)
            try:
                for step_index,step in enumerate(case['steps']):
                    current_step=step_index
                    before=snapshot(folder)
                    wire=initial(case_index,step_index,step)
                    first=len(capture.rows)
                    turn=wire;last_effect=0
                    while True:
                        result,out,work,call=capture.call(0,turn,8192,work,case_index,step_index)
                        require(128<=result<=len(out),'owner actual complete frame, no silent capacity refusal')
                        full=out[:result];state=response(full,result)
                        require(state['generation']==word(wire,16),'actual generation binding')
                        if state['kind'] in (0,1):
                            transport.quiescent()
                            final=semantic(full)
                            observations.append(dict(case=case_index,step=step_index,initial_hex=wire.hex(),
                                first_call=first,last_call=call,semantic_hex=final.hex(),before=before,after=snapshot(folder)))
                            if 'terminal-ack' not in controls_seen and turn[:8]==b'HAIOACK1':
                                capture.call(0,turn,8192,work,case_index,step_index,
                                    dict(name='terminal-ack-replay',expected=INVALID,writes=[]))
                                controls_seen.add('terminal-ack')
                            break
                        require(state['sequence']==last_effect+1,'every HIA effect sequence exactly once')
                        last_effect=state['sequence']
                        if state['kind']==2:
                            turn=transport.apply(state)
                        else:
                            child=state['payloads'][0]
                            returned,child_out,_,child_call=capture.call(1,child,4096,bytes(8192),case_index,step_index)
                            require(returned==INVALID or 0<=returned<=4096,'actual frozen codec result')
                            payload=b'' if returned==INVALID else child_out[:returned]
                            turn=acknowledgement(state,status=2 if returned==INVALID else 0,value=returned,payload=payload)
                            journal(dict(generation=state['generation'],sequence=state['sequence'],
                                operation=state['operation'],kind=3,child_call=child_call,
                                input_hex=child.hex(),acknowledgement_hex=turn.hex()))
                        key=(state['kind'],state['operation'],word(turn,40))
                        if key not in controls_seen:
                            capture.probes(acknowledgement_controls(turn,8192,len(work)),work,case_index,step_index,
                                           'ack-%d-%d-%d'%key)
                            controls_seen.add(key)
                    require(len(observations)==sum(len(v['steps']) for v in domain[:case_index])+step_index+1,
                            'complete ordered operation coverage')
            finally:
                transport.close()
        success=True
    finally:
        try:
            if effect_file is not None:effect_file.close()
        finally:
            try:
                if capture is not None:capture.close(success)
            finally:
                for module in modules[::-1]:module.close()
        (output/'OBSERVATIONS.json').write_bytes(encoded(observations))
    require(success and len(observations)==459,'all frozen filesystem operations completed')
    retirement=retire(fixture,domain)
    (output/'RETIREMENT.json').write_bytes(encoded(retirement))
    require(source()==identity,'source unchanged during native execution')
    report=dict(schema='hepta.audit-record-io.native.v1',status='PASS',source_manifest_sha256=identity,
        cases=219,operations=459,native_calls=len(capture.rows),
        controls=[r['probe']['name'] for r in capture.rows if r['probe'] is not None],
        json_calls=sum(r['module']==1 for r in capture.rows),
        buffers=pin(read(output/'buffers.bin.gz')),invocations=pin(read(output/'INVOCATIONS.json')),
        effects=pin(read(output/'effects.jsonl')),observations=pin(read(output/'OBSERVATIONS.json')),
        retirement=pin(read(output/'RETIREMENT.json')),
        modules=[dict(manifest=pin(read(path)),image=pin(read(path.parent/'module.image.bin'))) for path in paths],
        root=str(fixture),public_handler_qualified=False,whole_runtime_replaced=False)
    (output/'NATIVE.json').write_bytes(encoded(report))
    print(encoded(report).decode(),end='')

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--build',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--fixture',type=Path,required=True)
    a=p.parse_args();run(a.build.resolve(strict=True),a.output.absolute(),a.fixture.absolute())
