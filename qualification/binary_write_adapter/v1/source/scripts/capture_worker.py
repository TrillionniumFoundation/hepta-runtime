#!/usr/bin/env python3
"""Qualification-only fixed-image carrier, with complete native byte journals."""
import argparse
import contextlib
import ctypes
import gzip
import json
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts'),str(ROOT/'dependency/scripts')]
from common import B3,PACK,WORD,SHA,UNBASE,inputs,source_evidence,pin,save,require,start_wire,request,parent_projection
from hia_native_loader import NativeModule

OWNERS={'map':1,'typed':4,'planner':7,'adapter':8}
INITIAL={'map':(32,16512),'typed':(256,65536),'planner':(64,512),'adapter':(64,256)}
LIMIT=0xffff0000
INVALID=0xffffffff


class Recorder:
    def __init__(self,output,modules):
        self.output=output;self.modules=modules;self.rows=[];self.bytes=0;self.contexts=0
        self.stream=gzip.GzipFile(filename=str(output/'calls.bin.gz'),mode='xb',compresslevel=6,mtime=0)
        self.index=(output/'calls.jsonl').open('xb')

    def context(self,owner,output_capacity=None,workspace_capacity=None):
        oc,wc=INITIAL[owner]
        self.contexts+=1
        session=self.modules[owner].session(output_capacity=oc if output_capacity is None else output_capacity,
                                          workspace_capacity=wc if workspace_capacity is None else workspace_capacity)
        session.capture_owner=owner;session.capture_context=self.contexts
        return session

    def raw(self,session,wire,case,label):
        before=ctypes.string_at(session._workspace,session.workspace_capacity)
        ctypes.memset(session._output,0xa5,session.output_capacity)
        old=ctypes.string_at(session._output,session.output_capacity)
        code,out,after=session.invoke_raw(wire)
        ordinal=len(self.rows)+1
        fields=(ordinal,OWNERS[session.capture_owner],case,code,len(wire),len(out),len(after),0)
        arrays=(wire,before,old,out,after)
        raw=PACK(*fields)+b''.join(arrays)
        row=dict(call=ordinal,owner=fields[1],case_id=case,label=label,context=session.capture_context,
                 return_code=code,input_bytes=len(wire),output_capacity=len(out),workspace_capacity=len(after),
                 offset=self.bytes,bytes=len(raw),record_sha256=SHA(raw))
        for key,value in zip(('input','before','output_before','output','after'),arrays):row[key+'_sha256']=SHA(value)
        self.stream.write(raw);self.index.write((json.dumps(row,sort_keys=True,separators=(',',':'))+'\n').encode())
        self.rows.append(row);self.bytes+=len(raw)
        return ordinal,code,out,after

    def resize(self,session,which,needed):
        require(which in (1,2) and type(needed)is int,'structural growth selector')
        if which==1:
            require(session.workspace_capacity<needed<=256<<20,'bounded increasing workspace')
            old=ctypes.string_at(session._workspace,session.workspace_capacity)
            session._workspace=ctypes.create_string_buffer(needed+16)
            ctypes.memmove(session._workspace,old,len(old))
            session.workspace_capacity=needed
        else:
            require(session.output_capacity<needed<=128<<20,'bounded increasing output')
            session._output=ctypes.create_string_buffer(needed+16)
            session.output_capacity=needed

    def complete(self,session,wire,case,label):
        calls=[]
        for _ in range(12):
            call,code,out,after=self.raw(session,wire,case,label)
            calls.append(call)
            owner=session.capture_owner
            if code in (INVALID,0xfffffffe):return code,b'',calls
            if owner in ('map','typed'):
                header=32 if owner=='map' else 256
                require(code==header and len(out)>=header,'fixed owner structural header')
                status=WORD(out,8)
                if status in (2,3):
                    needed=WORD(out,24 if owner=='map' else 80)
                    self.resize(session,1 if status==2 else 2,needed)
                    continue
                if owner=='map':extent=32+WORD(out,16)
                elif status==0:extent=256+sum(WORD(out,at)for at in range(88,152,8))
                else:extent=256+WORD(out,72)
                require(extent<=len(out),'complete owner extent')
                return code,out[:extent],calls
            if code==0xffffffd0:
                require(out[:8]==b'HGRWS002' and WORD(out,24)==0,'fixed growth protocol')
                self.resize(session,WORD(out,8),WORD(out,16));continue
            require(64<=code<LIMIT and code<=len(out),'complete fixed owner publication')
            return code,out[:code],calls
        raise ValueError('original twelve-call continuation bound exceeded')

    def invoke(self,owner,wire,case,label):
        with self.context(owner)as session:return self.complete(session,wire,case,label)

    def compose(self,wire,ready,case,label):
        with self.context('adapter')as session:
            start=start_wire(wire,ready)
            code,published,calls=self.complete(session,start,case,label+'-start')
            result=dict(start_calls=calls,start_code=code,start_frame=published.hex(),planner_calls=[],resume_calls=[],release_calls=[])
            if code>=LIMIT:return result
            require(published[:8]==b'HBWAR001' and WORD(published,8)==1 and WORD(published,32)==0,'fixed planner child action')
            sequence=WORD(published,16)
            child_code,child,child_calls=self.invoke('planner',published[64:],case,label+'-fixed-child')
            result['planner_calls']=child_calls
            complete=request(2,sequence,child_code,child)
            result_code,frame,resumes=self.complete(session,complete,case,label+'-resume')
            result.update(resume_calls=resumes,result_code=result_code,result_frame=frame.hex())
            require(frame[:8]==b'HBWAR001' and WORD(frame,8)in(2,3),'adapter terminal publication')
            release_code,released,release_calls=self.complete(session,request(3,sequence),case,label+'-release')
            result.update(release_calls=release_calls,release_code=release_code,release_frame=released.hex())
            return result

    def close(self):
        self.stream.close();self.index.close()
        return dict(calls=len(self.rows),contexts=self.contexts,logical_bytes=self.bytes,
                    by_owner={name:sum(row['owner']==code for row in self.rows)for name,code in OWNERS.items()})


def typed_case(rec,raw,case,label):
    _,value,vcalls=rec.invoke('map',b'HJSMS002'+PACK(1,len(raw))+raw,case,label+'-map')
    result=dict(value_calls=vcalls,value_frame=value.hex(),typed_calls=[],typed_frame=None)
    if WORD(value,8)==0:
        _,typed,tcalls=rec.invoke('typed',b'HBPRQ001'+PACK(len(value)-32,3)+value[32:],case,label+'-typed')
        result.update(typed_calls=tcalls,typed_frame=typed.hex())
    return result


def controls(rec,data):
    good=next((s for row in data['plan_cases']if row['kind']==3 for s in row['stages']if s['eligible']))
    wire,ready=UNBASE(good['request']),UNBASE(good['actual_result'])
    valid=start_wire(wire,ready)
    controls=[]
    def raw_control(name,packet,oc=64,wc=256,prepare=None):
        case=200000+len(controls)
        with rec.context('adapter',oc,wc)as session:
            if prepare:prepare(session)
            call,code,out,after=rec.raw(session,packet,case,name)
        controls.append(dict(name=name,kind='private-invalid',calls=[call],expected_code=0xfffffffe if oc<64 else INVALID))
    def mutate(raw,offset,value):
        result=bytearray(raw);struct.pack_into('<Q',result,offset,value);return bytes(result)
    for capacity in (0,1,63):raw_control('short-output-'+str(capacity),valid,oc=capacity)
    for length in (0,1,47):raw_control('short-input-'+str(length),valid[:length])
    changes=[('magic',0,0),('command-zero',8,0),('command-four',8,4),('start-sequence',16,1),('start-return',24,64),
             ('payload-short',32,len(valid)-49),('payload-long',32,len(valid)-47),('request-small',40,303),('request-max',40,(1<<64)-1),
             ('planner-magic',48,0),('planner-phase-zero',56,0),('planner-phase-one',56,1),('planner-pool',64,2),
             ('typed-small',72,255),('typed-max',72,(1<<64)-1),('feedback-length',80,0),('planner-reserved',88,1),
             ('typed-magic',96,0),('typed-status',104,1),('typed-kind',112,4),('typed-action',120,1),('typed-option',128,1),
             ('typed-error-length',168,1),('typed-required',176,1),('host-max',184,(1<<64)-1),('path-max',192,(1<<64)-1),
             ('data-max',200,(1<<64)-1),('version-max',208,(1<<64)-1),('foreign-string',216,1),('typed-reserved',248,1)]
    feedback=96+WORD(wire,24)
    changes += [('root-magic',feedback,0),('root-error',feedback+8,1),('root-reserved',feedback+16,1),('root-length',feedback+24,(1<<64)-1)]
    at=48+len(wire)
    changes += [('ready-magic',at,0),('ready-error',at+8,1),('ready-kind',at+16,2),('ready-phase',at+24,1),('ready-operation',at+32,2),('ready-audit',at+40,0),('ready-pool',at+48,1),('ready-length',at+56,(1<<64)-1)]
    for name,at,value in changes:raw_control(name,mutate(valid,at,value))
    # Both byte corruptions reach the actual unchanged planner; no return value is fabricated.
    changed=bytearray(ready);changed[-2]^=1
    result=rec.compose(wire,bytes(changed),200000+len(controls),'whole-json-mismatch')
    controls.append(dict(name='whole-json-mismatch',kind='fixed-child-mismatch',composition=result,expected_detail=2))
    changed=bytearray(wire);changed[304]=255
    result=rec.compose(bytes(changed),ready,200000+len(controls),'actual-planner-utf8-rejection')
    controls.append(dict(name='actual-planner-utf8-rejection',kind='fixed-child-mismatch',composition=result,expected_detail=1))
    raw_control('dirty-workspace',valid,wc=256+len(wire)+len(ready),prepare=lambda s:ctypes.memset(s._workspace,0x55,s.workspace_capacity))
    def overflow(s):
        raw=b'HBWAS001'+PACK(0,(1<<64)-1,0,0,0)+bytes(208)
        ctypes.memmove(s._workspace,raw,len(raw))
    raw_control('sequence-overflow',valid,wc=256+len(wire)+len(ready),prepare=overflow)
    # One real retained context proves ordering and stale replies across actual completed generations.
    case=200000+len(controls);events=[]
    with rec.context('adapter')as session:
        def normal(name,packet):
            code,frame,calls=rec.complete(session,packet,case,name)
            events.append(dict(name=name,calls=calls,code=code,frame=frame.hex()))
            return code,frame
        def invalid(name,packet):
            call,code,out,after=rec.raw(session,packet,case,name)
            events.append(dict(name=name,calls=[call],code=code,expected_invalid=True))
        invalid('release-idle',request(3,1))
        _,first=normal('first-start',valid);seq=WORD(first,16)
        invalid('start-while-waiting',valid)
        invalid('release-before-child',request(3,seq))
        code,child,calls=rec.invoke('planner',first[64:],case,'lifecycle-fixed-child')
        events.append(dict(name='lifecycle-fixed-child',calls=calls,code=code,frame=child.hex()))
        invalid('stale-child-sequence',request(2,seq+1,code,child))
        # Actual output shrinkage forces the HIA's parent-publication growth continuation.
        session._output=ctypes.create_string_buffer(64+16);session.output_capacity=64
        _,result=normal('valid-resume-after-output-shrink',request(2,seq,code,child))
        invalid('duplicate-resume',request(2,seq,code,child))
        invalid('start-before-release',valid)
        normal('first-release',request(3,seq))
        invalid('duplicate-release',request(3,seq))
        _,second=normal('second-start',valid)
        invalid('stale-previous-generation',request(2,seq,code,child))
        code2,child2,calls2=rec.invoke('planner',second[64:],case,'second-fixed-child')
        events.append(dict(name='second-fixed-child',calls=calls2,code=code2,frame=child2.hex()))
        normal('second-resume',request(2,WORD(second,16),code2,child2))
        normal('second-release',request(3,WORD(second,16)))
    controls.append(dict(name='complete-lifecycle-and-growth',kind='lifecycle',events=events))
    return controls


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--images',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--mode',choices=('typed','plan','interface','controls'),required=True);p.add_argument('--group')
    a=p.parse_args();require(not a.output.exists(),'fresh capture worker output')
    identity=source_evidence();domain,data=inputs()
    build=json.loads((a.images/'IMAGES.json').read_bytes())
    require(build['source']==identity and build['compiler_image']['sha256']==B3,'exact frozen build/source')
    a.output.mkdir(parents=True)
    with contextlib.ExitStack()as stack:
        modules={}
        for name,row in build['members'].items():
            manifest=a.images/row['manifest'];require(pin(manifest)==row['identity'],'exact admitted image manifest')
            modules[name]=stack.enter_context(NativeModule(manifest,manifest_sha256=row['identity']['sha256']))
        rec=Recorder(a.output,modules);results=[]
        try:
            if a.mode=='typed':
                for row in data['typed_write_cases']:
                    result=typed_case(rec,UNBASE(row['raw_json']),row['case_id'],'old-write-typed')
                    results.append(dict(case_id=row['case_id'],name=row['name'],**result))
            elif a.mode=='plan':
                selected=[row for row in data['plan_cases']if row['group']==a.group]
                require(selected,'original complete planner group')
                for row in selected:
                    stages=[]
                    for position,stage in enumerate(row['stages']):
                        wire,ready=UNBASE(stage['request']),UNBASE(stage['actual_result'])
                        code,result,calls=rec.invoke('planner',wire,row['case_id'],'old-planner-stage-'+str(position))
                        composed=rec.compose(wire,ready,row['case_id'],'old-write-ready')if stage['eligible']else None
                        stages.append(dict(calls=calls,code=code,result=result.hex(),composition=composed))
                    results.append(dict(case_id=row['case_id'],kind=row['kind'],name=row['name'],stages=stages))
            elif a.mode=='interface':
                for row in data['parent_interface_cases']:
                    case=100000+row['id'];root,raw=parent_projection(row)
                    result=typed_case(rec,raw,case,'parent-interface')
                    result.update(case_id=case,original_id=row['id'],name=row['name'],planner_calls=[],composition=None)
                    typed=bytes.fromhex(result['typed_frame'])if result['typed_frame']is not None else None
                    if typed is not None and WORD(typed,8)==0:
                        feedback=b'HRCFGM01'+PACK(0,0,len(root))+root
                        wire=b'HBPLQ001'+PACK(2,0,len(typed),len(feedback),0)+typed+feedback
                        code,ready,calls=rec.invoke('planner',wire,case,'interface-planner')
                        result.update(planner_calls=calls,planner_code=code,planner_frame=ready.hex())
                        if code<LIMIT and WORD(ready,8)==3:
                            result['composition']=rec.compose(wire,ready,case,'parent-interface-ready')
                    results.append(result)
            else:results=controls(rec,data)
        finally:summary=rec.close()
    require(source_evidence()==identity,'whole source remains unchanged')
    save(a.output/'RESULTS.json',results)
    save(a.output/'CAPTURE.json',dict(schema='hepta.runtime.binary-write-adapter.capture.v1',status='CAPTURE_COMPLETE',mode=a.mode,group=a.group,
        source=identity,images=pin(a.images/'IMAGES.json'),domain=pin(ROOT/'inputs/DOMAIN.json'),summary=summary,cases=len(results),
        original_rust_executions=0,parent_effects_executed=0,public_binary_write_registered=False,whole_runtime_replaced=False))
    print(json.dumps(dict(mode=a.mode,group=a.group,cases=len(results),summary=summary,status='CAPTURE_COMPLETE'),sort_keys=True))


if __name__=='__main__':main()
