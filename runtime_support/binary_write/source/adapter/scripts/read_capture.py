#!/usr/bin/env python3
"""Independent DATA-only reader of complete fixed-source native records."""
import argparse
import collections
import gzip
import json
import stat
import struct
import sys
from pathlib import Path

sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from common import B3,HEPTA,PACK,WORD,SHA,UNBASE,inputs,source_evidence,pin,save,require,owned,parent_projection

INVALID=0xffffffff
SHORT=0xfffffffe
GROW=0xffffffd0
LIMIT=0xffff0000


def read_images(folder,source):
    result=json.loads(owned(folder,'IMAGES.json').read_bytes())
    require(result['schema']=='hepta.runtime.binary-write-adapter.images.v1' and result['status']=='FRESH_ACTUAL_B3_COMPILE_PASS','actual successful image build')
    require(result['source']==source and result['compiler']['commit']==HEPTA and result['compiler_image']['sha256']==B3,'image source and compiler binding')
    require(set(result['members'])=={'map','typed','planner','adapter'} and result['actual_hia_compilations']==4,'all four fresh image compilations')
    require(result['new_seed_executions']==result['new_bootstrap_generations']==result['parent_effects_executed']==0,'exact build scope')
    require(result['public_binary_write_registered']is False and result['whole_runtime_replaced']is False,'build activation flags')
    dependency=json.loads(owned(ROOT,'COMPILER_INPUT.json').read_bytes())
    require(result['compiler']==dependency and len(dependency['files'])==1080,'complete fixed compiler closure')
    for name,sha in dependency['files'].items():require(pin(owned(folder,'compiler-source/'+name))['sha256']==sha,'retained compiler source: '+name)
    bootstrap=folder/'build/bootstrap'
    actual={}
    for path in bootstrap.rglob('*'):
        require(not path.is_symlink(),'bootstrap ordinary files')
        if path.is_file():actual[path.relative_to(bootstrap).as_posix()]=dict(**pin(path),mode=stat.S_IMODE(path.stat().st_mode))
    require(actual==result['retained_bootstrap'],'all retained bootstrap bytes and modes')
    b=json.loads(owned(bootstrap,'bootstrap.json').read_bytes())
    require(b['generation_sha256']==B3 and b['dependency']==dependency and b['qualification']=='development_fixed_point','retained bootstrap provenance')
    for label in ('B1','B2','B3'):require(pin(owned(bootstrap,label+'.image.bin'))['sha256']==B3,'actual fixed generations')
    expected_image={'typed':'ea53fe4db03ea7463541129504afa8a289f5c2201cbef10b8747a61a0e75bdd2','planner':'59d6e9fbe8c60feccebea8f701253f37cb49f41d15c6d50801011780fe11bbed'}
    for name,row in result['members'].items():
        manifest=owned(folder,row['manifest']);require(pin(manifest)==row['identity'],'exact member manifest')
        metadata=json.loads(manifest.read_bytes());base=manifest.parent
        module_source=owned(base,metadata['source']).read_bytes();image=owned(base,metadata['image']).read_bytes()
        require(pin(owned(ROOT,row['source_path']))==row['source'] and SHA(module_source)==row['source']['sha256']==metadata['source_sha256'],'unchanged compiled member source')
        require(dict(bytes=len(image),sha256=SHA(image))==row['image'] and SHA(image)==metadata['image_sha256'],'complete actual image bytes')
        require(metadata['compiler_commit']==HEPTA and metadata['compiler_sha256']==B3 and metadata['buffer_profile']=='history.v1' and metadata['standalone']is None,'exact image ABI profile')
        require([metadata[k]for k in ('input_capacity','output_capacity','workspace_capacity')]==[128<<20,128<<20,256<<20],'original unchanged byte capacities')
        if name in expected_image:require(SHA(image)==expected_image[name],'current product typed/planner image bytes unchanged')
        request=json.loads(owned(base,'module.request.json').read_bytes())
        receipt=json.loads(owned(base,'module.receipt.json').read_bytes())
        full=owned(base,'module.output.bin').read_bytes()
        require(owned(base,'module.input.bin').read_bytes()==module_source,'actual compiler input')
        require(receipt['status']=='returned' and type(receipt['abi_status'])is int and receipt['abi_status']==0,'actual compiler clean return')
        require(receipt['core_u32']==receipt['result_u64']==receipt['produced_bytes']==len(image) and full[:len(image)]==image,'whole actual compiled image')
        require(receipt['input_bytes']==len(module_source) and receipt['input_sha256']==SHA(module_source) and receipt['output_sha256']==SHA(full) and receipt['produced_sha256']==SHA(image),'complete compile buffer hashes')
        require(receipt['artifact_sha256']==B3 and receipt['source_unchanged']is True and receipt['forbidden_compiler_modules_loaded']==[],'actual B3 custody')
        require(request['source_sha256']==SHA(module_source) and request['image_sha256']==B3 and request['format']=='flat-x86-64' and request['capacity']==1<<20,'unchanged compile request budget')
        build=json.loads(owned(base,'build.json').read_bytes())
        require(build['compile_receipt']==receipt and build['compiler_dependency']==dependency,'full compile dependency identity')
    return result


def publication(owner,code,out,before,after):
    if code in (INVALID,SHORT):
        require(out==b'\xa5'*len(out) and after==before,'physical refusal preserves complete output/workspace')
        return b''
    if code==GROW:
        require(owner in (7,8) and len(out)>=64 and out[:8]==b'HGRWS002' and WORD(out,8)in(1,2) and WORD(out,24)==0,'complete growth framing')
        require(WORD(out,16)>(len(before)if WORD(out,8)==1 else len(out)) and out[32:]==b'\xa5'*(len(out)-32),'strict capacity increase and unchanged growth tail')
        if owner==8:require(before==after,'adapter growth does not consume continuation')
        return out[:32]
    if owner in (1,4):
        header=32 if owner==1 else 256
        require(code==header and out[:8]==(b'HJSVR002'if owner==1 else b'HBPRR001'),'full original Map/typed framing')
        flag=WORD(out,8)
        require(flag in ((0,1,2,3,5)if owner==1 else(0,1,2,3,4)),'complete original status domain')
        if flag in (2,3):
            size=header;needed=WORD(out,24 if owner==1 else 80)
            require(needed>(len(before)if flag==2 else len(out)),'actual original increasing growth')
        elif owner==1:size=32+WORD(out,16)
        else:
            require(WORD(out,16)==3 and out[152:256]==bytes(104),'write typed kind and reserved words')
            size=256+(sum(WORD(out,at)for at in range(88,152,8))if flag==0 else WORD(out,72))
        require(size<=len(out) and out[size:]==b'\xa5'*(len(out)-size),'complete original owner publication and tail')
        return out[:size]
    require(owner in (7,8) and 64<=code<LIMIT and code<=len(out) and out[code:]==b'\xa5'*(len(out)-code),'entire planner/adapter output and tail')
    frame=out[:code]
    if owner==7:
        require(frame[:8]==b'HBPLR001' and WORD(frame,56)==code-64 and WORD(frame,8)in(1,2,3) and WORD(frame,16)in range(1,6),'whole original planner frame')
    else:
        require(frame[:8]==b'HBWAR001' and WORD(frame,8)in range(4) and WORD(frame,24)==code-64 and frame[40:64]==bytes(24),'whole adapter frame')
        require(len(before)>=256 and before[0:8]in(bytes(8),b'HBWAS001') and after[:8]==b'HBWAS001','owned adapter context')
    return frame


def records(folder):
    index=[json.loads(line)for line in owned(folder,'calls.jsonl').read_bytes().splitlines()]
    remaining=collections.Counter(row['context']for row in index)
    last={};result={};offset=0
    with gzip.open(owned(folder,'calls.bin.gz'),'rb')as stream:
        for ordinal,row in enumerate(index,1):
            require(row['call']==ordinal and row['offset']==offset and row['owner']in(1,4,7,8),'ordered full native journal identity')
            require(0<=row['input_bytes']<=128<<20 and 0<=row['output_capacity']<=128<<20 and 0<=row['workspace_capacity']<=256<<20,'original bounded native buffers')
            raw=stream.read(row['bytes']);require(len(raw)==row['bytes'] and SHA(raw)==row['record_sha256'],'whole native record bytes')
            fields=struct.unpack_from('<8Q',raw)
            require(fields==(ordinal,row['owner'],row['case_id'],row['return_code'],row['input_bytes'],row['output_capacity'],row['workspace_capacity'],0),'full native record header')
            at=64;arrays=[]
            for size,label in ((fields[4],'input'),(fields[6],'before'),(fields[5],'output_before'),(fields[5],'output'),(fields[6],'after')):
                value=raw[at:at+size];require(len(value)==size and SHA(value)==row[label+'_sha256'],'complete native '+label)
                at+=size;arrays.append(value)
            require(at==len(raw),'no hidden record suffix')
            wire,before,old,out,after=arrays
            require(old==b'\xa5'*len(old),'full original output fill')
            context=row['context']
            if context in last:
                previous=last[context]
                require(len(before)>=len(previous) and before==previous+bytes(len(before)-len(previous)),'complete workspace retained across resize/continuation')
            elif row['label']=='dirty-workspace':require(before==b'\x55'*len(before),'exact dirty-state control')
            elif row['label']=='sequence-overflow':require(before[:256]==b'HBWAS001'+PACK(0,(1<<64)-1,0,0,0)+bytes(208) and before[256:]==bytes(len(before)-256),'exact overflow-state control')
            else:require(before==bytes(len(before)),'actual new context begins zeroed')
            frame=publication(row['owner'],row['return_code'],out,before,after)
            if row['owner']==8 and row['return_code']<LIMIT:
                command=WORD(wire,8);kind=WORD(frame,8)
                if command==1:
                    require(kind==1 and WORD(frame,16)==WORD(before,16)+1 and WORD(frame,32)==0,'new exact child generation')
                    expected=bytearray(before)
                    expected[:48]=b'HBWAS001'+PACK(1,WORD(frame,16),WORD(wire,40),len(wire)-48-WORD(wire,40),len(wire)-48)
                    expected[256:256+len(wire)-48]=wire[48:]
                    require(after==bytes(expected) and frame[64:]==wire[48:48+WORD(wire,40)],'complete immutable input custody and fixed child bytes')
                elif command==2:
                    require(kind in(2,3) and WORD(before,8)==1 and WORD(wire,16)==WORD(before,16)==WORD(frame,16),'bound private child completion')
                    expected=bytearray(before);struct.pack_into('<Q',expected,8,2)
                    require(after==bytes(expected),'only finish phase changes on completion')
                else:
                    require(command==3 and kind==0 and len(frame)==64 and WORD(frame,32)==0 and WORD(before,8)==2 and WORD(wire,16)==WORD(before,16)==WORD(frame,16),'bound exact release')
                    expected=bytearray(before);struct.pack_into('<Q',expected,8,0);expected[24:48]=bytes(24)
                    require(after==bytes(expected),'release preserves entire generation and immutable packet storage')
            remaining[context]-=1
            if remaining[context]:last[context]=after
            else:last.pop(context,None)
            result[ordinal]=(row,wire,frame)
            offset+=len(raw)
        require(stream.read(1)==b'' and not last and not any(remaining.values()),'no omitted record or open context journal')
    return result,dict(calls=len(index),contexts=len(remaining),logical_bytes=offset,
        by_owner={name:sum(row['owner']==owner for row in index)for name,owner in [('map',1),('typed',4),('planner',7),('adapter',8)]})


def terminal(records,used,calls,owner,expected_wire=None):
    require(calls and len(calls)<=12 and calls==list(range(calls[0],calls[-1]+1)),'complete original bounded call chain')
    wire=None;context=None
    for position,call in enumerate(calls):
        require(call not in used and call in records,'no repeated/unknown invocation credit');used.add(call)
        row,current,frame=records[call]
        require(row['owner']==owner,'fixed image owner')
        if wire is None:wire=current;context=row['context']
        require(current==wire and row['context']==context,'same immutable input/context on continuation')
        code=row['return_code']
        growth=code==GROW or owner in(1,4)and code in(32,256)and WORD(frame,8)in(2,3)
        require(growth==(position+1<len(calls)),'neither omitted growth nor replayed completion')
    if expected_wire is not None:require(wire==expected_wire,'whole source-bound request bytes')
    return code,frame,wire


def parent_request(ready):
    require(ready[:8]==b'HBPLR001' and tuple(WORD(ready,at)for at in range(8,56,8))==(3,3,0,3,1,0) and WORD(ready,56)==len(ready)-64,'actual ready write semantics')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'duplicate actual ready JSON member')
            result[key]=value
        return result
    value=json.loads(ready[64:],object_pairs_hook=unique)
    require(type(value)is dict and set(value)=={'data_base64','expected_version','op','path','root'} and value['op']=='write','complete original write JSON object')
    require(all(type(value[key])is str for key in ('root','path','expected_version','data_base64')),'original String fields')
    strings=[value[key].encode('utf-8')for key in ('root','path','expected_version','data_base64')]
    return b'HBPWQ001'+PACK(1,0,1,*map(len,strings),1,0,0,sum(map(len,strings)))+b''.join(strings)


def composition(row,records,used,expected_wire,expected_ready,expected_detail=None):
    start=b'HBWAQ001'+PACK(1,0,0,len(expected_wire)+len(expected_ready),len(expected_wire))+expected_wire+expected_ready
    code,first,_=terminal(records,used,row['start_calls'],8,start)
    require(code==row['start_code'] and first.hex()==row['start_frame'] and WORD(first,8)==1,'actual HIA fixed child request')
    child_code,child,wire=terminal(records,used,row['planner_calls'],7,first[64:])
    require(wire==expected_wire,'fixed exact original planner invocation')
    resume=b'HBWAQ001'+PACK(2,WORD(first,16),child_code,len(child),0)+child
    code,result,_=terminal(records,used,row['resume_calls'],8,resume)
    require(code==row['result_code'] and result.hex()==row['result_frame'],'entire observed adapter completion')
    if expected_detail is None:
        require(child==expected_ready and WORD(result,8)==2 and WORD(result,32)==0 and result[64:]==parent_request(child),'complete parent byte projection from actual original JSON')
    else:
        require(WORD(result,8)==3 and WORD(result,32)==expected_detail,'actual fixed-child mismatch refusal')
        if expected_detail==1:require(child_code==INVALID and child==b'' and len(result)==64,'actual planner invalid return preserved')
        else:require(child!=expected_ready and result[64:]==child,'whole actual mismatching child retained')
    code,release,_=terminal(records,used,row['release_calls'],8,b'HBWAQ001'+PACK(3,WORD(first,16),0,0,0))
    require(code==row['release_code']==64 and release.hex()==row['release_frame'] and WORD(release,8)==0,'actual final adapter release')
    return result


def private_refusal_specs(wire,ready):
    """Independently bind each named refusal to complete physical input bytes."""
    valid=b'HBWAQ001'+PACK(1,0,0,len(wire)+len(ready),len(wire))+wire+ready
    specs={}
    def add(name,packet,oc=64,wc=256,before=None):
        require(name not in specs,'unique independent refusal contract')
        specs[name]=dict(wire=packet,output_capacity=oc,workspace_capacity=wc,
            before_sha256=SHA(bytes(wc)if before is None else before),code=SHORT if oc<64 else INVALID)
    for capacity in (0,1,63):add('short-output-'+str(capacity),valid,oc=capacity)
    for length in (0,1,47):add('short-input-'+str(length),valid[:length])
    maximum=(1<<64)-1
    # Offsets are the declared HBWAQ001/HBPLQ001/HBPRR001 layouts, not a
    # producer-supplied expected_code, label, packet or mutation description.
    offsets=[('magic',0,0),('command-zero',8,0),('command-four',8,4),
        ('start-sequence',16,1),('start-return',24,64),
        ('payload-short',32,len(valid)-49),('payload-long',32,len(valid)-47),
        ('request-small',40,303),('request-max',40,maximum),
        ('planner-magic',48,0),('planner-phase-zero',56,0),('planner-phase-one',56,1),
        ('planner-pool',64,2),('typed-small',72,255),('typed-max',72,maximum),
        ('feedback-length',80,0),('planner-reserved',88,1),('typed-magic',96,0),
        ('typed-status',104,1),('typed-kind',112,4),('typed-action',120,1),
        ('typed-option',128,1),('typed-error-length',168,1),('typed-required',176,1),
        ('host-max',184,maximum),('path-max',192,maximum),('data-max',200,maximum),
        ('version-max',208,maximum),('foreign-string',216,1),('typed-reserved',248,1)]
    root=48+48+WORD(wire,24)
    offsets.extend([('root-magic',root,0),('root-error',root+8,1),
        ('root-reserved',root+16,1),('root-length',root+24,maximum)])
    at=48+len(wire)
    offsets.extend([('ready-magic',at,0),('ready-error',at+8,1),('ready-kind',at+16,2),
        ('ready-phase',at+24,1),('ready-operation',at+32,2),('ready-audit',at+40,0),
        ('ready-pool',at+48,1),('ready-length',at+56,maximum)])
    for name,offset,value in offsets:
        changed=bytearray(valid);struct.pack_into('<Q',changed,offset,value)
        add(name,bytes(changed))
    workspace=256+len(wire)+len(ready)
    add('dirty-workspace',valid,wc=workspace,before=b'\x55'*workspace)
    add('sequence-overflow',valid,wc=workspace,
        before=b'HBWAS001'+PACK(0,maximum,0,0,0)+bytes(workspace-48))
    require(len(specs)==50,'all fifty independent physical refusal contracts')
    return specs


def control_identity(native,calls,case,label,owner):
    require(type(calls)is list and calls,'complete explicit control call list')
    contexts=set()
    for call in calls:
        require(type(call)is int and call in native,'existing integer control invocation')
        row=native[call][0]
        require(row['case_id']==case and row['label']==label and row['owner']==owner,
            'exact control case/label/image ownership')
        contexts.add(row['context'])
    require(len(contexts)==1,'one retained context per control operation')
    return next(iter(contexts))


def read_private_refusal(row,native,used,spec,case):
    require(row['kind']=='private-invalid' and len(row['calls'])==1 and row['expected_code']==spec['code'],
        'independent single-call refusal kind and return')
    context=control_identity(native,row['calls'],case,row['name'],8)
    code,frame,_=terminal(native,used,row['calls'],8,spec['wire'])
    actual=native[row['calls'][0]][0]
    require(code==spec['code'] and frame==b'','exact physical refusal result')
    require(all(actual[key]==spec[key]for key in ('output_capacity','workspace_capacity','before_sha256')),
        'independent exact refusal capacities and complete initial workspace')
    return context


def read_lifecycle(row,native,used,wire,ready,case):
    """Bind the complete ordered sixteen-event trace, including real growth."""
    request=lambda command,seq=0,code=0,payload=b'',split=0:b'HBWAQ001'+PACK(command,seq,code,len(payload),split)+payload
    frame=lambda kind,seq,payload=b'':b'HBWAR001'+PACK(kind,seq,len(payload),0,0,0,0)+payload
    growth=lambda kind,size:b'HGRWS002'+PACK(kind,size,0)
    valid=request(1,payload=wire+ready,split=len(wire))
    parent=parent_request(ready)
    work=256+len(wire)+len(ready);start_size=64+len(wire);end_size=64+len(parent)
    require(64<len(ready) and 64<end_size<start_size and work>256,
        'fixed original lifecycle fixture exercises both exact growth boundaries')
    # Each record tuple is (return, published bytes, output capacity, workspace
    # capacity). These are independent of all mutable event/result metadata.
    invalid=lambda oc:[(INVALID,b'',oc,work)]
    plan=[(GROW,growth(2,len(ready)),64,512),(len(ready),ready,len(ready),512)]
    first=[(GROW,growth(1,work),64,256),(GROW,growth(2,start_size),64,work),
        (start_size,frame(1,1,wire),start_size,work)]
    second=[(GROW,growth(2,start_size),end_size,work),(start_size,frame(1,2,wire),start_size,work)]
    resume1=request(2,1,len(ready),ready);resume2=request(2,2,len(ready),ready)
    expectations=[
        ('release-idle',8,request(3,1),[(INVALID,b'',64,256)]),
        ('first-start',8,valid,first),
        ('start-while-waiting',8,valid,invalid(start_size)),
        ('release-before-child',8,request(3,1),invalid(start_size)),
        ('lifecycle-fixed-child',7,wire,plan),
        ('stale-child-sequence',8,resume2,invalid(start_size)),
        ('valid-resume-after-output-shrink',8,resume1,[(GROW,growth(2,end_size),64,work),(end_size,frame(2,1,parent),end_size,work)]),
        ('duplicate-resume',8,resume1,invalid(end_size)),
        ('start-before-release',8,valid,invalid(end_size)),
        ('first-release',8,request(3,1),[(64,frame(0,1),end_size,work)]),
        ('duplicate-release',8,request(3,1),invalid(end_size)),
        ('second-start',8,valid,second),
        ('stale-previous-generation',8,resume1,invalid(start_size)),
        ('second-fixed-child',7,wire,plan),
        ('second-resume',8,resume2,[(end_size,frame(2,2,parent),start_size,work)]),
        ('second-release',8,request(3,2),[(64,frame(0,2),start_size,work)])]
    events=row['events']
    require(row['kind']=='lifecycle' and len(events)==16 and [e['name']for e in events]==[e[0]for e in expectations],
        'independent exact sixteen-event lifecycle order')
    context=None;children=set();ordered=[]
    for event,(name,owner,packet,expected)in zip(events,expectations):
        current=control_identity(native,event['calls'],case,name,owner)
        if owner==8:
            if context is None:context=current
            require(current==context,'same retained adapter context across both generations')
        else:
            require(current!=context and current not in children,'fresh fixed planner context for each generation')
            children.add(current)
        code,published,_=terminal(native,used,event['calls'],owner,packet)
        require(len(event['calls'])==len(expected),'complete exact lifecycle growth invocation count')
        for call,(returned,output,oc,wc)in zip(event['calls'],expected):
            actual,actual_wire,actual_frame=native[call]
            require((actual['return_code'],actual_frame,actual['output_capacity'],actual['workspace_capacity'])==(returned,output,oc,wc),
                'exact lifecycle result, growth, capacities and full publication')
        require(code==event['code']==expected[-1][0],'independent lifecycle terminal return')
        if code==INVALID:
            require(event.get('expected_invalid')is True and published==b'','independent lifecycle refusal')
        else:
            require('expected_invalid'not in event and event['frame']==published.hex(),'complete independent lifecycle publication')
        ordered.extend(event['calls'])
    require(len(children)==2 and ordered==list(range(ordered[0],ordered[-1]+1)),
        'complete chronological lifecycle journal without permutation or omission')
    return ordered,{context,*children}


def read_controls(rows,native,data):
    control_domain=json.loads(owned(ROOT,'CONTROL_DOMAIN.json').read_bytes())
    good=next(s for old in data['plan_cases']if old['kind']==3 for s in old['stages']if s['eligible'])
    wire,ready=UNBASE(good['request']),UNBASE(good['actual_result'])
    specs=private_refusal_specs(wire,ready);names=list(specs)
    expected_names=names[:-2]+['whole-json-mismatch','actual-planner-utf8-rejection']+names[-2:]+['complete-lifecycle-and-growth']
    require(len(rows)==control_domain['cases']==53 and [r['name']for r in rows]==control_domain['names']==expected_names,
        'complete independently ordered ABI and lifecycle domain')
    used=set();contexts=set();ordered=[];counts=collections.Counter()
    for index,row in enumerate(rows):
        name=row['name'];case=200000+index
        if name in specs:
            context=read_private_refusal(row,native,used,specs[name],case)
            require(context not in contexts,'fresh physical refusal context');contexts.add(context)
            ordered.extend(row['calls']);counts['private_refusal_controls']+=1
        elif name in ('whole-json-mismatch','actual-planner-utf8-rejection'):
            require(row['kind']=='fixed-child-mismatch','exact actual child control kind')
            detail=2 if name=='whole-json-mismatch'else 1
            changed_wire,changed_ready=bytearray(wire),bytearray(ready)
            if detail==2:changed_ready[-2]^=1
            else:changed_wire[304]=255
            require(row['expected_detail']==detail,'independent fixed child mismatch class')
            composed=row['composition'];owner_context=None;child_context=None
            for field,suffix,owner in [('start_calls','start',8),('planner_calls','fixed-child',7),('resume_calls','resume',8),('release_calls','release',8)]:
                calls=composed[field];current=control_identity(native,calls,case,name+'-'+suffix,owner)
                if owner==8:
                    if owner_context is None:
                        owner_context=current;first=native[calls[0]][0]
                        require((first['output_capacity'],first['workspace_capacity'])==(64,256),'actual child control initial adapter capacities')
                    require(current==owner_context,'one retained mismatch adapter context')
                else:
                    child_context=current;first=native[calls[0]][0]
                    require((first['output_capacity'],first['workspace_capacity'])==(64,512),'actual fixed child initial capacities')
                ordered.extend(calls)
            require(owner_context!=child_context and not contexts.intersection((owner_context,child_context)),
                'fresh exact mismatch owner and child contexts')
            contexts.update((owner_context,child_context))
            composition(composed,native,used,bytes(changed_wire),bytes(changed_ready),detail)
            counts['actual_child_mismatch_controls']+=1
        else:
            calls,current=read_lifecycle(row,native,used,wire,ready,case)
            require(not contexts.intersection(current),'fresh retained lifecycle and planner contexts')
            contexts.update(current);ordered.extend(calls);counts['lifecycle_controls']+=1
    require(used==set(native) and ordered==list(range(1,len(native)+1)),
        'entire actual control journal in exact domain and event order')
    counts['control_cases']=53
    return used,counts


def read_worker(folder,source,images_pin,mode,group,data):
    capture=json.loads(owned(folder,'CAPTURE.json').read_bytes())
    require(capture['schema']=='hepta.runtime.binary-write-adapter.capture.v1' and capture['status']=='CAPTURE_COMPLETE','complete raw worker capture')
    require(capture['source']==source and capture['images']==images_pin and capture['mode']==mode and capture['group']==group,'exact worker source/image/domain identity')
    require(capture['domain']==pin(ROOT/'inputs/DOMAIN.json') and capture['parent_effects_executed']==capture['original_rust_executions']==0 and capture['whole_runtime_replaced']is False,'worker unchanged qualification scope')
    rows=json.loads(owned(folder,'RESULTS.json').read_bytes());require(capture['cases']==len(rows),'entire result domain')
    native,summary=records(folder);require(summary==capture['summary'],'all full native record totals')
    used=set();counts=collections.Counter()
    if mode=='typed':
        require(len(rows)==196,'all original write typed cases')
        for row,old in zip(rows,data['typed_write_cases']):
            require((row['case_id'],row['name'])==(old['case_id'],old['name']),'original write typed identity')
            raw=UNBASE(old['raw_json']);_,value,_=terminal(native,used,row['value_calls'],1,b'HJSMS002'+PACK(1,len(raw))+raw)
            require(value==UNBASE(old['actual_map']) and value.hex()==row['value_frame'],'whole actual Map matches retained original')
            if old['actual_typed']is None:require(row['typed_calls']==[] and row['typed_frame']is None,'original Map rejection has no typed call')
            else:
                _,typed,_=terminal(native,used,row['typed_calls'],4,b'HBPRQ001'+PACK(len(value)-32,3)+value[32:])
                require(typed==UNBASE(old['actual_typed']) and typed.hex()==row['typed_frame'],'complete actual typed success/error matches original')
            counts['original_typed_inputs']+=1
    elif mode=='plan':
        oldrows=[r for r in data['plan_cases']if r['group']==group]
        require(len(rows)==len(oldrows),'complete original planner group retained')
        for row,old in zip(rows,oldrows):
            require([row[k]for k in ('case_id','kind','name')]==[old[k]for k in ('case_id','kind','name')] and len(row['stages'])==len(old['stages']),'whole original planner case/stages')
            for stage,prior in zip(row['stages'],old['stages']):
                wire,ready=UNBASE(prior['request']),UNBASE(prior['actual_result'])
                code,actual,_=terminal(native,used,stage['calls'],7,wire)
                require(code==stage['code']==len(ready) and actual==ready and actual.hex()==stage['result'],'every original planner result byte unchanged')
                if prior['eligible']:
                    composition(stage['composition'],native,used,wire,ready);counts['original_write_ready']+=1
                else:require(stage['composition']is None,'no adapter effect on earlier error/non-write phases')
            counts['original_plan_inputs']+=1
            if old['kind']==3:counts['original_write_plan_inputs']+=1
    elif mode=='interface':
        require(len(rows)==256,'entire parent interface projection retained')
        null_error=None
        for old in data['typed_write_cases']:
            raw=json.loads(UNBASE(old['raw_json']))
            if type(raw)is dict and raw.get('expected_version','missing')is None and old['actual_typed']is not None:
                frame=UNBASE(old['actual_typed'])
                if WORD(frame,8)==1 and b'null' in frame[256:]:null_error=frame[256:];break
        require(null_error is not None,'retained actual original null String diagnostic')
        for row,old in zip(rows,data['parent_interface_cases']):
            require(row['original_id']==old['id'] and row['case_id']==100000+old['id'] and row['name']==old['name'],'exact projected parent input identity')
            root,raw=parent_projection(old)
            _,value,_=terminal(native,used,row['value_calls'],1,b'HJSMS002'+PACK(1,len(raw))+raw)
            require(WORD(value,8)==0 and json.loads(value[32:])==json.loads(raw) and value.hex()==row['value_frame'],'actual complete Map predecessor')
            _,typed,_=terminal(native,used,row['typed_calls'],4,b'HBPRQ001'+PACK(len(value)-32,3)+value[32:])
            require(typed.hex()==row['typed_frame'],'actual complete typed predecessor')
            if old['expected_version']is None:
                require(WORD(typed,8)==1 and typed[256:]==null_error and row['planner_calls']==[] and row['composition']is None,'None remains original typed String error before any plan/parent')
                counts['interface_typed_null_rejections']+=1
            else:
                require(WORD(typed,8)==0,'all original String fields remain typed')
                feedback=b'HRCFGM01'+PACK(0,0,len(root))+root
                wire=b'HBPLQ001'+PACK(2,0,len(typed),len(feedback),0)+typed+feedback
                code,ready,_=terminal(native,used,row['planner_calls'],7,wire)
                require(code==row['planner_code'] and ready.hex()==row['planner_frame'],'entire actual interface planner result')
                if WORD(ready,8)==3:
                    result=composition(row['composition'],native,used,wire,ready)
                    desired=[root,json.loads(raw)['path'].encode(),old['expected_version'].encode(),old['data_base64'].encode()]
                    require(result[160:]==b''.join(desired),'parent bytes remain exact including UTF-8/NUL/Base64/version')
                    counts['interface_ready']+=1
                else:
                    require(WORD(ready,8)==1 and row['composition']is None,'original encoded-payload precondition remains before adapter')
                    counts['interface_plan_rejections']+=1
            counts['parent_interface_inputs']+=1
    else:
        require(mode=='controls','declared control worker')
        used,counts=read_controls(rows,native,data)
    require(used==set(native),'every original and control native call attributed exactly once')
    return dict(counts=counts,summary=summary)


def read_all(capture,images,source_sha256,capture_sha256):
    require(pin(ROOT/'SOURCE_MANIFEST.json')['sha256']==source_sha256,'external exact source manifest identity')
    source=source_evidence();image_build=read_images(images,source);images_pin=pin(images/'IMAGES.json')
    require(pin(owned(capture,'RUN.json'))['sha256']==capture_sha256,'external completed run identity')
    run=json.loads(owned(capture,'RUN.json').read_bytes())
    require(run['schema']=='hepta.runtime.binary-write-adapter.run.v1' and run['status']=='COMPLETE_CAPTURE_AWAITING_DATA_READER','complete natural process domain')
    require(run['source']==source and run['images']==images_pin and run['whole_limit_seconds']==1800 and run['elapsed_ns']<=1800*1_000_000_000,'source-bound whole deadline')
    require(run['original_rust_executions']==run['parent_effects_executed']==0 and run['whole_runtime_replaced']is False and run['public_binary_write_registered']is False,'honest qualification scope')
    domain,data=inputs();groups=list(dict.fromkeys(row['group']for row in data['plan_cases']))
    jobs=[('typed','typed',None)]+[('plan-'+g,'plan',g)for g in groups]+[('parent-interface','interface',None),('controls','controls',None)]
    require(run['declared_jobs']==[x[0]for x in jobs] and len(run['completed'])==len(jobs)==27,'complete 24 groups plus typed/interface/control processes')
    counts=collections.Counter();calls=0;logical=0;by_owner=collections.Counter();processes=[]
    for row,(label,mode,group)in zip(run['completed'],jobs):
        require((row['label'],row['mode'],row['group'])==(label,mode,group),'original process identity')
        require(json.loads(owned(capture,label+'.process.json').read_bytes())==row,'complete process receipt')
        require(row['returncode']==0 and row['timed_out']is False and row['cleanup_used']is False and row['limit_seconds']==60 and row['cleanup_seconds']==5,'original deadlines and natural termination')
        require(row['elapsed_ns']<=60*1_000_000_000 and pin(owned(capture,label+'.stdout'))==row['stdout'] and pin(owned(capture,label+'.stderr'))==row['stderr'] and row['stderr']['bytes']==0,'full original process streams/time')
        result=read_worker(capture/label,source,images_pin,mode,group,data)
        counts.update(result['counts']);calls+=result['summary']['calls'];logical+=result['summary']['logical_bytes'];by_owner.update(result['summary']['by_owner'])
        processes.append(dict(label=label,elapsed_ns=row['elapsed_ns'],**result['summary']))
    require(counts['original_typed_inputs']==196 and counts['original_plan_inputs']==433 and counts['original_write_plan_inputs']==59 and counts['original_write_ready']==19,'all original domains and real ready count')
    require(counts['parent_interface_inputs']==256 and counts['interface_typed_null_rejections']==2 and counts['interface_ready']+counts['interface_plan_rejections']==254,'complete parent ABI projection without false filesystem credit')
    return dict(schema='hepta.runtime.binary-write-adapter.read.v1',status='COMPLETE_NATIVE_ADAPTER_DATA_PASS',counts=dict(counts),
        actual_native_entries=calls,complete_native_bytes=logical,by_owner=dict(by_owner),processes=processes,
        source_sha256=source_sha256,capture_sha256=capture_sha256,images=images_pin,
        actual_hia_compilations=4,compiler_commit=HEPTA,compiler_sha256=B3,
        planner_and_typed_images_equal_current_product=True,adapter_byte_projection_qualified=True,
        native_executions_by_reader=0,compiler_executions_by_reader=0,new_original_rust_executions=0,parent_effects_executed=0,
        old_body_101_requalified=False,parent_256_effect_domain_requalified=False,
        production_carrier_installed=False,public_binary_write_registered=False,
        host_audit_ssh_lifecycle_qualified=False,whole_runtime_replaced=False)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--capture',type=Path,required=True);p.add_argument('--images',type=Path,required=True)
    p.add_argument('--source-sha256',required=True);p.add_argument('--capture-sha256',required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();require(not a.output.exists(),'fresh DATA receipt')
    result=read_all(a.capture,a.images,a.source_sha256,a.capture_sha256)
    save(a.output,result);print(json.dumps({k:v for k,v in result.items()if k!='processes'},sort_keys=True))


if __name__=='__main__':main()
