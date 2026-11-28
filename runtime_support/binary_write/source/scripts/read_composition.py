"""Independent complete preparation and same-process fixed-child byte custody."""
import gzip,hashlib,importlib.util,json,struct,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'adapter/scripts'))
spec=importlib.util.spec_from_file_location('composition_retained_adapter_reader',ROOT/'adapter/scripts/read_capture.py')
old=importlib.util.module_from_spec(spec);spec.loader.exec_module(old)
from evidence_common import decode,encoded,pin,require
from protocol import U
PACK=lambda *v:struct.pack('<'+'Q'*len(v),*v)
INVALID=0xffffffff
GROW=0xffffffd0


def mismatch_frame(actual,child,sequence,detail):
    require(type(sequence)is int and sequence>0 and type(detail)is int and detail in(1,2),'fixed mismatch identity')
    require(actual==b'HBWAR001'+PACK(3,sequence,len(child),detail,0,0,0)+child,'whole actual child remains in mismatch publication')
    return actual


def parent_packet(query):
    require(type(query['expected_version'])is str,'composition requires original typed String version')
    parts=[query[k].encode()for k in('root','path','expected_version','data_base64')]
    return b'HBPWQ001'+PACK(1,0,1,*map(len,parts),1,0,0,sum(map(len,parts)))+b''.join(parts)


class Prepared:
    def __init__(self,folder,images):
        self.folder=folder;self.native,self.summary=old.records(folder);self.used=set();self.cursor=0
        self.rows=decode((folder/'PREPARED.json').read_bytes());self.receipt=decode((folder/'PREPARATION.json').read_bytes())
        require(self.receipt==dict(schema='hepta.runtime.binary-write-composition-preparation.v1',images=pin(images/'IMAGES.json'),summary=self.summary,requests=len(self.rows),parent_effect_calls=0),'entire preparation inventory')
        _,frozen=old.inputs()
        self.null_error=None
        for row in frozen['typed_write_cases']:
            value=json.loads(old.UNBASE(row['raw_json']))
            if type(value)is dict and value.get('expected_version','missing')is None and row['actual_typed']is not None:
                typed=old.UNBASE(row['actual_typed'])
                if U(typed,8)==1 and b'null'in typed[256:]:self.null_error=typed[256:];break
        require(self.null_error is not None,'actual frozen original null String rejection')

    def request(self,ordinal,query,case,label,actual_packet):
        require(type(ordinal)is int and ordinal==self.cursor+1 and ordinal<=len(self.rows),'every preparation ordinal in exact application order')
        row=self.rows[self.cursor];self.cursor+=1
        require((row['case_id'],row['label'])==(case,label),'full preparation identity')
        value={'host':'composition-fixture',**{name:query[name]for name in('path','expected_version','data_base64')}}
        raw=json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
        require(bytes.fromhex(row['raw_json_hex'])==raw,'complete actual public argument bytes')
        _,mapped,_=old.terminal(self.native,self.used,row['value_calls'],1,b'HJSMS002'+PACK(1,len(raw))+raw)
        require(U(mapped,8)==0 and decode(mapped[32:])==value and row['value_frame']==mapped.hex(),'actual Map fields preserve full query')
        _,typed,_=old.terminal(self.native,self.used,row['typed_calls'],4,b'HBPRQ001'+PACK(len(mapped)-32,3)+mapped[32:])
        require(row['typed_frame']==typed.hex(),'actual typed result bytes')
        for calls,owner,suffix in((row['value_calls'],1,'-map'),(row['typed_calls'],4,'-typed')):
            require(all(self.native[n][0]['case_id']==case and self.native[n][0]['label']==label+suffix and self.native[n][0]['owner']==owner for n in calls),'whole raw predecessor label/case/owner binding')
        if query['expected_version']is None:
            require(U(typed,8)==1 and typed[256:]==self.null_error and row['planner_calls']==[] and row['request_hex']is None and actual_packet is None,'None remains original String rejection with no planner/adapter/parent call')
            return None
        require(U(typed,8)==0,'admitted String query remains typed success')
        root=query['root'].encode();feedback=b'HRCFGM01'+PACK(0,0,len(root))+root
        plan=b'HBPLQ001'+PACK(2,0,len(typed),len(feedback),0)+typed+feedback
        code,ready,_=old.terminal(self.native,self.used,row['planner_calls'],7,plan)
        require(code==len(ready)==row['planner_return'] and row['planner_request_hex']==plan.hex() and row['ready_hex']==ready.hex(),'whole actual ready planner result')
        require(all(self.native[n][0]['case_id']==case and self.native[n][0]['label']==label+'-planner'for n in row['planner_calls']),'fixed actual ready planner identity')
        packet=b'HBWAQ001'+PACK(1,0,0,len(plan)+len(ready),len(plan))+plan+ready
        require(actual_packet==packet and row['request_hex']==packet.hex(),'entire admitted request consumed by actual composition')
        require(old.parent_request(ready)==parent_packet(query),'ready JSON and public query produce one exact parent packet')
        return dict(start=packet,plan=plan,ready=ready,parent=parent_packet(query))

    def finish(self):
        require(self.cursor==len(self.rows) and self.used==set(self.native),'every preparation row/native call credited once')
        return self.receipt


def composed_calls(rows):
    """Five full raw spans per entry, strict capacities and owned continuations."""
    require(len(rows)%5==0,'complete five-span composition journal')
    result={};last={};caps={7:[4096,4096],8:[4096,4096]};pending={};context=None
    for pos in range(0,len(rows),5):
        group=rows[pos:pos+5];heads=[row['head']for row in group];arrays=[row['payload']for row in group]
        first=heads[0];owner=U(first,16);ordinal=pos//5+1
        require(owner in(7,8) and [U(h,8)for h in heads]==[1,10,12,2,11],'fixed pure owner and complete span order')
        if context is None:context=U(first,80)
        require(context>0 and all(h[:8]==b'HBCWJR01' and len(h)==128 and U(h,16)==owner and U(h,24)==1
                and U(h,56)==ordinal and U(h,80)==context for h in heads),'actual one context/generation and exact entry ordinal')
        require([row['index']for row in group]==list(range(group[0]['index'],group[0]['index']+5)),'no hidden frame inside one fixed pure call')
        wire,before,old_output,out,after=arrays
        command=U(wire,8)if owner==7 and len(wire)>=16 else None
        phase=2 if command==3 else 1
        sequence=0 if command==1 else 1
        planner_generation=0 if command==1 else 1
        adapter_held=1 if command==3 else 0
        require(all(U(h,40)==phase and U(h,96)==sequence and U(h,104)==planner_generation
                    and U(h,112)==0 and U(h,120)==adapter_held for h in heads),
                'exact live wrapper phase/sequence/generation/borrow flags for each fixed call')
        require(all(U(h,32)==len(a)for h,a in zip(heads,arrays)) and len(before)==len(after)==U(first,64)
                and len(out)==len(old_output)==U(first,72) and all(U(h,88)==len(wire)for h in heads),'entire actual input/output/workspace capacities')
        require(all(U(h,64)==len(before)and U(h,72)==len(out)for h in heads),'stable full capacities during one HIA call')
        require(old_output==b'\xa5'*len(old_output),'whole pure output initial fill')
        expected_work,expected_output=caps[owner]
        if owner in pending:
            which,needed=pending.pop(owner);wanted=(needed+4095)&~4095
            if which==1:expected_work=wanted
            else:expected_output=wanted
        require((len(before),len(out))==(expected_work,expected_output),'only the actual requested rounded arena may grow')
        caps[owner]=[expected_work,expected_output]
        previous=last.get(owner,b'')
        require(len(before)>=len(previous) and before==previous+bytes(len(before)-len(previous)),'all owned workspace bytes preserved across real growth and other owners')
        code=U(heads[3],48);require(U(heads[4],48)==code,'actual full return agrees across both after spans')
        fixed_owner=8 if owner==7 else 7
        published=old.publication(fixed_owner,code,out,before,after)
        if code==GROW:pending[owner]=(U(out,8),U(out,16))
        elif owner==7 and code<old.LIMIT:
            command=U(wire,8);expected=bytearray(before)
            if command==1:
                require(U(published,8)==1 and U(published,16)==U(before,16)+1 and U(published,32)==0,'actual adapter wait generation')
                expected[:48]=b'HBWAS001'+PACK(1,U(published,16),U(wire,40),len(wire)-48-U(wire,40),len(wire)-48)
                expected[256:256+len(wire)-48]=wire[48:]
                require(published[64:]==wire[48:48+U(wire,40)],'one exact private planner request')
            elif command==2:
                require(U(before,8)==1 and U(wire,16)==U(before,16)==U(published,16) and U(published,8)in(2,3),'bound actual child completion')
                struct.pack_into('<Q',expected,8,2)
            else:
                require(command==3 and U(before,8)==2 and U(wire,16)==U(before,16)==U(published,16) and U(published,8)==0,'actual held adapter release')
                struct.pack_into('<Q',expected,8,0);expected[24:48]=bytes(24)
            require(after==bytes(expected),'only declared complete adapter state transition')
        last[owner]=after
        result[ordinal]=dict(owner=owner,code=code,input=wire,output=out,frame=published,before=before,after=after,head=first,
                             first_index=group[0]['index'],last_index=group[-1]['index'])
    require(not pending,'no unconsumed actual pure growth request')
    return result,last,context


def complete_chain(calls,at,owner,wire):
    start=at
    while True:
        require(at in calls and at-start<12,'complete bounded fixed-owner invocation')
        row=calls[at];require(row['owner']==owner and row['input']==wire,'entire exact same-process fixed-owner input')
        at+=1
        if row['code']!=GROW:return at,row,start


def check_flow(rows,prepared,store,row,parent_input,parent_first,parent_last,finished=True):
    calls,last,address=composed_calls(rows)
    at,first,start=complete_chain(calls,1,7,prepared['start'])
    require(first['frame'][:8]==b'HBWAR001' and U(first['frame'],8)==1 and U(first['frame'],16)==1
            and first['frame'][64:]==prepared['plan'],'actual adapter yields exact original planner')
    at,child,_=complete_chain(calls,at,8,prepared['plan'])
    require(child['code']==len(prepared['ready']) and child['frame']==prepared['ready'],'actual same-process planner equals whole actual predecessor ready frame')
    resume=b'HBWAQ001'+PACK(2,1,child['code'],len(child['frame']),0)+child['frame']
    at,done,_=complete_chain(calls,at,7,resume)
    require(done['frame'][:8]==b'HBWAR001' and (U(done['frame'],8),U(done['frame'],16),U(done['frame'],32))==(2,1,0)
            and done['frame'][64:]==prepared['parent']==parent_input,'actual HIA parent packet is precisely the first actual parent call')
    require(done['last_index']<parent_first<=parent_last,'fixed parent invocation begins only after the actual adapter permission')
    if not finished:
        require(at==len(calls)+1 and U(last[7],8)==2,'cancelled parent retains completed adapter without fabricated release')
        return dict(calls=len(calls),parent_started=True,adapter_released=False)
    held_release(prepared,store,row)
    at,released,release_start=complete_chain(calls,at,7,b'HBWAQ001'+PACK(3,1,0,0,0))
    require(released['code']==64 and released['frame']==b'HBWAR001'+PACK(0,1,0,0,0,0,0),'actual exact adapter release acknowledgement')
    require(at==len(calls)+1 and calls[release_start]['first_index']>parent_last,'no additional native invocation or release before completed parent work')
    c=store.get(row['snapshots']['composition']['bytes']);p=store.get(row['snapshots']['context']['bytes'])
    require(len(c)==4096 and c[:8]==b'HBCWCI01' and U(c,8)==4096 and U(c,56)==2 and U(c,192)==1
            and U(c,568)==U(c,576)==1 and U(c,640)==0 and U(c,584)==64,'held root has both real owned loans and no private failure')
    require(U(c,384)==row['snapshots']['context']['actual_process_bytes']['address'] and U(c,376)==U(p,376)
            and U(c,408)==U(p,408) and U(c,480)==U(p,480)==row['process']['pid'],'actual wrapper owns precisely this observed parent and shared capabilities')
    obs=row['snapshots']['composition']['actual_process_bytes'];require(obs['writes']==0 and obs['observation']=='process_vm_readv' and obs['address']==address,'actual full wrapper address from independent process memory')
    matches=[x for x in obs['candidates']if store.get(x['bytes'])==c]
    require(len(matches)==1 and matches[0]['address']==address and store.get(matches[0]['second'])==c,'one actual stable complete wrapper context')
    require(store.get(row['snapshots']['adapter_workspace']['bytes'])==done['after'] and store.get(row['snapshots']['planner_workspace']['bytes'])==child['after'],'both held complete pure workspaces are their actual last HIA outputs')
    require(store.get(row['snapshots']['adapter_output']['bytes'])==done['output'] and store.get(row['snapshots']['planner_output']['bytes'])==child['output'],'entire held pure output buffers')
    initial=store.get(row['snapshots']['composition_input']['bytes']);require(U(c,80)==len(prepared['start']) and initial[:U(c,80)]==prepared['start'] and initial[U(c,80):]==bytes(len(initial)-U(c,80)),'entire immutable original adapter request custody')
    end=store.get(row['snapshots']['composition_after_release']['bytes']);work=store.get(row['snapshots']['adapter_after_release']['bytes'])
    require(len(end)==4096 and end[:8]==b'HBCWCI01' and U(end,56)==U(end,568)==U(end,576)==U(end,640)==0
            and U(end,248)==len(calls) and U(end,216)==1 and work==last[7] and U(work,8)==0,'actual complete root/adapter release and precise invocation count')
    require(U(c,248)==release_start-1 and U(c,592)==U(end,592)==1,'one actual fresh planner generation and held-before-release count')
    return dict(calls=len(calls),parent_started=True,adapter_released=True)


def held_release(prepared,store,row):
    """Whole context transitions and every held/result byte, without live calls."""
    c=store.get(row['snapshots']['composition']['bytes']);p=store.get(row['snapshots']['context']['bytes'])
    end=store.get(row['snapshots']['composition_after_release']['bytes']);p_end=store.get(row['snapshots']['parent_after_release']['bytes'])
    frame=store.get(row['application_frame']);parent_output=store.get(row['snapshots']['output']['bytes'])
    require(len(c)==len(p)==len(end)==len(p_end)==4096 and c[:8]==end[:8]==b'HBCWCI01' and p[:8]==p_end[:8]==b'HBPWCI01','entire actual held and released contexts')
    require(U(c,56)==U(p,56)==2 and U(c,168)==U(p,168)==len(frame) and parent_output[:len(frame)]==frame,'entire wrapper result equals still-held parent result')
    require(U(c,384)==row['snapshots']['context']['actual_process_bytes']['address'] and U(c,376)==U(p,376)
            and U(c,408)==U(p,408) and U(c,480)==U(p,480)==row['process']['pid'],'one exact parent/shared pool/entropy capability graph')
    expected=bytearray(c)
    for at in(56,168,176,568,576,640):struct.pack_into('<Q',expected,at,0)
    struct.pack_into('<Q',expected,208,48);struct.pack_into('<Q',expected,248,U(c,248)+1);struct.pack_into('<Q',expected,632,1)
    require(end==bytes(expected),'complete root release changes only declared control words')
    expected_parent=bytearray(p)
    for at in(56,168,176):struct.pack_into('<Q',expected_parent,at,0)
    require(p_end==bytes(expected_parent),'complete parent release changes only its three declared words')
    held=store.get(row['snapshots']['adapter_workspace']['bytes']);finished=store.get(row['snapshots']['adapter_after_release']['bytes'])
    expected_work=bytearray(held);struct.pack_into('<Q',expected_work,8,0);expected_work[24:48]=bytes(24)
    require(finished==bytes(expected_work),'entire adapter workspace preserved by actual release')
    out=store.get(row['snapshots']['adapter_output_after_release']['bytes'])
    require(out==b'HBWAR001'+PACK(0,1,0,0,0,0,0)+b'\xa5'*(len(out)-64),'complete actual final adapter acknowledgement and tail')
    for label,context in(('composition',c),('composition_after_release',end),('context',p),('parent_after_release',p_end)):
        obs=row['snapshots'][label]['actual_process_bytes']
        require(obs['writes']==0 and obs['observation']=='process_vm_readv','actual independent context observation is read-only')
        matches=[v for v in obs['candidates']if store.get(v['bytes'])==context]
        require(len(matches)==1 and matches[0]['address']==obs['address'] and store.get(matches[0]['second'])==context,'one actual stable complete observed context')
    require(row['snapshots']['composition']['actual_process_bytes']['address']==row['snapshots']['composition_after_release']['actual_process_bytes']['address']
            and row['snapshots']['context']['actual_process_bytes']['address']==row['snapshots']['parent_after_release']['actual_process_bytes']['address'],'release does not replace either actual context')
    return c,end


def check_unobserved(prepared,store,row):
    c,end=held_release(prepared,store,row)
    require(U(c,192)==1 and U(c,216)==1 and U(c,568)==U(c,576)==U(c,592)==1 and U(c,640)==0
            and U(c,584)==64 and 3<=U(c,248)<=36,'actual held unobserved complete owner state')
    work=store.get(row['snapshots']['adapter_workspace']['bytes'])
    body=prepared['start'][48:]
    expected=b'HBWAS001'+PACK(2,1,len(prepared['plan']),len(prepared['ready']),len(body))+bytes(208)+body
    require(work==expected+bytes(len(work)-len(expected)),'entire actual held private input and adapter state')
    out=store.get(row['snapshots']['adapter_output']['bytes'])
    frame=b'HBWAR001'+PACK(2,1,len(prepared['parent']),0,0,0,0)+prepared['parent']
    require(out==frame+b'\xa5'*(len(out)-len(frame)),'actual complete parent request publication')
    planner=store.get(row['snapshots']['planner_output']['bytes']);ready=prepared['ready']
    require(planner==ready+b'\xa5'*(len(planner)-len(ready)) and U(c,232)==U(c,240)==len(ready),'entire actual fixed planner result')
    input_value=store.get(row['snapshots']['composition_input']['bytes'])
    require(U(c,80)==len(prepared['start']) and input_value==prepared['start']+bytes(len(input_value)-len(prepared['start'])),'entire immutable actual original input')
    return dict(calls=U(end,248),parent_started=True,adapter_released=True,observer=False)
