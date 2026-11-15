"""Complete actual race predecessor bytes, separate from the kernel/private owner gate."""
from pathlib import Path
import struct
from common import Files,require,pin,same,frames,parse_wire,snapshot,loads
from race_cases import race_cases
def evidence(root,origins):
    root=Path(root);d=root/'domains/races';f=Files(origins)
    res=f.json(d/'RESULT.json');require(res['schema']=='hepta.runtime.text-publication-native-races.v1' and res['status']=='PASS' and res['cases']==20,'completed actual native race domain')
    corpus=f.json(d/'corpus.json',res['corpus']);same(corpus,race_cases(),'one exact frozen race input generator')
    for name,expected in res['source_pins'].items():f.raw(root/'source/scripts'/name,expected)
    p=f.json(d/'process/process.json');same(p,res['process'],'actual native race process')
    require(p['exit_code']==0 and p['failure'] is None and p['killed_by_harness'] is False,'complete native race process exit')
    streams={n:f.raw(d/'process'/q['file'],{k:q[k] for k in ('bytes','sha256')}) for n,q in p['streams'].items()}
    require(set(streams)=={'stdin','stdout','stderr'},'all native race streams')
    outputs=frames(streams['stdout']);require(len(outputs)==40==len(p['exchanges']),'complete native START/DROP output frames')
    rawfx=streams['stderr'];fx=f.json(d/'effects.json',res['effects'])
    require(len(rawfx)==len(fx)*256 and type(res['native_effects']) is int and len(fx)==res['native_effects'],'all actual race kernel effects')
    for i,e in enumerate(fx):
        raw=rawfx[i*256:(i+1)*256];require(raw[:8]==b'HTXTEF01' and raw[64:72]==b'HTXTFX01','actual native effect magic')
        gen,seq,kind,phase,retval,wcap,z=struct.unpack_from('<7Q',raw,8);q=struct.unpack_from('<16Q',raw,64)
        require(seq==i+1 and q[1:4]==(seq,gen,kind) and q[13]==1 and q[12]==q[14]==q[15]==z==0,'actual completed race effect')
        signed=retval if retval<1<<63 else retval-(1<<64)
        same([e['generation'],e['sequence'],e['kind'],e['phase'],e['raw_linux_return'],e['workspace_capacity']],[gen,seq,kind,phase,signed,wcap],'complete race effect header')
        same(e['args'],list(q[4:10]),'actual complete race syscall arguments')
        require(e['value']==q[10] and e['errno']==q[11] and e['stream_offset']==i*256 and e['frame_sha256']==pin(raw)['sha256'],'actual effect payload and raw span')
    last=0;rows=[]
    for i,(desc,row) in enumerate(zip(corpus,res['rows'])):
        case=d/'cases'/desc['name'];same(f.json(case/'case.json'),row,'whole native race case')
        require(row['name']==desc['name'] and row['ordinal']==i and row['status']=='PASS','native race identity')
        wire=f.raw(case/'input.bin',row['input']);parse_wire(wire)
        record=f.raw(case/'record.bin',row['record']);drop=f.raw(case/'drop-record.bin')
        require(record==outputs[i*2] and drop==outputs[i*2+1],'whole native race output bytes')
        require(record[:8]==b'HTXTER01' and record[64:72]==b'HTXTR001','native result headers')
        code,gen,seq,pn,live,phase,z=struct.unpack_from('<7Q',record,8)
        require(code==pn==len(record)-64 and gen==i+1 and phase==100 and live==z==0,'actual native race terminal')
        require(row['generation']==gen and row['first_sequence']==last+1 and row['last_sequence']==seq and row['effects']==seq-last,'complete actual case effect interval')
        selected=fx[last:seq];require(all(e['generation']==gen for e in selected),'case effect generation')
        require(drop==b'HTXTER01'+struct.pack('<7Q',64,gen,seq,64,0,0,0)+b'HTXTR001'+struct.pack('<7Q',2,0,0,0,gen,seq,0),'exact terminal DROP')
        for j,request in ((i*2,wire),(i*2+1,b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,gen,0))):
            x=p['exchanges'][j];a=x['started_stream_offsets'];b=x['ended_stream_offsets']
            require(x['timeout_seconds']==60 and 0<x['elapsed_seconds']<60,'native actual unchanged exchange budget')
            chunk=streams['stdin'][a['stdin']:b['stdin']];head=struct.pack('<Q',len(request))+request
            require(chunk.startswith(head),'complete native original input bytes')
            tail=chunk[len(head):]
            wants=b''.join(b'HTXTACK1'+struct.pack('<2Q',e['generation'],e['sequence']) for e in selected) if j%2==0 else b''
            require(tail==wants,'complete identity-only real effect ACK sequence')
            require(streams['stdout'][a['stdout']:b['stdout']]==struct.pack('<Q',len(outputs[j]))+outputs[j],'complete actual response stream span')
            require(streams['stderr'][a['stderr']:b['stderr']]==(rawfx[last*256:seq*256] if j%2==0 else b''),'complete effect stream span')
        actor=f.json(case/'actor.json',row['actor']);trigger=actor['trigger_receipt']
        target=next(e for e in selected if e['sequence']==row['actor_sequence'])
        same([trigger[k] for k in ('generation','sequence','kind','phase','args','value','errno','workspace_capacity')],[target[k] for k in ('generation','sequence','kind','phase','args','value','errno','workspace_capacity')],'external actor triggered by actual completed native effect')
        require(actor['effect_results_injected'] is False and actor['monotonic_end_ns']>=actor['monotonic_start_ns'],'actual external actor')
        same(actor['operation'],desc['race']['action'],'exact frozen external mutation')
        before=snapshot(f,case/'before.json',d/'blobs');after=snapshot(f,case/'after.json',d/'blobs')
        published=sum(e['kind']==17 and e['errno']==0 for e in selected)
        require(published==int(desc['race']['published']) and row['published'] is desc['race']['published'],'actual publication independent of later success')
        rows.append({'ordinal':i,'name':desc['name'],'wire':str(case/'input.bin'),'record':str(case/'record.bin'),
            'before':str(case/'before.json'),'after':str(case/'after.json'),'actor':str(case/'actor.json'),
            'published':published,'effects':len(selected)})
        last=seq
    require(last==len(fx),'all native race effects consumed')
    return {'schema':'hepta.runtime.text-publication-race-predecessor.v1','status':'PASS','cases':20,'actual_native_effects':len(fx),
            'actual_external_mutations':20,'rows':rows,'artifact_sha256':f.artifacts,'new_native_calls':0,
            'detailed_kernel_private_qualification_in_separate_native_reader':True}
