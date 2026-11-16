"""Read the complete fixed-engine edge fixture without executing its images.

The frame emitter and unused-capability traps are qualification fixtures. This
reader does not turn them into a public-handler or SDK scheduling claim.
"""
import argparse, ast, collections, hashlib, json, pathlib, re, struct, sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from read_port import read, doc, sha, get, words, journal_records, WORKER_MAGICS
from worker_projection import verify_projection, decode_body
from engine_edges import domain
from build_engine_fixture import WRAPPER

OLD = '803544707acae3b30a6274fe16cf0ed4bb9d0ad5a5798ff5eb0dea41fa45b7fd'
NEW = '1b101a553b9f2cfe601179d143f6eff639220c845769ddb61835fc1939cebe39'
IMAGES = {'old': (6484, '6c58347ae30687fe2458cd9cfe9dcce63242665050e66bead6ab51b851618900'),
          'new': (6582, 'fcf1a36be142a2b06735f4806207fd085418642ec8457f7ca40471304a352548')}
PORT = '006f3635c31ed8ac4a590933ce9081604d1353bebaacfb19ac92a0f91b243536'
INVALID = 0xffffffff
DELIVERY = 0xffffffcd

def processes(folder, commands):
    labels = set(commands)
    assert {p.name for p in (folder/'processes').iterdir()} == {n+'.'+s for n in labels for s in ('json','stdout','stderr')}
    parent = None
    for name, command in commands.items():
        row = doc(folder/'processes'/(name+'.json'))
        assert row['label'] == name and row['command'] == command
        assert row['started'] is True and row['timed_out'] is False and row['returncode'] == 0
        assert row['pid'] == row['pgid'] > 0 and row['parent_pid'] > 0
        assert row['timeout_seconds'] == 60 and 0 <= row['elapsed_ns'] <= 60_000_000_000
        if parent is None: parent = row['parent_pid']
        assert row['parent_pid'] == parent and row['stdin_sha256'] is None
        for stream in ('stdout','stderr'):
            raw = read(folder/'processes'/(name+'.'+stream))
            assert row[stream] == {'path':'processes/'+name+'.'+stream,'bytes':len(raw),'sha256':sha(raw)}
        assert read(folder/'processes'/(name+'.stderr')) == b''
    return len(commands)

def build_evidence(build, overlay, author):
    proof = doc(overlay/'source-proof.json')
    assert proof['baseline']['sha256'] == OLD and proof['output']['sha256'] == NEW
    assert proof['batch_reference']['sha256'] == '2791e3dc9590a833b1e182c4312ca8288554dc9e956c7f878e94d14a47b745ac'
    assert proof['frontend_mapping'] == {'12':56,'13':47,'14':57}
    assert proof['pending_extent'] == 64 and proof['pending_zero_offsets'] == [16,24,32,40,56]
    assert proof['slot_count'] == 58 and proof['port_owned_export_offset'] == 2469
    old = read(build/'old/engine.S'); new = read(build/'new/engine.S')
    assert sha(old) == OLD and sha(new) == NEW and new == read(overlay/'scripts/runtime_mcp_extra_engine.S')
    tree = ast.parse(read(author)); main = next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='main')
    node = next(n for n in main.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='changes' for t in n.targets))
    changes = ast.literal_eval(node.value); assert len(changes) == proof['reversible_edits'] == 10
    value = old.decode()
    for before,after in changes:
        assert value.count(before) == 1; value = value.replace(before,after,1)
    assert value.encode() == new
    for before,after in reversed(changes):
        assert value.count(after) == 1; value = value.replace(after,before,1)
    assert value.encode() == old
    meta = doc(build/'BUILD.json')
    assert meta['status'] == 'ACTUAL_GAS_ENGINE_FIXTURE_BUILD_PASS' and meta['public_handler_qualified'] is False
    assert meta['unused_capabilities'] == 'trap; no synthetic successful operation'
    assert set(meta['images']) == {'old','new'}
    count = 0
    for role, row in meta['images'].items():
        folder = build/role; image = read(folder/'module.bin')
        assert (len(image),sha(image)) == IMAGES[role] == (row['image_bytes'],row['image_sha256'])
        assert row['source_sha256'] == (OLD if role=='old' else NEW)
        assert read(folder/'wrapper.S') == WRAPPER.encode()
        commands = {n:doc(folder/'processes'/(n+'.json'))['command'] for n in ('engine-assemble','undefined','wrapper-assemble','stubs-assemble','link','flat','symbols')}
        origin = doc(folder/'processes/engine-assemble.json')['cwd']
        tools = {'as':commands['engine-assemble'][0],'nm':commands['undefined'][0],'ld':commands['link'][0],'objcopy':commands['flat'][0]}
        expected = {n+'-assemble':[tools['as'],'--64',origin+'/'+n+'.S','-o',origin+'/'+n+'.o'] for n in ('engine','wrapper','stubs')}
        expected.update(undefined=[tools['nm'],'-u',origin+'/engine.o'],link=[tools['ld'],'--build-id=none','-e','_start','-Ttext=0','-o',origin+'/linked.elf',origin+'/wrapper.o',origin+'/engine.o',origin+'/stubs.o'],flat=[tools['objcopy'],'-O','binary','--only-section=.text',origin+'/linked.elf',origin+'/module.bin'],symbols=[tools['nm'],'-n','-P',origin+'/linked.elf'])
        count += processes(folder,expected)
        undefined = []
        for line in read(folder/'processes/undefined.stdout').decode().splitlines():
            fields=line.split(); assert len(fields)==2 and fields[0]=='U' and all(c.isalnum() or c=='_' for c in fields[1]); undefined.append(fields[1])
        assert undefined == row['undefined_traps'] and undefined
        stubs='.intel_syntax noprefix\n.section .text\n'+''.join('.global '+name+'\n'+name+':\n' for name in undefined)+'    mov edi,71\n    mov eax,231\n    syscall\n    ud2\n.section .note.GNU-stack,"",@progbits\n'
        assert read(folder/'stubs.S') == stubs.encode()
        symbols={r[0]:int(r[2],16) for line in read(folder/'processes/symbols.stdout').decode().splitlines() if len(r:=line.split())>=3 and r[1].lower()=='t'}
        assert row['exports'] == {n:symbols[n] for n in ('fixture_frame','fixture_invoke','fixture_port_invoke','fixture_destroy','runtime_grow_target')}
        assert row['exports'] == {'fixture_frame':14,'fixture_invoke':40,'fixture_port_invoke':62,'fixture_destroy':87,'runtime_grow_target':5551 if role=='old' else 5641}
        assert {p.name for p in folder.iterdir()} == {'engine.S','engine.o','wrapper.S','wrapper.o','stubs.S','stubs.o','linked.elf','module.bin','processes'}
    return {'status':'READ_ONLY_ENGINE_BUILD_PASS','assembler_processes':count,'reversible_source_changes':len(changes)}

def verify_join(build, capture, process, joined):
    seen = {}
    def blob(pin):
        assert type(pin) is dict and set(pin)=={'bytes','sha256'}
        h=pin['sha256']; assert len(h)==64 and all(c in '0123456789abcdef' for c in h)
        raw=read(capture/'blobs'/h); assert len(raw)==pin['bytes'] and sha(raw)==h
        seen[h]=pin; return raw
    rows=[json.loads(line) for line in read(capture/'calls.jsonl').splitlines()]
    identity=rows[0]; assert identity['phase']=='identity' and identity['executable_sha256']==PORT
    assert all(identity[k]==process[k] for k in ('pid','pgid','parent_pid'))
    assert blob(identity['component'])==read(build/'component.json') and blob(identity['pack_receipt'])==read(build/'pack.receipt.json')
    addresses=[]; begins={}; ends={}; wires={}; ready=[]; active=None; last=None
    def snapshot(value):
        assert set(value)=={'context','engines','rows','ready'} and len(value['engines'])==len(addresses)
        for address,pin in zip(addresses,value['engines']):
            e=blob(pin); assert len(e)==16384 and e[40:48]==b'HRGENG02' and get(e,8)==address+8192
        if value['context'] is None:
            assert not value['rows'] and not value['ready']; return
        c=blob(value['context']); assert len(c)==4096 and c[:8]==b'HRBPCT01' and get(c,16)==process['pid']
        assert get(c,40)==0 and get(c,32) in (1,2) and get(c,56)==len(value['rows'])
        assert c[120:128]==bytes(8) and c[160:192]==bytes(32) and c[256:]==bytes(3840)
        pointers=[r['address'] for r in value['rows']]; assert len(set(pointers))==len(pointers) and get(c,48)==(pointers[0] if pointers else 0)
        for i,row in enumerate(value['rows']):
            r=blob(row['state']); assert len(r)==4096 and r[:8]==b'HBLROW01' and r[192:]==bytes(3904)
            assert get(r,8)==(pointers[i+1] if i+1<len(pointers) else 0) and get(r,16) in addresses and get(r,24)==1
            assert get(r,32) in (0,1,2) and get(r,40)<=4 and set(row['buffers'])=={'48','72','88','120','136','152','168'}
            for offset in (48,72,88,120,136,152,168):
                pointer,size=get(r,offset),get(r,offset+8); assert size<=256<<20 and bool(pointer)==bool(size)
                if pointer: assert len(blob(row['buffers'][str(offset)]))==size
                else: assert row['buffers'][str(offset)] is None
            assert get(r,64)<=get(r,56)
            if get(r,72):
                work=blob(row['buffers']['72']); assert work[:8]==b'HBLCST01' and get(work,24)==1
            if get(r,88):
                out=blob(row['buffers']['88']); assert out[:8]==b'HBLCLR01' and get(out,8)==get(r,40) and get(out,16)==1 and 64+get(out,32)<=len(out) and out[40:64]==bytes(24)
        pointers=[r['address'] for r in value['ready']]; assert len(set(pointers))==len(pointers)
        assert get(c,64)==(pointers[0] if pointers else 0) and get(c,72)==(pointers[-1] if pointers else 0) and get(c,112) in ([0,pointers[0]] if pointers else [0])
        for i,row in enumerate(value['ready']):
            r=blob(row['state']); assert len(r)==4096 and get(r,0)==(pointers[i+1] if i+1<len(pointers) else 0)
            assert get(r,8)==192 and r[24:32]==bytes(8) and r[32:40]==b'HBPMSR01' and get(r,48)==2 and r[224:]==bytes(3872) and get(r,16)<=get(c,104)
    for row in rows[1:]:
        phase=row['phase']
        if phase=='engine':
            assert active is None and row['index']==len(addresses); addresses.append(row['address']); e=blob(row['before'])
            assert len(e)==16384 and get(e,8)==row['address']+8192 and e[40:48]==b'HRGENG02'
            last=dict(last,engines=list(last['engines'])+[row['before']])
        elif phase=='begin':
            assert active is None and row['call']==len(begins); active=row['call']; snapshot(row['before'])
            if last is not None: assert row['before']==last
            begins[active]=row
        elif phase=='end':
            assert row['call']==active and row['name']==begins[active]['name']; snapshot(row['after'])
            assert 0<=begins[active]['journal_bytes']<=row['journal_bytes']<=(capture/'journal.bin').stat().st_size
            ends[active]=row; last=row['after']; active=None
        elif phase=='wire':
            i=row['call']; assert active is None and i not in wires and begins[i]['name']=='invoke'
            raw=blob(row['input']); assert blob(row['input_full_before'])==blob(row['input_full_after'])==raw+b'\xd6'*8
            out=blob(row['output']); d=blob(row['descriptor']); assert row['code']==ends[i]['return'] and len(d)==64
            e=blob(ends[i]['after']['engines'][row['engine']]); assert e[8192+57*64:8192+58*64]==d and get(d,48)==row['code'] and get(d,56)==len(out)<=get(d,40)
            wires[i]=(raw,out)
        elif phase=='ready':
            i=row['call']; assert active is None and begins[i]['name']=='ready_receive' and row['code']==ends[i]['return']
            before=blob(row['before']); after=blob(row['after']); event=blob(row['event']); assert before==b'\xa5'*40
            if row['code']==32:
                assert after[:8]==b'HBRPBR01' and get(after,16)==len(event)==192 and get(after,24)==row['token'] and after[32:]==b'\xa5'*8
                ready.append(event)
            else: assert row['code']==0 and after==before and event==b'' and row['token']==0
        else: raise AssertionError(('unknown joined observation',phase))
    assert active is None and last['context'] is None and len(addresses)==1 and len(ready)==1 and len(wires)==4
    assert set(wires)=={i for i,b in begins.items() if b['name']=='invoke'}
    expected_body=b'{"states":[{"actions":[{"kind":"terminal","value":2.5},null,null,null,null,null]}]}'
    wire_rows=list(wires.items()); tags=[]
    for i,(wire,out) in wire_rows:
        if wire[:8]==b'HBLTAG01': assert wire==b'HBLTAG01'+struct.pack('<7Q',1,0,0,0,0,0,0) and out==b'HBLTGR01'+struct.pack('<3Q',1,0,0)
        elif wire[:8]==b'HBLRET01': assert wire==b'HBLRET01'+struct.pack('<7Q',1,1,0,0,0,0,0) and out==b'HBLRTR01'+struct.pack('<3Q',1,0,0)
        else:
            assert wire[:8]==b'HBLCLQ01' and get(wire,16)==1 and wire[32:64]==bytes(32)
            op=get(wire,8); assert op in (1,2) and wire[64:]==(expected_body if op==1 else b'') and get(wire,24)==len(wire)-64
            assert out[:8]==b'HBLCLR01' and get(out,16)==get(out,24)==1 and len(out)==64+get(out,32) and out[40:64]==bytes(24)
            assert get(out,8)==(3 if op==1 else 0)
            if op==1: assert len(out)==64
            else: final=out
    assert joined['tag']==joined['job']==joined['worker_contexts']==1 and joined['public_handler_qualified'] is False and joined['status']=='ACTUAL_SLOT57_DISPATCH_PASS'
    requests=[]; outputs=[]; actions=[]; current=None; sequence=0; pending=None
    for at,magic,b in journal_records(capture/'journal.bin'):
        if magic==b'HBPAC001':
            assert current is None and get(b,16)==1; d=words(b[32:]); assert b[32:40]==b'HBLCAC01' and d[2]<=2 and d[3]<=1 and d[8:]==(0,)*6
            if d[3]==0: assert d[1]>sequence; sequence=d[1]
            else: assert pending is not None and (d[1],d[2],d[5])==pending[:3]
            current={'before':b,'requests':[],'outputs':[],'start':at}; actions.append(current)
        elif magic==b'HBPWIN01':
            raw=b[16:]; assert current is not None and get(current['before'],48)==2 and get(current['before'],56)==0
            assert raw[:8]==b'HBWKRQ01' and len(raw)==64+get(raw,40) and get(raw,16)==1 and get(raw,32)==get(raw,48)==get(raw,56)==0
            requests.append(raw); current['requests'].append(raw)
        elif magic==b'HBPMSR01':
            outputs.append(b)
            if get(b,16)==1: assert current is not None; current['outputs'].append(b)
        elif magic==b'HBPAA001':
            assert current is not None; before=current['before']; d=words(before[32:]); ack=words(b[32:])
            assert get(b,16)==1 and b[32:96]==before[32:96] and ack[8]==d[1] and ack[10:12]==(0,0) and ack[13]==0 and ack[12]>0
            assert ack[9]==(ack[12] if ack[12]<=ack[7] else DELIVERY)
            if d[3]==1: assert not current['requests'] and not current['outputs'] and ack[12]==pending[3]
            elif d[2]==2:
                assert len(current['requests'])==len(current['outputs'])==1 and ack[12]==len(current['outputs'][0])
                assert get(current['outputs'][0],24)==1
            else: assert not current['requests'] and not current['outputs']
            pending=(d[1],d[2],d[5],ack[12]) if ack[9]==DELIVERY else None
            owners=[i for i,r in begins.items() if r['name']=='invoke' and r['journal_bytes']<=current['start'] and at+len(b)<=ends[i]['journal_bytes']]
            assert len(owners)==1 and wires[owners[0]][0][:8]==b'HBLCLQ01'; current=None
    assert current is None and pending is None and ready==[b for b in outputs if get(b,16)==2]
    worker=verify_projection(requests,outputs,((m,b) for _,m,b in journal_records(capture/'journal.bin') if m in WORKER_MAGICS),process['pid'])
    assert worker['jobs']==worker['physical_clones']==worker['physical_reaps']==1 and worker['successful_complete_without_take']==0
    takes=[b for b in outputs if get(b,16)==1 and get(b,48)]; assert len(takes)==1
    body=decode_body(takes[0][192:]); assert final[64:]==body[1][2][64:] and json.loads(final[64:])['states'][0]['value']==2.5
    assert {p.name for p in (capture/'blobs').iterdir()}==set(seen) and {p.name for p in capture.iterdir()}=={'blobs','calls.jsonl','journal.bin'}
    return {'worker':worker,'export_calls':len(begins),'actions':len(actions),'full_blobs':len(seen),'full_blob_bytes':sum(p['bytes'] for p in seen.values()),'final':final}

def verify(build, fixture, run, overlay, author):
    built=build_evidence(fixture,overlay,author); process=doc(run/'process.json'); capture=run/'capture'
    assert process['started'] is True and process['timed_out'] is False and process['returncode']==0 and process['pid']==process['pgid']>0 and process['parent_pid']>0
    assert process['timeout_seconds']==60 and 0<=process['elapsed_ns']<=60_000_000_000
    command=process['command']; assert len(command)==9 and command[1:4]==['-I','-S','-B'] and pathlib.Path(command[4]).name=='engine_edges.py' and command[5]=='--build' and command[7]=='--output'
    for name in ('stdout','stderr'):
        b=read(run/name); assert process[name]=={'bytes':len(b),'sha256':sha(b)}
    assert read(run/'stderr')==b''
    result=doc(capture/'RESULT.json'); records=doc(capture/'RECORDS.json'); assert json.loads(read(run/'stdout'))==result
    assert result=={'status':'ACTUAL_ENGINE_EDGE_PASS','frame_cases':213,'paired_frames':426,'target_pairs':1003,'actual_worker_jobs':1,'old_source_sha256':OLD,'new_source_sha256':NEW,'public_handler_qualified':False}
    seen={}
    def blob(pin):
        h=pin['sha256']; assert len(h)==64 and all(c in '0123456789abcdef' for c in h) and set(pin)=={'bytes','sha256'}
        b=read(capture/'blobs'/h); assert sha(b)==h and len(b)==pin['bytes']; seen[h]=pin; return b
    expected_domain=domain(); assert len(records['cases'])==len(expected_domain)==213
    for row,(label,wire,expected) in zip(records['cases'],expected_domain):
        assert row['label']==label and blob(row['input'])==wire and row['new_expected']==expected and set(row['versions'])=={'old','new'}
        for role,item in row['versions'].items():
            before={k:blob(v) for k,v in item['before'].items()}; after={k:blob(v) for k,v in item['after'].items()}
            assert set(before)==set(after)=={'engine','input','output','workspace'}
            assert before['input']==after['input']==wire+b'\xd6'*8 and before['workspace']==after['workspace']==b'\x5a'*4096
            assert before['output']==b'\xa5'*4096 and after['output']==wire+b'\xa5'*(4096-len(wire))
            want=INVALID if role=='old' and get(wire,8)==4 else expected; assert item['code']==want
            a=before['engine']; b=after['engine']; d=8192+18*64
            assert len(a)==len(b)==16384 and a[40:48]==b'HRGENG02' and a[d+48:d+64]==bytes(16)
            initial=bytearray(16384)
            struct.pack_into('<Q',initial,8,get(a,8)); initial[40:48]=b'HRGENG02'
            struct.pack_into('<8Q',initial,d,get(a,d),get(a,d+8),4096,0,get(a,d+32),4096,0,0)
            assert a==initial and get(a,8)>8192 and get(a,d)>14 and get(a,d+8)>0 and get(a,d+32)>0
            desired=bytearray(a); struct.pack_into('<Q',desired,128,1)
            struct.pack_into('<QQ',desired,d+48,want,64+get(wire,24)+get(wire,32) if want==64 else 0)
            assert b==desired,('unexplained engine mutation',label,role)
    targets=records['targets']; assert len(targets)==59*17
    target_sets={}
    for role in ('old','new'):
        source=read(fixture/role/'engine.S').decode()
        table={name:[int(x.strip()) for x in values.split(',')] for name,values in re.findall(r'^runtime_grow_(\w+)_targets:\n    \.byte ([0-9, ]+)$',source,re.M)}
        choices={19:('sdk_protocol',0),37:('text_gateway',0),35:('text_create',0),18:('frontend',0),5:('context',1),13:('workdir',0),1:('admission',0),2:('gateway',0),7:('policy',1),26:('policy',1),21:('filesystem_gateway',0),23:('filesystem_caller',0),27:('fence',0)}
        expected_targets={}
        for parent in range(59):
            for child in range(17):
                value=(1<<64)-1
                if parent==39 and child==0: value=40
                elif parent==3 and child==1: value=10
                elif parent in choices:
                    name,start=choices[parent]
                    if start<=child<start+len(table[name]): value=table[name][child-start]
                expected_targets[(parent,child)]=value
        target_sets[role]=expected_targets
    for index,row in enumerate(targets):
        parent,child=divmod(index,17); assert row['parent']==parent and row['child']==child
        expected=47 if (parent,child)==(18,13) else 57 if (parent,child)==(18,14) else row['old']
        assert row['new']==expected==target_sets['new'][(parent,child)] and row['old']==target_sets['old'][(parent,child)]
    assert next(r for r in targets if (r['parent'],r['child'])==(18,12))['new']==56
    joined=verify_join(build,capture/'port',process,records['joined'])
    assert blob(records['joined']['full_result'])==joined.pop('final')
    assert {p.name for p in (capture/'blobs').iterdir()}==set(seen)
    assert {p.name for p in capture.iterdir()}=={'blobs','RECORDS.json','RESULT.json','port'}
    return {'status':'READ_ONLY_ENGINE_EDGE_PASS','build':built,'paired_frames':426,'target_pairs':1003,'joined':joined,'full_frame_blobs':len(seen),'full_frame_bytes':sum(p['bytes'] for p in seen.values()),'process_seconds':process['elapsed_ns']/1e9,'native_or_rust_executed':False,'public_handler_qualified':False}

def main():
    p=argparse.ArgumentParser()
    for name in ('build','fixture','run','overlay','author'): p.add_argument('--'+name,type=pathlib.Path,required=True)
    a=p.parse_args(); print(json.dumps(verify(a.build,a.fixture,a.run,a.overlay,a.author),sort_keys=True))
if __name__=='__main__': main()
