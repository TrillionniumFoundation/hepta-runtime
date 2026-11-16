"""Read complete private state and derive current-target replay input; no execution."""
from pathlib import Path
import argparse
import gzip
import hashlib
import json
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "joint/authority/drivers"))
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from authority_cases import plan,framed,OWNER_REQUEST

SHA=lambda b:hashlib.sha256(b).hexdigest()
U64=lambda b,at:struct.unpack_from('<Q',b,at)[0]
RA_BYTES=24928256
ENGINE_BYTES=16384
B3='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
def doc(path):return json.loads(path.read_bytes())
def need(value,message):
    if not value:raise ValueError(message)
def exact(stream,count):
    raw=stream.read(count);need(len(raw)==count,'truncated actual output');return raw
def file_pin(path):
    h=hashlib.sha256();size=0
    with path.open('rb') as stream:
        while data:=stream.read(1<<20):h.update(data);size+=len(data)
    return dict(bytes=size,sha256=h.hexdigest())
def projection(owner):return b'HROWR001'+bytes(8)+owner.encode()

def module_path(original,module_map=None):
    if module_map is None:return Path(original)
    relative=Path(doc(module_map)['modules'][original])
    need(not relative.is_absolute() and '..' not in relative.parts,'module relocation escaped the retained artifact')
    result=module_map.parent/relative
    need(result.resolve(strict=True)==result.absolute(),'module relocation is aliased')
    return result

def graph(source,manifest,module_map=None):
    raw=manifest.read_bytes();md=json.loads(raw);elf=(manifest.parent/md['elf']).read_bytes()
    need(md['status']=='PASS' and md['private_instance_fixture'] is True,'actual private build')
    need(md['physical_images']==104 and len(md['members'])==103,'complete image inventory')
    need(md['fixture_pseudo_selectors']==[33,34,41,57,58],'private observation namespace')
    need(md['authority_slot']==56 and md['authority_context_offset']==432,'authority slot/control')
    need(md['private_descriptor_base']==8192 and md['private_engine_bytes']==ENGINE_BYTES,'disjoint public table')
    need(md['elf_bytes']==len(elf) and md['elf_sha256']==SHA(elf),'actual ELF custody')
    binding=doc(source/'native/runtime_mcp_sources.json')
    need(md['source_binding']['manifest_sha256']==SHA((source/'native/runtime_mcp_sources.json').read_bytes()),'source binding')
    need(binding['sources']==md['source_binding']['files'],'whole source closure')
    for name,pin in binding['sources'].items():need(file_pin(source/name)==pin,'bound source '+name)
    names=md['physical_image_members'];positions=md['pack']['image_offsets']
    need(len(names)==len(positions)==104 and len(set(names))==104,'packed member inventory')
    members={row['name']:row for row in md['members']};addresses={}
    for name,at in zip(names,positions,strict=True):
        if name=="bellman_port":
            capability=md["packed_capabilities"]["57"]
            path=module_path(str(Path(capability["build_root"])/"bellman-port-packed.elf"),module_map)
            image=path.read_bytes()
            need(file_pin(path)=={"bytes":capability["elf_bytes"],"sha256":capability["elf_sha256"]},
                 "complete packed capability bytes")
            need(doc(source/"native/bellman_port_component.json")["executable"]==file_pin(path),
                 "immutable packed capability source declaration")
            need(at%16==0 and elf[at:at+len(image)]==image,"every loaded packed capability byte")
            addresses[name]=4194304+at
            continue
        row=members[name];module=module_path(row['manifest'],module_map);m=doc(module)
        need(SHA(module.read_bytes())==row['manifest_sha256'],'actual module manifest')
        image=(module.parent/m['image']).read_bytes();text=(source/row['source']).read_bytes()
        need(m['source_sha256']==row['source_sha256']==SHA(text),'actual source')
        need(m['compiler_sha256']==B3 and m['standalone'] is None and
             m['compiler_commit']=='d3e2c90173cf733e42b299d0c4274df4b593a12f','compiler identity')
        need((module.parent/m['source']).read_bytes()==text and
             (module.parent/'module.input.bin').read_bytes()==text,'actual full compiler input')
        need(m['image_sha256']==row['image_sha256']==SHA(image) and len(image)==row['image_bytes'],'actual image')
        receipt=doc(module.parent/'module.receipt.json')
        need(receipt['status']=='returned' and receipt['abi_status']==0 and
             receipt['artifact_sha256']==B3 and receipt['source_unchanged'] is True,'actual compile receipt')
        need(receipt['source_sha256']==receipt['input_sha256']==SHA(text) and
             receipt['produced_sha256']==SHA(image) and
             receipt['core_u32']==receipt['result_u64']==receipt['produced_bytes']==len(image),'complete compiler result')
        output=(module.parent/'module.output.bin').read_bytes()
        need(SHA(output)==receipt['output_sha256'] and output[:len(image)]==image and
             (module.parent/'module.stderr.log').read_bytes()==b'','complete compiler output')
        need(at%16==0 and elf[at:at+len(image)]==image,'every loaded image byte')
        addresses[name]=4194304+at
    pack=(manifest.parent/'pack.input.bin').read_bytes();packed=(manifest.parent/'pack.output.bin').read_bytes()
    need(SHA(pack)==md['pack']['input_sha256'] and SHA(packed)==md['pack']['output_sha256'],'complete pack I/O')
    need(packed[:8]==b'HIAIMR02' and struct.unpack_from('<3Q',packed,8)==(0,len(elf),0) and packed[32:]==elf,'actual HIA pack output')
    for kind,at,index in md['pack']['fixed_patches']:
        if kind==1:need(U64(elf,at)==4194304+positions[index],'fixed pointer patch')
        else:need(kind==2 and struct.unpack_from('<I',elf,at)[0]==positions[index]-at-4,'fixed call patch')
    profile=doc(source/'native/caller_owner_export_profile.json');anames=md['authority_fixed_local_members']
    need(len(profile['members'])==len(anames)==9,'fixed private authority closure')
    for expected,name in zip(profile['members'],anames,strict=True):
        need(all(members[name][k]==expected[k] for k in ('source_sha256','image_sha256','image_bytes')),'qualified owner profile binding')
    return md,addresses,profile

def verify(source,manifest,capture,module_map=None):
    md,addresses,profile=graph(source,manifest,module_map)
    report=doc(capture/'SUMMARY.json');need(report['status']=='NATIVE_PRIVATE_BINDING_CAPTURE_COMPLETE','complete capture')
    need(report['elf_sha256']==md['elf_sha256'] and report['manifest_sha256']==SHA(manifest.read_bytes()),'capture build identity')
    need(report['source_binding_sha256']==SHA((source/'native/runtime_mcp_sources.json').read_bytes()),'capture source identity')
    totals=dict(processes=0,sessions=0,input_frames=0,full_snapshots=0,full_snapshot_bytes=0,
                current_call_projections=0,private_projection_responses=0,actual_releases=0,
                idempotent_releases=0,public_responses=0,config_query_calls=0,authority_child_calls=0)
    references=[];expected=[];details=[]
    for index,configured in enumerate((False,True)):
        label='configured' if configured else 'disabled';folder=capture/label
        receipt=doc(folder/'PROCESS.json');row=report['processes'][index]
        need(row==dict(label=label,process_sha256=SHA((folder/'PROCESS.json').read_bytes())),'actual process receipt')
        need(receipt['exit_code']==0 and receipt['timed_out'] is False and receipt['timeout_seconds']==60,'actual successful bounded process')
        need(receipt['environment']=={'PATH':'','LC_ALL':'C'},'process environment')
        for name,pin in receipt['files'].items():need(file_pin(folder/name)==pin,'retained whole file '+name)
        corpus=plan(configured);need(doc(folder/'CORPUS.json')==corpus,'ordinary corpus')
        need((folder/'stdin').read_bytes()==framed(corpus),'complete process input')
        digest=hashlib.sha256();total=0
        with gzip.open(folder/'stdout.bin.gz','rb') as stream:
            while block:=stream.read(1<<20):digest.update(block);total+=len(block)
        need(dict(bytes=total,sha256=digest.hexdigest())==receipt['files']['stdout.raw'],'compressed complete output custody')
        owners={};engines={};authority_addresses={};startup={};hubs=set();snapshots=[];public=[]
        with gzip.open(folder/'stdout.bin.gz','rb') as stream:
            for case in corpus:
                session=case['session'];context=index*2+session;label=case['label'];magic=exact(stream,8)
                if case['action'] in (57,58):
                    need(magic==b'HRAOBS02','private snapshot envelope')
                    header=magic+exact(stream,56)
                    sid,enginebase,esize,raptr,rasize,frontptr,frontcap=struct.unpack('<7Q',header[8:])
                    need(sid==session and esize==ENGINE_BYTES,'actual engine extent')
                    engine=exact(stream,esize);authority=exact(stream,rasize);front=exact(stream,frontcap)
                    need(engine[40:48]==b'HRGENG02' and U64(engine,8)==enginebase+8192,'descriptor table uses engine+8')
                    need(U64(engine,432)==raptr and U64(engine,416)==U64(engine,424)==0,'reserved control ownership')
                    need(engine[4288:8192]==bytes(3904) and engine[11968:]==bytes(4416),'59-row continuation and descriptor boundaries remain disjoint')
                    for slot in range(59):
                        need(engine[512+slot*64:528+slot*64]==bytes(16),'completed busy/pending records')
                        name='bellman_port' if slot==57 else md['extra_table'][slot]
                        need(U64(engine,8192+slot*64)==(addresses[name] if name else 0),'fixed public descriptor entry')
                    frow=8192+18*64
                    need(U64(engine,frow+8)==frontptr and U64(engine,frow+16)==frontcap,'complete frontend allocation')
                    need(engines.setdefault(session,enginebase)==enginebase,'stable engine identity')
                    hubs.add(U64(engine,400))
                    if case['released']:
                        need(raptr==rasize==0 and engine[8192+56*64:8192+57*64]==bytes(64),'released +432 and borrowed descriptor cleared')
                        if label=='release-1':
                            totals['actual_releases']+=1
                            references.append(dict(context=context,operation='shutdown',code=0,output_hex=''))
                            expected.append(dict(context=context,code=0,output_hex='',binding=None))
                        else:totals['idempotent_releases']+=1
                    else:
                        need(rasize==RA_BYTES and raptr>0,'whole actual authority context')
                        need(authority[:8]==b'HRUACT01' and U64(authority,8)==1,'live private owner')
                        need(U64(authority,16)==U64(authority,24)==0,'private child calls drained')
                        need(U64(authority,32)==U64(authority,40)==U64(authority,48)==1,'trusted stdio lifecycle')
                        need(U64(authority,56)==U64(authority,80)==(1<<64)-1,'loader and transient entropy FDs retired')
                        need(U64(authority,88)==case['authority_calls'],'only actual private CALLs counted')
                        need(authority_addresses.setdefault(session,raptr)==raptr,'stable private allocation')
                        offset=4096
                        for child,(spec,name) in enumerate(zip(profile['members'],md['authority_fixed_local_members'],strict=True)):
                            at=256+64*child
                            wanted=[addresses[name],raptr+offset,spec['workspace_capacity'],spec['input_capacity'],spec['output_capacity'],spec['flags'],spec['call_mask']]
                            need(list(struct.unpack_from('<7Q',authority,at))==wanted,'all fixed private child capabilities')
                            offset+=(spec['workspace_capacity']+4095)&-4096
                        need(offset==RA_BYTES,'complete private allocation layout')
                        root=authority[4096:4096+16777216]
                        need(U64(root,64)==1,'actual OS fallback present')
                        owner=root[320:352].hex();need(len(owner)==64 and owner!='0'*64,'complete observed native fallback')
                        need(owners.setdefault(session,owner)==owner,'protocol metadata cannot change fallback')
                        bound=case['authority_calls']>0
                        need(U64(root,80)==int(bound) and U64(root,88)==0,'actual first-call binding and stdio flag')
                        if bound:need(root[352:384]==bytes.fromhex(owner),'bound owner equals private native fallback')
                        else:need(root[352:384]==bytes(32),'protocol-only path remains unbound')
                        if label=='startup':
                            startup[session]=authority
                            references.append(dict(context=context,operation='start',mode=1,entropy_seed=7,entropy_fail=0,
                                owner_failure=False,stdio_fallback_source='native-os-observation',observed_stdio_fallback=owner,code=0,output_hex=''))
                            expected.append(dict(context=context,code=0,output_hex='',binding=None))
                        if label=='protocol-only':need(authority==startup[session],'G2/peer/catalog work does not resolve authority')
                        if label.startswith('after-tool-') and configured:
                            body=projection(owner);references.append(dict(context=context,operation='request',request_op=3,
                                headers=[],payload_hex='',code=0,output_hex=body.hex()))
                            expected.append(dict(context=context,code=0,output_hex=body.hex(),binding=dict(owner=owner,authenticated=False)))
                            totals['current_call_projections']+=1
                    if front:
                        need(U64(front,192)==(80 if case['projection'] else 0),'owned projection extent')
                        if case['projection']:need(front[1152:1232]==projection(owners[session]),'actual CALL body copied before next owner call')
                        else:need(front[1152:1232]==bytes(80),'no projection from protocol context')
                    totals['full_snapshots']+=1;totals['full_snapshot_bytes']+=len(engine)+len(authority)+len(front)
                    snapshots.append(dict(session=session,label=label,engine_sha256=SHA(engine),authority_sha256=SHA(authority),frontend_sha256=SHA(front)))
                elif case['action']==56:
                    need(magic==b'HFSFXR02','actual private call response envelope')
                    header=magic+exact(stream,96);values=struct.unpack('<12Q',header[8:])
                    need(values[:4]==(session,56,168,168),'private result code and entire extent')
                    actual=exact(stream,168);body=projection(owners[session])
                    need(actual==(bytes(4)+body).hex().encode(),'complete strict lowerhex private bound projection')
                    references.append(dict(context=context,operation='request',request_op=3,headers=[],payload_hex='',code=0,output_hex=body.hex()))
                    expected.append(dict(context=context,code=0,output_hex=body.hex(),binding=dict(owner=owners[session],authenticated=False)))
                    totals['private_projection_responses']+=1
                else:
                    need(magic==b'HFSJPR03','private current public response carrier')
                    header=magic+exact(stream,88);values=struct.unpack('<11Q',header[8:]);need(values[0]==session and values[2]==0,'open public session')
                    kind=values[1];need(kind in (0,1,2,3),'public output action')
                    if label=='initialized':need(kind==0,'notification has no response')
                    else:
                        need(kind!=0,'ordinary request has full response')
                        raw=stream.readline();need(raw.endswith(b'\n'),'complete public JSON frame')
                        answer=json.loads(raw);query=json.loads(bytes.fromhex(case['data_hex']))
                        need(answer['jsonrpc']=='2.0' and answer['id']==query['id'] and 'result' in answer,'ordinary public response')
                        if label=='tool-1':
                            need(answer['result']=={'content':[{'type':'text','text':"Parameter 'path' must be a non-empty string"}],'isError':True},'retained original workdir parameter diagnostic')
                        if label=='tool-2':need(answer['result']['isError'] is False,'ordinary workdir success')
                        need(all(owner.encode() not in raw for owner in owners.values()),'private owner not published')
                        totals['public_responses']+=1;public.append(dict(session=session,label=label,sha256=SHA(raw),bytes=len(raw)))
                totals['input_frames']+=1
            need(stream.read(1)==b'','no unaccounted native output')
        need(len(engines)==len(set(engines.values()))==2 and len(set(authority_addresses.values()))==2,'independent session allocations')
        need(len(set(owners.values()))==2 and len(hubs)==1 and next(iter(hubs))>0,'separate session identity with shared process hub')
        trace=(folder/'stderr').read_bytes();at=0;trace_counts={}
        config_calls=owner_calls=0
        while at<len(trace):
            magic=trace[at:at+8]
            width={b'HRGTR002':224,b'HWDIOAK2':160,b'HRCNAK02':128}.get(magic)
            need(width is not None and at+width<=len(trace),'whole source-declared private trace record')
            record=trace[at:at+width];at+=width
            trace_counts[magic.decode()]=trace_counts.get(magic.decode(),0)+1
            if magic==b'HRGTR002':
                slot,event,phase=U64(record,16),U64(record,24),U64(record,56)
                need(slot<59,'trace uses only fixed public table')
                if slot==18 and event==3:
                    config_calls+=int(phase==13);owner_calls+=int(phase==14)
        need(config_calls==4 and owner_calls==(4 if configured else 0),'actual configured gate then authority CALL edges')
        totals['config_query_calls']+=config_calls;totals['authority_child_calls']+=owner_calls
        totals['processes']+=1;totals['sessions']+=2
        details.append(dict(configured=configured,process_sha256=row['process_sha256'],snapshots=snapshots,public=public,trace_counts=trace_counts))
    need(len(references)==len(expected)==16,'complete additional target replay rows')
    need(totals['input_frames']==56 and totals['full_snapshots']==28 and totals['public_responses']==20,'complete ordinary private domains')
    return dict(schema='hepta.public-authority.private-readonly.v1',status='READONLY_PRIVATE_SESSION_BINDING_PASS',
        counts=totals,processes=details,original_input=references,expected_original=expected,
        source_binding_sha256=report['source_binding_sha256'],elf_sha256=report['elf_sha256'],
        original_rust_executed=False,current_target_projection_replay_pending=True,
        peer_info_is_authority=False,annotation_integrated=False,request_audit_integrated=False,
        public_http_qualified=False,concurrent_binding_qualified=False,full_sdk_qualified=False,
        production_activated=False,old_path_removed=False,reader_wrote_files=False,reader_executed_native_or_rust=False)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('source','manifest','capture'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--module-map',type=Path)
    a=p.parse_args();print(json.dumps(verify(a.source.resolve(strict=True),a.manifest.resolve(strict=True),a.capture.resolve(strict=True),a.module_map.resolve(strict=True) if a.module_map else None),sort_keys=True))
