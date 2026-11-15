"""Native-first full-byte admission, without launching HIA or Rust."""
from pathlib import Path
import gzip
import hashlib
import importlib.util
import io
import json
import math
import re
import stat
import struct
import sys
sys.dont_write_bytecode = True
from capture_format import Files, actual_process, blob, canonical, fields, need, parse_records, pin, same, sha, strict_json, uint

MEMBERS = ['batch_call','view_read','line_endpoint','file_lock_key','request_scope_lifecycle',
    'request_cache_lease','view_cache','batch_line_verify','request_context','view_error','batch_plan_input',
    'batch_plan','batch_apply','editable_content','batch_diff','history','file_lock_state','atomic_write',
    'batch_edit_params','serde_json_span']
SLOTS = [0,1,1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19]
D3 = 'd3e2c90173cf733e42b299d0c4274df4b593a12f'
TREE = '8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49'
COMPILER = 'bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
CASES = '6288fc54dbef5786fb867c5255996808316fba41c752568eaf65bc45ed912b21'
CONTROL = '0144beec3a1b22a11027278f81658f56bf96b38bbb24c3f200900c1d7dbcabd1'
BOUNDARY_SOURCES=['scripts/batch_call_fixture.S','scripts/batch_call_fixture_controls.S','scripts/batch_call_native_support.S',
    'scripts/batch_call_engine.S','scripts/batch_call_tree_bridge.S','scripts/batch_call_atomic_bridge.S',
    'scripts/batch_call_atomic_effects.S','scripts/batch_call_atomic_observer.S','scripts/batch_call_driver.S',
    'scripts/batch_call_retire.S','scripts/batch_call_async.S','scripts/batch_call_shared.S','scripts/batch_call_fixture_sessions.S',
    'scripts/view_call_read_bridge.S','scripts/view_call_key_bridge.S','scripts/view_call_scope_bridge.S']


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def module_evidence(files, path, source_path, profile):
    meta = files.json(str(path))
    same(meta.get('schema'), 'hepta.runtime.native-module.v1', 'native module schema')
    same(meta.get('compiler_commit'), D3, 'native compiler commit')
    same(meta.get('compiler_sha256'), COMPILER, 'native compiler bytes')
    same(meta.get('target'), 'linux-x86_64', 'native target')
    same(meta.get('abi'), 'hepta.runtime.borrowed-bytes.linux-x86_64.v1', 'native ABI')
    same(meta.get('standalone'), None, 'unexpected module transport')
    same(meta.get('buffer_profile'), profile, 'native carrier profile')
    capacity = {'batch-plan.v1': (512<<20,1024<<20,1152<<20), 'history.v1': (128<<20,128<<20,256<<20)}[profile]
    same([meta.get(n) for n in ('input_capacity','output_capacity','workspace_capacity')], list(capacity), 'native carrier capacities')
    folder = path.parent
    source = files.raw(str(folder/meta['source']))
    image = files.raw(str(folder/meta['image']))
    same(sha(source), meta['source_sha256'], 'compiled source hash')
    same(source, files.raw(str(source_path)), 'compiled source differs from admitted source root')
    same(sha(image), meta['image_sha256'], 'compiled image hash')
    request = files.json(str(folder/'module.request.json'))
    receipt = files.json(str(folder/'module.receipt.json'))
    build = files.json(str(folder/'build.json'))
    same(build['compile_receipt'], receipt, 'compile receipt/build identity')
    need(build.get('whole_runtime_replaced') is False, 'build scope inflated')
    same(files.raw(str(folder/'module.input.bin')), source, 'complete compiler input')
    output = files.raw(str(folder/'module.output.bin'))
    need(len(output)>=len(image) and output == image+b'\xa5'*(len(output)-len(image)), 'complete compiler output')
    for value in (request, receipt):
        same(value['format'], 'flat-x86-64', 'compile input format')
        same(value['image_sha256'], COMPILER, 'actual compiler identity')
        same(value['source_sha256'], sha(source), 'actual compile source identity')
    same(receipt['artifact_sha256'], COMPILER, 'actual compiler artifact')
    same(receipt['input_sha256'], sha(source), 'actual compiler input digest')
    same(receipt['input_bytes'], len(source), 'actual compiler input extent')
    same(request['capacity'], len(output), 'actual compiler output capacity')
    same(request['workspace_fill'], 0, 'actual compiler workspace fill')
    same(receipt['limits']['output_capacity'], len(output), 'compiler output limit')
    same(receipt['limits']['workspace_bytes'], request['workspace_size'], 'compiler workspace limit')
    for field in ('core_u32','result_u64','produced_bytes'):
        same(receipt[field], len(image), 'actual compiler return '+field)
    same(receipt['produced_sha256'], sha(image), 'compiler produced image')
    same(receipt['output_sha256'], sha(output), 'compiler complete output digest')
    need(receipt['source_unchanged'] is True and receipt['status']=='returned', 'compiler did not return unchanged source')
    same(receipt['abi_status'], 0, 'compiler ABI return')
    same(receipt['return_encoding'], 'zero-extended-u32', 'compiler return encoding')
    same(receipt['forbidden_compiler_modules_loaded'], [], 'host compiler fallback')
    stdout = files.json(str(folder/'module.stdout.log'))
    for key, value in stdout.items(): same(receipt.get(key), value, 'actual compiler full stdout')
    same(files.raw(str(folder/'module.stderr.log')), b'', 'actual compiler stderr')
    return meta, image


def transport_records(raw):
    at = 0
    result = []
    while at < len(raw):
        need(len(raw)-at >= 16, 'truncated native transport header')
        kind, n = struct.unpack_from('<2Q', raw, at)
        need(kind in (1,2,3,4,6,7,8) and n <= len(raw)-at-16, 'native transport extent/type')
        body = raw[at+16:at+16+n]
        result.append({'kind':kind,'offset':at,'bytes':16+n,'payload_bytes':n,'payload_sha256':sha(body)})
        at += 16+n
    need(at == len(raw), 'unconsumed native stdout')
    return result


def raw_blob(files, capture, value):
    fields(value, ('artifact','bytes','sha256'), 'native body descriptor')
    need(type(value['artifact']) is str and re.fullmatch(r'blobs/[0-9a-f]{64}\.bin\.gz', value['artifact']), 'native body artifact name')
    raw = gzip.decompress(files.raw(str(capture/value['artifact'])))
    same({'bytes':len(raw),'sha256':sha(raw)}, {key:value[key] for key in ('bytes','sha256')}, 'complete native body')
    same(value['artifact'], 'blobs/'+sha(raw)+'.bin.gz', 'native content address')
    return raw


def build_evidence(files, source, manifest):
    meta = files.json(str(manifest))
    same(meta.get('schema'), 'hepta.runtime.batch-call-build.v1', 'Batch graph schema')
    same([m['name'] for m in meta['members']], MEMBERS, 'closed 20-image membership')
    same(meta['slots'], SLOTS, 'closed 22-slot mapping')
    for field in ('runtime_python_required','runtime_rust_required','runtime_libc_required','public_route_replaced','whole_runtime_replaced'):
        need(meta.get(field) is False, 'Batch build scope '+field)
    parent = manifest.parent
    boot = parent/'build/bootstrap'
    bootstrap = files.json(str(boot/'bootstrap.json'))
    same(bootstrap['dependency']['commit'], D3, 'bootstrap commit')
    same(bootstrap['dependency']['tree'], TREE, 'bootstrap tree')
    same(bootstrap['generation_sha256'], COMPILER, 'bootstrap fixed point')
    need(bootstrap['matching_source_cold_qualified'] is False, 'unexecuted cold bootstrap claim')
    for name in ('B1','B2','B3'):
        same(sha(files.raw(str(boot/(name+'.image.bin')))), COMPILER, 'full bootstrap generation')
    images = []
    for member in meta['members']:
        path = parent/member['manifest']
        same(sha(files.raw(str(path))), member['manifest_sha256'], 'member manifest identity')
        child, image = module_evidence(files, path, source/'native'/(member['name']+'.hepta'), 'batch-plan.v1')
        same(child['source_sha256'], member['source_sha256'], 'member source identity')
        same(sha(image), member['image_sha256'], 'member image identity')
        same(len(image), member['image_bytes'], 'member image extent')
        images.append(image)
    pack_path = parent/meta['packer_manifest']
    same(sha(files.raw(str(pack_path))), meta['packer_manifest_sha256'], 'packer manifest identity')
    module_evidence(files, pack_path, source/'native/batch_call_packer.hepta', 'history.v1')
    prefix = files.raw(str(parent/'prefix.bin'))
    same(len(prefix), meta['prefix_bytes'], 'native prefix extent')
    same(sha(prefix), meta['prefix_sha256'], 'native prefix identity')
    table = uint(meta['table_offset'], 'native slot table offset')
    need(table+8*len(SLOTS)<=len(prefix) and prefix[table:table+8*len(SLOTS)]==bytes(8*len(SLOTS)), 'unpatched native table')
    expected = bytearray(prefix)
    positions = []
    for image in images:
        expected += bytes((-len(expected))%16)
        positions.append(len(expected))
        expected += image
    struct.pack_into('<QQ', expected, 96, len(expected), len(expected))
    for slot, index in enumerate(SLOTS): struct.pack_into('<Q', expected, table+8*slot, 0x400000+positions[index])
    same(meta['image_offsets'], positions, 'actual image positions')
    elf = files.raw(str(parent/meta['elf']))
    need(elf==expected and sha(elf)==meta['elf_sha256'], 'complete static ELF/image/link identity')
    frame = b'HBCCELF2'+struct.pack('<3Q',len(prefix),len(images),table)+struct.pack('<20Q',*map(len,images))+prefix+b''.join(images)
    need(files.raw(str(parent/'packer.input.bin'))==frame and sha(frame)==meta['input_frame_sha256'], 'complete HIA packer input')
    same(files.raw(str(parent/'packer.output.bin')), elf, 'complete HIA packer output')
    source_pins = meta['sources']
    same(sorted(source_pins),sorted(BOUNDARY_SOURCES),'closed native boundary source membership')
    for name, digest in source_pins.items(): same(sha(files.raw(str(source/name))), digest, 'native assembly source '+name)
    source_owned='builder_source' in meta
    if source_owned:
        same(meta['builder_source'],'scripts/hia_native_batch_call_build.py','source-owned build entry')
        builder=files.raw(str(source/meta['builder_source']))
        same(sha(builder),meta['builder_sha256'],'actual build source bytes')
        same(files.raw(str(parent/'builder.py')),builder,'retained executed builder')
        same(meta['packer_composition'],'native/batch_call_packer_composition.json','source-owned packer contract')
        proof_raw=files.raw(str(source/meta['packer_composition']))
        same(sha(proof_raw),meta['packer_composition_sha256'],'actual packer composition bytes')
        same(files.raw(str(parent/'packer-composition.json')),proof_raw,'retained packer composition')
        proof=strict_json(proof_raw)
        same(proof['schema'],'hepta.runtime.batch-call-packer-composition.v1','packer composition schema')
        same(proof['source_sha256'],sha(files.raw(str(source/'native/batch_call_packer.hepta'))),'packer composition source')
        same(proof['boundary'],{'prefix_bytes':len(prefix),'prefix_sha256':sha(prefix),
             'table_offset':table,'slots':SLOTS,'sources':source_pins},'complete source-owned packer boundary')
        need(proof['build_time_only'] is True and proof['source_generation_during_build'] is False and
             all(proof[name] is False for name in ('public_mcp_route_replaced','whole_runtime_replaced','whole_view_replaced')),
             'packer composition scope')
        for item in proof['imports']:
            same(sha(files.raw(str(source/item['source']))),item['source_sha256'],'packer imported source bytes')
    combined='\n'.join(files.raw(str(source/name)).decode() for name in BOUNDARY_SOURCES)
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',combined,re.M):
        if name=='_start':continue
        alias=name+'_flat'
        if '\n'+alias+':' not in combined:combined=combined.replace('\n'+name+':','\n'+name+':\n'+alias+':')
        combined=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',lambda m:m[1]+' '+alias,combined)
        combined=combined.replace('[rip + '+name+']','[rip + '+alias+']')
    same(files.raw(str(parent/'combined.S')),combined.encode(),'actual source-owned linked assembly')
    boundary = files.json(str(parent/'boundary.json'))
    same(boundary['sources'], source_pins, 'assembly/graph source equality')
    same(boundary['table_offset'], table, 'assembly table identity')
    same(boundary['prefix_sha256'], sha(prefix), 'assembly prefix identity')
    for name in ('combined.S','boundary.o','boundary.bin'):
        files.raw(str(parent/name))
    native_boundary = files.raw(str(parent/'boundary.bin'))
    header=(b'\x7fELF\x02\x01\x01'+bytes(9)+struct.pack('<HHIQQQIHHHHHH',2,62,1,0x4000b0,64,0,0,64,56,2,0,0,0)
      +struct.pack('<IIQQQQQQ',1,5,0,0x400000,0x400000,0,0,4096)
      +struct.pack('<IIQQQQQQ',0x6474e551,6,0,0,0,0,0,16))
    same(prefix, header+native_boundary, 'full executable prefix and actual assembler text')
    obj = files.raw(str(parent/'boundary.o'))
    need(obj[:16]==b'\x7fELF\x02\x01\x01'+bytes(9), 'assembler ELF identification')
    shoff=struct.unpack_from('<Q',obj,40)[0]
    shsize,shcount,shstr=struct.unpack_from('<HHH',obj,58)
    need(shsize==64 and shcount>0 and shstr<shcount and shoff+64*shcount<=len(obj), 'assembler ELF sections')
    sections=[struct.unpack_from('<IIQQQQIIQQ',obj,shoff+64*i) for i in range(shcount)]
    names=sections[shstr]
    need(names[4]+names[5]<=len(obj), 'assembler names extent')
    strings=obj[names[4]:names[4]+names[5]]
    text_sections=[]
    for section in sections:
        need(section[0]<len(strings), 'assembler section name')
        end=strings.find(b'\0',section[0]);need(end>=0,'assembler unterminated section name')
        if strings[section[0]:end]==b'.text':text_sections.append(section)
        need(section[1] not in (4,9) or section[5]==0,'assembler relocation section')
    need(len(text_sections)==1,'assembler text uniqueness')
    section=text_sections[0]
    same(obj[section[4]:section[4]+section[5]], native_boundary, 'actual ELF object text extraction')
    boundary_commands=[['--64','-o',str(parent/'boundary.o'),str(parent/'combined.S')],
        ['-r',str(parent/'boundary.o')],
        ['-O','binary','-j','.text',str(parent/'boundary.o'),str(parent/'boundary.bin')],
        ['-n',str(parent/'boundary.o')]]
    for i, command in enumerate(('as','readelf','objcopy','nm')):
        record = files.json(str(parent/f'boundary-{i}.process.json'))
        if source_owned:
            executable=Path(record['command'][0])
            need(executable.is_absolute() and executable.name in (command,'x86_64-linux-gnu-'+command),
                 'actual assembler executable')
            actual_process(record,[str(executable),*boundary_commands[i]],parent)
            same(record['controlled_env'],{'LC_ALL':'C'},'actual assembler environment')
            need(type(record['executable_sha256']) is str and re.fullmatch(r'[0-9a-f]{64}',record['executable_sha256']) is not None,
                 'recorded assembler executable identity')
        else:
            need(record['command'][0]==command and record['exit_code']==0 and record['timeout']==180, 'actual assembler process')
        stdout = files.raw(str(parent/f'boundary-{i}.stdout'))
        same(files.raw(str(parent/f'boundary-{i}.stderr')), b'', 'actual assembler stderr')
        if source_owned:
            same(record['stdout'],{'bytes':len(stdout),'sha256':sha(stdout)},'complete actual assembler stdout')
            same(record['stderr'],{'bytes':0,'sha256':sha(b'')},'complete actual assembler stderr')
        if i==1: need(b'There are no relocations' in stdout, 'native boundary retains relocations')
        if i==3:
            symbols=re.findall(rb'^([0-9a-f]+) T batch_image_table$',stdout,re.M)
            need(len(symbols)==1 and int(symbols[0],16)+176==table,'actual assembled table symbol')
    if not source_owned:
        files.raw(str(parent/'packer-author.stdout'))
        same(files.raw(str(parent/'packer-author.stderr')), b'', 'packer authoring stderr')
    return {'members':len(images),'slots':len(SLOTS),'elf_bytes':len(elf),'elf_sha256':sha(elf),
            'source_owned_builder':source_owned,'fresh_cold_qualification':False}


def words(raw, offset, count):
    need(offset>=0 and offset+8*count<=len(raw),'binary integer extent')
    return struct.unpack_from('<'+'Q'*count,raw,offset)


def json_lines(raw):
    need(not raw or raw.endswith(b'\n'),'incomplete JSONL last record')
    return [strict_json(line) for line in raw.split(b'\n')[:-1]]


def full_transport(stdin, stdout):
    """Reconcile every request, continuation and ACK with full output bytes."""
    a=b=0;messages=[];transactions=[]
    def take_input():
        nonlocal a
        begin=a
        need(a+8<=len(stdin),'missing transport request')
        if stdin[a:a+8] in (b'HBCACK02',b'HBCATA02'):
            n=32;wire=stdin[a:a+n]
        else:
            n=8+words(stdin,a,1)[0]
            need(n>=16 and n<=len(stdin)-a,'framed request extent')
            wire=stdin[a+8:a+n]
        need(n<=len(stdin)-a,'short transport request')
        a+=n
        return wire,{'offset':begin,'bytes':n,'sha256':sha(stdin[begin:a])}
    def take_output():
        nonlocal b
        begin=b
        kind,n=words(stdout,b,2)
        need(kind in (1,2,3,4,6,7,8) and n<=len(stdout)-b-16,'transport response extent')
        payload=stdout[b+16:b+16+n];b+=16+n
        record={'kind':kind,'offset':begin,'bytes':16+n,'payload_bytes':n,'payload_sha256':sha(payload)}
        messages.append(record)
        return kind,payload,record
    while a<len(stdin):
        request,span=take_input();magic=request[:8]
        need(magic in (b'HBCSEL02',b'HBCFXQ02',b'HBCALQ02',b'HBCACTL2'),'unexpected top-level request')
        transaction={'request':request,'span':span,'messages':[]}
        if magic==b'HBCSEL02':
            need(len(request)==16 and words(request,8,1)[0] in (0,1,2,3),'fixture session selector')
            kind,body,record=take_output()
            need(kind==6 and body==b'HBCSLR02'+request[8:],'actual session selection response')
            transaction['messages'].append(record)
        elif magic==b'HBCFXQ02':
            slot,n,z=words(request,8,3)
            need(slot in (5,8,17,18) and z==0 and n==len(request)-32,'private owner request extent')
            kind,body,record=take_output()
            need(kind==4 and body[:8]==b'HBCFXR02','private owner response type')
            target,ret,extent=words(body,8,3)
            need(slot==target and extent==len(body)-32,'private owner full response')
            transaction['messages'].append(record)
        else:
            if magic==b'HBCALQ02':
                op,gen,seq,typed_n,path_n,z1,z2=words(request,8,7)
                need(op==1 and gen==seq==z1==z2==0 and typed_n+path_n==len(request)-64,'original START frame')
            else:need(len(request)==16 and words(request,8,1)[0] in (1,2,3),'async control frame')
            while True:
                kind,body,record=take_output();transaction['messages'].append(record)
                if kind==1:
                    need(body[:8]==b'HBCIO002','child event magic')
                    gen,seq,slot,ret,n,phase,z=words(body,8,7)
                    need(gen>0 and seq>0 and slot<22 and z==0 and n==len(body)-64,'child event extent')
                    ack,_=take_input()
                    same(ack,b'HBCACK02'+struct.pack('<3Q',gen,seq,0),'child ACK order and identity')
                elif kind in (7,8):
                    need(len(body)==160 and body[:8]==(b'HBCATE02' if kind==7 else b'HBCATB02'),'atomic event extent')
                    gen,seq,value,_,_,_,_=words(body,8,7)
                    need(body[64:72]==b'HIAATFX1' and words(body,144,1)[0]==1,'completed atomic effect')
                    if kind==8:
                        need(value in (1,2,3,4,5),'atomic await stage')
                        ack,_=take_input()
                        same(ack,b'HBCATA02'+struct.pack('<3Q',gen,seq,value),'atomic ACK order and identity')
                else:
                    need(kind in (2,3) and len(body)>=72 and body[8:16]==b'HBCAR002','terminal or pending frame')
                    ret=words(body,0,1)[0]
                    status,gen,seq,target,n,aux,z=words(body,16,7)
                    need(ret in (64,0xfffffff0) and n==len(body)-72 and z==0,'terminal body extent')
                    break
        transactions.append(transaction)
    need(a==len(stdin) and b==len(stdout),'unconsumed transport bytes')
    return messages,transactions


def decode_state(files,capture,value,kind):
    raw=raw_blob(files,capture,value)
    need(len(raw)>=64,'short complete private state')
    magic,version,used,count,extra,total,poison,end=struct.unpack_from('<8s7Q',raw)
    need(version==1 and 64<=used<=len(raw) and raw[used:]==bytes(len(raw)-used),'private state extent/tail')
    at=64;entries={}
    if kind=='history':
        need(magic==b'HHISTA01' and 64<=end<=used and poison in (0,1),'history header')
        actual=0;payload=0
        while at<end:
            kn,vn=words(raw,at,2);at+=16
            need(kn+vn<=end-at,'history item extent')
            key=raw[at:at+kn];at+=kn;body=raw[at:at+vn];at+=vn
            key.decode();body.decode();entries.setdefault(key,[]).append({'bytes':len(body),'sha256':sha(body)})
            actual+=1;payload+=len(body)
        need(at==end and actual==count and payload==total,'history item counts')
        order=[]
        for _ in range(extra):
            kn=words(raw,at,1)[0];at+=8;need(kn<=used-at,'history queue extent')
            key=raw[at:at+kn];at+=kn;key.decode();order.append(key.hex())
        need(at==used,'history trailing bytes')
        return {'poisoned':bool(poison),'total_bytes':total,'order_hex':order,
                'entries':[{'key_hex':key.hex(),'values':values} for key,values in sorted(entries.items())]}
    need(magic==b'HVCSTA01' and extra in (0,1) and total==poison==end==0,'cache header')
    for _ in range(count):
        kn,vn=words(raw,at,2);at+=16;need(kn+vn<=used-at,'cache item extent')
        key=raw[at:at+kn];at+=kn;body=raw[at:at+vn];at+=vn
        key.decode();body.decode();need(key not in entries,'duplicate cache key')
        entries[key]={'bytes':len(body),'sha256':sha(body)}
    need(at==used,'cache trailing bytes')
    return {'poisoned':bool(extra),'entries':[{'key_hex':key.hex(),'value':value} for key,value in sorted(entries.items())]}


def without_artifact(value):
    if type(value) is list:return [without_artifact(x) for x in value]
    if type(value) is dict:return {k:without_artifact(v) for k,v in value.items() if k!='artifact'}
    return value


def projection_evidence(files,capture):
    indices=json_lines(files.raw(str(capture/'projection.jsonl')))
    records={};at=0
    def take(stream,n):
        need(type(n) is int and n>=0,'projection byte extent')
        parts=[]
        while n:
            part=stream.read(min(n,1<<20));need(part,'truncated projection bytes')
            parts.append(part);n-=len(part)
        return b''.join(parts)
    with gzip.open(files.file(str(capture/'projection.bin.gz')),'rb') as stream:
        for expected_index,index in enumerate(indices,1):
            header=take(stream,64)
            number,owner,case,ret,ni,no,nw,z=struct.unpack('<8Q',header)
            need(number==expected_index and owner in (1,2) and z==0,'projection record identity')
            need(ni<=512<<20 and no<=1024<<20 and nw<=1152<<20,'projection exceeds compiled carrier')
            need(ret==(32 if owner==1 else 64),'projection native return')
            ni,no,nw=int(ni),int(no),int(nw)
            raw=take(stream,ni);before=take(stream,nw);beforeout=take(stream,no)
            out=take(stream,no);after=take(stream,nw)
            digest=hashlib.sha256(header)
            for part in (raw,before,beforeout,out,after):digest.update(part)
            n=64+ni+2*no+2*nw
            base={'index':number,'owner':owner,'case_id':case,'offset':at,'bytes':n,
                  'sha256':digest.hexdigest(),'return_code':ret}
            clock_fields=('started_monotonic_ns','invoked_monotonic_ns',
                          'returned_monotonic_ns','recorded_monotonic_ns')
            fields(index,(*base,*clock_fields),'complete projection index fields')
            same({key:index[key] for key in base},base,'complete projection index')
            clocks=[uint(index[key],'projection clock '+key) for key in clock_fields]
            need(0<clocks[0]<=clocks[1]<clocks[2]<=clocks[3],'actual native projection call interval')
            need(beforeout==b'\xa5'*no,'projection initial output bytes')
            magic=b'HJSVR002' if owner==1 else b'HBPRR002'
            need(out[:8]==magic,'projection response magic')
            status=words(out,8,1)[0];needed=words(out,24 if owner==1 else 48,1)[0]
            need(status in (0,2,3),'unexpected projection refusal')
            if status==2:need(needed>nw,'workspace growth required extent')
            elif status==3:need(needed>no,'output growth required extent')
            else:
                need(needed==0,'successful projection still needs growth')
                used=32+words(out,16,1)[0] if owner==1 else 64+sum(words(out,16,2))
                need(used<=no and out[used:]==b'\xa5'*(no-used),'projection full output/tail')
            after_digest=hashlib.sha256(after)
            if status==2:
                need(needed<=1152<<20,'projection growth exceeds compiled carrier')
                remaining=needed-nw
                while remaining:
                    part=min(remaining,1<<20);after_digest.update(bytes(part));remaining-=part
            records[number]={'owner':owner,'case_id':case,'input_bytes':ni,'input_sha256':sha(raw),
                             'output':out[:used] if status==0 else None,'before_sha256':sha(before),
                             'after_sha256':sha(after),'expanded_after_sha256':after_digest.hexdigest(),
                             'output_capacity':no,'workspace_capacity':nw,'status':status,'needed':needed}
            at+=n
        need(stream.read(1)==b'','unindexed projection tail')
    return records


def projection_sequence(records,ids,owner,case,expected_input):
    need(type(ids) is list and ids and len(set(ids))==len(ids),'projection invocation sequence')
    prior=None
    for number in ids:
        need(type(number) is int and number in records,'missing projection invocation')
        row=records[number]
        same([row['owner'],row['case_id']],[owner,case],'projection owner/case binding')
        same([row['input_bytes'],row['input_sha256']],[len(expected_input),sha(expected_input)],'projection complete input binding')
        if prior is None:
            same(row['workspace_capacity'],16512 if owner==1 else 65536,'initial projection workspace')
            same(row['before_sha256'],sha(bytes(row['workspace_capacity'])),'initial projection state')
            same(row['output_capacity'],32 if owner==1 else 64,'initial projection output')
        elif prior['status']==2:
            same(row['workspace_capacity'],prior['needed'],'exact relocated workspace extent')
            same(row['before_sha256'],prior['expanded_after_sha256'],'growth preserved full workspace')
            same(row['output_capacity'],prior['output_capacity'],'workspace growth changed output')
        elif prior['status']==3:
            same(row['workspace_capacity'],prior['workspace_capacity'],'output growth changed workspace extent')
            same(row['before_sha256'],prior['after_sha256'],'output growth changed workspace')
            same(row['output_capacity'],prior['needed'],'exact output growth extent')
        else:need(False,'projection repeated after completion')
        prior=row
    need(prior['status']==0,'projection did not complete')
    return prior['output']


def span(raw, value, *, message=False):
    if message:
        fields(value,('kind','offset','bytes','payload_bytes','payload_sha256','observed_monotonic_ns'),
               'output message fields')
        need(uint(value['observed_monotonic_ns'],'actual response clock')>0,'zero response clock')
    else:
        fields(value,('offset','bytes','sha256','started_monotonic_ns','finished_monotonic_ns'),
               'input span fields')
        start=uint(value['started_monotonic_ns'],'actual send start')
        finish=uint(value['finished_monotonic_ns'],'actual send finish')
        need(0<start<finish,'actual send interval')
    at=uint(value['offset'],'span offset');n=uint(value['bytes'],'span length')
    need(at<=len(raw) and n<=len(raw)-at,'span exceeds complete stream')
    body=raw[at:at+n]
    if message:
        kind,size=words(body,0,2)
        same([kind,size,n,sha(body[16:])],[value['kind'],value['payload_bytes'],16+size,value['payload_sha256']],
             'complete output message/index binding')
        return body[16:]
    same(sha(body),value['sha256'],'complete input span binding')
    return body


def check_tree(files,capture,tree,fixture):
    fields(tree,('root_hex','nodes'),'fixture tree fields')
    same(bytes.fromhex(tree['root_hex']),fixture,'fixture snapshot origin')
    need(type(tree['nodes']) is list and tree['nodes'],'empty fixture snapshot')
    seen={}
    for node in tree['nodes']:
        relative=bytes.fromhex(node['relative_hex'])
        need(relative not in seen and not relative.startswith(b'/') and
             all(part not in (b'.',b'..') for part in relative.split(b'/')),'snapshot relative path')
        info=node['metadata']
        fields(info,('mode','size','dev','ino','nlink','uid','gid'),'complete snapshot metadata')
        for key,value in info.items():uint(value,'snapshot '+key)
        need(info['ino']>0 and info['nlink']>0,'snapshot inode identity')
        mode=info['mode']
        if stat.S_ISREG(mode):
            content=node['content'];need(type(content['ok']) is bool,'snapshot read outcome')
            if content['ok']:
                data=raw_blob(files,capture,content['blob'])
                same(len(data),info['size'],'complete file snapshot extent')
                if 'fixture_retained_fd' in content:
                    need(content['fixture_retained_fd'] is True and type(content.get('pathname_errno')) is int and
                         content['pathname_errno']>0,'retained file descriptor observation')
            else:need(type(content['errno']) is int and content['errno']>0,'snapshot read errno')
        elif stat.S_ISLNK(mode):
            target=bytes.fromhex(node['target_hex']);same(len(target),info['size'],'complete symlink target extent')
        else:need(stat.S_ISDIR(mode) or stat.S_ISFIFO(mode),'unexpected fixture node type')
        seen[relative]=node
    need(b'' in seen and stat.S_ISDIR(seen[b'']['metadata']['mode']),'fixture root directory absent')
    for relative in seen:
        if not relative:continue
        parent=relative.rpartition(b'/')[0]
        need(parent in seen and stat.S_ISDIR(seen[parent]['metadata']['mode']),'snapshot parent is absent/not directory')


def check_state(files,capture,state,fixture,stdin,stdout,created):
    fields(state,('history','caches','locks','tree','descriptors'),'full state observation fields')
    def owner_payload(value,slot):
        request=span(stdin,value['request'])
        need(len(request)>=40 and request[8:16]==b'HBCFXQ02' and words(request,16,1)[0]==slot,'private observation request')
        response=span(stdout,value['response'],message=True)
        need(response[:8]==b'HBCFXR02' and words(response,8,1)[0]==slot,'private observation response')
        return response[32:]
    history=state['history']
    same(raw_blob(files,capture,history['raw']),owner_payload(history['wire'],17),'complete actual history state')
    same(decode_state(files,capture,history['raw'],'history'),without_artifact(history['decoded']),'decoded history equals raw state')
    same([x['session'] for x in state['caches']],sorted(created),'all actual session cache observations')
    for cache in state['caches']:
        same(raw_blob(files,capture,cache['raw']),owner_payload(cache['wire'],8),'complete actual session cache state')
        decoded={key:cache[key] for key in ('poisoned','entries')}
        same(decode_state(files,capture,cache['raw'],'cache'),without_artifact(decoded),'decoded cache equals raw state')
    locks=state['locks']
    body=raw_blob(files,capture,locks['raw'])
    same(body,owner_payload(locks['wire'],18),'complete actual global lock observation')
    need(len(body)>=64 and body[:8]==b'HRFLKR01','lock result prefix')
    check_tree(files,capture,state['tree'],fixture)
    seen=set()
    for descriptor in state['descriptors']:
        fields(descriptor,('fd','target_hex','mode'),'descriptor fields')
        fd=uint(descriptor['fd'],'descriptor number');need(fd not in seen,'duplicate actual descriptor')
        seen.add(fd);bytes.fromhex(descriptor['target_hex']);uint(descriptor['mode'],'descriptor mode')
    need({0,1,2}<=seen,'missing actual transport descriptors')


def check_result(files,capture,value,stdout):
    fields(value,('kind','native_return','status','generation','sequence','target','aux','body','wire'),'native result fields')
    raw=span(stdout,value['wire'],message=True)
    need(value['wire']['kind']==value['kind'] and value['kind'] in (2,3),'native result message type')
    need(raw[8:16]==b'HBCAR002','native result magic')
    status,gen,seq,target,n,aux,z=words(raw,16,7)
    same([words(raw,0,1)[0],status,gen,seq,target,aux,z],
         [value['native_return'],value['status'],value['generation'],value['sequence'],value['target'],value['aux'],0],
         'native result header fields')
    same(raw[72:],raw_blob(files,capture,value['body']),'native result entire body')
    same(n,len(raw)-72,'native result body extent')
    raw[72:].decode('utf-8')


def check_events(files,capture,events,hooks,stdout):
    counts={};used=[];expected_mutations=[];last_offset=-1;event_offsets=[]
    for event in events:
        kind=event.get('kind')
        if kind=='mutation':
            need(expected_mutations,'mutation without corresponding actual completed operation')
            same(event,expected_mutations.pop(0),'fixture mutation order and exact input hook')
            used.append(event['hook']);continue
        need(not expected_mutations,'fixture mutation was omitted/delayed')
        raw=span(stdout,event['wire'],message=True)
        offset=event['wire']['offset'];need(offset>last_offset,'events are out of actual stdout order')
        last_offset=offset;event_offsets.append(offset);observed=None
        if kind=='child':
            need(event['wire']['kind']==1 and raw[:8]==b'HBCIO002','actual child event type')
            gen,seq,slot,ret,n,phase,z=words(raw,8,7)
            same([gen,seq,slot,ret,phase,z],[event['generation'],event['sequence'],event['slot'],event['return_code'],event['phase'],0],
                 'actual child complete header')
            same(raw[64:],raw_blob(files,capture,event['body']),'actual child complete response')
            need(n==len(raw)-64,'actual child body extent')
            if slot==1 and phase in (4,15):observed='exists'
            if slot in (2,3) and phase in (10,16):observed='read'
            if slot==17 and phase==18:observed='history'
        else:
            need(kind in ('atomic-effect','atomic-await'),'unknown event kind')
            expected=7 if kind=='atomic-effect' else 8
            need(event['wire']['kind']==expected and len(raw)==160,'actual atomic event type/extent')
            same(list(words(raw,8,7)),event['header'],'actual atomic header')
            same(raw[64:],raw_blob(files,capture,event['effect']),'complete atomic effect and ACK')
            if kind=='atomic-await':observed={1:'atomic_metadata',2:'atomic_write',3:'atomic_permissions',4:'atomic_rename',5:'atomic_cleanup'}[event['header'][2]]
        if observed is not None:
            counts[observed]=counts.get(observed,0)+1
            for index,hook in enumerate(hooks):
                if hook['event']==observed and hook['occurrence']==counts[observed]:
                    need(index not in used,'replayed fixture mutation')
                    expected_mutations.append({'kind':'mutation','hook':index,'event':observed,'occurrence':counts[observed]})
    need(not expected_mutations and sorted(used)==list(range(len(hooks))),'missing complete fixture mutations')
    return counts,used,event_offsets


def proc_identity(raw, *, pid, umask, parent=None):
    """Read captured kernel process identity; no live /proc lookup."""
    rows={}
    for line in raw.decode('utf-8').splitlines():
        name,separator,value=line.partition(':')
        need(separator and name not in rows,'malformed/duplicate captured process status field')
        rows[name]=value.strip()
    need(type(pid) is int and pid>0 and type(umask) is int and 0<=umask<=0o777,
         'typed actual process identity')
    need(re.fullmatch(r'[0-9]+',rows.get('Pid','')) is not None,'captured process PID')
    need(re.fullmatch(r'[0-7]{4}',rows.get('Umask','')) is not None,'captured process umask')
    same(int(rows['Pid']),pid,'actual kernel PID differs from execution receipt')
    same(int(rows['Umask'],8),umask,'actual kernel umask differs from execution receipt')
    if parent is not None:
        need(re.fullmatch(r'[0-9]+',rows.get('PPid','')) is not None,'captured parent PID')
        same(int(rows['PPid']),parent,'actual kernel parent differs from producer')


def capture_evidence(files,source,capture,partition,input_raw,input_rows,manifest,producer):
    result=files.json(str(capture/'result.json'))
    same(result['schema'],'hepta.runtime.batch-call-native.v1','native capture schema')
    same(result['status'],'PASS','native producer completion')
    same(result['partition'],partition,'native partition identity')
    need(result['original_reference_status']=='NOT_RUN' and result['public_handler_replaced'] is False and
         result['whole_runtime_replaced'] is False,'native capture scope changed')
    same(result['manifest'],str(manifest),'capture executable manifest origin')
    same(result['manifest_sha256'],sha(files.raw(str(manifest))),'capture actual executable manifest')
    fixture_status=files.raw(str(capture/'fixture-proc-status-at-start.txt'))
    same(result['fixture_proc_status_at_start'],{'bytes':len(fixture_status),'sha256':sha(fixture_status)},
         'complete actual fixture process status')
    proc_identity(fixture_status,pid=producer['pid'],umask=result['fixture_umask'])
    raw_input=files.raw(str(capture/'input.bin'));same(raw_input,input_raw,'complete independently generated native input')
    same(result['input'],{'bytes':len(input_raw),'sha256':sha(input_raw)},'native full input identity')
    expected=[]
    for row in input_rows:
        meta=row['metadata'];part='async' if meta['execution']=='async' else ('wide' if meta['large'] else 'small')
        if partition==part:expected.append(row)
    rows=json_lines(files.raw(str(capture/'native-cases.jsonl')))
    same([row['case_id'] for row in rows],[row['metadata']['case_id'] for row in expected],'exact complete native partition IDs')
    same(result['cases'],len(rows),'native partition case count');same(result['full_input_cases'],215,'native full case count')
    producer_sources=['tests/hia_native/test_batch_call.py','tests/hia_native/batch_call_capture.py',
                      'tests/hia_native/batch_call_oracle/cases.py','tests/hia_native/batch_call_oracle/control_inputs.py',
                      'scripts/hia_native_loader.py']
    same(sorted(result['sources']),sorted(str(source/name) for name in producer_sources),'native producer exact source set')
    for name,expected_pin in result['sources'].items():
        raw=files.raw(name);same({'bytes':len(raw),'sha256':sha(raw)},expected_pin,'native producer full source')
    same(result['sources'][str(source/producer_sources[2])]['sha256'],CASES,'native frozen generator')
    same(result['sources'][str(source/producer_sources[3])]['sha256'],CONTROL,'native frozen continuation generator')
    projections=projection_evidence(files,capture);used_projection=[];state_sessions=set();modes={}
    build=files.json(str(manifest));elf=manifest.parent/build['elf']
    for mode in sorted({row['process'] for row in rows}):
        process_root=capture/'sessions'/mode
        process=files.json(str(process_root/'process.json'))
        started=files.json(str(process_root/'started.json'))
        same(started,{name:process[name] for name in ('command','cwd','pid','started_monotonic_ns',
            'request_timeout_seconds','umask','proc_status_at_start')},'actual native started/process identity')
        process_status=files.raw(str(process_root/'proc-status-at-start.txt'))
        same(process['proc_status_at_start'],{'bytes':len(process_status),'sha256':sha(process_status)},
             'complete actual native ELF kernel status')
        proc_identity(process_status,pid=process['pid'],umask=process['umask'],parent=producer['pid'])
        same(process['command'],[str(elf),'--'+mode],'actual native ELF argv')
        same(process['cwd'],str(source),'actual native ELF cwd')
        same(process['request_timeout_seconds'],60,'actual per-request native deadline')
        need(type(process['pid']) is int and process['pid']>0 and process['exit_code']==0 and
             process['timed_out'] is False and process['start_error'] is None and process['cleanup_killed'] is False and
             process['terminal_state']=='exited','native ELF actual completion')
        start=uint(process['started_monotonic_ns'],'native process start');end=uint(process['finished_monotonic_ns'],'native process finish')
        need(end>start and type(process['elapsed_seconds']) in (float,int) and math.isfinite(process['elapsed_seconds']),'native process elapsed')
        same(process['elapsed_seconds'],(end-start)/1e9,'native actual elapsed interval')
        streams={}
        for name in ('stdin','stdout','stderr'):
            raw=gzip.decompress(files.raw(str(process_root/(name+'.bin.gz'))))
            same({'bytes':len(raw),'sha256':sha(raw)},process['streams'][name],'native full '+name)
            streams[name]=raw
        same(streams['stderr'],b'','unexpected native fixture stderr')
        messages,transactions=full_transport(streams['stdin'],streams['stdout'])
        indexed=json_lines(files.raw(str(process_root/'messages.jsonl')))
        same(len(indexed),len(messages),'every full native message is indexed')
        previous_clock=start
        for exact,observed in zip(messages,indexed):
            fields(observed,(*exact,'observed_monotonic_ns'),'complete native message index fields')
            same({key:observed[key] for key in exact},exact,'every full native output message')
            clock=uint(observed['observed_monotonic_ns'],'actual response observation clock')
            need(previous_clock<clock<=end,'actual response order/process lifetime')
            previous_clock=clock
        modes[mode]={'process':process,'streams':streams,'messages':messages,'transactions':transactions,'referenced_starts':set(),'events':set()}
    same(result['processes'],len(modes),'actual native ELF count')
    def call_projection(value,meta):
        ids=value['projection_calls'];fields(ids,('value','typed'),'projection call lists')
        raw=json.dumps(meta['params'],ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        value_response=projection_sequence(projections,ids['value'],1,meta['case_id'],b'HJSVS002'+struct.pack('<2Q',1,len(raw))+raw)
        same(strict_json(value_response[32:]),meta['params'],'actual Value canonicalization')
        typed=projection_sequence(projections,ids['typed'],2,meta['case_id'],b'HBPRQ002'+struct.pack('<2Q',len(value_response)-32,0)+value_response[32:])
        same(typed,raw_blob(files,capture,value['typed']),'actual native typed projection')
        used_projection.extend(ids['value']+ids['typed']);return typed
    def call_request(value,meta,cwd,mode):
        typed=call_projection(value,meta)
        path=typed[64:64+words(typed,16,1)[0]]
        resolved=path if path.startswith(b'/') else cwd+b'/'+path
        request=b'HBCALQ02'+struct.pack('<7Q',1,0,0,len(typed),len(resolved),0,0)+typed+resolved
        same(request,raw_blob(files,capture,value['request']),'actual complete controller input')
        same(span(mode['streams']['stdin'],value['request_wire']),struct.pack('<Q',len(request))+request,'controller actual transport input')
        need(value['request_wire']['offset'] not in mode['referenced_starts'],'duplicate native START binding')
        mode['referenced_starts'].add(value['request_wire']['offset'])
    for row,original in zip(rows,expected):
        meta=original['metadata'];case=meta['case_id'];mode=modes[row['process']];streams=mode['streams']
        for key in ('case_id','name','domain','sequence','session'):same(row[key],meta[key],'native logical input '+key)
        same(row['case_input_sha256'],original['record']['sha256'],'entire native case input record')
        need(row['public_handler_executed'] is False and row['original_reference_status']=='NOT_RUN','native row scope')
        same(row['process'],meta['execution'],'native request mode')
        directory='sequence-'+meta['sequence'] if meta['sequence'] else 'case-'+str(case).zfill(4)
        fixture=str(capture/'files'/directory).encode();suffix=bytes.fromhex(meta['workdir_rel_hex'])
        cwd=fixture+(b'/'+suffix if suffix else b'')
        same(bytes.fromhex(row['fixture_root_hex']),fixture,'owned fixture root input')
        same(bytes.fromhex(row['workdir_hex']),cwd,'complete raw Unix workdir input')
        state_sessions.add(meta['session']);call_request(row,meta,cwd,mode)
        check_result(files,capture,row['result'],streams['stdout'])
        exchange=row['caller_exchange']
        fields(exchange,('started_monotonic_ns','finished_monotonic_ns','timeout_seconds','elapsed_seconds'),
               'complete actual caller exchange fields')
        began=uint(exchange['started_monotonic_ns'],'caller exchange start')
        ended=uint(exchange['finished_monotonic_ns'],'caller exchange finish')
        need(mode['process']['started_monotonic_ns']<=began<ended<=mode['process']['finished_monotonic_ns'],
             'caller exchange outside actual process')
        same(exchange['timeout_seconds'],60,'caller exchange deadline')
        same(exchange['elapsed_seconds'],(ended-began)/1e9,'actual caller exchange interval')
        need(ended-began<=60_000_000_000,'actual caller exceeded unchanged deadline')
        need(began<=row['request_wire']['started_monotonic_ns']<row['request_wire']['finished_monotonic_ns']<=ended,
             'actual START send outside caller interval')
        need(began<row['result']['wire']['observed_monotonic_ns']<=ended,'actual result outside caller interval')
        counts,used,offsets=check_events(files,capture,row['events'],meta['hooks'],streams['stdout'])
        same(counts,row['io_counts'],'actual completed logical operation counts')
        same(used,row['hook_used'],'actual hook order');mode['events'].update(offsets)
        for phase in ('before','after'):
            check_state(files,capture,row[phase],fixture,streams['stdin'],streams['stdout'],state_sessions)
        if meta['execution']=='sync':
            need(row['cancel'] is None and row['result']['kind']==2 and row['result']['status'] in (0,3),'sync terminal domain')
        else:
            need(row['result']['status']==4 and row['result']['kind']==2,'actual cancelled parent')
            cancel=row['cancel'];blocked=cancel['blocked']
            need(blocked['parent']==mode['process']['pid'] and type(blocked['pid']) is int and blocked['pid']>0 and
                 'wait_for_partner' in blocked['wchan'] and type(blocked['syscall']) is str,'actual blocked private worker observation')
            check_result(files,capture,cancel['late'],streams['stdout'])
            need(cancel['late']['kind']==2 and cancel['late']['status']==7,'actual late worker retirement')
            transfer=raw_blob(files,capture,cancel['transfer'])
            if meta['cancel']['stage']=='first_read':
                same(transfer,blob(input_raw,original,meta['cancel']['transfer_blob']),'complete actual late FIFO read input')
            else:need(transfer,'actual late write lost entire body')
            control_path=files.path(str(source/'tests/hia_native/batch_call_oracle/control_inputs.py'))
            control=load(control_path,'_batch_companion_qualification').cancel_followup(meta)
            followup=cancel['followup']
            same(followup['input_metadata'],control['metadata'],'subordinate cancellation continuation input')
            same(len(followup['input_blobs']),len(control['blobs']),'complete followup fixture blob count')
            for observed,expected_blob in zip(followup['input_blobs'],control['blobs']):
                same(raw_blob(files,capture,observed),expected_blob,'complete followup fixture bytes')
            input_module=load(files.path(str(source/'tests/hia_native/batch_call_oracle/cases.py')),'_batch_input_qualification_followup')
            same(followup['input_record_sha256'],sha(input_module.record(control['metadata'],control['blobs'])),'entire continuation input record')
            followmeta=dict(control['metadata'],case_id=case)
            call_request(followup,followmeta,cwd,mode);check_result(files,capture,followup['result'],streams['stdout'])
            need(followup['result']['status'] in (0,3) and followup['result']['kind']==2,'subordinate native followup result')
            followcounts,followused,followoffsets=check_events(files,capture,followup['events'],[],streams['stdout'])
            same(followcounts,followup['io_counts'],'actual continuation logical operations');mode['events'].update(followoffsets)
            for phase in ('before','after'):
                check_state(files,capture,followup[phase],fixture,streams['stdin'],streams['stdout'],state_sessions)
    same(sorted(used_projection),list(range(1,len(projections)+1)),'every projection used exactly once')
    same(result['projection_calls'],len(projections),'actual projection count')
    for mode in modes.values():
        starts={value['span']['offset'] for value in mode['transactions'] if value['request'][:8]==b'HBCALQ02'}
        same(sorted(mode['referenced_starts']),sorted(starts),'every actual native START is bound')
        actual_events={x['offset'] for x in mode['messages'] if x['kind'] in (1,7,8)}
        same(sorted(mode['events']),sorted(actual_events),'every actual child/effect event is retained')
    same(result['post_cancel_followup_calls'],sum(x['cancel'] is not None for x in rows),'actual subordinate followup count')
    for name,value in result['blobs'].items():
        raw_blob(files,capture,dict(value,artifact=name))
    return {'partition':partition,'cases':len(rows),'case_ids':[x['case_id'] for x in rows],
            'actual_native_elf_processes':len(modes),'projection_calls':len(projections),
            'fixture_umask':result['fixture_umask'],
            'elf_umasks':{mode:value['process']['umask'] for mode,value in sorted(modes.items())},
            'post_cancel_followup_calls':result['post_cancel_followup_calls'],
            'body_bytes':sum(x['result']['body']['bytes'] for x in rows),'fixture_directories':sorted({x['fixture_root_hex'] for x in rows})}


def native_evidence(*,native_source,native_run,build_source,manifest,origins):
    """Pure native predecessor admission. All paths are execution origins.

    ``origins`` supplies explicit origin/read-root pairs. Relocated readers never
    consult the old tree or live fixtures. No original code is executed here.
    """
    native_source,native_run,build_source,manifest=map(Path,(native_source,native_run,build_source,manifest))
    need(all(x.is_absolute() for x in (native_source,native_run,build_source,manifest)),'native origin roots')
    files=Files(origins)
    source_table=files.json(str(native_run/'SOURCE-FILES.json'))
    need(type(source_table) is dict and source_table,'native immutable source snapshot')
    for name,digest in source_table.items():
        path=Path(name)
        need(not path.is_absolute() and '..' not in path.parts and type(digest) is str,'native source table path')
        same(sha(files.raw(str(native_source/path))),digest,'native source snapshot full bytes')
    case_path=native_source/'tests/hia_native/batch_call_oracle/cases.py'
    need(sha(files.raw(str(case_path)))==CASES,'frozen independent native generator changed')
    generator=load(files.path(str(case_path)),'_batch_native_input_regeneration')
    buffer=io.BytesIO();same(generator.write_input(buffer),215,'independent generated case count')
    raw_input=buffer.getvalue();inputs=parse_records(raw_input,b'HBCCI002')
    need(len(inputs)==215 and len({x['metadata']['case_id'] for x in inputs})==215,'unique original input IDs')
    build=build_evidence(files,build_source,manifest)
    processes=files.json(str(native_run/'PROCESSES.json'))
    process_names=[x['name'] for x in processes]
    support=[x for x in processes if x['name'] not in ('small','wide','async')]
    partitions=[x for x in processes if x['name'] in ('small','wide','async')]
    same([x['name'] for x in partitions],['small','wide','async'],'complete actual native partition processes')
    need(process_names in (['small','wide','async'],
                           ['generate-strings','build','string-helpers','small','wide','async'],
                           ['build','private-state','small','wide','async']),
         'unaccounted native preparation/qualification process')
    complete=files.json(str(native_run/'RESULT.json'))
    same(complete['status'],'PASS','complete actual native producer run')
    need(complete['source_unchanged'] is True and complete['original_reference_status']=='NOT_RUN' and
         complete['public_handler_replaced'] is False,'producer source/scope admission')
    same(complete['processes'],processes,'complete producer receipt identity')
    if 'native_manifest' in complete:
        same(complete['native_manifest'],str(manifest),'producer actual build origin')
        same(complete['native_manifest_sha256'],sha(files.raw(str(manifest))),'producer actual manifest bytes')
    support_sources={'generate-strings':'authoring/batch_strings/generate.py',
                     'build':'authoring/build_graph_v1.py',
                     'private-state':'tests/hia_native/test_batch_call_state.py',
                     'string-helpers':'authoring/batch_strings/test_helpers.py'}
    for process in support:
        name=process['name']
        script=native_source/('scripts/hia_native_batch_call_build.py'
            if name=='build' and build['source_owned_builder'] else support_sources[name])
        files.raw(str(script))
        command=[process['command'][0],'-I','-B',str(script)]
        if name=='build' and build['source_owned_builder']:
            need(len(process['command'])==10 and Path(process['command'][5]).is_absolute(),
                 'actual source-owned builder selected compiler invocation')
            command.extend(['--hepta',process['command'][5],'--output',str(manifest.parent),
                            '--source',str(native_source)])
        if name=='private-state':
            command.extend(['--manifest',str(manifest),'--output',str(native_run/'state-controls')])
        actual_process(process,command,native_source)
        for kind in ('stdout','stderr'):
            raw=files.raw(str(native_run/(name+'.'+kind)))
            same(process[kind],{'bytes':len(raw),'sha256':sha(raw)},'complete actual preparation '+kind)
            if kind=='stderr':same(raw,b'','native preparation stderr')
    captures=[]
    for process in partitions:
        part=process['name'];capture=native_run/('output-'+part)
        command=[process['command'][0],'-I','-B',str(native_source/'tests/hia_native/test_batch_call.py'),
                 '--manifest',str(manifest),'--output',str(capture),'--partition',part]
        need(Path(command[0]).is_absolute(),'actual Python executable path')
        actual_process(process,command,native_source)
        stdout=files.raw(str(native_run/(part+'.stdout')));stderr=files.raw(str(native_run/(part+'.stderr')))
        same(process['stdout'],{'bytes':len(stdout),'sha256':sha(stdout)},'complete actual native process stdout')
        same(process['stderr'],{'bytes':len(stderr),'sha256':sha(stderr)},'complete actual native process stderr')
        same(stderr,b'','unexpected native process stderr')
        admitted=capture_evidence(files,native_source,capture,part,raw_input,inputs,manifest,process)
        emitted=json_lines(stdout)
        need(len(emitted)==admitted['cases']+1,'native outer stdout complete case emissions')
        same([x['case_id'] for x in emitted[:-1]],admitted['case_ids'],'native actual case execution order')
        same(emitted[-1],{'status':'PASS','cases':admitted['cases'],'error':None},'actual producer terminal stdout')
        captures.append(admitted)
    same(sum(x['cases'] for x in captures),215,'all complete native cases')
    same(sum(x['post_cancel_followup_calls'] for x in captures),2,'actual subordinate native requests')
    return {'schema':'hepta.runtime.batch-call-native-predecessor.v1','status':'PASS',
        'cases':215,'native_gate_processes':3,'preparation_processes':len(support),
        'native_elf_processes':sum(x['actual_native_elf_processes'] for x in captures),
        'post_cancel_followup_calls':2,'projection_calls':sum(x['projection_calls'] for x in captures),
        'body_bytes':sum(x['body_bytes'] for x in captures),'build':build,'captures':captures,
        'input':{'bytes':len(raw_input),'sha256':sha(raw_input)},'original_reference_executed':False,
        'public_handler_replaced':False,'whole_runtime_replaced':False,'new_native_calls':0,
        'artifact_sha256':{name:value['sha256'] for name,value in sorted(files.artifacts.items())}}
