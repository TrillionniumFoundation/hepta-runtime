"""Admission of the completed native predecessor for original replay.

This reads the actual four source-bound native domains, complete framed streams,
full snapshots and effect receipts. Detailed native kernel/private-state
qualification is maintained independently by the native owner.
"""
from pathlib import Path
import hashlib,struct
from common import Files,require,pin,same,frames,parse_wire,snapshot,unb64,integer

DOMAINS={'ordinary':38,'paths':23,'metadata':29,'wide':9}
ELF_SHA='cbd3869e3b336fea03dbf1fffe995fe08d589d6a5d200d41141675cf65f38967'
FIXTURE_SHA='444145bdbb842da038d18d04f18484782fad7d5e50b213ef6dd78a8ac0e8b1b1'
def evidence(native_root,native_source,build_root,origins):
    files=Files(origins);root=Path(native_root);source=Path(native_source);build=Path(build_root)
    aggregate=files.json(root/'RESULT.json')
    require(aggregate['status']=='PASS' and aggregate['native_elf_sha256']==ELF_SHA and aggregate['cases']==144,'completed native source scope')
    seeds=files.json(root/'SOURCE-PINS.json')
    for name,expected in seeds.items():files.raw(root/'source'/name,expected)
    require(seeds['scripts/hia_native_text_publication_fixtures.py']['sha256']==FIXTURE_SHA,'unique native fixture source')
    native_pins=files.json(root/'NATIVE-PINS.json')
    for name,expected in native_pins.items():files.raw(name,expected)
    manifest=files.json(build/'manifest.json')
    require(manifest['schema']=='hepta.runtime.text-publication-build.v1' and manifest['elf_sha256']==ELF_SHA,'actual native build identity')
    elf=files.raw(build/manifest['elf'],ELF_SHA)
    require(len(manifest['members'])==3 and manifest['slots']==[0,1,2],'actual three HIA members')
    for member,offset in zip(manifest['members'],manifest['image_offsets']):
        mf=build/member['manifest'];m=files.json(mf,member['manifest_sha256'])
        image=files.raw(mf.parent/m['image'],member['image_sha256'])
        require(len(image)==member['image_bytes'] and elf[offset:offset+len(image)]==image,'actual ELF complete HIA image')
        files.raw(source/member['source'],member['source_sha256'])
        files.raw(mf.parent/m['source'],member['source_sha256'])
    files.raw(source/manifest['builder_source'],manifest['builder_sha256'])
    files.raw(source/manifest['packer_composition'],manifest['packer_composition_sha256'])
    files.json(build/manifest['packer_manifest'],manifest['packer_manifest_sha256'])
    for name,sha in manifest['sources'].items():files.raw(source/name,sha)
    result_rows=[];effects_total=0
    for domain,count in DOMAINS.items():
        folder=root/'domains'/domain;res=files.json(folder/'RESULT.json')
        require(res['status']=='PASS' and res['domain']==domain and res['cases']==res['original_eligible_cases']==count,'actual native domain completion')
        descriptions=files.json(folder/'corpus.json',res['corpus'])
        require(len(descriptions)==count and len({d['name'] for d in descriptions})==count,'complete unique logical input')
        for name,expected in res['source_pins'].items():files.raw(root/'source/scripts'/name,expected)
        outer=files.json(root/(domain+'.process.json'))
        require(outer['exit_code']==0 and outer['timed_out'] is False and outer['timeout_seconds']==180,'actual native parent gate')
        integer(outer['pid'],'actual native producer PID',1)
        require(type(outer['elapsed_seconds']) in (int,float) and 0<outer['elapsed_seconds']<180,'actual native parent interval')
        same(outer['command'],[outer['command'][0],'-I','-B',str(root/'source/scripts/qualify_hia_text_publication_native.py'),
            '--elf',str(build/'text-publication.elf'),'--output',str(folder),'--diagnostics',str(root/'source/authoring/diagnostics.json'),
            '--domain',domain],'actual native producer command')
        require(outer['cwd']==str(root/'source'),'actual native producer cwd')
        files.raw(root/(domain+'.stdout'),outer['stdout']);require(files.raw(root/(domain+'.stderr'),outer['stderr'])==b'','actual native producer stderr')
        proc=files.json(folder/'process/process.json');same(proc,res['process'],'whole native process identity')
        require(proc['command']==[str(build/'text-publication.elf'),'--trace'] and proc['cwd']==str(folder/'process'),'native ELF invocation')
        require(proc['exit_code']==0 and proc['failure'] is None and proc['killed_by_harness'] is False and proc['stdout_unframed_bytes']==0,'native clean natural terminal')
        integer(proc['pid'],'actual native ELF PID',1)
        streams={name:files.raw(folder/'process'/p['file'],{'bytes':p['bytes'],'sha256':p['sha256']}) for name,p in proc['streams'].items()}
        require(set(streams)=={'stdin','stdout','stderr'},'all complete native streams')
        inputs=frames(streams['stdin']);outputs=frames(streams['stdout'])
        require(len(inputs)==len(outputs)==len(proc['exchanges'])==2*count,'native START/DROP frame count')
        effect_stream=streams['stderr'];require(len(effect_stream)%256==0,'complete native effect records')
        effects=files.json(folder/'effects.json',res['effects']);require(len(effects)==len(effect_stream)//256==res['native_effects'],'native receipt count')
        last_sequence=0
        for index,item in enumerate(effects):
            raw=effect_stream[index*256:(index+1)*256]
            require(raw[:8]==b'HTXTEF01' and raw[64:72]==b'HTXTFX01','actual effect magic')
            gen,seq,kind,phase,actual,capacity,reserved=struct.unpack_from('<7Q',raw,8)
            fields=struct.unpack_from('<16Q',raw,64)
            require(fields[1:4]==(seq,gen,kind) and seq==last_sequence+1 and reserved==0,'monotonic full effect identity')
            require(fields[13]==1 and fields[12]==fields[14]==fields[15]==0,'actual completed effect')
            signed=actual if actual<1<<63 else actual-(1<<64)
            same([item['generation'],item['sequence'],item['kind'],item['phase'],item['raw_linux_return'],item['workspace_capacity']],
                 [gen,seq,kind,phase,signed,capacity],'full original receipt header projection')
            same(item['args'],list(fields[4:10]),'complete effect arguments')
            require(item['value']==fields[10] and item['errno']==fields[11] and item['stream_offset']==index*256 and item['frame_sha256']==pin(raw)['sha256'],'complete effect result projection')
            require(1<=kind<=19 and capacity>=4096 and fields[11]<=4095,'effect scalar domain')
            if fields[11]:require(fields[10]==0 and signed==-fields[11],'actual kernel error provenance')
            for slot in range(4):
                fd,serial=struct.unpack_from('<qQ',raw,192+slot*16)
                same(item['slots'][slot],{'slot':slot+1,'fd':fd,'opening_sequence':serial},'actual full descriptor observation')
                require((fd==-1 and serial==0) or (fd>=0 and 0<serial<=seq),'actual owned descriptor serial')
            last_sequence=seq
        sequence=0
        for ordinal,(description,row) in enumerate(zip(descriptions,res['rows'])):
            require(row['name']==description['name'] and row['ordinal']==ordinal and row['status']=='PASS' and row['original_eligible'] is True,'complete native case index')
            case=folder/'cases'/row['name'];saved=files.json(case/'case.json');same(saved,row,'complete native case receipt')
            request=files.raw(case/'input.bin',row['input']);record=files.raw(case/'record.bin',row['record'])
            require(inputs[ordinal*2]==request and outputs[ordinal*2]==record,'native full transport START binding')
            mode,path,expected,text=parse_wire(request)
            req=description['request'];suffix=unb64(req['path_base64'])
            require(path==(str(row['fixture']).encode()+suffix if req['path_anchor']=='fixture' else suffix),'exact native raw Unix path input')
            require(row['fixture']==str(folder/'fixtures'/str(ordinal)),'owned native fixture origin')
            require(mode==req['mode'] and row['request']['mode']==mode and unb64(row['request']['path_base64'])==path and unb64(row['request']['expected_base64'])==expected,'complete request projection')
            require(row['request']['content_bytes']==len(text) and row['request']['content_sha256']==pin(text)['sha256'],'complete native text input')
            before=snapshot(files,case/'before.json',folder/'blobs');after=snapshot(files,case/'after.json',folder/'blobs')
            require(record[:8]==b'HTXTER01' and len(record)>=64,'native full result frame')
            code,gen,seq,pn,live,phase,reserved=struct.unpack_from('<7Q',record,8)
            body=record[64:];require(code==pn==len(body) and live==reserved==0 and phase==100 and body[:8]==b'HTXTR001','native terminal result extent')
            tag,en,size,was_new,bg,bs,zero=struct.unpack_from('<7Q',body,8)
            require(tag in (0,1) and (bg,bs)==(gen,seq) and zero==0 and gen==ordinal+1,'native terminal result identity')
            require(row['generation']==gen and row['last_sequence']==seq and row['first_sequence']==sequence+1 and row['effects']==seq-sequence,'native per-case complete sequence')
            selected=effects[sequence:seq]
            require(all(e['generation']==gen for e in selected),'complete case-specific actual effects')
            published=[e for e in selected if e['kind']==17 and e['errno']==0]
            if tag==1:
                require(en==len(body)-64 and size==was_new==0 and len(published)==0,'native error exact body')
                body[64:].decode('utf-8');same(before,after,'ordinary rejected publication preserved actual whole fixture')
            else:
                require(en==0 and len(body)==160 and body[152:]==b'\0'*8 and len(published)==1 and was_new==(mode==1),'native actual successful publication')
                targets=[r for r in after if r['path_base64']==description['expect']['target_base64']]
                require(len(targets)==1 and targets[0]['kind']=='file','actual native published target')
                target=targets[0];raw=files.raw(folder/'blobs'/target['data']['file'],{'bytes':target['data']['bytes'],'sha256':target['data']['sha256']})
                require(size==len(raw) and body[120:152]==hashlib.sha256(raw).digest(),'native full published byte digest')
                same(list(struct.unpack_from('<7Q',body,64)),target['identity'],'native result actual seven-field stat')
            drop=b'HTXTQ001'+struct.pack('<7Q',2,0,0,0,0,gen,0)
            dropped=files.raw(case/'drop-record.bin')
            require(inputs[ordinal*2+1]==drop and outputs[ordinal*2+1]==dropped,'native full DROP transport')
            require(dropped==b'HTXTER01'+struct.pack('<7Q',64,gen,seq,64,0,0,0)+b'HTXTR001'+struct.pack('<7Q',2,0,0,0,gen,seq,0),'actual complete terminal DROP')
            for j in (ordinal*2,ordinal*2+1):
                e=proc['exchanges'][j]
                require(e['timeout_seconds']==60 and type(e['elapsed_seconds']) in (int,float) and 0<e['elapsed_seconds']<60,'actual native exchange budget')
                require(e['request_bytes']==len(inputs[j]) and e['request_sha256']==pin(inputs[j])['sha256'] and e['record_bytes']==len(outputs[j]) and e['record_sha256']==pin(outputs[j])['sha256'],'complete exchange input/output')
            sequence=seq
            result_rows.append({'domain':domain,'ordinal':ordinal,'name':row['name'],'case_id':len(result_rows),
                'native_input':str(case/'input.bin'),'native_input_pin':pin(request),'native_record':str(case/'record.bin'),
                'native_record_pin':pin(record),'native_fixture':row['fixture'],'tag':tag,'effects':len(selected)})
        require(sequence==len(effects),'all native effect receipts consumed')
        effects_total+=len(effects)
    return {'schema':'hepta.runtime.text-publication-original-native-predecessor.v1','status':'PASS',
        'cases':99,'domains':DOMAINS,'native_effects':effects_total,'rows':result_rows,
        'native_execution_precedes_reference':True,'new_native_calls':0,'new_original_processes':0,
        'native_fresh_build_qualification':False,'detailed_private_native_qualification_in_separate_owner_reader':True,
        'artifact_sha256':files.artifacts}
