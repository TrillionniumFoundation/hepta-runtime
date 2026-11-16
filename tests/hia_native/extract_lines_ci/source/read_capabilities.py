"""Read the complete actual exported-call journal, including real suspended leases."""
from pathlib import Path
import struct
from common import ROOT, files, loads, pin, read, require, sha
import native_observations as arena


def word(raw,at):return struct.unpack_from('<Q',raw,at)[0]


def verify(root,native_summary):
    root=Path(root);domain=loads(read(ROOT/'DOMAIN.json'));report=loads(read(root/'result.json'))
    events=loads(read(root/'events.json'));members=loads(read(ROOT/'MEMBERS.json'))
    require(report['status']=='PASS' and report['build_verification']==native_summary
            and report['original_processes']==0 and report['full_body_async_qualified'] is False
            and report['public_handler_qualified'] is False and report['callback_exception'] is None
            and 0<report['elapsed_seconds']<180,'actual capability scope and original budget')
    require(len(events)==66 and report['actual_export_calls']==51 and report['actual_explicit_owner_calls']==15,
            'every actual capability call exactly once')
    require(sum(e.get('code')==0xffffffdf for e in events)==7,'all actual physical wait returns')
    require(report['cases']==[dict(name=name,status='PASS',actual_calls=end) for name,end in domain['capability_cases']],
            'all source-owned physical capability cases')
    code=loads(read(root/'code-proof.json'))
    require(report['code_proof']==code and code['source_sha256']==sha(read(ROOT/'native/local_extract_lines_callable.S'))
            and code['code_sha256']==members['export_code']['sha256'] and code['code_bytes']==members['export_code']['bytes']
            and code['exports']==members['exports'] and code['mapping_kernel_sealed'] is True and code['commands']==[]
            and pin(read(root/'export.bin'))==members['export_code'],'actual kernel-sealed exported code')
    vault=root/'blobs';seen=set();physical=0
    def blob(row):
        nonlocal physical
        require(set(row)=={'path','bytes','sha256'} and row['path']==row['sha256']+'.bin','fixed physical blob path')
        raw=read(vault/row['path']);require(pin(raw)=={k:row[k] for k in ('bytes','sha256')},'full physical blob identity')
        seen.add(row['path']);physical+=len(raw);return raw
    decoded=[]
    for event in events:
        values={k:blob(v) if isinstance(v,dict) and 'path' in v else v for k,v in event.items()}
        if event['kind']=='owner':
            require(event['owner'] in (3,6,8) and event['code'] in (32,64),'actual explicit shared owner call')
            require(len(values['output'])==event['code'],'complete explicit owner output')
            require(values['input'][:8]=={3:b'HRFLOCK1',6:b'HHISTQ01',8:b'HVCACH01'}[event['owner']],
                    'explicit owner frame')
            require(values['output'][:8]=={3:b'HRFLKR01',6:b'HHISTR01',8:b'HVCAR001'}[event['owner']],
                    'actual explicit owner response')
        else:
            require(event['kind']=='export' and event['function'] in ('run','resume','cancel_wait','release'),
                    'only frozen mechanical exports')
            before,after=values['context_before'],values['context_after']
            require(len(before)==len(after)==192,'complete physical callable context')
            require(values['target_mode']==0o644,'complete target permission preservation')
            for name in ('lock_state','history_state','cache_state'):
                state=values[name];require(len(state)>=4096 and len(state)%4096==0,'complete physical shared arena')
                used=word(state,16);require(used<=len(state) and not any(state[used:]),'complete shared arena tail')
            locks=values['lock_state']
            require(locks[:8]==b'HFLSTATE' and word(locks,8)==1 and not any(locks[80:256]),'complete actual lock header')
            if word(locks,72)==0:arena.locks(locks,1,1)
            arena.history(values['history_state'],1,1);arena.cache(values['cache_state'],1,1)
            code=event['code'];out=values['output']
            if code==0xffffffdf:
                require(out[:8]==b'HLTBWT01' and len(out)==48 and word(out,8)>0 and word(out,16)>0
                        and word(out,24)>0 and out[32:]==bytes(16) and word(locks,72) in (2,3),
                        'actual suspended HIA lease and complete wait frame')
            elif code<0xffff0000 and event['function']!='release':
                if code!=16:
                    require(code==len(out) and out[:8]==b'HEXTRP01' and word(out,8)==1 and word(out,16)==0
                            and word(out,24)==len(out)-32,'complete successful native body response')
                    out[32:].decode('utf-8')
        decoded.append(values)
    require(set(files(vault))==seen and report['complete_retained_blobs']==len(seen),'entire physical journal blob set')
    require([e['owner'] for e in decoded[:3]]==[3,6,8],'explicit shared owner initialization')
    for event in decoded[3:17]:
        require(event['kind']=='export' and event['function']=='run' and event['code']==0xffffffff
                and event['context_before']==event['context_after'] and event['target']==b'alpha\n',
                'actual refused capability preserves complete context and target')
    for offset in range(17,25,2):
        run,release=decoded[offset:offset+2]
        require(run['function']=='run' and run['code']==0xffffffff and release['function']=='release'
                and release['code']==0 and run['target']==release['target']==b'alpha\n',
                'physical malformed request refusal and complete release')
    # Each finite suspended sequence is read from actual physical state. The
    # reader never invokes an owner or invents an asynchronous host outcome.
    waited=[e for e in decoded[25:38] if e.get('code')==0xffffffdf]
    require(len(waited)==4 and len({word(e['output'],24) for e in waited})==1
            and [word(e['output'],16) for e in waited]==sorted({word(e['output'],16) for e in waited})
            and all(e['target']==b'alpha\n' for e in waited),'three real resumes retain one queued lease')
    require(decoded[28]['code']==16 and decoded[28]['context_before']==decoded[28]['context_after'],
            'active wait cannot be released')
    require(decoded[33]['function']=='cancel_wait' and decoded[33]['code']==0xfffffff7
            and word(decoded[33]['lock_state'],72)==1,'cancel drops only the actual waiting lease')
    require(word(decoded[37]['workspace_after'],72)==0,'external predecessor released after cancellation')
    require(decoded[43]['function']=='resume' and decoded[43]['target']==b'beta\nalpha\n'
            and word(decoded[43]['lock_state'],72)==0,'actual predecessor release permits one completion')
    require(decoded[47]['code']==decoded[48]['code']==0xffffffdf
            and word(decoded[48]['lock_state'],72)==3
            and decoded[49]['code']==0xfffffff7 and word(decoded[49]['lock_state'],72)==2
            and decoded[53]['function']=='resume' and decoded[53]['target']==b'beta\nalpha\n'
            and word(decoded[53]['lock_state'],72)==0,'two real waiters preserve separate cancellation and completion')
    for offset in (55,57):
        run=decoded[offset]
        require(run['code']==0xfffffffc and word(run['context_after'],160)==70
                and run['target']==b'beta\nalpha\n' and word(run['lock_state'],72)==0,
                'callback refusal retains completed atomic write and drains lease')
    large=b'alpha\n'+b'x'*8192
    for offset,failure in ((59,71),(61,70)):
        run=decoded[offset]
        require(run['code']==0xfffffffc and word(run['context_after'],160)==failure
                and run['target']==large and word(run['lock_state'],72)==0,'refused or false growth preserves pre-write target')
        require(run['history_state']==decoded[58]['history_state'],'growth refusal cannot repeat a history push')
    final=decoded[64];require(final['function']=='run' and final['code']==len(final['output'])
            and final['target']==b'beta\n'+large and word(final['lock_state'],72)==0,'actual shared growth completes once')
    history=arena.history(final['history_state'],1,1)
    require(history['snapshots']==5 and len(history['entries'])==1
            and next(iter(history['entries'].values()))==[b'alpha\n']*4+[large],
            'complete shared history contains exactly the actual pre-write snapshots')
    require(read(root/'fixtures/file')==b'beta\n'+large and read(root/'fixtures/source')==b'beta\n',
            'actual retained capability files')
    return dict(status='PASS',cases=26,export_calls=51,explicit_owner_calls=15,
                actual_wait_returns=7,physical_bytes=physical,full_body_async_qualified=False)
