"""Pure complete-buffer reader for isolated native pending ABI controls."""
from pathlib import Path
import argparse, hashlib, json, struct
word=lambda raw,at:struct.unpack_from('<Q',raw,at)[0]
pin=lambda raw:dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def frame(magic,*values):return magic+struct.pack('<'+'Q'*len(values),*values)

def verify(package,build,capture):
    manifest=json.loads((package/'package-manifest.json').read_bytes())
    assert {str(p.relative_to(package)) for p in package.rglob('*') if p.is_file()}==set(manifest['files'])|{'package-manifest.json'}
    assert not any(p.is_symlink() for p in package.rglob('*'))
    for name,identity in manifest['files'].items():assert pin((package/name).read_bytes())==identity,name
    domain=json.loads((package/'domain.json').read_bytes())
    source=bytes.fromhex(domain['input_hex']);tag=domain['tag'];job=domain['job'];sequence=domain['sequence']
    built=json.loads((build/'build.json').read_bytes())
    assert built['status']=='BUILD_PASS' and built['fresh_components']==1 and built['reused_components']==0
    manifests=[p for p in build.rglob('*.json') if pin(p.read_bytes())['sha256']==built['manifest_sha256']]
    assert len(manifests)==1
    module=json.loads(manifests[0].read_bytes());image=(manifests[0].parent/module['image']).read_bytes()
    assert pin(image)['sha256']==built['image_sha256']==module['image_sha256']
    assert module['source_sha256']==built['source_sha256']==pin((package/'source/native/runtime_mcp.hepta').read_bytes())['sha256']
    compiler='bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0'
    for name in ['B1.image.bin','B2.image.bin','B3.image.bin']:
        assert pin((build/'bootstrap'/name).read_bytes())==dict(bytes=673413,sha256=compiler)
    assert module['compiler_sha256']==compiler
    blobs={}
    for p in (capture/'blobs').iterdir():
        assert p.is_file() and not p.is_symlink()
        raw=p.read_bytes();assert pin(raw)['sha256']==p.name;blobs[p.name]=raw
    used=set()
    def blob(identity):
        raw=blobs[identity['sha256']];assert pin(raw)==identity;used.add(identity['sha256']);return raw
    calls=[json.loads(line) for line in (capture/'calls.jsonl').read_text().splitlines()]
    events=[json.loads(line) for line in (capture/'events.jsonl').read_text().splitlines()]
    groups={n:[] for n in [r['name'] for r in domain['cases']]+domain['lifecycle']}
    for i,row in enumerate(calls):
        assert row['index']==i and row['case'] in groups and blob(row['input'])==source
        before_o=blob(row['before_output']);before_w=blob(row['before_workspace'])
        out=blob(row['output']);work=blob(row['workspace'])
        assert len(out)==len(before_o)==row['output_capacity']
        assert len(work)==len(before_w)==row['workspace_capacity']
        code=row['code'];groups[row['case']].append(row)
        if code in (0xffffffff,0xfffffffe):
            assert out==before_o,'refusal wrote output'
            assert work==before_w,'refusal mutated live continuation'
        elif code==0xffffffd0:
            assert out[:8]==b'HGRWS002' and word(out,8)==1 and word(out,16)>len(work) and word(out,24)==0
            assert out[32:]==before_o[32:]
        elif code==0xfffffff0:
            a=struct.unpack_from('<14Q',work,256)
            assert work[256:264]==b'HRMCFA02' and a[2:4]==(14,0) and a[8:]==(0,0,0,0,0,0)
            assert a[1]==word(work,16) and a[4]>=4096 and a[5]==64 and a[5]<=len(work)-a[4]
            assert a[6]>=4096 and a[7]>=64 and a[7]<=len(work)-a[6]
            request=work[a[4]:a[4]+a[5]]
            assert request[16:24]==struct.pack('<Q',tag) and request[24:]==bytes(40)
            if request[:8]==b'HBLCLQ01':
                assert word(request,8) in (2,3) and word(work,8)==16 and word(work,1304)==word(request,8)
            else:
                assert request[:8]==b'HBLRET01' and word(request,8)==1 and word(work,8)==17 and word(work,1312)==4
            assert work[1344:1408]==bytes(64),'host control was not consumed once'
        elif code==64:
            kind=word(out,8);seq=word(work,16);assert kind in (0,4)
            assert out==frame(b'HRCMFR02',kind,0,0,0,0,seq,0)
            if kind==4:
                assert word(work,8)==97 and work[1280:1344]==frame(b'HBLFRS01',tag,job,0,0,seq,0,0)
                assert work[1344:1408]==bytes(64)
            else:assert word(work,8)==0 and work[1280:1408]==bytes(128)
        else:raise AssertionError(('unexpected native return',i,code))
    for row in domain['cases']:
        trace=groups[row['name']];assert trace
        assert trace[-1]['code']=={'invalid':0xffffffff,'short':0xfffffffe,'pending':64,'child':0xfffffff0}[row['expect']]
        if row.get('relocate'):assert len(trace)>1 and all(x['code']==0xffffffd0 for x in trace[:-1])
        else:assert len(trace)==1
        if row['expect']=='child':assert word(blob(trace[-1]['workspace']),16)==sequence+1
    for name in domain['lifecycle']:
        trace=groups[name];codes=[r['code'] for r in trace];trimmed=[c for c in codes if c!=0xffffffd0]
        if name.startswith('poll-'):
            assert trimmed==[0xfffffff0,0xffffffff,64,0xffffffff]
            assert word(blob(trace[2]['workspace']),16)==sequence+1
        else:
            assert trimmed==[0xfffffff0,0xffffffff,0xfffffff0,64]
            assert word(blob(trace[-1]['workspace']),16)==sequence+2
        assert (0xffffffd0 in codes)==name.endswith('workspace-relocation')
    return complete(package,capture,domain,calls,events,blobs,blob,used)

def complete(package,capture,domain,calls,events,blobs,blob,used):
    tag=domain['tag'];job=domain['job'];relocations=0;acknowledgments=0
    for i,event in enumerate(events):
        assert event['index']==i
        prior=calls[event['after_call_index']];assert prior['case']==event['case']
        old=blob(prior['workspace'])
        if event['kind']=='relocation':
            relocations+=1;assert prior['code']==0xffffffd0
            assert event['workspace_address_changed'] and event['output_address_changed']
            assert event['old_workspace_capacity']==len(old)
            following=calls[event['after_call_index']+1]
            assert following['case']==event['case']
            assert len(blob(following['before_workspace']))==event['new_workspace_capacity']
            assert blob(following['before_workspace'])[:len(old)]==old
            previous_output=blob(prior['output'])
            assert blob(following['before_output'])[:len(previous_output)]==previous_output
        else:
            assert event['kind']=='test_owned_child_acknowledgment';acknowledgments+=1
            before=blob(event['before_workspace']);after=blob(event['after_workspace']);assert before==old
            a=struct.unpack_from('<14Q',before,256);assert a[1]==event['sequence']
            assert blob(event['request'])==before[a[4]:a[4]+a[5]]
            reply=blob(event['reply']);assert len(reply)<=a[7]
            expected=bytearray(before)
            for at,value in [(320,a[1]),(328,event['code']),(352,len(reply))]:struct.pack_into('<Q',expected,at,value)
            expected[a[6]:a[6]+len(reply)]=reply;assert after==bytes(expected)
            if reply[:8]==b'HBLCLR01':
                assert event['code']==64
                assert reply==frame(b'HBLCLR01',3 if event['case'].startswith('poll-') else 4,tag,job,0,0,0,0)
            else:assert event['code']==32 and reply==frame(b'HBLRTR01',tag,0,0)
            following=calls[event['after_call_index']+1]
            assert following['case']==event['case'] and blob(following['before_workspace'])==after
    assert used==set(blobs),'unread complete blob'
    report=json.loads((capture/'report.json').read_bytes())
    assert report['status']=='NATIVE_PENDING_ABI_CONTROLS_PASS'
    assert report['source_manifest']==pin((package/'package-manifest.json').read_bytes())
    assert report['domain']==pin((package/'domain.json').read_bytes())
    assert report['calls']==len(calls) and report['events']==len(events)
    assert [r['name'] for r in report['controls']]==[r['name'] for r in domain['cases']]
    assert [r['name'] for r in report['lifecycle']]==domain['lifecycle']
    assert report['public_qualified'] is False and report['real_workers_executed']==report['rust_executions']==0
    return dict(status='COMPLETE_PENDING_ABI_READBACK_PASS',controls=len(domain['cases']),lifecycle=len(domain['lifecycle']),
        calls=len(calls),events=len(events),relocations=relocations,test_owned_child_acknowledgments=acknowledgments,
        complete_blobs=len(blobs),complete_blob_bytes=sum(len(b) for b in blobs.values()),
        public_qualified=False,real_workers_executed=0,rust_executions=0)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for key in ['package','build','capture']:p.add_argument('--'+key,type=Path,required=True)
    a=p.parse_args();print(json.dumps(verify(a.package,a.build,a.capture),sort_keys=True))

