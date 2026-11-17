"""Finite independent copies for the mechanical-engine evidence reader."""
import argparse, json, pathlib, sys, traceback
sys.dont_write_bytecode=True
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parent))
from port_reader_controls import files,copy_exact,encoded,file_pin,value_pin,same_content,chunks
from read_port import read,doc,sha,get,journal_records
from read_engine_edges import verify
CASES=['changed-pending-input','changed-target-map','missing-joined-core-clock','changed-engine-source']

def mutation(case,run,fixture):
    changes={}
    if case in ('changed-pending-input','changed-target-map'):
        records=doc(run/'capture/RECORDS.json')
        if case=='changed-target-map':
            row=records['targets'][0];assert row['parent']==row['child']==0 and row['old']==row['new']==(1<<64)-1
            row['old']=row['new']=1
        else:
            row=next(r for r in records['cases'] if r['label']=='pending-0')
            original=read(run/'capture/blobs'/row['input']['sha256']);assert original[:8]==b'HRCMFR02' and get(original,8)==4
            changed=original[:40]+(1).to_bytes(8,'little')+original[48:]
            pin={'bytes':len(changed),'sha256':sha(changed)};row['input']=pin
            changes['run/capture/blobs/'+pin['sha256']]=changed
        changes['run/capture/RECORDS.json']=encoded(records)
    elif case=='missing-joined-core-clock':
        capture=run/'capture/port';last=None
        for at,magic,b in journal_records(capture/'journal.bin'):
            if magic==b'HBCLOCK1' and get(b,16)==1 and get(b,32)==1:last=(at,at+len(b))
        assert last is not None;begin,end=last
        changes['run/capture/port/journal.bin']={'splice':str(capture/'journal.bin'),'cuts':[last]}
        rows=[json.loads(line) for line in read(capture/'calls.jsonl').splitlines()]
        for row in rows:
            if 'journal_bytes' in row:
                old=row['journal_bytes'];assert not begin<old<end
                if end<=old:row['journal_bytes']=old-(end-begin)
        changes['run/capture/port/calls.jsonl']=b''.join((json.dumps(r,sort_keys=True,separators=(',',':'))+'\n').encode() for r in rows)
    elif case=='changed-engine-source':
        changes['fixture/new/engine.S']=read(fixture/'new/engine.S')+b'\n/* rehashed unadmitted source */\n'
    else:raise AssertionError(case)
    return changes

def create(build,fixture,run,overlay,author,output):
    baseline=verify(build,fixture,run,overlay,author);output.mkdir()
    run_files=files(run);fixture_files=files(fixture);rows=[]
    for case in CASES:
        folder=output/case;folder.mkdir();copy_exact(run,folder/'run',run_files)
        changes=mutation(case,run,fixture);candidate=fixture
        if any(n.startswith('fixture/') for n in changes):copy_exact(fixture,folder/'fixture',fixture_files);candidate=folder/'fixture'
        for name,value in changes.items():
            target=folder/name;target.parent.mkdir(parents=True,exist_ok=True)
            with target.open('wb') as stream:
                for b in chunks(value):stream.write(b)
        try:verify(build,candidate,folder/'run',overlay,author)
        except AssertionError as exc:failure={'type':'AssertionError','message':str(exc),'traceback':traceback.format_exc()}
        else:raise AssertionError('accepted mechanical evidence mutation: '+case)
        row={'case':case,'changes':{name:value_pin(value) for name,value in changes.items()},'failure':failure,'native_or_rust_executed':False}
        (folder/'REFUSAL.json').write_bytes(encoded(row));rows.append(row)
    result={'status':'PHYSICAL_ENGINE_REFUSALS_PASS','cases':CASES,'baseline':baseline,'run_files':run_files,'fixture_files':fixture_files,'refusals':rows,'native_or_rust_executed':False}
    (output/'RESULT.json').write_bytes(encoded(result));return result

def verify_controls(build,fixture,run,overlay,author,output):
    result=doc(output/'RESULT.json')
    assert result['status']=='PHYSICAL_ENGINE_REFUSALS_PASS' and result['cases']==CASES and result['native_or_rust_executed'] is False
    assert result['baseline']==verify(build,fixture,run,overlay,author)
    assert result['run_files']==files(run) and result['fixture_files']==files(fixture) and len(result['refusals'])==len(CASES)
    for case,row in zip(CASES,result['refusals']):
        folder=output/case;changes=mutation(case,run,fixture);assert row['case']==case and row['changes']=={name:value_pin(value) for name,value in changes.items()}
        groups=[('run',run,result['run_files'])]
        if any(n.startswith('fixture/') for n in changes):groups.append(('fixture',fixture,result['fixture_files']))
        for label,original,pins in groups:
            expected=dict(pins)
            for name,pin in row['changes'].items():
                if name.startswith(label+'/'):expected[name[len(label)+1:]]=pin
            assert files(folder/label)==expected
            for name in expected:
                key=label+'/'+name;wanted=changes[key] if key in changes else {'splice':str(original/name),'cuts':[]}
                same_content(folder/label/name,wanted)
        assert doc(folder/'REFUSAL.json')==row and row['failure']['type']=='AssertionError'
        candidate=folder/'fixture' if (folder/'fixture').exists() else fixture
        try:verify(build,candidate,folder/'run',overlay,author)
        except AssertionError as exc:assert str(exc)==row['failure']['message']
        else:raise AssertionError('retained mechanical mutant accepted: '+case)
        assert {p.name for p in folder.iterdir()}=={name for name,_,_ in groups}|{'REFUSAL.json'}
    assert {p.name for p in output.iterdir()}==set(CASES)|{'RESULT.json'}
    return {'status':'READ_ONLY_ENGINE_REFUSALS_PASS','physical_copies_checked':len(CASES),'complete_bytes_compared':True,'native_or_rust_executed':False,'verified_tree_writes':False}

def main():
    p=argparse.ArgumentParser()
    for name in ('build','fixture','run','overlay','author','output'):p.add_argument('--'+name,type=pathlib.Path,required=True)
    p.add_argument('--verify',action='store_true');a=p.parse_args()
    result=(verify_controls if a.verify else create)(a.build,a.fixture,a.run,a.overlay,a.author,a.output)
    print(json.dumps({k:v for k,v in result.items() if k not in ('run_files','fixture_files','refusals')},sort_keys=True))
if __name__=='__main__':main()
