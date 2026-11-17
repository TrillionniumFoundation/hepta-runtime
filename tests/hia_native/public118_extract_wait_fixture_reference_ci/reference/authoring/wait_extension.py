"""Source-only fixed FD5 fixture extension of the retained actual SDK stdio."""
from pathlib import Path
import copy,hashlib,json
PIN=lambda raw:{'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
    'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}
def apply(root,files,oldproof):
    root=Path(root);assets=root/'authoring'
    plan=json.loads((assets/'WAIT_SPLICES.json').read_bytes())
    assert PIN(files['SOURCE.json'])==plan['extension']['baseline_source_proof']
    out=dict(files);del out['SOURCE.json']
    for name,key,source in [('src/main.rs','main',files['src/main.rs']),
                            ('src/stdio_wait_bridge.rs','relay',files['src/stdio_bridge.rs'])]:
        text=source.decode()
        for row in plan[key]:
            assert text.count(row['before'])==row['count']==1,(name,row['before'])
            text=text.replace(row['before'],row['after'],1)
        value=text.encode()
        restored=value.decode()
        for row in reversed(plan[key]):
            assert restored.count(row['after'])==1,(name,'inverse')
            restored=restored.replace(row['after'],row['before'],1)
        assert restored.encode()==source
        out[name]=value
    out['src/wait_fixture.rs']=(assets/'wait_fixture.rs').read_bytes()
    assert out['src/stdio_wait_bridge.rs']==(assets/'stdio_wait_bridge.rs').read_bytes()
    assert out['src/main.rs']==(assets/'wait_reference_main.rs').read_bytes()
    for name,row in plan['extension']['new_sources'].items():assert PIN(out[name])==row,name
    for name,raw in files.items():
        if name not in ('src/main.rs','SOURCE.json'):assert out[name]==raw,name
    for group in ('preserved_original_items','extract_exact_spans'):
        for item in oldproof[group]:
            for span in item['compiled_spans']:
                assert span['container']!='src/main.rs'
                raw=out[span['container']][span['start']:span['end']]
                assert PIN(raw)=={k:item[k] for k in ('bytes','sha256','git_blob')}
    proof=copy.deepcopy(oldproof)
    proof['files']={name:PIN(raw) for name,raw in out.items()}
    proof['new_wrapper']=PIN(out['src/main.rs'])
    proof['wait_fixture']=plan['extension']
    out['SOURCE.json']=(json.dumps(proof,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
    return out,proof
