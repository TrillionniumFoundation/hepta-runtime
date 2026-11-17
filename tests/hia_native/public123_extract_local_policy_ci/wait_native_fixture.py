"""Explicit test-only raw boundary adaptation; no production source is changed."""
from pathlib import Path
import hashlib,json,re
HERE=Path(__file__).resolve().parent
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def source(root,builder):
    root=Path(root).resolve(strict=True)
    assert SHA((root/'native/runtime_mcp_sources.json').read_bytes())=='18234f394c9db95c6c78e486867da614fd3353453698e9994207bf4426d4b814'
    before=builder.adapter_source(root,private_pump_fixture=True,private_pump_trace=True)
    assert '.equ PM_FIXED_FIXTURE_FDS,1\n' in before and '.equ PM_FIXED_TRACE_FD,1\n' in before
    current=before
    plan=json.loads((HERE/'WAIT_NATIVE_SPLICES.json').read_bytes())
    for old,new in plan:
        assert current.count(old)==1,old
        current=current.replace(old,new,1)
    added=(HERE/'wait_fixture.S').read_text()
    # The original source builder aliases global labels before its relocation-
    # free pack. Apply the exact same global-reference transform to this added
    # fixture boundary, never to data bytes or public input.
    for name in re.findall(r'^\.global ([A-Za-z_][A-Za-z_0-9]*)$',before,re.M):
        if name=='_start':continue
        assert '\n'+name+'_flat:' in before,name
        added=re.sub(r'\b(call|jmp) '+re.escape(name)+r'\b',
            lambda m:m[1]+' '+name+'_flat',added)
        added=added.replace('[rip + '+name+']','[rip + '+name+'_flat]')
    current+='\n'+added
    restored=current[:-len(added)-1]
    for old,new in reversed(plan):
        assert restored.count(new)==1,new
        restored=restored.replace(new,old,1)
    assert restored==before
    proof={'schema':'hepta.runtime.actual-extract-wait-private-carrier.v1',
        'base_source_commit':'fc73c39569c2c36ed027662d3f9e96614bd4b7d3',
        'base_assembly':{'bytes':len(before.encode()),'sha256':SHA(before.encode())},
        'fixture_assembly':{'bytes':len(current.encode()),'sha256':SHA(current.encode())},
        'added_boundary':{'bytes':len(added.encode()),'sha256':SHA(added.encode())},
        'splices':len(plan),'complete_inverse_to_actual_trace_carrier':True,
        'production_files_changed':False,'fixed_control_fd':5,'private_only':True,
        'real_hia_lock_holder':True,'public_wait_fabricated':False,'semantic_executions':0}
    return before.encode(),current.encode(),proof
