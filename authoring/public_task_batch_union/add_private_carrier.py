"""Add the explicit instance carrier without changing production assembly.

Input is the complete 388-file source closure frozen at commit6009ee17. This
successor changes only the builder's explicit private branch, the private
pointer-table extent and their source/provenance records. No image is run.
"""
from pathlib import Path
import argparse, hashlib, json, shutil, sys
sys.dont_write_bytecode = True
SHA = lambda value: hashlib.sha256(value).hexdigest()
ENCODE = lambda value: (json.dumps(value,sort_keys=True,indent=2)+"\n").encode()
OLD = "376b8a13f2a1ae4f7630807e35f90bc15a3e7f617472e34e5fc82c2b6a950cc9"
NEW = "e320d8204f300fe31441e47dee7b224136ec3f394806277076b90e6320d14218"

def pin(raw):
    return {"bytes":len(raw),"sha256":SHA(raw)}

def replace(text,before,after):
    assert text.count(before)==1,before[:100]
    return text.replace(before,after,1)

def derive(source):
    binding_raw=(source/"native/runtime_mcp_sources.json").read_bytes()
    assert SHA(binding_raw)==OLD
    binding=json.loads(binding_raw)
    values={}
    for name,wanted in binding["sources"].items():
        raw=(source/name).read_bytes()
        assert pin(raw)==wanted,name
        values[name]=raw
    assert len(values)==387
    name="scripts/public_nine_build.py"
    text=values[name].decode()
    first="    if private_fixture:\n        raise ValueError('historical filesystem fixture belongs to its frozen serial source view')\n"
    last="    for name in re.findall(r'^\\.global ([A-Za-z_][A-Za-z_0-9]*)$', source, re.M):\n"
    assert text.count(first)==text.count(last)==1
    old=text[text.index(first):text.index(last)]
    normal=old[len(first):]
    new=("    if private_fixture:\n"
        "        if private_pump_fixture or private_pump_trace:\n"
        "            raise ValueError('private instance carrier cannot expose pump observation descriptors')\n"
        "        transport = '\\n'.join((root / name).read_text() for name in FIXTURE_BOUNDARIES)\n"
        "        fixed = combine((root / BASE).read_text(), transport)\n"
        "        carrier = [name for name in BOUNDARIES if not name.startswith('scripts/runtime_mcp_task_')]\n"
        "        source = '\\n'.join((root / name).read_text() for name in carrier) + '\\n' + fixed\n"
        "    else:\n"+"".join("    "+line if line.strip() else line for line in normal.splitlines(keepends=True)))
    text=replace(text,old,new)
    for before,after in (
        ("binary = folder / ('task-pump-fixture.elf' if private_pump_fixture else 'runtime-mcp.elf')",
         "binary = folder / ('filesystem-fixture.elf' if private_fixture else 'task-pump-fixture.elf' if private_pump_fixture else 'runtime-mcp.elf')"),
        ("'task_registry_slot': 58, 'task_registry_operation15_integrated': True,",
         "'task_registry_slot': 58, 'task_registry_operation15_integrated': not private_fixture,"),
        ("'task_event_pump_integrated': True, 'task_event_pump_qualified': False,",
         "'task_event_pump_integrated': not private_fixture, 'task_event_pump_qualified': False,"),
        ("'async_eof_policy_owner': 58, 'historical_shutdown53_retained': True,",
         "'async_eof_policy_owner': None if private_fixture else 58, 'historical_shutdown53_retained': True,"),
        ("[BASE, *(FIXTURE_BOUNDARIES if private_fixture else [TRANSPORT]), *BOUNDARIES]",
         "[BASE, *(FIXTURE_BOUNDARIES if private_fixture else [TRANSPORT]), *(name for name in BOUNDARIES if not private_fixture or not name.startswith('scripts/runtime_mcp_task_'))]")):
        text=replace(text,before,after)
    values[name]=text.encode()
    fixture="scripts/runtime_mcp_filesystem_fixture.S"
    old_fixture=values[fixture]
    values[fixture]=replace(old_fixture.decode(),".zero 456 /* 57 fixed public-engine slots. */",
        ".zero 472 /* 59 fixed public-engine slots; original private selectors are unchanged. */").encode()
    proof=json.loads(values["native/public_task_batch_source_union.json"])
    del proof["retained_installed_shared_corrections"][fixture]
    proof["private_instance_carrier"]={"source_before":pin(old_fixture),"source_after":pin(values[fixture]),
        "only_native_fixture_change":"pointer table grows from57 to59 slots",
        "original_selectors_and_observers_unchanged":True,"session_count":2,
        "private_selectors":[32,33,34,41,57,58],"pump_host_installed_in_carrier":False,
        "production_cannot_select_this_entry":True,"carrier_proves_public_async":False}
    values["native/public_task_batch_source_union.json"]=ENCODE(proof)
    binding["sources"]={name:pin(raw) for name,raw in sorted(values.items())}
    values["native/runtime_mcp_sources.json"]=ENCODE(binding)
    assert SHA(values["native/runtime_mcp_sources.json"])==NEW
    return values

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--check",action="store_true")
    a=p.parse_args();source=a.source.resolve(strict=True);values=derive(source)
    if not a.check:
        assert not a.output.exists()
        a.output.mkdir(parents=True)
    for name,raw in values.items():
        target=a.output/name
        if a.check:
            assert target.read_bytes()==raw,name
        else:
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(raw);target.chmod((source/name).stat().st_mode&0o777)
    print(json.dumps({"status":"SOURCE_BYTES_PASS","files":len(values),"source_binding_sha256":NEW,
        "native_executed":False,"rust_executed":False},sort_keys=True))
if __name__=="__main__":
    main()
