#!/usr/bin/env python3
"""Complete frozen source and input-only domain admission; zero fixture effects."""
from pathlib import Path
import ast,hashlib,sys
sys.dont_write_bytecode=True
SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE/"scripts"))
from evidence_common import source_evidence,require,encoded,pin,decode
from cases import cases
from protocol import wire,U
def main():
    identity=source_evidence(SOURCE);files=[]
    for path in sorted(SOURCE.rglob("*.py")):
        raw=path.read_bytes();ast.parse(raw,filename=str(path));compile(raw,str(path),"exec")
        files.append(dict(path=path.relative_to(SOURCE).as_posix(),**pin(path)))
    require(pin(SOURCE/"target/binary_file.py")["sha256"]=="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12"
        and pin(SOURCE/"target/file_metadata.py")["sha256"]=="24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3","complete exact original targets")
    import read_capture,read_journal,read_fingerprint_journal,read_metadata_journal
    queries=cases();require(len(queries)==78 and[q["id"]for q in queries]==list(range(1,79)),"frozen full input extent")
    groups={};observed=off=0
    for q in queries:
        require(q["expected_result"]is None and(q["observer"]or not q["actions"]and not q["arm_fstat_error"]),"input-only observed actors")
        require(q["attempts"]in(1,2)and(q["attempts"]==1 or q["arm_fstat_error"]and not q["actions"]),"fixed multi-context input")
        groups.setdefault(q["group"],[]).append(dict(id=q["id"],name=q["name"],input_sha256=hashlib.sha256(encoded(q)).hexdigest()))
        if q["observer"]:observed+=1
        else:off+=1
        packet=wire(q);require(packet[:8]==b"HINFQ001"and U(packet,32)==0 and U(packet,88)==len(packet)-96,"fixed complete input ABI")
        require(decode(encoded(q))==q,"all exact input bytes roundtrip")
    require(observed==66 and off==12 and len(groups)==18,"fixed domain groups")
    # The only adaptations to the qualified child readers permit a not-yet-known
    # terminal to be returned to the outer streaming reader. Every old check stays.
    old=(SOURCE/"reference/read_fingerprint_journal_before.py").read_text()
    new=old.replace('and frame==terminal,\n                "terminal borrow or owned descriptor set differs")',
        'and (terminal is None or frame==terminal),\n                "terminal borrow or owned descriptor set differs")')
    new=new.replace('return dict(workspace=wa,output=oa,body_calls=call)',
        'return dict(workspace=wa,output=oa,body_calls=call,frame=frame)')
    require(new==(SOURCE/"scripts/read_fingerprint_journal.py").read_text(),"exact fingerprint reader derivation")
    old=(SOURCE/"reference/read_metadata_journal_before.py").read_text()
    new=old.replace("from protocol import U,I,result,stat_decode","from metadata_protocol import U,I,result,stat_decode")
    new=new.replace('require(frame==terminal and hook_at==len(hooks),"terminal frame/full notification set")',
        'require((terminal is None or frame==terminal)and hook_at==len(hooks),"terminal frame/full notification set")')
    new=new.replace('return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec)',
        'return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec,frame=frame)')
    require(new==(SOURCE/"scripts/read_metadata_journal.py").read_text(),"exact metadata reader derivation")
    report=dict(status="INFO_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=files,groups=groups,
        observed_inputs=observed,observer_off_inputs=off,entry_invocations=sum(q["attempts"]for q in queries),
        info_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0,original_binding=read_capture.reference_binding(SOURCE))
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
