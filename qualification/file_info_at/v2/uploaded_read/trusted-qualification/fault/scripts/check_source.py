#!/usr/bin/env python3
"""Frozen info/shared-pool dependency composition and new input-only domain."""
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
        and pin(SOURCE/"target/file_metadata.py")["sha256"]=="24b9df89816536db16dd35a74d6460b1a215981a00798393a00853da6077f5d3",
        "complete exact original targets")
    proof=decode((SOURCE/"HARNESS_DERIVATION.json").read_bytes())
    require(proof["production_hia_changes"]is False and proof["original_target_changes"]is False,
        "qualification does not rewrite the production or original")
    for row in proof["patches"]:
        old=(SOURCE/"reference/harness_before"/row["path"]).read_text()
        require(hashlib.sha256(old.encode()).hexdigest()==row["before_sha256"],"complete original harness preimage")
        new=old
        for edit in row["changes"]:
            require(new.count(edit["before"])==1,"unique exact source adaptation")
            new=new.replace(edit["before"],edit["after"])
        require(new==(SOURCE/row["path"]).read_text()
            and hashlib.sha256(new.encode()).hexdigest()==row["after_sha256"],"complete adapted harness bytes")
    require((SOURCE/"scripts/read_fingerprint_journal.py").read_bytes()==
        (SOURCE/"reference/read67_qualified_journal.py").read_bytes(),"unchanged qualified read67 full-buffer reader")
    old=(SOURCE/"reference/read_metadata_journal_before.py").read_text()
    new=old.replace("from protocol import U,I,result,stat_decode","from metadata_protocol import U,I,result,stat_decode")
    new=new.replace('require(frame==terminal and hook_at==len(hooks),"terminal frame/full notification set")',
        'require((terminal is None or frame==terminal)and hook_at==len(hooks),"terminal frame/full notification set")')
    new=new.replace('return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec)',
        'return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec,frame=frame)')
    require(new==(SOURCE/"scripts/read_metadata_journal.py").read_text(),"unchanged exact metadata reader derivation")
    pins={"native/binary_read_body.hepta":"0ff27a8ba9a8a53ca7cd97054a8394c04023fd7cb84fe2406bf8d2b7e867f4ba",
        "asm/binary_read_body_callable.S":"07177c2a6861f88916bc47e89c462e28dd2dcc3a1ffaa101d1594be5b100274b",
        "asm/process_orphans.S":"f1d4e92b9d2ce68c68dcbc730950eaddaf3aa1093f143d34924c3eafc302e050",
        "native/path_error.hepta":"23a5e7ae451cda076a2caa910d10ac34ae0757922b55df538dab03746ed4ff9a"}
    for name,digest in pins.items():require(pin(SOURCE/"trusted-build"/name)["sha256"]==digest,"exact final dependency bytes")
    import read_capture,read_journal,read_fingerprint_journal,read_metadata_journal
    from continuation import planned
    require(planned(SOURCE,"child-orphans")["roles"]["original"]["actual_calls"]==7
        and planned(SOURCE,"shm")["roles"]["original"]["actual_calls"]==2,"all originals retained without application replay")
    queries=cases();require(len(queries)==32 and[q["id"]for q in queries]==list(range(1,33)),"fixed new input extent")
    groups={};observed=off=0;faults={"read":0,"info":0}
    for q in queries:
        require(q["expected_result"]is None and(q["observer"]or not q["actions"]and not q["arm_fstat_error"]),
            "input-only observed actors")
        require(q["fault_owner"]in(None,"read","info")and(q["fault_owner"]is not None)==q["arm_fstat_error"],
            "fixed actual first-fstat fault owner")
        require(q["attempts"]in(1,2)and(q["attempts"]==1 or q["arm_fstat_error"]and not q["actions"]),
            "fixed independent two-context input")
        groups.setdefault(q["group"],[]).append(dict(id=q["id"],name=q["name"],input_sha256=hashlib.sha256(encoded(q)).hexdigest()))
        if q["observer"]:observed+=1
        else:off+=1
        if q["arm_fstat_error"]:faults[q["fault_owner"]]+=q["attempts"]
        packet=wire(q);require(packet[:8]==b"HINFQ001"and U(packet,32)==0 and U(packet,88)==len(packet)-96,"fixed full input ABI")
        require(decode(encoded(q))==q,"all input bytes roundtrip")
    require(observed==28 and off==4 and len(groups)==8 and faults==dict(read=8,info=6)
        and sum(q["attempts"]for q in queries)==34,"complete fixed rebind domain")
    report=dict(status="INFO_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=files,groups=groups,
        observed_inputs=observed,observer_off_inputs=off,entry_invocations=34,first_fstat_fault_invocations=faults,
        info_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0,original_binding=read_capture.reference_binding(SOURCE),
        read67_final="8bb4e020fc8a728ec7b06e8ffa510052d5e8fa64",
        formatter34_final="96a3ecccb3b054a9bf0059659040d4bb9e38e4a9",
        original_cpython_internal_syscall_stream_observed=False)
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
