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
    import read_capture,read_journal,read_metadata_journal
    queries=cases();require(len(queries)==78 and[q["id"]for q in queries]==list(range(1,79)),"frozen full input extent")
    groups={};observed=off=0
    for q in queries:
        require(q["expected_result"]is None and(q["observer"]or not q["actions"]and not q["arm_fstat_error"]),"input-only observed actors")
        require(q["attempts"]in(1,2)and(q["attempts"]==1 or q["arm_fstat_error"]and not q["actions"]),"fixed multi-context input")
        groups.setdefault(q["group"],[]).append(dict(id=q["id"],name=q["name"],input_sha256=hashlib.sha256(encoded(q)).hexdigest()))
        if q["observer"]:observed+=1
        else:off+=1
        prior=None if q["prior_kind"]=="none"else"absent"if q["prior_kind"]=="absent"else""if q["prior_kind"]=="empty"else"0:0:0:0:0"
        packet=wire(q,prior);require(packet[:8]==b"HPUBQ001"and U(packet,32)==0 and U(packet,88)==len(packet)-96,"fixed complete input ABI")
        require(decode(encoded(q))==q,"all exact input bytes roundtrip")
    require(observed==68 and off==10 and len(groups)==31,"fixed domain groups")
    # The only adaptations let the qualified metadata reader return its observed
    # terminal to this outer streaming reader. Every original check stays.
    old=(SOURCE/"reference/read_metadata_journal_before.py").read_text()
    new=old.replace("from protocol import U,I,result,stat_decode","from metadata_protocol import U,I,result,stat_decode")
    new=new.replace('require(frame==terminal and hook_at==len(hooks),"terminal frame/full notification set")',
        'require((terminal is None or frame==terminal)and hook_at==len(hooks),"terminal frame/full notification set")')
    new=new.replace('return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec)',
        'return dict(workspace=wa,output=oa,body_calls=call,effects=effects,codec=codec,frame=frame)')
    require(new==(SOURCE/"scripts/read_metadata_journal.py").read_text(),"exact metadata reader derivation")
    require(sum(q["attempts"]for q in queries)==79 and sum(len(q["actions"])*q["attempts"]for q in queries)==20,
        "complete entry and actual fixture actor input counts")
    require(sum(q["attempts"]for q in queries if q["arm_fstat_error"])==7,"complete actual fault input count")
    for q in queries:
        require(q["prior_kind"]in("absent","current","none","wrong","empty")
            and q["control_fd0"]in(None,"parent","file")and q["filesystem"]=="runner-temp","fixed publication input selectors")
        for key in("destination","temporary"):
            f=q[key];require(f["kind"]in("missing","regular","directory","symlink","fifo")
                and 0<=f["mode"]<=4095 and isinstance(f["attributes"],list),"fixed real object description")
            if f["kind"]=="regular":bytes.fromhex(f["content_hex"])
            for attr in f["attributes"]:
                name=bytes.fromhex(attr["name_hex"]);bytes.fromhex(attr["value_hex"])
                require(name and b"\0"not in name,"fixed complete attribute input bytes")
        if q["arm_fstat_error"]:
            require(q["arm_fstat_error"]["role"]in(1,2,3)and 1<=q["arm_fstat_error"]["occurrence"]<=8,"fixed first-fstat fault selector")
        for a in q["actions"]:
            require(a["owner"]in("publish","metadata")and 1<=a["operation"]<=10 and a["occurrence"]>=1
                and a.get("target","destination")in("destination","temporary"),"fixed real actor boundary")
    report=dict(status="PUBLISH_SOURCE_AND_INPUT_ONLY_PASS",source=identity,python_sources=files,groups=groups,
        observed_inputs=observed,observer_off_inputs=off,entry_invocations=sum(q["attempts"]for q in queries),
        publish_function_calls=0,hia_calls=0,rust_calls=0,fixture_effects=0,original_binding=read_capture.reference_binding(SOURCE))
    print(encoded(report).decode(),end="")
if __name__=="__main__":main()
