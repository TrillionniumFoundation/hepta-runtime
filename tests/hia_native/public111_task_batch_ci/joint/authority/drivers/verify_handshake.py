"""Read complete 54-session native wire against the retained actual current SDK.

This verifier never executes native code, Rust, or a subprocess and writes no
files. All original peer/context checks remain in the unchanged reference gate.
"""
from pathlib import Path
import argparse,gzip,hashlib,importlib.util,json,sys
sys.dont_write_bytecode=True
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
def doc(path):return json.loads(path.read_bytes())
def packed(folder,row):
    path=Path(row["path"]);assert path.name==str(path)
    raw=(folder/path).read_bytes()
    assert len(raw)==row["compressed_bytes"] and SHA(raw)==row["compressed_sha256"]
    data=gzip.decompress(raw);assert len(data)==row["bytes"] and SHA(data)==row["sha256"]
    return data
def original_module(source):
    spec=importlib.util.spec_from_file_location("_retained_actual_handshake_verifier",source/"scripts/verify_reference.py")
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module
def verify(source,reference,native,build):
    oracle=original_module(source)
    original=oracle.verify(source,reference,True)
    corpus=oracle.cases();assert len(corpus)==54
    assert doc(native/"CORPUS.json")==doc(reference/"CORPUS.json")==corpus
    capture=doc(native/"SUMMARY.json");built=doc(build/"BUILD.json")
    assert capture["status"]=="NATIVE_HANDSHAKE54_CAPTURE_COMPLETE" and capture["completed_sessions"]==54
    assert capture["target_reference_read"] is False and capture["actual_original_wire_compared"] is False
    assert capture["original_rust_executed"] is False
    assert capture["physical_images"]==built["physical_images"]==102
    assert capture["source_case_sha256"]==SHA((source/"scripts/cases.py").read_bytes())
    assert capture["source_manifest_sha256"]==SHA((source/"source-manifest.json").read_bytes())
    assert capture["elf_sha256"]==built["elf_sha256"]
    assert capture["manifest_sha256"]==built["manifest_sha256"]
    folder=build/"build/public-authority-batch";manifest=folder/"manifest.json"
    assert SHA(manifest.read_bytes())==built["manifest_sha256"]
    md=doc(manifest);assert md["extra_table"][55]=="target_connection"
    assert md["target_connection_lifecycle_integrated"] is True and md["target_connection_slot"]==55
    assert SHA((folder/md["elf"]).read_bytes())==capture["elf_sha256"]
    rows=[];count=0;modern=0;floats=0
    assert len(capture["cases"])==54
    for index,(case,receipt) in enumerate(zip(corpus,capture["cases"],strict=True)):
        name="case-"+str(index).zfill(3)
        assert receipt["index"]==index and receipt["label"]==case["label"] and receipt["folder"]==name
        target=native/name;raw=(target/"PROCESS.json").read_bytes();assert SHA(raw)==receipt["process_sha256"]
        process=json.loads(raw)
        assert process["index"]==index and process["label"]==case["label"]
        assert process["exit_code"]==0 and process["timed_out"] is False and process["deadline_seconds"]==60
        assert process["environment"]=={"PATH":"","LC_ALL":"C"} and process["cwd_entries"]==[]
        assert list((target/"cwd").iterdir())==[]
        assert process["target_reference_read"] is False and process["original_rust_executed"] is False
        stdin=packed(target,process["stdin"]);stdout=packed(target,process["stdout"]);stderr=packed(target,process["stderr"])
        assert not stderr
        assert stdin==b"".join(event["wire"].encode()+b"\n" for event in case["events"])
        observed=doc(reference/name/"stdout.jsonl")
        assert observed["label"]==case["label"]
        expected=b"".join(event["response_raw"].encode() for event in observed["events"] if "response_raw" in event)
        assert stdout==expected,case["label"]
        assert process["response_lines"]==len(stdout.splitlines())==6
        count+=6
        assert observed["events"][5]["response"]["error"]["code"]==-32601
        modern+=1
        floats+=int('"id":17.0,' in case["events"][0]["wire"])
        rows.append(dict(index=index,label=case["label"],process_sha256=receipt["process_sha256"],
            stdin_sha256=SHA(stdin),stdout_sha256=SHA(stdout),stdout_bytes=len(stdout),
            original_stdout_sha256=SHA((reference/name/"stdout.jsonl").read_bytes())))
    assert count==324 and modern==54 and floats==9
    return dict(schema="hepta.current-connection.public-handshake-readonly.v1",
        status="READONLY_PUBLIC91_CURRENT_HANDSHAKE54_PASS",sessions=54,responses=324,
        modern_ping_method_not_found_responses=54,integral_float_initialize_responses=9,
        all_full_wire_bytes_equal=True,actual_original_gate=original,comparisons=rows,
        candidate_elf_sha256=built["elf_sha256"],physical_images=102,
        original_observed_peer_info=54,native_peer_state_separately_observed=False,
        generic_initialize_fixture_published=False,native_or_rust_executed_by_reader=False,
        source_or_evidence_written_by_reader=False,full_sdk_qualified=False,
        full_async_runtime_qualified=False,production_activated=False,old_path_removed=False)
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","reference","native","build"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();paths={name:getattr(a,name).resolve(strict=True) for name in ("source","reference","native","build")}
    oracle=original_module(paths["source"])
    before=tuple(oracle.snapshot(root) for root in paths.values());sys.addaudithook(oracle.audit)
    result=verify(**paths)
    assert before==tuple(oracle.snapshot(root) for root in paths.values())
    print(json.dumps(result,sort_keys=True))

