"""Read complete captured bytes, exact registry archives and normal transport results."""
from pathlib import Path
import argparse,gzip,hashlib,io,json,tarfile,tomllib,sys
sys.dont_write_bytecode=True
SHA=lambda b:hashlib.sha256(b).hexdigest()
def need(ok,why):
    if not ok:raise ValueError(why)
def read(root,path):
    rel=Path(path);need(not rel.is_absolute() and ".." not in rel.parts,"relative file")
    p=root/rel;need(p.resolve(strict=True)==p and p.is_file(),"regular retained file")
    return p.read_bytes()
def doc(root,path):return json.loads(read(root,path))
def pin(raw):return dict(bytes=len(raw),sha256=SHA(raw))
def zipped(root,folder,record):
    packed=read(root,Path(folder)/record["path"])
    need(pin(packed)==dict(bytes=record["compressed_bytes"],sha256=record["compressed_sha256"]),"compressed capture")
    raw=gzip.decompress(packed);need(pin(raw)=={k:record[k] for k in ("bytes","sha256")},"complete capture")
    return raw
def verify(source,reference,native,cases):
    source,reference,native,cases=(Path(p).resolve(strict=True) for p in (source,reference,native,cases))
    sys.path.insert(0,str(source/"drivers"))
    from transport_cases import records,inputs
    provenance=doc(source,"reference/SOURCES.json")
    for row in provenance["files"]:need(pin(read(source,row["path"]))=={k:row[k] for k in ("bytes","sha256")},"reference input source")
    corpus=doc(cases,"cases/manifest.json")
    need(corpus["cases"]==records() and corpus["async_cases"]==24 and corpus["codec_eof_reference_only_cases"]==4,"normal corpus")
    need(corpus["selected_modes"]==["async","codec-eof"] and corpus["shutdown_service_mode_selected"] is False
        and corpus["partial_receive_cancellation_mode_selected"] is False,"limited normal modes")
    for label,payload,_ in inputs():
        need(read(cases,"cases/inputs/"+label+".bin")==payload,"corpus file")
        need(read(reference,"cases/inputs/"+label+".bin")==payload,"actual original input file")
    need(read(cases,"cases/manifest.json")==read(reference,"cases/manifest.json"),"same original corpus")
    native_summary=doc(native,"SUMMARY.json");summary=doc(reference,"SUMMARY.json")
    need(native_summary["status"]=="NATIVE_CAPTURE_COMPLETE" and native_summary["completed_cases"]==24,"native completion")
    need(native_summary["actual_target_transport_compared"] is False and native_summary["original_rust_executed"] is False,"independent capture")
    need(summary["status"]=="ACTUAL_TARGET_TRANSPORT_REFERENCE_PASS" and summary["completed_cases"]==28,"original completion")
    need(summary["fresh_exact_sdk_built"] is True and summary["rust_executed"] is True,"actual original execution")
    need(summary["actual_target_transport_compared"] is True and summary["serial_public_wire_cases"]==24
         and summary["codec_eof_reference_only_cases"]==4,"limited compared counts")
    for item in (native_summary,summary):
        for name in ("full_sdk_qualified","full_async_runtime_qualified","public_codec_implemented","production_activated","old_path_removed"):
            need(item[name] is False,"scope: "+name)
    build=doc(reference,"BUILD.json");subset=doc(reference,"evidence/target-lock-subset.json")
    need(build["fresh_target_dir"] is True and build["actual_target_sdk_built"] is True
         and build["actual_target_sdk_executed"] is True and build["offline_resolution"] is True,"fresh exact original")
    need(build["rust_version"].splitlines()[0].startswith("rustc 1.95.0 "),"Rust version")
    for name in ("main.rs","message_model.rs","Cargo.toml"):
        need(read(reference,"oracle/"+name)==read(source,"reference/oracle/"+name),"unchanged original observer "+name)
    for name,digest in build["project_files"].items():need(SHA(read(reference,"oracle/"+name))==digest,"original project file")
    locked=read(reference,"oracle/Cargo.lock");target=read(source,"reference/target/Cargo.lock")
    need(read(reference,"target/Cargo.lock")==target,"exact target seed lock")
    need(SHA(locked)==build["fixture_lock_sha256"]==subset["fixture_lock_sha256"]
         and SHA(target)==subset["target_lock_sha256"],"lock identity")
    target_packages={(p["name"],p["version"],p.get("source")):p.get("checksum")
                     for p in tomllib.loads(target.decode())["package"] if p.get("source")}
    retained=[]
    for package in tomllib.loads(locked.decode())["package"]:
        if package.get("source"):
            need(target_packages.get((package["name"],package["version"],package["source"]))==package["checksum"],"retained registry checksum")
            retained.append({k:package[k] for k in ("name","version","source","checksum")})
        else:need(package["name"]=="g3-target-transport-oracle","only owned local package")
    need(retained==subset["retained_registry_packages"] and subset["all_retained_exactly_match_target"] is True,"complete lock subset")
    verified={(r["name"],r["version"],r["source"]):r for r in subset["registry_source_verification"]}
    archives=build["registry_archive_custody"]
    need(len(archives)==len(verified)==len(retained),"archive closure")
    for row in archives:
        raw=read(reference,row["path"]);need(pin(raw)=={k:row[k] for k in ("bytes","sha256")},"crate archive")
        actual=verified[(row["name"],row["version"],row["source"])]
        need(SHA(raw)==actual["checksum"]==target_packages[(row["name"],row["version"],row["source"])],"crate matches current lock")
        files={}
        with tarfile.open(fileobj=io.BytesIO(raw),mode="r:gz") as archive:
            for member in archive:
                parts=Path(member.name).parts
                need(parts and parts[0]==row["name"]+"-"+row["version"] and ".." not in parts,"registry member path")
                if member.isdir():continue
                need(member.isfile(),"registry regular file")
                data=archive.extractfile(member).read();rel=Path(*parts[1:]).as_posix();need(rel not in files,"unique registry member")
                files[rel]=SHA(data)
                if row["name"]=="rmcp" and rel=="src/transport/async_rw.rs":
                    need(data==read(source,"reference/sdk/async_rw.rs"),"actual exact SDK transport implementation")
        need(files==actual["source_files"] and len(files)==actual["files_verified"],"all retained registry source hashes")
    binary=read(reference,build["retained_binary_relative_path"]);need(SHA(binary)==build["binary_sha256"],"actual original binary")
    for folder,labels in [("evidence/cache-prefetch",["rustc-version","cargo-fetch-locked"]),
                          ("evidence/rust-build-processes",["rustc-version","cargo-version","metadata-offline","cargo-build-locked-offline"])]:
        processes=doc(reference,folder+"/processes.json");need([r["label"] for r in processes]==labels,"build process order")
        for row in processes:
            need(row["exit_code"]==0 and row["timed_out"] is False and row["timeout_seconds"]==180,"build deadline completion")
            for stream in ("stdout","stderr"):
                raw=read(reference,folder+"/"+row["label"]+"."+stream)
                need(pin(raw)==dict(bytes=row[stream+"_bytes"],sha256=row[stream+"_sha256"]),"complete build stream")
    native_rows={r["label"]:r for r in native_summary["rows"]}
    need(len(native_rows)==24 and len(summary["rows"])==28,"exact case counts")
    comparisons=[];codec=[]
    for index,(spec,row) in enumerate(zip(corpus["cases"],summary["rows"],strict=True)):
        need(row["label"]==spec["label"] and row["mode"]==spec["mode"] and row["index"]==index,"reference order")
        folder=row["folder"];raw=read(reference,folder+"/PROCESS.json");need(SHA(raw)==row["process_sha256"],"original case receipt")
        process=json.loads(raw);need(process["exit_code"]==0 and process["timed_out"] is False and process["deadline_seconds"]==60,"original bounded completion")
        need(process["environment"]=={"PATH":"","LC_ALL":"C"},"original process environment")
        request=zipped(reference,folder,process["stdin"]);output=zipped(reference,folder,process["stdout"])
        need(zipped(reference,folder,process["stderr"])==b"","ordinary original stderr")
        expected_request={k:v for k,v in spec.items() if k not in ("input_bytes","input_sha256")}
        need(request==json.dumps(expected_request,ensure_ascii=False,separators=(",",":")).encode()+b"\n","actual observer input")
        need(pin(output)==dict(bytes=row["stdout_bytes"],sha256=row["stdout_sha256"]),"original output custody")
        observed=json.loads(output);need(observed["label"]==spec["label"] and observed["mode"]==spec["mode"]
            and observed["input_bytes"]==spec["input_bytes"],"observed case identity")
        if spec["mode"]=="async":
            n=native_rows[spec["label"]];raw=read(native,n["folder"]+"/PROCESS.json")
            need(SHA(raw)==n["process_sha256"],"native process receipt");p=json.loads(raw)
            need(p["exit_code"]==0 and p["timed_out"] is False and p["deadline_seconds"]==60 and p["cwd_entries"]==[],"native bounded no-effect completion")
            need(p["target_reference_read"] is False and p["original_rust_executed"] is False,"native observer independence")
            need(p["environment"]=={"PATH":"","LC_ALL":"C"},"native process environment")
            need(zipped(native,n["folder"],p["stdin"])==read(cases,spec["input_file"]),"actual native input")
            actual=zipped(native,n["folder"],p["stdout"]);need(zipped(native,n["folder"],p["stderr"])==b"","native stderr")
            need(actual==observed["writer_bytes"].encode(),"whole public wire differs: "+spec["label"])
            need(pin(actual)==dict(bytes=n["stdout_bytes"],sha256=n["stdout_sha256"]),"native output custody")
            need(observed["default_max_line_length"]==16*1024*1024 and observed["writer_closed"] is True
                 and observed["poll_shutdown_calls"]==0 and observed["cancelled_pending_receive"] is False,"actual serial SDK transport")
            events=observed["events"];names=[e["event"] for e in events]
            need(names.count("read_eof")==names.count("writer_drop")==1 and names[-1]=="writer_drop","actual original EOF then writer drop")
            need(all(n in ("write","flush","read_eof","writer_drop") for n in names),"ordinary original events")
            need(events[-1]["children_cancelled"]==[] and events[-1]["external_cancelled"] is None,"no service child registry")
            need(sum(e.get("bytes",0) for e in events if e["event"]=="write")==len(actual),"complete original writes")
            need(process["native_wire_compared"] is True,"comparison completion")
            comparisons.append(dict(label=spec["label"],input=pin(read(cases,spec["input_file"])),wire=pin(actual),
                native_process_sha256=n["process_sha256"],original_process_sha256=row["process_sha256"]))
        else:
            need(process["native_wire_compared"] is False,"codec is reference-only")
            need(observed["remaining_bytes"]==0 and observed["default_max_length"]==(1<<64)-1,"unbounded default codec EOF contract")
            expected={"codec-eof-tail":1,"codec-eof-cr-tail":1,"codec-complete-then-tail":2,"codec-over-cap-eof":1}
            need(len(observed["messages"])==expected[spec["label"]],"codec delivers final valid EOF message")
            codec.append(dict(label=spec["label"],messages=len(observed["messages"]),original_process_sha256=row["process_sha256"]))
    need(len(comparisons)==24 and len(codec)==4,"complete finite domains")
    return dict(schema="hepta.public-serial-transport.readonly-reference.v1",status="SERIAL_TRANSPORT_CURRENT_TARGET_PASS",
        serial_public_wire_cases=24,codec_eof_reference_only_cases=4,original_processes=28,
        all_full_wire_bytes_equal=True,exact_current_sdk_source_verified=True,
        actual_native_elf_sha256=native_summary["elf_sha256"],actual_original_elf_sha256=build["binary_sha256"],
        comparisons=comparisons,codec_observations=codec,new_native_or_rust_executed=False,
        full_sdk_qualified=False,full_async_runtime_qualified=False,public_codec_implemented=False,
        service_task_or_future_lifecycle_qualified=False,cancellation_timing_qualified=False,
        production_activated=False,old_path_removed=False)
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("source","reference","native","cases"):p.add_argument("--"+name,required=True,type=Path)
    a=p.parse_args();print(json.dumps(verify(a.source,a.reference,a.native,a.cases),sort_keys=True))
