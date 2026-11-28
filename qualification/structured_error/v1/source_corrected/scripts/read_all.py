#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Full immutable byte comparison; never executes HIA, Python reference or libc."""
from pathlib import Path
import gzip,hashlib,struct
from common import canonical,decode,owned,pin,require,sha,source_evidence,B3,HEPTA,SCOPE
import cases
def build_evidence(source, output):
    source, output = Path(source), Path(output)
    bundle = decode(owned(output, "build/formatter.json").read_bytes())
    require(bundle["schema"] == "hepta.runtime.structured-error.native-build.v1", "build schema changed")
    require(bundle["application_calls"] == 0 and bundle["compiler_cold_gate_repeated"] is False, "build scope changed")
    require(bundle["compiler_commit"] == HEPTA and bundle["compiler_sha256"] == B3, "build compiler changed")
    bootstrap = decode(owned(output, "build/bootstrap/bootstrap.json").read_bytes())
    require(bootstrap["generation_sha256"] == B3 and bootstrap["qualification"] == "development_fixed_point", "bootstrap identity changed")
    dependency = bootstrap["dependency"]
    require(dependency["commit"] == HEPTA and dependency["tree"] == "8d8b0fb8d015fb7edab302498bb9ed4c74ab6f49", "compiler source commit/tree changed")
    for path, digest in dependency["files"].items():
        require(pin(owned(output, "compiler-source/" + path))["sha256"] == digest, "compiler dependency file changed: " + path)
    require({p.relative_to(output/"compiler-source").as_posix()for p in(output/"compiler-source").rglob("*")if p.is_file()} == set(dependency["files"]), "complete compiler source set")
    require(bundle["compiler_modes"] == {name:(output/"compiler-source"/name).stat().st_mode&0o777 for name in dependency["files"]}, "complete compiler modes")
    for generation in ("B1", "B2", "B3"):
        require(pin(owned(output, "build/bootstrap/" + generation + ".image.bin"))["sha256"] == B3, "bootstrap generation changed")
    artifacts = {"build/formatter.json": pin(output / "build/formatter.json")}
    for name, row in {"structured_error": bundle["member"]}.items():
        path = owned(output, row["manifest"])
        require(pin(path)["sha256"] == row["manifest_sha256"], "member manifest changed")
        metadata = decode(path.read_bytes())
        require(metadata["source_sha256"] == row["source_sha256"] == pin(owned(source, "native/" + name + ".hepta"))["sha256"], "member source changed")
        require(metadata["image_sha256"] == row["image_sha256"], "member image declaration changed")
        require(metadata["compiler_commit"] == HEPTA and metadata["compiler_sha256"] == B3 and "buffer_profile" not in metadata and metadata["standalone"] is None, "member ABI changed")
        require([metadata[k] for k in ("input_capacity", "output_capacity", "workspace_capacity")] == [8 << 20, 8 << 20, 32 << 20], "member capacities changed")
        module_source = owned(path.parent, metadata["source"]).read_bytes()
        image = owned(path.parent, metadata["image"]).read_bytes()
        require(sha(module_source) == metadata["source_sha256"] and sha(image) == metadata["image_sha256"], "actual member bytes changed")
        request = decode(owned(path.parent, "module.request.json").read_bytes())
        receipt = decode(owned(path.parent, "module.receipt.json").read_bytes())
        raw_output = owned(path.parent, "module.output.bin").read_bytes()
        require(owned(path.parent, "module.input.bin").read_bytes() == module_source, "compiled input differs from published source")
        require(receipt["status"] == "returned" and type(receipt["abi_status"]) is int and receipt["abi_status"] == 0 and type(receipt["core_u32"]) is int, "compile did not return cleanly")
        require(receipt["core_u32"] == receipt["result_u64"] == receipt["produced_bytes"] == len(image) and image == raw_output[:len(image)], "compiled complete output/image differs")
        require(receipt["source_unchanged"] is True and receipt["forbidden_compiler_modules_loaded"] == [] and receipt["artifact_sha256"] == B3, "compile custody changed")
        require(receipt["input_bytes"] == len(module_source) and receipt["input_sha256"] == sha(module_source) and receipt["output_sha256"] == sha(raw_output) and receipt["produced_sha256"] == sha(image), "compile complete input/output hash differs")
        require(request["source_sha256"] == sha(module_source) and request["image_sha256"] == B3 and request["format"] == "flat-x86-64", "compile request changed")
        build = decode(owned(path.parent, "build.json").read_bytes())
        require(build["compile_receipt"] == receipt and build["compiler_dependency"] == dependency, "member build source closure changed")
        for artifact in (path, path.parent / metadata["source"], path.parent / metadata["image"]):
            artifacts[artifact.relative_to(output).as_posix()] = pin(artifact)
    return artifacts


def take(stream,size):
    raw=stream.read(size);require(len(raw)==size,"short full-buffer record");return raw
def process_evidence(capture):
    origin=decode(owned(capture,"ORIGIN.json").read_bytes());original=Path(origin["capture"]);source=original/"source"
    py=[origin["python"],"-I","-S","-B"]
    expected=[("author",py+[str(source/"authoring/author_structured_error.py"),"--source",str(source),
        "--hepta",origin["hepta"],"--output",str(original/"authored")],60),
        ("native-build",py+[str(source/"scripts/build.py"),"--hepta",origin["hepta"],
            "--capture",str(original)],900)]
    for group in cases.domain()["groups"]:
        name=group["name"]
        expected.append(("original-"+name,py+[str(source/"scripts/original.py"),"--group",name,
            "--output",str(original/"original"/name)],60))
        expected.append(("native-"+name,py+[str(source/"scripts/native_capture.py"),"--group",name,
            "--capture",str(original),"--output",str(original/"native"/name)],60))
    expected.append(("native-controls",py+[str(source/"scripts/native_capture.py"),"--group","controls",
        "--capture",str(original),"--output",str(original/"native/controls")],60))
    rows=decode(owned(capture,"processes/processes.json").read_bytes())
    require(len(rows)==len(expected),"complete actual producer process set")
    by_name={}
    for row,(name,argv,budget)in zip(rows,expected):
        require(row["name"]==name and row["argv"]==argv and row["cwd"]==str(source)
            and row["completed"]is True and row["timed_out"]is False and row["exit_code"]==0
            and row["timeout_seconds"]==budget and 0<=row["elapsed_seconds"]<budget+1
            and type(row["pid"])is int and row["pid"]>0 and row["pgid"]==row["pid"],
            "actual bounded process identity: "+name)
        require(row["stdin"]is None,"unexpected producer stdin")
        for which in("stdout","stderr"):
            value=row[which]
            require(value["file"]==name+"."+which and {k:value[k]for k in("bytes","sha256")}==
                pin(owned(capture,"processes/"+value["file"])),"complete actual process stream: "+name)
        require(row["stderr"]["bytes"]==0,"producer stderr not empty: "+name)
        by_name[name]=row
    return by_name
def capture_meta(source,capture,side,group,processes):
    folder=capture/side/group;meta=decode(owned(folder,"CAPTURE.json").read_bytes())
    require(meta["status"]=="PASS"and meta["group"]==group and meta["source"]==source_evidence(source),
        "capture identity differs: "+side+"/"+group)
    require(meta["compressed"]==pin(owned(folder,"records.bin.gz"))and
        meta["records"]==pin(owned(folder,"records.json")),"capture full retained stream differs")
    pname=side+"-"+group
    require(decode(owned(capture,"processes/"+pname+".stdout").read_bytes())==meta
        and meta["pid"]==processes[pname]["pid"],"capture does not match actual process stdout")
    if side=="original":
        require(meta["hia_executed"]is False and meta["native_result_read"]is False
            and meta["environment"]["unicode_version"]=="15.0.0"and meta["environment"]["lc_messages"]=="C"
            and meta["environment"]["platform"]=="linux","original environment or provenance differs")
    else:
        require(meta["original_result_read"]is False and meta["semantic_replay"]is False,"native provenance changed")
    return folder,meta,decode(owned(folder,"records.json").read_bytes())
def original_group(source,capture,group,processes):
    folder,meta,records=capture_meta(source,capture,"original",group,processes)
    values=list(cases.cases(group));require(len(records)==meta["cases"]==len(values),"original case count")
    digest=hashlib.sha256();offset=0;results={}
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for value,record in zip(values,records):
            wire=cases.frame(value);header=take(stream,24);cid,in_size,out_size=struct.unpack("<3Q",header)
            require(cid==value["case_id"]and in_size==len(wire)and out_size==record["response_bytes"],
                "original complete frame header")
            actual_input=take(stream,in_size);response=take(stream,out_size);block=header+actual_input+response
            require(actual_input==wire and record["offset"]==offset and record["bytes"]==len(block)
                and record["record_sha256"]==sha(block)and record["response_sha256"]==sha(response),
                "original exact request/result bytes")
            require({k:record[k]for k in cases.public_row(value)}==cases.public_row(value),"original frozen case identity")
            require(response.startswith(record["actual_exception_class"].encode()+b": "),"original actual exception class")
            response.decode("utf-8");results[cid]=response;digest.update(block);offset+=len(block)
        require(stream.read()==b"","trailing original bytes")
    require(meta["raw"]==dict(bytes=offset,sha256=digest.hexdigest()),"complete original raw custody")
    return results,offset
def native_group(source,capture,group,original,processes,artifacts,data):
    folder,meta,records=capture_meta(source,capture,"native",group,processes)
    require(meta["artifacts"]==artifacts,"actual admitted native image/source differs")
    control=group=="controls";values=cases.controls()if control else list(cases.cases(group))
    require(len(records)==meta["cases"]==len(values),"native case count")
    digest=hashlib.sha256();offset=0;previous=None;success=0;invalid=0;capacity=0
    with gzip.open(owned(folder,"records.bin.gz"),"rb")as stream:
        for index,(value,record)in enumerate(zip(values,records),1):
            wire=value["wire"]if control else cases.frame(value)
            outcap=value["output_capacity"]if control else cases.capacity(value)
            workcap=value["workspace_capacity"]if control else cases.WORK+31
            before=previous if control and value.get("reuse")else b"\x7b"*workcap
            old=b"\xa5"*outcap
            header=take(stream,64);cid,code,insize,oc,wc,number,z0,z1=struct.unpack("<8Q",header)
            require((cid,insize,oc,wc,number,z0,z1)==(value["case_id"],len(wire),outcap,workcap,index,0,0),
                "native complete frame header")
            actual_input=take(stream,insize);actual_before=take(stream,wc);actual_old=take(stream,oc)
            output=take(stream,oc);after=take(stream,wc)
            spans=(header,actual_input,actual_before,actual_old,output,after)
            record_hash=hashlib.sha256();size=0
            for raw in spans:record_hash.update(raw);digest.update(raw);size+=len(raw)
            expected=dict(case_id=cid,label=value["label"],offset=offset,bytes=size,return_code=code,
                input_bytes=len(wire),input_sha256=sha(wire),output_capacity=outcap,workspace_capacity=workcap,
                before_sha256=sha(before),output_before_sha256=sha(old),output_sha256=sha(output),
                after_sha256=sha(after),record_sha256=record_hash.hexdigest())
            require(record==expected and actual_input==wire and actual_before==before and actual_old==old,
                "native all raw input/output/workspace bytes")
            if control:
                require(code==value["expected"],"native frozen boundary result: "+value["label"])
                installed=value["mutation"]=="installed"
                if code not in(cases.INVALID,cases.CAPACITY):
                    expected_output=(original[value["reference_case_id"]]if "reference_case_id"in value else
                        cases.CLASSES[value["reference_class"]-1].encode()+b": "+bytes.fromhex(value["message_hex"]))
                    require(code==len(expected_output)==value["required"],"literal boundary extent")
            else:
                expected_output=original[cid];require(code==len(expected_output),"native return differs from actual original")
                installed=True
            if code in(cases.INVALID,cases.CAPACITY):
                require(output==old,"rejected input/capacity changed complete output")
                if code==cases.INVALID:invalid+=1
                else:capacity+=1
            else:
                require(0<=code<=outcap and output==expected_output+b"\xa5"*(outcap-code),
                    "complete native diagnostic differs from actual original or output tail")
                success+=1
            if installed:
                size_data=data["data_bytes"]
                require(len(after)>=data["workspace_required"]and sha(after[:size_data])==data["data_sha256"]
                    and after[size_data:]==before[size_data:],"immutable formatter data/workspace tail differs")
            else:require(after==before,"rejected input/capacity changed complete workspace")
            previous=after;offset+=size
        require(stream.read()==b"","trailing native full-buffer bytes")
    require(meta["raw"]==dict(bytes=offset,sha256=digest.hexdigest()),"complete native raw custody")
    return dict(calls=len(values),raw_bytes=offset,successes=success,invalid=invalid,capacity=capacity)
def verify(source,capture):
    source,capture=Path(source),Path(capture);frozen=source_evidence(source)
    require(source_evidence(capture/"source")==frozen,"retained complete source differs")
    domain=cases.validate();artifacts=build_evidence(source,capture)
    artifacts.pop("build/formatter.json")
    processes=process_evidence(capture)
    for name in("structured_error.hepta","structured_error.pseudo","structured_error_composition.json","platform_data.json"):
        require(owned(capture,"authored/"+name).read_bytes()==owned(source,"native/"+name).read_bytes(),
            "fresh source author differs from frozen bytes")
    data=decode(owned(source,"native/platform_data.json").read_bytes())
    require(data["data_bytes"]==10152 and data["workspace_required"]==12288
        and data["unicode_version"]=="15.0.0"and len(data["classes"])==16,"formatter data contract")
    author=decode(owned(source,"AUTHOR_BINDING.json").read_bytes())
    require(author["source_only"]is True and author["process"]["status"]=="PASS","source-author provenance")
    for name,row in author["complete"]["members"].items():
        path="native/"+name.removeprefix("generated/")if name.startswith("generated/")else"author-evidence/"+name
        require(pin(owned(source,path))=={k:row[k]for k in("bytes","sha256")},"full source-author byte binding")
    native=[];original_bytes=0;compared=0;all_original={}
    for group in cases.domain()["groups"]:
        results,count=original_group(source,capture,group["name"],processes);original_bytes+=count
        require(not(set(results)&set(all_original)),"duplicate original case identity");all_original.update(results)
        result=native_group(source,capture,group["name"],results,processes,artifacts,data)
        require(result["invalid"]==result["capacity"]==0,"semantic case rejected")
        compared+=len(results);native.append(result)
    controls=native_group(source,capture,"controls",all_original,processes,artifacts,data)
    require(compared==domain["semantic_cases"] and controls["calls"]==domain["controls"]
        and controls["invalid"]==domain["control_counts"]["invalid"]
        and controls["capacity"]==domain["control_counts"]["capacity"]
        and controls["successes"]==domain["control_counts"]["success"],"complete comparison/control count")
    return dict(status="STRUCTURED_ERROR_COMPLETE_PASS",comparison=dict(native_cases=compared,original_cases=compared,
        controls=controls,unicode_scalars=1112064,errno_values=4095,groups=domain["groups"],
        legacy_cases=domain["legacy_cases"],metadata_cases=domain["metadata_cases"],integer_values=domain["integer_values"]),
        native_calls=compared+controls["calls"],native_full_buffer_bytes=sum(r["raw_bytes"]for r in native)+controls["raw_bytes"],
        original_full_bytes=original_bytes,domain=domain,source=frozen,build=artifacts,
        producer_processes=len(processes),scope=SCOPE,native_or_original_replayed=False)
def prepare(capture):
    # Preload all reader definitions before a caller activates the read-only guard.
    cases.validate();gzip.decompress(gzip.compress(b""))
