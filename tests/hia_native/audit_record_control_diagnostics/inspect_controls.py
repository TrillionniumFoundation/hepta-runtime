"""Read complete preserved native-pump capture and exact recovery counters; no execution."""
from pathlib import Path, PurePosixPath
import argparse,gzip,hashlib,io,json,os,stat,struct,sys,tarfile,zipfile
def need(ok,text):
    if not ok: raise ValueError(text)
def pin(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def encoded(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+"\n").encode()
def path(name):
    item=PurePosixPath(name)
    need(type(name) is str and name and not item.is_absolute() and item.as_posix()==name
         and all(x not in ("",".","..") for x in item.parts),"contained ordinary archive path")
    return item
def main(archive,output):
    output.mkdir(parents=True,exist_ok=False)
    raw=archive.read_bytes()
    need(pin(raw)==dict(bytes=156028150,sha256="50dea39e1347a4d3bc18ca6534f872fc5ede0c3d9ddca271b54dfa32442aa9ff"),"complete failed ZIP")
    with zipfile.ZipFile(io.BytesIO(raw)) as z:
        need(z.namelist()==list(dict.fromkeys(z.namelist())) and set(z.namelist())==
            {"audit-record-callable.tar.gz","audit-record-callable.tar.gz.json"} and z.testzip() is None,"complete ZIP members/CRC")
        packed=z.read("audit-record-callable.tar.gz")
        producer=json.loads(z.read("audit-record-callable.tar.gz.json"))
    need(pin(packed)==dict(bytes=156027265,sha256="ac3b4ecb8d3233138f7327bcc3ca7c7dfd02c1cb6c98112abf4be97ef0599b3b"),"complete failed TAR")
    need(producer["status"]=="NO_FINAL_GATE" and producer["all_logical_files_reread"] is True
         and producer["all_objects_and_modes_reread"] is True,"actual preserved failure export")
    objects={}; bodies={}; manifest=None
    with tarfile.open(fileobj=io.BytesIO(packed),mode="r:gz") as tar:
        for member in tar:
            path(member.name)
            need(member.isfile() and member.name not in objects,"unique regular complete member")
            with tar.extractfile(member) as stream:body=stream.read()
            need(len(body)==member.size,"all member bytes")
            identity=dict(**pin(body),mode=member.mode);objects[member.name]=identity
            if member.name=="artifact-manifest.json":
                manifest=json.loads(body)
            else:
                need(member.name=="objects/"+identity["sha256"]+"-"+format(member.mode,"03o"),"whole object-addressed bytes/mode")
                # Only small source/reports/streams are retained for diagnosis.
                bodies[member.name]=body
    need(manifest["git_head"]=="f7273eb417e1f90c4e11b0556f7d6c7d2758bd33" and
        manifest["run_id"]=="44061230103" and manifest["source_manifest_sha256"]==
        "f7a18ccac088bb820a2df262b4f5b700f11a2e6ee0f2f307f2ada4fa89f90d4b","exact failed producer/source")
    logical=manifest["files"]; expected={}
    for name,row in logical.items():
        path(name)
        need(set(row)=={"bytes","sha256","mode","object"} and row["object"]==
            "objects/"+row["sha256"]+"-"+format(row["mode"],"03o"),"all complete logical bindings")
        value={k:row[k] for k in ("bytes","sha256","mode")}
        need(objects[row["object"]]==value,"every logical file bound to fully read bytes")
        expected[row["object"]]=value
    expected["artifact-manifest.json"]=objects["artifact-manifest.json"]
    need(objects==expected and len(logical)==44786 and sum(x["bytes"] for x in logical.values())==2581124108,
         "complete failed logical domain/object set")
    def get(name):
        row=logical[name];body=bodies[row["object"]]
        need(pin(body)=={k:row[k] for k in ("bytes","sha256")},"retained complete selected file")
        return body
    def emit(name,body):
        destination=output/"selected"/path(name)
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(body);destination.chmod(logical[name]["mode"])
    selected=("source/SOURCE.json","source/read_transport_controls.py","source/transport_cases.py",
              "source/DOMAIN.json","run/semantic/transport-controls/CONTROLS.json",
              "run/semantic/transport-controls/CALLS.json","run/semantic/transport-controls/OBSERVATIONS.json",
              "run/semantic/transport-controls/buffers.bin.gz","run/semantic/native-observed/OBSERVATIONS.json",
              "run/semantic/native-observed/effects.jsonl","run/semantic/processes/processes.json",
              "run/semantic/build/BUILD.json","run/semantic/build/callable/BINDING.json",
              "run/reader-processes/semantic/readonly-semantic.stderr")
    for name in selected:emit(name,get(name))
    rows=json.loads(get("run/semantic/transport-controls/CALLS.json"))
    packed_controls=get("run/semantic/transport-controls/buffers.bin.gz")
    raw_controls=gzip.decompress(packed_controls)
    stream=io.BytesIO(raw_controls)
    def exact(n):
        value=stream.read(n);need(len(value)==n,"complete original physical control bytes");return value
    need(exact(8)==b"AIOCTLOG","actual native control header")
    recovery=[]
    for row in rows:
        need(exact(8)==b"AIOCTL01","actual native control call")
        index,returned,nm,ni,no,nc,nt=struct.unpack("<7Q",exact(56))
        meta=json.loads(exact(nm))
        need(meta==row and index==row["index"] and returned==row["returned"],"actual complete receipt binding")
        before=[exact(n) for n in (ni,no,nc,nt)]
        after=[exact(n) for n in (ni,no,nc,nt)]
        need([pin(b) for b in before]==row["before"] and [pin(b) for b in after]==row["after"],
             "all original control buffer bytes")
        if row["phase"]=="recovery-run":
            ctx=after[2];word=lambda n:struct.unpack_from("<Q",ctx,n)[0]
            recovery.append(dict(index=index,case=row["case"],name=row["name"],returned=returned,
                addresses=row["addresses"],header={str(n):word(n) for n in range(0,256,8)},
                capability_words=list(struct.unpack("<48Q",ctx[256:640])),
                library_table_unchanged=ctx[640:768]==before[3],
                input_unchanged=before[0]==after[0],table_unchanged=before[3]==after[3],
                output_tail_unchanged=after[1][returned:]==b"\xa5"*(no-returned),
                context_guard_unchanged=ctx[98304:]==b"\x5a"*16,
                complete_context=pin(ctx),terminal_hex=after[1][:returned].hex()))
    need(exact(8)==b"AIOCTEND" and struct.unpack("<Q",exact(8))[0]==len(rows)==180
         and len(recovery)==45 and not stream.read(1),"all controls and final full footer")
    observed=json.loads(get("run/semantic/native-observed/OBSERVATIONS.json"))
    events=[json.loads(line) for line in get("run/semantic/native-observed/effects.jsonl").splitlines()]
    ordinary=observed[5]
    need(ordinary["case"]==0 and ordinary["step"]==5,"fixed ordinary comparison operation")
    relevant=[event for event in events if event["case"]==0 and event["generation"]==6]
    outer_compressed=get("run/semantic/native-observed/outer.bin.gz")
    outer_stream=gzip.GzipFile(fileobj=io.BytesIO(outer_compressed),mode="rb")
    def ox(n):
        value=outer_stream.read(n);need(len(value)==n,"complete original outer record");return value
    need(ox(8)==b"AIOTOP01","outer header")
    ordinary_context=None
    for count in range(897):
        need(ox(8)==b"AIOENT01","ordinary physical outer call")
        index,ci,si,kind,returned,ni,no,nc,nt,gi,go,gc=struct.unpack("<12Q",ox(96))
        need(index==count,"complete ordered outer call")
        sizes=(ni+gi,no+go,nc+gc,nt)
        before=[ox(n) for n in sizes];after=[ox(n) for n in sizes]
        if ci==0 and si==5 and kind==1:
            bw=lambda n:struct.unpack_from("<Q",before[2],n)[0]
            aw=lambda n:struct.unpack_from("<Q",after[2],n)[0]
            ordinary_context=dict(index=index,returned=returned,input=pin(before[0]),
                before_header={str(n):bw(n) for n in range(0,256,8)},
                after_header={str(n):aw(n) for n in range(0,256,8)},
                deltas={str(n):aw(n)-bw(n) for n in (80,88,96)},
                terminal_hex=after[1][:returned].hex())
    need(ox(8)==b"AIOTEND1" and struct.unpack("<Q",ox(8))[0]==897 and not outer_stream.read(1),
         "entire ordinary outer physical capture and footer")
    outer_stream.close()
    (output/"FAILED_ARCHIVE_MANIFEST.json").write_bytes(encoded(manifest))
    result=dict(schema="hepta.audit-record-callable.control-inspection.v1",status="OBSERVED",
        failed_head=manifest["git_head"],failed_run=44061230103,failed_job=133963332394,
        complete_zip=pin(raw),complete_tar=pin(packed),logical_files=len(logical),
        logical_bytes=sum(x["bytes"] for x in logical.values()),all_objects_read=True,
        selected_files={name:{k:logical[name][k] for k in ("bytes","sha256","mode")} for name in selected},
        controls_complete_buffer=pin(raw_controls),all_45_recoveries=recovery,
        ordinary_observation=ordinary,ordinary_effects=relevant,ordinary_context=ordinary_context,
        native_or_rust_executions=0,original_failure_preserved=True,public_handler_qualified=False)
    (output/"REPORT.json").write_bytes(encoded(result))
    print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--archive",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();main(a.archive.resolve(strict=True),a.output.absolute())
