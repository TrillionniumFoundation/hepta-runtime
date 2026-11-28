"""Independent complete archive and physical-buffer reader; no target code execution."""
from pathlib import Path
import argparse
import base64
import encodings.cp437
import gzip
import hashlib
import io
import json
import os
import stat
import struct
import sys
import tarfile
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
from read_only_guard import guarded


def encoded(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def identity():
    raw = (ROOT / 'SOURCE_MANIFEST.json').read_bytes()
    value = json.loads(raw)
    actual = {}
    for path in sorted(ROOT.rglob('*')):
        assert not path.is_symlink()
        if path.is_dir():
            continue
        assert path.is_file()
        name = path.relative_to(ROOT).as_posix()
        if name != 'SOURCE_MANIFEST.json':
            actual[name] = dict(**pin(path.read_bytes()), mode=stat.S_IMODE(path.stat().st_mode))
    assert actual == value['files']
    return hashlib.sha256(raw).hexdigest()


class Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlparse(newurl).hostname != 'api.github.com':
            new.remove_header('Authorization')
        return new


def fetch(folder, binding):
    folder.mkdir(parents=True, exist_ok=False)
    target = folder / 'complete.zip'
    request = urllib.request.Request(
        'https://api.github.com/repos/TrillionniumFoundation/hepta-runtime/actions/artifacts/'
        + str(binding['artifact_id']) + '/zip',
        headers={'Accept': 'application/vnd.github+json', 'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
                 'X-GitHub-Api-Version': '2022-11-28'})
    count, digest = 0, hashlib.sha256()
    with urllib.request.build_opener(Redirect()).open(request, timeout=60) as source, target.open('xb') as out:
        while block := source.read(1 << 20):
            count += len(block)
            assert count <= binding['zip']['bytes']
            digest.update(block); out.write(block)
    result = dict(bytes=count, sha256=digest.hexdigest())
    assert result == binding['zip']
    return dict(status='PASS', archive=result, target_native_or_rust_executions=0)


def full_tar(stream, retain):
    observed, content, manifest = {}, {}, None
    with tarfile.open(fileobj=stream, mode='r|gz') as archive:
        while member := archive.next():
            path = Path(member.name)
            assert member.isfile() and member.name not in observed and not path.is_absolute()
            assert '..' not in path.parts and member.mode in (0o600, 0o644, 0o755)
            with archive.extractfile(member) as handle:
                if retain or member.name == 'artifact-manifest.json':
                    raw = handle.read()
                    item = pin(raw)
                else:
                    digest, count = hashlib.sha256(), 0
                    while block := handle.read(1 << 20):
                        count += len(block); digest.update(block)
                    item = dict(bytes=count, sha256=digest.hexdigest())
            assert item['bytes'] == member.size
            observed[member.name] = dict(**item, mode=member.mode)
            if member.name == 'artifact-manifest.json':
                assert member.mode == 0o644
                manifest = raw
            else:
                assert len(path.parts) == 2 and path.parts[0] == 'objects'
                assert member.name == 'objects/' + item['sha256'] + '-' + format(member.mode, '03o')
                if retain:
                    content[member.name] = raw
            archive.members.clear()
    assert manifest is not None
    index = json.loads(manifest)
    expected = {'artifact-manifest.json': dict(**pin(manifest), mode=0o644)}
    for name, row in index['files'].items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts
        item = {key: row[key] for key in ('bytes', 'sha256', 'mode')}
        assert row['object'] == 'objects/' + row['sha256'] + '-' + format(row['mode'], '03o')
        if row['object'] in expected:
            assert expected[row['object']] == item
        expected[row['object']] = item
    assert observed == expected
    return index, manifest, observed, content


def inspect(folder,binding):
    archive_path=folder/"complete.zip"
    assert pin(archive_path.read_bytes())==binding["zip"]
    expected_names={"engine-layout.tar.gz","engine-layout.tar.gz.json",
        "engine-layout-export-processes/complete-export.stdout","engine-layout-export-processes/complete-export.stderr",
        "engine-layout-export-processes/processes.json","engine-layout-archive-processes/complete-archive-read.stdout",
        "engine-layout-archive-processes/complete-archive-read.stderr","engine-layout-archive-processes/processes.json",
        "engine-layout-archive-read/ARCHIVE_READ.json","engine-layout-archive-read/admission.json",
        "engine-layout-archive-read/processes/independent-archive-admission.stdout",
        "engine-layout-archive-read/processes/independent-archive-admission.stderr",
        "engine-layout-archive-read/processes/processes.json"}
    outer={};small={}
    with zipfile.ZipFile(archive_path) as archive:
        assert len(archive.infolist())==len(expected_names)
        for item in archive.infolist():
            assert item.filename in expected_names and item.filename not in outer and not item.is_dir()
            assert not item.flag_bits&1 and item.compress_type in (0,8)
            with archive.open(item) as handle:
                raw=handle.read();actual=pin(raw)
            assert actual["bytes"]==item.file_size
            outer[item.filename]=dict(**actual,external_attributes=item.external_attr)
            if item.filename!="engine-layout.tar.gz":small[item.filename]=raw
            else:assert actual==binding["tar"]
        with archive.open("engine-layout.tar.gz") as handle:index,manifest,objects,content=full_tar(handle,True)
    assert set(outer)==expected_names
    assert index["schema"]=="hepta.runtime.engine-layout.complete-archive.v1"
    assert index["git_head"]==binding["head"] and str(index["run_id"])==str(binding["run_id"])
    assert index["gate_status"]=="PASS" and index["native_or_rust_executions"]==0
    files=index["files"];assert len(files)==binding["logical_files"]
    assert sum(value["bytes"] for value in files.values())==binding["logical_bytes"]
    assert len(objects)-1==binding["unique_objects"]
    assert sum(value["bytes"] for name,value in objects.items() if name!="artifact-manifest.json")==binding["unique_bytes"]
    def logical(name):
        value=files[name];raw=content[value["object"]]
        assert pin(raw)=={key:value[key] for key in ("bytes","sha256")}
        return raw
    source_raw=logical("source/SOURCE_MANIFEST.json");assert pin(source_raw)["sha256"]==binding["source_manifest_sha256"]
    source=json.loads(source_raw)
    assert {name[7:] for name in files if name.startswith("source/")}==set(source["files"])|{"SOURCE_MANIFEST.json"}
    for name,value in source["files"].items():assert pin(logical("source/"+name))==value
    gate=json.loads(logical("run/GATE.json"));assert gate["status"]=="PASS" and gate["stage"]=="complete" and gate["failure"] is None
    assert gate["source_manifest_sha256"]==binding["source_manifest_sha256"]
    def processes(rows,prefix,budgets,get):
        assert [row["name"] for row in rows]==list(budgets)
        for row in rows:
            assert row["completed"] is True and row["timed_out"] is False and row["exit_code"]==0
            assert row["pid"]==row["pgid"] and row["timeout_seconds"]==budgets[row["name"]]
            assert 0<=row["elapsed_seconds"]<row["timeout_seconds"]
            for key in ("stdout","stderr"):
                value=row[key];assert pin(get(prefix+"/"+value["file"]))=={field:value[field] for field in ("bytes","sha256")}
    processes(gate["processes"],"run/processes",{"build":900,"native":60,"read-only-admission":180,"physical-controls":180},logical)
    def proof(value,prefixes):
        assert value["before"]==value["after"] and len(value["probes"])==12
        assert value["reader_writes"]==value["native_or_rust_executions"]==0
        observed=set()
        for key,row in value["before"].items():
            if row["sha256"] is None:continue
            root,path=key.split(":",1);name=prefixes[int(root)]+"/"+path;observed.add(name)
            item=files[name]
            assert row["bytes"]==item["bytes"] and row["sha256"]==item["sha256"] and stat.S_IMODE(row["mode"])==item["mode"]
        assert observed=={name for name in files if any(name.startswith(prefix+"/") for prefix in prefixes)}
    base=json.loads(logical("run/admission.json"));proof(base,["source","run/build","run/native"])
    assert base["pid"]==gate["processes"][2]["pid"]
    assert base["evidence"]==binding["admission"]
    controls=json.loads(logical("run/controls/CONTROLS.json"));assert controls["status"]=="PASS"
    assert controls["physical_mutants"]==4 and controls["relocated_admissions"]==2 and controls["guard_probes"]==72
    names=["high-work-bit","borrowed-work-byte","engine-guard-permission","compiled-image-byte","relocation-1","relocation-2"]
    assert [row["name"] for row in controls["records"]]==names
    processes([row["process"] for row in controls["records"]],"run/controls/processes",{name:180 for name in names},logical)
    retained_proofs=[base]
    for number,row in enumerate(controls["records"]):
        prefix="run/controls/"+row["name"];raw=logical(prefix+"/proof.json");assert pin(raw)==row["proof"]
        value=json.loads(raw);assert value["pid"]==row["process"]["pid"]
        assert value["evidence"]["status"]==("EXPECTED_REFUSAL" if number<4 else "PASS")
        if number>=4:assert value["evidence"]==binding["admission"]
        proof(value,[prefix+"/source" if number>=4 else "source",prefix+"/build",prefix+"/native"])
        retained_proofs.append(value)
    native=json.loads(logical("run/native/NATIVE.json"));assert native["status"]=="CAPTURED"
    assert native["cases"]==57 and native["actions"]==1182 and native["actual_native_calls"]==1122
    assert native["physical_bytes"]==binding["physical_bytes"] and native["snapshots"]==2478
    journal=logical("run/native/journal.ndjson");assert pin(journal)==binding["journal"]==native["journal"]
    rows=[json.loads(line) for line in journal.splitlines()]
    assert rows[0]["kind"]=="session" and rows[-1]["kind"]=="session_end"
    referenced=set();physical=0;snapshots=0;actions=0;cases=0;calls=0
    def physical_object(value):
        nonlocal physical
        raw=logical("run/native/objects/"+value["sha256"]);assert pin(raw)==value
        physical+=len(raw);referenced.add(value["sha256"]);return raw
    physical_object(rows[0]["leaf"]);physical_object(rows[-1]["leaf_after"])
    for row in rows[1:-1]:
        if row["kind"]=="create":
            cases+=1;calls+=1;physical_object(row["engine_image"])
        elif row["kind"]=="action":
            actions+=1;calls+=row["actual_native_calls"]
        else:assert row["kind"]=="case_end";physical_object(row["engine_image_after"])
        if row["kind"] in ("create","action"):
            for key in ("before","after"):
                snapshot=row[key];snapshots+=1;physical_object(snapshot["maps"])
                for value in snapshot["regions"].values():
                    if value["mapped"]:assert len(physical_object(value["physical"]))==value["capacity"]
                    else:assert value["physical"] is None
    assert (cases,actions,calls,snapshots,physical)==(57,1182,1122,2478,binding["physical_bytes"])
    assert referenced=={name[len("run/native/objects/"):] for name in files if name.startswith("run/native/objects/")}
    assert len(referenced)==native["objects"]==1792
    assert sum(files["run/native/objects/"+name]["bytes"] for name in referenced)==native["unique_bytes"]==89545618
    archive_read=json.loads(small["engine-layout-archive-read/ARCHIVE_READ.json"])
    assert archive_read["status"]=="PASS" and archive_read["archive"]==dict(**binding["tar"],mode=0o644)
    assert archive_read["guard_proofs"]==8 and archive_read["guard_probes"]==96
    assert archive_read["independent_admission"]==binding["admission"]
    archive_proof=json.loads(small["engine-layout-archive-read/admission.json"])
    proof(archive_proof,["source","run/build","run/native"])
    assert archive_proof["evidence"]==binding["admission"];retained_proofs.append(archive_proof)
    outer_get=lambda name:small[name]
    processes(json.loads(small["engine-layout-export-processes/processes.json"]),
        "engine-layout-export-processes",{"complete-export":180},outer_get)
    processes(json.loads(small["engine-layout-archive-processes/processes.json"]),
        "engine-layout-archive-processes",{"complete-archive-read":180},outer_get)
    processes(json.loads(small["engine-layout-archive-read/processes/processes.json"]),
        "engine-layout-archive-read/processes",{"independent-archive-admission":180},outer_get)
    export=json.loads(small["engine-layout.tar.gz.json"])
    assert {key:export[key] for key in ("bytes","sha256")}==binding["tar"] and export["gate_status"]=="PASS"
    assert export["logical_files"]==binding["logical_files"] and export["logical_bytes"]==binding["logical_bytes"]
    assert export["all_object_bytes_and_modes_reread"] and export["all_logical_files_reread"]
    return dict(schema="hepta.runtime.engine-layout.complete-zip-read.v1",status="PASS",zip=binding["zip"],tar=binding["tar"],
        zip_members=outer,logical_files=len(files),logical_bytes=binding["logical_bytes"],
        unique_objects=binding["unique_objects"],unique_bytes=binding["unique_bytes"],
        physical_snapshots=snapshots,complete_native_physical_bytes=physical,cases=cases,actions=actions,
        actual_recorded_native_calls=calls,retained_guard_proofs=len(retained_proofs),retained_guard_probes=96,
        actual_rejected_physical_controls=4,relocated_admissions=2,original_pipeline_success_preserved=True,
        native_or_rust_executions=0,reader_writes=0,private_storage_only=True,public_tools=False,whole_runtime_replaced=False)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("stage",choices=["fetch","read"]);parser.add_argument("--artifact-root",type=Path,required=True)
    parser.add_argument("--source-manifest-sha256",required=True);args=parser.parse_args()
    assert identity()==args.source_manifest_sha256
    binding=json.loads((ROOT/"BINDING.json").read_bytes())
    if args.stage=="fetch":result=fetch(args.artifact_root.absolute(),binding)
    else:
        result=guarded(lambda:inspect(args.artifact_root.absolute(),binding),
            roots=[ROOT,args.artifact_root.absolute()],foreign_path=Path("/proc/self/status"))
        assert len(result["probes"])==12 and result["before"]==result["after"]
    assert identity()==args.source_manifest_sha256
    print(encoded(result).decode(),end="")
if __name__=="__main__":main()
