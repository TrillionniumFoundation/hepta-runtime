"""Four physical controls and two relocated complete evidence readers."""
from pathlib import Path
import argparse,json,shutil,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from common import source,read,pin,put
from memory import maps
from process import Recorder
def change_blob(native,value,mutate):
    raw=read(native/"objects"/value["sha256"]);assert pin(raw)==value
    changed=mutate(raw);assert changed!=raw and len(changed)==len(raw)
    identity=pin(changed);(native/"objects"/identity["sha256"]).write_bytes(changed)
    value.clear();value.update(identity)
def change_journal(native,kind):
    rows=[json.loads(line) for line in read(native/"journal.ndjson").splitlines()]
    if kind=="high-work-bit":
        row=next(row for row in rows if row.get("case")=="new65-main" and row.get("kind")=="action"
                 and row["action"]==dict(op="invoke",slot=64))
        def mutation(raw):
            value=bytearray(raw);value[12352]^=1;return bytes(value)
        change_blob(native,row["after"]["regions"]["engine"]["physical"],mutation)
    elif kind=="borrowed-work-byte":
        row=next(row for row in rows if row.get("case")=="old59-main" and row.get("kind")=="action"
                 and row["action"]==dict(op="invoke",slot=58))
        def mutation(raw):return bytes([raw[0]^1])+raw[1:]
        change_blob(native,row["after"]["regions"]["work:58"]["physical"],mutation)
    elif kind=="engine-guard-permission":
        row=next(row for row in rows if row.get("case")=="new65-main" and row.get("kind")=="create")
        engine=row["after"]["regions"]["engine"];guard=engine["address"]+engine["capacity"]
        def mutation(raw):
            lines=raw.decode().splitlines(keepends=True);changed=0
            for i,line in enumerate(lines):
                fields=line.split();low,high=(int(x,16) for x in fields[0].split("-"))
                if low<=guard and guard+4096<=high:
                    assert fields[1]=="---p";lines[i]=line.replace("---p","rw-p",1);changed+=1
            assert changed==1;return "".join(lines).encode()
        change_blob(native,row["after"]["maps"],mutation)
    else:raise AssertionError(kind)
    journal=b"".join((json.dumps(row,sort_keys=True,separators=(",",":"))+"\n").encode() for row in rows)
    (native/"journal.ndjson").write_bytes(journal)
    capture=json.loads(read(native/"NATIVE.json"));capture["journal"]=pin(journal)
    objects=[p for p in (native/"objects").iterdir()]
    capture["objects"]=len(objects);capture["unique_bytes"]=sum(p.stat().st_size for p in objects)
    put(native/"NATIVE.json",capture)
def main():
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True)
    p.add_argument("--native",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);a=p.parse_args()
    identity=source(a.source_manifest_sha256);assert not a.output.exists();a.output.mkdir(parents=True)
    out=a.output.resolve();rec=Recorder(ROOT,out/"processes");records=[]
    controls=[("high-work-bit","complete physical bytes"),("borrowed-work-byte","complete physical bytes"),
              ("engine-guard-permission","guard page"),("compiled-image-byte","compiled engine image bytes")]
    for name,expected in controls:
        folder=out/name;folder.mkdir();shutil.copytree(a.build,folder/"build");shutil.copytree(a.native,folder/"native")
        if name=="compiled-image-byte":
            path=folder/"build/new65/module.bin";raw=read(path);path.write_bytes(raw[:-1]+bytes([raw[-1]^1]))
        else:change_journal(folder/"native",name)
        raw,row=rec.run(name,[sys.executable,"-I","-B",ROOT/"verify_readonly.py","--build",folder/"build",
            "--native",folder/"native","--proof",folder/"proof.json","--source-manifest-sha256",identity,
            "--expect-refusal",expected],timeout=180)
        proof=json.loads(read(folder/"proof.json"));assert proof["evidence"]["status"]=="EXPECTED_REFUSAL"
        records.append(dict(name=name,proof=pin(read(folder/"proof.json")),process=row))
    for number in (1,2):
        name="relocation-"+str(number);folder=out/name;folder.mkdir()
        shutil.copytree(ROOT,folder/"source");shutil.copytree(a.build,folder/"build");shutil.copytree(a.native,folder/"native")
        raw,row=rec.run(name,[sys.executable,"-I","-B",folder/"source/verify_readonly.py","--build",folder/"build",
            "--native",folder/"native","--proof",folder/"proof.json","--source-manifest-sha256",identity],timeout=180)
        proof=json.loads(read(folder/"proof.json"));assert proof["evidence"]["status"]=="PASS"
        records.append(dict(name=name,proof=pin(read(folder/"proof.json")),process=row))
    result=dict(schema="hepta.runtime.engine-layout.controls.v1",status="PASS",source_manifest_sha256=identity,
                physical_mutants=4,relocated_admissions=2,guard_probes=72,records=records,
                native_or_rust_executions=0,whole_runtime_replaced=False)
    put(out/"CONTROLS.json",result);print(json.dumps(result,sort_keys=True))
if __name__=="__main__":main()
