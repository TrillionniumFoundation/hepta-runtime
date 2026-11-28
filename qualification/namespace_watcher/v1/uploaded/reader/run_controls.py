"""Owned whole physical reader-controls process, original 180 second limit."""
import argparse,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from reader_common import source,read,require,loads,encoded
from process import Recorder
def run(bundle,output,phase,controls):
    identity=source();output.mkdir(parents=True,exist_ok=False)
    recorder=Recorder(ROOT,output/"processes")
    name="physical-controls"if phase=="create"else"physical-controls-read"
    evidence=output/"evidence"if phase=="create"else controls
    require(evidence is not None,"verify owns an existing complete controls input")
    try:
        raw,row=recorder.run(name,[sys.executable,"-I","-B",ROOT/"evidence_controls.py",
            "--phase",phase,"--bundle",bundle,"--output",evidence],timeout=180)
    except BaseException:
        if recorder.records:sys.stderr.buffer.write(read(output/"processes"/(name+".stderr")))
        raise
    require(source()==identity,"whole source unchanged after complete evidence controls")
    if phase=="create":print(raw.decode(),end="")
    else:
        proof=loads(raw);require(proof["evidence"]["status"]=="COMPLETE_PHYSICAL_CONTROLS_READ_PASS","whole independent controls read")
        print(encoded(dict(status=proof["evidence"]["status"],elapsed_seconds=row["elapsed_seconds"],
            files=len(proof["before"]),guards=len(proof["probes"]),physical_refusals=proof["evidence"]["physical_refusals"],
            whole_group_admissions=proof["evidence"]["whole_group_admissions"])).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--bundle",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("create","verify"),default="create");p.add_argument("--controls",type=Path)
    a=p.parse_args();run(a.bundle.resolve(strict=True),a.output.absolute(),a.phase,None if a.controls is None else a.controls.resolve(strict=True))
