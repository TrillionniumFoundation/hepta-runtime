"""Record only complete pure-reader processes; never compile or execute an application."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent.parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/"reader"))
from reader_common import read,loads,encoded,require,pin
from process import Recorder
sys.path.insert(0,str(ROOT/"scripts"))
from join_uploaded import outer_source
def run(work):
    identity=outer_source();work.mkdir(parents=True,exist_ok=True);(work/"diagnostics").mkdir(exist_ok=True)
    capture=work/"inputs/capture.zip";uploaded=work/"inputs/uploaded.zip"
    fixed=work/"restored";complete=fixed/"complete";old=work/"uploaded"
    fresh=work/"fresh-reader";controls=work/"controls-read"
    r=Recorder(ROOT,work/"processes")
    commands=[
      ("restore-capture",[sys.executable,"-I","-B",ROOT/"reader/restore.py","--archive",capture,"--output",fixed,"--pins",ROOT/"reader/CAPTURE-PINS.json"]),
      ("restore-uploaded",[sys.executable,"-I","-B",ROOT/"scripts/extract_uploaded.py","--archive",uploaded,"--output",old,"--report",work/"diagnostics/UPLOADED-RESTORE.json"]),
      ("complete-semantic",[sys.executable,"-I","-B",ROOT/"reader/run_reader.py","--bundle",complete,"--output",fresh]),
      ("complete-controls",[sys.executable,"-I","-B",ROOT/"reader/run_controls.py","--phase","verify","--bundle",complete,"--controls",old/"controls/evidence","--output",controls]),
      ("complete-uploaded",[sys.executable,"-I","-B",ROOT/"scripts/join_uploaded.py","--bundle",complete,"--uploaded",old,"--fresh",fresh,
        "--controls-read",controls,"--archive",uploaded,"--capture-zip",capture,"--output",work/"diagnostics/UPLOADED-GUARDED.json"])
    ]
    try:
        for name,argv in commands:
            raw,row=r.run(name,argv,timeout=180);sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
        require(outer_source()==identity,"entire independent frozen source unchanged")
        result=dict(status="WATCHER_UPLOADED_READBACK_FINAL_PASS",source=identity,
            new_native_application_calls=0,new_original_application_calls=0,compiler_calls=0,
            completed_application_replays=0,whole_pure_reader_deadline_seconds=180,processes=r.records,
            upload_guard=pin(read(work/"diagnostics/UPLOADED-GUARDED.json")))
        (work/"diagnostics/GATE.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
    except BaseException:
        for row in r.records:
            sys.stderr.buffer.write(read(work/"processes"/row["stderr"]["file"]))
        raise
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--work",type=Path,required=True);a=p.parse_args();run(a.work.resolve(strict=True))
