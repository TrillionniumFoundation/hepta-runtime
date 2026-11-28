"""Fresh source/compile/pack-only candidate; no Watcher or Rust application."""
import argparse,sys,os
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import read,loads,source,require,encoded
from process import Recorder,environment

def run(hepta,output):
    output.mkdir(parents=True,exist_ok=False);identity=source()
    env,binding=environment(os.environ);rec=Recorder(ROOT,output/"processes",env)
    python=Path(sys.executable).resolve(strict=True)
    try:
        rec.run("source-check",[python,"-I","-B",ROOT/"source_check_fixed9.py"],timeout=60)
        rec.run("fixed-eight-proof",[python,"-I","-B",ROOT/"authoring/author_fixed8.py",
            "--root",ROOT,"--hepta",hepta,"--output",output/"fixed8-author"],timeout=60)
        rec.run("fresh-owner",[python,"-I","-B",ROOT/"build_fixed9.py","--phase","owner",
            "--hepta",hepta,"--output",output/"build"],timeout=900)
        rec.run("author-callable",[python,"-I","-B",ROOT/"authoring/author_callable.py",
            "--hepta",hepta,"--root",ROOT,"--owner-image",output/"build/modules/namespace-watcher/module.image.bin",
            "--output",output/"authored"],timeout=60)
        rec.run("fresh-packer",[python,"-I","-B",ROOT/"build_fixed9.py","--phase","packer",
            "--hepta",hepta,"--output",output/"build","--authored",output/"authored"],timeout=900)
        rec.run("complete-read",[python,"-I","-B",ROOT/"read_build_fixed9.py",
            "--build",output/"build","--authored",output/"authored"],timeout=180)
        require(source()==identity,"all source unchanged")
        result=loads(read(output/"processes/complete-read.stdout"))
        result.update(status="WATCHER_FIXED_NINE_SOURCE_BUILD_PASS",processes=rec.records,environment=binding,
            watcher_semantic_executions=0,rust_executions=0,original_comparison_qualified=False)
        (output/"GATE.json").write_bytes(encoded(result))
        for name in ("authoring/namespace_watcher_callable.S","native/namespace_watcher_callable.hepta",
            "native/namespace_watcher_callable.composition.json","authoring/namespace_watcher_callable.pseudo"):
            raw=read(output/"authored/generated"/name)
            print("GENERATED_FILE_BEGIN "+name);print(raw.decode(),end="");print("GENERATED_FILE_END "+name)
        print("FIXED_NINE_GATE_BEGIN");print(encoded(result).decode(),end="");print("FIXED_NINE_GATE_END")
    finally:
        for row in rec.records:
            path=output/"processes"/row["stderr"]["file"]
            if path.is_file() and path.stat().st_size:sys.stderr.write(path.read_text())

if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.output.absolute())
