"""Own source/author/build processes; no new watcher semantic execution."""
import argparse,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,require,encoded
from process import Recorder,environment
def run(hepta,output):
    output.mkdir(parents=True,exist_ok=False);identity=source()
    env,binding=environment(os.environ);rec=Recorder(ROOT,output/"processes",env);python=Path(sys.executable).resolve(strict=True)
    try:
        rec.run("source-check",[python,"-I","-B",ROOT/"source_check.py"],timeout=60)
        rec.run("author-owner",[python,"-I","-B",ROOT/"authoring/author_owner.py","--root",ROOT,"--hepta",hepta,"--output",output/"generated-owner"],timeout=60)
        rec.run("fresh-image-build",[python,"-I","-B",ROOT/"build_prepare.py","--hepta",hepta,"--owner",output/"generated-owner","--output",output/"build"],timeout=900)
        require(source()==identity,"entire source unchanged")
        result=json.loads(read(output/"build/BUILD.json"))
        result.update(processes=rec.records,environment=binding)
        (output/"GATE.json").write_bytes(encoded(result))
        print(encoded(result).decode(),end="")
    finally:
        for row in rec.records:
            error=output/"processes"/row["stderr"]["file"]
            if error.is_file()and error.stat().st_size:sys.stderr.write(error.read_text())
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.output.absolute())
