"""Record frozen source authoring and fresh image build without semantic replay."""
import argparse,json,os,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,pin,require,encoded
from process import Recorder,environment
def run(hepta,output):
    output.mkdir(parents=True,exist_ok=False);identity=source()
    env,binding=environment(os.environ);rec=Recorder(ROOT,output/"processes",env);python=Path(sys.executable).resolve(strict=True)
    rec.run("source-check",[python,"-I","-B",ROOT/"source_check.py"],timeout=60)
    rec.run("author-owner",[python,"-I","-B",ROOT/"authoring/author_owner.py","--root",ROOT,"--hepta",hepta,"--output",output/"generated-owner"],timeout=60)
    rec.run("fresh-image-build",[python,"-I","-B",ROOT/"build_prepare.py","--hepta",hepta,"--owner",output/"generated-owner","--output",output/"build"],timeout=900)
    build=json.loads(read(output/"build/BUILD.json"));module=output/"build"/build["modules"]["namespace-fingerprint"]["manifest"]["path"]
    rec.run("author-callable",[python,"-I","-B",ROOT/"authoring/author_callable.py","--hepta",hepta,"--root",output/"build/pack-input",
        "--output",output/"callable-author","--owner-image",module.parent/"module.image.bin"],timeout=180)
    require(source()==identity,"full source unchanged")
    result=dict(status="SOURCE_AND_BUILD_PREPARATION_PASS",source_sha256=identity,processes=rec.records,modules=build["modules"],
        callable_author=json.loads(read(output/"callable-author/AUTHORING.json")),environment=binding,
        owner_semantic_executions=0,rust_executions=0,qualification_pending=True,namespace_watch_qualified=False,
        public_handler_qualified=False,whole_runtime_replaced=False)
    (output/"PREPARATION.json").write_bytes(encoded(result));print(encoded(result).decode(),end="")
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--hepta",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();run(a.hepta.resolve(strict=True),a.output.absolute())
