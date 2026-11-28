"""Run the fixed pure reader under the complete read-only guard."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT))
from reader import admit
from common import source,put
from read_only_guard import guarded
def main():
    p=argparse.ArgumentParser();p.add_argument("--build",type=Path,required=True)
    p.add_argument("--native",type=Path,required=True);p.add_argument("--proof",type=Path,required=True)
    p.add_argument("--source-manifest-sha256",required=True);p.add_argument("--expect-refusal")
    a=p.parse_args();identity=source(a.source_manifest_sha256)
    build=a.build.resolve(strict=True);native=a.native.resolve(strict=True);proof=a.proof.absolute()
    assert not proof.exists() and not any(proof.is_relative_to(root) for root in (ROOT,build,native))
    def operation():
        if a.expect_refusal is None:return admit(build,native,identity)
        try:admit(build,native,identity)
        except (AssertionError,ValueError,KeyError) as error:
            message=str(error)
            assert a.expect_refusal in message,("wrong control refusal",message,a.expect_refusal)
            return dict(status="EXPECTED_REFUSAL",error_type=type(error).__name__,message=message,
                        required_message=a.expect_refusal,native_or_rust_executions=0)
        raise RuntimeError("physical control was incorrectly admitted")
    result=guarded(operation,roots=[ROOT,build,native],foreign_path=Path("/proc/self/status"))
    assert len(result["probes"])==12 and result["before"]==result["after"]
    put(proof,result)
    print(json.dumps(dict(status="PASS",proof=str(proof),evidence=result["evidence"],
                          guard_probes=len(result["probes"]),native_or_rust_executions=0,reader_writes=0),sort_keys=True))
if __name__=="__main__":main()
