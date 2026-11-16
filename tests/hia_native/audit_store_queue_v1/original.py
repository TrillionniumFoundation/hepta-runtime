"""Fresh unchanged std-only target lock tests and frozen observable queue traces."""
from pathlib import Path
import argparse, hashlib, json, os, sys, tomllib
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from build import verify_source,pin
from cases import domain,encoded
from process import Recorder,environment
from projection import expected

TESTS=(
 "expired_shared_owner_keeps_custody_until_finish_then_releases_writer",
 "shared_admission_and_finish_preserve_writer_and_queue_poison",
 "shared_gate_allows_two_readers_without_bypassing_a_queued_writer",
 "shared_panic_refuses_active_peers_without_revoking_finished_reads",
 "shared_readers_have_no_count_cap_and_cancelled_waiters_preserve_fifo",
)
FLAGS=("--edition=2021","--target","x86_64-unknown-linux-gnu",
       "-C","opt-level=1","-C","debuginfo=2","-C","debug-assertions=yes",
       "-C","overflow-checks=yes","-C","lto=no","-C","codegen-units=256","-C","rpath=no")
def source_identity():
    reference=ROOT/"reference"
    original=(reference/"target/src/mcp/runtime/request_audit.rs").read_bytes()
    owner=(reference/"audit_store_lock.rs.txt").read_bytes()
    tests=(reference/"target/src/mcp/runtime/request_audit_tests.rs").read_bytes()
    selected=(reference/"audit_store_tests.rs.txt").read_bytes()
    assert hashlib.sha256(original).hexdigest()=="b5189f2923153ffa83d0b45a7cdf89873b0f17ebbe6ec1b174c05bab291d73da"
    assert hashlib.sha256(owner).hexdigest()=="6b80246ce3c2ff97edb71f6f70d21b692b801648c355427672780d01b5f14b25"
    assert original.count(owner)==1
    assert hashlib.sha256(tests).hexdigest()=="a066822705a713929dd2791f1e889f9cf6b7c16567d0d6e71a4c4946b20e14a7"
    start=tests.index(b"fn wait_for_shared_gate_queue(")
    end=tests.index(b"\n#[test]\nfn shared_hot_preflight_never_creates_recovers_or_hides_unsafe_storage()")
    assert tests[start:end]==selected and selected.count(b"#[test]")==5
    cargo=(reference/"target/Cargo.toml").read_bytes()
    assert hashlib.sha256(cargo).hexdigest()=="bf00111f6ec88df9df4d0d1d14c125a64ce4f6bdc6724ba20e70498f56dcae7f"
    profile=tomllib.loads(cargo.decode())["profile"]["dev"]
    assert profile==dict(**{"opt-level":1,"debug":True,"debug-assertions":True,"overflow-checks":True,
                           "lto":False,"codegen-units":256,"incremental":True,"rpath":False})
    return dict(target_commit="d3d75c30719db966b004756f610007a7c723729e",
                owner=pin(owner),tests=pin(selected),original_tests=list(TESTS),profile=profile,
                unchanged_target_owner=True,unchanged_five_original_tests=True)
def check_tests(raw):
    text=raw.decode("utf-8")
    assert "\nrunning 5 tests\n" in "\n"+text
    assert [line for line in text.splitlines() if line.startswith("test ") and not line.startswith("test result:")]==[
        "test "+name+" ... ok" for name in TESTS]
    result=[line for line in text.splitlines() if line.startswith("test result:")]
    assert len(result)==1 and result[0].startswith("test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in ")
def run(output,rust_bin):
    if os.environ.get("GITHUB_ACTIONS")!="true" and os.environ.get("HIA_AUTHORIZED_REFERENCE_HOST")!="ai395":
        raise RuntimeError("fresh Rust requires CI or explicitly authorized ai395")
    source=verify_source();identity=source_identity()
    output.mkdir(parents=True,exist_ok=False)
    project=output/"project";project.mkdir()
    for name in ("audit_store_lock.rs.txt","audit_store_tests.rs.txt","original_tests.rs","trace.rs"):
        (project/name).write_bytes((ROOT/"reference"/name).read_bytes())
    rust_bin=rust_bin.resolve(strict=True)
    rustc=rust_bin/"rustc"
    env,binding=environment(os.environ,rust_bin)
    rec=Recorder(ROOT,output/"processes",env)
    version,_=rec.run("rustc-version",[rustc,"--version","--verbose"],timeout=60)
    assert version.decode().splitlines()[0].startswith("rustc 1.95.0 ")
    for name,source_name,extra in (("tests","original_tests.rs",["--test"]),("trace","trace.rs",[])):
        rec.run(name+"-build",[rustc,*FLAGS,*extra,"-C","incremental="+str(output/"incremental"/name),
                              project/source_name,"-o",output/name],cwd=project,timeout=900)
    test_out,_=rec.run("tests",[output/"tests","--test-threads=1"],timeout=180)
    check_tests(test_out)
    trace,_=rec.run("trace",[output/"trace"],timeout=180)
    assert trace==expected(domain())
    (output/"trace.bin").write_bytes(trace)
    assert verify_source()==source
    report=dict(schema="hepta.runtime.audit-store-queue.original.v2",status="PASS",
        source_manifest_sha256=source,source_identity=identity,source_unchanged=True,
        rustc_version=version.decode(),rustc=pin(rustc.read_bytes()),environment=binding,
        binaries={name:pin((output/name).read_bytes()) for name in ("tests","trace")},
        trace=pin(trace),projection_records=748,original_tests=5,process_count=5,
        limited_original_projection_pass=True,all_native_boundaries_original_compared=False,
        concurrent_native_lock_qualified=False,public_audit_qualified=False,whole_runtime_replaced=False)
    (output/"CAPTURE.json").write_bytes(encoded(report))
    print(json.dumps(report,sort_keys=True))
if __name__=="__main__":
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--rust-bin",type=Path,required=True);a=p.parse_args();run(a.output.resolve(),a.rust_bin)
