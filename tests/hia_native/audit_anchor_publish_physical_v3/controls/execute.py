"""Only new admission/control domains; previously completed ordinary Rust/native are never replayed."""
from pathlib import Path
import argparse,sys
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
import control_common as rc
def prepare(original):
    identity=rc.source()
    sys.path[:0]=[str(ROOT/"reader"),str(original),str(original/"scripts")]
    import common,reader
    rc.check(common.ROOT==original and common.source()=="5108ee26b26723f601207fe15fa849f6b4f07b80aa0b752574792062c49010a9","complete frozen producer source")
    reader.prepare(original)
    import owner_controls,transport_controls,read_transport_controls
    return identity,owner_controls,transport_controls,read_transport_controls
def run(prior,output,phase):
    original=prior/"source";capture=prior/"run/semantic";identity,owner,transport,transport_reader=prepare(original)
    import read_callable_build
    compiled=read_callable_build.verify(capture/"build")
    if phase=="owner":owner.run(capture/"build",capture,output)
    elif phase=="transport":transport.run(capture/"build",output,output.parent/"owned-transport-fixture")
    else:raise ValueError("explicit new control phase")
    rc.check(rc.source()==identity,"whole control source stable")
if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--prior",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--phase",choices=("owner","transport"),required=True);a=p.parse_args()
    run(a.prior.resolve(strict=True),a.output.absolute(),a.phase)
