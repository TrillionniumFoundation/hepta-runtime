"""Freeze the exact one-instruction File clone correction; zero runtime applications."""
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT))
from common import source,read,loads,encoded,pin,require
from source_check_fixed8 import check as fixed_eight
def check():
    identity=source();prior=fixed_eight();revision=loads(read(ROOT/"FIXED9_REVISION.json"))
    before=read(ROOT/"authoring/namespace_watcher_callable.S.in");after=read(ROOT/"authoring/namespace_watcher_callable.fixed9.S.in")
    old=revision["exact_single_before"].encode();new=revision["exact_single_after"].encode()
    require(before.count(old)==1 and after==before.replace(old,new),"sole actual F_DUPFD_CLOEXEC minimum correction")
    require(pin(before)=={k:revision["prior_template"][k]for k in("bytes","sha256")}
        and pin(after)=={k:revision["corrected_template"][k]for k in("bytes","sha256")},"whole before/after mechanics sources")
    require(revision["original_fcntl_minimum"]==3 and revision["previous_fcntl_minimum"]==0,"actual observed Rust std File::try_clone floor")
    domain=loads(read(ROOT/"LOW_FD_DOMAIN.json"))
    require(domain["masks"]==list(range(1,8))and domain["content_choices"]==[False,True]and len(domain["cases"])==14,"all closed standard-descriptor subsets")
    return dict(status="FIXED_NINE_SOURCE_ONLY_PASS",source_manifest_sha256=identity,prior_symbolic_owner=prior,
        correction=revision,low_fd_cases=14,watcher_semantic_executions=0,rust_executions=0,application_replays=0)
if __name__=="__main__":print(encoded(check()).decode(),end="")
