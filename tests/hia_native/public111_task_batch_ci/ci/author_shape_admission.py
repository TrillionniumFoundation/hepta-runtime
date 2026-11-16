"""Recheck the qualified one-byte registry change independently of graph rebinding."""
from pathlib import Path
import argparse,json,sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import qualified_shape_author as old
from qualified_shape_author import require,sha,pin,blob,BASELINES,OWNER,PSEUDO,PROOF,COMPOSITION,ABI
PROOF_SHA="4a3cf68f16aad5cbc25c476d3435861f9fbe9da335b2bc6c13b6f895c0f257fe"
def verify(package,hepta=None):
    package=Path(package).resolve(strict=True);baseline=package/"ci/shape-baseline"
    before={n:(baseline/n).read_bytes() for n in old.BASELINES}
    for name,digest in old.BASELINES.items():require(sha(before[name])==digest,"complete original baseline: "+name)
    after={n:(package/"graph"/n).read_bytes() for n in (OWNER,PSEUDO,PROOF,COMPOSITION,ABI)}
    require(before[OWNER].count(old.OLD)==1 and before[OWNER].count(old.NEW)==0,"old HIA bound")
    require(after[OWNER]==before[OWNER].replace(old.OLD,old.NEW)
        and len(after[OWNER])==len(before[OWNER])
        and sum(a!=b for a,b in zip(after[OWNER],before[OWNER],strict=True))==1,"one exact HIA byte")
    require(before[PSEUDO].count(old.OLD_PSEUDO)==1
        and after[PSEUDO]==before[PSEUDO].replace(old.OLD_PSEUDO,old.NEW_PSEUDO),"exact pseudo bound")
    require(after[ABI]==before[ABI]+old.ABI_APPEND,"complete ABI extension")
    proof=json.loads(after[PROOF])
    require(sha(after[PROOF])==PROOF_SHA and proof["author_sha256"]==sha(Path(old.__file__).read_bytes())
        and proof["baseline"]==pin(before[OWNER]) and proof["output"]==pin(after[OWNER])
        and proof["baseline_admission_proof"]==pin(before[PROOF]),"qualified proof identity")
    require(sha((package/"graph/source/native/sdk_message_target.hepta").read_bytes())==old.MESSAGE_SHA,
            "qualified actual G1 source")
    if hepta is not None:
        require(old.ast_proof(before[OWNER],after[OWNER],hepta)==proof["ast"],"complete actual AST inverse")
    composition=json.loads(before[COMPOSITION])
    composition.update(schema="hepta.sdk-request-tasks.composition.v3",
        previous_composition_sha256=sha(before[COMPOSITION]),
        previous_author_sha256=composition["author_sha256"],author_sha256=proof["author_sha256"],
        previous_required_message_source_sha256=composition["required_message_source_sha256"],
        required_message_source_sha256=old.MESSAGE_SHA,source_bytes=len(after[OWNER]),
        source_sha256=sha(after[OWNER]),pseudo_sha256=sha(after[PSEUDO]),
        public_admission_proof_sha256=sha(after[PROOF]),accepts_g1_top_level_shape_class_5=True,
        unsupported_class_6_rejected=True)
    require(after[COMPOSITION]==old.encoded(composition),"qualified source composition")
    return {"status":"ONE_CONSTANT_SHAPE_ADMISSION_SOURCE_PASS",
        "changed_files":{n:{**pin(raw),"git_blob":blob(raw)} for n,raw in after.items()},
        "proof":proof,"native_executed":False,"rust_executed":False}
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--package",type=Path,required=True);p.add_argument("--hepta",type=Path,required=True)
    a=p.parse_args();print(json.dumps(verify(a.package,a.hepta),sort_keys=True,allow_nan=False))
if __name__=="__main__":main()
