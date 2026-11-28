"""Independent static scope and exact-source review; never touches remote state."""
import ast
import hashlib
import json
from pathlib import Path
import time

ROOT=Path(__file__).resolve().parents[1]
DEPLOYED=ROOT/'deployed';CANDIDATE=ROOT/'candidate/tools/cloud-compute/kaggle'


def definitions(path):
    tree=ast.parse(path.read_text());found={}
    for node in tree.body:
        if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
            found[node.name]=ast.dump(node,include_attributes=False)
        if isinstance(node,ast.ClassDef):
            for item in node.body:
                if isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef)):
                    found[node.name+'.'+item.name]=ast.dump(item,include_attributes=False)
    return found


def main():
    start,wall=time.process_time(),time.perf_counter()
    files={};unchanged=[];changes={}
    allowed={'kaggle_jobs.py':{'KaggleAdapter.artifacts','KaggleAdapter._reuse_artifacts'},
             'kaggle_create_only.py':{'CreateOnlyKaggleAdapter.artifacts'},
             'hepta_kaggle.py':{'main'},'tool_contract.py':set()}
    for name in ('kaggle_jobs.py','kaggle_create_only.py','hepta_kaggle.py','tool_contract.py','kaggle_transport.py'):
        old,new=DEPLOYED/name,CANDIDATE/name
        files[name]={'original_sha256':hashlib.sha256(old.read_bytes()).hexdigest(),
                     'candidate_sha256':hashlib.sha256(new.read_bytes()).hexdigest()}
        od,nd=definitions(old),definitions(new)
        for function in od:
            if od[function]!=nd.get(function):
                changes.setdefault(name,[]).append(function)
                if function not in allowed.get(name,set()):raise AssertionError('unexpected changed original function '+name+':'+function)
            else:unchanged.append(name+':'+function)
    router=ROOT/'candidate/qualification/hepta_compute_base.py'
    assert router.read_bytes()==(DEPLOYED/'hepta_compute_base.py').read_bytes()
    files['qualification/hepta_compute_base.py']={'sha256':hashlib.sha256(router.read_bytes()).hexdigest(),'deployed_byte_identical':True}
    for name in ('test_recovered_cache.py','test_original_router_collection.py'):
        p=CANDIDATE/'tests'/name
        files['tests/'+name]={'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
    findings=[
      {'id':'original_identity','result':'PASS_STATIC','basis':'artifacts requires original ACCEPTED state and positive kernel ID for external cache; ref_params requires known exact positive version; active account checked; original _status and _check_source_identity bodies are unchanged. No cache field creates an execution identity.'},
      {'id':'terminal_and_source','result':'PASS_STATIC','basis':'fresh initial import calls _status then checks COMPLETE, reads the pinned original source again and compares original source SHA/ref/kernel/private status. Existing publication reuse is separate and normal router collection independently calls fresh observe_locked.'},
      {'id':'manifest_authority','result':'PASS_STATIC','basis':'manifest always freshly downloads via original pinned-version output URL. Its actual byte SHA must equal caller prior pin, its request_id must match original provider request, and its declared paths must exactly cover the complete fixed-version output catalog except itself.'},
      {'id':'fullpath_catalog','result':'PASS_STATIC','basis':'actual CLI uses CreateOnlyKaggleAdapter; its original full-path URL catalog authority survives as _artifact_catalog. Lossy display-basename conflicts remain warnings, never file-identity authority.'},
      {'id':'cache_payloads','result':'PASS_STATIC','basis':'external cache directory opened through no-follow descriptors; each declared payload must be owned regular single-link file, with exact manifest length/hash and stable descriptor metadata. Destination is create-only private staging; independently rehashed before publication.'},
      {'id':'receipt_reuse','result':'PASS_STATIC','basis':'cache-specific receipt binds input digest/kernel/version/manifest, distinguishes fresh manifest HTTP from verified local payloads, and cannot silently downgrade manifest policy or invent HTTP payload lengths. Original receipt identity and complete local rehash remain enforced.'},
      {'id':'normal_router_finalize','result':'PASS_STATIC','basis':'deployed router bytes unchanged; collect holds normal request/account locks, observes terminal state, verifies wrapper identity, rehashes/copies all original outputs and verifies required artifact names before normal finish_collection sets COLLECTED and zero lease.'},
      {'id':'no_reexecution_or_manual_state','result':'PASS_STATIC','basis':'original submit/resume/cancel/status/ref binding/ledger method ASTs remain unchanged. New path invokes no submit/cancel/release. Production uses ledger event/publication interfaces; local test-fixture DB setup is not production recovery.'},
      {'id':'preserve_failures','result':'PASS_STATIC','basis':'new import appends artifact_source_verified/artifacts_verified or artifact_download_failed events through unchanged append-only event-file mechanism. Failed stage removed only after failure event; previous immutable event files remain. Time/monetary accounting must be supplied by the external original-run controller, not inferred free from cache.'},
      {'id':'historical_sunfo','result':'NOT_APPLICABLE','basis':'absent original acknowledged kernel/version cannot pass cache import; local bytes never establish unknown original submission. No authorization is inferred for resubmission or clearing that reservation.'}
    ]
    result={'status':'PASS_SCOPED_STATIC_CORE_REVIEW','blocking_findings':[],
      'files':files,'changed_original_functions':changes,'unchanged_original_function_count':len(unchanged),
      'unchanged_original_functions':unchanged,'review_findings':findings,
      'author_77_test_result_used_as_independent_evidence':False,'author_tests_read_for_coverage_only':True,
      'remote_calls':0,'production_state_edits':0,'candidate_source_edits':0,
      'activation_and_restore_scripts':'PENDING_SEPARATE_REVIEW','actual_collection_claim':False,
      'body_cpu_seconds':time.process_time()-start,'body_wall_seconds':time.perf_counter()-wall}
    output=Path(__file__).with_name('CACHE_CORE_STATIC_REVIEW.json');output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:v for k,v in result.items() if k not in ('files','unchanged_original_functions','review_findings')},indent=2))


if __name__=='__main__':main()
