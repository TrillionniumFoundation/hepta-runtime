#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recheck the rejected R17 candidate's complete compile-input Git binding."""
import argparse,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
EXPECTED_COMMIT='a784b92df7c84e6047343b436222716eb4b532d6'
EXPECTED_ROOT='f85e12bd92eb03df9e4352c115bd8d29dc13069e'
OVERRIDES={'src/bin/jobctl.rs':('cd5989b57e2249d9c7e78a76ceb29db5f1d5dbf7','c22fdcd5bafad3a2123d5817c27fd73e7b5c26001bf1a8bdd6f8dbacabc8b562'),'src/mcp/runtime/jobs.rs':('758bdda38b58f01d1cd281661a165d5f033779bd','f7c23620d2d79c5a02938b432e90f8dadb6352a897bf5a575547eabc121119f4')}
def sha(b):return hashlib.sha256(b).hexdigest()
def need(v,s):
    if not v:raise ValueError(s)
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--candidate-root',type=Path,required=True)
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    proof=json.loads((HERE/'baseline-tree-proof.json').read_bytes())
    commit=json.loads((HERE/'baseline-commit.json').read_bytes())
    observation=json.loads((HERE/'x230-observation.json').read_bytes())
    execution=json.loads((HERE/'remote-execution.json').read_bytes())
    entries=proof['entries'];by_path={e['path']:e for e in entries}
    need(len(entries)==len(by_path),'duplicate proof paths')
    need(commit['sha']==proof['baseline_commit']==EXPECTED_COMMIT,'baseline commit differs')
    need(commit['tree']['sha']==proof['baseline_root_tree']==EXPECTED_ROOT,'baseline root differs')
    need(proof['recursive_response_truncated'] is False,'truncated Git tree')
    def tree_hash(path,overrides):
        prefix=path+'/' if path else ''
        children=[e for e in entries if e['path'].startswith(prefix) and '/' not in e['path'][len(prefix):]]
        children.sort(key=lambda e:(e['path'][len(prefix):]+('/' if e['type']=='tree' else '')).encode())
        raw=b''.join(e['mode'].lstrip('0').encode()+b' '+e['path'][len(prefix):].encode()+b'\0'+bytes.fromhex(overrides.get(e['path'],e['sha'])) for e in children)
        return hashlib.sha1(b'tree '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
    subtrees=[e for e in entries if e['type']=='tree' and (e['path'] in ('src','examples') or e['path'].startswith(('src/','examples/')))]
    need(tree_hash('',{})==EXPECTED_ROOT,'root tree proof differs')
    for e in entries:
        p=e['path'];need(not p.startswith('/') and all(x not in ('','.','..') for x in p.split('/')),'invalid proof path')
        if '/' in p:need(p.rsplit('/',1)[0] in by_path and by_path[p.rsplit('/',1)[0]]['type']=='tree','missing proof parent')
    for e in subtrees:need(tree_hash(e['path'],{})==e['sha'],'subtree proof differs: '+e['path'])
    baseline={p:e for p,e in by_path.items() if (p in ('Cargo.toml','Cargo.lock','rustfmt.toml') or p.startswith(('src/','examples/'))) and e['type']!='tree'}
    need(len(baseline)==219 and all(e['type']=='blob' and e['mode'] in ('100644','100755') for e in baseline.values()),'compile inventory differs')
    current={r['path']:r for r in observation['files']}
    need(len(current)==len(observation['files'])==219 and set(current)==set(baseline),'observation inventory differs')
    need(observation['success'] is True and all(observation['checks'].values()),'remote observation failed')
    need(execution['state']=='succeeded' and execution['exit_code']==0,'remote job failed')
    need(observation['report_sha256']=='883d65c6947f6d6617dabc9af04246fb28e75b4fdb473e175a65212d5e14f1a9','qualification report differs')
    files=[]
    for p,e in sorted(baseline.items()):
        expected=OVERRIDES.get(p,(e['sha'],None))
        row=current[p]
        need(row['git_blob_sha1']==expected[0],'qualified source Git blob differs: '+p)
        if p in OVERRIDES:
            raw=(args.candidate_root/p).read_bytes()
            need(sha(raw)==row['sha256']==expected[1],'candidate source SHA256 differs: '+p)
            need(hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()==expected[0],'candidate Git blob differs: '+p)
        files.append({'path':p,'mode':e['mode'],'baseline_git_blob_sha1':e['sha'],'qualified_git_blob_sha1':row['git_blob_sha1'],'qualified_sha256':row['sha256'],'bytes':row['bytes'],'changed_from_baseline':p in OVERRIDES})
    need([r['path'] for r in files if r['baseline_git_blob_sha1']!=r['qualified_git_blob_sha1']]==sorted(OVERRIDES),'delta differs')
    hashes={p:v[0] for p,v in OVERRIDES.items()}
    for e in sorted(subtrees,key=lambda e:e['path'].count('/'),reverse=True):hashes[e['path']]=tree_hash(e['path'],hashes)
    checks={'baseline_root_and_all_compile_subtrees_recomputed':True,'219_compile_inputs':True,'no_added_or_deleted_compile_inputs':True,'all_219_git_blob_bindings_match':True,'all_219_sha256_bound_to_qualified_report':True,'exactly_two_candidate_source_changes':True,'candidate_two_files_match_qualified_source':True,'cargo_lock_rustfmt_unchanged':all(current[p]['git_blob_sha1']==baseline[p]['sha'] for p in ('Cargo.toml','Cargo.lock','rustfmt.toml'))}
    result={'schema':'hepta-r17-historical-candidate-publication-source-verification/v1','success':all(checks.values()),'historical_candidate':True,'adopted':False,'decision':'R17 combined candidate rejected after final performance review. This receipt describes historical candidate bytes, not the final adopted publication overlay.','decision_reference_sha256':'6a462fcf70100a962227cc3762b6d95b746a7e89f69d954c6f941ccb7e2988da','baseline_commit':EXPECTED_COMMIT,'baseline_root_tree_sha1':EXPECTED_ROOT,'candidate_src_tree_sha1':hashes['src'],'candidate_examples_tree_sha1':hashes['examples'],'report_sha256':observation['report_sha256'],'remote_job_id':execution['job_id'],'checks':checks,'remote_checks':observation['checks'],'verified_subtree_count':len(subtrees),'file_count':len(files),'unchanged_count':217,'changed_count':2,'files':files,'evidence_sha256':{n:sha((HERE/n).read_bytes()) for n in ('baseline-commit.json','baseline-tree-proof.json','verify_x230_source.py','x230-observation.json','remote-execution.json','bind_publication_source.py')}}
    with args.output.open('xb') as f:f.write((json.dumps(result,sort_keys=True,indent=2)+'\n').encode())
    print(json.dumps({'success':result['success'],'receipt':str(args.output),'receipt_sha256':sha(args.output.read_bytes()),'file_count':219,'candidate_src_tree_sha1':hashes['src'],'historical_candidate':True,'adopted':False}))
if __name__=='__main__':main()
