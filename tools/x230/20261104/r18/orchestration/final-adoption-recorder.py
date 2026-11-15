import datetime,hashlib,json,os
from pathlib import Path
root=Path('/home/qian/hepta-runtime-optimization-20261104-r18')
def sha(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def need(v,m):
 if not v:raise RuntimeError(m)
need(os.geteuid()==1000,'wrong operator')
bindings={
 'qualification-02/report.json':'e2d346eb47fce0812913cc6c830fcb945796f308c9340245b0b368b3fcc41367',
 'independent-acceptance-02.json':'d86c5e90720e632d431af59c888910c7b186ccc62e3bf73532fe952a8f6cc219',
 'publication-source-verification-02.json':'b238a45f538469d3b56196488d3661ed3a43d28ffca53fc3e304d43b5a324f18',
 'source-map.json':'b874f7f608cb394fe8b1e7ccb0a6eb240f37dc46ead2aa2c719e767c86e49593',
 'implementation-ready.json':'003990f5d4beb5b86e6c41fabda034d3d2c6b767da43072f554ab1d30affa52b',
 'source-freeze.json':'95450caab4049b6badb3056f7430c2a7c7da68d8316d99b173b51d9af7a97ff8',
}
for rel,want in bindings.items():
 p=root/rel
 need(p.resolve()==p and p.is_file() and sha(p)==want,'changed binding: '+rel)
a=json.loads((root/'independent-acceptance-02.json').read_bytes())
q=json.loads((root/'qualification-02/report.json').read_bytes())
need(a['schema']=='hepta-r18-independent-acceptance/v1' and a['accepted'] is True and len(a['checks'])==35 and all(v is True for v in a['checks'].values()),'independent acceptance failed')
need(a['qualified_report_sha256']==bindings['qualification-02/report.json'] and a['source_compile_input_count']==219 and q['qualified'] is True,'qualification binding failed')
need(a['test_counts']=={'passed':1637,'failed':0,'ignored':33,'selected':1670},'test counts differ')
source=json.loads((root/'source-map.json').read_bytes())
need(source==q['source_input']==q['source_tested']==q['source_after'] and len(source)==219,'source map differs')
for name,row in a['binaries'].items():
 need(row['byte_for_byte_equal'] is True and row['actual_sha256']==row['expected_sha256']==q['binaries'][name]['sha256']==sha(row['path'])==sha(row['reference_path']),'binary changed: '+name)
entry=lambda rel:{'path':str(root/rel),'sha256':bindings[rel]}
adoption={
 'schema':'hepta-x230-r18-final-adoption/v1','accepted':True,
 'created_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
 'acceptance_scope':'Qualified one-file source and exact release artifact selection; final lifecycle campaign is separately retained.',
 'workers':2,'arena_max':1,'recommended_observation_client_concurrency':8,
 'qualification_attempt':'qualification-02','rejected_attempts':['qualification-01'],
 'qualification_report':entry('qualification-02/report.json'),
 'independent_verification':entry('independent-acceptance-02.json'),
 'publication_source_verification':entry('publication-source-verification-02.json'),
 'source_map':entry('source-map.json'),'source_compile_input_count':219,
 'baseline_git_commit':'a784b92df7c84e6047343b436222716eb4b532d6',
 'candidate_src_git_tree':'8aa5705f6a42ae28938b767846b51388218b23b1',
 'changed_production_sources':['src/bin/jobctl.rs'],
 'rejected_runtime_candidates':['r16-profile-preparse-and-pin-buffer','r17-lazy-legacy-request'],
 'binaries':a['binaries'],'test_counts':a['test_counts'],
 'native_observation_evidence_reuse':'R18 runtime and native driver are byte-for-byte equal to retained R14 artifacts. Reuse R14 observation/configuration/boundary evidence; no additional throughput ABBA.',
 'jobctl_gain_scope':'Bounded buffered JSON reads in the isolated Linux helper; component probe results do not establish six-host operator throughput gains.',
 'planned_lifecycle_report':str(root/'recovery-control-01/report.json'),
 'production_services_modified':False,'automatic_qualification_retries':0,'automatic_third_attempt':False
}
raw=(json.dumps(adoption,ensure_ascii=False,indent=2)+'\n').encode()
path=root/'final-adoption.json'
with path.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
print(json.dumps({'created':str(path),'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw),'accepted':True,'checks':len(a['checks'])}))
