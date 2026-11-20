#!/usr/bin/env python3
"""Read only exact source inheritance and independently derive the input split."""
import ast,hashlib,importlib.util,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
from evidence_common import decode,pin,require,source_evidence

PARENT='b674d9c033dd43350a2d5f38039df469c8983149c0e568ab9c51ca614411d612'
ADAPTER='1c38b08d610c2440ae2e246bc06519f416591bbca590850f758ea8eef5848d4a'
DOMAIN='0dc9c300dab0380e746ead00b3a8338db7abf9b8c15190208436377838999114'
sha=lambda b:hashlib.sha256(b).hexdigest()

def partition(domain):
 require(domain['lanes']==['original-1','original-2','native-observed','native-unobserved'],'entire original lane order')
 require([row['id']for row in domain['cases']]==list(range(256)),'entire original input order')
 original=[];admitted=[];rejected=[]
 for case in domain['cases']:
  require(type(case['expected_version'])is str or case['expected_version']is None,'original exact String or None boundary')
  for lane in domain['lanes']:
   if lane=='native-unobserved'and(case['fault_plans']or case['descriptor_actor']or case['nofile']):continue
   pair=[case['id'],lane];original.append(pair)
   (rejected if case['expected_version']is None else admitted).append(pair)
 require(len(original)==992 and len(admitted)==985 and len(rejected)==7,'complete original 992 lanes partition as 985 plus seven None lanes')
 require(rejected==[[217,lane]for lane in domain['lanes']]+[[244,lane]for lane in domain['lanes'][:3]],'original None 217 has four lanes; faulted None244 has three')
 require({lane:sum(p[1]==lane for p in admitted)for lane in domain['lanes']}==dict(zip(domain['lanes'],(254,254,254,223))),'complete original lane multiplicities')
 return dict(original=original,admitted=admitted,typed_rejected=rejected)

def read_source(root=ROOT):
 root=Path(root);identity=source_evidence(root)
 require(pin(root/'parent/SOURCE_MANIFEST.json')['sha256']==PARENT and pin(root/'adapter/SOURCE_MANIFEST.json')['sha256']==ADAPTER,'original entire qualified child source manifests')
 parent=source_evidence(root/'parent');require(parent['files']==57,'all frozen parent source files')
 adapter=decode((root/'adapter/SOURCE_MANIFEST.json').read_bytes())['files']
 require(len(adapter)==38 and {p.relative_to(root/'adapter').as_posix()for p in(root/'adapter').rglob('*')if p.is_file()}==set(adapter)|{'SOURCE_MANIFEST.json'},'all frozen adapter source paths')
 for name,record in adapter.items():
  file=root/'adapter'/name;require({**pin(file),'mode':file.stat().st_mode&0o777}==record,'whole original adapter bytes/modes')
 require(pin(root/'parent/DOMAIN.json')['sha256']==DOMAIN,'complete original parent input bytes')
 domain=decode((root/'parent/DOMAIN.json').read_bytes());admitted=[];rejected=[]
 for case in domain['cases']:
  require(type(case['expected_version'])is str or case['expected_version']is None,'original declared typed values only')
  (rejected if case['expected_version']is None else admitted).append(case['id'])
 require(domain['case_count']==len(domain['cases'])==256 and len(admitted)==254 and len(rejected)==2,'complete disjoint ordered parent input split')
 lanes=partition(domain)
 require(len(domain['retry_controls'])*len(domain['retry_lanes'])==6,'entire unchanged EINTR cancellation set')
 evidence={}
 for file in('integration_edits.json','reader_integration_edits.json'):
  records=decode((root/'authoring'/file).read_bytes())
  for name,row in records.items():
   current=(root/'scripts'/name).read_text();original=(root/'parent/scripts'/name).read_bytes()
   require(row['complete_inverse']is True and sha(original)==row['original'] and sha(current.encode())==row['source'],'exact source/inverse endpoints')
   restored=current
   for edit in reversed(row['edits']):
    require(sha(restored.encode())==edit['after_sha256'] and restored.count(edit['after'])==edit['count'],'exact inverse edit position/count')
    restored=restored.replace(edit['after'],edit['before'])
    require(sha(restored.encode())==edit['before_sha256'],'full inverse intermediate bytes')
   require(restored.encode()==original,'complete original capture/reader recovered')
   replay=original.decode()
   for edit in row['edits']:
    require(replay.count(edit['before'])==edit['count'],'exact forward occurrence count');replay=replay.replace(edit['before'],edit['after'])
   require(replay==current,'whole current source reproduced forward')
   evidence[name]=dict(original=row['original'],current=row['source'],edits=len(row['edits']))
 row=decode((root/'authoring/binary_write_composition_fixture_edits.json').read_bytes())
 full=(root/'asm/binary_write_composition_fixture.S').read_bytes();extension=(root/'authoring/composition_fixture_extension.S').read_bytes();original=(root/'parent/asm/binary_parent_owner_fixture.S').read_bytes()
 require(row['complete_inverse']is True and sha(full)==row['source'] and sha(extension)==row['extension'] and sha(original)==row['original'] and full.endswith(b'\n'+extension),'exact whole frozen mechanical fixture inheritance')
 restored=full[:-len(extension)-1].decode()
 for edit in reversed(row['edits']):
  require(sha(restored.encode())==edit['after_sha256'] and restored.count(edit['after'])==edit['count'],'exact fixture inverse')
  restored=restored.replace(edit['after'],edit['before']);require(sha(restored.encode())==edit['before_sha256'],'whole fixture inverse step')
 require(restored.encode()==original,'all original fixture/fault/actor bytes retained')
 for path in(root/'scripts').glob('*.py'):ast.parse(path.read_bytes(),filename=str(path))
 require(source_evidence(root)==identity,'whole source custody during DATA read')
 return dict(status='PASS_EXACT_SOURCE_INHERITANCE',source=identity,parent_source=parent,adapter_sources=38,original_parent_inputs=256,admitted_ids=admitted,typed_rejected_ids=rejected,ordered_lane_partition=lanes,retries=6,inverse=evidence,public_binary_write_registered=False,whole_runtime_replaced=False)
if __name__=='__main__':print(json.dumps(read_source(),sort_keys=True))
