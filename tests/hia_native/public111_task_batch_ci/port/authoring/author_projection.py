"""Factor the existing strict worker reader into an honest callable journal view.

Only its file/process admission is replaced. The integer pool, completed-job
CLOCK, final writer boundary, body and actual PID checks remain the same AST.
"""
import ast,copy,hashlib,json,pathlib
BASE=pathlib.Path(__file__).resolve().parent
ORIGINAL=BASE.parents[2]/'integration-work/bellman-call-v1/checkpoint-v7/caller_worker_evidence.py'
PIN='e93c0e3b65383ae80cc95c9025f52239ba7ca731e9621eb2ee0d1daf32426371'
def dump(n):return ast.dump(n,include_attributes=False)
def main():
 raw=ORIGINAL.read_bytes();assert hashlib.sha256(raw).hexdigest()==PIN
 ref=BASE/'source-v1/tests/hia_native/bellman_port/reference';ref.mkdir(parents=True,exist_ok=True)
 (ref/'caller_worker_evidence.py').write_bytes(raw)
 tree=ast.parse(raw);fn=next(n for n in tree.body if isinstance(n,ast.FunctionDef) and n.name=='verify_process')
 start=next(i for i,n in enumerate(fn.body) if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='requests' for t in n.targets))
 body=copy.deepcopy(fn.body[start:-1]);assert isinstance(fn.body[-1],ast.Return)
 substitutions={
  "packets(raw['stdin'])":'request_frames',
  "packets(raw['stdout'])":'output_frames',
  'journal_records(journal)':'journal_rows',
  "receipt['pid']":'pid',
 }
 class Substitute(ast.NodeTransformer):
  def __init__(self):self.counts={k:0 for k in substitutions}
  def generic_visit(self,node):
   for old,new in substitutions.items():
    if dump(node)==dump(ast.parse(old,mode='eval').body):
     self.counts[old]+=1;return ast.copy_location(ast.parse(new,mode='eval').body,node)
   return super().generic_visit(node)
 transform=Substitute();skip=dump(ast.parse("assert receipt['outputs']==all_output").body[0]);removed=0;out=[]
 for node in body:
  if dump(node)==skip:removed+=1;continue
  out.append(transform.visit(node))
 assert removed==1 and all(v>0 for v in transform.counts.values())
 # No file or process receipt survives in this pure projection. Their actual
 # custody is checked by read_port against the enclosing observed process.
 assert not any(isinstance(n,ast.Name) and n.id in {'receipt','raw','journal'} for n in ast.walk(ast.Module(body=out,type_ignores=[])))
 result=ast.parse("return {'status':'READ_ONLY_WORKER_PROJECTION_PASS','jobs':len(jobs),'pool_calls':sequence,'clock_calls':sum(v[0] for v in clock_counts.values()),'physical_clones':len(clones),'physical_reaps':len(reaped),'held_jobs':len(holds),'growth_calls':growth,'successful_complete_without_take':sum(finishes[job][1]==0 and job not in bodies for job in jobs),'all_completed_job_clock_sequences_checked':True,'actual_rust_executed':False,'public_handler_qualified':False}").body[0]
 new=ast.FunctionDef(name='verify_projection',args=ast.arguments(posonlyargs=[],args=[ast.arg(arg=x) for x in ['request_frames','output_frames','journal_rows','pid']],kwonlyargs=[],kw_defaults=[],defaults=[]),body=out+[result],decorator_list=[])
 retained=[copy.deepcopy(n) for n in tree.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name in {'words','Pool','decode_body'}]
 header=ast.parse('import json,struct\nINVALID=0xffffffff\nGROW=0xffffffd0\n')
 generated=ast.fix_missing_locations(ast.Module(body=header.body+retained+[new],type_ignores=[]))
 code=('"""Pure exact worker checks on actual callable journal projections; no process claim."""\n'+ast.unparse(generated)+'\n').encode()
 parsed=ast.parse(code)
 for node in retained:assert dump(next(n for n in parsed.body if isinstance(n,(ast.FunctionDef,ast.ClassDef)) and n.name==node.name))==dump(node)
 (BASE/'worker_projection.py').write_bytes(code)
 proof={'original_sha256':PIN,'projection_sha256':hashlib.sha256(code).hexdigest(),'retained_definitions':[n.name for n in retained],'substitutions':transform.counts,'removed_external_output_summary_assertions':removed,'retained_semantic_nodes':len(out),'process_custody':'actual enclosing port process, not synthetic worker process','native_or_rust_executed':False}
 (BASE/'projection-proof.json').write_text(json.dumps(proof,sort_keys=True,indent=2)+'\n');print(json.dumps(proof,sort_keys=True))
if __name__=='__main__':main()
