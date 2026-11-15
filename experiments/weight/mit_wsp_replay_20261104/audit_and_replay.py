"""Independent numeric reconstruction and MinAtar execution of MIT's published edits.

This replays released prescriptions; it does not independently rediscover them.
Game source is the original MinAtar 1.0.15 source embedded in the MIT prompt;
see upstream/exp5_write_from_scratch/LICENSE-MinAtar. MIT artifacts CC BY 4.0.
"""
from __future__ import annotations
import argparse, ast, hashlib, importlib.util, json, re, resource, time
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent
UP = ROOT / 'upstream' / 'exp5_write_from_scratch'
MAP = {'W1':'actor/dense1/kernel','b1':'actor/dense1/bias','W2':'actor/dense2/kernel','b2':'actor/dense2/bias','W3':'actor/logits/kernel','b3':'actor/logits/bias'}
CHANNELS = {
 'breakout':[['paddle'],[],['brick'],['ball'],['trail'],[]],
 'asterix':[['player'],['enemy'],['gold'],[],['trail'],[]],
 'seaquest':[['sub_front','sub_back'],['enemy_fish','enemy_sub','enemy_bullet'],['enemy_fish','enemy_sub','diver'],['friendly_bullet'],['trail','sub_back'],['oxygen_guage','diver_guage']]
}
def digest(p): return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def idx(n):
 if isinstance(n, ast.Tuple): return tuple(idx(v) for v in n.elts)
 if isinstance(n, ast.Slice):
  v=[None if x is None else ast.literal_eval(x) for x in [n.lower,n.upper,n.step]]
  if any(x is not None and (type(x) is not int or x<0) for x in v) or v[2]==0: raise ValueError('bad slice')
  return slice(*v)
 v=ast.literal_eval(n)
 if type(v) is not int or v<0: raise ValueError('bad integer index')
 return v

def reconstruct(game):
 refp=UP/'networks'/game/'hand.npz'
 with np.load(refp,allow_pickle=False) as z:
  weights={k:np.zeros_like(z[v]) for k,v in MAP.items()}
  original={k:z[v].copy() for k,v in MAP.items()}
 answer=(UP/'runs'/game/'reply'/'answer.md').read_text()
 code=re.findall(r'```edits\s*\n(.*?)```',answer,re.S)[-1]
 count=0
 for stmt in ast.parse(code).body:
  if isinstance(stmt,ast.Assign) and len(stmt.targets)==1: target=stmt.targets[0];op='assign'
  elif isinstance(stmt,ast.AugAssign):
   target=stmt.target
   op={ast.Add:'add',ast.Sub:'sub',ast.Mult:'mul'}.get(type(stmt.op))
   if op is None: raise ValueError('unsupported update')
  else: raise ValueError('unsupported edit statement')
  if not isinstance(target,ast.Subscript) or not isinstance(target.value,ast.Name) or target.value.id not in weights: raise ValueError('bad edit target')
  key=idx(target.slice);value=np.asarray(ast.literal_eval(stmt.value),dtype=np.float32)
  if not np.isfinite(value).all() or np.max(np.abs(value))>1e6: raise ValueError('nonfinite or excessive value')
  w=weights[target.value.id]
  if op=='assign': w[key]=value
  elif op=='add': w[key]+=value
  elif op=='sub': w[key]-=value
  elif op=='mul': w[key]*=value
  count+=1
 diffs={k:int(np.count_nonzero(weights[k].view(np.uint32)!=original[k].view(np.uint32))) for k in weights}
 if any(diffs.values()): raise AssertionError({'game':game,'diffs':diffs})
 return weights, {'statements':count,'bitwise_identical_to_released_checkpoint':True,'differing_f32_entries':diffs,'parameter_count':sum(w.size for w in weights.values()),'checkpoint_sha256':digest(refp),'answer_sha256':digest(UP/'runs'/game/'reply'/'answer.md')}

def environment(game):
 prompt=(UP/'runs'/game/'message.txt').read_text()
 code=re.findall(r'```python\s*\n(.*?)```',prompt,re.S)[0]
 # Source is version-pinned original MinAtar code, inspected before this run.
 modpath=ROOT/'generated_env'/f'{game}.py';modpath.parent.mkdir(exist_ok=True);modpath.write_text(code)
 spec=importlib.util.spec_from_file_location(f'minatar_original_{game}',modpath)
 module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
 return module.Env,hashlib.sha256(code.encode()).hexdigest()

def run(game,w,episodes,seed,mode):
 Env,envhash=environment(game)
 scores=[];lengths=[];wall=time.perf_counter();cpu=time.process_time();calls=0
 for ep in range(episodes):
  env=Env();env.random=np.random.RandomState(seed+ep);env.reset();last_action=0
  arng=np.random.default_rng(seed+100000+ep)
  total=0
  for t in range(10000):
   obs=env.state();x=np.zeros((10,10,6),np.float32)
   for i,names in enumerate(CHANNELS[game]):
    for name in names: x[:,:,i]=np.maximum(x[:,:,i],obs[:,:,env.channels[name]])
   if mode=='zero': logits=np.zeros(6,np.float32)
   else:
    h1=np.tanh(x.ravel()@w['W1']+w['b1']);h2=np.tanh(h1@w['W2']+w['b2']);logits=h2@w['W3']+w['b3']
   calls+=1
   probs=np.exp(logits-logits.max());probs/=probs.sum()
   action=int(arng.choice(6,p=probs))
   if env.random.rand()<0.1: action=last_action
   last_action=action
   reward,terminal=env.act(action);total+=reward
   if terminal: break
  scores.append(total);lengths.append(t+1)
 return {'game':game,'mode':mode,'episodes':episodes,'seeds':{'env_first':seed,'action_first':seed+100000,'scheme':'fresh episode seed = first + episode index'},'mean':float(np.mean(scores)),'standard_error':float(np.std(scores,ddof=1)/np.sqrt(episodes)),'mean_steps':float(np.mean(lengths)),'max_score':int(max(scores)),'cut_share':sum(x==10000 for x in lengths)/episodes,'forward_calls':calls,'elapsed_seconds':time.perf_counter()-wall,'cpu_seconds':time.process_time()-cpu,'game_source_sha256':envhash,'scores':scores,'lengths':lengths}

def audit_existing():
 base=ROOT/'hepta_existing/experiments/weight/mit_replay/portable'
 report=json.loads((base/'report.json').read_text());bounds=json.loads((ROOT/'upstream/transfer_probe_bounds.json').read_text())
 with np.load(base/'token_logprobs.npz',allow_pickle=False) as z,np.load(base/'first_attempt_token_logprobs.npz',allow_pickle=False) as z0:
  checks=[]
  for pair in report['paired']:
   i=pair['text_index'];b=bounds[i];j,k=b['start']-1,b['length']-1
   a=float(z[f'base_{i}'][j:k].mean());e=float(z[f'edited_{i}'][j:k].mean())
   checks.append({'i':i,'base':a,'edited':e,'delta':e-a,'exact_means':a==pair['base_branch_logprob'] and e==pair['edited_branch_logprob']})
  retries={k:bool(np.array_equal(z0[k],z[k])) for k in z0.files if k in z}
 hashes={p.name: {'sha256':digest(p),'expected':report['token_arrays'][p.name]['sha256'],'ok':digest(p)==report['token_arrays'][p.name]['sha256']} for p in base.glob('*.npz')}
 assert all(r['exact_means'] for r in checks) and all(h['ok'] for h in hashes.values()) and all(retries.values())
 return {'status':'passed','scope':'independent recomputation of previously published arrays, no new inference','pairs_verified':len(checks),'hash_checks':hashes,'retry_arrays_equal':retries,'checks':checks,'regression_warning':'Five of six productive log probabilities decrease; premature-close control probabilities increase. The mean mechanism gate is not a capability or preservation gate.'}

def main():
 p=argparse.ArgumentParser();p.add_argument('--episodes',type=int,default=128);p.add_argument('--output',default='new_replay.json');a=p.parse_args()
 output=ROOT/a.output
 if output.exists(): raise FileExistsError(output)
 result={'schema':'hepta.mit_independent_audit.v1','source_commit':'4d09ba6d6a7e891dd8063974dfe81b3d78e3494f','existing_replay_commit':'1f2d3d782e8803e769989234e7902ca5c04eff97','numpy_version':np.__version__,'method':'released prescription reconstruction plus independent environment evaluation; no LLM discovery, no training','comparability':'fresh explicit seeds; original RNG seeds and PPO checkpoints unavailable; zero baseline is not a training baseline','existing_replay_audit':audit_existing(),'games':{}}
 for game in ['breakout','asterix','seaquest']:
  w,r=reconstruct(game)
  result['games'][game]={'reconstruction':r,'runs':[]}
  for mode in ['zero','edited']:
   row=run(game,w,a.episodes,20261104,mode);result['games'][game]['runs'].append(row)
   print(json.dumps({k:v for k,v in row.items() if k not in ('scores','lengths')}),flush=True)
 result['peak_rss_kib']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
 output.write_text(json.dumps(result,indent=2,allow_nan=False)+'\n')
 print(json.dumps({'output':str(output),'sha256':digest(output)}),flush=True)
if __name__=='__main__':main()
