"""One fixed source-derived dense-expm oracle; no training or financial labels."""
import ast
import copy
from functools import lru_cache
import gzip
import hashlib
import json
from pathlib import Path
import os
import struct
import sys
import time
import numpy as np
import scipy
from scipy.linalg import expm
from scipy.special import expit, ndtr

ROOT = Path(os.environ['HEPTA_EVENT_STUDY_DIR']).resolve()
BASE = Path(os.environ['HEPTA_EVENT_SOURCE_ROOT']).resolve()


def sha(data): return hashlib.sha256(data).hexdigest()
def canonical(x): return json.dumps(x, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
def array_sha(x): return sha(np.asarray(x, dtype='<f8').tobytes(order='C'))
def put(name, x):
    with (ROOT / 'evidence' / name).open('x') as f:
        json.dump(x, f, indent=2, allow_nan=False)
        f.write('\n')


def load_definitions(path, names, namespace):
    tree = ast.parse(path.read_text())
    body = [n for n in tree.body if getattr(n, 'name', None) in names]
    exec(compile(ast.Module(body=body, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace


def event_basis():
    result = []
    for history in range(7):
        allowed = (range(31) if history == 0 else [31] if history == 1 else [32]
                   if history == 2 else range(32) if history == 3 else list(range(31))+[32]
                   if history == 4 else range(33))
        result.extend((history, latent) for latent in allowed)
    assert len(result) == 163
    return result


def lifted_generator(original, nodes):
    index = {pair:i for i,pair in enumerate(nodes)}
    matrix = np.zeros((len(nodes), len(nodes)))
    for i, (history, latent) in enumerate(nodes):
        matrix[i,i] = original[latent,latent]
        for target, rate in enumerate(original[latent]):
            if target == latent or rate == 0: continue
            reset = latent in (31,32) and target < 31
            after = {1:3,2:4}.get(history,history) if reset else history
            if target == 31: after = {0:1,4:6}.get(after,after)
            if target == 32: after = {0:2,3:5}.get(after,after)
            matrix[i,index[after,target]] += rate
    assert np.max(abs(matrix.sum(1))) < 2e-10
    return matrix


def decoder(mass, nodes):
    h = np.asarray([x[0] for x in nodes]); latent = np.asarray([x[1] for x in nodes])
    positive = ((latent >= 16)&(latent < 31))|(latent == 32)
    p = float(mass[positive].sum())
    return dict(first_lower=float(mass[np.isin(h,[1,3,5])].sum()),
                first_upper=float(mass[np.isin(h,[2,4,6])].sum()),
                no_outer_hit=float(mass[h==0].sum()), reset_seen=float(mass[h>=3].sum()),
                both_boundaries=float(mass[h>=5].sum()), endpoint_above_zero=p,
                endpoint_at_zero=float(mass[latent==15].sum()),
                endpoint_below_zero=float(mass[~positive&(latent!=15)].sum()),
                current_endpoint_nonpositive_sign_score=1-2*p, current_endpoint_positive_sign_score=2*p-1)


def main():
    started = time.process_time()
    protocol_bytes = (ROOT/'PROTOCOL_FROZEN.json').read_bytes()
    protocol = json.loads(protocol_bytes)
    if protocol['profile'] != 'finite-checkpoint-renewal-history-163-f64-v2': raise ValueError('v2 current-endpoint score contract required')
    for row in protocol['sources']:
        if sha(Path(row['path']).read_bytes()) != row['sha256']: raise ValueError('source drift')
    joint = BASE/'neuron_margin_experiment/vendor/frozen_joint'
    task = load_definitions(joint/'joint_task.py', {'validate_public','initial','legal','due_request','successor'},
                           dict(np=np,copy=copy,Path=Path,SCHEMA='joint-current-at-due-fixed-deadline-v1'))
    law_ns = load_definitions(joint/'joint_law.py', {'IndependentLaw'},
                             dict(np=np,lru_cache=lru_cache,expit=expit,ndtr=ndtr,expm=expm))
    nodes = event_basis(); index = {pair:i for i,pair in enumerate(nodes)}
    arrays = {}; cache = {}; requests = []; models = []
    numeric = dict(dtype='IEEE754-binary64', method='scipy.linalg.expm', scipy_version=scipy.__version__,
                   profile=protocol['profile'], tolerance_abs=2e-10, duration_unit='checkpoint model time')
    generator_error = 0.; table_error = 0.; marginal_error = 0.
    for item in protocol['inputs']:
        raw = Path(item['checkpoint_path']).read_bytes()
        if sha(raw) != item['checkpoint_gzip_sha256']: raise ValueError('checkpoint drift')
        model = json.loads(gzip.decompress(raw)); fit = item['fit']; public = item['public']
        own = law_ns['IndependentLaw'](model['core']['raw'],31)
        gen = {}; lifted = {}
        for drive in [-1,0,1]:
            gen[drive] = np.asarray(model['core']['generators'][str(drive)])
            generator_error = max(generator_error,float(np.max(abs(gen[drive]-own.generator(drive)))))
            lifted[drive] = lifted_generator(gen[drive],nodes)
            arrays[f'fit{fit}_original_drive{drive}'] = gen[drive]
            arrays[f'fit{fit}_joint_drive{drive}'] = lifted[drive]
        if generator_error > 2e-10: raise ArithmeticError('stored/source generator decomposition mismatch')
        initial = np.zeros(163)
        for latent,p in enumerate(own.initial_mass(public['prior_distance'])):
            if p: initial[index[0,latent]] = p
        arrays[f'fit{fit}_initial_joint'] = initial
        cases = []
        for label in ['WAIT_ONLY','TWO_LEGAL_READS']:
            state=task['initial'](public); mass=initial.copy(); marginal=own.initial_mass(public['prior_distance']); steps=[]; completed=0
            for tick in range(6):
                action=2 if label=='TWO_LEGAL_READS' and state['budget']>1 and task['legal'](public,state)[2] else 1
                due=task['due_request'](public,state,action)
                completion=None if due is None else dict(observation=completed,observation_tick=due)
                record=dict(kind='none',observation_tick=None,observation=None) if completion is None else dict(kind='observation',**completion)
                before=copy.deepcopy(state); before_mass=mass.copy(); state=task['successor'](public,state,action,completion)
                drive=public['drive'][tick]; dt=float(public['duration'][tick]); G=lifted[drive]
                key_payload=dict(checkpoint_sha256=item['checkpoint_gzip_sha256'],generator_sha256=array_sha(G),
                                 duration_f64_le=struct.pack('<d',dt).hex(),numeric_contract=numeric)
                key=sha(canonical(key_payload)); lookup=time.process_time(); hit=key in cache
                lookup_cpu=time.process_time()-lookup; build_cpu=None
                if not hit:
                    begin=time.process_time();P=expm(dt*G);build_cpu=time.process_time()-begin
                    if not np.isfinite(P).all() or P.min() < -2e-12 or np.max(abs(P.sum(1)-1))>2e-10: raise ArithmeticError('invalid dense event transition')
                    cache[key]=P;arrays['operator_'+key]=P
                P=cache[key]; start=time.process_time();mass=mass@P; application_cpu=time.process_time()-start
                original_table=next(np.asarray(t['matrix']) for t in model['core']['tables'] if t['dt']==dt and t['drive']==drive)
                table_error=max(table_error,float(np.max(abs(expm(dt*gen[drive])-original_table))))
                marginal=marginal@original_table
                if completion is not None:
                    emissions=own.emission(public['reliability'][due-1],model['confusion'])
                    mass*=np.array([emissions[latent,completed] for _,latent in nodes]);mass/=mass.sum()
                    marginal*=emissions[:,completed];marginal/=marginal.sum();completed+=1
                projected=np.zeros(33)
                for value,(_,latent) in zip(mass,nodes):projected[latent]+=value
                marginal_error=max(marginal_error,float(np.max(abs(projected-marginal))))
                identity=dict(checkpoint=item['checkpoint_gzip_sha256'],public=public,owner_before=before,
                              action=action,completion=record,joint_state_sha256=array_sha(before_mass),profile=protocol['profile'])
                requests.append(dict(request_id=f'fit{fit}:{label}:tick{tick}',fit=fit,history=label,tick=tick,
                    checkpoint_sha256=item['checkpoint_gzip_sha256'],checkpoint_decoded_sha256=item['checkpoint_decoded_sha256'],
                    public_sha256=sha(canonical(public)),initial_joint_sha256=array_sha(initial),
                    complete_request_sha256=sha(canonical(identity)),current_joint_sha256=array_sha(before_mass),
                    operator_key=key,operator_key_payload=key_payload,cache_event='HIT' if hit else 'BUILD',
                    operator_array_key='operator_'+key,joint_generator_array_key=f'fit{fit}_joint_drive{drive}',
                    original_generator_array_key=f'fit{fit}_original_drive{drive}',
                    operator_build_cpu_seconds=build_cpu,lookup_cpu_seconds=lookup_cpu,application_cpu_seconds=application_cpu,
                    restore_cpu_seconds=None,restore_cost_known=False))
                steps.append(dict(endpoint_score_target_tick=state['tick'],fixed_task_target_tick=public['deadline'],consumable_as_submit_or_continuation_q=False,action=action,completion=record,owner_before=before,state=state,joint=mass.tolist(),decoder=decoder(mass,nodes),marginal=marginal.tolist()))
            if label=='TWO_LEGAL_READS' and completed!=2: raise ArithmeticError('two legal observations were not completed')
            cases.append(dict(label=label,initial_joint_sha256=array_sha(initial),steps=steps))
        models.append(dict(fit=fit,checkpoint_sha256=item['checkpoint_gzip_sha256'],public=public,cases=cases))
    if max(table_error,marginal_error)>2e-10:raise ArithmeticError('generator/table or joint marginal mismatch')
    np.savez(ROOT/'evidence/ORACLE_ARRAYS.npz',**arrays)
    put('ORACLE_INPUT.json',dict(schema='hepta.event-history-oracle.v2',profile=protocol['profile'],endpoint_score_contract='CURRENT_JOINT_ENDPOINT_ONLY_NOT_DEADLINE_SUBMIT_OR_CONTINUATION_Q',models=models))
    put('OPERATOR_TRACE.json',dict(schema='hepta.event-operator-trace.v1',protocol_sha256=sha(protocol_bytes),numeric_contract=numeric,
        requests=requests,unique_operators=len(cache),request_count=len(requests),baseline_already_reuses_operator=True,
        full_history_result_cache_enabled=False,claimed_WSP_cache_saving=None,arrays_sha256=sha((ROOT/'evidence/ORACLE_ARRAYS.npz').read_bytes())))
    put('ORACLE_RECEIPT.json',dict(schema='hepta.event-oracle-receipt.v1',generator_source_max_error=generator_error,
        stored_transition_max_error=table_error,joint_marginal_max_error=marginal_error,CPU_seconds=time.process_time()-started,
        inputs=10,intervals=60,financial_labels=0,source_script_sha256=sha(Path(__file__).read_bytes())))
    print(json.dumps(dict(status='ORACLE_COMPLETE',cases=10,intervals=60,unique_operators=len(cache),CPU_seconds=time.process_time()-started)))


if __name__=='__main__':main()
