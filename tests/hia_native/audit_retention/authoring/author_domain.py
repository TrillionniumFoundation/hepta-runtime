"""Generate input-only retention scenarios and external-effect tapes; no expected outputs."""
from pathlib import Path
import base64
import copy
import gzip
import hashlib
import json
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from protocol import initial, projection, START_PROBES, RESUME_PROBES


def record(index, owner='owner', **updates):
    value = dict(request_id=f'{index:064x}', owner=owner, tool_name='view', state='unknown',
                 accepted_unix_ms=10_000-index, elapsed_ms=None)
    value.update(updates)
    return value


def generate():
    rows = []
    def add(name, records, *, mode=2, owner='owner', pending=(), sync=True, effects=None, tags=(), probes=False):
        wire = initial(mode, owner, records, list(pending), sync)
        rows.append(dict(name=name, initial_hex=wire.hex(), effects=effects or {}, tags=list(tags),
                         output_capacity=160, workspace_extra=64, max_effects=4096,
                         start_probes=probes, resume_probes=probes, after_completion_probe=probes))

    for mode in (1, 2):
        for count in (0, 1, 126, 127, 128, 129, 130, 132):
            add(f'owner-threshold-{mode}-{count}', [record(i) for i in range(count)], mode=mode,
                tags=('owner-threshold', 'before-begin' if mode==1 else 'batch'), probes=(mode==1 and count==128))
    for count in (510, 511, 512, 513, 520):
        for sync in (False, True):
            add(f'global-threshold-{count}-{int(sync)}', [record(i, owner=f'foreign-{i}') for i in range(count)],
                sync=sync, tags=('global-threshold', 'sync-forwarding'))

    base = [record(i) for i in range(128)]
    blocked = [row['request_id'] for row in base[1:]]
    elapsed_values = (None, 0, 7, (1<<64)-1)
    for state in ('unknown', 'completed', 'failed'):
        for archived_state in ('unknown', 'completed', 'failed'):
            for elapsed_index, elapsed in enumerate(elapsed_values):
                for archived_elapsed_index, archived_elapsed in enumerate(elapsed_values):
                    records = copy.deepcopy(base)
                    records[0].update(state=state, elapsed_ms=elapsed)
                    archived = dict(records[0], state=archived_state, elapsed_ms=archived_elapsed)
                    effects = {'archive': {records[0]['request_id']+'.json': [
                        dict(status=0, error=0, record_hex=projection(archived).hex())]}}
                    add(f'archive-state-elapsed-{state}-{archived_state}-{elapsed_index}-{archived_elapsed_index}',
                        records, pending=blocked, effects=effects, tags=('archive-state', 'archive-elapsed'))
    for key, value in [('owner','other'), ('tool_name','different'), ('accepted_unix_ms',0),
                       ('accepted_unix_ms',10_000+(1<<64)), ('accepted_unix_ms',(1<<128)-1),
                       ('request_id','different-typed-id')]:
        archived = dict(base[0]); archived[key]=value
        effects = {'archive': {base[0]['request_id']+'.json': [
            dict(status=0, error=0, record_hex=projection(archived).hex())]}}
        add(f'archive-field-{key}-{len(rows)}', base, pending=blocked, effects=effects,
            tags=('archive-binding', 'typed-boundary'))
    for time in (0, (1<<64)-1, 1<<64, (1<<127)+5, (1<<128)-1):
        records=copy.deepcopy(base); records[0]['accepted_unix_ms']=time
        add(f'accepted-u128-{time}', records, pending=blocked, tags=('u128',))
    for text in ('', 'nul\0owner', '中文所有者', 'e\u0301/\\.json', '😺𐀀'):
        records=[record(i,owner=text,tool_name=text or '', request_id=(text if i==0 else f'{i:064x}')) for i in range(128)]
        add(f'utf8-fields-{len(rows)}', records, owner=text, pending=[r['request_id'] for r in records[1:]],
            tags=('utf8', 'empty-fields'))

    add('owner-all-pending',base,pending=[r['request_id'] for r in base],tags=('pending-short-circuit',))
    add('pending-duplicate-membership',base,pending=blocked+blocked,tags=('pending-short-circuit','duplicate-pending'))
    add('owner-all-active',base,effects={'active':{r['request_id']:[dict(status=1,error=0)] for r in base}},tags=('active-short-circuit',))
    add('owner-all-archive-errors',base,effects={'archive':{r['request_id']+'.json':[dict(status=1,error=55)] for r in base}},tags=('archive-read-error',))
    global_rows=[record(i,owner=f'other-{i}') for i in range(512)]
    add('global-all-active',global_rows,effects={'active':{r['request_id']:[dict(status=1,error=0)] for r in global_rows}},tags=('global-scan-order','active-short-circuit'))
    add('global-all-pending',global_rows,pending=[r['request_id'] for r in global_rows],tags=('global-scan-order','pending-short-circuit'))
    add('owner-false-prevents-global',base+[record(128+i,owner='foreign') for i in range(384)],
        pending=[r['request_id'] for r in base],tags=('phase-order','partial-false'))
    foreign=record(999,owner='foreign')
    add('owner-scan-skips-foreign-active-error',[foreign,*base],effects={'active':{foreign['request_id']:[dict(status=2,error=88)]}},
        tags=('owner-filter-short-circuit','phase-order'))
    phase_rows=[record(9000+i,owner='foreign') for i in range(386)]+[record(i) for i in range(130)]
    add('owner-then-global-partial-vector',phase_rows,tags=('phase-order','multiple-removals','no-sort'))
    for kind, status in (('active',2),('archive',1),('remove',1)):
        for error in (1,(1<<64)-1):
            key=base[0]['request_id']+('.json' if kind=='archive' else '')
            add(f'{kind}-error-{error}',base,pending=blocked,effects={kind:{key:[dict(status=status,error=error)]}},
                tags=('error-token',kind+'-error'))
    repeat=[record(i) for i in range(129)]
    add('activity-requeried-after-removal',repeat,effects={'active':{repeat[0]['request_id']:[dict(status=1,error=0),dict(status=0,error=0)]}},
        tags=('repeat-query','multiple-removals'))
    add('archive-requeried-after-removal',repeat,effects={'archive':{repeat[0]['request_id']+'.json':[
        dict(status=1,error=71),dict(status=0,error=0,record_hex=projection(repeat[0]).hex())]}},
        tags=('repeat-query','multiple-removals'))
    add('remove-error-after-success',repeat,effects={'remove':{repeat[1]['request_id']:[dict(status=1,error=72)]}},
        tags=('partial-error','remove-vector-order'))
    add('active-error-after-success',repeat,effects={'active':{repeat[1]['request_id']:[dict(status=2,error=73)]}},
        tags=('partial-error','activity-error'))
    add('false-after-success',repeat,pending=[r['request_id'] for r in repeat[1:]],
        tags=('partial-false','remove-vector-order'))
    duplicate=copy.deepcopy(repeat);duplicate[1]['request_id']=duplicate[0]['request_id'];duplicate[1]['tool_name']='other'
    add('duplicate-request-id-different-records',duplicate,tags=('duplicate-record-id','repeat-query'))
    add('duplicate-complete-records',[base[0],base[0],*base[1:]],tags=('duplicate-record-id','remove-vector-order'))
    shuffled=copy.deepcopy(repeat);random.Random(1701).shuffle(shuffled)
    add('unsorted-record-order-is-preserved',shuffled,tags=('no-sort','remove-vector-order'))

    rng=random.Random(0x484941524554454e)
    for case in range(48):
        count=rng.randrange(127,133)
        records=[record(i,accepted_unix_ms=rng.getrandbits(128),state=rng.choice(('unknown','completed','failed')),
                        elapsed_ms=rng.choice((None,0,rng.getrandbits(64)))) for i in range(count)]
        rng.shuffle(records)
        pending=[r['request_id'] for r in records[4:]]
        effects={}
        for item in records[:4]:
            if rng.randrange(5)==0:
                effects.setdefault('active',{})[item['request_id']]=[dict(status=1,error=0),dict(status=0,error=0)]
            if rng.randrange(7)==0:
                effects.setdefault('archive',{})[item['request_id']+'.json']=[dict(status=1,error=100+case)]
            if rng.randrange(11)==0:
                effects.setdefault('remove',{})[item['request_id']]=[dict(status=1,error=200+case)]
        add(f'seeded-typed-effects-{case}',records,pending=pending,sync=bool(case%2),effects=effects,
            tags=('seeded-input','u128','partial-effects','no-sort'))

    assert len(rows)==len({r['name'] for r in rows})
    plain=b''.join((json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False)+'\n').encode() for row in rows)
    compressed=gzip.compress(plain,mtime=0)
    (ROOT/'CASES.jsonl.gz.b64').write_bytes(base64.b64encode(compressed))
    tags={tag:sum(tag in row['tags'] for row in rows) for tag in sorted({tag for row in rows for tag in row['tags']})}
    budgets={name:60 for name in ('format','toolchain','cargo-version','original','native')}
    budgets.update({name:900 for name in ('native-build','rust-fetch','rust-vendor','rust-build')})
    budgets.update({name:180 for name in ('readonly_semantic','reader_controls','readonly_complete')})
    domain=dict(schema='hepta.audit-retention.domain.v1', cases=dict(file='CASES.jsonl.gz.b64',count=len(rows),
        bytes=len(plain),sha256=hashlib.sha256(plain).hexdigest(),compressed_bytes=len(compressed),
        compressed_sha256=hashlib.sha256(compressed).hexdigest()),
        process_budgets=budgets,tags=tags,native_schedule='round-robin-independent-workspaces',
        input_only=True,expected_semantic_outputs_present=False,
        native_protocol_controls=dict(start=list(START_PROBES),resume=list(RESUME_PROBES),
            resume_effect_kinds=[1,2,3],after_completion=True,expected_refusals=len(START_PROBES)+3*len(RESUME_PROBES)+1),
        full_runtime_qualified=False)
    (ROOT/'DOMAIN.json').write_text(json.dumps(domain,sort_keys=True,indent=2)+'\n')
    print(json.dumps(dict(cases=len(rows),plain_bytes=len(plain),compressed_bytes=len(compressed),tags=tags),sort_keys=True))


if __name__=='__main__':
    generate()
