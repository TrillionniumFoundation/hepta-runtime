"""Frozen inputs only: expected values come from unchanged original Deserialize."""
from __future__ import annotations
import copy
import importlib.util
import json
from pathlib import Path
import struct
import sys

SCALARS=(None,False,True,0,-1,1.5,'x',{},[])
BRANCH={'probability':1.0,'successor':0,'reward':0.0,'fee':0.0}

def encode(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()

def terminal(value=1.0):return {'kind':'terminal','value':value}
def continuation(branches=None):
    return {'kind':'continue','branches':[dict(BRANCH)] if branches is None else branches}
def one(action=None):
    return {'states':[{'actions':[terminal() if action is None else action]+[None]*5}]}
def convert(graph):
    result=[]
    for row in graph:
        actions=[]
        for action in row:
            value=copy.deepcopy(action)
            if value is not None and value['kind']=='continue':
                value['branches']=[dict(zip(('probability','successor','reward','fee'),branch)) for branch in value['branches']]
            actions.append(value)
        result.append({'actions':actions})
    return {'states':result}

def corpus(core_source:Path, group='ordinary'):
    if group=='unicode':
        text=''.join(chr(value) for value in range(0x110000) if not 0xd800<=value<=0xdfff)
        yield 'all-unicode-scalars-unexpected-string',encode(one(terminal(text)))
        yield 'all-unicode-scalars-unknown-variant',encode(one({'kind':text}))
        value=one();value[text]=False
        yield 'all-unicode-scalars-unknown-field',encode(value)
        return
    assert group=='ordinary'
    spec=importlib.util.spec_from_file_location('bellman_param_core_cases',core_source)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    for name,graph,error in module.corpus():
        if error is None:yield 'core-'+name,encode(convert(graph))
    for name,value in [('empty-states',{'states':[]}),('all-null-actions',{'states':[{'actions':[None]*6}]}),
                       ('maximum-typed-states',{'states':one()['states']*4097})]:yield name,encode(value)
    for count in (0,1,2,3,4,50):
        yield f'typed-branches-{count}',encode(one(continuation([dict(BRANCH)]*count)))
    for count in range(7):
        yield f'typed-continue-count-{count}',encode({'states':[{'actions':[continuation()]*count+[None]*(6-count)}]})
    for i,value in enumerate(SCALARS):
        yield f'root-type-{i}',encode(value)
        yield f'states-type-{i}',encode({'states':value})
        yield f'state-type-{i}',encode({'states':[value]})
        yield f'actions-type-{i}',encode({'states':[{'actions':value}]})
        yield f'action-type-{i}',encode({'states':[{'actions':[value]+[None]*5}]})
        yield f'kind-type-{i}',encode(one({'kind':value,'value':0}))
        yield f'terminal-value-type-{i}',encode(one(terminal(value)))
        yield f'branches-type-{i}',encode(one({'kind':'continue','branches':value}))
        yield f'branch-type-{i}',encode(one(continuation([value])))
        for field in BRANCH:
            branch=dict(BRANCH);branch[field]=value
            yield f'branch-{field}-type-{i}',encode(one(continuation([branch])))
    for length in range(9):
        yield f'actions-length-{length}',encode({'states':[{'actions':[None]*length}]})
        if length:
            yield f'actions-error-before-length-{length}',encode({'states':[{'actions':[0]+[None]*(length-1)}]})
    for name,action in [('missing-kind',{}),('kind-terminal-missing-value',{'kind':'terminal'}),
                        ('kind-continue-missing-branches',{'kind':'continue'}),('unknown-kind',{'kind':'stop'}),
                        ('bad-tag-before-bad-field',{'kind':1,'branches':False}),
                        ('missing-tag-before-bad-field',{'branches':False}),
                        ('unknown-before-missing',{'kind':'terminal','a':None}),
                        ('bad-known-before-unknown',{'kind':'terminal','value':False,'z':None}),
                        ('unknown-before-bad-known',{'kind':'terminal','a':None,'value':False}),
                        ('sequence-terminal',['terminal',1.0]),('sequence-continue',['continue',[dict(BRANCH)]]),
                        ('sequence-terminal-empty',['terminal']),('sequence-terminal-extra',['terminal',1,2]),
                        ('sequence-terminal-invalid-first',['terminal',None,2]),
                        ('sequence-continue-empty',['continue']),('sequence-continue-extra',['continue',[],2]),
                        ('sequence-kind-empty',[]),('sequence-kind-unknown',['bad',None])]:
        yield name,encode(one(action))
    for key in ('','a','actions','branches','fee','kind','probability','reward','states','successor','value','z','\0','`','\n','é','\u2028','\U0010ffff'):
        root=one();root[key]=False
        yield 'root-key-'+key.encode().hex(),encode(root)
        state={'actions':[None]*6};state[key]=False
        yield 'state-key-'+key.encode().hex(),encode({'states':[state]})
        for variant in ('terminal','continue'):
            value=terminal() if variant=='terminal' else continuation()
            value[key]=False
            yield variant+'-key-'+key.encode().hex(),encode(one(value))
        branch=dict(BRANCH);branch[key]=False
        yield 'branch-key-'+key.encode().hex(),encode(one(continuation([branch])))
    fields=tuple(BRANCH)
    for mask in range(16):
        branch={name:BRANCH[name] for index,name in enumerate(fields) if mask&(1<<index)}
        yield f'branch-fields-{mask}',encode(one(continuation([branch])))
    sequences=[[],[[]],[[],1],[[{'actions':[None]*6}]],[[{'actions':[None]*6}],False]]
    for index,value in enumerate(sequences):yield f'root-sequence-{index}',encode(value)
    for length in range(4):
        value=[[None]*6]+[False]*(max(0,length-1)) if length else []
        yield f'state-sequence-{length}',encode({'states':[value]})
    for length in range(7):
        value=[1.0,0,0.0,0.0,False,False][:length]
        yield f'branch-sequence-{length}',encode(one(continuation([value])))
    for index,value in enumerate((-0.0,0.0,1.0,-1,0,1,(1<<32)-1,1<<32,(1<<53)-1,1<<53,
                                  (1<<53)+1,(1<<63)-1,1<<63,(1<<64)-1,-(1<<63),-(1<<63)-1,
                                  sys.float_info.max,5e-324,1e-300,1e100)):
        yield f'terminal-number-{index}',encode(one(terminal(value)))
        for field in BRANCH:
            branch=dict(BRANCH);branch[field]=value
            yield f'branch-number-{field}-{index}',encode(one(continuation([branch])))
    for field in ('value','kind'):
        for index,text in enumerate(('\0\t\n\r\b\f"\\','\x7f\x85\u200b\u2028\u2029','é😀\U0010ffff','` apostrophe \' ')):
            value=terminal();value[field]=text
            yield f'debug-{field}-{index}',encode(one(value))
    states=one()['states']*4096+[{'actions':[0]+[None]*5}]
    yield 'typed-error-in-state-4097',encode({'states':states})
    yield 'typed-error-in-branch-5',encode(one(continuation([dict(BRANCH)]*4+[{'successor':False}])))
    # Duplicate resolution and number classification belong to the upstream Value owner.
    for name,raw in [('duplicate-root',b'{"states":null,"states":[]}'),
                     ('duplicate-kind',b'{"states":[{"actions":[{"kind":false,"kind":"terminal","value":0},null,null,null,null,null]}]}'),
                     ('integer-negative-zero',b'{"states":[{"actions":[{"kind":"terminal","value":-0},null,null,null,null,null]}]}'),
                     ('float-integer-successor',b'{"states":[{"actions":[{"kind":"continue","branches":[{"probability":1,"successor":2e0,"reward":0,"fee":0}]},null,null,null,null,null]}]}')]:
        yield name,raw
    raw_key='$serde_json::private::RawValue'
    yield 'raw-value-params',encode({raw_key:encode(one()).decode()})
    nested='['*127+'0'+']'*127
    yield 'raw-value-deep-tail',encode(one(terminal({raw_key:nested})))

def all_cases(core_source):
    for group in ('ordinary','unicode'):
        for name,raw in corpus(core_source,group):yield group,name,raw
