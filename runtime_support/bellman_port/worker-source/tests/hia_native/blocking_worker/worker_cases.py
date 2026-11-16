"""Complete inherited graph corpus and integer nanosecond conversion cases."""
from __future__ import annotations
import itertools,json,random,struct,sys
from pathlib import Path

def graph_cases():
    sys.path.insert(0,str(Path(__file__).resolve().parent/'reference'))
    from qualify_bellman import corpus,terminal
    result=list(corpus());patterns=list(itertools.product((-0.,0.),repeat=3))
    for i,(first,second) in enumerate(itertools.product(patterns,repeat=2)):
        result.append(('signed-zero-'+str(i),[[terminal(x) for x in row]+[None]*3 for row in (first,second)],None))
    assert len(result)==363
    return result

def bits(value):return struct.unpack('<Q',struct.pack('<d',value))[0]

def original_graphs():
    result=[]
    for name,graph,error in graph_cases():
        rows=[]
        for state in graph:
            actions=[]
            for action in state:
                if action is None:actions.append(None)
                elif action['kind']=='terminal':actions.append({'kind':'terminal','value_bits':bits(action['value'])})
                else:actions.append({'kind':'continue','branches':[{'probability_bits':bits(p),'successor':s,'reward_bits':bits(r),'fee_bits':bits(f)} for p,s,r,f in action['branches']]})
            rows.append(actions)
        result.append({'name':name,'states':rows,'expected_error_code':error})
    return result

def duration_cases():
    values={0,1,2,3,(1<<64)-1,(1<<64)-2}
    for point in [999999999,1000000000,1000000001,30000000000,1<<32,1<<53,1<<63,(1<<64)-1]:
        for delta in range(-17,18):
            if 0<=point+delta<1<<64:values.add(point+delta)
    for seconds in [0,1,2,29,30,31,1<<20,1<<30,(1<<64)//1000000000]:
        for nano in [0,1,2,3,499999999,500000000,500000001,999999997,999999998,999999999]:
            value=seconds*1000000000+nano
            if value<1<<64:values.add(value)
    rng=random.Random(678030)
    for _ in range(1024):values.add(rng.getrandbits(64))
    return sorted(values)

def lines(values):return b''.join(json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n' for v in values)
