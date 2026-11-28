"""Complete private Bellman outputs compared with independent scalar arithmetic."""
import argparse
import copy
import hashlib
import json
import math
from pathlib import Path
import random
import struct
import sys
import time

ERRORS = {
    0xfffffe01:'Bellman needs 1..4096 topologically ordered states',
    0xfffffe02:'Bellman requires finite arithmetic in terminal value',
    0xfffffe03:'Bellman continuing actions need 1..3 branches',
    0xfffffe04:'Bellman exceeds its 24576-branch budget',
    0xfffffe05:'Bellman requires finite arithmetic in branch probability',
    0xfffffe06:'Bellman requires finite arithmetic in branch reward',
    0xfffffe07:'Bellman requires finite arithmetic in branch fee',
    0xfffffe08:'Bellman probabilities and fees must be nonnegative',
    0xfffffe09:'Bellman successors must strictly precede their parent state',
    0xfffffe0a:'Bellman requires finite arithmetic in probability sum',
    0xfffffe0b:'Bellman probabilities must sum to one within 1e-12; no normalization is performed',
    0xfffffe0c:'Bellman states need at least one legal action and at most two continuing actions',
    0xfffffe0d:'Bellman exceeds its scalar arithmetic work budget',
    0xfffffe0e:'Bellman requires finite arithmetic in Q consistency residual',
    0xfffffe0f:'Bellman repeated selection disagrees with its recorded action',
    0xfffffe10:'Bellman requires finite arithmetic in value consistency residual',
    0xffffff01:'Bellman requires finite arithmetic in child value plus reward',
    0xffffff02:'Bellman requires finite arithmetic in branch continuation less fee',
    0xffffff03:'Bellman requires finite arithmetic in weighted continuation',
    0xffffff04:'Bellman requires finite arithmetic in ordered action sum',
}
def bits(x): return struct.unpack('<Q',struct.pack('<d',x))[0]
def terminal(value): return {'kind':'terminal','value':value}
def continuation(*branches): return {'kind':'continue','branches':list(branches)}
def branch(probability,successor,reward=0.,fee=0.): return (probability,successor,reward,fee)
def state(value): return [terminal(value),None,None,None,None,None]
def pack_graph(graph):
    out=bytearray(b'HIABELL1'+struct.pack('<Q',len(graph)))
    for row in graph:
        for action in row:
            raw=bytearray(120)
            if action is not None:
                if action['kind']=='terminal':struct.pack_into('<QQ',raw,0,1,bits(action['value']))
                else:
                    bs=action['branches'];struct.pack_into('<QQQ',raw,0,2,0,len(bs))
                    for i,(p,s,r,f) in enumerate(bs[:3]):struct.pack_into('<QQQQ',raw,24+32*i,bits(p),s,bits(r),bits(f))
            out.extend(raw)
    return bytes(out)

def reference(graph):
    legal=continuing=branches=zeros=0;prob_error=0.
    for row in graph:
        for action in row:
            if action is None:continue
            legal+=1
            if action['kind']=='continue':
                continuing+=1;branches+=len(action['branches']);total=0.
                for p,_,_,_ in action['branches']:total+=p;zeros+=int(p==0.)
                prob_error=max(prob_error,abs(total-1.))
    plans=[];ties=near=0;minimum=None
    for row in graph:
        q=[]
        for action in row:
            if action is None:q.append(None)
            elif action['kind']=='terminal':q.append(action['value'])
            else:
                total=0.
                for p,s,r,f in action['branches']:
                    if p==0.:continue
                    rewarded=plans[s][2]+r
                    continuation_value=rewarded-f
                    contribution=p*continuation_value
                    total+=contribution
                    assert all(math.isfinite(v) for v in (rewarded,continuation_value,contribution,total))
                q.append(total)
        best=None
        for i,v in enumerate(q):
            if v is not None and (best is None or v>q[best]):best=i
        value=q[best];other=[v for i,v in enumerate(q) if v is not None and i!=best]
        if other:
            second=max(other);scale=max(1.,abs(value),abs(second));gap=value/scale-second/scale
            minimum=gap if minimum is None else min(minimum,gap)
            ties+=int(second==value);near+=int(gap<=2e-12)
        mask=sum(1<<i for i,v in enumerate(q) if v is not None)
        plans.append((mask,best,value,q))
    header=[int.from_bytes(b'HIABPLN1','little'),len(graph),legal,continuing,branches,zeros,bits(prob_error),
            len(graph)*256+legal*64+branches*128,ties,near,int(minimum is not None),bits(minimum or 0.),0,0,0,0]
    # Preserve an explicitly computed negative zero in the diagnostic.
    if minimum is not None:header[11]=bits(minimum)
    out=bytearray(struct.pack('<16Q',*header))
    for mask,best,value,q in plans:
        out.extend(struct.pack('<9Q',mask,best,bits(value),*(bits(v) if v is not None else 0 for v in q)))
    return bytes(out)

def corpus():
    known=[state(2.),[terminal(0.),None,None,None,None,terminal(4.)],
           [terminal(0.),continuation(branch(.25,0,0.,.5),branch(.75,1,0.,.5)),None,None,None,None],
           [terminal(3.),None,terminal(3.),continuation(branch(1.,2,1.,.25)),None,None]]
    yield 'original-known',known,None
    yield 'original-ties',[[None,terminal(-2.),terminal(-2.),None,terminal(-3.),None],
        [terminal(1.),terminal(math.nextafter(1.,math.inf)),None,None,None,None],
        [terminal(-0.),terminal(0.),None,None,None,None]],None
    yield 'original-fee-order',[state(1.),state(5.),[None,continuation(branch(.25,0,0.,3.),
        branch(.7500000000001,1,0.,3.)),None,None,None,None]],None
    order=[branch(.25,0,4e16),branch(.25,0,-4e16),branch(.5,0,2.)]
    for i,bs in enumerate((order,[order[0],order[2],order[1]])):
        yield f'original-branch-order-{i}',[state(0.),[None,continuation(*bs),None,None,None,None]],None
    maximum=sys.float_info.max
    zero=[state(maximum),[None,continuation(branch(0.,0,maximum),branch(1.,0,0.,maximum)),None,None,None,None]]
    yield 'original-zero-skip',zero,None
    for first in (-0.,0.):
        for second in (-0.,0.):
            for third in (-0.,0.):
                yield f'zero-ties-{bits(first)}-{bits(second)}-{bits(third)}',[[terminal(first),terminal(second),terminal(third),None,None,None]],None
    for p in (math.nextafter(1.-1e-12,1.),1.,math.nextafter(1.+1e-12,1.)):
        yield f'probability-boundary-{bits(p)}',[state(1.),[continuation(branch(p,0)),None,None,None,None,None]],None
    rng=random.Random(6780)
    for case in range(256):
        graph=[]
        for i in range(rng.randrange(1,65)):
            row=[None]*6
            for j in rng.sample(range(6),rng.randrange(1,7)):
                row[j]=terminal(rng.choice([0.,-0.,rng.uniform(-1000,1000),math.ldexp(rng.uniform(-1,1),rng.randrange(-1074,1000))]))
            if i:
                for j in rng.sample(range(6),rng.randrange(3)):
                    ps=rng.choice([[1.],[.5,.5],[.25,.25,.5],[0.,1.],[-0.,0.,1.]])
                    row[j]=continuation(*(branch(p,rng.randrange(i),rng.uniform(-5,5),rng.uniform(0,2))for p in ps))
            graph.append(row)
        yield f'random-{case}',graph,None
    maxrow=[terminal(0.),continuation(branch(0.,0),branch(0.,0),branch(1.,0)),
        continuation(branch(0.,0),branch(0.,0),branch(1.,0)),terminal(0.),terminal(0.),terminal(0.)]
    maxgraph=[[terminal(0.)]*6]+[maxrow]*4095
    yield 'original-maximum-4096',maxgraph,None
    for name,g,code in [
        ('empty',[],0xfffffe01),('too-many-states',[state(0.)]*4097,0xfffffe01),
        ('all-illegal',[[None]*6],0xfffffe0c),
        ('terminal-nan',[state(math.nan)],0xfffffe02),('terminal-infinity',[state(math.inf)],0xfffffe02),
    ]:yield name,g,code
    badbranches=[('negative-probability',branch(-1.,0),0xfffffe08),('zero-sum',branch(0.,0),0xfffffe0b),
        ('bad-sum',branch(1.+2e-12,0),0xfffffe0b),('nan-probability',branch(math.nan,0),0xfffffe05),
        ('infinite-probability',branch(math.inf,0),0xfffffe05),('nan-reward',branch(1.,0,math.nan),0xfffffe06),
        ('negative-fee',branch(1.,0,0.,-.1),0xfffffe08),('infinite-fee',branch(1.,0,0.,math.inf),0xfffffe07),
        ('forward-child',branch(1.,1),0xfffffe09),('huge-child',branch(1.,(1<<32)-1),0xfffffe09)]
    for name,b,code in badbranches:yield name,[state(0.),[None,continuation(b),None,None,None,None]],code
    for n in (0,4):yield f'branch-count-{n}',[state(0.),[None,continuation(*([branch(.25,0)]*n)),None,None,None,None]],0xfffffe03
    yield 'three-continuations',[state(0.),[continuation(branch(1.,0))]*3+[None]*3],0xfffffe0c
    yield 'branch-budget-before-state-count',maxgraph[:-1]+[[maxrow[1]]*6],0xfffffe04
    for name,g,code in [
        ('reward-overflow',[state(maximum),[continuation(branch(1.,0,maximum)),None,None,None,None,None]],0xffffff01),
        ('fee-overflow',[state(0.),[continuation(branch(1.,0,-maximum,maximum)),None,None,None,None,None]],0xffffff02),
        ('weighted-overflow',[state(maximum),[continuation(branch(1.+5e-13,0)),None,None,None,None,None]],0xffffff03),
        ('sum-overflow',[state(maximum),[continuation(branch(.5,0),branch(.5+5e-13,0)),None,None,None,None,None]],0xffffff04),
        ('probability-sum-overflow',[state(0.),[continuation(branch(maximum,0),branch(maximum,0)),None,None,None,None,None]],0xfffffe0a),
        ('zero-branch-forward-child',[state(maximum),[continuation(branch(0.,1,maximum),branch(1.,0)),None,None,None,None,None]],0xfffffe09),
    ]:yield name,g,code

def main():
    p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,required=True)
    p.add_argument('--manifest',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    a=p.parse_args();sys.dont_write_bytecode=True;sys.path.insert(0,str(a.runtime/'scripts'))
    from hia_native_loader import NativeModule
    raw=a.manifest.read_bytes();module=NativeModule(a.manifest,manifest_sha256=hashlib.sha256(raw).hexdigest())
    a.output.mkdir();rows=[];started=time.monotonic()
    with (a.output/'inputs.bin').open('xb') as inputs,(a.output/'native.bin').open('xb') as native,\
         (a.output/'python-reference.bin').open('xb') as reference_out:
        for name,graph,error in corpus():
            wire=pack_graph(graph);inputs.write(struct.pack('<Q',len(wire))+wire)
            capacity=max(128,128+72*len(graph));t=time.monotonic()
            status,output,workspace=module.invoke_raw(wire,output_capacity=capacity,workspace_capacity=capacity,
                output_fill=0xa5,workspace_fill=0x5a)
            if error is not None:
                assert status==error,(name,hex(status),hex(error))
                assert output==b'\xa5'*capacity,(name,'refusal changed output')
                expected=ERRORS[error].encode();actual=ERRORS[status].encode();kind=1
            else:
                assert status==capacity,(name,hex(status),capacity)
                expected=reference(graph);actual=output;kind=0
                assert actual==expected,(name,'complete native/reference bytes differ',
                    next((i for i,(x,y)in enumerate(zip(actual,expected))if x!=y),None))
            for f,data in ((native,actual),(reference_out,expected)):f.write(struct.pack('<QQ',kind,len(data))+data)
            rows.append({'name':name,'states':len(graph),'input_bytes':len(wire),'status':status,
                'output_bytes':len(actual),'output_sha256':hashlib.sha256(actual).hexdigest(),'wall_seconds':time.monotonic()-t})
    controls=0;base=pack_graph([state(1.)]);base_capacity=200
    mutated=[b'',base[:15],b'X'+base[1:],base[:-1],base+b'X']
    for at,val in ((16,3),(16+120+8,1),(16+16,1)):
        b=bytearray(base);struct.pack_into('<Q',b,at,val);mutated.append(bytes(b))
    for wire in mutated:
        code,out,w=module.invoke_raw(wire,output_capacity=base_capacity,workspace_capacity=base_capacity,
            output_fill=0xa5,workspace_fill=0x5a)
        assert code==0xffffffff and out==b'\xa5'*base_capacity;controls+=1
    for outcap,wcap in ((199,200),(200,199)):
        code,out,w=module.invoke_raw(base,output_capacity=outcap,workspace_capacity=wcap,output_fill=0xa5,workspace_fill=0x5a)
        assert code==0xfffffffd and out==b'\xa5'*outcap and w==b'\x5a'*wcap;controls+=1
    report={'status':'PASS','native_graph_cases':len(rows),'refusal_controls':controls,'cases':rows,
        'wall_seconds':time.monotonic()-started,'manifest_sha256':hashlib.sha256(raw).hexdigest(),
        'reference':'independent Python hardware arithmetic; original Rust replay pending',
        'scope':'private canonical-buffer numerical owner only; no JSON/canonical commitment/deadline/async/public activation',
        'files':{f.name:{'bytes':f.stat().st_size,'sha256':hashlib.sha256(f.read_bytes()).hexdigest()}for f in a.output.iterdir()}}
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items()if k!='cases'}))
if __name__=='__main__':main()
