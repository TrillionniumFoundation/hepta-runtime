"""Actual registry/lease scenarios; this driver does not implement registry policy."""
def definitions():
    ids=['','a'*64,'a/b\0c','汉😀','x'*255,'x'*256]
    for kind in (1,2):
        for index,id in enumerate(ids):yield (f'serial-{kind}-{index}','serial',(kind,id))
    for expired in (False,True):
        for flag in (0,1):yield (f'collision-{expired}-{flag}','collision',(expired,flag))
    for count in (1,2,4,65,257):yield (f'pin-group-{count}','pins',count)
    for count in (4,33,129,513):yield (f'growth-{count}','growth',count)
    for which in (9,10):
        for flag in (0,1):yield (f'poison-{which}-{flag}','poison',(which,flag))
    yield ('invalid-leases','invalid',None)
    yield ('distinct-pin-keys','keys',None)
    yield ('eof-pending','eof',None)
    yield ('concurrent-readers','readers',None)
    for kind in (1,2):yield (f'concurrent-clones-{kind}','clones',kind)
    yield ('concurrent-new-pins','new_pins',None)

def exercise(s,kind,data):
    def call(op,token=0,id='',flag=0,diagnostic=0,actor=0):
        value=s.receive(s.send(actor,op,token,id,flag))
        assert value[0]==diagnostic,(op,value,diagnostic)
        return value
    def query(id,active,dispatch=None):
        assert call(7,id=id)[1]==active
        if dispatch is not None:assert call(6,id=id)[1]==dispatch
    def create(kind,id,flag=1):return call(kind,id=id,flag=flag if kind==1 else 0)[1]
    def drop(handle):return call(4,token=handle)
    if kind=='serial':
        variant,id=data;one=create(variant,id);two=call(3,token=one,actor=1)[1]
        query(id,1,1 if variant==1 else 0)
        if variant==1:
            call(5,token=one,flag=0,actor=2);query(id,0,0)
            call(5,token=two,flag=1,actor=3);query(id,1,1)
        drop(one);query(id,1,1 if variant==1 else 0)
        drop(two);assert call(6,id=id)[1]==0;query(id,0,0)
        call(3,token=one,diagnostic=40);new=create(variant,id);assert new>two
        call(12);query(id,0,0);assert call(8)[3:]==(0,0,0,0)
    elif kind=='collision':
        expired,flag=data;one=create(1,'same');two=call(3,token=one)[1]
        if expired:drop(one);drop(two)
        new=create(1,'same',flag)
        if not expired:call(5,token=one,flag=1-flag)
        query('same',flag,flag);drop(new);query('same',0,0)
        if not expired:
            call(5,token=one,flag=1);query('same',0,0);drop(one);drop(two)
        assert call(8)[3:]==(0,0,0,0)
    elif kind=='pins':
        active=create(1,'target');pins=[create(2,'target') for _ in range(data)]
        call(5,token=active,flag=0);query('target',1,0);drop(active)
        for handle in pins[:-1]:drop(handle)
        query('target',1,0);drop(pins[-1]);query('target',0,0)
        assert call(8)[3:]==(0,0,0,0)
    elif kind=='growth':
        handles=[create(1,f'{i:064x}') for i in range(data)]
        for i in range(0,data,2):drop(handles[i])
        assert call(8)[3]==data
        assert call(6,id='missing')[1]==0
        assert call(8)[3]==data//2
        for i in range(1,data,2):
            assert call(6,id=f'{i:064x}')[1]==1;drop(handles[i])
        query('missing',0,0);assert call(8)[3:]==(0,0,0,0)
    elif kind=='poison':
        which,flag=data;active=create(1,'target',flag);pin=create(2,'target')
        dead=create(1,'dead');drop(dead);call(which)
        if which==9:
            call(6,id='target',diagnostic=38);call(7,id='target',diagnostic=38)
            call(1,id='fresh',flag=1,diagnostic=38);fresh=create(2,'fresh');drop(fresh)
            assert call(8)[3]==2
        else:
            assert call(6,id='target')[1]==flag
            call(7,id='target',diagnostic=39);call(2,id='fresh',diagnostic=39)
            fresh=create(1,'fresh');drop(fresh);call(7,id='target',diagnostic=39)
            assert call(8)[3]==1
        clone=call(3,token=pin)[1];drop(pin);drop(clone);call(5,token=active,flag=0);drop(active)
        call(9);call(10);call(7,id='target',diagnostic=38);call(12)
        assert call(8)[-1]==0
    elif kind=='invalid':
        for op in (3,4,5,11):call(op,token=(1<<64)-1,diagnostic=40)
        pin=create(2,'x')
        for op in (5,11):call(op,token=pin,diagnostic=40)
        drop(pin)
        for op in (3,4,5,11):call(op,token=pin,diagnostic=40)
        query('x',0,0)
    elif kind=='keys':
        handles=[]
        for i in range(33):
            first=create(2,str(i));second=create(2,str(i));clone=call(3,token=first)[1]
            handles.extend((first,second,clone));drop(first)
        assert call(8)[4:]==(33,66,66)
        for i in range(33):drop(handles[3*i+1])
        query('missing',0,0);assert call(8)[4:]==(33,33,33)
        for i in range(33):drop(handles[3*i+2])
        query('missing',0,0);assert call(8)[3:]==(0,0,0,0)
    elif kind=='readers':
        create(1,'target');create(2,'target')
        for _ in range(16):
            tags=[s.send(actor,7 if actor%2 else 6,id='target') for actor in range(4)]
            for tag in tags:assert s.receive(tag)==(0,1,0,1,1,1,2)
        call(12);query('target',0,0)
    elif kind=='clones':
        original=create(data,'target');tags=[s.send(actor,3,token=original) for actor in range(4)]
        results=[s.receive(tag) for tag in tags];assert sorted(r[1] for r in results)==[2,3,4,5]
        assert sorted(r[-1] for r in results)==[2,3,4,5] and all(r[0]==0 and r[2]==1 for r in results)
        s.phases.append(dict(name='clone',native_result_multiset=sorted(bytes.fromhex(s.received[t][1]).hex() for t in tags)))
        tags=[s.send(actor,4,token=result[1]) for actor,result in enumerate(results)]
        results=[s.receive(tag) for tag in tags];assert sorted(r[-1] for r in results)==[1,2,3,4]
        assert all(r[0]==0 and r[1]==0 and r[2]==1 for r in results)
        s.phases.append(dict(name='drop',native_result_multiset=sorted(bytes.fromhex(s.received[t][1]).hex() for t in tags)))
        query('target',1,1 if data==1 else 0);drop(original);query('target',0,0)
        s.commuting_tags.update(range(2,10))
    elif kind=='new_pins' or kind=='eof':
        call(0)
        tags=[s.send(actor,2,id='target') for actor in range(4)]
        if kind=='eof':s.deferred_tags=tags;s.commuting_tags.update(tags);return
        rows=[s.receive(t) for t in tags];assert sorted(r[1] for r in rows)==[1,2,3,4]
        assert sorted(r[-1] for r in rows)==[1,2,3,4] and all(r[0]==0 and r[1]==r[2] and r[4]==1 for r in rows)
        s.phases.append(dict(name='new-pins',native_result_multiset=sorted(s.received[t][1] for t in tags)))
        s.commuting_tags.update(tags);query('target',1,0);call(12);query('target',0,0)
    else:raise AssertionError(kind)
