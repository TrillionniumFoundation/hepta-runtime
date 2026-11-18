"""Deferred strong-marker publication and unchanged base registry scenarios."""
from base_audit_active_cases import definitions as base_definitions,exercise as base_exercise
def definitions():
    yield from base_definitions()
    for flag in (0,1):
        for index,id in enumerate(['','a'*64,'a/b\0c','汉😀','x'*255,'x'*256]):
            yield (f'deferred-{flag}-{index}','deferred',(flag,id))
    for expired in (False,True):
        for flag in (0,1):yield (f'deferred-replace-{expired}-{flag}','deferred_replace',(expired,flag))
    for poison in (9,10):
        for flag in (0,1):yield (f'deferred-poison-{poison}-{flag}','deferred_poison',(poison,flag))
    yield ('detached-drop','detached_drop',None)
    for mode in ('base','detached','empty'):yield ('binding-'+mode,'binding',mode)
    yield ('publication-bad-leases','bad_publication',None)
    for count in (1,33,129):yield (f'detached-many-{count}','detached_many',count)
    for eof in (False,True):yield ('concurrent-detached-'+str(eof),'concurrent_detached',eof)
    for shared in (False,True):yield ('concurrent-publication-'+str(shared),'concurrent_publication',shared)

def exercise(s,kind,data):
    if not kind.startswith(('deferred','detached','binding','bad_publication','concurrent_detached','concurrent_publication')):
        return base_exercise(s,kind,data)
    def call(op,token=0,id='',flag=0,diagnostic=0,actor=0):
        row=s.receive(s.send(actor,op,token,id,flag));assert row[0]==diagnostic,(op,row,diagnostic);return row
    def query(id,value):
        assert call(6,id=id)[1]==value and call(7,id=id)[1]==value
    def detached(flag=1,actor=0):return call(13,flag=flag,actor=actor)[1]
    def publish(token,id,actor=0):return call(14,token=token,id=id,actor=actor)
    def drop(token):return call(4,token=token)
    if kind=='deferred':
        flag,id=data;one=detached(flag);two=call(3,token=one,actor=1)[1]
        query(id,0);assert call(11,token=two)[1]==flag
        assert publish(two,id,2)[2]==one;query(id,flag)
        publish(one,id,3);assert call(8)[3:]==(1,0,0,2)
        call(5,token=one,flag=1);query(id,1);drop(one);query(id,1)
        drop(two);query(id,0);call(14,token=one,id=id,diagnostic=40)
        assert call(8)[3:]==(0,0,0,0)
    elif kind=='deferred_replace':
        expired,flag=data;old=call(1,id='same',flag=1)[1];new=detached(flag)
        query('same',1)
        if expired:drop(old);query('same',0)
        publish(new,'same');query('same',flag)
        if not expired:
            call(5,token=old,flag=0);publish(old,'same');query('same',0)
            publish(new,'same');query('same',flag);drop(old)
        call(14,token=new,id='other',diagnostic=42);query('other',0)
        drop(new);query('same',0);assert call(8)[3:]==(0,0,0,0)
    elif kind=='deferred_poison':
        poison,flag=data;call(poison);one=detached(flag);two=call(3,token=one)[1]
        assert call(11,token=two)[1]==flag
        if poison==9:
            call(14,token=one,id='target',diagnostic=38)
            call(14,token=(1<<64)-1,id='target',diagnostic=38)
            call(6,id='target',diagnostic=38);call(7,id='target',diagnostic=38)
            assert call(8)[3]==0
        else:
            publish(one,'target');assert call(6,id='target')[1]==flag
            call(7,id='target',diagnostic=39);assert call(8)[3]==1
        call(5,token=two,flag=0);drop(one);drop(two)
        assert call(8)[-1]==0
    elif kind=='detached_drop':
        one=detached();two=call(3,token=one)[1];query('target',0)
        drop(one);drop(two);query('target',0)
        later=call(1,id='target',flag=1)[1];assert later>two
        call(14,token=one,id='target',diagnostic=40);query('target',1)
        drop(later);query('target',0)
    elif kind=='binding':
        id='' if data=='empty' else 'target'
        one=call(1,id=id,flag=1)[1] if data=='base' else detached()
        publish(one,id);call(14,token=one,id='different',diagnostic=42)
        query(id,1);query('different',0);publish(one,id);drop(one);query(id,0)
    elif kind=='bad_publication':
        call(14,token=(1<<64)-1,id='target',diagnostic=40)
        pin=call(2,id='target')[1];call(14,token=pin,id='target',diagnostic=40)
        assert call(6,id='target')[1]==0 and call(7,id='target')[1]==1
        drop(pin);query('target',0)
    elif kind=='detached_many':
        handles=[detached() for _ in range(data)]
        assert call(8)[3:]==(0,0,0,data)
        for index,handle in enumerate(handles):
            query(str(index),0)
            if index%2:publish(handle,str(index))
        assert call(8)[3]==data//2
        for index,handle in enumerate(handles):
            query(str(index),int(bool(index%2)));drop(handle)
        query('missing',0);assert call(8)[3:]==(0,0,0,0)
    elif kind=='concurrent_detached':
        call(0);tags=[s.send(actor,13,flag=1) for actor in range(4)]
        s.commuting_tags.update(tags)
        if data:
            s.deferred_tags=tags;s.deferred_kind='detached';return
        rows=[s.receive(tag) for tag in tags]
        assert sorted(r[1] for r in rows)==[1,2,3,4] and sorted(r[-1] for r in rows)==[1,2,3,4]
        assert all(r[0]==0 and r[1]==r[2] and r[3:6]==(0,0,0) for r in rows)
        s.phases.append(dict(name='detached',native_result_multiset=sorted(s.received[t][1] for t in tags)))
        query('target',0);call(12);assert call(8)[3:]==(0,0,0,0)
    elif kind=='concurrent_publication':
        first=detached();handles=[first]
        for _ in range(3):handles.append(call(3,token=first)[1] if data else detached())
        tags=[s.send(actor,14,token=handle,id='target') for actor,handle in enumerate(handles)]
        for index,tag in enumerate(tags):
            row=s.receive(tag);assert row==(0,0,first if data else handles[index],1,0,0,4)
        query('target',1);call(12);query('target',0);assert call(8)[3:]==(0,0,0,0)
    else:raise AssertionError(kind)
