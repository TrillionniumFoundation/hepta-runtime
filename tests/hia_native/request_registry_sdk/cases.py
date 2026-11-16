"""Frozen schedules for native-first request registry and unchanged SDK replay."""
import itertools

def schedules():
    cases=[]
    def new(name,initial_parent=False):
        case={'case':len(cases)+1,'name':name,'initial_parent':initial_parent,'steps':[{'op':'init'}]}
        cases.append(case);return case['steps']
    def register(steps,ident):
        generation=1+sum(step['op']=='register'for step in steps)
        steps.append({'op':'register','generation':generation,'id':ident});return generation
    def complete(steps,generation,retire=False):
        steps.append({'op':'complete','generation':generation})
        if retire:steps.append({'op':'retire','generation':generation})
    def retire(steps,generations):
        for generation in generations:steps.append({'op':'retire','generation':generation})
    ids=[1,'1',0,'0',-1,'-1',-(1<<63),(1<<63)-1,'','nul\0tail','nul','汉字😀']
    steps=new('complete-typed-id-boundaries')
    for ident in ids:register(steps,ident)
    for ident in [1,'0','',None,'nul\0tail','unregistered',99]:
        steps.append({'op':'cancel','id':ident})
    for generation in reversed(range(1,len(ids)+1)):complete(steps,generation,True)
    for ident in [-1,'1','nul\0tail','汉字😀']:
        for order in itertools.permutations(('old','new','cancel')):
            steps=new('duplicate-'+repr(ident)+'-'+'-'.join(order))
            register(steps,ident);register(steps,ident);register(steps,'independent')
            for action in order:
                if action=='cancel':steps.append({'op':'cancel','id':ident})
                else:complete(steps,1 if action=='old'else 2)
            complete(steps,3);retire(steps,[1,2,3])
    for order in itertools.permutations((1,2,3)):
        for cancel_at in range(4):
            steps=new('three-duplicate-'+str(order)+'-cancel-'+str(cancel_at))
            for _ in range(3):register(steps,'shared')
            register(steps,12)
            for at in range(4):
                if at==cancel_at:steps.append({'op':'cancel','id':'shared'})
                if at<3:complete(steps,order[at])
            complete(steps,4);retire(steps,[1,2,3,4])
    for reason in [1,2]:
        for order in itertools.permutations((1,2,3)):
            steps=new('drain-'+str(reason)+'-'+str(order))
            register(steps,1);register(steps,1);register(steps,'1')
            if reason==2:steps.extend([{'op':'parent'},{'op':'parent'}])
            steps.append({'op':'drain','reason':reason})
            for generation in order:complete(steps,generation,True)
    steps=new('EOF-wins-before-parent-cancellation')
    register(steps,'x');register(steps,'x');register(steps,'z')
    steps.extend([{'op':'cancel','id':'z'},{'op':'drain','reason':1},{'op':'parent'}])
    for generation in [2,1,3]:complete(steps,generation,True)
    for ident in [0,'1','nul\0tail','']:
        steps=new('initial-modern-request-under-cancelled-parent-'+repr(ident),True)
        steps.append({'op':'parent'});register(steps,ident)
        steps.extend([{'op':'drain','reason':2},{'op':'inspect','generation':1}])
        complete(steps,1,True)
    steps=new('complete-five-MiB-typed-string-id')
    ident='q'*(5*1024*1024-4)+'汉a'
    assert len(ident.encode())==5*1024*1024
    register(steps,ident);register(steps,ident)
    steps.append({'op':'cancel','id':ident+'\0'})
    complete(steps,1);steps.append({'op':'inspect','generation':2});complete(steps,2)
    retire(steps,[1,2])
    steps=new('2306-retained-contexts-with-257-displaced-owners')
    for ident in range(2049):register(steps,ident)
    for ident in range(257):register(steps,ident)
    for ident in range(0,2049,17):steps.append({'op':'cancel','id':ident})
    steps.append({'op':'cancel','id':None})
    for generation in range(1,2307):complete(steps,generation,True)
    return cases
