"""Deterministic original batch application inputs; no expected diff renderer."""
import itertools
import random
import struct


def plan(operations):
    body=bytearray()
    for index,(kind,start,end,content) in enumerate(operations):
        raw=content.encode('utf-8')
        body.extend(struct.pack('<6Q',index,kind,kind,start,end,len(raw)));body.extend(raw)
    return struct.pack('<8s5Q',b'HBPLR001',0,len(operations),len(body),0,0)+body


def encode(row):
    original=row['original'].encode('utf-8');operations=plan(row['operations'])
    return struct.pack('<8s7Q',b'HBACT001',2,len(original),len(operations),0,0,0,0)+original+operations


def iter_cases():
    case_id=0
    def row(name,original,operations,domain='resolved-application'):
        nonlocal case_id
        value={'case_id':case_id,'name':name,'domain':domain,'original':original,'operations':operations};case_id+=1
        return value
    for original in ['', 'a', 'a\n', '\n', '\r', '\r\n', 'a\r\nb\nc\r', 'α\r\n中🙂\n\t\nlast']:
        total=len(original.splitlines()) if not original.endswith('\r') else None
        # Count exactly Rust LF/CRLF lines; Python's Unicode splitlines also
        # splits characters Rust keeps, so never use it for actual framing.
        lines=original.split('\n')
        if lines and lines[-1]=='':lines.pop()
        if not original:lines=[]
        n=len(lines)
        for content in ['\n','one','one\n','one\ntwo','one\ntwo\nthree','one\ntwo\nthree\nfour','\r\n\r\r\n\r','中🙂\n\x00\t','a\u2028b\u0085c']:
            for at in sorted({0,n//2,n}):
                yield row(f'insert-{n}-{at}-{case_id}',original,[(1,at,0,content)])
            if n:
                yield row(f'replace-all-{n}-{case_id}',original,[(2,1,n,content)])
                yield row(f'replace-one-{n}-{case_id}',original,[(2,max(1,n//2),max(1,n//2),content)])
        if n:
            yield row('delete-all',original,[(2,1,n,'')])
    original=''.join(f'original-{i}\n' for i in range(1,13))
    shapes=[[(2,2,4,'R\nS'),(1,7,0,'I\nJ\nK\nL')],
            [(1,4,0,'I'),(2,5,6,'R')],
            [(2,2,2,''),(1,2,0,'I')],
            [(1,2,0,'I'),(2,2,2,'')],
            [(1,0,0,'I\nJ'),(2,1,2,'R'),(2,8,10,'')],
            [(2,1,2,''),(2,3,4,''),(2,5,6,''),(1,11,0,'I')],
            [(2,3,3,'R\nS'),(2,7,8,'R'),(1,12,0,'I')],
            [(2,1,1,'R'),(2,12,12,'Z')]]
    for shape in shapes:
        for permutation in itertools.islice(itertools.permutations(shape),6):
            for ending in ['\n','\r\n']:
                yield row('ordered-regions-'+str(case_id),original.replace('\n',ending),list(permutation))
    randomizer=random.Random(0xBADD1FF)
    for ordinal in range(450):
        n=randomizer.randrange(1,90)
        ending=randomizer.choice(['\n','\r\n'])
        original=ending.join(f'old-{ordinal}-{i}-'+randomizer.choice(['α','中','🙂',' ','\r','\t','\x00']) for i in range(n))
        if randomizer.randrange(2):original+=ending
        anchors=sorted(randomizer.sample(range(n+1),randomizer.randrange(1,min(12,n+1)+1)))
        operations=[]
        for at in anchors:
            count=randomizer.randrange(1,9)
            content='\n'.join(f'new-{ordinal}-{at}-{i}-'+randomizer.choice(['α','中','🙂','\r','\r\r','\x00']) for i in range(count))
            if randomizer.randrange(2):content+='\n'
            operations.append((1,at,0,content))
        randomizer.shuffle(operations)
        yield row('random-inserts-'+str(ordinal),original,operations)
    for count in [1,2,3,4,5,49,50]:
        original=''.join(f'old-{i}\n' for i in range(count*3+5))
        operations=[(2,i*3+1,i*3+2,'' if i%3==0 else '\n'.join(f'new-{i}-{j}' for j in range(i%7+1))) for i in range(count)]
        yield row('operation-count-'+str(count),original,list(reversed(operations)))
    # Complete output exceeds the view-specific 8 MiB gate. Batch edit has no
    # such gate; the complete original Rust body remains the only expectation.
    long_line='x'*(2*1024*1024+33)
    yield row('result-over8mib','\n'.join([long_line]*5)+'\n',[(2,3,3,'replacement')])
    yield row('incoming-over8mib','a\nb\nc\n',[(2,2,2,'Z'*(8*1024*1024+123))])
    yield row('dense-line-index','\n'*(1024*1024),[(2,524288,524288,'middle')])
    # Retain true original errors separately; these rows never become native
    # diff comparisons because the original apply stage did not succeed.
    yield row('original-overlap-error','a\nb\nc\n',[(2,1,2,'x'),(2,2,3,'y')],'original-rejection')
    yield row('original-duplicate-error','a\nb\nc\n',[(1,1,0,'b')],'original-rejection')


def write_input(stream):
    stream.write(b'HBDIQ001');count=0
    for row in iter_cases():
        raw=encode(row);stream.write(struct.pack('<Q',len(raw)));stream.write(raw);count+=1
    return count



def private_frames(wire):
    for size in [0,1,63]:yield 'short-output-'+str(size),wire,size,2048,0xfffffffe
    for size in [0,7,63,111]:yield 'short-input-'+str(size),wire[:size],256,2048,0xffffffff
    for at,value in [(0,0),(8,1),(16,(1<<64)-1),(24,(1<<64)-1),(32,0),(40,1),(48,1),(56,1)]:
        raw=bytearray(wire);struct.pack_into('<Q',raw,at,value);yield 'outer-'+str(at),bytes(raw),256,2048,0xffffffff
    p=64+struct.unpack_from('<Q',wire,16)[0]+struct.unpack_from('<Q',wire,24)[0]
    for at,value in [(0,0),(8,1),(16,0),(16,51),(24,0),(32,1),(40,1),(48,1),(56,0),(64,2),(72,(1<<64)-1),(80,1),(88,(1<<64)-1)]:
        raw=bytearray(wire);struct.pack_into('<Q',raw,p+at,value);yield 'plan-'+str(at)+'-'+str(value),bytes(raw),256,2048,0xffffffff
    yield 'extra-tail',wire+b'x',256,2048,0xffffffff
    for name,old,new,content in [('old',b'a',b'b',b'c'),('new',b'a',b'b',b'c'),('content',b'a',b'b',b'c')]:
        for bad in [b'\xff',b'\xc0\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xe2\x82']:
            spans={'old':old,'new':new,'content':content};spans[name]=bad
            body=struct.pack('<6Q',0,2,2,1,1,len(spans['content']))+spans['content']
            plan=struct.pack('<8s5Q',b'HBPLR001',0,1,len(body),0,0)+body
            invalid=struct.pack('<8s7Q',b'HBDFQ002',0,len(spans['old']),len(spans['new']),len(plan),0,0,0)+spans['old']+spans['new']+plan
            yield 'invalid-utf8-'+name+'-'+bad.hex(),invalid,256,2048,0xffffffff


