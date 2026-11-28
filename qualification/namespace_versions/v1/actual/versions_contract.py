"""Inert complete private-frame readers; no native imports, mapping, or effect synthesis."""
import struct
from common import require
from protocol import require_semantic
FUNCTIONS=("inotify_init1","read","fstat","fcntl","inotify_add_watch","inotify_rm_watch","close","__errno_location",
    "openat","fdopendir","readdir","closedir","pthread_mutex_init","pthread_mutex_lock","pthread_mutex_unlock","pthread_mutex_destroy")
TABLE_ORDER=(0,1,2,3,4,5,6,7,8,9,6,10,11,7,None,12,13,14,15)
HIGH=1<<63
def q(b,at):require(0<=at<=len(b)-8,"complete scalar in retained bytes");return struct.unpack_from("<Q",b,at)[0]
def zero(b,a,z,message):require(b[a:z]==bytes(z-a),message)
def request(b):
    require(96<=len(b)<=4224 and b[:8]==b"HNVSQ001"and q(b,16)>0,"whole actual namespace request")
    cmd=q(b,8);kind=q(b,24);require(cmd in range(1,7)and kind==(1 if cmd in(1,6)else 2 if cmd==2 else 3),"source command kind")
    zero(b,48,80,"all request reserved words");require(q(b,88)==0 and q(b,80)==len(b)-96,"entire exact request payload")
    if cmd in(1,2,6):require(len(b)==96 and q(b,32)<=0x7fffffff and q(b,40)==0,"whole borrowed global directory")
    else:
        require(q(b,32)==0,"no set global FD")
        if cmd==3:
            n=q(b,40);require(len(b)==96+(16*n if n<=258 else 0),"entire original constructor slice")
            for i in range(min(n,258)if n<=258 else 0):
                require(q(b,96+16*i)<=0x7fffffff and q(b,104+16*i)>0,"every complete actual member capability")
        else:require(len(b)==96 and q(b,40)==0,"exact no-payload set request")
    return dict(cmd=cmd,generation=q(b,16),kind=kind,fd=q(b,32),count=q(b,40),
        members=[dict(fd=q(b,at),pointer=q(b,at+8))for at in range(96,len(b),16)])
def shared(b,kind=None):
    require(len(b)==64,"entire mutex-protected region")
    if b==bytes(64):return dict(kind=0,child=0,id=0,invalid=False,initialized=False)
    require(b[:8]==b"HNVGS001"and q(b,8)in(1,2,3)and q(b,32)in(0,1)and q(b,40)in(0,1),
        "complete actual shared source state")
    zero(b,48,64,"all shared reserved bytes")
    if kind is not None:require(q(b,8)==kind,"same actual mutex kind")
    if q(b,8)!=3:require(q(b,24)==q(b,32)==0,"globals have no composite ID or permanent-invalid flag")
    elif q(b,40):require(q(b,16)>0 and q(b,24)>=HIGH,"entire live immutable scope")
    return dict(kind=q(b,8),child=q(b,16),id=q(b,24),invalid=bool(q(b,32)),initialized=bool(q(b,40)))
def terminal(b):
    require(len(b)==128 and b[:8]==b"HNVSR001"and q(b,8)in range(6)and q(b,16)>0
        and q(b,24)in range(1,7),"whole exact terminal")
    require(q(b,72)==q(b,112)==q(b,120)==0,"all terminal reserved bytes")
    kind=q(b,8);v=dict(kind=kind if kind<4 else 0,family=q(b,40),code=q(b,48),
        version=[q(b,56),q(b,64)]if kind==1 else None,digest=b[80:112].hex()if kind==2 else None)
    require_semantic(v)
    if kind in(0,3,5):require(q(b,56)==q(b,64)==0 and b[80:112]==bytes(32),"all non-value terminal bytes")
    if kind==1:require(b[80:112]==bytes(32)and 0<q(b,64)<HIGH,"complete Watch token and digest tail")
    if kind==2:require(q(b,56)==q(b,64)==0,"fingerprint has no Watch token")
    if kind==4:require(q(b,24)==3 and q(b,56)>=HIGH and q(b,64)==0 and b[80:112]==bytes(32),"complete constructed set ID")
    if kind==5:require(q(b,24)==5,"complete final drop result")
    return v
def pending(b):
    require(len(b)in(128,192)and b[:8]==b"HNVSR001"and q(b,8)==6 and q(b,16)>0 and
        q(b,24)in range(1,7)and q(b,32)>0 and q(b,40)in range(1,9),"whole actual pending effect")
    zero(b,96,128,"all pending reserved bytes")
    op=q(b,40);require(q(b,80)==len(b)-128 and q(b,88)==len(b)and(len(b)==192)==(op==2),"complete source effect extent")
    a,bv,c,d=(q(b,x)for x in(48,56,64,72))
    if op in(1,2,7):require(a==bv==c==d==0,"no fabricated mechanical effect argument")
    if op==2:shared(b[128:192])
    if op==3:require(0<a<=258 and bv in(0,1)and c==d==0,"actual source Watcher creation arguments")
    if op==4:require(a>0 and bv in(2,3)and(c==d==0 if bv==3 else c<=0x7fffffff),"actual child command and borrow")
    if op==5:require(a>0 and bv==c==d==0,"actual exact child owner drop")
    if op==6:require(a<=0x7fffffff and bv==c==d==0,"actual fingerprint borrow")
    if op==8:require(a+1==bv and bv<HIGH and c==d==0,"source checked atomic proposal")
    return dict(op=op,sequence=q(b,32),args=[a,bv,c,d],generation=q(b,16),cmd=q(b,24))
def ack(b,p):
    require(96<=len(b)<=65760 and b[:8]==b"HNVSAK01"and q(b,8)==p["generation"]and q(b,16)==p["sequence"]
        and q(b,24)==p["op"]and q(b,40)==q(b,80)==q(b,88)==0 and q(b,64)==len(b)-96 and q(b,72)==len(b),
        "whole actual response continuation")
    op=p["op"];require(q(b,32)in(0,1)if op==1 else q(b,32)==0,"actual mutex poison versus completed mechanical operation")
    if op==1:require(len(b)==160 and q(b,48)==q(b,56)==0,"complete lock copy");shared(b[96:160])
    elif op in(3,4,5):
        require(len(b)==65760 and b[96:104]==b"HNWR0001"and q(b,104)in(0,1)and q(b,112)==q(b,56)
            and b[224:232]==b"HNWST001","whole real child terminal and complete owner workspace")
        if op!=3 or q(b,104)==0:require(q(b,48)>0,"live actual child capability")
        else:require(q(b,48)==0,"failed new child disposed before original None")
    elif op==6:require(len(b)==224 and q(b,48)==q(b,56)==0 and b[96:104]==b"HNFRS001","complete fingerprint child frame")
    else:
        require(len(b)==96,"complete scalar mechanical response")
        if op==2:require(q(b,48)==q(b,56)==0,"actual mutex unlock no value")
        if op==7:require(q(b,56)==0,"actual atomic load no status alias")
        if op==8:require(q(b,56)in(0,1)and(q(b,48)==p["args"][0])==(q(b,56)==1),"actual strong CAS old-value success witness")
def workspace(b):
    require(len(b)==8192,"whole private namespace workspace")
    if b==bytes(8192):return
    require(b[:8]==b"HNVSW001"and q(b,8)in(0,1)and q(b,16)>0 and q(b,24)in range(1,7)
        and q(b,32)in(1,2,3)and q(b,88)in(0,1)and q(b,128)in(0,1)and q(b,136)in range(6)
        and q(b,144)in(0,1,2)and q(b,224)in(0,1,2),"all typed namespace private state")
    for a,z in((96,128),(232,512),(576,2048),(6176,8192)):zero(b,a,z,"whole namespace workspace reserved range")
    shared(b[512:576])
def environment(b,pid,pointers):
    require(len(b)in(4096,4112)and b[:8]==b"HNVENV01"and q(b,8)==pid and q(b,16)==1,
        "actual process-global environment custody")
    require(b[64:128]==struct.pack("<8Q",*pointers[:8])and
        b[128:184]==struct.pack("<7Q",pointers[8],pointers[9],pointers[6],pointers[10],pointers[11],pointers[7],0)
        and b[184:216]==struct.pack("<4Q",*pointers[12:]),"all exact actual libc and mutex table pointers")
    zero(b,32,64,"whole native environment reserved prefix");zero(b,232,256,"whole native environment reserved middle")
    zero(b,768,4096,"whole process environment unused tail")
    if len(b)==4112:require(b[4096:]==b"\x5a"*16,"entire actual environment guard")
def object_state(b,ptr,environment_pointer,pid):
    require(len(b)in(256,4096)and b[:8]==b"HNVOBJ01"and q(b,8)==environment_pointer and q(b,16)==pid
        and q(b,24)in(1,2,3)and q(b,32)==1 and q(b,40)in(0,1),"complete actual mutex object custody")
    require((len(b)==4096)==(q(b,24)==3)and q(b,184)==q(b,192)==0,"actual kind extent and no quarantined transport")
    zero(b,168,176,"whole mutex-object alignment");zero(b,200,len(b),"whole object unused tail")
    s=shared(b[64:128],q(b,24))
    return s
def file_pin(b,pointers):
    require(len(b)==4096 and b[:8]==b"HNWFP001"and 0<q(b,8)<HIGH and q(b,16)<=0x7fffffff and q(b,24)==4096
        and q(b,32)==pointers[6]and q(b,40)==pointers[7],"whole live real File reference page")
    zero(b,48,4096,"entire actual File page unused bytes")
def watcher(b,pointers):
    require(len(b)==131072 and b[:8]==b"HNWCTX01"and q(b,8)in(0,1)and q(b,152)==0,
        "whole qualified Watcher context without transport poison")
    require(b[256:320]==struct.pack("<8Q",*pointers[:8])and q(b,104)<=259,"actual child libc table and native pin ledger")
    for a,z in((160,256),(320,512),(4656,6144),(6288,6400),(6464,6528),(6592,8192),(24848,24960),(25088,32768),(98320,98336),(114720,131072)):
        zero(b,a,z,"whole Watcher context unused range")
    w=b[32768:98304]
    if w!=bytes(65536):
        require(w[:8]==b"HNWST001"and q(w,8)in(0,1)and q(w,56)<=258 and q(w,64)in(0,1)and q(w,88)<=258,
            "whole typed qualified Watcher owner state")
        require(b[98304:98320]==b"\x5a"*16 and b[24832:24848]==b"\xa5"*16,"whole actual child workspace/output guards")
def fingerprint(b,pointers):
    require(len(b)==32768 and b[:8]==b"HNFCTX01"and q(b,8)in(0,1),"whole qualified fingerprint context")
    require(b[64:112]==struct.pack("<6Q",pointers[8],pointers[9],pointers[6],pointers[10],pointers[11],pointers[7]),"actual fallback libc capabilities")
    zero(b,192,256,"whole fingerprint reserved header")
    zero(b,4992,8192,"whole fingerprint context middle gap");zero(b,24592,32768,"whole fingerprint unused final range")
