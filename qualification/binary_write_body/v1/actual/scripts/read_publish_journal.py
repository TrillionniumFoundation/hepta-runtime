"""Read all five HIA-image boundaries and actual fixed effects; never execute."""
import gzip,hashlib,struct
from evidence_common import pin,require
from publish_protocol import U,I,result,stat_decode,version
import read_metadata_journal as metadata
class Journal:
    def __init__(self,path):
        self.path=path;self.stream=gzip.open(path,"rb");self.digest=hashlib.sha256();self.head=None
        self.position=0;self.events=0;self.full_buffer_bytes=0;self.calls=0;self.children=0;self.effects=0;self.formatters=0
        self.owner_counts={k:dict(calls=0,children=0,effects=0)for k in("publish","metadata")}
    def peek(self):
        if self.head is None:self.head=self.stream.read(8)
        return self.head
    def raw_take(self,magic,header_size=128):
        head=self.peek();self.head=None;require(head==magic,"mixed full journal owner/order")
        header=head+self.stream.read(header_size-8);require(len(header)==header_size,"short mixed header")
        h=struct.unpack("<"+str(header_size//8)+"Q",header);size=h[4]if header_size==128 else h[2]
        require(size<=256<<20,"mixed journal span cap");raw=self.stream.read(size);require(len(raw)==size,"short mixed complete span")
        self.digest.update(header);self.digest.update(raw);self.position+=header_size+size;self.events+=1;self.full_buffer_bytes+=size
        return h,raw
    def take(self,event,generation,call):
        return self.view("publish").take(event,generation,call)
    def view(self,owner):return View(self,owner)
    def finish(self,receipt):
        require(self.peek()==b"","unread complete mixed journal suffix");self.stream.close()
        require(dict(bytes=self.position,sha256=self.digest.hexdigest())==receipt["raw"]and pin(self.path)==receipt["compressed"]
            and receipt["complete_raw_bytes_in_gzip"]is True and receipt["no_expanded_ordinary_copy_created"]is True,"full journal custody")
        return dict(events=self.events,full_buffer_bytes=self.full_buffer_bytes,journal_bytes=self.position,
            owner_counts=self.owner_counts,formatter_calls=self.formatters)
class View:
    def __init__(self,parent,owner):
        self.parent=parent;self.owner=owner;self.calls=0;self.children=0;self.effects=0;self.pending=None;self.records=[]
    def take(self,event,generation,call):
        magic={"publish":b"HPUBJR01","metadata":b"HMDTJR01"}[self.owner]
        h,raw=self.parent.raw_take(magic)
        require(h[1]==event and h[2]==generation and h[3]==call and h[5]==1 and h[7]==0,"mixed event/generation/call/state")
        require(h[8]>=4096 and h[9]>=4096 and h[8]%4096==h[9]%4096==0,"actual guarded arena capacities")
        if event==8:self.pending=raw
        if event==9 and self.pending is not None:
            request=self.pending;self.pending=None;op=U(request,24);ret=I(U(raw,24));data=raw[96:]
            self.records.append(dict(operation=op,fd=U(request,32),a=U(request,40),b=U(request,48),
                request=request[64:].hex(),raw_return=ret,payload=data.hex()if op in(1,2,3,5,6,9,11,19)else None,
                returned_bytes=len(data),returned_sha256=hashlib.sha256(data).hexdigest()))
        return h,raw
    def commit(self):
        row=self.parent.owner_counts[self.owner]
        for k in("calls","children","effects"):row[k]+=getattr(self,k)
def selected_hooks(hooks,owner,generation=None):
    return [h for h in hooks if h["owner"]==owner and(generation is None or h["generation"]==generation)]
def invocation(journal,start,terminal,generation,parent,hooks,previous_work=None):
    view=journal.view("publish");incoming=bytearray(start);struct.pack_into("<Q",incoming,32,parent);incoming=bytes(incoming)
    last_work=previous_work;owned=set();call=0;effects=[];children=[];order=[];orphan_transfers=[]
    publish_hooks=selected_hooks(hooks,"publish");hook_at=0;meta_work=None;meta_gen=0;last_stat=None
    while True:
        call+=1;view.calls+=1;count=len(owned)
        h,raw=view.take(1,generation,call);require(raw==incoming and h[11]==len(incoming)and h[10]==count,"outer complete input/binding")
        hb,wb=view.take(10,generation,call);ho,ob=view.take(12,generation,call)
        require(len(wb)==hb[8]and hb[10]==count and(last_work is None or wb==last_work)
            and len(ob)==ho[9]and ob==b"\xa5"*len(ob),"outer complete initial arenas")
        if call==1:require(wb==bytes(len(wb)),"fresh outer workspace")
        ha,oa=view.take(2,generation,call);hw,wa=view.take(11,generation,call)
        require(ha[6]==hw[6]==64 and len(oa)==ha[9]==len(ob)and len(wa)==hw[8]==len(wb)
            and ha[10]==hw[10]==count,"outer actual HIA return/full arenas")
        require(oa[:8]==b"HPUBR001"and U(oa,8)in range(6),"outer result ABI")
        extent=64+U(oa,56);require(extent<=len(oa)and oa[extent:]==ob[extent:],"outer complete output suffix")
        frame=oa[:extent];kind=U(frame,8);last_work=wa
        if kind in(0,3):
            require(not owned and (terminal is None or frame==terminal) and hook_at==len(publish_hooks),"terminal ownership/frame/hooks")
            result(frame);view.commit()
            return dict(workspace=wa,output=oa,body_calls=call,effects=effects,children=children,
                order=order,orphans=orphan_transfers,metadata_generation=meta_gen)
        if kind in(4,5):
            require(all(U(frame,p)==0 for p in(16,24,40,48,56)),"outer growth words")
            need=U(frame,32);old=len(wb)if kind==4 else len(ob)
            require(old<need<=(256<<20 if kind==4 else 128<<20),"outer growth extent")
            if kind==4:
                _,before=view.take(3,generation,call);hg,after=view.take(4,generation,call)
                require(before==wa==wb and len(after)==hg[8]==((need+4095)&~4095)
                    and after[:len(before)]==before and after[len(before):]==bytes(len(after)-len(before)),"outer full relocated work")
                last_work=after
            continue
        seq,op,a,b,c=(U(frame,p)for p in(16,24,32,40,48));payload=frame[64:]
        require(seq>0,"outer positive action sequence")
        if kind==1:
            he,request=view.take(8,generation,call);view.effects+=1
            require(request==frame and he[12:14]==(seq,op)and he[10]==count and op in range(1,11),"outer fixed capability request")
            require(hook_at<len(publish_hooks),"missing outer effect hook");hook=publish_hooks[hook_at];hook_at+=1
            require(hook["raw_bytes"]==b"HPUBHK01"+struct.pack("<7Q",generation,call,seq,op,a,b,c)
                and hook["ack_bytes"]==bytes(8),"actual outer hook/ACK")
            hr,resume=view.take(9,generation,call);ret=I(U(resume,24));data=resume[96:];before=sorted(owned)
            if op in(1,6):
                require(a==parent and b==c==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1]
                    and not data,"fixed borrowed-parent openat")
                if ret>=0:
                    require(ret<=2147483647 and ret!=parent and ret not in owned,"actual fresh owned Linux file token");owned.add(ret)
            elif op in(2,3,4):
                require(a in owned and b==c==0 and not payload,"actual owned file token")
                if op==2:
                    require(ret<=0 and len(data)==(144 if ret==0 else 0),"outer complete fstat")
                    if ret==0:
                        require(hook["after"]["ok"]and stat_decode(data)==hook["after"]["stat"],"outer stat vs real held FD")
                        last_stat=data
                elif op==3:
                    require(ret<=0 and not data,"outer close complete return");owned.remove(a)
                else:
                    require(ret==0 and not data,"actual process-orphan append ACK")
                    orphan_transfers.append(dict(fd=a,generation=generation,call=call,sequence=seq));owned.remove(a)
            elif op==5:
                require(a==b==c==0 and not payload and not data and 0<=ret<=4294967295,"actual geteuid scalar")
            elif op==7:
                require((a in owned or a==parent)and b==c==0 and not payload and ret<=0 and not data,"fixed owned or borrowed-parent fsync")
            elif op in(8,10):
                require(a==parent and b>0 and c>0 and len(payload)==b+c and payload[b-1]==payload[-1]==0
                    and b"\0"not in payload[:b-1]and b"\0"not in payload[b:-1]and ret<=0 and not data,
                    "fixed destination/temporary dual-path publication")
            else:
                require(op==9 and a==parent and b==c==0 and payload.endswith(b"\0")and b"\0"not in payload[:-1]
                    and ret<=0 and not data,"fixed borrowed-parent unlinkat")
            require(hr[10]==len(owned),"outer actual native owned count")
            effects.append(dict(operation=op,fd=a,b=b,c=c,phase=U(wa,8),regular_role=U(wa,128),sequence=seq,call=call,raw_return=ret,
                payload=payload.hex(),actual=data.hex(),before_owned=before,after_owned=sorted(owned),hook=hook))
            order.append(dict(kind="effect",index=len(effects)-1))
        else:
            require(kind==2 and op in(1,2)and c==0,"outer fixed HIA child")
            _,request=view.take(5,generation,call);require(request==payload,"complete child input")
            if op==1:
                require(a==b==0 and len(payload)==72 and payload[:8]==b"HSTVER01"and U(payload,8)==1
                    and last_stat is not None,"version child input")
                expected_packet=b"HSTVER01"+struct.pack("<Q",1)+b"".join(last_stat[p:p+8]for p in(0,8,48,88,96,104,112))
                require(payload==expected_packet,"version child binds immediately preceding actual fstat")
                _,cb=view.take(13,generation,call);_,cw=view.take(14,generation,call)
                hc,ca=view.take(6,generation,call);_,cwa=view.take(7,generation,call);view.children+=1
                require(cb==b"\xa5"*128 and len(ca)==128 and cw==bytes(256)and len(cwa)==256
                    and hc[14]==hc[15]<=128 and ca[hc[14]:]==cb[hc[14]:],"full stat image buffers")
                child=ca[:hc[14]];require(child==version(stat_decode(last_stat)).encode(),"actual version text")
            else:
                require(a in owned and b in owned and a!=b and payload[:8]==b"HMDTQ001"and U(payload,24)==3
                    and U(payload,32)==U(payload,40)==0,"metadata source/temporary borrowed owned tokens")
                meta_gen+=1;view_child=journal.view("metadata");files={"source":{"fd":a},"target":{"fd":b}}
                child_hooks=[]
                for hook in selected_hooks(hooks,"metadata",meta_gen):
                    require(hook["fd"]in(a,b),"metadata hook belongs to held file")
                    child_hooks.append(dict(hook,role="source"if hook["fd"]==a else"target"))
                row=metadata.invocation(view_child,payload,None,meta_gen,files,child_hooks,previous_work=meta_work)
                meta_work=row["workspace"];view_child.commit();child=row["frame"]
                he,returned=view.take(6,generation,call);_,child_context=view.take(15,generation,call)
                require(returned==child and len(child_context)==4096 and U(child_context,56)==2
                    and U(child_context,168)==len(child)and U(child_context,184)==0
                    and all(U(child_context,p)==0 for p in(344,352)),"complete actual child loan/context")
                require(child_context[:8]==b"HMDTCI01"and U(child_context,192)==meta_gen,"qualified metadata identity/generation")
                children.append(dict(operation=op,mode=3,frame=child.hex(),calls=row["body_calls"],generation=meta_gen,
                    files=files,effects=row["effects"],codec=row["codec"]))
                order.append(dict(kind="metadata",index=len(children)-1))
            hr,resume=view.take(9,generation,call)
            require(U(resume,24)==len(child)and resume[96:]==child and hr[10]==count,"complete copied child resume")
        require(resume[:8]==b"HPUBQ001"and U(resume,8)==2 and U(resume,16)==seq
            and all(U(resume,p)==0 for p in(32,40,48,56,64,72,80))and U(resume,88)==len(resume)-96
            and hr[12:14]==(seq,op)and hr[14]==U(resume,24)and hr[15]==len(resume)-96,"outer exact full resume")
        incoming=resume
def formatter(journal,packet,text):
    rows=[]
    for stage in range(1,6):
        h,raw=journal.raw_take(b"HPUBER01",64)
        require(h[1]==stage and h[6]==h[7]==0,"full actual formatter header")
        rows.append((h,raw))
    require(rows[0][1]==packet and rows[1][1]==bytes(12288)and len(rows[2][1])>=6*len(packet)+1024
        and rows[2][1]==b"\xa5"*len(rows[2][1]),"complete formatter input/before buffers")
    h,after=rows[3];_,work=rows[4]
    require(h[3]==len(text)and h[4]==len(after)==len(rows[2][1])and h[5]==len(work)==12288
        and after[:len(text)]==text and after[len(text):]==rows[2][1][len(text):],"complete formatter actual return/tail")
    journal.formatters+=1
