"""Read the entire retained original ELF and exact local-static/type bytes; no execution."""
import struct
from common import require,pin
def symbols(raw):
    require(len(raw)>=64 and raw[:7]==b"\x7fELF\x02\x01\x01","complete actual ELF64")
    def integer(at,size):require(0<=at<=len(raw)-size,"ELF scalar bounds");return int.from_bytes(raw[at:at+size],"little")
    def span(at,size):require(0<=at<=len(raw)-size,"complete ELF range");return raw[at:at+size]
    require(integer(16,2)in(2,3)and integer(18,2)==62,"actual x86-64 ELF")
    off=integer(40,8);size=integer(58,2);count=integer(60,2);require(size==64 and count>0,"complete ELF sections")
    headers=[span(off+i*64,64)for i in range(count)]
    def word(h,at,n=8):return int.from_bytes(h[at:at+n],"little")
    rows={}
    for h in headers:
        if word(h,4,4)!=2:continue
        body=span(word(h,24),word(h,32));require(word(h,56)==24 and len(body)%24==0,"whole ELF symbols")
        si=word(h,40,4);require(si<len(headers)and word(headers[si],4,4)==3,"actual symbol strings")
        strings=span(word(headers[si],24),word(headers[si],32))
        for at in range(0,len(body),24):
            b=body[at:at+24];section=word(b,6,2)
            if b[4]&15!=1 or section==0:continue
            no=word(b,0,4);require(no<len(strings),"actual symbol name range")
            tail=strings[no:];end=tail.find(b"\0");require(end>=0,"complete symbol name");name=tail[:end].decode()
            key=("ordinary"if"watched_version"in name and"WATCHER"in name else
                "content"if"content_version"in name and"CONTENT"in name else
                "next"if"ContentWatchSet"in name and"new"in name and"NEXT"in name else
                "types"if name=="NAMESPACE_VERSIONS_FIXTURE_TYPES"else None)
            if key is None:continue
            require(key not in rows and section<len(headers),"unique actual target static")
            value=word(b,8);length=word(b,16);sh=headers[section];require(length>0,"nonempty static")
            relative=value-word(sh,16);require(0<=relative<=word(sh,32)-length,"entire static lies in actual section")
            zero=word(sh,4,4)==8
            data=bytes(length)if zero else span(word(sh,24)+relative,length)
            rows[key]=dict(name=name,elf_value=value,bytes=length,section=section,section_type=word(sh,4,4),
                initial_hex=data.hex(),initial=pin(data))
    require(set(rows)=={"ordinary","content","next","types"},"all actual original statics and exact compiled types")
    typebytes=bytes.fromhex(rows["types"]["initial_hex"]);require(len(typebytes)==64,"all compiled Rust type words")
    sizes=list(struct.unpack("<8Q",typebytes));require(all(x>0 for x in sizes),"actual nonzero type layouts")
    for key in("ordinary","content"):
        require(rows[key]["bytes"]==sizes[0]and rows[key]["elf_value"]%sizes[1]==0 and
            len(bytes.fromhex(rows[key]["initial_hex"]))==sizes[0],"complete actual source-defined OnceLock storage and compiled alignment")
    require(rows["next"]["bytes"]==sizes[2]==8 and sizes[3]==8
        and bytes.fromhex(rows["next"]["initial_hex"])==struct.pack("<Q",1),"actual original AtomicU64 NEXT begins at one")
    return dict(schema="hepta.namespace-versions.original-elf-bindings.v1",binary=pin(raw),symbols=rows,type_words=sizes,
        original_application_calls=0,native_application_calls=0,
        initial_storage_policy="exact ELF bytes; OnceLock value availability is verified by original typed get during the first actual process")
