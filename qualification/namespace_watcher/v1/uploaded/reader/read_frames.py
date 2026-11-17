"""Read every original full-buffer record, its complete index and gzip footer."""
import gzip,struct
from reader_common import loads,pin,read,require,word
from evidence_codec import encoded
def take(stream,size):
    require(type(size)is int and 0<=size<=1<<20,"bounded physical record extent")
    out=bytearray()
    while len(out)<size:
        part=stream.read(size-len(out));require(part,"no truncated physical capture");out+=part
    return bytes(out)
def frames(folder):
    rows=loads(read(folder/"RECORDS.json"))
    require(type(rows)is list and rows,"entire ordered physical native index")
    offset=8
    with (folder/"complete-native-buffers.bin.gz").open("rb")as physical:
        with gzip.GzipFile(fileobj=physical,mode="rb")as stream:
            require(take(stream,8)==b"HNWLOG01","actual physical native stream header")
            for index,row in enumerate(rows):
                require(set(row)=={"index","kind","offset","case","step","operation","meta","buffers"}and
                    row["index"]==index and type(row["index"])is int and row["offset"]==offset,
                    "complete sequential physical index and exact keys")
                size=word(take(stream,8),0);header=take(stream,size)
                require(header==encoded(row)and loads(header)==row,"full physical header equals retained index")
                offset+=8+size;raws=[]
                require(type(row["buffers"])is list and len(row["buffers"])<=1024,"all bounded real context/pin buffers")
                for item in row["buffers"]:
                    require(set(item)=={"bytes","sha256"}and type(item["bytes"])is int and 0<=item["bytes"]<=1<<20,
                        "whole buffer identity and exact extent")
                    raw=take(stream,item["bytes"]);require(pin(raw)==item,"all complete before/after bytes")
                    offset+=len(raw);raws.append(raw)
                yield row,raws
            require(take(stream,16)==b"HNWEND01"+struct.pack("<Q",len(rows))and stream.read(1)==b"",
                "complete capture count, gzip integrity/footer, and no unclaimed suffix")
