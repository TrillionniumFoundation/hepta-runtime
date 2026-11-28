"""Stream every lossless native object and record, retaining compressed in-memory ownership."""
import gzip,hashlib,struct,zlib
from common import read,loads,pin,require
def walk(folder,consume):
    expected_rows=loads(read(folder/"RECORDS.json"));expected_objects=loads(read(folder/"OBJECTS.json"))
    require(loads(read(folder/"OBSERVER-ERRORS.json"))==[],"no observer failure can count as actual evidence")
    objects={};actual={};used=set();count=0;logical=0;position=8
    with gzip.open(folder/"complete-native-buffers.bin.gz","rb")as stream:
        def take(n):
            raw=stream.read(n);require(len(raw)==n,"complete untruncated native memory stream");return raw
        require(take(8)==b"HNVLOG02","complete native object-stream header")
        while True:
            start=position;tag=take(8);position+=8
            if tag==b"NVOBJ001":
                length=struct.unpack("<Q",take(8))[0];digest=take(32).hex();position+=40
                require(0<=length<=1<<20 and digest not in objects,"bounded unique whole physical object")
                raw=take(length);position+=length;row=pin(raw)
                require(row["sha256"]==digest,"all raw native object bytes independently hashed")
                actual[digest]=dict(**row,offset=start);objects[digest]=zlib.compress(raw,1)
            elif tag==b"NVREC001":
                length=struct.unpack("<Q",take(8))[0];position+=8
                require(0<length<=1<<20,"bounded whole native observation record")
                raw=take(length);position+=length;row=loads(raw)
                require(count<len(expected_rows)and row==expected_rows[count]and row["index"]==count and row["offset"]==start,
                    "every complete native record index, offset and metadata")
                values=[]
                for ref in row["buffers"]:
                    digest=ref["sha256"];require(digest in objects and ref=={k:actual[digest][k]for k in("bytes","sha256")},
                        "every complete logical native buffer belongs to its actual object")
                    value=zlib.decompress(objects[digest]);require(len(value)==ref["bytes"],"complete reconstructed logical buffer")
                    values.append(value);logical+=len(value);used.add(digest)
                consume(row,values);count+=1
            elif tag==b"NVEND001":
                footer=struct.unpack("<3Q",take(24));position+=24
                require(footer==(count,len(objects),logical)and not stream.read(1),"whole complete native stream footer and EOF")
                break
            else:raise ValueError("unlisted actual native stream record")
    require(count==len(expected_rows)and actual==expected_objects and used==set(objects),"no omitted record or unreferenced physical object")
    return dict(records=count,objects=len(objects),logical_bytes=logical,uncompressed_stream_bytes=position,
        complete_object_bytes=sum(r["bytes"]for r in actual.values()),complete_archive=pin(read(folder/"complete-native-buffers.bin.gz")))
