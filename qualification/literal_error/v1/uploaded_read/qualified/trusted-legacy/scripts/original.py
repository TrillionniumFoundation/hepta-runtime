#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Actual CPython diagnostic reference; never imports the HIA loader."""
from pathlib import Path
import argparse,builtins,gzip,hashlib,json,locale,os,struct,sys,unicodedata
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from common import canonical,require,source_evidence,pin,sha
import cases
def main():
    p=argparse.ArgumentParser();p.add_argument("--group",required=True);p.add_argument("--output",type=Path,required=True)
    a=p.parse_args();frozen=source_evidence(ROOT)
    require(not a.output.exists(),"fresh original group");a.output.mkdir(parents=True)
    require(unicodedata.unidata_version=="15.0.0"and locale.setlocale(locale.LC_MESSAGES)=="C","reference platform changed")
    records=[];offset=0;whole=hashlib.sha256()
    with(a.output/"records.bin.gz").open("xb")as raw,gzip.GzipFile(filename="",mode="wb",fileobj=raw,compresslevel=1,mtime=0)as stream:
        for value in cases.cases(a.group):
            wire=cases.frame(value)
            try:
                if value["errno"]:
                    args=[value["errno"],os.strerror(value["errno"])]
                    if value.get("protocol")=="dual":
                        n=value["first_size"];args.extend([value["payload"][:n].decode("utf-8"),None,value["payload"][n:].decode("utf-8")])
                    elif value.get("filename_kind")==2:args.append(struct.unpack("<Q",value["payload"])[0])
                    elif value["named"]:args.append(value["payload"].decode("utf-8"))
                    error=OSError(*args)
                else:error=getattr(builtins,cases.CLASSES[value["kind"]-1])(value["payload"].decode("utf-8"))
            except Exception as constructor_error:
                error=constructor_error
            response=(type(error).__name__+": "+str(error)).encode("utf-8")
            header=struct.pack("<3Q",value["case_id"],len(wire),len(response))
            block=header+wire+response;stream.write(block);whole.update(block)
            records.append(dict(**cases.public_row(value),offset=offset,bytes=len(block),
                response_bytes=len(response),response_sha256=sha(response),record_sha256=sha(block),
                actual_exception_class=type(error).__name__))
            offset+=len(block)
    (a.output/"records.json").write_bytes(canonical(records))
    result=dict(status="PASS",schema="hepta.runtime.path-error.original.v1",group=a.group,cases=len(records),
        raw=dict(bytes=offset,sha256=whole.hexdigest()),compressed=pin(a.output/"records.bin.gz"),
        records=pin(a.output/"records.json"),source=frozen,pid=os.getpid(),python=sys.executable,
        environment=dict(python=sys.version,unicode_version=unicodedata.unidata_version,
            lc_messages=locale.setlocale(locale.LC_MESSAGES),platform=sys.platform),
        hia_executed=False,native_result_read=False)
    require(source_evidence(ROOT)==frozen,"source changed during original capture")
    (a.output/"CAPTURE.json").write_bytes(canonical(result));print(canonical(result).decode(),end="")
if __name__=="__main__":main()
