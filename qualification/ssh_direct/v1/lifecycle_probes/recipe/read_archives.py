#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Initial artifact-file read. Later uploaded-ZIP custody is a separate pure gate."""
from pathlib import Path
import argparse,os,sys,zipfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
from capture_util import canonical,decode,pin,need,unpack
from archive import verify
import read_capture
def main():
    p=argparse.ArgumentParser()
    for name in("source","native","original","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();need(os.environ.get("GITHUB_ACTIONS")=="true","CI-only pure gate")
    need(not a.output.exists(),"new original pure reading destination");a.output.mkdir(parents=True)
    sources={};roots={}
    for role,directory in(("native",a.native),("original",a.original)):
        need({p.name for p in directory.iterdir()}=={"ARCHIVE.json","FILES.json","evidence.tar.gz"},"whole downloaded artifact member set")
        index=decode((directory/"FILES.json").read_bytes());receipt=decode((directory/"ARCHIVE.json").read_bytes())
        need(verify(directory/"evidence.tar.gz",index)==receipt,"all captured archive bytes, directories and metadata")
        zpath=a.output/(role+".zip")
        with zipfile.ZipFile(zpath,"x",compression=zipfile.ZIP_STORED)as z:
            for name in("ARCHIVE.json","FILES.json","evidence.tar.gz"):z.write(directory/name,name)
        spec=dict(zip=pin(zpath),tar=receipt["archive"])
        roots[role]=unpack(zpath,a.output/role,spec);sources[role]=dict(reconstructed_downloaded_file_zip=spec,
            uploaded_zip_identity_pending=True,receipt=receipt)
    (a.output/"DOWNLOADED_INPUTS.json").write_bytes(canonical(sources))
    sys.argv=[str(Path(read_capture.__file__)), "--source",str(a.source),"--native",str(roots["native"]),"--original",str(roots["original"]),
        "--stage",str(a.output/"predecessors"),"--output",str(a.output/"comparison")]
    read_capture.main()
if __name__=="__main__":main()
