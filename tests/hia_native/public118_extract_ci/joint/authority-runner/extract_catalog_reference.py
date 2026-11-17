"""Select an already qualified original get_info observation by complete byte identity."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,tarfile,zipfile
SHA=lambda raw:hashlib.sha256(raw).hexdigest()
ZIP_BYTES=95269620
ZIP_SHA="32e325c73e8a47ee14683ff96dec87bf505c1e7ce2fff56af509aacc1b51e6a5"
PROFILE_BYTES=1236951
PROFILE_SHA="c9ff4c9282e406de911119c2287093165d3829c333be43da06ac14f75edf295d"
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("archive","output"):p.add_argument("--"+name,type=Path,required=True)
    a=p.parse_args();archive=a.archive.resolve(strict=True);out=a.output.absolute()
    assert archive.stat().st_size==ZIP_BYTES
    with archive.open("rb") as f:assert hashlib.file_digest(f,"sha256").hexdigest()==ZIP_SHA
    assert not out.exists();out.mkdir(parents=True)
    selected=[]
    with zipfile.ZipFile(archive) as zipped:
        tars=[name for name in zipped.namelist() if name.endswith(".tar.gz")];assert len(tars)==1
        with zipped.open(tars[0]) as compressed,tarfile.open(fileobj=compressed,mode="r|gz") as tar:
            for item in tar:
                path=PurePosixPath(item.name);assert not path.is_absolute() and ".." not in path.parts
                if not item.isfile() or not item.name.startswith("processes/") or not item.name.endswith(".stdout") or item.size!=PROFILE_BYTES:continue
                raw=tar.extractfile(item).read()
                if SHA(raw)==PROFILE_SHA:selected.append((item.name,raw))
    assert len(selected)==1
    name,raw=selected[0];doc=json.loads(raw)
    wire=doc["get_info_wire"].encode()
    assert SHA(wire)=="6d005e04c53f0a4ef515d4f61ea95e564cbe841a51b7752fe312fc4af86cbf41"
    (out/"current-get-info-original.stdout").write_bytes(raw)
    receipt=dict(schema="hepta.retained-current-get-info-reference.v1",status="EXACT_QUALIFIED_PROFILE_RECOVERED",
        original_run=43796801388,original_artifact=14194828118,
        original_commit="c5b484f9f7702794392bd01bebd4b87a6d0e3393",zip_bytes=ZIP_BYTES,zip_sha256=ZIP_SHA,
        zip_member=tars[0],tar_member=name,profile_bytes=len(raw),profile_sha256=SHA(raw),
        current_get_info_wire_sha256=SHA(wire),used_as_implementation=False,new_original_executed=False)
    (out/"RECEIPT.json").write_text(json.dumps(receipt,sort_keys=True,indent=2)+"\n")
    print(json.dumps(receipt,sort_keys=True))
if __name__=="__main__":main()
