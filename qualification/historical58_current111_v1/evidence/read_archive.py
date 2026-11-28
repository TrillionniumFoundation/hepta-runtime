"""Read every retained ZIP/TAR byte and materialize the declared source proof."""
# Copyright 2026 Muvon Un Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, tarfile, zipfile
ROOT=Path('/tmp/hia-historical58-current111-proof-6780-v1')

def pin(raw):
    return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest(),
            'git_blob':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest()}

def safe(name):
    p=PurePosixPath(name);assert not p.is_absolute() and '..' not in p.parts and p.as_posix()==name
    return p

def main():
    archive=ROOT/'artifact.zip';raw=archive.read_bytes()
    assert len(raw)==95028687 and hashlib.sha256(raw).hexdigest()=='2a1084d5c138ee9bbccc9de04cb0d73ab6456d5622eb6bc7048ca7a04190f514'
    out=ROOT/'extracted';assert not out.exists();out.mkdir()
    zips=[];payloads={}
    with zipfile.ZipFile(archive) as z:
        for item in z.infolist():
            assert not item.is_dir();safe(item.filename)
            data=z.read(item);assert len(data)==item.file_size
            zips.append({'path':item.filename,'crc':item.CRC,**pin(data)})
            assert item.filename not in payloads;payloads[item.filename]=data
    index_name=[name for name in payloads if name.endswith('/ARCHIVE.json') or name=='ARCHIVE.json'];assert len(index_name)==1
    manifest=json.loads(payloads[index_name[0]])
    tar_name=[name for name in payloads if name.endswith('/source-proof.tar.gz') or name=='source-proof.tar.gz'];assert len(tar_name)==1
    compressed=payloads[tar_name[0]];assert pin(compressed)==manifest['archive']
    expected={r['path']:r for r in manifest['files']};assert len(expected)==len(manifest['files'])
    rows=[]
    with tarfile.open(fileobj=io.BytesIO(compressed),mode='r:gz') as tar:
        for item in tar:
            assert item.isfile() and item.name in expected
            safe(item.name);data=tar.extractfile(item).read();row={'path':item.name,'mode':item.mode,**pin(data)}
            assert row==expected[item.name],item.name
            path=out/item.name;assert not path.exists();path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(data);path.chmod(item.mode);os.utime(path,(item.mtime,item.mtime))
            assert path.read_bytes()==data;rows.append(row)
    assert rows==manifest['files']
    (ROOT/'ARCHIVE.json').write_bytes(payloads[index_name[0]])
    (ROOT/'ZIP_MEMBERS.json').write_text(json.dumps(zips,sort_keys=True,indent=2)+'\n')
    result={'status':'COMPLETE_ZIP_AND_TAR_BYTES_MODES_PASS','run':43999490713,'artifact_id':14291282784,
            'zip':pin(raw),'zip_members':len(zips),'tar_members':len(rows),
            'logical_bytes':sum(r['bytes'] for r in rows),'all_member_files_equal':True,
            'native_or_rust_executed':False,'source_commit':'208ff61db1da78aadfeb8d7913af7ddf4b59d461'}
    (ROOT/'READBACK.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(json.dumps(result,sort_keys=True))

if __name__=='__main__':main()
