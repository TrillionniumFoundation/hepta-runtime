#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Static-ELF descriptor-read qualification using temporary fixtures only.

An owned-child seccomp supervisor injects deterministic syscall faults/races.
The production ELF is also exercised with an empty PATH. No MCP tool migration
is claimed and no host code computes native file results.
"""
from __future__ import annotations
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
COUNTS = {"elf_requests": 0, "original_read_comparisons": 0}

def request(path, *, identity=1, offset=0, limit=32768, version=None):
    raw = os.fsencode(path)
    values = [identity,1,offset,limit,int(version is not None),*(version or [0]*7),len(raw)]
    return b"HIARD001" + struct.pack("<13Q",*values) + raw

def wire(raw):
    return struct.pack("<Q",len(raw)) + raw

def decode(raw):
    if len(raw)<128 or raw[:8]!=b"HIARR001":
        raise AssertionError("native IO response header differs")
    words=struct.unpack_from("<15Q",raw,8)
    identity,status,error,size,offset,following,eof=words[:7]
    if len(raw)!=128+size:
        raise AssertionError("native IO response extent differs")
    if status and (size or any(raw[56:])):
        raise AssertionError("rejected IO response exposed file data or metadata")
    return dict(identity=identity,status=status,errno=error,offset=offset,next_offset=following,
                eof=bool(eof),version=words[7:14],mode=words[14],data=raw[128:])

def version(st):
    mt,mn=divmod(st.st_mtime_ns,1_000_000_000)
    ct,cn=divmod(st.st_ctime_ns,1_000_000_000)
    return (st.st_dev,st.st_ino,st.st_size,mt&((1<<64)-1),mn,ct&((1<<64)-1),cn)

class Session:
    def __init__(self,executable,root,*,trace=None,injection=None,fixture=None,close_ordinal=0,env=None):
        args=[str(executable),str(root)]
        if trace:
            args=[sys.executable,str(Path(__file__).with_name("io_fault_supervisor.py")),"--log",str(trace),
                  "--mode",injection,"--close-ordinal",str(close_ordinal),
                  *(["--fixture",str(fixture)] if fixture else []),"--",*args]
        self.process=subprocess.Popen(args,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,env=env)
    def exact(self,size):
        data=bytearray();deadline=time.monotonic()+8
        while len(data)<size:
            remaining=deadline-time.monotonic()
            if remaining<=0 or not select.select([self.process.stdout],[],[],remaining)[0]:
                raise AssertionError("native IO response timed out")
            chunk=os.read(self.process.stdout.fileno(),size-len(data))
            if not chunk:
                raise AssertionError("native IO exited before response: "+self.process.stderr.read().decode())
            data+=chunk
        return bytes(data)
    def send(self,packet,*,fragmented=False):
        raw=wire(packet)
        for at in range(0,len(raw),3 if fragmented else len(raw)):
            self.process.stdin.write(raw[at:at+(3 if fragmented else len(raw))]);self.process.stdin.flush()
    def receive(self):
        size=struct.unpack("<Q",self.exact(8))[0]
        if not 128<=size<=65664:raise AssertionError("native IO frame outside result profile")
        COUNTS["elf_requests"]+=1
        return decode(self.exact(size))
    def call(self,packet,**kwargs):
        self.send(packet,**kwargs);return self.receive()
    def close(self):
        if not self.process.stdin.closed:self.process.stdin.close()
        status=self.process.wait(timeout=8)
        extra=self.process.stdout.read();errors=self.process.stderr.read()
        self.process.stdout.close();self.process.stderr.close()
        if status or extra or errors:raise AssertionError((status,extra,errors))
    def __enter__(self):return self
    def __exit__(self,kind,*rest):
        if kind:
            self.process.kill();self.process.wait(timeout=5)
            for stream in [self.process.stdin,self.process.stdout,self.process.stderr]:stream.close()
        else:self.close()

def selected_manifest():
    if os.environ.get("HIA_IO_MANIFEST"):return Path(os.environ["HIA_IO_MANIFEST"]).resolve(strict=True)
    from hia_native_io_build import build_io
    return build_io(Path(os.environ["HIA_HEPTA_DIR"]),Path(os.environ["HIA_BUILD_ROOT"]))

class NativeIoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest_path=selected_manifest();cls.metadata=json.loads(cls.manifest_path.read_text())
        cls.executable=cls.manifest_path.parent/cls.metadata["executable"]
        if hashlib.sha256(cls.executable.read_bytes()).hexdigest()!=cls.metadata["executable_sha256"]:
            raise AssertionError("native IO executable identity differs")
        for kind in ["policy","packer"]:
            actual=hashlib.sha256((ROOT/"native"/("io_"+kind+".hepta")).read_bytes()).hexdigest()
            if cls.metadata[kind+"_source_sha256"]!=actual:raise AssertionError("native IO source differs")
        source=Path(os.environ.get("HIA_REFERENCE_RUNTIME",ROOT))/"src/mcp/runtime/binary_file.py"
        if hashlib.sha256(source.read_bytes()).hexdigest()!="c15e8900b0ab867b221ff08d5a10401c8b656c87676f57b478b9a21219f7fe12":
            raise AssertionError("retained binary-read reference changed")
        spec=importlib.util.spec_from_file_location("hia_original_binary_read",source)
        cls.reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(cls.reference)
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory(prefix="hia-native-read-");self.addCleanup(self.temporary.cleanup)
        self.base=Path(self.temporary.name);self.root=self.base/"allowed";self.root.mkdir()
        self.content=bytes(range(256))*400+"UTF-8 中文\n".encode()
        self.file=self.root/"data.bin";self.file.write_bytes(self.content)

    def test_actual_elf_matches_retained_read_and_empty_path(self):
        with Session(self.executable,self.root,env={"PATH":""}) as session:
            for offset,limit in [(0,1),(0,4097),(5,65536),(65530,4000),(len(self.content)-17,65536),(len(self.content),1)]:
                actual=session.call(request(self.file,offset=offset,limit=limit),fragmented=offset==5)
                old=self.reference.main(dict(root=str(self.root),path=str(self.file),op="read",offset=offset,limit=limit))
                self.assertEqual(actual["status"],0)
                self.assertEqual(actual["data"],base64.b64decode(old["data_base64"]))
                self.assertEqual(actual["next_offset"],old["next_offset"])
                self.assertEqual(actual["eof"],old["eof"])
                self.assertEqual(actual["version"],version(self.file.stat()))
                self.assertEqual(actual["mode"],self.file.stat().st_mode&0o7777)
                COUNTS["original_read_comparisons"]+=1

    def test_paths_symlinks_hardlinks_and_sidecars(self):
        outside=self.base/"outside.bin";outside.write_bytes(b"outside")
        (self.root/"link").symlink_to(outside)
        (self.root/"dirlink").symlink_to(self.base,target_is_directory=True)
        os.link(self.file,self.root/"hardlink")
        (self.root/".hepta-private").write_bytes(b"private")
        with Session(self.executable,self.root) as session:
            for path,status in [(outside,2),(str(self.root)+"-other/file",2),(str(self.root)+"/../outside.bin",1),
                ("relative",1),(self.root,1),(self.root/".hepta-private",1),(self.root/"link",3),
                (self.root/"dirlink/outside.bin",3),(self.root/"absent",3)]:
                self.assertEqual(session.call(request(path))["status"],status,str(path))
            for path in [self.root/"hardlink",str(self.root)+"//./data.bin","/"+str(self.root)+"/data.bin"]:
                actual=session.call(request(path,limit=7))
                if str(path).startswith("//"):
                    self.assertEqual(actual["status"],2)
                else:
                    self.assertEqual(actual["status"],0)
                    self.assertEqual(actual["data"],self.content[:7])
                    old=self.reference.main(dict(root=str(self.root),path=str(path),op="read",limit=7))
                    self.assertEqual(actual["data"],base64.b64decode(old["data_base64"]))
                    COUNTS["original_read_comparisons"]+=1

    def test_versions_offsets_regular_files_and_resource_cleanup(self):
        (self.root/"nested").mkdir();(self.root/"nested/value").write_bytes(b"child")
        os.mkfifo(self.root/"fifo")
        with Session(self.executable,self.root) as session:
            first=session.call(request(self.file,limit=8));self.assertEqual(first["status"],0)
            descriptors=Path(f"/proc/{session.process.pid}/fd")
            baseline=len(list(descriptors.iterdir()));self.assertEqual(baseline,4)
            self.assertEqual(session.call(request(self.file,version=first["version"],limit=8))["status"],0)
            self.file.write_bytes(self.content+b"changed")
            self.assertEqual(session.call(request(self.file,version=first["version"],limit=8))["status"],6)
            self.assertEqual(session.call(request(self.file,offset=(1<<64)-1))["status"],5)
            self.assertEqual(session.call(request(self.root/"fifo"))["status"],4)
            self.assertEqual(session.call(request(self.root/"nested"))["status"],4)
            for index in range(60):
                path=self.root/("nested/value" if index%3==0 else "nested/missing")
                self.assertEqual(session.call(request(path,identity=index+10))["status"],0 if index%3==0 else 3)
                self.assertEqual(len(list(descriptors.iterdir())),baseline)

    def test_startup_authority_and_eof_framing(self):
        alias=self.base/"rootlink";alias.symlink_to(self.root,target_is_directory=True)
        for path in [alias,"relative",str(self.root)+"/.."]:
            observed=subprocess.run([str(self.executable),str(path)],input=b"",capture_output=True,timeout=5)
            self.assertEqual(observed.returncode,64)
            self.assertEqual(observed.stdout,b"")
        for raw,status in [(b"",0),(b"x",2),(struct.pack("<Q",0),2),(struct.pack("<Q",4208),2),
                           (wire(request(self.file))[:-1],2)]:
            observed=subprocess.run([str(self.executable),str(self.root)],input=raw,capture_output=True,timeout=5)
            self.assertEqual((observed.returncode,observed.stdout),(status,b""))
        with Session(self.executable,"/"+str(self.root)) as session:
            self.assertEqual(session.call(request("/"+str(self.file),limit=3))["data"],self.content[:3])

    def test_malformed_requests_do_not_change_authority(self):
        good=request(self.file)
        variants=[b"BADMAGIC"+good[8:],request(self.file,limit=0),request(self.file,limit=65537),
                  good[:40]+struct.pack("<Q",2)+good[48:],good[:48]+struct.pack("<Q",1)+good[56:]]
        with Session(self.executable,self.root) as session:
            for value in variants:self.assertEqual(session.call(value)["status"],10)
            for raw in [b"/tmp/\x00x",b"/tmp/\xff",b"/tmp/\xc0\x80"]:
                self.assertEqual(session.call(request(raw))["status"],1)
            self.assertEqual(session.call(good)["data"],self.content[:32768])

    def test_kernel_eintr_and_multiple_partial_chunks(self):
        trace=self.base/"eintr.trace"
        with Session(self.executable,self.root,trace=trace,injection="eintr") as session:
            actual=session.call(request(self.file,limit=65536))
            self.assertEqual(actual["status"],0)
            self.assertEqual(actual["data"],self.content[:65536])
        events=json.loads(trace.read_text());reads=[row for row in events if row["syscall"]==17]
        self.assertEqual(reads[0]["mode"],"injected_eintr")
        self.assertEqual([row["offset"] for row in reads[:2]],[0,0])
        self.assertGreaterEqual(len(reads),17)

    def test_change_during_partial_read_is_rejected(self):
        trace=self.base/"changed.trace"
        with Session(self.executable,self.root,trace=trace,injection="change",fixture=self.file) as session:
            actual=session.call(request(self.file,limit=65536))
            self.assertEqual(actual["status"],7)
            self.assertEqual(actual["data"],b"")
        reads=[row for row in json.loads(trace.read_text()) if row["syscall"]==17]
        self.assertEqual(reads[0]["mode"],"changed_fixture_before_kernel_read")
        self.assertEqual([row["offset"] for row in reads[:2]],[0,9])

    def test_close_error_is_reported_without_retry(self):
        trace=self.base/"close.trace"
        # Root traversal closes one predecessor for each root component. The
        # next close releases the request file. The supervisor simulates EINTR rather
        # than performing that close, so the process exits immediately after
        # the response; kernel process teardown releases the injected residue.
        ordinal=len(self.root.parts)
        with Session(self.executable,self.root,trace=trace,injection="close",close_ordinal=ordinal) as session:
            actual=session.call(request(self.file,limit=8))
            self.assertEqual((actual["status"],actual["errno"],actual["data"]),(9,4,b""))
        lines=[row for row in json.loads(trace.read_text()) if row["syscall"]==3]
        self.assertEqual(sum(row["mode"]=="injected_eintr" for row in lines),1)
        self.assertEqual(len(lines),ordinal+1)

    def test_output_failure_and_sigpipe_exit_cleanly(self):
        with open("/dev/full","wb",buffering=0) as sink:
            observed=subprocess.run([str(self.executable),str(self.root)],input=wire(request(self.file,limit=3)),stdout=sink,stderr=subprocess.PIPE,timeout=5)
            self.assertEqual(observed.returncode,74)
        process=subprocess.Popen([str(self.executable),str(self.root)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        process.stdout.close();process.stdin.write(wire(request(self.file,limit=3)));process.stdin.close()
        self.assertEqual(process.wait(timeout=5),74)
        self.assertEqual(process.stderr.read(),b"");process.stderr.close()

    def test_pinned_root_custody_survives_pathname_replacement(self):
        with Session(self.executable,self.root) as session:
            self.assertEqual(session.call(request(self.file,limit=8))["data"],self.content[:8])
            moved=self.base/"relocated";self.root.rename(moved);self.root.mkdir()
            self.file.write_bytes(b"replacement")
            actual=session.call(request(self.file,limit=8))
            self.assertEqual(actual["data"],self.content[:8])
            old=self.reference.main(dict(root=str(self.root),path=str(self.file),op="read",limit=8))
            self.assertEqual(base64.b64decode(old["data_base64"]),b"replacem")
            # This distinction is the explicit persistent-root capability
            # profile, not a claim of complete old caller authorization parity.

    def test_read_error_closes_file_and_session_continues(self):
        trace=self.base/"read-error.trace"
        with Session(self.executable,self.root,trace=trace,injection="read_error") as session:
            actual=session.call(request(self.file,limit=8))
            self.assertEqual((actual["status"],actual["errno"],actual["data"]),(8,5,b""))
            self.assertEqual(session.call(request(self.file,limit=8))["data"],self.content[:8])
        events=json.loads(trace.read_text())
        self.assertEqual(sum(row["mode"]=="injected_eio" for row in events),1)
        self.assertEqual(sum(row["syscall"]==3 for row in events),len(self.root.parts)+2)

    def test_adapter_rejects_offsets_raw_handles_and_unknown_actions(self):
        from hia_native_io_build import build_io
        selected=os.environ.get("HIA_IO_PROBE_MANIFEST")
        if selected:
            probe=Path(selected)
        else:
            with tempfile.TemporaryDirectory(prefix="hia-io-probe-source-") as source:
                folder=Path(source);(folder/"native").mkdir()
                shutil.copyfile(Path(__file__).with_name("io_invalid_effect_probe.hepta"),folder/"native/io_policy.hepta")
                shutil.copyfile(ROOT/"native/io_packer.hepta",folder/"native/io_packer.hepta")
                probe=build_io(Path(os.environ["HIA_HEPTA_DIR"]),Path(os.environ["HIA_BUILD_ROOT"]),source_root=folder)
        metadata=json.loads(probe.read_text());executable=probe.parent/metadata["executable"]
        with Session(executable,self.root) as session:
            for mode in range(1,13):
                actual=session.call(request(self.file,identity=mode))
                self.assertEqual((actual["status"],actual["errno"]),(11,9 if mode in (4,5,12) else 22),mode)

    def test_cached_policy_image_tampering_is_refused(self):
        from hia_native_io_build import build_io
        with tempfile.TemporaryDirectory(prefix="hia-io-cache-guard-") as temp:
            build_root=Path(temp);bootstrap=build_root/"bootstrap";bootstrap.mkdir()
            for name in ["B1.image.bin","B2.image.bin","B3.image.bin","bootstrap.json"]:
                shutil.copyfile(Path(os.environ["HIA_BUILD_ROOT"])/"bootstrap"/name,bootstrap/name)
            cached=build_root/"io"/self.manifest_path.parent.name;cached.mkdir(parents=True)
            for name in ["manifest.json","policy.hepta","policy.image.bin","policy.json","packer.hepta","native-read.elf"]:
                shutil.copyfile(self.manifest_path.parent/name,cached/name)
            (cached/"policy.image.bin").write_bytes((cached/"policy.image.bin").read_bytes()+b"tampered")
            with self.assertRaisesRegex(ValueError,"cached policy image differs"):
                build_io(Path(os.environ["HIA_HEPTA_DIR"]),build_root)

if __name__=="__main__":
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument("--hepta");parser.add_argument("--build-root");parser.add_argument("--manifest")
    args,remaining=parser.parse_known_args()
    for value,key in [(args.hepta,"HIA_HEPTA_DIR"),(args.build_root,"HIA_BUILD_ROOT"),(args.manifest,"HIA_IO_MANIFEST")]:
        if value:os.environ[key]=value
    program=unittest.main(argv=[sys.argv[0],*remaining],exit=False,verbosity=2)
    print(json.dumps({"native_io":COUNTS},sort_keys=True))
    raise SystemExit(0 if program.result.wasSuccessful() else 1)
