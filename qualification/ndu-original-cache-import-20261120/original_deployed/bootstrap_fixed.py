#!/usr/bin/env python3
"""Fixed private entry for the reviewed isolated adoption release.

Invoke with the qualified host interpreter and -I -B. No current working
directory, PYTHONPATH, user-site, caller-selected code root or dynamic plugin
is an import source. Same-uid/root compromise is outside this local boundary.
"""
from __future__ import annotations
import hashlib
import importlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys

MODULES = {"compute":"hepta_compute_adoption", "adoption":"hepta_kaggle_adoption",
           "mac-sign":"mac_sign_adoption", "register-authority":"register_mac_authority"}


def refuse(code):
    print(json.dumps({"ok":False,"error":{"code":code}}))
    raise SystemExit(2)


def checked_file(path, *, limit=4*1024*1024):
    fd=os.open("/",os.O_RDONLY|os.O_DIRECTORY)
    try:
        info=os.fstat(fd)
        if info.st_uid not in (0,os.geteuid()) or info.st_mode&0o022:refuse("ADOPTION_RELEASE_ANCESTOR_UNSAFE")
        for part in path.parts[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=next_fd
            info=os.fstat(fd)
            if info.st_uid not in (0,os.geteuid()) or info.st_mode&0o022:refuse("ADOPTION_RELEASE_ANCESTOR_UNSAFE")
        child=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=fd)
        try:
            info=os.fstat(child)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.geteuid() or
                    info.st_nlink!=1 or info.st_mode&0o022 or info.st_size>limit):refuse("ADOPTION_RELEASE_FILE_UNSAFE")
            with os.fdopen(child,"rb",closefd=False) as stream:body=stream.read(limit+1)
            if len(body)>limit:refuse("ADOPTION_RELEASE_FILE_UNSAFE")
            return body
        finally:os.close(child)
    finally:os.close(fd)


def main():
    os.umask(0o077)
    if not sys.flags.isolated or not sys.dont_write_bytecode:refuse("ADOPTION_ISOLATED_INTERPRETER_REQUIRED")
    if len(sys.argv)<2 or sys.argv[1] not in MODULES:refuse("ADOPTION_FIXED_ENTRY_REQUIRED")
    mode=sys.argv[1]
    expected=Path("/Users/qianqi") if mode=="mac-sign" else Path("/home/qian-qi")
    if Path(pwd.getpwuid(os.geteuid()).pw_dir)!=expected:refuse("ADOPTION_CONFIGURED_HOST_REQUIRED")
    release=expected/".hepta-kaggle-adoption-releases/v5-batch-4920"
    environment=expected/".hepta-kaggle-adoption-releases/sdk-20261109-v1/venv"
    if Path(sys.prefix)!=environment or Path(__file__).absolute()!=release/"bootstrap_fixed.py":
        refuse("ADOPTION_FIXED_RELEASE_REQUIRED")
    try:
        body=checked_file(release/"runtime-files.json",limit=65536)
        def unique(items):
            result={}
            for key,value in items:
                if key in result:raise ValueError()
                result[key]=value
            return result
        manifest=json.loads(body,object_pairs_hook=unique)
        if manifest.get("schema")!="hepta-kaggle-adoption-runtime-files-v1" or not isinstance(manifest.get("files"),dict):
            refuse("ADOPTION_RELEASE_MANIFEST_INVALID")
        required={"adoption_security.py","adoption_controller.py","kaggle_adoption_target.py","kaggle_bound_target.py",
            "kaggle_jobs.py","kaggle_transport.py","hepta_compute_base.py","hepta_compute_adoption.py",
            "hepta_kaggle_adoption.py","mac_sign_adoption.py","cpu08_registered_target.json",
            "register_mac_authority.py","trusted/account_launcher.py","hepta_compute_batch.py"}
        if set(manifest["files"])!=required:refuse("ADOPTION_RELEASE_MANIFEST_INVALID")
        for name,expected_hash in manifest["files"].items():
            if hashlib.sha256(checked_file(release/name)).hexdigest()!=expected_hash:
                refuse("ADOPTION_RELEASE_HASH_MISMATCH")
    except (OSError,ValueError,TypeError):refuse("ADOPTION_RELEASE_EVIDENCE_UNAVAILABLE")
    # All added paths are fixed, private and verified above; -I omitted the
    # script directory, user-site and ambient PYTHONPATH before this point.
    sys.path.insert(0,str(release))
    module=importlib.import_module(MODULES[mode])
    raise SystemExit(module.main(sys.argv[2:]))


if __name__=="__main__":main()
