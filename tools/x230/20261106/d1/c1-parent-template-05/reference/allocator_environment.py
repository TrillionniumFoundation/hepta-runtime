#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Explicit child-only glibc allocator configuration; never changes parent os.environ."""
import hashlib,json,os,sys
from pathlib import Path
ALLOWED_ARENA_MAX=(1,2,4)
RUN_SCHEMA="hepta-x230-child-allocator-run/v1"
LIVE_SCHEMA="hepta-x230-child-allocator-observation/v1"
def need(value,reason):
    if not value: raise ValueError(reason)
def encoded(value):
    return (json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()
def digest(value): return hashlib.sha256(encoded(value)).hexdigest()
def source_sha256(): return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
def allocator_key(key): return key.startswith("MALLOC_") or key=="GLIBC_TUNABLES"
def allocator_values(environment):
    return {key:value for key,value in environment.items() if allocator_key(key)}
def configured(arena_max=None):
    if arena_max is None: return {}
    need(type(arena_max) is int and arena_max in ALLOWED_ARENA_MAX,"unsupported explicit arena maximum")
    return {"MALLOC_ARENA_MAX":str(arena_max)}
def checked(environment):
    need(isinstance(environment,dict),"allocator configuration must be an object")
    need(not environment or set(environment)=={"MALLOC_ARENA_MAX"},"only explicit MALLOC_ARENA_MAX is admitted")
    need(not environment or environment["MALLOC_ARENA_MAX"] in {"1","2","4"},"allocator arena maximum differs")
    return dict(environment)
def child_environment(base,configuration):
    """Retain all non-allocator inputs, including a held SSH_AUTH_SOCK."""
    configuration=checked(configuration)
    result={key:value for key,value in dict(base).items() if not allocator_key(key)}
    result.update(configuration)
    need(allocator_values(result)==configuration,"allocator keys survived clearing")
    return result
def platform_receipt():
    need(sys.platform=="linux","allocator experiment requires the Linux controller")
    libc=os.confstr("CS_GNU_LIBC_VERSION")
    need(isinstance(libc,str) and libc.startswith("glibc "),"allocator experiment requires glibc")
    return {"platform":"linux","libc":libc,"machine":os.uname().machine}
def run_metadata(configurations,binary_sha256):
    need(set(configurations)==set(binary_sha256),"allocator/binary variant keys differ")
    variants={}
    for label,configuration in configurations.items():
        configuration=checked(configuration)
        identity={"binary_sha256":binary_sha256[label],"allocator_environment":configuration}
        variants[label]={"environment":configuration,"environment_sha256":digest(configuration),
                         "binary_sha256":binary_sha256[label],"configuration_fingerprint":digest(identity)}
    return {"schema":RUN_SCHEMA,**platform_receipt(),"helper_sha256":source_sha256(),"variants":variants,
            "comparison_identity":"binary_sha256+allocator_environment",
            "same_binary_sha256":set(variants)=={"A","B"} and binary_sha256["A"]==binary_sha256["B"],
            "parent_environment_modified":False,"allocator_keys_cleared":["MALLOC_*","GLIBC_TUNABLES"],
            "scope":"X230/glibc controller child; no service/global environment changes; remote workload environment not configured"}
def process_identity(pid):
    fields=Path(f"/proc/{pid}/stat").read_text().rsplit(") ",1)[1].split()
    if fields[0] in {"Z","X"}: raise ProcessLookupError("child already exited")
    return int(fields[19])
def observe(pid,birth,configuration,child_env,phase):
    configuration=checked(configuration)
    need(process_identity(pid)==birth,"child PID generation changed before environment read")
    with Path(f"/proc/{pid}/environ").open("rb") as stream: raw=stream.read(1024*1024+1)
    need(len(raw)<=1024*1024,"child environment exceeds observation bound")
    selected={}
    agent_values=[]
    for part in raw.split(b"\0"):
        if not part: continue
        key,separator,value=part.partition(b"=")
        need(separator==b"=","invalid child environment entry")
        if key.startswith(b"MALLOC_") or key==b"GLIBC_TUNABLES":
            key=key.decode("ascii")
            need(key not in selected,"duplicate child allocator key")
            selected[key]=value.decode("utf-8")
        elif key==b"SSH_AUTH_SOCK":
            agent_values.append(value)
    need(process_identity(pid)==birth,"child PID generation changed during environment read")
    need(selected==configuration,"actual child allocator environment differs")
    expected_agent=child_env.get("SSH_AUTH_SOCK")
    expected_values=[] if expected_agent is None else [os.fsencode(expected_agent)]
    need(agent_values==expected_values,"held SSH agent was removed or changed in child environment")
    return {"schema":LIVE_SCHEMA,"status":"verified","pid":pid,"birth_ticks":birth,"phase":phase,
            "requested":configuration,"observed":selected,"environment_sha256":digest(selected),
            "ssh_auth_sock_present":expected_agent is not None,
            "held_ssh_agent_preserved":expected_agent is not None,
            "source":"same-PID/start-ticks /proc/PID/environ","full_environment_retained":False}
def command_observation(process,configuration,child_env):
    """Fast libtests may exit before /proc is readable; never rerun a test for a snapshot."""
    try:
        birth=process_identity(process.pid)
        return observe(process.pid,birth,configuration,child_env,"after-direct-Popen")
    except (FileNotFoundError,ProcessLookupError):
        need(process.poll() is not None,"live child environment was unexpectedly unavailable")
        return {"schema":LIVE_SCHEMA,"status":"unavailable_process_exited","pid":process.pid,
                "phase":"after-direct-Popen","reason":"child exited before a complete live snapshot",
                "binding":"explicit Popen(env=...) recorded separately; no automatic retry"}

