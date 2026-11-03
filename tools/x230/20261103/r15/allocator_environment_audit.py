#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation
# SPDX-License-Identifier: Apache-2.0
"""Independent validation of allocator evidence; does not import launcher construction code."""
import hashlib,json,re
from pathlib import Path
RUN_SCHEMA="hepta-x230-child-allocator-run/v1"
LIVE_SCHEMA="hepta-x230-child-allocator-observation/v1"
def need(value,reason):
    if not value: raise ValueError(reason)
def digest(value):
    return hashlib.sha256((json.dumps(value,sort_keys=True,separators=(",",":"))+"\n").encode()).hexdigest()
def valid_environment(environment):
    need(isinstance(environment,dict),"allocator environment missing")
    need(environment=={} or set(environment)=={"MALLOC_ARENA_MAX"} and environment["MALLOC_ARENA_MAX"] in {"1","2","4"},
         "unexpected allocator key/value; baseline GLIBC_TUNABLES must be absent")
def validate_metadata(value,binaries,expected_labels):
    need(value["schema"]==RUN_SCHEMA and value["platform"]=="linux" and value["libc"].startswith("glibc "),"allocator platform/schema differs")
    need(value["parent_environment_modified"] is False and value["allocator_keys_cleared"]==["MALLOC_*","GLIBC_TUNABLES"],"allocator isolation policy differs")
    need(value["comparison_identity"]=="binary_sha256+allocator_environment","configuration comparison identity differs")
    need(set(value["variants"])==set(expected_labels)==set(binaries),"allocator variant set differs")
    helper=Path(__file__).with_name("allocator_environment.py")
    need(value["helper_sha256"]==hashlib.sha256(helper.read_bytes()).hexdigest(),"allocator launcher helper changed")
    for label,variant in value["variants"].items():
        env=variant["environment"];valid_environment(env)
        need(variant["environment_sha256"]==digest(env),"allocator environment hash differs")
        need(variant["binary_sha256"]==binaries[label],"allocator binary binding differs")
        need(variant["configuration_fingerprint"]==digest({"binary_sha256":binaries[label],"allocator_environment":env}),"configuration fingerprint differs")
    if set(expected_labels)=={"A","B"}:
        need(value["variants"]["A"]["environment"]=={},"baseline allocator environment is not clean")
        need(value["variants"]["B"]["environment"]!={},"candidate allocator configuration missing")
        need(value["same_binary_sha256"] is (binaries["A"]==binaries["B"]),"same-binary label differs")
        need(value["variants"]["A"]["configuration_fingerprint"]!=value["variants"]["B"]["configuration_fingerprint"],"A/B configuration identities collapsed")
    else:
        need(expected_labels=={"candidate"} and value["variants"]["candidate"]["environment"]!={},"selected allocator configuration missing")
    return value
def validate_observation(value,environment,pid,birth=None,agent_required=None):
    need(value["schema"]==LIVE_SCHEMA and value["status"]=="verified","controller environment was not observed")
    need(value["pid"]==pid and type(value["birth_ticks"]) is int and value["birth_ticks"]>0,"observed process identity differs")
    if birth is not None: need(value["birth_ticks"]==birth,"observed PID generation differs")
    need(value["requested"]==value["observed"]==environment,"observed allocator environment differs from configured arm")
    valid_environment(value["observed"])
    need(value["environment_sha256"]==digest(environment),"observed allocator hash differs")
    need(value["full_environment_retained"] is False,"full process environment must not be retained")
    need(value["source"]=="same-PID/start-ticks /proc/PID/environ","environment evidence source differs")
    need(type(value["ssh_auth_sock_present"]) is bool and value["held_ssh_agent_preserved"] is value["ssh_auth_sock_present"],"SSH environment preservation differs")
    if agent_required is not None:
        need(value["ssh_auth_sock_present"] is agent_required,"held SSH agent presence differs")
def validate_abba(report,kind):
    need(kind in {"cancel","native"},"unknown allocator ABBA kind")
    meta=validate_metadata(report["allocator_configuration"],report["binary_sha256"],{"A","B"})
    count=0
    for row in report["rounds"]:
        arm=row["arm"] if kind=="cancel" else row["version"]
        env=meta["variants"][arm]["environment"]
        starts=("startup",) if kind=="cancel" else ("startup","restart_startup")
        for key in starts:
            startup=row[key]
            validate_observation(startup["allocator_environment"],env,startup["pid"],startup["birth_ticks"],kind=="native")
            need(startup["allocator_environment"]["phase"]=="after-native-initialize","environment was observed after timing began")
            count+=1
    return {"verified":True,"controllers_with_live_environment":count,"configuration":meta,
            "same_binary_configuration_comparison":meta["same_binary_sha256"]}
def validate_recovery(report):
    meta=validate_metadata(report["allocator_configuration"],{"candidate":report["candidate_sha256"]},{"candidate"})
    env=meta["variants"]["candidate"]["environment"]
    for key in ("first_startup","after_crash_startup","after_cancel_startup"):
        startup=report[key]
        validate_observation(startup["allocator_environment"],env,startup["pid"],startup["birth_ticks"],True)
        need(startup["allocator_environment"]["phase"]=="after-native-initialize","recovery environment observation phase differs")
    return {"verified":True,"controllers_with_live_environment":3,"configuration":meta}
def isolated_configuration(summary):
    return validate_metadata(summary["allocator_configuration"],{"candidate":None},{"candidate"})
def validate_isolated_command(command,meta):
    environment=meta["variants"]["candidate"]["environment"]
    need(command["allocator_environment"]==environment and command["allocator_environment_sha256"]==digest(environment),"libtest explicit child environment differs")
    value=command["allocator_observation"]
    if value.get("status")=="verified":
        validate_observation(value,environment,command["pid"])
        need(value["phase"]=="after-direct-Popen","isolated observation phase differs")
        return "verified"
    need(value["schema"]==LIVE_SCHEMA and value["status"]=="unavailable_process_exited" and value["pid"]==command["pid"]
         and value["phase"]=="after-direct-Popen" and command["exit_code"]==0,
         "unavailable libtest environment is not an observed child-exit race")
    return "unavailable_process_exited"
