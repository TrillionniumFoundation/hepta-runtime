#!/usr/bin/env python3
# Copyright 2026 Muvon Un Limited
# SPDX-License-Identifier: Apache-2.0
"""Exact per-request comparison for the one frozen independent-completion window."""
import json
from pathlib import Path
from common import require,sha
def compare(actual,expected,native_versions,original_versions,case,q,number,commands,store,view,original_value,host):
    if case["name"]!="two_same_session" or q["kind"]!="drain" or q["session"]!=0:
        require(actual==expected,"complete current SDK wire outside individually stat-bound version differs at command "+str(number))
        require([r["path"] for r in native_versions]==[r["path"] for r in original_versions],"same ordered publication version paths")
        return dict(command=number,comparison="exact ordered wire",native_order=None,original_order=None)
    # This exact input-only case has two distinct simultaneous request IDs and
    # two different create targets. Both bodies are observed blocked before one
    # actual unlock. Both futures have returned before this one EOF drain; there
    # is no intervening response read or cancellation. SDK service.rs spawns an
    # independent handler for each and sends its completion from sink_proxy_rx.
    sent=[]
    for step in case["steps"]:
        if step.get("kind")!="send":continue
        msg=json.loads(bytes.fromhex(step["wire_hex"]))
        if msg.get("method")=="tools/call":
            require(step["session"]==0 and msg["params"]["name"]=="text_file_write","fixed concurrent handler pair")
            sent.append(msg)
        require(msg.get("method")!="notifications/cancelled","no cancellation in independent pair")
    require(len(sent)==2 and [m["id"] for m in sent]==[10,11]
        and all(type(m["id"]) is int for m in sent),"two distinct exact current-SDK IDs")
    paths={m["id"]:m["params"]["arguments"]["path"] for m in sent}
    require(len(set(paths.values()))==2,"independent publication targets")
    before=[json.loads(store.get(r["request"])) for r in commands[:number]]
    blocked=[i for i,r in enumerate(before) if r["kind"]=="wait_blocked" and r["count"]==2]
    returned=[i for i,r in enumerate(before) if r["kind"]=="wait_events" and r["event"]=="returned" and r["count"]==2]
    unlock=host[2]["after_commands"]
    require(len(blocked)==len(returned)==1 and blocked[0]<unlock<=returned[0]<number
        and all(r["kind"] not in ("read","drain") for r in before[blocked[0]+1:])
        and before[-1]["kind"]=="eof" and before[-1]["session"]==0,"exact joined-futures EOF window")
    events=view["events"]
    require(len(events)==2 and len({e["engine"] for e in events})==1
        and all(e["stage"]==2 and e["dropped"]==0 for e in events),"both actual independent native futures returned")
    entered={};completed={}
    for e in original_value["state"]["events"]:
        if e["event"]=="entered":entered[e["number"]]=e["path"]
        elif e["event"]=="returned":
            require(e["ok"] is True and e["number"] in entered and entered[e["number"]]==e["path"],"actual original independent completion")
            completed[e["number"]]=e["path"]
    require(len(entered)==len(completed)==2 and set(completed.values())==set(paths.values()),"both actual original futures returned")
    def indexed(raw):
        require(raw.endswith(b"\n"),"complete concurrent response termination")
        rows=raw.splitlines(keepends=True);require(len(rows)==2,"exact pair of complete response lines")
        keyed={};order=[]
        for line in rows:
            value=json.loads(line);identifier=value.get("id")
            require(type(identifier) is int and identifier in paths and identifier not in keyed
                and set(value)=={"jsonrpc","id","result"} and value["jsonrpc"]=="2.0","one exact response for each independent ID")
            result=value["result"];content=result.get("content")
            require(result.get("isError") is False and isinstance(content,list) and len(content)==1
                and content[0].get("type")=="text","complete successful independent response")
            body=json.loads(content[0]["text"])
            require(body["path"]==paths[identifier],"response ID stays attached to its actual request target")
            keyed[identifier]=line;order.append(identifier)
        return keyed,order
    left,lo=indexed(actual);right,ro=indexed(expected)
    require(left==right,"all bytes of each independent response outside exact stat token")
    expected_paths={str(Path(p).relative_to(case["root"])) for p in paths.values()}
    require(len(native_versions)==len(original_versions)==2
        and {r["path"] for r in native_versions}=={r["path"] for r in original_versions}==expected_paths,
        "both complete per-file version proofs preserved")
    return dict(command=number,comparison="two independent completed requests, full per-ID wire",
        native_order=lo,original_order=ro,
        full_lines={str(i):dict(native=sha(left[i]),original=sha(right[i])) for i in (10,11)},
        native_returned=[dict(job=e["job"],tag=e["tag"],returned_trace=e["returned"]) for e in events],
        original_returned=completed,all_other_windows_ordered=True)
