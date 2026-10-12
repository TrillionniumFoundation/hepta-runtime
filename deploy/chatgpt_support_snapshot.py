#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Read-only, payload-free support snapshot for a private ChatGPT MCP tunnel.

Collects only allowlisted health counters, protocol method/status counts,
and service health. Never records caller IDs, request parameters, headers,
environment values, tokens, tool results, journal bodies or command lines.
It does not call native MCP tools or affect any service.
"""
import argparse
import collections
import datetime
import json
import os
import re
import subprocess
import sys
import urllib.request

HEALTH = "http://127.0.0.1:8793/health?details=true"
UNITS = (
    "hepta-openai-full-operator.service",
    "hepta-runtime-operator.service",
    "desktop-commander-remote.service",
)
TRACE_METHODS = frozenset({
    "server/discover", "initialize", "notifications/initialized",
    "tools/list", "tools/call", "ping",
})
TRACE_STATES = frozenset({"ok", "error", "no_reply"})
TRACE_ERAS = frozenset({"legacy", "modern", "invalid", "unsupported"})

def health_projection(raw):
    """Choose fields individually; new upstream fields never leak to output."""
    components = raw.get("components") or {}
    def component(name):
        value = components.get(name) or {}
        details = value.get("details") or {}
        permitted = ("completed", "accepted", "failures", "terminal_failures",
                     "initialize_epoch", "last_success", "consecutive_failures")
        selected = {k: details[k] for k in permitted
                    if k in details and type(details[k]) in (int, bool)}
        stamp = details.get("last_success")
        if isinstance(stamp, str) and re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z", stamp
        ):
            selected["last_success"] = stamp
        status = value.get("status")
        state = value.get("state")
        valid_statuses = {"ok", "unknown", "disabled", "degraded", "limited", "error", "failed", "unavailable"}
        valid_states = {"polling", "accepting", "not_observed", "accepted", "running", "available", "ready", "idle", "failed", "settled", "disabled", "direct", "unknown"}
        return {"status": status if status in valid_statuses else "other",
                "state": state if state in valid_states else "other",
                "counters": selected}
    return {
        "ready": raw.get("ready") is True,
        "control_plane": component("control-plane"),
        "dispatcher": component("dispatcher"),
        "response_delivery": component("response-delivery"),
        "mcp": component("mcp"),
    }

def journal_projection(raw):
    protocol = collections.Counter()
    dispatches = 0
    for line in raw.splitlines():
        try:
            event = json.loads(line)
        except (TypeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue
        if event.get("event") == "hepta_mcp_protocol":
            method, status, era = (event.get(k) for k in ("method", "status", "era"))
            if not isinstance(method, str) or method not in TRACE_METHODS or not isinstance(status, str) or status not in TRACE_STATES:
                continue
            if era not in TRACE_ERAS:
                era = "unknown"
            code = event.get("error_code")
            if type(code) is not int:
                code = None
            protocol[(method, era, status, code)] += 1
        elif event.get("msg") == "dispatcher forwarded command to MCP server":
            dispatches += 1
    return {
        "observed_dispatch_log_events": dispatches,
        "protocol_events": [
            {"method": key[0], "era": key[1], "status": key[2],
             "error_code": key[3], "count": count}
            for key, count in sorted(protocol.items(), key=lambda x: str(x[0]))
        ],
    }

def unit_projection(text):
    fields = dict(row.split("=", 1) for row in text.splitlines() if "=" in row)
    return {
        "active": fields.get("ActiveState") == "active",
        "loaded": fields.get("LoadState") == "loaded",
    }

def service_state(unit, env):
    value = subprocess.run(
        ["systemctl", "--user", "show", unit,
         "-p", "ActiveState", "-p", "LoadState"],
        capture_output=True, text=True, timeout=5, env=env, check=False,
    )
    if value.returncode:
        return {"active": False, "loaded": False, "check_failed": True}
    return unit_projection(value.stdout)

def collect(lookback_minutes=90):
    if not 1 <= lookback_minutes <= 240:
        raise ValueError("lookback must be in range 1..240 minutes")
    with urllib.request.urlopen(HEALTH, timeout=5) as response:
        if response.status != 200:
            raise RuntimeError("tunnel health endpoint did not return 200")
        raw = response.read(131073)
    if len(raw) > 131072:
        raise ValueError("unexpectedly large tunnel health response")
    health = health_projection(json.loads(raw))
    journal = subprocess.run(
        ["journalctl", "--user", "-u", UNITS[0],
         "--since", f"{lookback_minutes} minutes ago", "-o", "cat",
         "--no-pager"],
        capture_output=True, text=True, timeout=15, check=False,
    )
    if journal.returncode:
        raise RuntimeError("journalctl failed without payload collection")
    env = dict(os.environ)
    env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={env['XDG_RUNTIME_DIR']}/bus"
    return {
        "schema": "hepta-mcp-support-snapshot-v1",
        "collected_utc": datetime.datetime.now(
            datetime.timezone.utc).isoformat(),
        "window_minutes": lookback_minutes,
        "tunnel": health,
        "journal_summary": journal_projection(journal.stdout),
        "services": {name: service_state(name, env) for name in UNITS},
        "boundary": {
            "plugin_permission": "Must be checked independently in ChatGPT",
            "platform_pre_tool_decisions": "Not exposed by server logs",
            "server_response_accepted": "Does not prove tool action completed",
            "raw_payloads_collected": False,
            "caller_identifiers_collected": False,
            "credentials_collected": False,
        },
    }

def compare(before, after):
    def n(snapshot, component, counter):
        return (snapshot.get("tunnel") or {}).get(component, {}).get(
            "counters", {}).get(counter)
    names = (("dispatcher", "completed"),
             ("response_delivery", "accepted"),
             ("dispatcher", "failures"),
             ("response_delivery", "terminal_failures"))
    deltas = {}
    for component, key in names:
        x, y = n(before, component, key), n(after, component, key)
        deltas[f"{component}.{key}"] = y-x if type(x) is int and type(y) is int else None
    return {
        "schema": "hepta-mcp-support-delta-v1",
        "before_utc": before.get("collected_utc"),
        "after_utc": after.get("collected_utc"),
        "counter_deltas": deltas,
        "interpretation": "A positive delivery delta proves tunnel delivery only; zero delta cannot identify platform refusal policy.",
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lookback-minutes", type=int, default=90)
    ap.add_argument("--output", help="Save redacted JSON snapshot locally")
    ap.add_argument("--compare", help="Previous locally redacted snapshot")
    args = ap.parse_args()
    snapshot = collect(args.lookback_minutes)
    result = snapshot
    if args.compare:
        with open(args.compare, encoding="utf-8") as stream:
            previous = json.load(stream)
        if previous.get("schema") != snapshot["schema"]:
            raise ValueError("unexpected prior snapshot schema")
        result = {"current": snapshot, "delta": compare(previous, snapshot)}
    encoded = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        fd = os.open(args.output, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
    print(encoded, end="")

if __name__ == "__main__":
    main()
