"""Small JSON tool contract shared by the manifest and stdin dispatcher."""
from __future__ import annotations

VERSION = "0.1.7"
REQ = {"type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$"}
STR = {"type": "string"}
INT = {"type": "integer"}
BOOL = {"type": "boolean"}
LIST = {"type": "array", "items": STR, "maxItems": 50}

TOOLS = {
    "capabilities": ("Report implemented adapter features; optional live authentication check.", {"live": BOOL}, []),
    "account": ("Verify the active Kaggle account with the official token introspection API.", {}, []),
    "readiness": ("Observe authentication and complete owned-notebook inventory without creating a task or cloud resource. Correlation request_id does not reserve a notebook; submit rechecks.", {"request_id": REQ}, []),
    "quota": ("Read live accelerator quota, preserving used, reserved, total and refresh fields.", {}, []),
    "notebooks": ("List the authenticated account's own notebooks; paginate explicitly.", {"page_size": {"type": "integer", "minimum": 1, "maximum": 200}, "page_token": STR}, []),
    "submit": ("Create one private, bounded Python notebook execution under a stable request ID. Existing IDs never submit again.",
               {"request_id": REQ, "source": STR, "timeout": {"type": "integer", "minimum": 1, "maximum": 43200},
                "accelerator": STR, "internet": BOOL, "kernel_type": {"type": "string", "enum": ["script", "notebook"]},
                "dataset_source": LIST, "kernel_source": LIST, "model_source": LIST, "competition_source": LIST}, ["request_id", "source"]),
    "status": ("Observe the recorded exact notebook version.", {"request_id": REQ}, ["request_id"]),
    "resume": ("Reconcile or observe the original execution without submitting a new version.", {"request_id": REQ}, ["request_id"]),
    "wait": ("Observe the recorded execution for at most 60 seconds.", {"request_id": REQ, "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 60}}, ["request_id"]),
    "logs": ("Read a bounded, redacted log snapshot with a generation-aware cursor.", {"request_id": REQ, "cursor": STR, "limit": {"type": "integer", "minimum": 1, "maximum": 65536}}, ["request_id"]),
    "artifacts": ("Download fixed-version output files. With a manifest, require its payload sizes/SHA-256 and verified HTTP lengths, recording provider-size conflicts; without one, require provider-size matches.",
                  {"request_id": REQ, "max_bytes": {"type": "integer", "minimum": 1, "maximum": 68719476736}, "manifest_name": STR}, ["request_id"]),
    "cancel": ("Cancel only a proven Kaggle session ID and observe the remote terminal state. An acknowledgement does not mean stopped.",
               {"request_id": REQ, "wait_seconds": {"type": "integer", "minimum": 0, "maximum": 60}}, ["request_id"]),
    "inspect": ("Read the local durable request receipt without remote requests.", {"request_id": REQ}, ["request_id"]),
}


def manifest():
    return {"schema": "hepta-compute-adapter-v1", "provider": "kaggle", "adapter_version": VERSION,
            "entrypoint": "hepta_kaggle.py", "protocol": "json-stdout", "stdin_command": "call",
            "input": {"tool": "kaggle_<command>", "arguments": {}},
            "credentials": "host-local official Kaggle credential file; never tool arguments",
            "host_configuration": {"expected_username": "optional --expected-username; verified before business RPCs; cannot be overridden by tool arguments"},
            "tools": [{"name": "kaggle_" + command, "command": command, "description": values[0],
                       "mutates_cloud": command in {"submit", "cancel"}, "cloud_verified": False,
                       "input_schema": {"type": "object", "properties": values[1], "required": values[2], "additionalProperties": False}}
                      for command, values in TOOLS.items()]}


def call_argv(data):
    from kaggle_transport import AdapterError
    if not isinstance(data, dict) or set(data) != {"tool", "arguments"}:
        raise AdapterError("INVALID_TOOL_CALL", "Tool call requires exactly tool and arguments.")
    tool, arguments = data["tool"], data["arguments"]
    command = tool.removeprefix("kaggle_") if isinstance(tool, str) and tool.startswith("kaggle_") else None
    if command not in TOOLS or not isinstance(arguments, dict):
        raise AdapterError("INVALID_TOOL_CALL", "Tool name or arguments are invalid.")
    _, properties, required = TOOLS[command]
    if set(arguments) - set(properties) or set(required) - set(arguments):
        raise AdapterError("INVALID_TOOL_ARGUMENTS", "Tool arguments contain unknown keys or lack required keys.")
    argv = [command]
    for key, value in arguments.items():
        spec = properties[key]; kind = spec["type"]
        valid = {"string": isinstance(value, str), "integer": isinstance(value, int) and not isinstance(value, bool),
                 "boolean": isinstance(value, bool), "array": isinstance(value, list) and all(isinstance(x, str) for x in value)}[kind]
        if not valid or ("enum" in spec and value not in spec["enum"]):
            raise AdapterError("INVALID_TOOL_ARGUMENTS", "Tool argument has an invalid type or value.", details={"argument": key})
        if kind == "integer" and (value < spec.get("minimum", value) or value > spec.get("maximum", value)):
            raise AdapterError("INVALID_TOOL_ARGUMENTS", "Tool integer is outside its allowed range.", details={"argument": key})
        if kind == "array" and len(value) > spec.get("maxItems", len(value)):
            raise AdapterError("INVALID_TOOL_ARGUMENTS", "Tool array exceeds its bound.", details={"argument": key})
        flag = "--" + key.replace("_", "-")
        if kind == "boolean":
            if value: argv.append(flag)
        elif kind == "array":
            for item in value: argv.extend([flag, item])
        else: argv.extend([flag, str(value)])
    return argv
