"""Derive the fixed get_info contract only from immutable original sources."""
from pathlib import Path
import hashlib
import json
import re
import tomllib

TARGET = "d3d75c30719db966b004756f610007a7c723729e"
SDK_COMMIT = "5596a8a0bba2a1ec5519cc855cdadf23e4dcecdc"
SOURCE_PINS = {
    "server.rs": "0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f",
    "Cargo.lock": "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631",
    "rmcp-model.rs": "ac438543401b6b9d60021fc044dcf27b446df9539e837c6fecdf16a670091b9a",
    "rmcp-capabilities.rs": "34e941d97f50d41be5e3878ead4150f850a1f285a348ac8d119ebe1f55ea9aba",
}
RMCP_CHECKSUM = "d24a7e92f4bcaa36b97fa93c4fa7ca8f3e669eced949345b3462dba333c7f909"

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def need(condition, label):
    if not condition:
        raise ValueError("fixed get_info derivation: " + label)

def one(pattern, text, label, flags=0):
    matches = re.findall(pattern, text, flags)
    need(len(matches) == 1, label)
    return matches[0]

def fields(source, name):
    body = one(r"pub struct " + name + r" \{(.*?)\n\}", source, name, re.S)
    return re.findall(r"pub ([a-z_]+):", body), body

def derive(primary):
    primary = Path(primary)
    raw = {name: (primary / name).read_bytes() for name in (*SOURCE_PINS, "rmcp-Cargo.toml")}
    for name, expected in SOURCE_PINS.items():
        need(sha(raw[name]) == expected, name + " complete primary source")
    server, model, caps = (raw[name].decode() for name in
                          ("server.rs", "rmcp-model.rs", "rmcp-capabilities.rs"))
    method = one(r"(\tfn get_info\(&self\) -> ServerConfig \{.*?\n\t\})\n\n\tasync fn list_tools",
                 server, "one original get_info method", re.S)
    need(re.findall(r"\.enable_([a-z_]+)\(", method) ==
         ["experimental_with", "tools", "resources", "resources_subscribe"],
         "exact original capability builder calls")
    need(".with_server_info(Implementation::from_build_env())" in method,
         "actual SDK build identity constructor")
    protocol_constant = one(r"\.with_protocol_version\(ProtocolVersion::([A-Z_0-9]+)\)",
                            method, "fixed protocol constant")
    protocol = one(r"pub const " + protocol_constant +
                   r': Self = Self\(Cow::Borrowed\("([^"]+)"\)\);',
                   model, "actual SDK protocol spelling")
    channel = one(r'const CLAUDE_CHANNEL_CAPABILITY: &str = "([^"]+)";',
                  server, "original experimental channel constant")
    need("CLAUDE_CHANNEL_CAPABILITY.to_string()" in method and "JsonObject::new()" in method,
         "original channel has empty settings")
    quoted = one(r'\.with_instructions\(\s*("(?:[^"\\]|\\.)*")\s*\.to_string\(\),\s*\)',
                 method, "original instruction literal", re.S)
    # Rust escaped physical newlines remove the following indentation. The
    # retained literal has no Rust-only escapes after this exact operation.
    joined = re.sub(r"\\\r?\n[ \t]*", "", quoted)
    instructions = json.loads(joined)
    need(isinstance(instructions, str) and instructions, "decoded original instructions")
    initialize_fields, initialize_body = fields(model, "InitializeResult")
    need(initialize_fields == ["protocol_version", "capabilities", "server_info", "instructions", "meta"],
         "SDK InitializeResult declaration order")
    need('pub type ServerConfig = InitializeResult;' in model, "ServerConfig alias")
    need('#[serde(rename = "_meta", skip_serializing_if = "Option::is_none")]' in initialize_body,
         "unset meta omitted")
    need("instructions: None,\n            meta: None," in model, "new result optional defaults")
    implementation_fields, implementation_body = fields(model, "Implementation")
    need(implementation_fields == ["name", "title", "version", "description", "icons", "website_url"],
         "SDK Implementation declaration order")
    need(implementation_body.count('skip_serializing_if = "Option::is_none"') == 4,
         "optional implementation fields omitted")
    build_env = one(r"    pub fn from_build_env\(\) -> Self \{(.*?)\n    \}",
                    model, "one SDK from_build_env constructor", re.S)
    need('name: env!("CARGO_CRATE_NAME").to_owned()' in build_env
         and 'version: env!("CARGO_PKG_VERSION").to_owned()' in build_env,
         "SDK crate compile-time identity")
    for name in ("title", "description", "icons", "website_url"):
        need(name + ": None" in build_env, "build identity optional default " + name)
    cap_fields, cap_body = fields(caps, "ServerCapabilities")
    need(cap_fields == ["experimental", "extensions", "logging", "completions", "prompts", "resources", "tools"],
         "SDK capability declaration order")
    need(cap_body.count('skip_serializing_if = "Option::is_none"') == 7,
         "unset capability fields omitted")
    resource_fields, resource_body = fields(caps, "ResourcesCapability")
    tool_fields, tool_body = fields(caps, "ToolsCapability")
    need(resource_fields == ["subscribe", "list_changed"] and tool_fields == ["list_changed"],
         "nested capability fields")
    need(resource_body.count('skip_serializing_if = "Option::is_none"') == 2
         and tool_body.count('skip_serializing_if = "Option::is_none"') == 1,
         "nested optional fields omitted")
    need("$fn: Some($TN::default())" in caps and "$fn: Some($fn)" in caps,
         "actual builder default and explicit setters")
    subscribe = one(r"    pub fn enable_resources_subscribe\(mut self\) -> Self \{(.*?)\n    \}",
                    caps, "SDK resources subscribe setter", re.S)
    need("c.subscribe = Some(true);" in subscribe, "explicit subscribe true")
    cargo = tomllib.loads(raw["rmcp-Cargo.toml"].decode())
    package = cargo["package"]
    name = cargo.get("lib", {}).get("name", package["name"].replace("-", "_"))
    version = package["version"]
    locked = [p for p in tomllib.loads(raw["Cargo.lock"].decode())["package"]
              if p["name"] == package["name"] and p["version"] == version]
    need(package["name"] == name == "rmcp" and version == "3.9.0" and len(locked) == 1,
         "normalized RMCP crate matches exact target lock")
    need(locked[0]["checksum"] == RMCP_CHECKSUM, "exact target RMCP registry checksum")
    contract = {
        "schema": "hepta.current-get-info.primary-derived-contract.v1",
        "target_commit": TARGET, "rmcp_source_commit": SDK_COMMIT,
        "protocol_version": protocol, "experimental_channel": channel,
        "resources_subscribe": True, "tools_present": True,
        "server_name": name, "server_version": version, "instructions": instructions,
        "result_field_order": initialize_fields, "capability_field_order": cap_fields,
        "implementation_field_order": implementation_fields,
        "meta_present": False, "implementation_optional_fields_present": False,
        "configuration_input_required": False,
        "primary_sources": {name: {"bytes": len(value), "sha256": sha(value)}
                            for name, value in sorted(raw.items())},
        "original_method": {"bytes": len(method.encode()), "sha256": sha(method.encode())},
        "expected_output_or_process_stream_used_for_generation": False,
    }
    return contract
