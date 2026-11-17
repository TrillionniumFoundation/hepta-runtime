"""Copy exact original get_info and feature functions into an isolated Rust observer."""
from pathlib import Path
import argparse, hashlib, json, re, shutil

SHA = lambda raw: hashlib.sha256(raw).hexdigest()
TARGET_SERVER = "0957f7d7d56ad76540a42ba82b33fc29a625bb186cece2a207a764ea8c5beb6f"


def slices(source):
    raw = (Path(source) / "original/target-server.rs").read_bytes()
    assert SHA(raw) == TARGET_SERVER
    text = raw.decode("utf-8")
    spans = {}
    start = text.index("\tfn get_info(&self) -> ServerConfig {")
    end = text.index("\n\tasync fn list_tools(", start)
    spans["get_info"] = (start, end)
    for name in ("allows_unsolicited_notifications", "supports_cache_hints"):
        start = text.index("fn " + name + "(context: &RequestContext<RoleServer>) -> bool {")
        end = text.index("\n}\n", start) + 3
        spans[name] = (start, end)
    constant = 'const CLAUDE_CHANNEL_CAPABILITY: &str = "claude/channel";'
    start = text.index(constant);spans["CLAUDE_CHANNEL_CAPABILITY"] = (start, start + len(constant))
    start = text.index("use rmcp::{");end = text.index("\n};", start) + 3
    import_text = text[start:end]
    required = ("ServerHandler", "ExperimentalCapabilities", "Implementation", "JsonObject",
                "ProtocolVersion", "ServerCapabilities", "ServerConfig", "RequestContext", "RoleServer")
    for name in required:
        assert re.search(r"\b" + name + r"\b", import_text)
    spans["original_rmcp_imports"] = (start, end)
    chunks = {name: text[start:end] for name, (start, end) in spans.items()}
    receipts = {name: {"start_byte": len(text[:start].encode()), "end_byte": len(text[:end].encode()),
                       "bytes": len(chunks[name].encode()), "sha256": SHA(chunks[name].encode())}
                for name, (start, end) in spans.items()}
    header = text[:text.index("//! MCP schemas")]
    generated = (header + "// Exact original source excerpts; only the implementation type is the fixture.\n"
                 + chunks["CLAUDE_CHANNEL_CAPABILITY"] + "\n\n"
                 + chunks["allows_unsolicited_notifications"] + "\n"
                 + chunks["supports_cache_hints"] + "\n"
                 + "impl ServerHandler for ReferenceServer {\n" + chunks["get_info"] + "\n}\n")
    return generated.encode(), receipts, import_text


def prepare(source, output):
    source = Path(source).resolve(strict=True);output = Path(output).absolute()
    assert not output.exists() and not output.is_relative_to(source)
    output.mkdir(parents=True)
    for name in ("oracle", "cache-seed", "target"):
        shutil.copytree(source / name, output / name, copy_function=shutil.copyfile)
    generated, spans, original_imports = slices(source)
    (output / "oracle/generated_get_info.rs").write_bytes(generated)
    (output / "ORIGINAL_IMPORTS.txt").write_text(original_imports + "\n")
    receipt = {"schema": "hepta.current-get-info.handshake-extraction.v1",
               "target_commit": "d3d75c30719db966b004756f610007a7c723729e",
               "target_server_sha256": TARGET_SERVER, "original_spans": spans,
               "generated_sha256": SHA(generated), "generated_bytes": len(generated),
               "unchanged_get_info_body": True, "unchanged_original_feature_functions": True,
               "original_wire_used_as_implementation": False, "rust_executed": False}
    (output / "EXTRACTION.json").write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.output), sort_keys=True))
