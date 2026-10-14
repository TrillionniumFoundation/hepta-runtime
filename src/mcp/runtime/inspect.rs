// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
//! Read-only host inspection and administrator-defined actions.
use anyhow::{bail, Result};
use regex::Regex;
use rmcp::schemars;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

use super::config::{check_protected_input, runtime_config, valid_name, Platform};
use super::jobs::audit;
use super::ssh::run_python_json;

#[derive(Debug, Clone, Default, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostListParams {}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct HostParams {
	pub host: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatusParams {
	pub host: String,
	/// Exact systemd unit or launchd label names, max 64.
	pub services: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PrivilegedActionParams {
	pub host: String,
	/// Exact symbolic action name from the host policy.
	pub action: String,
	#[serde(default)]
	pub args: Vec<String>,
}

pub fn host_list() -> Result<String> {
	let config = runtime_config()?;
	let hosts: Vec<Value> = config
		.hosts
		.iter()
		.map(|(name, host)| {
			json!({
				"name": name,
				"platform": host.platform,
				"execution_mode": host.execution_mode,
				"operator_tools": host.execution_mode == super::config::ExecutionMode::Operator,
				"allow_execute": host.allow_execute,
				"allow_pty": host.allow_pty,
				"allow_write": host.allow_write,
				"privileged_actions": host.privileged_actions.keys().collect::<Vec<_>>(),
			})
		})
		.collect();
	Ok(serde_json::to_string_pretty(&json!({"hosts": hosts}))?)
}

const HARDWARE_CODE: &str = r#"
import glob, json, os, pathlib, platform, subprocess, sys, time

def read(path, default=None):
    try:
        return pathlib.Path(path).read_text(errors="replace").strip()
    except Exception:
        return default

def number(path, scale=1.0):
    value = read(path)
    try:
        return float(value) / scale
    except Exception:
        return None

def cmd(argv):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=8)
        return {"exit_code": p.returncode, "stdout": p.stdout.strip(), "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"exit_code": -1, "stderr": str(exc), "stdout": ""}

result = {
    "schema": "hepta-hardware-v1",
    "sampled_at_unix_ms": int(time.time()*1000),
    "hostname": platform.node(),
    "platform": sys.platform,
    "kernel": platform.release(),
    "machine": platform.machine(),
}
if sys.platform == "linux":
    result["board"] = read("/sys/class/dmi/id/board_name")
    result["product"] = read("/sys/class/dmi/id/product_name")
    result["bios"] = read("/sys/class/dmi/id/bios_version")
    result["platform_profile"] = read("/sys/firmware/acpi/platform_profile")
    result["cpu_model"] = None
    for line in (read("/proc/cpuinfo", "") or "").splitlines():
        if line.lower().startswith("model name") and ":" in line:
            result["cpu_model"] = line.split(":", 1)[1].strip(); break
    mem = {}
    for line in (read("/proc/meminfo", "") or "").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            if key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                mem[key] = value.strip()
    result["memory"] = mem
    hwmon = []
    for root in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        item = {"path": root, "name": read(root + "/name", "unknown")}
        values = {}
        for pattern in ("temp*_input", "power*_average", "power*_input", "fan*_input", "freq*_input"):
            for path in sorted(glob.glob(root + "/" + pattern)):
                values[os.path.basename(path)] = read(path)
        if values:
            item["values"] = values; hwmon.append(item)
    result["hwmon"] = hwmon
    normalized = []
    for monitor in hwmon:
        for field, raw in monitor['values'].items():
            unit, scale = ('C', 1000.0) if field.startswith('temp') else ('W', 1000000.0) if field.startswith('power') else ('RPM', 1.0) if field.startswith('fan') else ('Hz', 1.0)
            try: value = float(raw) / scale
            except (ValueError, TypeError): value = None
            normalized.append({'source': monitor['path']+'/'+field, 'sensor': monitor['name'], 'value': value, 'unit': unit, 'available': value is not None})
    result['sensors'] = normalized
    gpus = []
    for dev in sorted(glob.glob("/sys/class/drm/card[0-9]*/device")):
        if not read(dev + "/vendor"):
            continue
        gpu = {
            "card": pathlib.Path(dev).parent.name,
            "vendor": read(dev + "/vendor"),
            "device": read(dev + "/device"),
            "busy_percent": number(dev + "/gpu_busy_percent"),
            "vram_total": number(dev + "/mem_info_vram_total"),
            "vram_used": number(dev + "/mem_info_vram_used"),
            "gtt_total": number(dev + "/mem_info_gtt_total"),
            "gtt_used": number(dev + "/mem_info_gtt_used"),
            "sclk": read(dev + "/pp_dpm_sclk"),
            "mclk": read(dev + "/pp_dpm_mclk"),
        }
        gpus.append(gpu)
    result["gpus"] = gpus
    supplies = []
    for root in sorted(glob.glob("/sys/class/power_supply/*")):
        values = {}
        for line in (read(root + "/uevent", "") or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                if key in ("POWER_SUPPLY_NAME", "POWER_SUPPLY_TYPE", "POWER_SUPPLY_STATUS", "POWER_SUPPLY_ONLINE", "POWER_SUPPLY_CAPACITY", "POWER_SUPPLY_POWER_NOW"):
                    values[key] = value
        supplies.append({"path": root, "values": values})
    result["power_supplies"] = supplies
    limits = {}
    for name in ("ppt_pl1_spl", "ppt_pl2_sppt", "ppt_pl3_fppt"):
        root = f"/sys/class/firmware-attributes/asus-armoury/attributes/{name}"
        if pathlib.Path(root).is_dir():
            limits[name] = {key: read(root + "/" + key) for key in ("current_value", "default_value", "min_value", "max_value")}
    legacy = "/sys/devices/platform/asus-nb-wmi"
    for name in ("ppt_pl1_spl", "ppt_pl2_sppt", "ppt_fppt", "ppt_apu_sppt", "ppt_platform_sppt"):
        value = read(legacy + "/" + name)
        if value is not None:
            limits["legacy_" + name] = value
    result["power_limits"] = limits
    result["power_limit_semantics"] = "Driver-reported requests/cached values; not measured sustained power."
    result["accel_devices"] = sorted(glob.glob("/dev/accel/*"))
    thunderbolt = []
    for root in sorted(glob.glob("/sys/bus/thunderbolt/devices/*")):
        item = {"name": os.path.basename(root)}
        for key in ("device_name", "generation", "rx_speed", "tx_speed", "security", "unique_id"):
            value = read(root + "/" + key)
            if value is not None: item[key] = value
        thunderbolt.append(item)
    result["thunderbolt"] = thunderbolt
else:
    result["cpu"] = cmd(["sysctl", "-n", "machdep.cpu.brand_string"])
    result["memory_bytes"] = cmd(["sysctl", "-n", "hw.memsize"])
    result["thermal_sensors_available"] = False
    result["battery"] = cmd(["pmset", "-g", "batt"])
print(json.dumps(result, sort_keys=True))
"#;

const SERVICE_CODE: &str = include_str!("service_inspect.py");

const NETWORK_CODE: &str = r#"
import glob, json, os, pathlib, subprocess, sys

def run(argv):
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10)
        data = p.stdout.strip()
        try: parsed = json.loads(data)
        except Exception: parsed = data
        return {"exit_code": p.returncode, "data": parsed, "stderr": p.stderr.strip()}
    except Exception as exc:
        return {"exit_code": -1, "data": "", "stderr": str(exc)}

def read(path):
    try:return pathlib.Path(path).read_text(errors="replace").strip()
    except Exception:return None

if sys.platform == "linux":
    result = {
        "links": run(["ip", "-j", "link"]),
        "addresses": run(["ip", "-j", "address"]),
        "routes": run(["ip", "-j", "route", "show", "table", "all"]),
        "listeners": run(["ss", "-H", "-lntup"]),
    }
    tb = []
    for root in sorted(glob.glob("/sys/bus/thunderbolt/devices/*")):
        item = {"name": os.path.basename(root)}
        for key in ("device_name", "generation", "rx_speed", "tx_speed", "security", "unique_id"):
            value = read(root + "/" + key)
            if value is not None:item[key] = value
        tb.append(item)
    result["thunderbolt"] = tb
else:
    result = {"interfaces": run(["ifconfig", "-a"]), "routes": run(["netstat", "-rn"]), "listeners": run(["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"])}
print(json.dumps(result, sort_keys=True))
"#;

const PRIVILEGED_CODE: &str = r#"
import json, os, selectors, subprocess, sys, time
q = json.load(sys.stdin)
argv = ["sudo", "-n", q["executable"], *q.get("fixed_args", []), *q.get("args", [])]
LIMIT = 524288
def bounded_text(value, seen):
    encoded = bytes(value).decode("utf-8", "replace").encode("utf-8")
    return encoded[-LIMIT:].decode("utf-8", "ignore"), seen > LIMIT or len(encoded) > LIMIT

# Bound memory while the action runs; never communicate() on inherited pipes.
# Only the direct action launcher is killed on timeout. Descendant state remains
# unconfirmed, and inherited pipe writers cannot hold this helper indefinitely.
p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, close_fds=True)
tails = {"stdout": bytearray(), "stderr": bytearray()}
seen = {"stdout": 0, "stderr": 0}
eof = {"stdout": False, "stderr": False}
selector = selectors.DefaultSelector()
for name, stream in (("stdout", p.stdout), ("stderr", p.stderr)):
    os.set_blocking(stream.fileno(), False)
    selector.register(stream, selectors.EVENT_READ, name)
deadline = time.monotonic() + float(q.get("timeout_seconds", 30))
timed_out, kill_deadline, drain_deadline, capture_error = False, None, None, None
try:
    while selector.get_map() or p.poll() is None:
        now = time.monotonic()
        if not timed_out and p.poll() is None and now >= deadline:
            timed_out, kill_deadline = True, now + 2
            try: p.kill()
            except ProcessLookupError: pass
        if p.poll() is not None and drain_deadline is None:
            drain_deadline = now + 1
        if (kill_deadline is not None and now >= kill_deadline) or (drain_deadline is not None and now >= drain_deadline):
            break
        for key, _ in selector.select(.05):
            try: chunk = os.read(key.fd, 65536)
            except BlockingIOError: continue
            except OSError:
                capture_error = "read_failed"; chunk = b""
            if not chunk:
                eof[key.data] = capture_error is None
                selector.unregister(key.fileobj); key.fileobj.close()
                continue
            name = key.data; seen[name] += len(chunk)
            tails[name].extend(chunk)
            if len(tails[name]) > LIMIT: del tails[name][:-LIMIT]
finally:
    selector.close()
    for stream in (p.stdout, p.stderr):
        if not stream.closed: stream.close()
confirmed = p.poll() is not None
stdout, stdout_truncated = bounded_text(tails["stdout"], seen["stdout"])
stderr, stderr_truncated = bounded_text(tails["stderr"], seen["stderr"])
result = {"exit_code": 124 if timed_out else p.returncode,
          "exit_code_authoritative": confirmed and not timed_out,
          "process_exit_confirmed": confirmed, "stdout": stdout, "stderr": stderr,
          "timed_out": timed_out, "stdout_truncated": stdout_truncated,
          "stderr_truncated": stderr_truncated, "stdout_bytes_seen": seen["stdout"],
          "stderr_bytes_seen": seen["stderr"], "capture_error": capture_error,
          "output_complete": confirmed and all(eof.values()) and capture_error is None and not stdout_truncated and not stderr_truncated,
          "output_limit_bytes_per_stream": LIMIT, "descendant_termination_confirmed": False}
print(json.dumps(result, sort_keys=True))
"#;

pub async fn hardware_snapshot(params: HostParams) -> Result<String> {
	let host = runtime_config()?.host(&params.host)?;
	let output: Value =
		run_python_json(host, HARDWARE_CODE, &json!({}), Duration::from_secs(20)).await?;
	Ok(serde_json::to_string_pretty(&output)?)
}

pub async fn service_status(params: ServiceStatusParams) -> Result<String> {
	let host = runtime_config()?.host(&params.host)?;
	if params.services.is_empty() || params.services.len() > 64 {
		bail!("services must contain 1..64 exact names");
	}
	for service in &params.services {
		if !valid_name(service) {
			bail!("invalid service name `{service}`");
		}
	}
	let platform = match host.platform {
		Platform::Linux => "linux",
		Platform::Macos => "macos",
	};
	let output: Value = run_python_json(
		host,
		SERVICE_CODE,
		&json!({"platform": platform, "services": params.services}),
		Duration::from_secs(20),
	)
	.await?;
	Ok(serde_json::to_string_pretty(&output)?)
}

#[path = "inspection_result.rs"]
mod inspection_result;

pub async fn network_inspect(params: HostParams) -> Result<String> {
	let host = runtime_config()?.host(&params.host)?;
	let output: Value =
		run_python_json(host, NETWORK_CODE, &json!({}), Duration::from_secs(25)).await?;
	inspection_result::network_result(&output)
}

pub async fn privileged_action(params: PrivilegedActionParams) -> Result<String> {
	if params.args.len() > 32
		|| params
			.args
			.iter()
			.any(|arg| arg.len() > 8192 || arg.contains('\0'))
	{
		bail!("privileged action arguments exceed policy limits");
	}
	let host = runtime_config()?.host(&params.host)?;
	let action = host.privileged_actions.get(&params.action).ok_or_else(|| {
		anyhow::anyhow!(
			"privileged action `{}` is not configured for `{}`",
			params.action,
			params.host
		)
	})?;
	if params.args.len() != action.extra_arg_patterns.len() {
		bail!(
			"privileged action `{}` requires exactly {} policy-matched arguments",
			params.action,
			action.extra_arg_patterns.len()
		);
	}
	for (index, (arg, pattern)) in params
		.args
		.iter()
		.zip(action.extra_arg_patterns.iter())
		.enumerate()
	{
		check_protected_input(&params.host, arg)?;
		let regex = Regex::new(&format!(r"\A(?:{pattern})\z"))?;
		if !regex.is_match(arg) {
			bail!(
				"privileged action `{}` argument {} violates its policy",
				params.action,
				index
			);
		}
	}
	let request = json!({
		"executable": action.executable,
		"fixed_args": action.fixed_args,
		"args": params.args,
		"timeout_seconds": action.timeout_seconds.min(300),
	});
	require_privileged_intent(audit(
		"privileged_action_requested",
		&params.host,
		&params.action,
		&json!({"phase":"intent","remote_operation_submitted":false}),
	))?;
	let remote: Result<Value> = run_python_json(
		host,
		PRIVILEGED_CODE,
		&request,
		Duration::from_secs(action.timeout_seconds.min(300) + 10),
	)
	.await;
	let output = retain_privileged_outcome(&params, remote);
	let completion = audit(
		"privileged_action",
		&params.host,
		&params.action,
		&json!({"phase":"result","exit_code":output["exit_code"],"timed_out":output["timed_out"]}),
	);
	Ok(serde_json::to_string_pretty(
		&retain_privileged_after_audit(output, completion),
	)?)
}

fn retain_privileged_after_audit(mut result: Value, outcome: Result<()>) -> Value {
	if !result.is_object() {
		result = json!({"result":"invalid_remote_acknowledgement","outcome":"unknown","automatic_retry":false});
	}
	result["audit_recorded"] = json!(outcome.is_ok());
	result["automatic_retry"] = json!(false);
	if outcome.is_err() {
		result["audit_warning"] = json!(
			"Administrator-pinned action result retained; completion audit unavailable. Do not repeat the action automatically."
		);
	}
	result
}

fn require_privileged_intent(outcome: Result<()>) -> Result<()> {
	outcome.map_err(|_| {
		anyhow::anyhow!("Pinned action intent audit unavailable; no action request dispatched")
	})
}

fn unknown_privileged(params: &PrivilegedActionParams) -> Value {
	json!({"host":params.host,"action":params.action,"result":"action_outcome_unknown","outcome":"unknown","automatic_retry":false,
		"reconcile_warning":"Administrator-pinned action outcome is not confirmed. Reconcile its existing effect; do not repeat automatically."})
}

fn retain_privileged_outcome(params: &PrivilegedActionParams, remote: Result<Value>) -> Value {
	let mut value = match remote {
		Ok(value) => value,
		Err(_) => return unknown_privileged(params),
	};
	if !value.is_object()
		|| !value["exit_code"]
			.as_i64()
			.is_some_and(|code| (-128..=255).contains(&code))
		|| !value["timed_out"].is_boolean()
		|| !value["exit_code_authoritative"].is_boolean()
		|| !value["process_exit_confirmed"].is_boolean()
		|| !value["stdout_truncated"].is_boolean()
		|| !value["stderr_truncated"].is_boolean()
		|| !value["output_complete"].is_boolean()
		|| !value["stdout_bytes_seen"].is_u64()
		|| !value["stderr_bytes_seen"].is_u64()
		|| value["output_limit_bytes_per_stream"] != 524288
		|| value["descendant_termination_confirmed"] != false
		|| !(value["capture_error"].is_null() || value["capture_error"] == "read_failed")
		|| (value["timed_out"] == true
			&& (value["exit_code"] != 124 || value["exit_code_authoritative"] != false))
		|| (value["timed_out"] == false
			&& (value["process_exit_confirmed"] != true
				|| value["exit_code_authoritative"] != true))
		|| (value["output_complete"] == true
			&& (value["process_exit_confirmed"] != true
				|| value["stdout_truncated"] != false
				|| value["stderr_truncated"] != false
				|| !value["capture_error"].is_null()))
		|| value["stdout"]
			.as_str()
			.is_none_or(|text| text.len() > 524288)
		|| value["stderr"]
			.as_str()
			.is_none_or(|text| text.len() > 524288)
	{
		return unknown_privileged(params);
	}
	if let Some(fields) = value.as_object_mut() {
		fields.retain(|key, _| {
			matches!(
				key.as_str(),
				"exit_code"
					| "exit_code_authoritative"
					| "process_exit_confirmed"
					| "stdout" | "stderr"
					| "timed_out" | "stdout_truncated"
					| "stderr_truncated"
					| "stdout_bytes_seen"
					| "stderr_bytes_seen"
					| "capture_error"
					| "output_complete"
					| "output_limit_bytes_per_stream"
					| "descendant_termination_confirmed"
			)
		});
	}
	value["host"] = json!(params.host);
	value["action"] = json!(params.action);
	let envelope = serde_json::to_string_pretty(&value).ok().and_then(|text| {
		serde_json::to_vec(&rmcp::model::CallToolResult::success(vec![
			rmcp::model::ContentBlock::text(text),
		]))
		.ok()
	});
	if envelope.is_none_or(|bytes| bytes.len() > crate::utils::truncation::MAX_RESULT_BYTES - 4096)
	{
		return unknown_privileged(params);
	}
	value
}

#[cfg(test)]
#[path = "inspect_tests.rs"]
mod tests;
