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

const SERVICE_CODE: &str = r#"
import json, subprocess, sys
q = json.load(sys.stdin)
result = []
if q["platform"] == "linux":
    props = "LoadState,ActiveState,SubState,UnitFileState,Result,MainPID,ExecMainStatus,Description"
    for name in q["services"]:
        p = subprocess.run(["systemctl", "show", "--no-pager", "--property=" + props, "--", name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        values = {}
        for line in p.stdout.splitlines():
            if "=" in line:
                key, value = line.split("=", 1); values[key] = value
        result.append({"name": name, "exit_code": p.returncode, "properties": values, "stderr": p.stderr.strip()})
else:
    for name in q["services"]:
        p = subprocess.run(["launchctl", "print", "system/" + name], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        result.append({"name": name, "exit_code": p.returncode, "stdout": p.stdout[-65536:], "stderr": p.stderr.strip()})
print(json.dumps({"services": result}, sort_keys=True))
"#;

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
import json, subprocess, sys
q = json.load(sys.stdin)
argv = ["sudo", "-n", q["executable"], *q.get("fixed_args", []), *q.get("args", [])]
try:
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=float(q.get("timeout_seconds", 30)))
    result = {"exit_code": p.returncode, "stdout": p.stdout[-1048576:], "stderr": p.stderr[-1048576:]}
except subprocess.TimeoutExpired as exc:
    result = {"exit_code": 124, "stdout": (exc.stdout or "")[-1048576:], "stderr": "privileged action timed out"}
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

pub async fn network_inspect(params: HostParams) -> Result<String> {
	let host = runtime_config()?.host(&params.host)?;
	let output: Value =
		run_python_json(host, NETWORK_CODE, &json!({}), Duration::from_secs(25)).await?;
	Ok(serde_json::to_string_pretty(&output)?)
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
	let output: Value = run_python_json(
		host,
		PRIVILEGED_CODE,
		&request,
		Duration::from_secs(action.timeout_seconds.min(300) + 10),
	)
	.await?;
	audit("privileged_action", &params.host, &params.action, &output)?;
	Ok(serde_json::to_string_pretty(&output)?)
}
