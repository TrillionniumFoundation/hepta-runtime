def select_trace(controller, parser, bench, expected_boot, all_done_ns, next_start_ns, correlation):
    binding, startup, shutdown = controller["binding"], controller["startup"], controller["shutdown"]
    directory = Path(binding["directory"])
    capture = shutdown["transport_capture"]
    raw, raw_pin = regular(directory / "transport-responses.jsonl", MAX_REPORT)
    index, index_pin = regular(directory / "transport-responses.index.jsonl", MAX_REPORT)
    for observed, recorded, filename in (
        (raw_pin, capture["raw"], "transport-responses.jsonl"),
        (index_pin, capture["index"], "transport-responses.index.jsonl"),
    ):
        need(recorded.get("file") == filename and recorded.get("bytes") == observed["bytes"]
             and recorded.get("sha256") == observed["sha256"], "original transport identity differs")
    relative = directory.relative_to(ROOT).as_posix()
    originals = {relative + "/transport-responses.jsonl": raw,
                 relative + "/transport-responses.index.jsonl": index}

    class ClosedOriginalBytes:
        def read(self, member):
            need(member in originals, "correlation requested an unbound original byte stream")
            return originals[member]

    need(correlation.ROOT == str(ROOT), "correlation root differs from the sealed adapter")
    calls = correlation.transport_calls(ClosedOriginalBytes(), controller)
    trace, trace_pin = regular(binding["trace"], MAX_TRACE)
    summary = parser.summarize(trace, trace_pin["sha256"])
    lines = trace.splitlines()
    header, footer = json_object(lines[0]), json_object(lines[-1])
    need(header["mode"] == binding["mode"] and header["pid"] == startup["pid"]
         and header["start_ticks"] == startup["birth_ticks"] and header["boot_id"] == expected_boot
         and header["declared_elf_sha256"] == SPEC["qualified_feature_binary"]["sha256"]
         and header["elf_hash_verified_here"] is False,
         "trace mode/ELF/controller birth binding differs")
    need(startup["start_monotonic_ns"] <= header["start_monotonic_ns"] <= startup["ready_monotonic_ns"]
         and footer["end_monotonic_ns"] <= min(all_done_ns, next_start_ns),
         "trace lies outside original controller lifetime boundaries")
    selected = []
    result = {
        "binding": binding, "startup": startup, "trace": trace_pin,
        "raw_transport": raw_pin, "raw_transport_index": index_pin,
        "original_request_groups": {call["row_key"]: call for call in calls},
        "trace_summary": summary,
        "phase_cpu_available": binding["mode"] == "on",
        "category_phase_summaries": None,
        "whole_trace_cpu_is_measured_cell_cpu": False,
        "native_auditor_reexecuted_here": False,
        "wire_native_id_source": "absent on status/read; identity comes only from the bound trace",
        "off_empty_trace_is_zero_work_cpu_claim": False,
        "validation_whole_cpu_uses_parent_inclusive_field": True,
        "read_loop_phase_includes_original_reads_comparison_or_hash_and_cancellation_checks": True,
    }
    if binding["mode"] == "on":
        rows = [json_object(line) for line in lines[1:-1]]
        per_request, scopes = correlation.phase_values(rows, summary, parser)
        selected = correlation.correlate(calls, summary, scopes, per_request, result)
        result["new_selective_phase_arithmetic_reconciled_with_parser"] = True
        result["category_phase_summaries"] = {
            category: correlation.aggregate([item for item in selected if item["category"] == category], parser)
            for category in ("preflight", "warmup", "measured", "restart")
            if any(item["category"] == category for item in selected)
        }
        measured = [item for item in selected if item["category"] == "measured"]
        if measured:
            cells = [interval for category, _, interval in controller["groups"] if category == "measured"]
            need(len(cells) == 1, "measured controller has no unique original cell")
            result["measured_controller_cpu_comparison"] = correlation.measured_counter(
                {"raw_timing": cells[0]}, startup, measured)
    else:
        need(summary["requests"] == [], "OFF arm recorded request events")
    result["selected_on_requests"] = selected
    result["selected_on_counts"] = {name: sum(item["category"] == name for item in selected)
                                     for name in ("preflight", "warmup", "measured", "restart")}
    return result
