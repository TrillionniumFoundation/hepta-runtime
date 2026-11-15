#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Bind real completed dependencies and create one first-attempt capacity input.

No SSH, agent observation, compiler, monitor, fixture or campaign is started.
The actual input is created only after every completed prerequisite is verified.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets

import run_capacity_campaign as campaign


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=Path, required=True)
    args = parser.parse_args()
    raw = campaign.bootstrap_read(args.seed)
    seed = json.loads(raw)
    campaign.need(seed.get("schema") == "hepta-r34-capacity-campaign-seed/v1"
                  and seed.get("status") == "actual_dependencies_ready", "campaign seed remains unsealed")
    launcher = campaign.bootstrap_read(campaign.PACKAGE / "run_capacity_campaign.py")
    value = {key: item for key, item in seed.items() if key not in {"schema", "status"}}
    value.update(schema="hepta-r34-capacity-campaign/v1", status="sealed_actual_inputs", attempt="01",
                 launcher_sha256=hashlib.sha256(launcher).hexdigest(), holder_sha256=campaign.HOLDER_SHA,
                 control_parent=campaign.PARENT, automatic_retries=0, on_failure="stop_remaining_cells",
                 quiet_seconds=90, cell_timeout_seconds=campaign.CELL_SECONDS,
                 cells=[{"index": index, "label": label, "arm": arm, "victim": victim, "nonce": secrets.token_hex(12)}
                        for index, (label, arm, victim) in enumerate(campaign.ORDER)])
    modules, manifest = campaign.bootstrap(value, value["launcher_sha256"])
    parent = modules["parent"]
    bindings = []

    def bind(path, expected=None, maximum=128 * 1024 * 1024, retain=False):
        result = parent.checked(path, expected, maximum, retain)
        bindings.append(result[0] if retain else result)
        return result

    campaign.prerequisites(value, modules, manifest, bind)
    parent.bind_compiler_monitor_inputs(value, bind)  # Definitions/policy only; no monitor start.
    campaign.need(not os.path.lexists(campaign.INPUT) and not os.path.lexists(campaign.OUTPUT)
                  and all(not os.path.lexists(path) for path in campaign.SOCKETS), "first capacity namespace already exists")
    for row in bindings:
        campaign.need(parent.checked(row["path"], row) == row, "actual prerequisite changed during materialization")
    campaign.need(campaign.bootstrap_read(args.seed) == raw, "actual dependency seed changed")
    value["materialization"] = {"seed": parent.checked(args.seed),
                                "input_bindings": bindings, "campaign_executed": False,
                                "native_build_or_fixture_started": False,
                                "actual_runtime_ci_success_verified": True}
    parent.create(campaign.INPUT, parent.canonical(value))
    print(json.dumps({"input": parent.checked(campaign.INPUT), "executed": False,
                      "fixed_cells": [row["label"] for row in value["cells"]], "automatic_retries": 0}, sort_keys=True))


if __name__ == "__main__":
    os.umask(0o077)
    main()
