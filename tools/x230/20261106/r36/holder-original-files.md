# Original Mac holder files to retrieve

Producer: the unchanged `held_agent_campaign_02.py`, SHA-256 `715e996217c7d33a7483354f16f2d39c9a033f51f3a20a52484495a00262dd65`. This is a static producer contract; it does not assert that any planned directory exists or succeeded.

Only these three exact output directories are in scope, after their creation is observed:

- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/observation-holder-01`
- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/lifecycle-holder-01`
- `/Users/qianqi/work/hepta-runtime-x230-r36-20261106/async-read-holder-01`

First fetch the original `report.json`. Its `log_files` array supplies exact filenames, byte counts and SHA-256 values. Fetch every actual original listed there, preserving empty files and failures. The producer excludes `report.json` and `report.next` from that array, so `report.json` must be fetched separately.

| Exact filename or producer format | What it preserves |
| --- | --- |
| `report.json` | Original holder outcome, launcher hash, remote return code, retry/timeout flags and owned-agent closure |
| `remote-script.py` | Exact script sent through the foreground SSH connection |
| `forwarded.stdout` | Complete original remote launcher stdout |
| `forwarded.stderr` | Complete original remote launcher stderr |
| `owned-agent.stderr` | This holder's owned agent stderr |
| `identity-discovery-{index:02d}.stderr` | Original stderr for each configured target's `ssh -G`; indices come from actual output |
| `identity-load-{index:02d}.stdout` | Original stdout for each actual configured identity load |
| `identity-load-{index:02d}.stderr` | Original stderr for each actual configured identity load |
| `holder.error.txt` | Original traceback only if the Python `except BaseException` handler runs and writes it |

Some files are absent if an earlier step failed; do not create empty replacements. Use `log_files` as the final inventory even if an early failure prevented `identity_discovery` from being assigned to the report. Cross-check any reported discovery/load rows against those actual files. A successful completed holder normally has no `report.next`: this is an exclusive temporary file replaced atomically by `report.json`. If it remains, preserve it as interrupted/unfinished evidence and investigate closure rather than interpreting it as the final report.

A nonzero remote return code is handled separately from Python exceptions. The producer records `passed=false` and `error.type=RemoteCampaignFailed` in `report.json`, without creating `holder.error.txt`. The actual R36 lifecycle holder returned 1 with that error type; its original `log_files` has no `holder.error.txt`, while its owned agent was reaped and its directory/socket were absent. That absent traceback file is expected. The original lifecycle holder report SHA-256 is `f885250569a1ab28089ccc618bc08bb20bb90942a8a8a9f12512494d4245f44e`.

The R36 observation and lifecycle holder directories were observed. The async-read directory remains an approved planned path only: the R36 async supplement was not executed after the required lifecycle gates failed. Do not infer that the async holder directory or any of its output files exists.

The producer intentionally never persists discovery stdout, raw SSH configuration, configured key bytes, the full environment, or the agent socket body. Do not fetch the controller plist, runtime configuration, `.ssh` bodies or `/tmp/hr19a-*` paths. Agent directory/socket names in the report are metadata. Native job terminal/output custody records are separate from these holder directory files.

The approved X230 evidence exporter accepts copies only under `holder-inputs-01/<holder-directory-name>/...`, with an observed copy manifest binding each original exact Mac path, byte length and SHA-256. Do not mark planned or missing outputs as observed.
