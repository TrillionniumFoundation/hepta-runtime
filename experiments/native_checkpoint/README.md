# Non-shipping native checkpoint experiment

The files in this directory are retained research source, not registered or compiled into the runtime. The native acceptance used a development build and proved capture/same-PID restoration, but failed automatic continuation because the restored task retained its stop state. A subsequent explicit signal to only that known fixture allowed cleanup and showed matching memory/pipe hashes; this does not turn the failed acceptance into a pass.

The current production HostConfig deliberately has no checkpoint binary/pin fields. The experiment originally added those fields, and its prototype Rust module is therefore not a drop-in compiled module. No CRIU image or raw memory is committed. Existing standalone CRIU memory/external-pipe qualification remains a separate, narrower experiment.

The new two-phase production candidate is described in `docs/CHECKPOINT_LIFECYCLE.md`. It reports a stopped restore and requires a separate identity-bound resume. Its new acceptance is independent of the failed automatic-continuation attempt retained here; no historical failure is relabelled.
