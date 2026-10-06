# Non-shipping native checkpoint experiment

The files in this directory are retained research source, not registered or compiled into the runtime. The native acceptance used a development build and proved capture/same-PID restoration, but failed automatic continuation because the restored task retained its stop state. A subsequent explicit signal to only that known fixture allowed cleanup and showed matching memory/pipe hashes; this does not turn the failed acceptance into a pass.

The current production HostConfig deliberately has no checkpoint binary/pin fields. The experiment originally added those fields, and its prototype Rust module is therefore not a drop-in compiled module. No CRIU image or raw memory is committed. Existing standalone CRIU memory/external-pipe qualification remains a separate, narrower experiment.
