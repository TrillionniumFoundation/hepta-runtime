# Session and process runtime lifetime

The ordinary public stdio entry still calls `pump_finish`. Its unchanged
single-session policy is now expressed as three actual native functions:
`pump_finish_service`, `pump_finish_runtime`, then
`pump_finish_storage`. HIA request registry58, all futures and all worker
owners are byte-identical.

`pump_initialize_shared(port)` accepts an already owned native process
port, then invokes the real port attach for this engine. Passing zero uses the
existing create path. The ordinary entry still creates its own port. The
capability is private; it never comes from request JSON, metadata or configuration.

`pump_begin_finish` begins actual registry EOF and returns to the host.
`pump_finish_service` preserves old sends, bounded drain, writer close,
token delivery, handler destruction, registry retirement and actual port detach.
It sets phase4 only after those operations. It does not close the process-wide
publication pool or shared port.

After every session has detached, the process host calls
`pump_finish_runtime` once. It performs the original port shutdown,
publication close and actual service/reap/destroy sequence. Only afterward may
the host retire each session's scratch and owned journal with
`pump_finish_storage`. The single-session wrapper keeps the original order.

The forthcoming two-session fixture will use distinct real engines and PM
registries, one real port, one shared publication pool, separate OS transport
pipes and retained complete mappings. This source gate runs no application.
It does not qualify multi-session Bellman READY routing, which still needs
a process-level cross-session delivery owner. Public async, complete SDK,
136 handlers and production installation remain false.
