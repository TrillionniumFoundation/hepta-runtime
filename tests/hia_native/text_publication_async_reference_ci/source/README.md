# Publisher asynchronous reference v1

This isolated package compiles the exact current target's publisher and gateway through RMCP 3.9.0. All 120 original spans and the complete publisher module are retained. The 62-file ordinary reference is preserved byte for byte under `ordinary/`; the new wrapper has three explicit reversible text changes and a separate observer module.

The observer exposes only private owned-process commands. It records actual SDK service responses, original handler entry/return/Drop, complete cache/history/lock/session observations, and Linux flock syscall state for this process's owned directory. Public cancellation notifications and EOF use the actual SDK. A separate private direct domain aborts the actual gateway task to observe future Drop. Queued experiments explicitly use one blocking thread occupied by an owned Condvar fixture; they do not claim the SDK default pool has that size.

This first source freeze is a reference build candidate. It contains no expected wire, no native async implementation, and no lifecycle PASS. Rust runs only in fresh CI 1.95.0. Individual build steps retain 180 seconds; the whole job retains 15 minutes. Semantic processes will retain 60-second exchanges and 180-second process limits.
