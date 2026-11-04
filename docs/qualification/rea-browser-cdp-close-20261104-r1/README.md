# Browser close and publication review

The review found that clearing the observed target session before Browser.close ignored late target events, and a blanket is_ok() swallowed protocol and budget failures. The repair separates browser-command routing from target event observation, drains to clean EOF on the original deadline, validates settled state afterward, and captures final loopback counters only after Chrome cleanup and fixture thread shutdown.

The extracted test receipt reports 11 tests: the original three settle tests plus six close groups and two actual loopback tests. Its cancellation and input-admission dependencies were stubs; this is not a full runtime or real Chrome qualification. Full combined release qualification is recorded separately.

The publication review also narrowed receipt fsync claims to completed HAR publication. A visible receipt cannot attest its own later directory sync; the original durable job must succeed and its post-sync complete event must confirm receipt publication. The actual native browser harness checks that contract. Original failure evidence remains in the earlier native-browser qualification directory.
