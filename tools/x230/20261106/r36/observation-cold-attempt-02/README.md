# First cold02 OBS attempt — baseline preflight stopped

The original held-agent job `1a1b20946a5-fc05-7c24` ended with exit code 1, complete durable stdout (325 bytes), empty stderr, no timeout and no automatic retry. The original holder report records the foreground process exited, the owned agent was reaped, and its directory and socket were absent after cleanup.

The original 90-second quiet period and continuous compiler-monitor audit passed. Inputs and source maps remained unchanged. The first native-observation stage then stopped during the initial six-host complete-output preflight for baseline A (accepted R24): five hosts returned the expected original outputs, while pocket4 returned `observation SSH child exited` after about 8.07 seconds. No measured or warmup cells were recorded; candidate B never started. Effect starts and remote mutation tool calls were both zero. The original native interrupted shutdown exited 0 and reported no observed descendant survivors.

This is an incomplete six-host preflight, not a throughput comparison or a candidate regression result. The first attempt is retained intact. No automatic measurement retry or normal lifecycle run occurred. The candidate remains unadopted; R24 remains accepted. Further read-only connection diagnosis is separate from this attempt.

The seven-stage OBS protocol and all original throughput, latency, CPU, RSS, boundary and recovery thresholds remain unchanged. Qualification and exact native CI had already passed 1,647 tests with zero failures or retries. Their full archives are retained separately; no audit or test is rerun by archive collection.
