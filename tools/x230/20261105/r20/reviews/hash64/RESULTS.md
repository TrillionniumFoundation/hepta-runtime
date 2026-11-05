# X230 R20 request-hash 64-byte follow-up: closed independent result

**Decision: reject the fixed 64-byte candidate and end this buffer direction under the preregistered stopping rule.** Both small-request cases regress beyond the original 2% CPU gate. The conditional integration draft remains unadopted. The selected R21 source contains only the STATUS and CANCEL lazy-import changes.

## Raw verification

225 independent checks passed over 96 fresh-worker cells and 102 original stages (six preparation/check stages plus 96 workers). All source, raw stdout/stderr, stage wait/reap and exit status, actual reduced lock, and remote ELF hash witnesses agree. Two Cargo tests passed and the separate semantic process covered six canonical fixtures plus seven buffer boundary cases. A separate Python JSON construction reproduces every canonical length and SHA256.

Integer CPU nanoseconds and iteration counts were used to independently recompute all block statistics, arm medians and resource lists. No performance rerun or replacement sample was used. Frozen preparation files retain their original prepared-only flags; actual compilation/tests/measurement are proved by the closed report and original stage records.

## CPU screen

Values are the percentage change in the within-block mean CPU per digest, B versus A. The last numeric column is the median of four block ratios, not the ratio of pooled arm medians.

| Scene | Block 0 | Block 1 | Block 2 | Block 3 | Median | Gate |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| small_176 | +11.5842% | +1.7936% | +5.5222% | +4.8732% | +5.1977% | **reject** |
| escaped_small | +2.4008% | +8.7576% | +4.6900% | +5.5488% | +5.1194% | **reject** |
| plain_64k | -3.0497% | +2.9051% | -2.7247% | -0.6644% | -1.6945% | pass |
| escaped_64k | -15.0338% | -18.9460% | -16.2178% | -14.5229% | -15.6258% | pass |
| plain_1mib | +0.4931% | +0.5880% | -0.3557% | +1.3698% | +0.5405% | pass |
| escaped_1mib | -11.2818% | -8.2995% | -12.0137% | -9.9341% | -10.6079% | pass |

Both large escaped fixtures improve by at least 5% in the median and in all four blocks. The two small cases regress in all four blocks, with medians above 2%, so the original combined screen is false. The smaller-buffer hypothesis does not justify overriding that rule or trying another size. No hash buffering enters the final source.

## Measurement and memory limits

CLOCK_PROCESS_CPUTIME_ID measures the digest loop including the common full-hash equality check. Startup, fixture creation, warmup and resource reads are excluded. The component does not measure complete SSH/status/read/start throughput. No statistical-significance or global-optimum claim is made.

Observed lifetime HWM values in bytes: 21102592. These whole-process high-water observations and before/after VmRSS snapshots do not measure per-call allocations or cluster RSS, and establish no RSS gain. The high-water origin was not independently diagnosed.

## Transfer and identities

The exact 170,704-byte archive arrived in **three chunks: 65,536 + 65,536 + 39,632 bytes**, with one pinned file version and matching independent chunk hashes. There was no transfer error or retry. All 333 regular members (332 source/evidence files plus export manifest) were size/SHA-verified before extraction into a fresh directory. No ELF, object or rlib is included.

| Artifact | Bytes | SHA256 |
| --- | ---: | --- |
| Original archive | 170,704 | `2a0293ccc4a413321b4a53844d236c34428a6d667e61eb75036d34bee69f9227` |
| Original report | 107,669 | `347626e60c950bcaeacafaaa6c863834d9dac0c75524372612cc93f402800d4b` |
| Raw cells | 93,217 | `427cb430b50dc1b9a013499f2f23dbc5bb6d525efe6a7bc88ac8060568e58736` |
| Resolved lock | 5,094 | `ec33648eaa4429e75dbcc81d67281f5424126f82996c602d3143b27e9be5ac66` |
| Input manifest | 2,078 | `ccb0092124f14438c37de36ee89ca08e22bbb3aab88f8b245502e73c4187050b` |
| Independent review | 27,182 | `d195aa35d751706ea3fb718706d93547319dc0738e793bd2c0ce1f9331079da9` |
| Offline audit tool | 16,659 | `9845b58e86a8a662fe20f282967869f58058816f28844eb0d35c92f78a9ff366` |

The excluded compiled probe ELF was remotely hashed as 461,872 bytes / `2687d7bf5230ccde6d1d36ccddd63a4ac69b38f34a92fadcb5da741feddebdfb`, with stable link count 2. The exporter permits stable hardlinks only for this explicit compiler-output hash witness; all archived source/evidence files retain the single-link requirement. This is a remote byte-identity witness, not an offline reproduction of the ELF.

```sh
python3 -B recompute_01.py --evidence received --output independent-review-replay.json
```

The evidence exporter completed once with exit 0. All remote reads/export operations have ended. The preceding 4 KiB failure, this 64-byte failure, and the unadopted integration draft are retained separately; R20 formal six-host measurements were never run and are superseded by the final R21 workflow.
