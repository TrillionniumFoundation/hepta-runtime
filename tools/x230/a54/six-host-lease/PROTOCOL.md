# One owned current-agent session for the original eight-stage gate

The main account owns one original OpenSSH process and its pidfd/wait4 receipt.
That connection forwards the already observed main keyring agent to X230 using
the same fixed public IdentityFile and host-key pins as the successful readiness
probe. X230 owns one original Python driver process and its pidfd/wait4 receipt.
No worker is detached from that session. No agent, key, authentication file,
network setting or production service is changed.
Main keeps the original SSH stream bytes and final custody report in one fresh
mode-0700 `/tmp/hepta-a54-main-lease-<plan nonce>` directory; stdout returns its
receipt. X230 separately retains its original driver streams and supervisor
report. These evidence directories never contain private-key contents.

The first request carries a frozen plan. Before any output or business fixture is
created, X230 verifies the exact A54 r01 completed qualification, 175 current
source hashes, the qualified executable, original A40 qualification/executable,
the binding-only driver, the five actual existing helper files, the old six-host
public SSH inputs, the current forwarded agent frame and X230 machine identity.
The driver binding must preserve the six host names and all eight stage budgets.
A ready reply binds these observations to the plan SHA. Only one subsequent
`start` request may launch the driver. Partial writes and a missing start reply
remain an unknown original attempt; there is no retry or replacement process.

The driver output is a fresh `a54-native-six-host-r01` directory. The independent
supervisor evidence is a fresh `a54-six-host-lease-r01` directory. Pool sockets
use a separate fresh `/home/qian/ha54-r1` directory. Stage canary directories keep
the original driver's nonce-bound allowlist and create-only behavior. Existing
fixtures and failures are never deleted or overwritten.

All eight stage budgets are unchanged: 300, 400, 480, 250, 250, 250, 250 and 900
seconds (3,080 total). The remote supervisor allows 3,500 seconds for the driver,
including its original preflight, source fences and final evidence accounting.
Main holds its original SSH connection for a maximum 3,700-second active window.
These envelopes do not renew any original stage or RPC deadline.

Main keeps stdin open and sends bounded, sequenced heartbeat records. X230 treats
EOF, invalid control input, a missing heartbeat, an explicit stop, a termination
signal or its absolute driver deadline as a stop request. It first sends SIGINT
only to the original driver pidfd. It gives that driver 80 seconds, covering its
unchanged 60-second helper cleanup plus 10-second forced reap window and report
finalization. If necessary it sends SIGKILL only to that same original driver
and waits a further 10 seconds. Any such supervisor stop remains a failed gate.
No group or enumerated remote PID is signalled.

On a local stop, main first closes the control stdin and keeps the authenticated
SSH/agent connection alive for 110 seconds so X230 can finish its cleanup. Only
after this fixed grace may main signal and reap its own original SSH child.
Repeated signals never reset a deadline. On an actual network loss the agent may
become unavailable; that is a failure, never a successful cleanup assertion.

Only a complete original driver report passing all eight original gates, a clean
driver wait4/EOF receipt, unchanged input/agent fences, and a clean original SSH
wait4/EOF receipt can pass this envelope. A wrapper's original-child cleanup does
not replace the driver's own descendant/EOF/witness conditions. No unknown
attempt, unconsumed reply or forced cleanup can be relabelled as a pass.

Preparation runs only short local child/protocol selfchecks. Root owns every
remote probe and the eventual native gate. Actual r02 qualification and final
driver hashes are required before a runnable plan can be frozen.
