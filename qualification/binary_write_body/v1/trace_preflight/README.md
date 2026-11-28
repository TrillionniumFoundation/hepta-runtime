# Locked-write kernel observer preflight

This frozen source first rereads every byte, file, mode and directory of build 031d7ea330ae0722756d72b83714e5120aa43342. It then runs four distinct 60-second-bounded CPython kernel probes: FileIO append and buffered read, FD zero, real seccomp EIO, and real RLIMIT partial write with SIGXFSZ. These probes execute no HIA target and do not invoke the original write body. The separate guarded reader reads all process streams, complete traced kernel entry/exit structs and observed memory, private frames, EOF descriptors and final file bytes. No ptrace call writes registers or memory; only syscall stepping, fixed observation options and GET_SYSCALL_INFO are allowed. process_vm_readv reads the actual stopped child.

The original write fixture is frozen here for syntax and provenance review only. Its locked suite and helpers retain the original AST including unreachable upload branches. Actual write qualification remains pending. This preflight does not replace the public runtime, publish routing, remote SSH transport or the existing implementation.

No completed or unknown probe is replayed on failure. Source, domain, readers and workflow are fully reread before the branch trigger. All complete and failed evidence remains in the exported archive.
