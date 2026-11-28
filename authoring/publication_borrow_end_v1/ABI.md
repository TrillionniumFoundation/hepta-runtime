# Publisher terminal and Scope borrow lifetime

Base production: f8857cbd18b3dedb38718f68822c072053b03233. This revision changes three mechanical source files. Every HIA program and image, the 69 descriptor table, all existing PN ranges, and the shared request/session layout remain unchanged. It has no inherited public async qualification.

## Actual failed send

The existing result_publication HIA has alternative terminal operations 11 (cancel) and 12 (drop). Its f0 blocks b38/b40 reject phase 0 or phase 5 before dispatch; b43 selects either operation and b49 clears the live arena and sets phase 5. An actual EPIPE or explicit send-future drop therefore invokes operation 11 once, checks the actual 64-byte reply, then retires native storage. The former second operation 12 was a duplicate terminal transition and correctly returned refusal. The adapter preserves return 74 to the SDK send task. Positive write ACK, EAGAIN, ordinary successful operation 12 and all HIA bytes are unchanged.

## Scope descriptor 68

The actual caller66 child6 copies the complete Forget reply before advancing to hints and the original Scope Close. Descriptor68 borrows Scope6 workspace/output; it owns no mmap. The pending node retains that alias while the actual parent CALL is suspended. On settled frontend detach, the existing complete trace first captures the live alias and complete mapped bytes. A fixed mechanical release then verifies the current closed Scope6 identity, exact mappings/capacity and inactive continuation and clears only the seven non-entry words of the saved alias. No owner operation is called and no mapping is released there.

A subsequent request may restore its actual Scope6 and retire the closed previous Scope mapping. Completed response nodes can remain in the SDK send queue after that restoration; they must retain no borrowed address into the retired Scope. Node retirement now requires descriptor68 to be empty. The actual caller/gateway/Scope and cancellation policy remain unchanged. A direct future drop skips Forget through the already fixed caller path; a notification cancellation continues the actual handler. EOF still uses the existing SDK drain ordering.

## Source evidence

CHANGES.json contains unique exact before/after edits and complete raw pins. author.py applies and reverses every edit, verifies all source rows and all unchanged HIA bytes, and copies the complete candidate closure. The original failed applications and incomplete final trace are preserved in FAILURES.json. Source checks and build-only checks do not imply full 30-case lifecycle or production qualification.
