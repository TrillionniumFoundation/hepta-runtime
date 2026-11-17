# Retained publication lifecycle comparison, revision 3

This revision runs no application. The first actual two-session capture remains source 6fc17546e226b3fab67208ea03b0ce07595816ad / run 44108055858, artifact 14339243128. The original thirty input processes remain ae6206b4d8b6ffa347e7cadd8fb97a5a07946a03 / run 44071799019.

Revision 2 correctly retained a wire mismatch at command 16. Pure byte inspection 4c804de9c7fd27bb7e2a3b8396d6a4fcaa7d67fa / run 44111166762 identified the sole differing token as the seven-field version generated from each process's real published-file stat. Its device, inode and timestamps cannot be equated between distinct executions.

The new version reader requires the exact original create-only input, complete published bytes/digest, all result booleans and every one of the seven version fields to equal that side's actual final filesystem observation. It changes only the single escaped numeric version token for comparison. All other public response bytes remain exact. Full filesystem identity relationships, mode, owner relation, links, xattrs and contents are still compared. It does not synthesize expected wire or discard a physical version field.

All prior source and application captures are immutable. The old comparison remains FAIL. This new reader still requires full byte/stream/control/state custody and all original budgets. The remaining public captures have retained actual failures, the eight direct future inputs are not yet executed, and full worker-journal semantic admission remains pending. Nothing here is a full thirty-case, SDK, public-installation or remote qualification.
