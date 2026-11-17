# Cache-forget source review

The fixed Scope owner is `native/request_scope_lifecycle.hepta`, SHA256 `9db58f6b764221c271fced0a3a25bd523815ce591fdc7c699fb1703194826d84`. Its op 9 dispatch clones the actual cache lease and forwards the complete cache request; the lease owner advertises `min(8 MiB, output_capacity - 64)` to the cache child. The unchanged View engine's cache output is 1,052,672 bytes, while the generic Scope alias originally provides 8 MiB. The checked `view_call_scope_bridge.S` requires each child output borrow to fit that child's physical output. This accounts for a refused nested borrow, not a file publisher or destructor error.

The new fixed descriptor provides a 96-byte Scope borrow for an ordinary Forget response. Scope and lease still validate the complete request, context, active lease and child result; no cache key is chosen in assembly. The parent owns its complete publication result before requesting the key or Forget, and consumes the Scope response before asking for hints or closing the Scope.

The `HRLKKEY1` local request payload is raw path bytes. The previous caller copied a complete `HRSOLR02` envelope into that payload. Revision 5 projects the admitted local path extent (+56/+96) and leaves the actual key owner unchanged.

This source review is separate from runtime evidence. The failed v2 capture and EOF 111 remain failed. All existing profile inputs and 60/180-second process limits are unchanged.
