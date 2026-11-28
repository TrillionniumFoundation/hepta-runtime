# TextFileWriteParams private typed projection

`text_file_write_params.hepta` has the ordinary borrowed input/output/workspace
three-buffer HIA entry and uses the `history.v1` capacity profile. It accepts an
actual canonical root `Map<String, Value>` produced by the current installed
`serde_json_span` `HJSMS002` operation. The original public raw arguments must pass
through that owner first. This component does not reenter `serde_json::Value` at
the root and does not decide body publication limits or policy.

## Input

The 24-byte `HTPPRQ01` header contains the magic, canonical JSON byte length at
offset 8, and zero at offset 16. The complete canonical JSON object follows.
Malformed private framing returns `0xffffffff`. Output shorter than 128 bytes
returns `0xfffffffe`. These pre-admission refusals leave all caller buffers intact.

## Output

The entry returns 128 on a framed result. The caller must read the header and the
complete declared payload; the return value is not the payload extent.

| Offset | Field |
| --- | --- |
| 0 | `HTPPRR01` |
| 8 | status: 0 success, 1 typed error, 2 workspace growth, 3 output growth, 4 extent refusal |
| 16 | success mode: 1 create, 2 replace, 3 append |
| 24 | decoded path bytes |
| 32 | decoded content bytes |
| 40 | decoded expected_sha256 bytes |
| 48–64 | zero |
| 72 | complete typed-error byte length |
| 80 | required workspace or output capacity on growth; otherwise zero |
| 88–120 | zero |

Successful payloads concatenate path, content, and expected_sha256. Error
payloads contain the entire current typed-deserialization diagnostic. Growth
replies contain only the header; the caller preserves the complete retained
workspace, appends zeroes when growing it, and retries the same immutable input.
Output suffixes beyond the published extent remain unchanged. Each admitted call
requires `max(input_length, 128) + 65536` workspace bytes. The first 1024 scratch bytes and
the 128-byte field table at 65536 are reset; exact retained helper functions use
their original scratch ranges below that table.

The string content is not capped here. The unchanged original types accept it;
the actual publisher body later applies its 64 KiB input and 4 MiB existing-file
limits. This interface conveys no caller identity or path authorization and has
no filesystem, task, transport, public registration, or production qualification.
