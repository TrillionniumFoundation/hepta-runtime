# Fixed current-target get_info owner

This is a source-only CI candidate for the fixed get_info method in target commit
d3d75c30719db966b004756f610007a7c723729e. It does not change a public frontend,
catalog registration, connection negotiation, or general result serializer.

## Independent construction and comparison

The recipe authenticates the complete previously successful catalog reference
ZIP (artifact 14194828118, run 43796801388) and every member of its enclosed tar.
It retains the complete ZIP so later readers can repeat the verification.

Before generation, only five primary files are extracted: the unchanged target
server and lockfile, and the actual RMCP 3.9.0 model, capability declarations and
normalized Cargo manifest. Original result streams are hashed at this stage but
are not decoded. The generator derives the instruction literal, capability
settings, protocol constant, SDK crate identity, field ordering and omitted
optional fields from these files. It writes JSON one typed field and token at a
time. It never reads or embeds a get_info_wire expected response.

A generation-only audit records actual reads, permits only the source package,
five primary files, pinned Hepta sources and Python standard library, and denies
child/native execution. A separate process compiles the generated HIA using the
pinned native compiler. This is a fresh module and development fixed-point
bootstrap, not a new independent cold qualification.

Nine case workers correspond to the unconfigured runtime and eight existing
configuration profiles. The source method has no configuration input, so each
worker invokes the same private fixed-operation request. Each makes one real
output-growth call and one complete-output call. Each native invocation retains
a 60 second OS deadline, its entire input/output/workspace, and its return code.
The capture process never opens an original observation stream.

Only after generation, compilation and native capture does the independent
reader decode the nine actual original get_info results. It compares the whole
UTF-8 wire for every profile, including field order, omission and instructions.
No new Rust process is executed by this recipe.

## Run and read

The workflow in ci/workflow.get-info.yml is ready for an isolated candidate
branch. Its publisher can add a branch-specific push trigger to the external
workflow copy without changing this package. Runtime paths are assigned in the
first step; job-level env does not reference runner.temp.

The recipe command in CI is:

    python3 -I -B scripts/run_ci.py --source PACKAGE --hepta PINNED_HEPTA \
      --reference-zip PINNED_REFERENCE_ZIP --output NEW_OUTPUT

The independent reader launches neither native code nor Rust, rejects file
mutation and child/native execution, and compares source/capture bytes,
mtime and ctime before and after reading:

    python3 -I -B scripts/verify.py --source PACKAGE --run OUTPUT \
      --reference-zip PINNED_REFERENCE_ZIP --require-pass

A relocated complete artifact uses recipe-source, run and reference.zip from
the extracted artifact root. All paths above are explicit and portable.

## Qualification boundaries

At package creation the Python author, HIA generation/build, native cases and
new comparison have not run. The source manifest preserves that source-only
status. Actual CI receipts must establish any later PASS.

A future successful run qualifies one fixed private get_info owner against all
nine retained current-original calls. It does not qualify a generic
InitializeResult serializer, public metadata registration, current connection
identity, transport tasks/cancellation, all 136 tool routes, production
activation, or removal of the historical stack. Historical public80 and
transport81 packages remain unchanged.
