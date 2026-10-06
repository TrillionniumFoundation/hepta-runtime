# Native document and image tools

**Current candidate update:** optional configured-host document/image access, native binary tools, PDF page editing and worksheet range editing are specified in [NATIVE_TRANSFER.md](NATIVE_TRANSFER.md). That document supersedes historical local-only and unregistered-prototype statements below. Check the exact qualification receipt for what is actually installed.

These are native MCP entry points, not a recommendation to run a shell command. The Rust server validates the controller's existing file roots, runs at most two bounded parser workers, and returns protocol-native text/image blocks. They operate on **local controller paths only**. Remote document tools and full Desktop Commander document-contract equivalence are separate remaining work.

## API

- `document_read`: PDF page text and optional rendered pages; DOCX paragraph/table outline and selected document/header/footer XML; XLSX/XLSM sheet-range reads with formulas preserved as formulas. It does not recalculate spreadsheets, decrypt PDFs, or perform OCR.
- `image_read`: PNG/JPEG/WebP/GIF/BMP/TIFF first-frame preview as native MCP image content, together with original dimensions, format, frame count and source SHA256. Preview resizing does not modify original image bytes. Image format and decoded-pixel limits remain enforced.
- `document_write`: create-only or expected-SHA256 replacement of a PDF/DOCX from basic markdown headings/plain paragraphs, or XLSX from named row arrays. This is not a full HTML/CSS/SVG rendering engine. It does not create arbitrary binary files.
- `document_edit`: exact, counted XML replacements in a selected DOCX body/header/footer package part. The source SHA256 is mandatory, invalid XML is rejected, and unselected package payloads are preserved. PDF page editing and XLSX range editing are not implemented by this entry point.

File inputs are bounded to 32 MiB, result text to 240 KiB, preview images to 512 KiB each, and worker output to 2 MiB. Worker time, address space and file-output sizes are bounded. FIFO/special files, forbidden paths, XML entity declarations, ZIP expansion bombs and stale fingerprints fail explicitly. The worker never requests URLs, invokes sudo, runs document macros, or accepts a caller-specified interpreter.

File publication uses directory-descriptor-relative operations, a cooperating per-document lock, an expected content fingerprint, and atomic replacement. Create-only publication uses a no-overwrite link operation. This is not a filesystem-wide compare-and-swap against noncooperating writers: callers must still reconcile after ambiguous transport failures. It does not promise preservation of external ACLs, extended attributes, signatures or every office/PDF application feature.

## Explicit parser setup

Use the dedicated optional virtual environment and `deploy/requirements-documents.txt`. The tested controller reused the system lxml package and installed the other pinned dependencies in its own virtual environment; the receipt records actual versions. No existing system Python package was removed.

`deploy/configure-document-worker.py --python /absolute/venv/bin/python --out report.json` verifies the parser imports and stages only the existing operator user's `50-native-documents.conf` service drop-in. It does not restart anything or broaden file roots. The next explicitly requested runtime upgrade activates it. Missing configuration fails with a clear error rather than silently using another interpreter.

The environment variable `HEPTA_RUNTIME_DOCUMENT_PYTHON` is administrator configuration. Tool schemas reject hidden interpreter/root fields. The worker uses Python isolated mode and does not borrow provider credentials.

## Verification

- `tests/document_local_tests.py`: actual package/parser fixtures, PDF rendering and image content, DOCX unchanged-part preservation, formula-aware worksheet reading, version/path/format failures and FIFO rejection.
- `tests/document_mcp_acceptance.py`: real authenticated MCP discovery and calls. It checks actual image content blocks, rendered page images, DOCX edits, spreadsheet ranges and rejection paths.
- `--url` and `--token-file` run the document acceptance against the installed local endpoint, using only disposable files. This is not ChatGPT/cloud connection testing.

The deployment rollback drill uses a previously qualified release, intentionally raises a validation error after the candidate starts, and verifies the prior executable hash, unit text and manifest are restored. The real sudo/PAM test uses a synthetic account inside a disposable private mount namespace. It verifies an actual password prompt and UID 0 without editing the host's passwd/shadow/sudoers/PAM; it does not authenticate as a real user's password-protected account.

## Remaining parity boundaries

Generic binary tool registration was blocked in the current execution session; the older untracked binary prototypes are not part of the compiled API. Native remote document access, PDF editing and richer formatting, Excel editing/recalculation, transparent transfer of existing DC process pipes, physical reboot acceptance and application-specific password policies remain separately unqualified. ChatGPT direct connection remains intentionally last.
