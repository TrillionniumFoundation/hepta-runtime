#!/usr/bin/env python3
"""Read a frozen Cargo.lock and check exact crates.io versions from public sparse metadata."""
import concurrent.futures
import datetime as dt
import email.utils
import hashlib
import json
from pathlib import Path
import re
import time
import tomllib
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent
EXPECTED_LOCK = "1509860cac0e7f26e6a845edfec1c87ae3bd92380ecaa357457e5263e861d631"
SOURCE = "registry+https://github.com/rust-lang/crates.io-index"
MAX_BYTES = 16 * 1024 * 1024
WORKERS = 4


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def index_path(name):
    assert re.fullmatch(r"[A-Za-z0-9_-]+", name), "Unexpected registry package name"
    name = name.lower()
    if len(name) == 1:
        return "1/" + name
    if len(name) == 2:
        return "2/" + name
    if len(name) == 3:
        return "3/" + name[0] + "/" + name
    return name[:2] + "/" + name[2:4] + "/" + name


def retry_seconds(value):
    if not value:
        return 2.0
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            return max(0.0, (email.utils.parsedate_to_datetime(value)
                             - dt.datetime.now(dt.timezone.utc)).total_seconds())
        except (ValueError, TypeError):
            return 2.0


def fetch(name):
    url = "https://index.crates.io/" + index_path(name)
    result = {"name": name, "url": url, "started_utc": now(), "attempts": []}
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(1, 3):
        request = urllib.request.Request(url, headers={
            "User-Agent": "hepta-runtime-readonly-lock-audit/1.0",
            "Cache-Control": "no-cache", "Accept": "text/plain",
        })
        try:
            with opener.open(request, timeout=20) as response:
                assert response.status == 200 and response.geturl() == url
                body = response.read(MAX_BYTES + 1)
                assert len(body) <= MAX_BYTES, "Response size exceeded audit bound"
                records = [json.loads(line) for line in body.splitlines() if line]
                versions = {}
                for record in records:
                    assert record["name"].lower() == name.lower()
                    assert record["vers"] not in versions, "Duplicate index version"
                    assert isinstance(record["yanked"], bool)
                    assert re.fullmatch(r"[0-9a-f]{64}", record["cksum"])
                    versions[record["vers"]] = record
                path = ROOT / "index-responses" / (name.lower() + ".jsonl")
                path.write_bytes(body)
                result.update(status="FETCHED", finished_utc=now(), http_status=response.status,
                              response_headers={key: response.headers.get(key) for key in
                                                ["Date", "Last-Modified", "ETag", "Age", "Cache-Control"]},
                              response_bytes=len(body), response_sha256=hashlib.sha256(body).hexdigest(),
                              saved_response=path.name, versions=versions)
                result["attempts"].append({"attempt": attempt, "status": 200})
                return result
        except urllib.error.HTTPError as error:
            delay = retry_seconds(error.headers.get("Retry-After"))
            result["attempts"].append({"attempt": attempt, "http_status": error.code,
                                       "retry_after_seconds": delay})
            if error.code in (408, 429, 500, 502, 503, 504) and attempt < 2 and delay <= 30:
                time.sleep(delay)
                continue
            result.update(status="COVERAGE_GAP", reason="http_" + str(error.code),
                          finished_utc=now())
            return result
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            result["attempts"].append({"attempt": attempt, "error_type": type(error).__name__})
            if attempt < 2:
                time.sleep(2)
                continue
            result.update(status="COVERAGE_GAP", reason=type(error).__name__, finished_utc=now())
            return result
        except (ValueError, AssertionError, KeyError, TypeError) as error:
            result.update(status="COVERAGE_GAP", reason="invalid_index_response_" + type(error).__name__,
                          finished_utc=now())
            return result


def msrv_tuple(value):
    if not value:
        return None
    if not re.fullmatch(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", value):
        return None
    parts = [int(part) for part in value.split(".")]
    return tuple((parts + [0, 0, 0])[:3])


def main():
    started = now()
    raw = (ROOT / "Cargo.lock").read_bytes()
    lock_hash = hashlib.sha256(raw).hexdigest()
    assert lock_hash == EXPECTED_LOCK
    packages = tomllib.loads(raw.decode("utf-8"))["package"]
    registry = [package for package in packages if package.get("source") == SOURCE]
    excluded = [{"name": package["name"], "version": package["version"],
                 "source": package.get("source"), "reason": "local_or_path_package"}
                for package in packages if not package.get("source")]
    unsupported = [package for package in packages
                   if package.get("source") not in (None, SOURCE)]
    names = sorted({package["name"] for package in registry})
    (ROOT / "index-responses").mkdir(exist_ok=True)
    fetched = {}
    print(json.dumps({"event": "started", "registry_package_versions": len(registry),
                      "unique_crates": len(names), "concurrency": WORKERS}), flush=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(fetch, name): name for name in names}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            fetched[name] = future.result()
            if len(fetched) % 25 == 0 or len(fetched) == len(names):
                print(json.dumps({"event": "progress", "completed": len(fetched),
                                  "total": len(names), "coverage_gaps": sum(
                                      item["status"] != "FETCHED" for item in fetched.values())}), flush=True)
    results = []
    for package in sorted(registry, key=lambda item: (item["name"], item["version"])):
        observed = fetched[package["name"]]
        record = {"name": package["name"], "version": package["version"],
                  "source": package["source"], "lock_checksum": package.get("checksum"),
                  "index_url": observed["url"], "observed_utc": observed.get("finished_utc"),
                  "index_response_sha256": observed.get("response_sha256"),
                  "response_date": observed.get("response_headers", {}).get("Date")}
        if observed["status"] != "FETCHED":
            record.update(status="COVERAGE_GAP", reason=observed["reason"])
        else:
            version = observed["versions"].get(package["version"])
            if version is None:
                record.update(status="COVERAGE_GAP", reason="exact_locked_version_missing")
            else:
                parsed_msrv = msrv_tuple(version.get("rust_version"))
                record.update(status="VERIFIED", yanked=version["yanked"],
                              index_checksum=version["cksum"],
                              checksum_matches=package.get("checksum") == version["cksum"],
                              declared_rust_version=version.get("rust_version"),
                              declared_msrv_within_project_1_95=(parsed_msrv <= (1, 95, 0))
                              if parsed_msrv is not None else None)
        results.append(record)
    failures = [record for record in results if record["status"] != "VERIFIED"]
    yanked = [record for record in results if record.get("yanked") is True]
    mismatch = [record for record in results if record.get("checksum_matches") is False]
    high_msrv = [record for record in results if record.get("declared_msrv_within_project_1_95") is False]
    no_msrv = [record for record in results if record["status"] == "VERIFIED"
               and record.get("declared_rust_version") is None]
    status = "PASS" if not (failures or yanked or mismatch or unsupported or high_msrv) else "FINDINGS_OR_COVERAGE_GAPS"
    fetch_metadata = [{key: value for key, value in fetched[name].items() if key != "versions"}
                      for name in names]
    report = {"schema": "hepta.full-official-sparse-index-audit.v1", "status": status,
              "started_utc": started, "finished_utc": now(), "lock_sha256": lock_hash,
              "source_scope": SOURCE, "request_concurrency": WORKERS,
              "explicit_origin_authentication_sent": False, "credentials_read_or_logged": False,
              "source_or_lock_mutations": False,
              "packages_in_lock": len(packages), "registry_package_versions": len(registry),
              "unique_registry_crates": len(names), "verified_registry_package_versions":
              len(results) - len(failures), "coverage_gaps": failures,
              "yanked_locked_versions": yanked, "checksum_mismatches": mismatch,
              "declared_msrv_exceeds_project": high_msrv,
              "msrv_not_declared_count": len(no_msrv),
              "msrv_not_declared": [{"name": r["name"], "version": r["version"]} for r in no_msrv],
              "non_registry_packages": excluded, "unsupported_sources": unsupported,
              "results": results, "fetches": fetch_metadata,
              "limits": ["This is a timed sequence of public index observations, not an atomic registry snapshot.",
                         "Checksums were compared between Cargo.lock and official index; downloaded package source archives were not rehashed.",
                         "A declared MSRV was checked against 1.95; missing declarations are recorded, and actual compiler validation is separate.",
                         "This index review does not replace the separately pinned RustSec advisory scan or production qualification."]}
    (ROOT / "official-index-report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: report[key] for key in ["status", "registry_package_versions",
                                                  "verified_registry_package_versions", "unique_registry_crates",
                                                  "msrv_not_declared_count"]}
                     | {"coverage_gaps": len(failures), "yanked": len(yanked),
                        "checksum_mismatches": len(mismatch), "higher_msrv": len(high_msrv)}), flush=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
