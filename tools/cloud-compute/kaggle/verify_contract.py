#!/usr/bin/env python3
"""Verify the installed official SDK request contract. No network or credentials."""
import json
import sys
from kaggle_transport import sdk_payload, dependency_versions, AdapterError


def main():
    cases = {
        "quota": ({}, {}),
        "list": ({"group": "PROFILE", "user": "contract-user", "page_size": 100, "language": "all", "kernel_type": "all", "output_type": "all"},
                 {"user": "contract-user", "pageSize": 100, "language": "all", "kernelType": "all", "outputType": "all"}),
        "get": ({"user_name": "contract-user", "kernel_slug": "contract-run", "version_label": "v1"}, {"versionLabel": "v1"}),
        "status": ({"user_name": "contract-user", "kernel_slug": "contract-run", "version_label": "v1"}, {"versionLabel": "v1"}),
        "output": ({"user_name": "contract-user", "kernel_slug": "contract-run", "version_label": "v1", "page_size": 1}, {"versionLabel": "v1", "pageSize": 1}),
        "files": ({"user_name": "contract-user", "kernel_slug": "contract-run", "version_label": "v1", "page_size": 1}, {"versionLabel": "v1", "pageSize": 1}),
        "submit": ({"slug": "contract-user/contract-run", "text": "print(5)", "language": "python", "kernel_type": "script",
                    "is_private": True, "enable_gpu": False, "enable_tpu": False, "enable_internet": False,
                    "session_timeout_seconds": 120, "kernel_execution_type": "SAVE_AND_RUN_ALL",
                    "dataset_data_sources": [], "kernel_data_sources": [], "competition_data_sources": [], "model_data_sources": []},
                   {"slug": "contract-user/contract-run", "isPrivate": True, "sessionTimeoutSeconds": 120}),
        "cancel": ({"kernel_session_id": 123}, {"kernelSessionId": 123}),
        "introspect": ({"token": "contract-placeholder-not-a-credential"}, {"token": "contract-placeholder-not-a-credential"}),
        "refresh": ({"refresh_token": "contract-placeholder-not-a-credential", "api_version": "API_VERSION_V1", "expiration_duration": 43200}, {}),
    }
    results = []
    try:
        for action, (values, expected) in cases.items():
            payload = sdk_payload(action, values)
            if any(payload.get(k) != v for k, v in expected.items()):
                raise AdapterError("SDK_CONTRACT", "Official SDK serialization changed.", details={"action": action})
            results.append({"action": action, "serialized_fields": sorted(payload), "passed": True})
        try: sdk_payload("submit", {"nonexistent_field": "must-not-be-ignored"})
        except AdapterError: pass
        else: raise AdapterError("SDK_CONTRACT", "Unknown request fields were silently ignored.")
        print(json.dumps({"ok": True, "network_requests": 0, "packages": dependency_versions(), "checks": results}, sort_keys=True))
        return 0
    except AdapterError as exc:
        print(json.dumps({"ok": False, "error": exc.as_dict(), "checks": results}, sort_keys=True))
        return 1


if __name__ == "__main__": sys.exit(main())
