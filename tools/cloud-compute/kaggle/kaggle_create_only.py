"""Targetless Kaggle creation: no existing notebook ID/slug is sent.

Original full-list submission remains byte-identical in kaggle_jobs. New CLI
requests use a distinct no-target SaveKernel protocol, proven by an actual
private QuickSave creation with version 1. Lost acknowledgements remain UNKNOWN
and are never repeated, even when the generated ref is not found. Legacy
records remain readable under their original identities.
"""
from kaggle_jobs import *

PROTOCOL = "SaveKernel.targetless-new-title.v1"
GPU_IMAGE = 'gcr.io/kaggle-gpu-images/python@sha256:de153e6d303881930c51286216393d56f56b26458d0661350305a1e8144eea01'


def create_only_preflight(record):
    username=record["account"].get("username")
    if record["account"].get("authenticated") is not True or not isinstance(username,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",username):
        raise AdapterError("ACCOUNT_UNVERIFIED","An introspected account is required.")
    if not re.fullmatch(re.escape(username)+r"/hepta-[a-z0-9-]+",record["notebook_ref"]):
        raise AdapterError("CREATE_ONLY_REF_INVALID","Targetless title must be bound to the selected owner.")
    if record.get("creation_protocol") != PROTOCOL or not re.fullmatch(r"[a-f0-9]{32}",record.get("request_nonce","")):
        raise AdapterError("CREATE_ONLY_PROTOCOL_UNBOUND","New requests require their original nonce and protocol.")
    return {"method":PROTOCOL,"existing_notebook_id_sent":False,"existing_notebook_slug_sent":False,
        "full_inventory_used":False,"all_pages_completed":False,"atomic_create_only":False,
        "server_must_ack_version":1,"random_title_nonce_bits":96}


def submission_readiness(transport, *, request_id=None):
    if request_id is not None: checked_request_id(request_id)
    result={"schema":"hepta-kaggle-readiness-v1","provider":"kaggle","observed_at":now(),
        "ready":False,"request_id":request_id,"request_id_is_correlation_only":True,
        "authorization_verified":False,"readiness_scope":"authentication_and_targetless_creation_protocol",
        "creation_protocol":PROTOCOL,"inventory_verified":False,"quota_checked":False,
        "cloud_mutation_performed":False,"allocation_guaranteed":False,"submission_must_recheck":True,
        "new_notebook_only":True,"existing_notebook_update_supported":False}
    try:
        account=transport.account();result["account"]=account
        result["authorization_verified"]=account.get("authenticated") is True
        username=account.get("username")
        if not result["authorization_verified"] or not isinstance(username,str) or not re.fullmatch(r"[A-Za-z0-9_-]+",username):
            raise AdapterError("ACCOUNT_UNVERIFIED","Provider authentication is not confirmed.")
        result["ready"]=True
    except AdapterError as exc:result["error"]=exc.as_dict()
    return scrub(result)


class CreateOnlyKaggleAdapter(KaggleAdapter):
    def receipt(self,record,**extra):
        result=super().receipt(record,**extra)
        if "creation_protocol"in record:result["creation_protocol"]=record["creation_protocol"]
        return result

    def resume(self,request_id):
        # Keep original legacy reconciliation. A new protocol must never accept
        # a version >1 from a contradictory retained response.
        with self.ledger.locked(request_id):
            record=self.ledger.load(request_id)
            if record.get("creation_protocol")==PROTOCOL:
                for _,payload in self.ledger.submission_responses(request_id):
                    if positive_int(attr(payload,"versionNumber","version_number")) not in (None,1):
                        raise AdapterError("CREATE_ONLY_ACK_VERSION_CONFLICT","Original targetless response did not prove a first version.")
        return super().resume(request_id)

    def submit(self, *, request_id, source, timeout=300, accelerator="cpu", internet=False,
               kernel_type="script", dataset_sources=(), kernel_sources=(), model_sources=(), competition_sources=()):
        checked_request_id(request_id)
        if kernel_type not in {"script", "notebook"}: raise AdapterError("INVALID_KERNEL_TYPE", "Only Python scripts and notebooks are supported.")
        if isinstance(timeout, bool) or not 1 <= timeout <= 43200:
            raise AdapterError("INVALID_TIMEOUT", "Remote runtime limit must be between 1 and 43200 seconds.")
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", accelerator):
            raise AdapterError("INVALID_ACCELERATOR", "Accelerator identifier has an invalid format.")
        code = read_source(Path(source), kernel_type)
        intent = {"source_sha256": hashlib.sha256(code.encode()).hexdigest(), "timeout_seconds": timeout,
                  "accelerator": accelerator, "internet": bool(internet), "kernel_type": kernel_type,
                  "language": "python", "is_private": True, "dataset_sources": list(dataset_sources),
                  "kernel_sources": list(kernel_sources), "model_sources": list(model_sources),
                  "competition_sources": list(competition_sources)}
        for key in ("dataset_sources", "kernel_sources", "model_sources", "competition_sources"):
            if len(intent[key]) > 50 or any(not isinstance(v, str) or len(v) > 512 or "\n" in v for v in intent[key]):
                raise AdapterError("INVALID_INPUT_REFERENCE", "Data source references exceed their bounds.")
        fingerprint = digest(intent)
        with self.ledger.locked(request_id):
            existing = self.ledger.load(request_id, required=False)
            if existing:
                if "docker_image" in existing.get("intent", {}):
                    intent.update(docker_image=existing["intent"]["docker_image"],
                                  docker_image_pinning_type=existing["intent"]["docker_image_pinning_type"])
                    fingerprint = digest(intent)
                if existing["input_digest"] != fingerprint:
                    raise AdapterError("IDEMPOTENCY_CONFLICT", "Request ID is already bound to different code, inputs or settings.")
                self._account_for(existing)
                if existing["submission_state"] == "SUBMITTING":
                    existing["submission_state"] = "UNKNOWN"
                    self.ledger.event(existing, "interrupted_submission_observed")
                # Deliberately never resubmit, including UNKNOWN and REJECTED.
                return self.receipt(existing, reused=True, remote_submission_replayed=False)
            if accelerator.lower() != "cpu" and not accelerator.lower().startswith("tpu"):
                intent.update(docker_image=GPU_IMAGE, docker_image_pinning_type="original")
                fingerprint = digest(intent)
            account = self.transport.account()
            username = account.get("username", "")
            if not re.fullmatch(r"[A-Za-z0-9_-]+", username):
                raise AdapterError("ACCOUNT_UNVERIFIED", "Authenticated username is not available.")
            stem = re.sub(r"[^a-z0-9]+", "-", request_id.lower()).strip("-")[:18]
            nonce = secrets.token_hex(16)
            slug = "hepta-" + stem + "-" + nonce[:24]
            ref = username + "/" + slug
            record = {"schema": SCHEMA, "provider": "kaggle", "request_id": request_id,
                      "input_digest": fingerprint, "account": account, "intent": intent, "request_nonce": nonce,
                      "notebook_ref": ref, "notebook_version": None, "kernel_id": None,
                      "kernel_session_id": None, "submission_state": "PREPARED", "remote_state": "UNKNOWN",
                      "remote_submission_state": "NOT_SENT", "remote_effect_unknown": False,
                      "created_at": now(), "identity_verified": False, "creation_protocol": PROTOCOL}
            self.ledger.write_source(request_id, code)
            self.ledger.event(record, "intent_persisted")
            try:
                collision_check = create_only_preflight(record)
                self.ledger.event(record, "targetless_create_only_preflight", collision_check)
            except BaseException as exc:
                record["submission_state"] = "REJECTED"
                record["last_error"] = exc.as_dict() if isinstance(exc, AdapterError) else {"code": "PREFLIGHT_INCOMPLETE", "type": type(exc).__name__}
                self.ledger.event(record, "preflight_failed", record["last_error"])
                raise
            values = {"new_title": slug, "text": code, "language": "python", "kernel_type": kernel_type,
                      "is_private": True, "enable_gpu": accelerator.lower() != "cpu" and not accelerator.lower().startswith("tpu"),
                      "enable_tpu": accelerator.lower().startswith("tpu"), "enable_internet": bool(internet),
                      "session_timeout_seconds": timeout, "kernel_execution_type": "SAVE_AND_RUN_ALL",
                      "dataset_data_sources": list(dataset_sources), "kernel_data_sources": list(kernel_sources),
                      "model_data_sources": list(model_sources), "competition_data_sources": list(competition_sources)}
            if accelerator.lower() != "cpu": values["machine_shape"] = accelerator
            if "docker_image" in intent:
                values.update(docker_image=intent["docker_image"], docker_image_pinning_type=intent["docker_image_pinning_type"])
            assert "id" not in values and "slug" not in values
            record["submission_state"] = "SUBMITTING"
            # Persist uncertainty before dispatch. This does not claim that bytes
            # necessarily reached Kaggle; it prevents false rollback assumptions.
            record["remote_submission_state"] = "MAY_HAVE_BEEN_SENT"
            record["remote_effect_unknown"] = True
            self.ledger.event(record, "remote_submit_intent", {"rpc": "SaveKernel", "payload_sha256": digest(values)})
            try:
                response = self.transport.call("submit", values, mutation=True)
            except BaseException as exc:
                record["submission_state"] = "UNKNOWN"
                if isinstance(exc, AdapterError):
                    exc.details["remote_effect_unknown"] = True
                    if isinstance(exc, RemoteError): exc.ambiguous = True
                record["last_error"] = exc.as_dict() if isinstance(exc, AdapterError) else {"code": "INTERRUPTED_OR_UNCERTAIN", "type": type(exc).__name__}
                self.ledger.event(record, "remote_submit_incomplete", record["last_error"])
                raise
            self.ledger.event(record, "remote_submit_response", response)
            if response.get("error"):
                record["submission_state"] = "UNKNOWN"
                record["last_error"] = {"code": "PROVIDER_REJECTED", "message": scrub(str(response["error"]))[:1000]}
                self.ledger.event(record, "remote_submit_rejected")
                return self.receipt(record, reused=False)
            version = positive_int(attr(response, "versionNumber", "version_number"))
            actual_ref = bound_response_ref(response.get("ref"), ref)
            kernel_id = positive_int(attr(response, "kernelId", "kernel_id"))
            if actual_ref != ref or version != 1 or kernel_id is None:
                record["submission_state"] = "UNKNOWN"
                record["last_error"] = {"code": "SUBMIT_IDENTITY_INCOMPLETE", "message": "SaveKernel did not confirm the intended reference, notebook ID and exact version."}
                self.ledger.event(record, "remote_submit_identity_unknown")
                return self.receipt(record, reused=False)
            record["notebook_version"] = version
            record["kernel_id"] = kernel_id
            self._bind_explicit_session(record, response, "SaveKernel.response")
            invalid = {k: v for k, v in response.items() if k.startswith("invalid") and v}
            record["submission_state"] = "ACCEPTED_WITH_INVALID_INPUTS" if invalid else "ACCEPTED"
            record["remote_submission_state"] = "ACKNOWLEDGED"
            record["remote_effect_unknown"] = False
            if invalid: record["invalid_inputs"] = scrub(invalid)
            self.ledger.event(record, "remote_identity_bound", {"invalid_inputs": invalid})
            return self.receipt(record, reused=False)

    def _artifact_catalog(self, record, manifest_name, max_bytes):
        # Preserve the deployed targetless adapter's fixed-session full-path
        # catalog authority. Ambiguous provider display basenames are warnings;
        # only the exact output catalog plus fresh execution manifest bind files.
        if not manifest_name:
            return super()._artifact_catalog(record, manifest_name, max_bytes)
        sizes, items, display_duplicates = {}, {}, set()
        for page in self._pages(record, "files"):
            for item in page.get("files") or []:
                name = safe_name(item.get("name"))
                if name == ".hepta-download-receipt.json":
                    raise AdapterError("RESERVED_OUTPUT_NAME", "Provider output conflicts with the adapter's reserved receipt filename.")
                if name in sizes: display_duplicates.add(name)
                raw_size = item.get("size", 0)
                size = int(raw_size) if isinstance(raw_size, (str, int)) and str(raw_size).isdigit() else None
                if size is None: raise AdapterError("INVALID_OUTPUT_SIZE", "Provider returned an invalid file size.")
                sizes[name] = None if name in display_duplicates else size
        if not manifest_name and sum(sizes.values()) > max_bytes: raise AdapterError("ARTIFACT_BUDGET", "Provider output exceeds the download budget.")
        for page in self._pages(record, "output"):
            for item in page.get("files") or []:
                name = safe_name(attr(item, "fileName", "file_name"))
                if name in items: raise AdapterError("DUPLICATE_OUTPUT", "Provider lists the same output URL more than once.")
                url = item.get("url")
                if not isinstance(url, str): raise AdapterError("INVALID_OUTPUT_URL", "Provider omitted an output URL.")
                items[name] = url
        listing_warning = ([{"code":"PROVIDER_AMBIGUOUS_DISPLAY_BASENAMES",
            "display_names":sorted(display_duplicates),
            "verification_authority":"pinned_session_output_and_execution_manifest"}]
            if display_duplicates else [])
        if set(sizes) != set(items):
            # ListKernelFiles loses parent paths and reports unreliable
            # display sizes. Only explicit manifest mode can use the exact
            # pinned-session URL catalog as the file identity authority.
            listing_warning += [{"code": "PROVIDER_OUTPUT_CATALOG_CONFLICT",
                "display_names": sorted(sizes), "pinned_output_names": sorted(items),
                "verification_authority": "pinned_session_output_and_execution_manifest"}]
            sizes = {name: sizes.get(name, sizes.get(Path(name).name)) for name in items}
        if manifest_name and manifest_name not in items: raise AdapterError("REMOTE_MANIFEST_MISSING", "Execution did not produce the required hash manifest.")
        return sizes, items, listing_warning
