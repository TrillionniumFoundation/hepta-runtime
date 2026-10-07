#!/usr/bin/env python3
# Copyright 2026 TrillionniumFoundation; SPDX-License-Identifier: Apache-2.0
"""Observe business identities and verify bounded, signed checkpoint/recovery evidence.

This gate has no lifecycle executor. A receipt signer must be independently trusted
for the resource and native adapter; caller readiness booleans are never evidence.
Cryptographic success attests the signer's statements, not universal application
semantics, and this tool never authorizes a controller reboot.
"""
import argparse
import base64
import datetime
import hashlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('maintenance_inventory', ROOT / 'maintenance_inventory.py')
inventory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inventory)
SHA256 = re.compile(r'^[0-9a-f]{64}$')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def timestamp(value):
    result = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timezone_required')
    return result.astimezone(datetime.timezone.utc)


def file_hash(path, limit=None):
    path = pathlib.Path(path)
    if not path.is_absolute():
        raise ValueError('absolute_evidence_path_required')
    # O_NOFOLLOW also protects the final component against a post-lstat swap.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or (limit is not None and before.st_size > limit):
            raise ValueError('unsafe_evidence_file')
        result = hashlib.sha256()
        for data in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(data)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise ValueError('evidence_file_changed')
        return result.hexdigest()


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate_json_key')
        value[key] = item
    return value


def read_object(path, expected_hash=None):
    path = pathlib.Path(path)
    actual = file_hash(path, 1024 * 1024)
    if expected_hash is not None and actual != expected_hash:
        raise ValueError('evidence_hash_mismatch')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        raw = stream.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024 or hashlib.sha256(raw).hexdigest() != actual:
        raise ValueError('evidence_file_changed')
    result = json.loads(raw, object_pairs_hook=unique_object)
    if not isinstance(result, dict):
        raise ValueError('json_object_required')
    return result


def identity(pid):
    row = inventory.process_identity(pid)
    return {key: row[key] for key in ('pid', 'ppid', 'start_ticks', 'uids', 'comm')}


def collect_snapshot():
    resources = {}
    failures = []
    rows, unknown = inventory.process_table()
    if unknown:
        failures.append('process_identity_scan_incomplete')
    for pid, row in rows.items():
        if row['uids'][0] == os.getuid() and pid != os.getpid():
            resources[f'process:{pid}'] = {key: row[key] for key in ('pid', 'ppid', 'start_ticks', 'uids', 'comm')}
    for user in (False, True):
        prefix = ['systemctl'] + (['--user'] if user else [])
        units = inventory.command_json(prefix + ['list-units', '--state=running', '--type=service', '--no-pager', '--output=json'])
        if not units.get('available'):
            failures.append(('user' if user else 'system') + '_service_inventory_unavailable')
            continue
        for item in units['value']:
            unit = item['unit']
            if not user and not any(token in unit.lower() for token in ('hepta', 'postgres', 'docker', 'waydroid', 'openbao', 'openclaw', 'ollama', 'runner')):
                continue
            p = subprocess.run(prefix + ['show', unit, '--property=Id,MainPID,InvocationID,ActiveState,SubState,UnitFileState,ControlGroup'], capture_output=True, text=True, timeout=8)
            if p.returncode:
                failures.append('service_properties_unavailable:' + unit)
                continue
            properties = dict(line.split('=', 1) for line in p.stdout.splitlines() if '=' in line)
            try:
                main_pid = int(properties['MainPID'])
                properties['main_process_identity'] = identity(main_pid) if main_pid > 1 else None
                if main_pid <= 1:
                    failures.append('service_main_process_unknown:' + unit)
            except (OSError, ValueError, KeyError):
                failures.append('service_main_process_changed:' + unit)
            resources[('user-service:' if user else 'system-service:') + unit] = properties
    containers = inventory.command_json(['docker', 'ps', '--format', 'json'])
    if not containers.get('available'):
        failures.append('container_inventory_unavailable')
    else:
        container_rows = containers['value']
        if isinstance(container_rows, dict):
            container_rows = [container_rows]
        for item in container_rows:
            value = inventory.command_json(['docker', 'inspect', item['ID']])
            if not value.get('available'):
                failures.append('container_identity_unavailable:' + item['ID'])
                continue
            v = value['value'][0]
            resources['container:' + v['Id']] = {
                'id': v['Id'], 'image_id': v['Image'], 'name': v['Name'],
                'pid': v['State']['Pid'], 'started_at': v['State']['StartedAt'],
                'status': v['State']['Status'], 'restart_policy': v['HostConfig']['RestartPolicy'],
                'mounts': [{k: m.get(k) for k in ('Type', 'Source', 'Destination', 'RW')} for m in v['Mounts']],
            }
    return {
        'version': 1, 'hostname': os.uname().nodename,
        'boot_id': pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
        'observed_at': utc_now().isoformat(), 'resources': resources,
        'identity_digest': digest(resources), 'inventory_failures': failures,
        'scope': 'all observed same-login processes except this observer; relevant system services; all running user services; running Docker containers',
        'observer_pid': os.getpid(), 'mode': 'observe_only',
        'safe_reboot_proven': False, 'power_action_authorized': False,
    }


def verify_envelope(reference, trust, resource_id, now, max_age):
    if set(reference) != {'path', 'sha256'} or not SHA256.fullmatch(str(reference['sha256'])):
        raise ValueError('receipt_reference_invalid')
    envelope = read_object(reference['path'], reference['sha256'])
    if set(envelope) != {'key_id', 'payload', 'signature_base64'}:
        raise ValueError('signed_receipt_envelope_required')
    payload = envelope['payload']
    if not isinstance(payload, dict):
        raise ValueError('receipt_payload_invalid')
    key = trust.get('keys', {}).get(envelope['key_id'])
    if not key or resource_id not in key.get('resource_ids', []) or payload.get('adapter') not in key.get('adapters', []):
        raise ValueError('resource_adapter_signer_not_trusted')
    if file_hash(key['public_key_path'], 65536) != key['public_key_sha256']:
        raise ValueError('trusted_public_key_hash_mismatch')
    # The verifier is optional for read-only inventory. Missing crypto fails closed.
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as error:
        raise ValueError('ed25519_verifier_unavailable') from error
    public_key = load_pem_public_key(pathlib.Path(key['public_key_path']).read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise ValueError('ed25519_public_key_required')
    try:
        public_key.verify(base64.b64decode(envelope['signature_base64'], validate=True), canonical(payload))
    except Exception as error:
        raise ValueError('receipt_signature_invalid') from error
    observed = timestamp(payload['observed_at'])
    expires = timestamp(payload['expires_at'])
    if (now - observed).total_seconds() < -5 or (now - observed).total_seconds() > max_age or expires <= now or expires <= observed or (expires - observed).total_seconds() > max_age:
        raise ValueError('receipt_stale_or_fence_expired')
    return payload


def evaluate(snapshot, current, manifest, trust, now=None, max_age=60):
    now = now or utc_now()
    blockers = []
    rows = []
    if not isinstance(max_age, int) or isinstance(max_age, bool) or not 1 <= max_age <= 300:
        raise ValueError('max_age_outside_1_to_300_seconds')
    if set(manifest) != {'version', 'boot_id', 'inventory_identity_digest', 'resources'} or manifest.get('version') != 1:
        blockers.append('manifest_schema_invalid')
    if not isinstance(manifest.get('resources'), dict):
        manifest = {**manifest, 'resources': {}}
    if trust.get('version') != 1 or not isinstance(trust.get('keys'), dict):
        blockers.append('independent_signer_trust_required')
    for observed in (snapshot, current):
        try:
            age = (now - timestamp(observed['observed_at'])).total_seconds()
            if age < -5 or age > max_age:
                blockers.append('inventory_observation_stale')
            if observed['identity_digest'] != digest(observed['resources']):
                blockers.append('inventory_digest_invalid')
        except (KeyError, TypeError, ValueError):
            blockers.append('inventory_schema_invalid')
        if observed.get('inventory_failures'):
            blockers.append('inventory_incomplete')
    if snapshot.get('hostname') != current.get('hostname') or snapshot.get('boot_id') != current.get('boot_id') or manifest.get('boot_id') != current.get('boot_id'):
        blockers.append('host_boot_identity_changed')
    if snapshot.get('resources') != current.get('resources') or manifest.get('inventory_identity_digest') != current.get('identity_digest'):
        blockers.append('business_resource_identity_drift')
    resources = current.get('resources', {})
    if set(manifest['resources']) - set(resources):
        blockers.append('receipt_for_unobserved_resource')
    for resource_id, binding in resources.items():
        reasons = []
        reference = manifest['resources'].get(resource_id)
        try:
            if not isinstance(reference, dict) or set(reference) != {'checkpoint', 'restore'}:
                raise ValueError('native_checkpoint_and_restore_receipts_missing')
            checkpoint = verify_envelope(reference['checkpoint'], trust, resource_id, now, max_age)
            restore = verify_envelope(reference['restore'], trust, resource_id, now, max_age)
            common = {'version', 'kind', 'resource_id', 'identity_digest', 'host_boot_id', 'observed_at', 'expires_at', 'adapter', 'status', 'checkpoint_sha256', 'quiescence_fence_id'}
            if set(checkpoint) != common | {'checkpoint_artifact_path', 'state_digest'} or set(restore) != common | {'expected_state_digest', 'recovered_state_digest'}:
                raise ValueError('native_receipt_schema_invalid')
            for payload in (checkpoint, restore):
                if payload['version'] != 1 or payload['resource_id'] != resource_id or payload['identity_digest'] != digest(binding) or payload['host_boot_id'] != current['boot_id']:
                    raise ValueError('receipt_resource_identity_mismatch')
                if not SHA256.fullmatch(str(payload['checkpoint_sha256'])) or not isinstance(payload['quiescence_fence_id'], str) or not payload['quiescence_fence_id']:
                    raise ValueError('checkpoint_or_quiescence_fence_required')
            if checkpoint['kind'] != 'HeptaBusinessCheckpointReceipt' or checkpoint['status'] != 'quiesced-durable-checkpoint' or restore['kind'] != 'HeptaBusinessRestoreReceipt' or restore['status'] != 'isolated-recovery-verified':
                raise ValueError('native_drain_checkpoint_restore_status_required')
            if checkpoint['checkpoint_sha256'] != restore['checkpoint_sha256'] or checkpoint['quiescence_fence_id'] != restore['quiescence_fence_id']:
                raise ValueError('checkpoint_restore_fence_or_artifact_mismatch')
            if timestamp(restore['observed_at']) < timestamp(checkpoint['observed_at']):
                raise ValueError('restore_precedes_checkpoint')
            if not SHA256.fullmatch(str(checkpoint['state_digest'])) or checkpoint['state_digest'] != restore['expected_state_digest'] or checkpoint['state_digest'] != restore['recovered_state_digest']:
                raise ValueError('recovered_business_state_mismatch')
            if file_hash(checkpoint['checkpoint_artifact_path']) != checkpoint['checkpoint_sha256']:
                raise ValueError('checkpoint_artifact_hash_mismatch')
        except Exception as error:
            reasons.append(str(error) if isinstance(error, ValueError) else type(error).__name__)
        rows.append({'resource_id': resource_id, 'identity_digest': digest(binding), 'status': 'unresolved' if reasons else 'signed_evidence_verified', 'blockers': reasons})
    if any(row['blockers'] for row in rows):
        blockers.append('business_resources_have_unresolved_restart_evidence')
    return {
        'version': 1, 'observed_at': now.isoformat(), 'boot_id': current.get('boot_id'),
        'inventory_identity_digest': current.get('identity_digest'),
        'business_evidence_status': 'blocked' if blockers else 'signed_evidence_complete_under_configured_trust',
        'blockers': sorted(set(blockers)), 'resources': rows,
        'safe_reboot_proven': False, 'power_action_authorized': False,
        'controller_reboot_executed': False,
        'scope': 'signed native per-resource drain/checkpoint/isolated-recovery evidence review; separate maintenance authorization and independent recovery are still required',
    }


def write_report(path, value):
    data = json.dumps(value, ensure_ascii=False, indent=2).encode() + b'\n'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'report': str(path), 'sha256': hashlib.sha256(data).hexdigest(), 'power_action_authorized': False}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('inspect', 'evaluate'))
    parser.add_argument('--out', required=True)
    parser.add_argument('--inventory')
    parser.add_argument('--manifest')
    parser.add_argument('--trust')
    parser.add_argument('--max-age-seconds', type=int, default=60)
    args = parser.parse_args()
    current = collect_snapshot()
    if args.action == 'inspect':
        result = current
    else:
        if not args.inventory or not args.manifest or not args.trust:
            parser.error('evaluate requires independently captured inventory, receipt manifest and signer trust')
        result = evaluate(read_object(args.inventory), current, read_object(args.manifest), read_object(args.trust), max_age=args.max_age_seconds)
    write_report(args.out, result)


if __name__ == '__main__':
    main()
