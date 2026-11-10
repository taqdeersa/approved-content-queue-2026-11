"""Upload an authenticated, preverified MP4 batch to the existing media library.

The runner must authenticate the bundle, protect its extracted files, and supply
an exclusive, opaque, durable checkpoint. This module never creates posts.
"""

from copy import deepcopy
from hashlib import sha256
import json
import math
from pathlib import Path
import re

import worker


MAX_ITEMS = 8
MAX_BATCH_BYTES = 48 * 1024 * 1024
API_RESERVE = 8
STORAGE_RESERVE_MB = 100


def prepare(root, manifest):
    items = manifest.get("items")
    worker.require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1
                   and isinstance(items, list) and 0 < len(items) <= MAX_ITEMS,
                   "media_stage_invalid_manifest")
    root = Path(root).resolve(strict=True)
    plan, names, digests = {}, set(), set()
    total_bytes = 0
    for item in items:
        worker.require(isinstance(item, dict), "media_stage_invalid_item")
        event, name, digest, size = (item.get(key) for key in ("event_id", "file", "sha256", "bytes"))
        worker.require(isinstance(event, str)
                       and (re.fullmatch(r"2026-11-(?:1[0-9]|2[0-9]|30):main", event) or event == "2026-11-10:trend")
                       and event not in plan and isinstance(name, str)
                       and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\.mp4", name)
                       and name.casefold() not in names and isinstance(digest, str)
                       and re.fullmatch(r"[a-f0-9]{64}", digest) and digest not in digests
                       and type(size) is int and 8 <= size <= MAX_BATCH_BYTES,
                       "media_stage_invalid_item")
        path = root / name
        worker.require(path.resolve(strict=True).parent == root and not path.is_symlink()
                       and path.is_file() and path.stat().st_size == size, "media_stage_file_changed")
        total_bytes += size
        worker.require(total_bytes <= MAX_BATCH_BYTES, "media_stage_batch_size")
        with path.open("rb") as source:
            data = source.read(size + 1)
        worker.require(len(data) == size and data[4:8] == b"ftyp" and sha256(data).hexdigest() == digest,
                       "media_stage_file_changed")
        plan[event] = (path, digest, size)
        names.add(name.casefold())
        digests.add(digest)
    manifest_hash = sha256(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return plan, manifest_hash


def previous(state, manifest_hash, plan):
    if state is None:
        return {"schema_version": 1, "manifest_sha256": manifest_hash, "items": {}}
    worker.require(isinstance(state, dict) and type(state.get("schema_version")) is int
                   and state["schema_version"] == 1 and state.get("manifest_sha256") == manifest_hash
                   and isinstance(state.get("items"), dict), "media_stage_checkpoint_mismatch")
    ids = set()
    for event, item in state["items"].items():
        worker.require(event in plan and isinstance(item, dict) and item.get("sha256") == plan[event][1],
                       "media_stage_checkpoint_mismatch")
        worker.require(item.get("phase") == "uploaded_verified", "media_stage_prior_attempt_unresolved")
        media_id = item.get("media_id")
        worker.require(type(media_id) is int and media_id > 0 and media_id not in ids,
                       "media_stage_checkpoint_mismatch")
        ids.add(media_id)
    return deepcopy(state)


def preflight(config, api, pending):
    contract = config.get("response_contract", {})
    worker.require(config.get("public_repository_sealed_verified") is True
                   and config.get("live_authorization_verified") is True and config.get("cost_evidence_reference")
                   and contract.get("verified_from_actual_responses") is True and contract.get("evidence_reference")
                   and all(isinstance(contract.get(key), list) for key in ("plan", "api_limit", "api_used"))
                   and isinstance(config.get("verified_username"), str) and config["verified_username"]
                   and type(config.get("channel_id")) is int and config["channel_id"] > 0
                   and config.get("provider_account_id"), "media_stage_protected_gates_missing")
    usage = api.call("GET", "/api/api-keys/usage")
    worker.require(worker.pointer(usage, contract["plan"]) == "pro", "media_stage_pro_required")
    limit, used = (worker.pointer(usage, contract[key]) for key in ("api_limit", "api_used"))
    worker.require(type(limit) is int and type(used) is int and 0 <= used <= limit - len(pending) - 3 - API_RESERVE,
                   "media_stage_api_headroom")

    quota = api.call("GET", "/api/quotas/usage")
    limit, used = quota["limits"].get("mediaStorageMB"), quota["usage"].get("mediaStorageMB")
    bytes_pending = sum(size for _, _, size in pending.values())
    worker.require(type(limit) in (int, float) and type(used) in (int, float)
                   and math.isfinite(limit) and math.isfinite(used) and 0 <= used
                   and used + STORAGE_RESERVE_MB + bytes_pending / 1_000_000 < limit,
                   "media_stage_storage_headroom")

    channels = api.call("GET", "/api/channels")
    matching = [channel for channel in channels["channels"] if channel.get("id") == config["channel_id"]]
    worker.require(len(matching) == 1, "media_stage_channel_unverified")
    channel = matching[0]
    worker.require(channel.get("accountId") == config["provider_account_id"]
                   and channel.get("platform") == "snapchat" and channel.get("accountType") == "public_profile"
                   and channel.get("isActive") is True and channel.get("needsReconnect") is False
                   and channel.get("tokenStatus") == "valid"
                   and channels.get("capabilities", {}).get("canCreatePosts") is True,
                   "media_stage_channel_unverified")


def stage(root, config, manifest, api, checkpoint, prior_state=None):
    """Stage exact assets using a bounded worker.Transport and a sealed checkpoint.

    A timeout or response mismatch intentionally leaves an unresolved reservation.
    A later run must reconcile it outside this path before it can upload again.
    """
    plan, manifest_hash = prepare(root, manifest)
    state = previous(prior_state, manifest_hash, plan)
    entries = state["items"]
    pending = {event: item for event, item in plan.items() if event not in entries}
    if not pending:
        return {"status": "audible_media_staged", "count": len(entries)}
    preflight(config, api, pending)
    media_ids = {item["media_id"] for item in entries.values()}
    for event, (path, digest, size) in pending.items():
        body, content_type = worker.multipart(path)
        boundary = content_type.removeprefix("multipart/form-data; boundary=")
        head_end = body.find(b"\r\n\r\n") + 4
        trailer = f"\r\n--{boundary}--\r\n".encode()
        payload = memoryview(body)[head_end:-len(trailer)]
        worker.require(head_end >= 4 and body.endswith(trailer) and len(payload) == size
                       and sha256(payload).hexdigest() == digest, "media_stage_file_changed")
        entry = {"phase": "upload_pending", "sha256": digest}
        entries[event] = entry
        worker.require(checkpoint(deepcopy(state)) is True, "media_stage_checkpoint_not_persisted")

        response = api.call("POST", "/api/media", body, content_type)
        media = worker.response_candidate(response, "media")
        media_id = media["id"]
        worker.require(media["fileName"] == path.name and media["mimeType"] == "video/mp4"
                       and media["sizeBytes"] == size and media_id not in media_ids,
                       "media_stage_upload_response_mismatch_no_retry")
        entry.update(phase="uploaded_verified", media_id=media_id)
        worker.require(checkpoint(deepcopy(state)) is True, "media_stage_checkpoint_not_persisted")
        media_ids.add(media_id)
    return {"status": "audible_media_staged", "count": len(entries)}
