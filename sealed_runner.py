"""Optional public-repository runner. Deploy remains blocked pending dependency/security review."""
import argparse
import base64
import datetime as dt
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import zipfile
import worker

BUNDLE_AAD = b"approved-snap-cloud-bundle-v1"
STATE_AAD = b"approved-snap-cloud-state-v1"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
AUDIBLE_PROBE_REF = "refs/heads/codex/snap-audible-november"


def cipher():
    # Dependency must be reviewed/pinned before deployment. No runtime auto-install.
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(os.environ["SNAP_QUEUE_SEAL_KEY"], validate=True)
    worker.require(len(key) == 32, "seal_key_must_be_256_bits")
    return AESGCM(key)


def encrypt(data, aad=BUNDLE_AAD):
    nonce = os.urandom(12)
    return nonce + cipher().encrypt(nonce, data, aad)


def decrypt(data, aad=BUNDLE_AAD):
    worker.require(28 <= len(data) <= MAX_BUNDLE_BYTES + 28, "sealed_size_invalid")
    return cipher().decrypt(data[:12], data[12:], aad)


def extract_bundle(data, root):
    worker.require(len(data) <= MAX_BUNDLE_BYTES, "bundle_size_invalid")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        worker.require(len(entries) <= 64 and len(set(names)) == len(names), "archive_entries_invalid")
        worker.require(sum(e.file_size for e in entries) <= MAX_BUNDLE_BYTES, "archive_expansion_invalid")
        for name in names:
            worker.require("\\" not in name and not name.startswith("/")
                           and (root / name).resolve().is_relative_to(root.resolve()), "unsafe_archive_path")
        worker.require("manifest.json" in names and "config.json" in names, "archive_missing_metadata")
        manifest = json.loads(archive.read("manifest.json"))
        worker.require(len(manifest.get("items", [])) == 29, "archive_manifest_invalid")
        allowed = {"manifest.json", "config.json"}
        for item in manifest["items"]:
            for kind in ("asset", "text"):
                allowed.add(item[kind])
        worker.require(set(names) == allowed, "archive_allowlist_mismatch")
        archive.extractall(root)


def seal(source, target):
    worker.require(not target.exists(), "sealed_bundle_already_exists")
    manifest = worker.read(source / "manifest.json")
    config = worker.read(source / "config.json")
    worker.require(config.get("public_repository_sealed_verified") is True, "public_sealing_review_missing")
    allowed = {"manifest.json", "config.json"}
    for item in manifest["items"]:
        for kind in ("asset", "text"):
            path = (source / item[kind]).resolve()
            worker.require(path.is_relative_to(source.resolve()) and worker.sha(path) == item[kind + "_sha256"], "seal_asset_hash")
            allowed.add(item[kind])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(allowed):
            archive.write(source / name, name)
    worker.require(len(buf.getvalue()) <= MAX_BUNDLE_BYTES, "bundle_size_invalid")
    target.write_bytes(encrypt(buf.getvalue()))


def execution_window(now, mode):
    local = now.astimezone(worker.RIYADH)
    day = local.date()
    if mode == "delivery":
        return day == dt.date(2026, 11, 2) and local.hour >= 9
    if mode == "publish":
        return dt.date(2026, 11, 2) <= day <= dt.date(2026, 11, 29)
    return mode == "verify" and dt.date(2026, 11, 1) <= day <= dt.date(2026, 12, 1)


def verification_context(root, config):
    """Validate immutable local inputs before any API request."""
    manifest, state = worker.read(root / "manifest.json"), worker.read(root / "state.json")
    c = config.get("response_contract", {})
    worker.require(config.get("public_repository_sealed_verified") is True
                   and config.get("cost_evidence_reference") and config.get("live_authorization_verified") is True
                   and c.get("verified_from_actual_responses") is True and c.get("evidence_reference")
                   and isinstance(c.get("read_post"), list), "verify_gates_missing")
    worker.require(worker.sha(root / "manifest.json") == config.get("manifest_sha256")
                   and manifest["source_sha256"] == worker.PLAN_SHA and manifest["approval_reference"] == worker.APPROVAL
                   and manifest["account"] == config.get("verified_username") and manifest["audience"] == "My Story Public"
                   and manifest["duration_hours"] == 24 and manifest["timezone"] == "Asia/Riyadh"
                   and len(manifest["items"]) == 29 and {i["day"] for i in manifest["items"]} == set(range(2, 31)),
                   "verify_frozen_manifest_invalid")
    for item in manifest["items"]:
        for kind in ("asset", "text"):
            path = (root / item[kind]).resolve()
            worker.require(path.is_relative_to(root.resolve()) and worker.sha(path) == item[kind + "_sha256"],
                           "verify_bundle_hash_changed")
    item = next(i for i in manifest["items"] if i["day"] == 2)
    entry = state["items"]["2"]
    worker.require(state.get("schema") == 1 and entry.get("phase") == "queued_verified"
                   and entry.get("asset_sha256") == item["asset_sha256"]
                   and entry.get("scheduled_at") == item["scheduled_at"]
                   and type(entry.get("provider_post_id")) is int and entry["provider_post_id"] > 0
                   and type(entry.get("media_id")) is int and entry["media_id"] > 0,
                   "verify_existing_state_invalid")
    worker.require(isinstance(entry.get("provider_mime_type"), str)
                   and type(entry.get("provider_size_bytes")) is int and entry["provider_size_bytes"] > 0,
                   "verify_media_pin_missing")
    return state, item, entry


def read_existing(root, config, api, statuses=("scheduled", "published"), context=None):
    """Two GETs only, returning private data to the encrypted caller."""
    state, item, entry = context or verification_context(root, config)
    channels = api.call("GET", "/api/channels")
    selected = [c for c in channels["channels"] if c.get("id") == config.get("channel_id")]
    worker.require(len(selected) == 1, "verify_channel_missing")
    channel = selected[0]
    worker.require(config.get("identity_evidence_reference") and channel.get("accountId") == config.get("provider_account_id")
                   and channel.get("platform") == "snapchat" and channel.get("accountType") == "public_profile"
                   and channel.get("isActive") is True and channel.get("needsReconnect") is False
                   and channel.get("tokenStatus") == "valid", "verify_identity_mismatch")
    response = api.call("GET", "/api/posts/" + str(entry["provider_post_id"]))
    post = worker.pointer(response, config["response_contract"]["read_post"])
    worker.require(worker.exact_scheduled_post(post, item, channel["id"], entry["media_id"],
                   entry["provider_post_id"], statuses=statuses), "verify_post_mismatch")
    media = post["mediaFiles"][0]
    worker.require(media.get("mimeType") == entry.get("provider_mime_type")
                   and media.get("sizeBytes") == entry.get("provider_size_bytes"), "verify_media_metadata_changed")
    return post


def verify_existing(root, config, api):
    read_existing(root, config, api)
    return {"status": "verified_existing_post_read_only", "requests": api.count}


class AudibleProbeTransport(worker.Transport):
    def call(self, method, path, body=None, content_type="application/json"):
        allowed = path in ("/api/api-keys/usage", "/api/quotas/usage", "/api/channels")
        worker.require(method == "GET" and body is None and self.count < 5
                       and (allowed or re.fullmatch(r"/api/posts/[1-9][0-9]*", path)),
                       "audible_probe_read_only")
        result = super().call(method, path, body, content_type)
        if path == "/api/channels":
            capabilities = result.get("capabilities", {})
            worker.require(capabilities.get("canCreatePosts") is True
                           and capabilities.get("canPublishPosts") is True, "audible_probe_write_scope")
        return result


def verify_audible_route(root, config, api, now):
    state, _, _ = verification_context(root, config)
    manifest = worker.read(root / "manifest.json")
    contract = config["response_contract"]
    worker.require(all(isinstance(contract.get(key), list) for key in ("plan", "api_limit", "api_used")),
                   "audible_probe_unverified_usage_schema")
    usage = api.call("GET", "/api/api-keys/usage")
    limit = worker.pointer(usage, contract["api_limit"])
    used = worker.pointer(usage, contract["api_used"])
    worker.require(worker.pointer(usage, contract["plan"]) == "pro"
                   and type(limit) is int and type(used) is int and 0 <= used <= limit - 15,
                   "audible_probe_no_safe_plan_headroom")
    quota = api.call("GET", "/api/quotas/usage")
    worker.require(quota["limits"]["postsPerDay"] > quota["usage"]["postsToday"]
                   and quota["limits"]["postsPerMonth"] > quota["usage"]["postsThisMonth"],
                   "audible_probe_no_post_headroom")
    day = now.astimezone(worker.RIYADH).day
    items = {item["day"]: item for item in manifest["items"]}
    for item in (items[day], items[day + 1]):
        entry = state["items"][str(item["day"])]
        worker.require(entry["phase"] == "queued_verified" and entry["scheduled_at"] == item["scheduled_at"]
                       and entry["asset_sha256"] == item["asset_sha256"]
                       and type(entry["provider_post_id"]) is int and entry["provider_post_id"] > 0
                       and type(entry["media_id"]) is int and entry["media_id"] > 0,
                       "audible_probe_silent_checkpoint_mismatch")
    post = read_existing(root, config, api, statuses=("published",), context=(state, items[day], state["items"][str(day)]))
    snap = post["postPlatforms"][0]
    published_at = snap.get("publishedAt") or post.get("publishedAt")
    worker.require(snap.get("status") == "published" and isinstance(snap.get("platformPostId"), str)
                   and snap["platformPostId"].strip() and isinstance(published_at, str)
                   and dt.datetime.fromisoformat(items[day]["scheduled_at"])
                   <= dt.datetime.fromisoformat(published_at.replace("Z", "+00:00")) <= now,
                   "audible_probe_missing_platform_delivery_receipt")
    next_entry = state["items"][str(day + 1)]
    next_id = next_entry["provider_post_id"]
    response = api.call("GET", f"/api/posts/{next_id}")
    queued = worker.pointer(response, contract["read_post"])
    worker.require(worker.exact_scheduled_post(queued, items[day + 1], config["channel_id"], next_entry["media_id"], next_id),
                   "audible_probe_next_silent_post_not_scheduled")
    return {"status": "audible_cloud_probe_verified_read_only", "requests": api.count}


def delivery_check(root, config, api, now, checkpoint):
    """One reserved read-only provider check; only encrypted checkpoint writes."""
    worker.require(execution_window(now, "delivery"), "delivery_window_closed")
    context = verification_context(root, config)
    state, item, entry = context
    worker.require(not entry.get("delivery_evidence"), "delivery_already_attempted_no_retry")
    evidence = {"status": "read_pending", "attempt_id": os.urandom(16).hex(),
                "checked_at": now.isoformat(), "provider": "BulkPublish",
                "source": "provider_api_two_gets", "snapchat_visual_appearance_verified": False,
                "provider_reported_published": False}
    entry["delivery_evidence"] = evidence
    entry["phase"] = "delivery_check_in_progress"
    checkpoint(root, state)  # A crash must not permit another check or blind feed.
    try:
        post = read_existing(root, config, api,
            statuses=("scheduled", "published", "processing", "publishing", "failed", "partial"), context=context)
        snap = post["postPlatforms"][0]
        evidence.update(post_status=post["status"], snapchat_status=snap.get("status"),
                        provider_post_id=post["id"], requests=api.count)
        timestamp, timestamp_source = None, None
        for source, value in [("snapchat_platform", snap.get("publishedAt")), ("global_post", post.get("publishedAt"))]:
            try:
                parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
                if parsed.utcoffset() is not None and dt.datetime.fromisoformat(item["scheduled_at"]) <= parsed <= now:
                    timestamp, timestamp_source = value, source
                    break
            except (AttributeError, ValueError, TypeError):
                pass
        platform_id = snap.get("platformPostId")
        reported = (post["status"] == "published" and snap.get("status") == "published"
                    and isinstance(platform_id, str) and bool(platform_id.strip()) and timestamp is not None)
        failed = post["status"] in ("failed", "partial") or snap.get("status") == "failed"
        status = ("provider_reported_delivery_failed_requires_review" if failed else
                  "provider_reported_published" if reported else "provider_not_yet_reported_published")
        evidence.update(status=status, provider_reported_published=reported,
                        platform_post_id=platform_id if isinstance(platform_id, str) else None,
                        published_at=timestamp, timestamp_source=timestamp_source)
        entry["phase"] = "delivery_failed_requires_review" if failed else "queued_verified"
        checkpoint(root, state)
        return {"status": status, "requests": api.count}
    except Exception:
        evidence.update(status="delivery_read_unknown_requires_review", requests=api.count)
        entry["phase"] = "delivery_read_unknown_requires_review"
        checkpoint(root, state)
        raise worker.Halt("delivery_result_unknown_no_retry")


def run(repo, execute=False, mode="verify", now=None):
    now = now or dt.datetime.now(worker.RIYADH)
    audible_probe = os.environ.get("GITHUB_REF") == AUDIBLE_PROBE_REF
    if audible_probe:
        worker.require(mode == "verify" and not execute
                       and os.environ.get("GITHUB_REPOSITORY") == "taqdeersa/approved-content-queue-2026-11"
                       and now.astimezone(worker.RIYADH).date() == dt.date(2026, 11, 9),
                       "audible_probe_scope_or_mode")
    worker.require(mode in ("verify", "publish", "delivery") and not (mode != "publish" and execute), "read_only_mode_cannot_execute")
    needs_api = mode in ("verify", "delivery") or execute
    worker.require(not needs_api or execution_window(now, mode), "execution_window_closed")
    worker.require(os.environ.get("QUEUE_ZERO_COST_VERIFIED") == "true" or not needs_api, "cost_gate")
    key = os.environ.get("BULKPUBLISH_API_KEY", "")
    worker.require(not needs_api or key.startswith("bp_"), "api_key_missing")
    with tempfile.TemporaryDirectory(prefix="sealed-queue-") as folder:
        root = Path(folder)
        bundle = repo / "bundle.sealed"
        worker.require(bundle.stat().st_size <= MAX_BUNDLE_BYTES + 28, "sealed_bundle_size_invalid")
        extract_bundle(decrypt(bundle.read_bytes(), BUNDLE_AAD), root)
        if (repo / "state.sealed").exists():
            state = repo / "state.sealed"
            worker.require(state.stat().st_size <= MAX_STATE_BYTES + 28, "sealed_state_size_invalid")
            (root / "state.json").write_bytes(decrypt(state.read_bytes(), STATE_AAD))
        config = worker.read(root / "config.json")
        worker.require(config.get("public_repository_sealed_verified") is True, "sealed_public_gate_missing")

        def checkpoint(_root, state):
            tmp = repo / "state.sealed.tmp"
            plain = json.dumps(state).encode()
            worker.require(len(plain) <= MAX_STATE_BYTES, "state_size_invalid")
            tmp.write_bytes(encrypt(plain, STATE_AAD))
            tmp.replace(repo / "state.sealed")
            for args in [["add", "--", "state.sealed"], ["commit", "-m", "Persist encrypted queue checkpoint"], ["push", "origin", "HEAD"]]:
                result = subprocess.run(["git", "-C", str(repo)] + args, capture_output=True, timeout=30)
                worker.require(result.returncode == 0, "encrypted_checkpoint_not_persisted")

        api = AudibleProbeTransport(key) if audible_probe else worker.Transport(key)
        if audible_probe:
            result = verify_audible_route(root, config, api, now)
        elif mode == "verify":
            result = verify_existing(root, config, api)
        elif mode == "delivery":
            result = delivery_check(root, config, api, now, checkpoint)
        else:
            result = worker.run(root, config, api, now, checkpoint, execute)
        # Only generic result status/count; no account, text, provider IDs, or timestamps.
        print(json.dumps({"status": result["status"], "requests": result.get("requests", 0)}))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["seal", "run"])
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--target", type=Path)
    p.add_argument("--execute", action="store_true")
    p.add_argument("--mode", choices=["verify", "publish", "delivery"], default="verify")
    a = p.parse_args()
    try:
        if a.command == "seal":
            worker.require(a.target is not None, "target_required")
            seal(a.root.resolve(), a.target.resolve())
        else:
            run(a.root.resolve(), a.execute, a.mode)
    except Exception:
        print('{"status":"halt","reason":"sealed_runner_gate_or_result_unknown"}')
        raise SystemExit(2)
