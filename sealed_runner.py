"""Optional public-repository runner. Deploy remains blocked pending dependency/security review."""
import argparse
import base64
import datetime as dt
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile
import re
import worker

BUNDLE_AAD = b"approved-snap-cloud-bundle-v1"
STATE_AAD = b"approved-snap-cloud-state-v1"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024
AUDIBLE_MEDIA_STAGE_REF = "refs/heads/codex/snap-audible-media-stage"
AUDIBLE_MEDIA_STAGE_AAD = b"approved-snap-audible-media-stage-state-v1"
AUDIBLE_MEDIA_BUNDLE_SHA = "2d3164511fd9d367239e3c205835e540a66bce62f33aa002c9434f4aaec38586"
AUDIBLE_CALENDAR_SHA = "1f3eb703fec69b09d45bc74680e769fe4903221c4e0e95fbf81287ad668ee66e"


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


class AudibleMediaTransport(worker.Transport):
    request_limit = 11

    def call(self, method, path, body=None, content_type="application/json"):
        valid_read = method == "GET" and body is None and path in (
            "/api/api-keys/usage", "/api/quotas/usage", "/api/channels")
        valid_upload = method == "POST" and body is not None and path == "/api/media"
        worker.require(valid_read or valid_upload, "media_stage_transport_scope")
        return super().call(method, path, body, content_type)


class AudibleCalendarTransport(worker.Transport):
    request_limit = 12

    def call(self, method, path, body=None, content_type="application/json"):
        allowed = path in ("/api/api-keys/usage", "/api/quotas/usage?tz=Asia%2FRiyadh",
                           "/api/posts?scheduledFrom=2026-11-10&scheduledTo=2026-11-30&limit=500")
        worker.require(method == "GET" and body is None
                       and (allowed or re.fullmatch(r"/api/(?:media/[1-9][0-9]*|posts\?channelId=[1-9][0-9]*&limit=500)", path)),
                       "media_stage_calendar_read_only")
        return super().call(method, path, body, content_type)


def read_frozen_stage_config(repo, root):
    root.mkdir()
    extract_bundle(decrypt((repo / "bundle.sealed").read_bytes(), BUNDLE_AAD), root)
    config = worker.read(root / "config.json")
    approved = worker.read(root / "manifest.json")
    worker.require(approved["account"] == config["verified_username"]
                   and approved["audience"] == "My Story Public" and config.get("identity_evidence_reference")
                   and worker.sha(root / "manifest.json") == config.get("manifest_sha256"),
                   "media_stage_destination_unverified")
    return config


def verify_audible_calendar(repo, receiver, now):
    import audible_envelope
    import audible_schedule_preflight

    calendar_file = repo / "audible-calendar.sealed"
    state_file = repo / "audible-media-stage-state.sealed"
    worker.require(calendar_file.stat().st_size < 16 * 1024 and state_file.stat().st_size <= 16 * 1024,
                   "media_stage_calendar_bundle_size")
    private = audible_envelope.open_in_runner(calendar_file.read_bytes(), receiver)
    worker.require(sha256(private).hexdigest() == AUDIBLE_CALENDAR_SHA, "media_stage_calendar_unapproved")
    state = json.loads(decrypt(state_file.read_bytes(), AUDIBLE_MEDIA_STAGE_AAD))
    key = os.environ.get("BULKPUBLISH_API_KEY", "")
    worker.require(key.startswith("bp_"), "media_stage_api_key_missing")
    with tempfile.TemporaryDirectory(prefix="audible-calendar-read-") as folder:
        config = read_frozen_stage_config(repo, Path(folder) / "frozen")
        result = audible_schedule_preflight.check(json.loads(private), state, config, AudibleCalendarTransport(key), now)
    print(json.dumps(result))


def run_audible_media_stage(repo, execute, mode, now):
    import audible_envelope
    import audible_media_stage

    local = now.astimezone(worker.RIYADH)
    worker.require(os.environ.get("GITHUB_REPOSITORY") == "taqdeersa/approved-content-queue-2026-11"
                   and local.date() == dt.date(2026, 11, 10)
                   and os.environ.get("QUEUE_ZERO_COST_VERIFIED") == "true"
                   and (mode, execute) in (("verify", False), ("publish", True)), "media_stage_scope")
    receiver = audible_envelope.runner_receiver(os.environ["SNAP_QUEUE_SEAL_KEY"])
    if mode == "verify" and not (repo / "audible-calendar.sealed").exists():
        print("AUDIBLE_RECEIVER_PUBLIC_V1=" + base64.b64encode(audible_envelope.public_bytes(receiver)).decode("ascii"))
        return
    worker.require(not dt.time(10, 10) <= local.time() <= dt.time(10, 25), "media_stage_silent_window_reserved")
    if mode == "verify":
        verify_audible_calendar(repo, receiver, now)
        return
    key = os.environ.get("BULKPUBLISH_API_KEY", "")
    worker.require(key.startswith("bp_"), "media_stage_api_key_missing")
    encrypted_bundle = repo / "audible-media-stage.sealed"
    worker.require(encrypted_bundle.stat().st_size <= audible_envelope.MAX_BUNDLE_BYTES + audible_envelope.OVERHEAD,
                   "media_stage_envelope_size")
    private = audible_envelope.open_in_runner(encrypted_bundle.read_bytes(), receiver)
    worker.require(sha256(private).hexdigest() == AUDIBLE_MEDIA_BUNDLE_SHA, "media_stage_unapproved_bundle")
    state_file = repo / "audible-media-stage-state.sealed"
    prior = None
    if state_file.exists():
        worker.require(state_file.stat().st_size <= 16 * 1024, "media_stage_checkpoint_size")
        prior = json.loads(decrypt(state_file.read_bytes(), AUDIBLE_MEDIA_STAGE_AAD))

    def checkpoint(state):
        plain = json.dumps(state, separators=(",", ":")).encode()
        worker.require(len(plain) <= 16 * 1024 - 28, "media_stage_checkpoint_size")
        tmp = state_file.with_suffix(".tmp")
        tmp.write_bytes(encrypt(plain, AUDIBLE_MEDIA_STAGE_AAD))
        tmp.replace(state_file)
        for args in (["add", "--", state_file.name], ["commit", "-m", "Persist encrypted media upload checkpoint"],
                     ["push", "origin", "HEAD:" + AUDIBLE_MEDIA_STAGE_REF]):
            result = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=25)
            worker.require(result.returncode == 0, "media_stage_checkpoint_not_persisted")
        return True

    with tempfile.TemporaryDirectory(prefix="audible-media-stage-") as folder:
        root = Path(folder)
        config = read_frozen_stage_config(repo, root / "frozen")
        media_root = root / "media"
        media_root.mkdir()
        with zipfile.ZipFile(io.BytesIO(private)) as bundle:
            entries = bundle.infolist()
            names = {item.filename for item in entries}
            worker.require(len(entries) == len(names) == 9
                           and sum(item.file_size for item in entries) <= audible_envelope.MAX_BUNDLE_BYTES
                           and bundle.getinfo("manifest.json").file_size <= 16 * 1024,
                           "media_stage_archive_shape")
            manifest = json.loads(bundle.read("manifest.json"))
            files = {item["file"] for item in manifest["items"]}
            worker.require(names == files | {"manifest.json"}
                           and all(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.mp4", name) for name in files),
                           "media_stage_archive_entries")
            for name in files:
                (media_root / name).write_bytes(bundle.read(name))
        api = AudibleMediaTransport(key)
        result = audible_media_stage.stage(media_root, config, manifest, api, checkpoint, prior)
        print(json.dumps({"status": result["status"], "count": result["count"], "requests": api.count}))


def run(repo, execute=False, mode="verify", now=None):
    now = now or dt.datetime.now(worker.RIYADH)
    if os.environ.get("GITHUB_REF") == AUDIBLE_MEDIA_STAGE_REF:
        run_audible_media_stage(repo, execute, mode, now)
        return
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

        api = worker.Transport(key)
        if mode == "verify":
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
    except Exception as error:
        if os.environ.get("GITHUB_REF") == AUDIBLE_MEDIA_STAGE_REF:
            reason = str(error) if isinstance(error, worker.Halt) else "media_stage_unexpected_result"
            if not re.fullmatch(r"(?:media_stage_|http_or_json_result_unknown_)[a-zA-Z0-9_]{1,75}", reason):
                reason = "media_stage_runtime_gate"
            print(json.dumps({"status": "audible_media_stage_halted", "reason": reason}))
        print('{"status":"halt","reason":"sealed_runner_gate_or_result_unknown"}')
        raise SystemExit(2)
