"""Optional public-repository runner. Deploy remains blocked pending dependency/security review."""
import argparse
import base64
import datetime as dt
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile
import worker

BUNDLE_AAD = b"approved-snap-cloud-bundle-v1"
STATE_AAD = b"approved-snap-cloud-state-v1"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_STATE_BYTES = 1024 * 1024


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
    day = now.astimezone(worker.RIYADH).date()
    if mode == "publish":
        return dt.date(2026, 11, 2) <= day <= dt.date(2026, 11, 29)
    return mode == "verify" and dt.date(2026, 11, 1) <= day <= dt.date(2026, 12, 1)


def verify_existing(root, config, api):
    """Two GETs only. No ledger/save/POST path is reachable from this function."""
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
    channels = api.call("GET", "/api/channels")
    selected = [c for c in channels["channels"] if c.get("id") == config.get("channel_id")]
    worker.require(len(selected) == 1, "verify_channel_missing")
    channel = selected[0]
    worker.require(config.get("identity_evidence_reference") and channel.get("accountId") == config.get("provider_account_id")
                   and channel.get("platform") == "snapchat" and channel.get("accountType") == "public_profile"
                   and channel.get("isActive") is True and channel.get("needsReconnect") is False
                   and channel.get("tokenStatus") == "valid", "verify_identity_mismatch")
    response = api.call("GET", "/api/posts/" + str(entry["provider_post_id"]))
    post = worker.pointer(response, c["read_post"])
    worker.require(worker.exact_scheduled_post(post, item, channel["id"], entry["media_id"],
                   entry["provider_post_id"], statuses=("scheduled", "published")), "verify_post_mismatch")
    media = post["mediaFiles"][0]
    worker.require(media.get("mimeType") == entry.get("provider_mime_type")
                   and media.get("sizeBytes") == entry.get("provider_size_bytes"), "verify_media_metadata_changed")
    return {"status": "verified_existing_post_read_only", "requests": api.count}


def run(repo, execute=False, mode="verify", now=None):
    now = now or dt.datetime.now(worker.RIYADH)
    worker.require(mode in ("verify", "publish") and not (mode == "verify" and execute), "verify_cannot_execute")
    needs_api = mode == "verify" or execute
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
    p.add_argument("--mode", choices=["verify", "publish"], default="verify")
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
