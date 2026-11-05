"""One-off, five-GET entitlement and capacity check for the approved Snap feed."""

import datetime as dt
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sys
import zipfile

from sealed_runner import BUNDLE_AAD, MAX_BUNDLE_BYTES, decrypt
from worker import Halt, RIYADH, Transport, pointer, read, require


SNAP_CHANNEL = 4659
PENDING = {"scheduled", "publishing", "processing"}
STATUSES = PENDING | {"draft", "published", "failed", "partial"}


def as_time(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() is not None, "timestamp_missing_offset")
    return parsed


def as_count(value):
    require(type(value) is int and value >= 0, "unverified_numeric_quota")
    return value


def read_pinned_scope(repo):
    bundle = repo / "bundle.sealed"
    require(bundle.stat().st_size <= MAX_BUNDLE_BYTES + 28, "bundle_size")
    plain = decrypt(bundle.read_bytes(), BUNDLE_AAD)
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        names = archive.namelist()
        for name in ("manifest.json", "config.json"):
            require(names.count(name) == 1 and archive.getinfo(name).file_size <= 256 * 1024,
                    "sealed_metadata_invalid")
        config = json.loads(archive.read("config.json"))
        manifest_bytes = archive.read("manifest.json")
    manifest = json.loads(manifest_bytes)
    require(config.get("public_repository_sealed_verified") is True
            and config.get("live_authorization_verified") is True
            and config.get("channel_id") == SNAP_CHANNEL
            and config.get("verified_username") == manifest.get("account")
            and manifest.get("audience") == "My Story Public"
            and hashlib.sha256(manifest_bytes).hexdigest() == config.get("manifest_sha256")
            and {item["day"] for item in manifest["items"]} == set(range(2, 31)),
            "pinned_snap_scope_unverified")
    final_at = max(as_time(item["scheduled_at"]) for item in manifest["items"])
    return config, final_at


def collect(api, config, final_at, proof, now):
    ref = proof.get("receipt_evidence_ref")
    cancellation_ref = proof.get("cancellation_evidence_ref")
    paid_through = dt.date.fromisoformat(proof["paid_through_riyadh_date"])
    paid_end = as_time(proof["paid_period_end_utc"])
    require(proof.get("plan") == "pro" and proof.get("currency") == "USD"
            and proof.get("total_usd") == "16.09" and type(proof.get("cycle_count")) is int
            and proof["cycle_count"] == 1 and ref != cancellation_ref
            and all(isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value)
                    for value in (ref, cancellation_ref))
            and paid_end.astimezone(RIYADH).date() == paid_through
            and max(final_at, now) < paid_end <= now + dt.timedelta(days=32),
            "approved_receipt_evidence_missing")

    def get(path):
        return api.call("GET", path)

    snap_platform = [p for p in get("/api/platforms")["platforms"] if p.get("platform") == "snapchat"]
    require(len(snap_platform) == 1 and snap_platform[0].get("enabled") is True
            and snap_platform[0].get("canPublish") is True, "snapchat_platform_unavailable")
    channel_result = get("/api/channels")
    channels = [c for c in channel_result["channels"] if c.get("id") == SNAP_CHANNEL]
    caps = channel_result.get("capabilities", {})
    require(len(channels) == 1 and caps.get("canCreatePosts") is True
            and caps.get("canPublishPosts") is True, "snapchat_role_or_channel_unverified")
    channel = channels[0]
    require(channel.get("accountId") == config["provider_account_id"]
            and channel.get("platform") == "snapchat" and channel.get("isActive") is True
            and channel.get("needsReconnect") is False and channel.get("tokenStatus") == "valid",
            "pinned_snap_channel_unhealthy")

    quota = get("/api/quotas/usage?tz=Asia%2FRiyadh")
    require(quota.get("plan") == "pro", "workspace_plan_not_pro")
    subscription = quota.get("subscription") or {}
    end_value = subscription.get("currentPeriodEnd")
    end = as_time(end_value) if end_value else None
    if end is not None:
        require(end > max(final_at, now) and abs(end - paid_end) < dt.timedelta(seconds=1),
                "live_and_receipt_period_disagree")
    renew = subscription.get("cancelAtPeriodEnd")
    require(renew is None or renew is True, "live_autorenew_conflicts_with_receipt")

    limits, used = quota["limits"], quota["usage"]
    capacity = {}
    for name, lim_key, used_key, minimum in (("creation_today", "postsPerDay", "postsToday", 1),
                                            ("creation_month", "postsPerMonth", "postsThisMonth", 30),
                                            ("scheduled_today_riyadh", "scheduledPerDay", "scheduledToday", 1)):
        limit, count = as_count(limits.get(lim_key)), as_count(used.get(used_key))
        require(limit >= minimum and count < limit, "live_creation_or_schedule_capacity")
        capacity[name] = {"used": count, "limit": limit}
    pending_limit, pending = limits.get("maxPendingScheduled"), as_count(used.get("pendingScheduled"))
    require(type(pending_limit) is int and (pending_limit == -1 or 3 <= pending_limit and pending < pending_limit),
            "live_pending_capacity")
    storage_limit, storage = limits.get("mediaStorageMB"), used.get("mediaStorageMB")
    require(type(storage_limit) in (int, float) and math.isfinite(storage_limit)
            and type(storage) in (int, float) and 0 <= storage < storage_limit - 100,
            "live_storage_capacity")
    usage = get("/api/api-keys/usage")
    contract = config["response_contract"]
    require(contract.get("verified_from_actual_responses") is True
            and pointer(usage, contract["plan"]) == "pro", "api_key_plan_not_pro")
    api_limit = as_count(pointer(usage, contract["api_limit"]))
    api_count = as_count(pointer(usage, contract["api_used"]))
    require(api_limit >= 10 and api_limit - api_count - 1 >= 8, "live_api_headroom")

    posts = get(f"/api/posts?channelId={SNAP_CHANNEL}&limit=500")
    rows = posts["posts"]
    require(isinstance(rows, list) and len(rows) == as_count(posts.get("total"))
            and (posts.get("totalPages") == 1 or posts.get("totalPages") == 0 and not rows),
            "snap_posts_pagination_unverified")
    ids = set()
    for post in rows:
        targets = post.get("postPlatforms")
        require(isinstance(targets, list) and len(targets) == 1
                and targets[0].get("platform") == "snapchat" and targets[0].get("channelId") == SNAP_CHANNEL
                and post.get("status") in STATUSES, "snap_post_scope_unverified")
        post_id = as_count(post.get("id"))
        require(post_id > 0 and post_id not in ids, "snap_post_id_unverified")
        ids.add(post_id)
    snap_pending = sum(p["status"] in PENDING for p in rows)
    require(snap_pending < 3 and api.count == 5, "snap_operating_capacity_or_request_count")
    report = {"status": "snap_pro_quota_readback_verified", "plan": "pro", "provider_get_requests": 5,
              "provider_write_requests": 0, "as_of_utc": now.isoformat(),
              "paid_cycle_total_usd": proof["total_usd"], "receipt_evidence_ref": ref,
              "cancellation_evidence_ref": cancellation_ref,
              "receipt_paid_through_riyadh_date": paid_through.isoformat(),
              "receipt_period_end_utc": paid_end.astimezone(dt.timezone.utc).isoformat(),
              "provider_period_end_utc": end.astimezone(dt.timezone.utc).isoformat() if end else None,
              "provider_cancel_at_period_end": renew, "capacity": capacity,
              "workspace_pending": {"used": pending, "limit": pending_limit}, "snap_pending": snap_pending,
              "storage_mb": {"used": storage, "limit": storage_limit},
              "api_calls": {"used_at_measurement": api_count, "limit": api_limit,
                            "headroom_after_final_get": api_limit - api_count - 1}}
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":")).encode()
    report["evidence_ref"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    return report


if __name__ == "__main__":
    try:
        repo = Path(__file__).resolve().parent
        key = os.environ.pop("BULKPUBLISH_API_KEY", "")
        require(key.startswith("bp_"), "existing_actions_key_required")
        config, final_at = read_pinned_scope(repo)
        proof = read(repo / "snap-pro-payment-proof.json")
        result = collect(Transport(key), config, final_at, proof, dt.datetime.now(dt.timezone.utc))
        print(json.dumps(result, sort_keys=True))
    except Halt as error:
        print(f"Readback stopped: {error}", file=sys.stderr)
        sys.exit(1)
    except Exception:
        print("Readback stopped: unverified sealed input or provider response", file=sys.stderr)
        sys.exit(1)
