"""Reviewable, fail-closed BulkPublish bridge. Standard library; no HTTP retries."""
import argparse
import datetime as dt
import hashlib
import json
import mimetypes
import os
from pathlib import Path
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
import uuid

BASE = "https://app.bulkpublish.com"
RIYADH = dt.timezone(dt.timedelta(hours=3))
APPROVAL = "human_current_turn_2026-11-01_reviewed_all_authorized_schedule_batch_contextual_times"
PLAN_SHA = "f10d9b13dbfff47d7fb929f84f1db57ddf3826858c82edd3532a5cd394df0764"


class Halt(Exception):
    pass


def require(value, reason):
    if not value:
        raise Halt(reason)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8-sig"))


def write(path, value):
    path = Path(path)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def pointer(value, path):
    """Explicitly verified response-contract path, never a guessed fallback."""
    require(isinstance(path, list), "missing_verified_response_path")
    try:
        for key in path:
            value = value[key]
        return value
    except (KeyError, TypeError, IndexError):
        raise Halt("response_contract_changed")


def compile_plan(source, root, expected_account):
    source, root = Path(source).resolve(), Path(root).resolve()
    require(sha(source) == PLAN_SHA, "source_plan_hash_changed")
    plan = read(source)
    require(plan["approval_reference"] == APPROVAL, "wrong_approval_reference")
    require(expected_account and plan["account_id"] == expected_account and plan["audience"] == "My Story Public"
            and plan["duration_hours"] == 24 and plan["timezone"] == "Asia/Riyadh", "wrong_scope")
    require(not (root / "manifest.json").exists(), "frozen_manifest_already_exists")
    items = []
    for item in plan["items"]:
        if item["day"] == 1:
            require(item["already_published"] and item["no_repost"], "day1_not_excluded")
            continue
        require(not item["already_published"] and item["approval_reference"] == APPROVAL, "item_scope")
        a, t = item["asset"], item["text"]
        require(sha(a["path"]) == a["sha256"] and sha(t["path"]) == t["sha256"], "source_asset_or_text_changed")
        ext = Path(a["path"]).suffix.lower()
        require(ext in (".png", ".mp4"), "unapproved_format")
        rel = "media/day-%02d%s" % (item["day"], ext)
        text_rel = "copy/day-%02d.txt" % item["day"]
        for source_path, target in [(a["path"], root / rel), (t["path"], root / text_rel)]:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source_path, target)
        items.append({"day": item["day"], "scheduled_at": item["scheduled_at"],
                      "title": item["title"],
                      "asset": rel, "asset_sha256": a["sha256"], "text": text_rel,
                      "text_sha256": t["sha256"], "format": ext[1:]})
    require(len(items) == 29 and {i["day"] for i in items} == set(range(2, 31)), "need_exact_future_29")
    write(root / "manifest.json", {"schema": 1, "source_sha256": PLAN_SHA,
          "approval_reference": APPROVAL, "account": expected_account, "audience": "My Story Public",
          "duration_hours": 24, "timezone": "Asia/Riyadh", "items": items})
    print(json.dumps({"compiled": 29, "manifest_sha256": sha(root / "manifest.json")}))


class Transport:
    def __init__(self, key):
        self.key, self.count = key, 0

    def call(self, method, path, body=None, content_type="application/json"):
        self.count += 1
        require(self.count <= 8, "request_limit")
        headers = {"Authorization": "Bearer " + self.key, "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(BASE + path, data=body, headers=headers, method=method)
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *args, **kwargs):
                    raise Halt("redirect_forbidden")
            with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
                require(response.geturl().startswith(BASE + "/"), "redirect_forbidden")
                return json.load(response)
        except Exception:
            # Never log response bodies, headers, API keys, or retry a request.
            raise Halt("http_or_json_result_unknown_" + method)


def response_candidate(value, kind):
    """Find one documented schema object, without assuming POST envelope keys."""
    stack, matches, visited = [(value, 0)], [], 0
    while stack:
        node, depth = stack.pop()
        visited += 1
        require(visited <= 512 and depth <= 8, "post_response_structure_limit")
        if isinstance(node, (dict, list)):
            require(len(node) <= 128, "post_response_structure_limit")
        if isinstance(node, dict):
            valid = type(node.get("id")) is int and node["id"] > 0
            if kind == "media":
                valid = (valid and isinstance(node.get("fileName"), str)
                         and isinstance(node.get("mimeType"), str)
                         and type(node.get("sizeBytes")) is int and node["sizeBytes"] > 0)
            else:
                valid = (valid and isinstance(node.get("content"), str)
                         and node.get("status") in ("draft", "scheduled", "publishing", "published", "processing", "failed", "partial")
                         and isinstance(node.get("mediaFiles"), list)
                         and isinstance(node.get("postPlatforms"), list)
                         and isinstance(node.get("postFormat"), str))
            if valid:
                matches.append(node)
            stack.extend((child, depth + 1) for child in node.values() if isinstance(child, (dict, list)))
        elif isinstance(node, list):
            stack.extend((child, depth + 1) for child in node if isinstance(child, (dict, list)))
    require(len(matches) == 1, "post_response_candidate_unknown_or_ambiguous")
    return matches[0]


def exact_scheduled_post(post, item, channel_id, media_id, expected_id=None, statuses=("scheduled",)):
    """Only a GET object can establish that this exact Story is queued."""
    try:
        actual_time = dt.datetime.fromisoformat(post["scheduledAt"].replace("Z", "+00:00"))
        return (type(post["id"]) is int and post["id"] > 0
                and (expected_id is None or post["id"] == expected_id)
                and post["status"] in statuses and post["content"] == item["title"]
                and actual_time.utcoffset() is not None
                and actual_time == dt.datetime.fromisoformat(item["scheduled_at"])
                and post["timezone"] == "Asia/Riyadh" and post["postFormat"] == "story"
                and post.get("postTypeOverrides", {}).get("snapchat", "story") == "story"
                and len(post["postPlatforms"]) == 1
                and post["postPlatforms"][0]["channelId"] == channel_id
                and post["postPlatforms"][0]["platform"] == "snapchat"
                and [m["id"] for m in post["mediaFiles"]] == [media_id])
    except (KeyError, ValueError, TypeError, AttributeError):
        return False


def multipart(path):
    boundary = "bp" + uuid.uuid4().hex
    name = Path(path).name
    kind = mimetypes.guess_type(name)[0] or "application/octet-stream"
    head = ('--%s\r\nContent-Disposition: form-data; name="file"; filename="%s"\r\n'
            'Content-Type: %s\r\n\r\n' % (boundary, name, kind)).encode()
    return head + Path(path).read_bytes() + ("\r\n--%s--\r\n" % boundary).encode(), "multipart/form-data; boundary=" + boundary


def git_save(root, state):
    """Push reservation before every mutation. Failure prevents the next API call."""
    write(root / "state.json", state)
    for args in [["add", "--", "state.json"], ["commit", "-m", "Persist publisher checkpoint"], ["push", "origin", "HEAD"]]:
        result = subprocess.run(["git", "-C", str(root)] + args, capture_output=True, timeout=30)
        require(result.returncode == 0, "cloud_checkpoint_not_persisted")


def candidate(root, manifest, state, now):
    require(bool(manifest["account"]) and manifest["approval_reference"] == APPROVAL
            and manifest["source_sha256"] == PLAN_SHA and manifest["audience"] == "My Story Public"
            and manifest["duration_hours"] == 24 and manifest["timezone"] == "Asia/Riyadh", "manifest_scope")
    require({i["day"] for i in manifest["items"]} == set(range(2, 31)) and len(manifest["items"]) == 29, "day1_or_missing_day")
    require(not any(v["phase"] != "queued_verified" for v in state["items"].values()), "pending_or_unknown_requires_review")
    pending = [i for i in manifest["items"] if str(i["day"]) not in state["items"]]
    if not pending:
        return None
    item = min(pending, key=lambda i: i["scheduled_at"])
    when = dt.datetime.fromisoformat(item["scheduled_at"])
    require(when.utcoffset() == dt.timedelta(hours=3), "wrong_timezone")
    require(when - now >= dt.timedelta(hours=2), "past_or_insufficient_lead_no_catchup")
    require(when.date() == now.astimezone(RIYADH).date() + dt.timedelta(days=1), "not_next_calendar_day")
    require(now.astimezone(RIYADH).date() <= dt.date(2026, 11, 29), "creation_window_closed")
    for field in ("asset", "text"):
        path = (root / item[field]).resolve()
        require(path.is_relative_to(root.resolve()) and sha(path) == item[field + "_sha256"], "asset_or_text_changed")
    require(isinstance(item.get("title"), str) and 0 < len(item["title"]) <= 160, "title_missing_or_too_long")
    for v in state["items"].values():
        require(v["utc_day"] != now.astimezone(dt.timezone.utc).date().isoformat()
                and v["riyadh_day"] != now.astimezone(RIYADH).date().isoformat(), "creation_already_reserved_today")
    return item


def pro_capacity(root, manifest, item, config, quota, usage, contract):
    """Explicit Pro compatibility; this worker retains its original Snap scope."""
    require(os.environ.get("SNAP_PRO_COMPAT_ENABLED") == "true"
            and config.get("channel_id") == 4659, "pro_compat_not_authorized")
    # Separate financial entitlement from the original zero-incremental-cost gate.
    # This is an operator-attested reference digest, never a credential or a URL.
    entitlement_ref = os.environ.get("SNAP_SHARED_PRO_ENTITLEMENT_EVIDENCE_REF", "")
    require(os.environ.get("SNAP_SHARED_PRO_ENTITLEMENT_VERIFIED") == "true"
            and entitlement_ref.startswith("sha256:") and len(entitlement_ref) == 71
            and all(char in "0123456789abcdef" for char in entitlement_ref[7:]),
            "pro_entitlement_not_verified")
    api_limit, api_used = pointer(usage, contract["api_limit"]), pointer(usage, contract["api_used"])
    require(type(api_limit) is int and api_limit >= 10 and type(api_used) is int
            and 0 <= api_used <= api_limit - 4, "api_quota")
    lim, used = quota.get("limits", {}), quota.get("usage", {})
    for limit_key, usage_key, minimum in (("postsPerDay", "postsToday", 1),
                                         ("postsPerMonth", "postsThisMonth", 30),
                                         ("scheduledPerDay", "scheduledToday", 1)):
        limit, count = lim.get(limit_key), used.get(usage_key)
        require(type(limit) is int and limit >= minimum and type(count) is int
                and 0 <= count < limit, "pro_capacity_or_unknown_shape")
    pending_limit, pending = lim.get("maxPendingScheduled"), used.get("pendingScheduled")
    require(type(pending_limit) is int and (pending_limit == -1 or pending_limit >= 3)
            and type(pending) is int and pending >= 0
            and (pending_limit == -1 or pending < pending_limit), "pro_pending_capacity")
    storage_limit, storage = lim.get("mediaStorageMB"), used.get("mediaStorageMB")
    require(type(storage_limit) in (int, float) and 100 <= storage_limit < float("inf")
            and type(storage) in (int, float) and 0 <= storage < storage_limit
            and storage + (root / item["asset"]).stat().st_size / 1000000 < storage_limit,
            "pro_storage_capacity")
    # Keep the frozen Snapchat bundle below its old 100 MB operational budget.
    assets = [(root / item["asset"]).resolve() for item in manifest["items"]]
    require(all(path.is_relative_to(root.resolve()) for path in assets)
            and sum(path.stat().st_size for path in assets) / 1000000 < 100,
            "snap_media_budget")


def verified_audible_ids(posts, receipts, state, channel_id):
    """Exempt only exact readback-confirmed records from the independent audible lane."""
    require(isinstance(receipts, list) and len(receipts) <= 62, "audible_receipts_invalid")
    own_ids = {entry.get("provider_post_id") for entry in state["items"].values()}
    remote = {post["id"]: post for post in posts}
    require(len(remote) == len(posts), "snap_posts_inventory_ambiguous")
    declared, verified = set(), set()
    for receipt in receipts:
        require(isinstance(receipt, dict), "audible_receipt_invalid")
        post_id, media_id = receipt.get("post_id"), receipt.get("media_id")
        require(type(post_id) is int and post_id > 0 and type(media_id) is int and media_id > 0
                and post_id not in own_ids and post_id not in declared
                and receipt.get("phase") == "queued_verified"
                and isinstance(receipt.get("created_at"), str)
                and isinstance(receipt.get("scheduled_at"), str)
                and isinstance(receipt.get("title"), str) and 0 < len(receipt["title"]) <= 160,
                "audible_receipt_invalid")
        try:
            created_at = dt.datetime.fromisoformat(receipt["created_at"].replace("Z", "+00:00"))
            scheduled_at = dt.datetime.fromisoformat(receipt["scheduled_at"])
        except ValueError:
            raise Halt("audible_receipt_timestamp_invalid") from None
        require(created_at.utcoffset() is not None and scheduled_at.utcoffset() == dt.timedelta(hours=3)
                and created_at < scheduled_at, "audible_receipt_timestamp_invalid")
        declared.add(post_id)
        post = remote.get(post_id)
        if post and post.get("createdAt") == receipt["created_at"] and exact_scheduled_post(
                post, receipt, channel_id, media_id, expected_id=post_id,
                statuses=("scheduled", "processing", "publishing", "published", "failed", "partial")):
            verified.add(post_id)
    return verified


def check_channel_inventory(rows, item, now, plan, audible_ids=()):
    if plan != "pro":
        audible_ids = ()
    own_rows = [post for post in rows if post.get("id") not in audible_ids]
    require(sum(p["status"] in ("scheduled", "publishing", "processing") for p in own_rows)
            < 3, "remote_queue_full")
    snap_this_month = 0
    for p in own_rows:
        created = dt.datetime.fromisoformat(p["createdAt"].replace("Z", "+00:00"))
        snap_this_month += created.astimezone(dt.timezone.utc).strftime("%Y-%m") == now.astimezone(dt.timezone.utc).strftime("%Y-%m")
        require(created.astimezone(dt.timezone.utc).date() != now.astimezone(dt.timezone.utc).date()
                and created.astimezone(RIYADH).date() != now.astimezone(RIYADH).date(), "remote_creation_today")
    require(plan != "pro" or snap_this_month < 30, "snap_monthly_cap")
    target_time = dt.datetime.fromisoformat(item["scheduled_at"])
    for p in rows:
        remote_time = p.get("scheduledAt")
        same_time = (remote_time is not None
                     and dt.datetime.fromisoformat(remote_time.replace("Z", "+00:00")) == target_time)
        require(not (same_time or p.get("content") == item["title"]), "remote_duplicate_requires_review")


def run(root, config, api, now, save, execute=False, audible_receipts=None):
    manifest = read(root / "manifest.json")
    state = read(root / "state.json") if (root / "state.json").exists() else {"schema": 1, "items": {}}
    item = candidate(root, manifest, state, now)
    if item is None:
        return {"status": "nothing_to_create"}
    if not execute:
        return {"status": "dry_run_only", "day": item["day"], "scheduled_at": item["scheduled_at"]}
    require((config.get("private_repo_zero_cost_cap_verified") is True
             or config.get("public_repository_sealed_verified") is True)
            and config.get("cost_evidence_reference") and config.get("live_authorization_verified") is True,
            "cost_or_human_authority_gate_missing")
    require(config.get("manifest_sha256") == sha(root / "manifest.json"), "frozen_manifest_changed")
    c = config.get("response_contract", {})
    require(c.get("verified_from_actual_responses") is True and c.get("evidence_reference"), "api_response_contract_unverified")
    require(all(isinstance(c.get(key), list) for key in ("plan", "api_limit", "api_used", "read_post")),
            "verified_get_contract_required")
    platforms = api.call("GET", "/api/platforms")["platforms"]
    snap = [p for p in platforms if p.get("platform") == "snapchat"]
    require(len(snap) == 1 and snap[0].get("enabled") is True and snap[0].get("canPublish") is True, "snapchat_disabled")
    channels = api.call("GET", "/api/channels")
    selected = [v for v in channels["channels"] if v.get("id") == config.get("channel_id")]
    require(len(selected) == 1, "channel_missing")
    ch = selected[0]
    require(config.get("identity_evidence_reference") and config.get("verified_username") == manifest["account"]
            and ch.get("accountId") == config.get("provider_account_id")
            and ch.get("platform") == "snapchat" and ch.get("isActive") is True
            and ch.get("needsReconnect") is False and ch.get("tokenStatus") == "valid"
            and channels.get("capabilities", {}).get("canCreatePosts") is True
            and channels["capabilities"].get("canPublishPosts") is True, "identity_or_channel_health")
    quota = api.call("GET", "/api/quotas/usage")
    usage = api.call("GET", "/api/api-keys/usage")
    plan = pointer(usage, c["plan"])
    require(plan in ("free", "pro"), "unsupported_plan")
    if plan == "pro":
        pro_capacity(root, manifest, item, config, quota, usage, c)
    else:
        require(pointer(usage, c["api_limit"]) == 10 and pointer(usage, c["api_used"]) <= 6, "api_quota")
        lim, used = quota.get("limits", {}), quota.get("usage", {})
        require(lim.get("postsPerDay") == 1 and used.get("postsToday") == 0
                and used.get("postsThisMonth", 30) < 30 and lim.get("maxPendingScheduled") == 3
                and used.get("pendingScheduled", 3) < 3
                and used.get("mediaStorageMB", 100) + (root / item["asset"]).stat().st_size / 1000000 < 100,
                "free_quota_or_unknown_shape")
    posts_path = "/api/posts?" + urllib.parse.urlencode({"channelId": ch["id"], "limit": 500})
    posts = api.call("GET", posts_path)
    require(posts.get("totalPages") == 1 or posts.get("total") == 0, "pagination_requires_review")
    rows = posts["posts"]
    if plan == "pro":
        require(all(isinstance(p.get("postPlatforms"), list) and len(p["postPlatforms"]) == 1
                    and p["postPlatforms"][0].get("channelId") == 4659
                    and p["postPlatforms"][0].get("platform") == "snapchat" for p in rows),
                "snap_posts_filter_unverified")
    audible_ids = ()
    if plan == "pro" and audible_receipts is not None:
        require(type(posts.get("total")) is int and len(rows) == posts["total"],
                "snap_posts_inventory_incomplete")
        audible_ids = verified_audible_ids(rows, audible_receipts, state, ch["id"])
    check_channel_inventory(rows, item, now, plan, audible_ids)
    # Story captions are not forwarded to Snapchat. The frozen title is provider metadata.
    text_value = item["title"]
    entry = {"phase": "upload_pending", "utc_day": now.astimezone(dt.timezone.utc).date().isoformat(),
             "riyadh_day": now.astimezone(RIYADH).date().isoformat(), "asset_sha256": item["asset_sha256"],
             "scheduled_at": item["scheduled_at"], "attempt_id": uuid.uuid4().hex}
    state["items"][str(item["day"])] = entry
    save(root, state)  # MUST be in durable private remote repo before upload.
    try:
        body, content_type = multipart(root / item["asset"])
        uploaded = api.call("POST", "/api/media", body, content_type)
        media_id = response_candidate(uploaded, "media")["id"]
        entry.update(phase="create_pending", media_id=media_id)
        save(root, state)  # MUST be durable before create; no idempotency header is documented.
        payload = {"content": text_value, "channels": [{"channelId": ch["id"], "platform": "snapchat"}],
                   "status": "scheduled", "mediaFiles": [media_id], "scheduledAt": item["scheduled_at"],
                   "timezone": "Asia/Riyadh", "postFormat": "story", "postTypeOverrides": {"snapchat": "story"}}
        try:
            created = api.call("POST", "/api/posts", json.dumps(payload).encode())
            post_id = response_candidate(created, "post")["id"]
        except Exception:
            # A lost/malformed/ambiguous creation response permits one READ,
            # never another upload/create. It consumes the same eighth slot.
            post_id = None
        entry.update(phase="readback_pending", create_response_candidate_id=post_id)
        save(root, state)
        if post_id is not None:
            response = api.call("GET", "/api/posts/" + str(post_id))
            post = pointer(response, c["read_post"])
            require(exact_scheduled_post(post, item, ch["id"], media_id, post_id), "queue_readback_mismatch")
            route = "get_post_by_candidate_id"
        else:
            response = api.call("GET", posts_path)
            require(response.get("totalPages") == 1 or response.get("total") == 0, "reconcile_pagination_unknown")
            matches = [p for p in response["posts"] if exact_scheduled_post(p, item, ch["id"], media_id)]
            require(len(matches) == 1, "create_result_unknown_no_unique_get_match")
            post, route = matches[0], "get_posts_exact_reconciliation"
        entry.update(phase="queued_verified", provider_post_id=post["id"], provider_status="scheduled",
                     get_readback_route=route, published_verified=False)
        save(root, state)
    except Exception:
        entry["phase"] = "unknown_requires_review"
        save(root, state)
        raise Halt("mutation_result_unknown_no_retry")
    return {"status": "queued_verified_not_published", "day": item["day"], "requests": api.count}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("command", choices=["compile", "run"])
    p.add_argument("--root", type=Path, required=True)
    p.add_argument("--source", type=Path)
    p.add_argument("--expected-account")
    p.add_argument("--execute", action="store_true")
    a = p.parse_args()
    try:
        if a.command == "compile":
            require(a.source is not None, "source_required")
            compile_plan(a.source, a.root, a.expected_account)
        else:
            require(not a.execute or os.environ.get("QUEUE_ZERO_COST_VERIFIED") == "true", "runner_cost_gate")
            key = os.environ.get("BULKPUBLISH_API_KEY", "")
            require(not a.execute or key.startswith("bp_"), "api_key_missing")
            config = read(a.root / "config.json") if (a.root / "config.json").exists() else {}
            print(json.dumps(run(a.root.resolve(), config, Transport(key), dt.datetime.now(RIYADH), git_save, a.execute)))
    except (Halt, KeyError, ValueError, TypeError) as e:
        print(json.dumps({"status": "halt", "reason": str(e) if isinstance(e, Halt) else "schema_or_configuration_invalid"}))
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
