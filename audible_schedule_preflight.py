"""Read back prepared media and measure capacity without creating posts."""

from collections import Counter
import datetime as dt
import re
import urllib.parse

import worker


def read_inventory(api, query):
    response = api.call("GET", "/api/posts?" + urllib.parse.urlencode(query | {"limit": 500}))
    rows = response["posts"]
    worker.require(response.get("totalPages") == 1 or response.get("total") == 0,
                   "media_stage_calendar_not_complete")
    worker.require(isinstance(rows, list) and response.get("total") == len(rows),
                   "media_stage_calendar_not_complete")
    return rows


def time_value(value):
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    worker.require(parsed.utcoffset() is not None, "media_stage_calendar_time_missing")
    return parsed.astimezone(worker.RIYADH)


def check(plan, ledger, config, api, now):
    now = now.astimezone(worker.RIYADH)
    items, staged = plan["items"], ledger["items"]
    worker.require(len(items) == len(staged) == 8 and {item["event_id"] for item in items} == set(staged),
                   "media_stage_calendar_ledger_mismatch")
    for item in items:
        entry = staged[item["event_id"]]
        when = time_value(item["scheduled_at"])
        worker.require(entry["phase"] == "uploaded_verified" and item["sha256"] == entry["sha256"]
                       and item["event_id"] == when.date().isoformat() + ":main"
                       and dt.date(2026, 11, 10) <= when.date() <= dt.date(2026, 11, 30)
                       and when >= now + dt.timedelta(hours=1)
                       and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\.mp4", item["file"])
                       and type(item["bytes"]) is int and item["bytes"] > 0
                       and type(entry["media_id"]) is int and entry["media_id"] > 0,
                       "media_stage_calendar_item_mismatch")
    contract = config["response_contract"]
    usage = api.call("GET", "/api/api-keys/usage")
    api_limit, api_used = (worker.pointer(usage, contract[key]) for key in ("api_limit", "api_used"))
    worker.require(worker.pointer(usage, contract["plan"]) == "pro"
                   and type(api_limit) is int and type(api_used) is int and 0 <= api_used <= api_limit - 22,
                   "media_stage_calendar_api_headroom")
    quota = api.call("GET", "/api/quotas/usage?tz=Asia%2FRiyadh")
    limits, used = quota["limits"], quota["usage"]
    channel_id = config["channel_id"]
    same_channel = read_inventory(api, {"channelId": channel_id})
    calendar = read_inventory(api, {"scheduledFrom": "2026-11-10", "scheduledTo": "2026-11-30"})
    active = {"scheduled", "processing", "publishing"}
    scheduled_days = Counter(time_value(post["scheduledAt"]).date()
                             for post in calendar if post["status"] in active)
    requested_days = Counter(time_value(item["scheduled_at"]).date() for item in items)
    for item in items:
        expected = staged[item["event_id"]]["media_id"]
        response = api.call("GET", f"/api/media/{expected}")
        media = worker.response_candidate(response, "media")
        worker.require(media["id"] == expected and media["fileName"] == item["file"]
                       and media["mimeType"] == "video/mp4" and media["sizeBytes"] == item["bytes"],
                       "media_stage_calendar_media_readback")
        for post in same_channel:
            worker.require(post.get("content") != item["title"]
                           and (not post.get("scheduledAt")
                                or time_value(post["scheduledAt"]) != time_value(item["scheduled_at"]))
                           and expected not in [m["id"] for m in post.get("mediaFiles", [])],
                           "media_stage_calendar_duplicate")

    silent_reserve = (dt.date(2026, 11, 30) - now.date()).days
    count = len(items)
    pending_limit = limits["maxPendingScheduled"]
    headroom = (used["postsToday"] + count + 1 <= limits["postsPerDay"]
                and used["scheduledToday"] + count + 1 <= limits["scheduledPerDay"]
                and used["postsThisMonth"] + count + silent_reserve <= limits["postsPerMonth"]
                and (pending_limit == -1 or used["pendingScheduled"] + count + 1 <= pending_limit)
                and all(scheduled_days[day] + quantity + 1 <= limits["scheduledPerDay"]
                        for day, quantity in requested_days.items()))
    pending_now = sum(post["status"] in active for post in same_channel)
    return {"status": "audible_batch_calendar_read_only", "count": count, "requests": api.count,
            "provider_capacity": headroom, "existing_silent_guard_would_hold": pending_now + count >= 3}
