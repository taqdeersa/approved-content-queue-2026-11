import copy
import datetime as dt
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import test_worker as fixtures

w = fixtures.w


class ProCompat(unittest.TestCase):
    setUp = fixtures.Guards.setUp
    tearDown = fixtures.Guards.tearDown
    save = fixtures.Guards.save
    go = fixtures.Guards.go

    def pro(self):
        self.config["channel_id"] = 4659
        self.responses[1]["channels"][0]["id"] = 4659
        for index in (6, 7):
            self.responses[index]["post"]["postPlatforms"][0]["channelId"] = 4659
        self.responses[2] = {"limits": {"postsPerDay": 30, "postsPerMonth": 900,
            "scheduledPerDay": 30, "maxPendingScheduled": -1, "mediaStorageMB": 2000},
            "usage": {"postsToday": 10, "postsThisMonth": 60, "scheduledToday": 2,
                      "pendingScheduled": 60, "mediaStorageMB": 200}}
        self.responses[3] = {"plan": "pro", "limit": 5000, "count": 100}

    def enabled(self):
        return mock.patch.dict(os.environ, {"SNAP_PRO_COMPAT_ENABLED": "true",
            "SNAP_SHARED_PRO_ENTITLEMENT_VERIFIED": "true",
            "SNAP_SHARED_PRO_ENTITLEMENT_EVIDENCE_REF": "sha256:" + "a" * 64})

    def test_free_remains_original_eight_requests_with_opt_in_absent_or_present(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            result, api = self.go()
        self.assertEqual((result["status"], api.count, api.writes),
                         ("queued_verified_not_published", 8, 2))
        (self.root / "state.json").unlink()
        self.saved.clear()
        with self.enabled():
            result, api = self.go()
        self.assertEqual((result["status"], api.count, api.writes),
                         ("queued_verified_not_published", 8, 2))

    def test_pro_requires_exact_explicit_opt_in_before_any_write(self):
        self.pro()
        for value in (None, "false", "TRUE", "1", "yes"):
            with self.subTest(value=value), mock.patch.dict(os.environ, {}, clear=True):
                if value is not None:
                    os.environ["SNAP_PRO_COMPAT_ENABLED"] = value
                with self.assertRaisesRegex(w.Halt, "pro_compat_not_authorized"):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_pro_opt_in_preserves_exact_snap_payload_and_eight_requests(self):
        self.pro()
        captures = []
        original_call = fixtures.Fake.call

        def capture(api, method, path, *args):
            if path == "/api/posts" and method == "POST":
                captures.append(json.loads(args[0]))
            return original_call(api, method, path, *args)

        with self.enabled(), mock.patch.object(fixtures.Fake, "call", capture):
            result, api = self.go()
        self.assertEqual((api.count, api.writes), (8, 2))
        self.assertEqual(captures, [{"content": "approved-test-copy",
            "channels": [{"channelId": 4659, "platform": "snapchat"}], "status": "scheduled",
            "mediaFiles": [11], "scheduledAt": "2026-11-02T09:00:00+03:00",
            "timezone": "Asia/Riyadh", "postFormat": "story",
            "postTypeOverrides": {"snapchat": "story"}}])
        self.assertEqual(result["status"], "queued_verified_not_published")
        self.assertFalse(any("x-usage" in path or "checkout" in path for _, path in api.calls))

    def test_pro_financial_gate_missing_or_false_blocks_before_writes(self):
        self.pro()
        for value in (None, "false", "TRUE", "1", ""):
            with self.subTest(value=value), self.enabled():
                if value is None:
                    os.environ.pop("SNAP_SHARED_PRO_ENTITLEMENT_VERIFIED", None)
                else:
                    os.environ["SNAP_SHARED_PRO_ENTITLEMENT_VERIFIED"] = value
                with self.assertRaisesRegex(w.Halt, "pro_entitlement_not_verified"):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_pro_empty_or_credential_like_evidence_ref_blocks_before_writes(self):
        self.pro()
        for value in (None, "", " ", "bp_not_real", "https://example.test?token=mock",
                      "sha256:", "sha256:" + "G" * 64):
            with self.subTest(value=value), self.enabled():
                if value is None:
                    os.environ.pop("SNAP_SHARED_PRO_ENTITLEMENT_EVIDENCE_REF", None)
                else:
                    os.environ["SNAP_SHARED_PRO_ENTITLEMENT_EVIDENCE_REF"] = value
                with self.assertRaisesRegex(w.Halt, "pro_entitlement_not_verified"):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_pro_financial_flags_do_not_replace_original_cost_or_authorization(self):
        self.pro()
        for field, value in (("private_repo_zero_cost_cap_verified", False),
                             ("cost_evidence_reference", ""),
                             ("live_authorization_verified", False)):
            with self.subTest(field=field), self.enabled():
                config = copy.deepcopy(self.config)
                self.config[field] = value
                with self.assertRaisesRegex(w.Halt, "cost_or_human_authority_gate_missing"):
                    self.go()
                self.assertEqual(self.api.count, 0)
                self.assertEqual(self.api.writes, 0)
                self.config = config

    def test_unknown_plans_fail_closed_even_with_opt_in(self):
        self.pro()
        for plan in ("business", "lifetime", "unknown", None, True):
            with self.subTest(plan=plan), self.enabled():
                self.responses[3]["plan"] = plan
                with self.assertRaises(w.Halt):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_other_snap_channel_cannot_use_pro_opt_in(self):
        self.pro()
        self.config["channel_id"] = 4660
        self.responses[1]["channels"][0]["id"] = 4660
        with self.enabled(), self.assertRaisesRegex(w.Halt, "pro_compat_not_authorized"):
            self.go()
        self.assertEqual(self.api.writes, 0)

    def test_pro_does_not_bypass_provider_capacity_or_unknown_usage(self):
        cases = [
            (2, "limits", "postsPerDay", None), (2, "limits", "postsPerMonth", 29),
            (2, "limits", "scheduledPerDay", True), (2, "limits", "mediaStorageMB", float("inf")),
            (2, "usage", "postsToday", 30), (2, "usage", "postsThisMonth", 900),
            (2, "usage", "scheduledToday", 30), (2, "usage", "pendingScheduled", None),
            (2, "usage", "mediaStorageMB", 2000), (2, "usage", "mediaStorageMB", -1),
            (2, "limits", "maxPendingScheduled", None),
            (2, "limits", "maxPendingScheduled", 2),
        ]
        for index, section, key, value in cases:
            with self.subTest(section=section, key=key, value=value):
                self.pro()
                self.responses[index][section][key] = value
                with self.enabled(), self.assertRaises(w.Halt):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_pro_api_headroom_missing_or_exhausted_stops_before_write(self):
        for api_limit, used in ((5000, 4997), (9, 0), (None, 0), (5000, None), (5000, -1)):
            self.pro()
            self.responses[3].update(limit=api_limit, count=used)
            with self.subTest(api_limit=api_limit, used=used), self.enabled():
                with self.assertRaisesRegex(w.Halt, "api_quota"):
                    self.go()
                self.assertEqual(self.api.writes, 0)

    def test_pro_bounded_pending_limit_still_enforced(self):
        self.pro()
        self.responses[2]["limits"]["maxPendingScheduled"] = 100
        self.responses[2]["usage"]["pendingScheduled"] = 100
        with self.enabled(), self.assertRaisesRegex(w.Halt, "pro_pending_capacity"):
            self.go()
        self.assertEqual(self.api.writes, 0)

    def test_pro_snap_queue_still_capped_at_three(self):
        self.pro()
        self.responses[4] = {"posts": [{"status": "scheduled", "postPlatforms": [
            {"channelId": 4659, "platform": "snapchat"}]}] * 3, "total": 3, "totalPages": 1}
        with self.enabled(), self.assertRaisesRegex(w.Halt, "remote_queue_full"):
            self.go()
        self.assertEqual(self.api.writes, 0)

    def test_pro_snap_creation_today_still_rejected(self):
        self.pro()
        self.responses[4] = {"posts": [{"id": 30, "status": "published",
            "createdAt": "2026-11-01T05:00:00Z", "content": "other", "scheduledAt": None,
            "postPlatforms": [{"channelId": 4659, "platform": "snapchat"}]}],
            "total": 1, "totalPages": 1}
        with self.enabled(), self.assertRaisesRegex(w.Halt, "remote_creation_today"):
            self.go()
        self.assertEqual(self.api.writes, 0)

    def test_pro_mixed_or_unverifiable_channel_filter_stops_before_write(self):
        for platforms in (None, [], [{"channelId": 5000, "platform": "x"}],
                          [{"channelId": 4659, "platform": "snapchat"},
                           {"channelId": 5000, "platform": "x"}]):
            self.pro()
            self.responses[4] = {"posts": [{"status": "published", "postPlatforms": platforms}],
                                 "total": 1, "totalPages": 1}
            with self.subTest(platforms=platforms), self.enabled():
                with self.assertRaisesRegex(w.Halt, "snap_posts_filter_unverified"):
                    self.go()
                self.assertEqual(self.api.writes, 0)
                self.assertFalse(self.saved)

    def test_pro_snap_month_cap_and_bundle_budget_still_enforced(self):
        self.pro()
        self.now = dt.datetime(2026, 11, 3, 10, 17, tzinfo=w.RIYADH)
        w.write(self.root / "state.json", {"schema": 1, "items": {
            str(day): {"phase": "queued_verified", "utc_day": "2026-11-0%d" % (day - 1),
                       "riyadh_day": "2026-11-0%d" % (day - 1)} for day in (2, 3)}})
        self.responses[4] = {"posts": [{"id": n, "status": "published", "createdAt":
            "2026-11-01T05:00:00Z", "content": "other-%d" % n, "scheduledAt": None,
            "postPlatforms": [{"channelId": 4659, "platform": "snapchat"}]}
            for n in range(30)], "total": 30, "totalPages": 1}
        with self.enabled(), self.assertRaisesRegex(w.Halt, "snap_monthly_cap"):
            self.go()
        self.assertEqual(self.api.writes, 0)
        self.pro()
        self.responses[4] = {"posts": [], "total": 0, "totalPages": 0}
        with self.enabled(), mock.patch.object(Path, "stat") as stat:
            stat.return_value.st_size = 4_000_000
            with self.assertRaisesRegex(w.Halt, "snap_media_budget"):
                w.pro_capacity(self.root, self.manifest, self.manifest["items"][0],
                               self.config, self.responses[2], self.responses[3],
                               self.config["response_contract"])


if __name__ == "__main__":
    unittest.main()
