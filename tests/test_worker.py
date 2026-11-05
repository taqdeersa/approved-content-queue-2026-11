import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("bridge", Path(__file__).parents[1] / "worker.py")
w = importlib.util.module_from_spec(spec)
spec.loader.exec_module(w)


class Fake:
    def __init__(self, responses):
        self.responses, self.count, self.writes = responses, 0, 0
        self.calls = []

    def call(self, method, path, *args):
        self.count += 1
        self.calls.append((method, path))
        self.writes += method == "POST"
        value = self.responses[self.count - 1]
        if isinstance(value, Exception):
            raise value
        return copy.deepcopy(value)


class Guards(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)
        (self.root / "asset.png").write_bytes(b"test-png-not-a-real-upload")
        (self.root / "copy.txt").write_text("approved-test-copy", encoding="utf-8")
        items = [{"day": day, "scheduled_at": "2026-11-%02dT09:00:00+03:00" % day,
                  "asset": "asset.png", "text": "copy.txt", "title": "approved-test-copy", "asset_sha256": w.sha(self.root / "asset.png"),
                  "text_sha256": w.sha(self.root / "copy.txt"), "format": "png"} for day in range(2, 31)]
        self.manifest = {"account": "fixture-snap-account", "approval_reference": w.APPROVAL,
                         "source_sha256": w.PLAN_SHA, "audience": "My Story Public", "duration_hours": 24,
                         "timezone": "Asia/Riyadh", "items": items}
        w.write(self.root / "manifest.json", self.manifest)
        self.now = dt.datetime(2026, 11, 1, 10, 17, tzinfo=w.RIYADH)
        self.config = {"private_repo_zero_cost_cap_verified": True, "cost_evidence_reference": "mock-only",
                       "live_authorization_verified": True, "manifest_sha256": w.sha(self.root / "manifest.json"),
                       "channel_id": 7, "provider_account_id": "fixture-profile", "verified_username": "fixture-snap-account",
                       "identity_evidence_reference": "mock-only", "response_contract": {
                           "verified_from_actual_responses": True, "evidence_reference": "MOCK_NOT_REAL_SCHEMA",
                           "plan": ["plan"], "api_limit": ["limit"], "api_used": ["count"],
                           "read_post": ["post"]}}
        self.responses = [
            {"platforms": [{"platform": "snapchat", "enabled": True, "canPublish": True}]},
            {"channels": [{"id": 7, "platform": "snapchat", "accountId": "fixture-profile", "isActive": True,
                           "needsReconnect": False, "tokenStatus": "valid"}],
             "capabilities": {"canCreatePosts": True, "canPublishPosts": True}},
            {"limits": {"postsPerDay": 1, "maxPendingScheduled": 3}, "usage": {
                "postsToday": 0, "postsThisMonth": 0, "pendingScheduled": 0, "mediaStorageMB": 0}},
            {"plan": "free", "limit": 10, "count": 4},
            {"posts": [], "total": 0, "totalPages": 0},
            {"file": {"id": 11, "fileName": "asset.png", "mimeType": "image/png",
                      "sizeBytes": (self.root / "asset.png").stat().st_size}}, {},
            {"post": {"id": 13, "status": "scheduled", "scheduledAt": items[0]["scheduled_at"],
                      "content": "approved-test-copy", "timezone": "Asia/Riyadh",
                      "postFormat": "story", "postPlatforms": [{"channelId": 7, "platform": "snapchat"}],
                      "mediaFiles": [{"id": 11}]}}]
        self.responses[6] = copy.deepcopy(self.responses[7])
        self.saved = []

    def tearDown(self):
        self.temp.cleanup()

    def save(self, root, state):
        self.saved.append(copy.deepcopy(state))
        w.write(root / "state.json", state)

    def go(self, responses=None, execute=True):
        api = Fake(self.responses if responses is None else responses)
        self.api = api
        return w.run(self.root, self.config, api, self.now, self.save, execute), api

    def test_dry_run_no_requests(self):
        result, api = self.go(execute=False)
        self.assertEqual(api.count, 0)
        self.assertEqual(result["status"], "dry_run_only")

    def test_past_no_catchup(self):
        self.now += dt.timedelta(days=2)
        with self.assertRaises(w.Halt): self.go()

    def test_wrong_identity(self):
        self.responses[1]["channels"][0]["accountId"] = "other"
        with self.assertRaises(w.Halt): self.go()
        self.assertFalse(self.saved)

    def test_asset_changed(self):
        (self.root / "asset.png").write_bytes(b"changed")
        with self.assertRaises(w.Halt): self.go()

    def test_disabled_platform(self):
        self.responses[0]["platforms"][0]["enabled"] = False
        with self.assertRaises(w.Halt): self.go()

    def test_quota(self):
        self.responses[2]["usage"]["postsToday"] = 1
        with self.assertRaises(w.Halt): self.go()

    def test_remote_duplicate(self):
        self.responses[4] = {"totalPages": 1, "total": 1, "posts": [{"id": 42, "status": "scheduled",
            "content": "approved-test-copy", "createdAt": "2026-10-31T00:00:00Z"}]}
        with self.assertRaises(w.Halt): self.go()
        self.assertFalse(self.saved)

    def test_unknown_stops_next_run(self):
        self.responses[6] = w.Halt("connection_lost_after_create")
        self.responses[7] = {"posts": [], "total": 0, "totalPages": 0}
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.saved[-1]["items"]["2"]["phase"], "unknown_requires_review")
        with self.assertRaises(w.Halt): self.go()

    def test_day1_forbidden(self):
        self.manifest["items"][0]["day"] = 1
        w.write(self.root / "manifest.json", self.manifest)
        with self.assertRaises(w.Halt): self.go()

    def test_queue_not_publication_and_checkpoints_before_mutation(self):
        result, api = self.go()
        self.assertEqual(api.count, 8)
        self.assertEqual(api.writes, 2)
        self.assertEqual([s["items"]["2"]["phase"] for s in self.saved],
                         ["upload_pending", "create_pending", "readback_pending", "queued_verified"])
        self.assertFalse(self.saved[-1]["items"]["2"]["published_verified"])
        self.assertEqual(result["status"], "queued_verified_not_published")

    def test_unverified_contract_halts_before_network(self):
        self.config["response_contract"]["verified_from_actual_responses"] = False
        with self.assertRaises(w.Halt): self.go()
        self.assertFalse(self.saved)

    def test_unknown_create_reconciles_exact_get_without_retry(self):
        post = copy.deepcopy(self.responses[7]["post"])
        post["scheduledAt"] = "2026-11-02T06:00:00Z"
        self.responses[6] = w.Halt("connection_lost_after_create")
        self.responses[7] = {"posts": [post], "total": 1, "totalPages": 1}
        result, api = self.go()
        self.assertEqual(api.count, 8)
        self.assertEqual(api.writes, 2)
        self.assertTrue(api.calls[-1][1].startswith("/api/posts?"))
        entry = self.saved[-1]["items"]["2"]
        self.assertIsNone(entry["create_response_candidate_id"])
        self.assertEqual(entry["get_readback_route"], "get_posts_exact_reconciliation")
        self.assertEqual(result["status"], "queued_verified_not_published")

    def test_new_post_envelopes_need_no_guessed_field_path(self):
        self.responses[5] = {"unexpected": {"data": copy.deepcopy(self.responses[5]["file"])}}
        self.responses[6] = {"unexpected": [copy.deepcopy(self.responses[7]["post"])]}
        result, api = self.go()
        self.assertEqual(api.count, 8)
        self.assertEqual(result["status"], "queued_verified_not_published")

    def test_unknown_upload_freezes_before_create(self):
        self.responses[5] = {"id": 11}
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.count, 6)
        self.assertEqual(self.api.writes, 1)
        self.assertEqual(self.saved[-1]["items"]["2"]["phase"], "unknown_requires_review")
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.count, 0)

    def test_ambiguous_media_candidates_freeze(self):
        media = copy.deepcopy(self.responses[5]["file"])
        other = dict(media, id=12)
        self.responses[5] = {"files": [media, other]}
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.writes, 1)

    def test_ambiguous_creation_readback_never_queues(self):
        post = copy.deepcopy(self.responses[7]["post"])
        self.responses[6] = {"unrecognized": True}
        self.responses[7] = {"posts": [post, dict(post, id=14)], "total": 2, "totalPages": 1}
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.count, 8)
        self.assertEqual(self.saved[-1]["items"]["2"]["phase"], "unknown_requires_review")

    def test_get_readback_mismatch_cannot_confirm_post_success(self):
        self.responses[7]["post"]["content"] = "different title"
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.count, 8)

    def test_verified_root_get_object_supported(self):
        self.config["response_contract"]["read_post"] = []
        self.responses[7] = self.responses[7]["post"]
        result, api = self.go()
        self.assertEqual(result["status"], "queued_verified_not_published")

    def test_response_extraction_bounds(self):
        value = self.responses[5]
        for _ in range(9): value = {"nested": value}
        with self.assertRaises(w.Halt): w.response_candidate(value, "media")
        with self.assertRaises(w.Halt): w.response_candidate([{}] * 129, "media")

    def test_no_daily_api_headroom_means_no_write(self):
        self.responses[3]["count"] = 7
        with self.assertRaises(w.Halt): self.go()
        self.assertEqual(self.api.count, 4)
        self.assertEqual(self.api.writes, 0)


if __name__ == "__main__":
    unittest.main()
