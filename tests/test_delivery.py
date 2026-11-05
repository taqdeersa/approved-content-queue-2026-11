import base64
import contextlib
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import sealed_runner as seal
import worker
import test_verification as verification
import test_worker as fixtures


class Delivery(unittest.TestCase):
    setUp = verification.Verification.setUp
    tearDown = verification.Verification.tearDown

    def prepare(self, status="published"):
        self.config, channels, post = verification.Verification.setup_verification(self)
        self.when = dt.datetime(2026, 11, 2, 9, 2, tzinfo=worker.RIYADH)
        post["status"] = status
        post["postPlatforms"][0].update(status="published" if status == "published" else "pending",
            platformPostId="mock-snap-id" if status == "published" else None,
            publishedAt="2026-11-02T06:00:20Z" if status == "published" else None)
        post["publishedAt"] = "2026-11-02T06:00:21Z" if status == "published" else None
        self.checkpoints = []
        return fixtures.Fake([channels, post]), post

    def save(self, root, state):
        self.checkpoints.append(copy.deepcopy(state))
        worker.write(root / "state.json", state)

    def test_report_requires_global_and_snap_publication_id_timestamp(self):
        api, post = self.prepare()
        result = seal.delivery_check(self.root, self.config, api, self.when, self.save)
        self.assertEqual(result, {"status": "provider_reported_published", "requests": 2})
        self.assertEqual(api.writes, 0)
        entry = self.checkpoints[-1]["items"]["2"]
        self.assertEqual(self.checkpoints[0]["items"]["2"]["phase"], "delivery_check_in_progress")
        self.assertEqual(entry["phase"], "queued_verified")
        self.assertTrue(entry["delivery_evidence"]["provider_reported_published"])
        self.assertFalse(entry["delivery_evidence"]["snapchat_visual_appearance_verified"])
        self.assertNotIn("published_verified", entry["delivery_evidence"])

    def test_pending_keeps_queue_phase(self):
        api, post = self.prepare("processing")
        result = seal.delivery_check(self.root, self.config, api, self.when, self.save)
        self.assertEqual(result["status"], "provider_not_yet_reported_published")
        self.assertEqual(self.checkpoints[-1]["items"]["2"]["phase"], "queued_verified")

    def test_partial_failure_stops_future_feeder(self):
        api, post = self.prepare("partial")
        result = seal.delivery_check(self.root, self.config, api, self.when, self.save)
        self.assertEqual(result["status"], "provider_reported_delivery_failed_requires_review")
        state = worker.read(self.root / "state.json")
        self.assertEqual(state["items"]["2"]["phase"], "delivery_failed_requires_review")
        with self.assertRaises(worker.Halt):
            worker.candidate(self.root, worker.read(self.root / "manifest.json"), state,
                             dt.datetime(2026, 11, 2, 10, 17, tzinfo=worker.RIYADH))

    def test_second_delivery_does_not_call_api(self):
        api, post = self.prepare()
        seal.delivery_check(self.root, self.config, api, self.when, self.save)
        again = fixtures.Fake([])
        with self.assertRaises(worker.Halt): seal.delivery_check(self.root, self.config, again, self.when, self.save)
        self.assertEqual(again.count, 0)

    def test_unknown_get_freezes_without_retry(self):
        api, post = self.prepare()
        api.responses[1] = worker.Halt("mock_network_failure")
        with self.assertRaises(worker.Halt): seal.delivery_check(self.root, self.config, api, self.when, self.save)
        self.assertEqual(api.count, 2)
        self.assertEqual(api.writes, 0)
        self.assertEqual(self.checkpoints[-1]["items"]["2"]["phase"], "delivery_read_unknown_requires_review")

    def test_missing_platform_id_or_timestamp_cannot_report_published(self):
        for missing in ("platformPostId", "publishedAt"):
            with self.subTest(missing=missing):
                api, post = self.prepare()
                post["postPlatforms"][0][missing] = None
                if missing == "publishedAt": post["publishedAt"] = None
                api.responses[1] = post
                result = seal.delivery_check(self.root, self.config, api, self.when, self.save)
                self.assertEqual(result["status"], "provider_not_yet_reported_published")

    def test_delivery_date_time_year_guard(self):
        for value in [(2026,11,1,9,2), (2026,11,2,8,59), (2026,11,3,9,2), (2027,11,2,9,2)]:
            self.assertFalse(seal.execution_window(dt.datetime(*value,tzinfo=worker.RIYADH), "delivery"))
        self.assertTrue(seal.execution_window(dt.datetime(2026,11,2,9,0,tzinfo=worker.RIYADH), "delivery"))
        with self.assertRaises(worker.Halt): seal.run(self.root, mode="delivery", now=self.now)

    def test_delivery_cannot_execute_publisher(self):
        with self.assertRaises(worker.Halt): seal.run(self.root, execute=True, mode="delivery")

    def test_runtime_writes_only_encrypted_state(self):
        api, post = self.prepare()
        worker.write(self.root / "config.json", self.config)
        repo = self.root / "public-repo"
        repo.mkdir()
        env = {"SNAP_QUEUE_SEAL_KEY": base64.b64encode(bytes(range(32))).decode(),
               "BULKPUBLISH_API_KEY": "bp_mock_not_real", "QUEUE_ZERO_COST_VERIFIED": "true"}
        with mock.patch.dict(os.environ, env):
            seal.seal(self.root, repo / "bundle.sealed")
            (repo / "state.sealed").write_bytes(seal.encrypt((self.root / "state.json").read_bytes(), seal.STATE_AAD))
            bundle_before = (repo / "bundle.sealed").read_bytes()
            output = io.StringIO()
            with mock.patch.object(worker, "Transport", return_value=api), \
                 mock.patch.object(seal.subprocess, "run", return_value=types.SimpleNamespace(returncode=0)), \
                 contextlib.redirect_stdout(output):
                seal.run(repo, mode="delivery", now=self.when)
            self.assertEqual(api.count, 2)
            self.assertEqual(api.writes, 0)
            self.assertEqual({p.name for p in repo.iterdir()}, {"bundle.sealed", "state.sealed"})
            self.assertEqual((repo / "bundle.sealed").read_bytes(), bundle_before)
            state = json.loads(seal.decrypt((repo / "state.sealed").read_bytes(), seal.STATE_AAD))
            self.assertEqual(state["items"]["2"]["delivery_evidence"]["status"], "provider_reported_published")
            self.assertEqual(json.loads(output.getvalue()), {"status": "provider_reported_published", "requests": 2})
