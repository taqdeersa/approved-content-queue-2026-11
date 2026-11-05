import base64
import contextlib
import copy
import datetime as dt
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import sealed_runner as seal
import worker
import test_worker as fixtures


class Verification(unittest.TestCase):
    setUp = fixtures.Guards.setUp
    tearDown = fixtures.Guards.tearDown

    def setup_verification(self):
        config = copy.deepcopy(self.config)
        config["public_repository_sealed_verified"] = True
        config["response_contract"]["read_post"] = []
        channels = copy.deepcopy(self.responses[1])
        channels["channels"][0]["accountType"] = "public_profile"
        post = copy.deepcopy(self.responses[7]["post"])
        post["mediaFiles"][0].update(mimeType="image/png", sizeBytes=(self.root / "asset.png").stat().st_size)
        entry = {"phase": "queued_verified", "asset_sha256": self.manifest["items"][0]["asset_sha256"],
                 "scheduled_at": self.manifest["items"][0]["scheduled_at"], "provider_post_id": 13,
                 "media_id": 11, "provider_mime_type": "image/png",
                 "provider_size_bytes": (self.root / "asset.png").stat().st_size}
        worker.write(self.root / "state.json", {"schema": 1, "items": {"2": entry}})
        return config, channels, post

    def test_two_gets_no_writes_or_ledger_mutation(self):
        config, channels, post = self.setup_verification()
        before = (self.root / "state.json").read_bytes()
        api = fixtures.Fake([channels, post])
        result = seal.verify_existing(self.root, config, api)
        self.assertEqual(api.count, 2)
        self.assertEqual(api.writes, 0)
        self.assertEqual([c[0] for c in api.calls], ["GET", "GET"])
        self.assertEqual((self.root / "state.json").read_bytes(), before)
        self.assertEqual(result["status"], "verified_existing_post_read_only")

    def test_wrong_identity_stops_after_one_get(self):
        config, channels, post = self.setup_verification()
        channels["channels"][0]["accountId"] = "wrong-profile"
        api = fixtures.Fake([channels, post])
        with self.assertRaises(worker.Halt): seal.verify_existing(self.root, config, api)
        self.assertEqual(api.count, 1)
        self.assertEqual(api.writes, 0)

    def test_wrong_remote_media_rejected(self):
        config, channels, post = self.setup_verification()
        post["mediaFiles"][0]["id"] = 999
        api = fixtures.Fake([channels, post])
        with self.assertRaises(worker.Halt): seal.verify_existing(self.root, config, api)
        self.assertEqual(api.count, 2)

    def test_changed_local_asset_stops_before_get(self):
        config, channels, post = self.setup_verification()
        (self.root / "asset.png").write_bytes(b"changed")
        api = fixtures.Fake([channels, post])
        with self.assertRaises(worker.Halt): seal.verify_existing(self.root, config, api)
        self.assertEqual(api.count, 0)

    def test_verify_cannot_reach_execute_path(self):
        with self.assertRaises(worker.Halt): seal.run(self.root, execute=True, mode="verify")

    def test_reserved_legacy_env_cannot_enable_cost_gate(self):
        legacy_name = "_".join(["GITHUB", "ZERO", "COST", "VERIFIED"])
        with mock.patch.dict(os.environ, {legacy_name: "true", "BULKPUBLISH_API_KEY": "bp_mock"}, clear=True):
            with self.assertRaisesRegex(worker.Halt, "cost_gate"):
                seal.run(self.root, mode="verify", now=self.now)

    def test_future_year_and_publish_boundaries(self):
        self.assertFalse(seal.execution_window(dt.datetime(2027, 11, 2, tzinfo=worker.RIYADH), "publish"))
        self.assertFalse(seal.execution_window(dt.datetime(2026, 11, 1, tzinfo=worker.RIYADH), "publish"))
        self.assertTrue(seal.execution_window(dt.datetime(2026, 11, 29, tzinfo=worker.RIYADH), "publish"))
        self.assertFalse(seal.execution_window(dt.datetime(2026, 11, 30, tzinfo=worker.RIYADH), "publish"))
        with self.assertRaises(worker.Halt):
            seal.run(self.root, mode="verify", now=dt.datetime(2027, 11, 1, tzinfo=worker.RIYADH))

    def test_utf8_bom_json_supported(self):
        path = self.root / "bom.json"
        path.write_text('{"ok":true}', encoding="utf-8-sig")
        self.assertEqual(worker.read(path), {"ok": True})

    def test_read_only_status_allowance_does_not_relax_queue_confirmation(self):
        config, channels, post = self.setup_verification()
        post["status"] = "published"
        self.assertFalse(worker.exact_scheduled_post(post, self.manifest["items"][0], 7, 11, 13))
        result = seal.verify_existing(self.root, config, fixtures.Fake([channels, post]))
        self.assertEqual(result["status"], "verified_existing_post_read_only")
        self.assertNotIn("published_verified", result)

    def test_encrypted_default_run_is_read_only(self):
        config, channels, post = self.setup_verification()
        worker.write(self.root / "config.json", config)
        repo = self.root / "public-repo"
        repo.mkdir()
        env = {"SNAP_QUEUE_SEAL_KEY": base64.b64encode(bytes(range(32))).decode(),
               "BULKPUBLISH_API_KEY": "bp_mock_not_real", "QUEUE_ZERO_COST_VERIFIED": "true"}
        with mock.patch.dict(os.environ, env):
            seal.seal(self.root, repo / "bundle.sealed")
            state = (self.root / "state.json").read_bytes()
            (repo / "state.sealed").write_bytes(seal.encrypt(state, seal.STATE_AAD))
            before = {p.name: p.read_bytes() for p in repo.iterdir()}
            api, output = fixtures.Fake([channels, post]), io.StringIO()
            with mock.patch.object(worker, "Transport", return_value=api), contextlib.redirect_stdout(output):
                seal.run(repo, now=self.now)
            self.assertEqual(api.count, 2)
            self.assertEqual(api.writes, 0)
            self.assertEqual(before, {p.name: p.read_bytes() for p in repo.iterdir()})
            self.assertEqual(json.loads(output.getvalue()), {"status": "verified_existing_post_read_only", "requests": 2})
