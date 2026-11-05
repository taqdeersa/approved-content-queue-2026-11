import base64
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(Path(__file__).parents[1]))
import sealed_runner as seal
import worker


class Sealing(unittest.TestCase):
    def setUp(self):
        self.old_key = os.environ.get("SNAP_QUEUE_SEAL_KEY")
        os.environ["SNAP_QUEUE_SEAL_KEY"] = base64.b64encode(bytes(range(32))).decode()
        self.temp = tempfile.TemporaryDirectory(dir=Path(__file__).parent)
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()
        if self.old_key is None:
            os.environ.pop("SNAP_QUEUE_SEAL_KEY", None)
        else:
            os.environ["SNAP_QUEUE_SEAL_KEY"] = self.old_key

    def archive(self, extra=None):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("manifest.json", json.dumps({"items": [
                {"day": n, "asset": "media/test.png", "text": "copy/test.txt"}
                for n in range(2, 31)]}))
            z.writestr("config.json", "{}")
            z.writestr("media/test.png", b"mock asset only")
            z.writestr("copy/test.txt", "mock approved text only")
            if extra:
                z.writestr(extra, "unexpected")
        return buf.getvalue()

    def test_roundtrip_and_fresh_nonce(self):
        plain = b"sanitized mock-only fixture"
        one, two = seal.encrypt(plain), seal.encrypt(plain)
        self.assertNotEqual(one, two)
        self.assertNotIn(plain, one)
        self.assertEqual(seal.decrypt(one), plain)

    def test_tamper_rejected(self):
        blob = bytearray(seal.encrypt(b"fixture"))
        blob[-1] ^= 1
        with self.assertRaises(Exception):
            seal.decrypt(bytes(blob))

    def test_bundle_state_swap_rejected(self):
        with self.assertRaises(Exception):
            seal.decrypt(seal.encrypt(b"{}", seal.STATE_AAD), seal.BUNDLE_AAD)

    def test_exact_archive_allowlist(self):
        seal.extract_bundle(self.archive(), self.root)
        self.assertTrue((self.root / "media/test.png").exists())
        with self.assertRaises(worker.Halt):
            seal.extract_bundle(self.archive("unexpected.txt"), self.root)

    def test_traversal_rejected(self):
        with self.assertRaises(worker.Halt):
            seal.extract_bundle(self.archive("../escape.txt"), self.root)

    def test_short_ciphertext_rejected(self):
        with self.assertRaises(worker.Halt):
            seal.decrypt(b"short")


if __name__ == "__main__":
    unittest.main()
