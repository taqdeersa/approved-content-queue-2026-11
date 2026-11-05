import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import sys
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).parents[1]))
import qstash_cleanup as q


class Response:
    def __init__(self, status): self.status = status
    def __enter__(self): return self
    def __exit__(self, *args): pass


class Opener:
    def __init__(self, result): self.result, self.calls, self.methods = result, 0, []
    def open(self, request, timeout):
        self.calls += 1
        self.methods.append(request.method)
        if isinstance(self.result, Exception): raise self.result
        return Response(self.result)


class Cleanup(unittest.TestCase):
    def setUp(self):
        self.now = dt.datetime(2026, 11, 29, 10, 18, tzinfo=q.RIYADH)
        self.env = {"QUEUE_ZERO_COST_VERIFIED": "true", "QSTASH_TOKEN": "mock-SECRET-never-log",
                    "QSTASH_SCHEDULE_ID": "scd_mock-123"}

    def go(self, result=204, **kwargs):
        self.opener = Opener(result)
        self.http = q.HTTP(self.opener)
        return q.cleanup(execute=True, now=self.now, env=self.env, transport=self.http, **kwargs)

    def test_delete_exactly_once(self):
        result, code = self.go()
        self.assertEqual((result, code), ({"status": "deleted", "requests": 1}, 0))
        self.assertEqual(self.opener.methods, ["DELETE"])
        with self.assertRaises(q.Refuse): self.http.delete(q.BASE + "scd_mock-123", self.env["QSTASH_TOKEN"])
        self.assertEqual(self.opener.calls, 1)

    def test_404_already_absent(self):
        error = urllib.error.HTTPError(q.BASE + "scd_mock-123", 404, "secret body", {}, io.BytesIO(b"secret"))
        result, code = self.go(error)
        self.assertEqual((result["status"], result["requests"], code), ("already_absent", 1, 0))

    def test_unknown_and_failure_never_retry(self):
        for failure in [TimeoutError("mock-SECRET-never-log"), 500, 302]:
            with self.subTest(failure=type(failure).__name__):
                result, code = self.go(failure)
                self.assertEqual(code, 2)
                self.assertEqual(self.opener.calls, 1)
                self.assertEqual(result["requests"], 1)

    def test_wrong_day_or_cost_gate_zero_requests(self):
        self.now = self.now + dt.timedelta(days=1)
        self.assertEqual(self.go()[0]["requests"], 0)
        self.now -= dt.timedelta(days=1)
        self.env["QUEUE_ZERO_COST_VERIFIED"] = "false"
        self.assertEqual(self.go()[0]["requests"], 0)

    def test_endpoint_and_id_validation(self):
        for url in ["http://qstash-eu-central-1.upstash.io/v2/schedules/a", "https://evil.test/v2/schedules/a",
                    "https://qstash-eu-central-1.upstash.io.evil.test/v2/schedules/a", q.BASE + "../x", q.BASE + "a?x=1",
                    q.BASE + "a/b", q.BASE + "%2Fa", "https://user@qstash-eu-central-1.upstash.io/v2/schedules/a"]:
            with self.subTest(url=url):
                opener = Opener(204)
                with self.assertRaises(q.Refuse): q.HTTP(opener).delete(url, "secret")
                self.assertEqual(opener.calls, 0)
        self.env["QSTASH_SCHEDULE_ID"] = "../other"
        self.assertEqual(self.go()[0]["requests"], 0)

    def test_redirect_handler_never_follows(self):
        with self.assertRaises(q.Refuse): q.NoRedirect().redirect_request(None, None, 302, "", {}, "https://evil.test")

    def test_generic_output_no_credentials_or_body(self):
        out, opener = io.StringIO(), Opener(TimeoutError("mock-SECRET-never-log"))
        with contextlib.redirect_stdout(out):
            code = q.main(["--execute"], now=self.now, env=self.env, transport=q.HTTP(opener))
        self.assertEqual(code, 2)
        self.assertNotIn(self.env["QSTASH_TOKEN"], out.getvalue())
        self.assertNotIn(self.env["QSTASH_SCHEDULE_ID"], out.getvalue())
        self.assertEqual(json.loads(out.getvalue())["requests"], 1)

    def test_dry_run_zero_calls(self):
        opener = Opener(204)
        result, code = q.cleanup(now=self.now, env=self.env, transport=q.HTTP(opener))
        self.assertEqual((result["status"], code, opener.calls), ("dry_run_no_request", 0, 0))


if __name__ == "__main__": unittest.main()
