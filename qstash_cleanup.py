"""Owner-approval draft: one QStash schedule DELETE, never retried."""
import argparse
import datetime as dt
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

HOST = "qstash-eu-central-1.upstash.io"
BASE = "https://" + HOST + "/v2/schedules/"
RIYADH = dt.timezone(dt.timedelta(hours=3))


class Refuse(Exception):
    pass


def valid_url(url):
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.netloc != HOST or parsed.hostname != HOST
            or parsed.query or parsed.fragment or not parsed.path.startswith("/v2/schedules/")):
        raise Refuse("invalid_endpoint")
    schedule_id = parsed.path[len("/v2/schedules/"):]
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", schedule_id):
        raise Refuse("invalid_schedule_id")
    return url


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise Refuse("redirect_refused")


class HTTP:
    def __init__(self, opener=None):
        self.opener = opener or urllib.request.build_opener(NoRedirect)
        self.requests = 0

    def delete(self, url, token):
        valid_url(url)
        if self.requests:
            raise Refuse("second_request_refused")
        request = urllib.request.Request(url, method="DELETE", headers={"Authorization": "Bearer " + token})
        self.requests = 1
        # No response body is read or logged. Redirects cannot forward the key.
        with self.opener.open(request, timeout=20) as response:
            return response.status


def cleanup(*, execute=False, now=None, env=None, transport=None):
    env = os.environ if env is None else env
    now = now or dt.datetime.now(RIYADH)
    http = transport or HTTP()
    try:
        if now.astimezone(RIYADH).date() != dt.date(2026, 11, 29):
            raise Refuse("outside_cleanup_day")
        if env.get("QUEUE_ZERO_COST_VERIFIED") != "true":
            raise Refuse("cost_gate_closed")
        schedule_id, token = env.get("QSTASH_SCHEDULE_ID", ""), env.get("QSTASH_TOKEN", "")
        url = valid_url(BASE + schedule_id)
        if (not token or len(token) > 8192 or not token.isascii()
                or any(ord(ch) < 33 or ord(ch) > 126 for ch in token)):
            raise Refuse("credential_missing_or_invalid")
        if not execute:
            return {"status": "dry_run_no_request", "requests": 0}, 0
        try:
            status = http.delete(url, token)
        except urllib.error.HTTPError as error:
            status = error.code
            error.close()
        if 200 <= status < 300:
            return {"status": "deleted", "requests": http.requests}, 0
        if status == 404:
            return {"status": "already_absent", "requests": http.requests}, 0
        return {"status": "cleanup_failed_no_retry", "requests": http.requests}, 2
    except Refuse:
        return {"status": "cleanup_halted_no_retry", "requests": http.requests}, 2
    except Exception:
        return {"status": "cleanup_result_unknown_no_retry", "requests": http.requests}, 2


def main(argv=None, **injected):
    parser = argparse.ArgumentParser()
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    result, code = cleanup(execute=args.execute, **injected)
    print(json.dumps(result))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
