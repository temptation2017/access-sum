#!/usr/bin/env python3
"""Tests for access_sum. Stdlib unittest only."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

import access_sum as asp  # noqa: E402

EXAMPLES = ROOT / "examples"
TZ8 = asp.load_timezone("+0800")


class ParseLines(unittest.TestCase):
    def test_combined(self):
        line = (
            '203.0.113.10 - - [23/Nov/2026:08:01:02 +0800] "GET /catalog HTTP/1.1" '
            '200 4320 "https://shop.example.com/" "Mozilla/5.0 Firefox/133.0"'
        )
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.ip, "203.0.113.10")
        self.assertEqual(ent.method, "GET")
        self.assertEqual(ent.path, "/catalog")
        self.assertEqual(ent.status, 200)
        self.assertEqual(ent.nbytes, 4320)
        self.assertEqual(ent.referer, "https://shop.example.com/")
        self.assertIn("Firefox", ent.ua)
        self.assertEqual(ent.time.utcoffset(), timedelta(hours=8))
        self.assertEqual(ent.time.hour, 8)

    def test_common_without_ref_ua(self):
        line = '192.0.2.10 - alice [23/Nov/2026:08:01:02 +0000] "GET /index.html HTTP/1.0" 200 1234'
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.path, "/index.html")
        self.assertEqual(ent.status, 200)
        self.assertEqual(ent.nbytes, 1234)
        self.assertEqual(ent.referer, "")
        self.assertEqual(ent.ua, "")

    def test_nginx_times_and_query_split(self):
        line = (
            '203.0.113.21 - - [23/Nov/2026:10:00:02 +0800] "GET /api/items?q=lamp HTTP/1.1" '
            '200 4096 "https://shop.example.com/catalog" "Mozilla/5.0" 0.355 0.340'
        )
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.path, "/api/items")
        self.assertEqual(ent.query, "q=lamp")
        self.assertEqual(ent.request_time, 0.355)
        self.assertEqual(ent.upstream_time, 0.340)

    def test_upstream_dash(self):
        line = (
            '198.51.100.8 - - [23/Nov/2026:10:03:00 +0800] "GET /health HTTP/1.1" '
            '200 16 "-" "curl/8.7.1" 0.002 -'
        )
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.request_time, 0.002)
        self.assertIsNone(ent.upstream_time)

    def test_ipv6(self):
        line = (
            '2001:db8::10 - - [23/Nov/2026:09:20:00 +0800] "GET /catalog/99 HTTP/1.1" '
            '200 1988 "-" "Mozilla/5.0"'
        )
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.ip, "2001:db8::10")
        self.assertEqual(ent.path, "/catalog/99")

    def test_json_nginx_and_duration_ms(self):
        line = (
            '{"time_local":"23/Nov/2026:11:00:01 +0800","remote_addr":"203.0.113.31",'
            '"request":"GET /api/v2/users/17 HTTP/1.1","status":200,"body_bytes_sent":256,'
            '"request_time":0.051,"http_user_agent":"Mozilla/5.0","http_referer":"-"}'
        )
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertEqual(ent.path, "/api/v2/users/17")
        self.assertEqual(ent.request_time, 0.051)
        self.assertEqual(ent.status, 200)

        line2 = (
            '{"timestamp":"2026-11-23T03:01:00Z","client_ip":"203.0.113.32","method":"POST",'
            '"path":"/api/v2/login","status":401,"bytes":40,"duration_ms":18,'
            '"user_agent":"Chrome","referer":"https://shop.example.com/login"}'
        )
        ent2 = asp.parse_line(line2)
        self.assertIsNotNone(ent2)
        assert ent2 is not None
        self.assertEqual(ent2.method, "POST")
        self.assertEqual(ent2.path, "/api/v2/login")
        self.assertEqual(ent2.request_time, 0.018)
        self.assertEqual(ent2.time, datetime(2026, 11, 23, 3, 1, 0, tzinfo=timezone.utc))

    def test_comments_and_garbage(self):
        self.assertIsNone(asp.parse_line("# just a comment"))
        self.assertIsNone(asp.parse_line("   "))
        self.assertIsNone(asp.parse_line("this is not a log"))

    def test_dash_status_and_bytes(self):
        line = '203.0.113.1 - - [23/Nov/2026:08:00:00 +0800] "GET / HTTP/1.1" - -'
        ent = asp.parse_line(line)
        self.assertIsNotNone(ent)
        assert ent is not None
        self.assertIsNone(ent.status)
        self.assertIsNone(ent.nbytes)


class PathAndFilter(unittest.TestCase):
    def test_normalize_id_and_uuid(self):
        self.assertEqual(asp.normalize_path("/api/items/1001"), "/api/items/:id")
        self.assertEqual(
            asp.normalize_path("/api/orders/550e8400-e29b-41d4-a716-446655440000"),
            "/api/orders/:id",
        )
        self.assertEqual(asp.normalize_path("/api/v2/users/17/orders"), "/api/v2/users/:id/orders")
        self.assertEqual(asp.normalize_path("/health"), "/health")

    def test_status_and_method_filters(self):
        self.assertTrue(asp.status_matches(502, ["5xx"]))
        self.assertTrue(asp.status_matches(404, ["4xx", "500"]))
        self.assertFalse(asp.status_matches(200, ["5xx"]))
        self.assertTrue(asp.method_matches("GET", ["get", "POST"]))
        self.assertFalse(asp.method_matches("PUT", ["GET"]))

    def test_percentile_and_bytes(self):
        vals = [0.002, 0.015, 0.028, 0.042, 0.091, 0.118, 0.220, 0.355, 1.842, 3.012]
        self.assertEqual(asp.percentile(vals, 50), 0.091)
        self.assertEqual(asp.percentile(vals, 95), 3.012)
        self.assertEqual(asp.format_bytes(16), "16 B")
        self.assertTrue(asp.format_bytes(4320).endswith("KB"))
        self.assertTrue(asp.is_bot("curl/8.7.1"))
        self.assertTrue(asp.is_bot("Mozilla/5.0 (compatible; Googlebot/2.1)"))
        self.assertFalse(asp.is_bot("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0)"))


class LoadExamples(unittest.TestCase):
    def test_combined_example(self):
        report = asp.load_reports(
            [str(EXAMPLES / "combined.log")],
            normalize=False,
            keep_query=False,
            since=None,
            until=None,
            statuses=[],
            methods=[],
        )
        self.assertEqual(report.parsed, 12)
        self.assertEqual(report.skipped, 0)
        self.assertEqual(len(report.entries), 12)
        summary = asp.summarize(report, normalize=False, keep_query=False, top=10, tz=TZ8)
        self.assertEqual(summary["requests"], 12)
        self.assertEqual(summary["status"]["200"], 7)
        self.assertEqual(summary["status"]["500"], 1)
        self.assertEqual(summary["methods"]["GET"], 9)
        cart = [r for r in summary["top_paths"] if r["path"] == "/api/cart"]
        self.assertEqual(len(cart), 1)
        self.assertEqual(cart[0]["hits"], 2)
        self.assertTrue(summary["bot_hits"] >= 3)
        text = asp.render_text(summary)
        self.assertIn("203.0.113.10", text)
        self.assertNotIn("session=demo", text)

    def test_nginx_normalize_and_times(self):
        report = asp.load_reports(
            [str(EXAMPLES / "nginx-timed.log")],
            normalize=True,
            keep_query=False,
            since=None,
            until=None,
            statuses=[],
            methods=[],
        )
        self.assertEqual(report.parsed, 10)
        summary = asp.summarize(report, normalize=True, keep_query=False, top=10, tz=TZ8)
        self.assertTrue(summary["has_request_time"])
        paths = {r["path"]: r for r in summary["top_paths"]}
        self.assertIn("/api/items/:id", paths)
        self.assertEqual(paths["/api/items/:id"]["hits"], 3)
        self.assertIn("/api/orders/:id", paths)
        self.assertEqual(summary["slowest"][0]["request_time"], 3.012)
        self.assertEqual(summary["slowest"][0]["status"], 502)

    def test_jsonl_example(self):
        report = asp.load_reports(
            [str(EXAMPLES / "jsonl.log")],
            normalize=True,
            keep_query=False,
            since=None,
            until=None,
            statuses=[],
            methods=[],
        )
        self.assertEqual(report.parsed, 6)
        summary = asp.summarize(report, normalize=True, keep_query=False, top=10, tz=TZ8)
        paths = {r["path"] for r in summary["top_paths"]}
        self.assertIn("/api/v2/users/:id", paths)
        self.assertIn("/api/v2/login", paths)
        self.assertEqual(summary["status"]["401"], 1)

    def test_status_filter_counts(self):
        report = asp.load_reports(
            [str(EXAMPLES / "combined.log")],
            normalize=False,
            keep_query=False,
            since=None,
            until=None,
            statuses=["4xx", "5xx"],
            methods=[],
        )
        self.assertEqual(report.parsed, 12)
        self.assertEqual(len(report.entries), 2)
        statuses = sorted(e.status for e in report.entries)
        self.assertEqual(statuses, [404, 500])

    def test_since_until(self):
        since = asp.parse_cli_time("2026-11-23T09:00:00+08:00")
        report = asp.load_reports(
            [str(EXAMPLES / "combined.log")],
            normalize=False,
            keep_query=False,
            since=since,
            until=None,
            statuses=[],
            methods=[],
        )
        self.assertEqual(report.parsed, 12)
        self.assertEqual(len(report.entries), 3)
        hours = {e.time.hour for e in report.entries if e.time}
        self.assertEqual(hours, {9})

    def test_keep_query(self):
        report = asp.load_reports(
            [str(EXAMPLES / "combined.log")],
            normalize=False,
            keep_query=True,
            since=None,
            until=None,
            statuses=[],
            methods=[],
        )
        summary = asp.summarize(report, normalize=False, keep_query=True, top=20, tz=TZ8)
        paths = [r["path"] for r in summary["top_paths"]]
        self.assertTrue(any("session=demo" in p for p in paths))

    def test_cli_json_and_strict(self):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            code = asp.main([str(EXAMPLES / "nginx-timed.log"), "--json", "--normalize", "--tz", "+0800"])
        finally:
            sys.stdout = old
        self.assertEqual(code, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["requests"], 10)
        self.assertTrue(data["has_request_time"])

        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write("not a log line\n")
            bad = fh.name
        try:
            buf2 = io.StringIO()
            sys.stdout = buf2
            try:
                code = asp.main([bad, "--strict"])
            finally:
                sys.stdout = old
            self.assertEqual(code, 1)
        finally:
            os.unlink(bad)

    def test_stdin_and_empty_tty_help(self):
        text = (EXAMPLES / "combined.log").read_text()
        old_in, old_out = sys.stdin, sys.stdout
        sys.stdin = io.StringIO(text)
        sys.stdout = io.StringIO()
        try:
            code = asp.main(["-", "--tz", "UTC"])
            out = sys.stdout.getvalue()
        finally:
            sys.stdin, sys.stdout = old_in, old_out
        self.assertEqual(code, 0)
        self.assertIn("parsed 12", out)
        self.assertIn("stdin", out)


if __name__ == "__main__":
    unittest.main()
