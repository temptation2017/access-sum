#!/usr/bin/env python3
"""Summarize HTTP access logs (Combined, Common, Nginx timed, JSON). Stdlib only."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, TextIO, Tuple

USAGE_EXIT = 2
FAIL_EXIT = 1
MAX_BYTES = 100 * 1024 * 1024

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}

COMBINED_RE = re.compile(
    r"^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"
    r'"(?P<req>[^"]*)"\s+(?P<status>\d{3}|-)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?'
    r"(?P<rest>.*)$"
)

REQUEST_RE = re.compile(r"^([A-Z]{1,16}|[A-Za-z]+)\s+(\S+)(?:\s+(\S+))?$")

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
NUM_RE = re.compile(r"^\d+$")
BOT_HINT = re.compile(
    r"bot|crawler|spider|slurp|scan|preview|monitor|wget|curl|"
    r"python-requests|httpie|okhttp|go-http-client|aiohttp|java/|"
    r"libwww|feedfetcher|facebookexternalhit|semrush|ahrefs|bingpreview",
    re.I,
)

JSON_TIME_KEYS = (
    "time_local", "time", "time_iso", "timestamp", "ts", "@timestamp",
    "iso8601", "datetime", "date",
)
JSON_IP_KEYS = ("remote_addr", "client_ip", "clientip", "ip", "client", "remoteIp")
JSON_STATUS_KEYS = ("status", "status_code", "code", "statusCode")
JSON_BYTES_KEYS = (
    "body_bytes_sent", "bytes_sent", "bytes", "size", "bodyBytesSent", "content_length",
)
JSON_RT_KEYS = ("request_time", "rt", "duration", "latency", "elapsed", "response_time")
JSON_RT_MS_KEYS = ("duration_ms", "latency_ms", "elapsed_ms", "response_time_ms", "request_time_ms")
JSON_UP_KEYS = ("upstream_response_time", "upstream_time", "upstream")
JSON_UA_KEYS = ("http_user_agent", "user_agent", "useragent", "ua", "userAgent")
JSON_REF_KEYS = ("http_referer", "http_referrer", "referer", "referrer")
JSON_METHOD_KEYS = ("request_method", "method")
JSON_PATH_KEYS = ("request_uri", "uri", "path", "url")
JSON_REQUEST_KEYS = ("request",)


@dataclass
class Entry:
    ip: str = ""
    time: Optional[datetime] = None
    method: str = ""
    path: str = ""
    query: str = ""
    protocol: str = ""
    status: Optional[int] = None
    nbytes: Optional[int] = None
    referer: str = ""
    ua: str = ""
    request_time: Optional[float] = None
    upstream_time: Optional[float] = None
    source: str = ""
    line_no: int = 0


@dataclass
class Report:
    sources: List[str] = field(default_factory=list)
    entries: List[Entry] = field(default_factory=list)
    parsed: int = 0
    skipped: int = 0
    warnings: List[str] = field(default_factory=list)
    unparsed_samples: List[str] = field(default_factory=list)


def first_present(obj: Dict[str, Any], keys: Sequence[str]) -> Any:
    for key in keys:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    lower = {str(k).lower(): v for k, v in obj.items()}
    for key in keys:
        if key.lower() in lower and lower[key.lower()] not in (None, ""):
            return lower[key.lower()]
    return None


def parse_int(value: Any) -> Optional[int]:
    if value is None or value == "" or value == "-":
        return None
    try:
        return int(float(str(value).strip()))
    except (TypeError, ValueError):
        return None


def parse_float(value: Any) -> Optional[float]:
    if value is None or value == "" or value == "-":
        return None
    text = str(value).strip()
    if "," in text and "." not in text:
        text = text.replace(",", ".")
    if "," in text:
        text = text.split(",")[0].strip()
    try:
        return float(text)
    except ValueError:
        return None


def parse_apache_time(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    if not text:
        return None
    # 10/Oct/2000:13:55:36 -0700  or  10/Oct/2000:13:55:36 +0800
    m = re.match(
        r"^(\d{1,2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s+([+-]\d{2}:?\d{2}|Z))?$",
        text,
    )
    if not m:
        return parse_iso_time(text)
    day, mon, year, hh, mm, ss, off = m.groups()
    month = MONTHS.get(mon.capitalize())
    if not month:
        return None
    tz = parse_offset(off) if off else timezone.utc
    try:
        return datetime(int(year), month, int(day), int(hh), int(mm), int(ss), tzinfo=tz)
    except ValueError:
        return None


def parse_offset(text: str) -> timezone:
    text = text.strip()
    if text in ("Z", "z", "UTC", "GMT"):
        return timezone.utc
    compact = text.replace(":", "")
    sign = 1 if compact[0] != "-" else -1
    hh = int(compact[1:3])
    mm = int(compact[3:5]) if len(compact) >= 5 else 0
    return timezone(sign * timedelta(hours=hh, minutes=mm))


def parse_iso_time(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    if not text:
        return None
    if re.fullmatch(r"\d{10,13}", text):
        try:
            n = int(text)
        except ValueError:
            return None
        if n > 10**12:
            n = n / 1000.0
        try:
            return datetime.fromtimestamp(n, tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return None
    cleaned = text.replace("Z", "+00:00").replace("z", "+00:00")
    cleaned = re.sub(r"\s+", "T", cleaned, count=1)
    # 2026-11-23 08:00:00 +0800  /  2026-11-23T08:00:00+08:00
    m = re.match(
        r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:\.(\d+))?(?:\s*)?(.*)$",
        cleaned,
    )
    if m:
        date, hms, frac, off = m.groups()
        micro = 0
        if frac:
            micro = int((frac + "000000")[:6])
        tz: Optional[timezone]
        off = (off or "").strip()
        if not off:
            tz = None
        else:
            try:
                tz = parse_offset(off)
            except (ValueError, IndexError):
                tz = None
        try:
            dt = datetime.strptime("%sT%s" % (date, hms), "%Y-%m-%dT%H:%M:%S")
            dt = dt.replace(microsecond=micro, tzinfo=tz)
            return dt
        except ValueError:
            pass
    try:
        dt = datetime.fromisoformat(cleaned)
        return dt
    except ValueError:
        return None


def parse_cli_time(text: str) -> Optional[datetime]:
    text = (text or "").strip()
    if not text:
        return None
    dt = parse_iso_time(text) or parse_apache_time(text)
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def split_request(req: str) -> Tuple[str, str, str, str]:
    req = (req or "").strip()
    if not req or req == "-":
        return "", "", "", ""
    m = REQUEST_RE.match(req)
    if not m:
        path, query = split_path(req)
        return "", path, query, ""
    method, target, proto = m.group(1), m.group(2), m.group(3) or ""
    path, query = split_path(target)
    return method.upper(), path, query, proto


def split_path(target: str) -> Tuple[str, str]:
    target = target.strip()
    if not target:
        return "", ""
    if target.startswith("http://") or target.startswith("https://"):
        # origin-form sometimes appears as a full URL
        rest = re.sub(r"^https?://[^/]+", "", target, flags=re.I)
        target = rest if rest.startswith("/") else "/" + rest
    if "?" in target:
        path, query = target.split("?", 1)
        return path or "/", query
    return target or "/", ""


def parse_trailing_times(rest: str) -> Tuple[Optional[float], Optional[float]]:
    if not rest:
        return None, None
    tokens = rest.strip().split()
    times: List[Optional[float]] = []
    for tok in tokens:
        tok = tok.strip().strip(",")
        if not tok:
            continue
        if tok.strip('"') in ("-", "") or re.fullmatch(r"[A-Za-z_]+", tok):
            times.append(None)
            continue
        # key=value
        if "=" in tok and not tok[0].isdigit() and tok[0] not in "+-":
            _, _, val = tok.partition("=")
            tok = val
        num = parse_float(tok)
        if num is None:
            continue
        times.append(num)
        if len(times) >= 2:
            break
    req = times[0] if times else None
    up = times[1] if len(times) > 1 else None
    return req, up


def parse_combined_line(line: str) -> Optional[Entry]:
    m = COMBINED_RE.match(line.rstrip("\n\r"))
    if not m:
        return None
    method, path, query, proto = split_request(m.group("req"))
    rest = m.group("rest") or ""
    req_t, up_t = parse_trailing_times(rest)
    status = parse_int(m.group("status"))
    size = parse_int(m.group("size"))
    return Entry(
        ip=m.group("ip"),
        time=parse_apache_time(m.group("time")),
        method=method,
        path=path or "/",
        query=query,
        protocol=proto,
        status=status,
        nbytes=size,
        referer=(m.group("ref") or "").strip(),
        ua=(m.group("ua") or "").strip(),
        request_time=req_t,
        upstream_time=up_t,
    )


def parse_json_line(line: str) -> Optional[Entry]:
    text = line.strip()
    if not text.startswith("{"):
        return None
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    raw_req = first_present(obj, JSON_REQUEST_KEYS)
    method, path, query, proto = "", "", "", ""
    if isinstance(raw_req, str):
        method, path, query, proto = split_request(raw_req)
    m2 = first_present(obj, JSON_METHOD_KEYS)
    p2 = first_present(obj, JSON_PATH_KEYS)
    if m2:
        method = str(m2).upper()
    if p2:
        path, query2 = split_path(str(p2))
        if query2:
            query = query2
    raw_time = first_present(obj, JSON_TIME_KEYS)
    dt = None
    if raw_time is not None:
        if isinstance(raw_time, (int, float)):
            dt = parse_iso_time(str(int(raw_time) if float(raw_time).is_integer() else raw_time))
        else:
            # nginx time_local is usually 10/Nov/2026:08:01:02 +0800
            dt = parse_apache_time(str(raw_time)) or parse_iso_time(str(raw_time))
    rt = parse_float(first_present(obj, JSON_RT_KEYS))
    if rt is None:
        ms = parse_float(first_present(obj, JSON_RT_MS_KEYS))
        if ms is not None:
            rt = ms / 1000.0
    return Entry(
        ip=str(first_present(obj, JSON_IP_KEYS) or ""),
        time=dt,
        method=method,
        path=path or "/",
        query=query,
        protocol=proto,
        status=parse_int(first_present(obj, JSON_STATUS_KEYS)),
        nbytes=parse_int(first_present(obj, JSON_BYTES_KEYS)),
        referer=str(first_present(obj, JSON_REF_KEYS) or ""),
        ua=str(first_present(obj, JSON_UA_KEYS) or ""),
        request_time=rt,
        upstream_time=parse_float(first_present(obj, JSON_UP_KEYS)),
    )


def parse_line(line: str) -> Optional[Entry]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if stripped.startswith("{"):
        ent = parse_json_line(stripped)
        if ent is not None:
            return ent
    return parse_combined_line(stripped)


def normalize_path(path: str) -> str:
    if not path:
        return "/"
    parts = path.split("/")
    out = []
    for part in parts:
        if part == "":
            out.append(part)
            continue
        if UUID_RE.match(part) or HEX_RE.match(part) or NUM_RE.match(part):
            out.append(":id")
        else:
            out.append(part)
    joined = "/".join(out)
    return joined if joined.startswith("/") else "/" + joined


def display_path(entry: Entry, normalize: bool, keep_query: bool) -> str:
    path = normalize_path(entry.path) if normalize else (entry.path or "/")
    if keep_query and entry.query:
        return path + "?" + entry.query
    return path


def status_matches(status: Optional[int], specs: Sequence[str]) -> bool:
    if not specs:
        return True
    if status is None:
        return False
    text = str(status)
    cls = text[0] + "xx"
    for spec in specs:
        spec = spec.strip().lower()
        if not spec:
            continue
        if spec in (text, cls, text[0] + "XX".lower()):
            return True
        if spec.endswith("xx") and spec[0] == text[0]:
            return True
        if spec.isdigit() and int(spec) == status:
            return True
    return False


def method_matches(method: str, specs: Sequence[str]) -> bool:
    if not specs:
        return True
    wanted = {s.strip().upper() for s in specs if s.strip()}
    return method.upper() in wanted


def as_utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def load_timezone(name: Optional[str]):
    if not name:
        return timezone.utc
    name = name.strip()
    if name.upper() in ("UTC", "GMT", "Z"):
        return timezone.utc
    if re.fullmatch(r"[+-]\d{2}:?\d{2}", name):
        return parse_offset(name)
    try:
        from zoneinfo import ZoneInfo  # type: ignore

        return ZoneInfo(name)
    except Exception:
        raise argparse.ArgumentTypeError(
            "unknown timezone %r (try UTC, +0800, or an IANA name such as Asia/Shanghai)" % name
        )


def format_bytes(n: Optional[int]) -> str:
    if n is None:
        return "-"
    if n < 0:
        n = 0
    units = ["B", "KB", "MB", "GB", "TB"]
    val = float(n)
    unit = 0
    while val >= 1024 and unit < len(units) - 1:
        val /= 1024.0
        unit += 1
    if unit == 0:
        return "%d B" % n
    if val >= 10:
        return "%.1f %s" % (val, units[unit])
    return "%.2f %s" % (val, units[unit])


def format_duration(seconds: Optional[float]) -> str:
    if seconds is None:
        return "-"
    if seconds < 0:
        seconds = 0.0
    if seconds < 1:
        return "%.0fms" % (seconds * 1000)
    if seconds < 10:
        return "%.3fs" % seconds
    if seconds < 60:
        return "%.1fs" % seconds
    minutes, rem = divmod(seconds, 60)
    if minutes < 60:
        return "%dm %04.1fs" % (int(minutes), rem)
    hours, minutes = divmod(int(minutes), 60)
    return "%dh %dm" % (hours, minutes)


def format_dt(dt: Optional[datetime], tz) -> str:
    if dt is None:
        return "-"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local = dt.astimezone(tz)
    return local.strftime("%Y-%m-%d %H:%M:%S %z")


def percentile(values: List[float], p: float) -> Optional[float]:
    if not values:
        return None
    if p <= 0:
        return values[0]
    if p >= 100:
        return values[-1]
    ordered = sorted(values)
    # nearest-rank
    k = int(math.ceil((p / 100.0) * len(ordered))) - 1
    k = min(max(k, 0), len(ordered) - 1)
    return ordered[k]


def short_ua(ua: str, limit: int = 72) -> str:
    ua = " ".join((ua or "").split())
    if not ua or ua == "-":
        return "-"
    if len(ua) <= limit:
        return ua
    return ua[: limit - 3] + "..."


def is_bot(ua: str) -> bool:
    if not ua or ua == "-":
        return False
    return BOT_HINT.search(ua) is not None


def bar(n: int, total: int, width: int = 16) -> str:
    if total <= 0 or n <= 0:
        return ""
    filled = int(round(width * n / float(total)))
    filled = min(max(filled, 1 if n else 0), width)
    return "█" * filled


def parse_csv_list(text: Optional[str]) -> List[str]:
    if not text:
        return []
    return [p.strip() for p in text.split(",") if p.strip()]


def iter_lines(path: str) -> Iterable[Tuple[int, str]]:
    if path == "-":
        for i, line in enumerate(sys.stdin, 1):
            yield i, line
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh, 1):
            yield i, line


def load_reports(
    paths: Sequence[str],
    *,
    normalize: bool,
    keep_query: bool,
    since: Optional[datetime],
    until: Optional[datetime],
    statuses: Sequence[str],
    methods: Sequence[str],
) -> Report:
    report = Report()
    if not paths:
        paths = ["-"]
    for path in paths:
        label = "stdin" if path == "-" else path
        if path != "-":
            try:
                size = os_size(path)
            except OSError as exc:
                report.warnings.append("cannot read %s: %s" % (path, exc))
                continue
            if size > MAX_BYTES:
                report.warnings.append(
                    "skip %s: %.1f MB exceeds %d MB limit" % (path, size / 1048576.0, MAX_BYTES // 1048576)
                )
                continue
        report.sources.append(label)
        local_parsed = 0
        local_skipped = 0
        try:
            for line_no, line in iter_lines(path):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                ent = parse_line(line)
                if ent is None:
                    local_skipped += 1
                    report.skipped += 1
                    if len(report.unparsed_samples) < 5:
                        sample = line.strip()
                        if len(sample) > 180:
                            sample = sample[:177] + "..."
                        report.unparsed_samples.append("%s:%d: %s" % (label, line_no, sample))
                    continue
                ent.source = label
                ent.line_no = line_no
                local_parsed += 1
                report.parsed += 1
                when = as_utc(ent.time)
                if since and (when is None or when < since):
                    continue
                if until and (when is None or when > until):
                    continue
                if not status_matches(ent.status, statuses):
                    continue
                if not method_matches(ent.method, methods):
                    continue
                report.entries.append(ent)
        except OSError as exc:
            report.warnings.append("cannot read %s: %s" % (label, exc))
            continue
        if local_parsed == 0 and local_skipped == 0:
            report.warnings.append("%s: no log lines found" % label)
    if report.skipped:
        report.warnings.append("%d line(s) could not be parsed" % report.skipped)
        report.warnings.extend(report.unparsed_samples)
    return report


def os_size(path: str) -> int:
    import os

    return os.path.getsize(path)


def summarize(report: Report, *, normalize: bool, keep_query: bool, top: int, tz) -> Dict[str, Any]:
    entries = report.entries
    times = [as_utc(e.time) for e in entries if e.time]
    start = min(times) if times else None
    end = max(times) if times else None
    span = None
    if start and end:
        span = (end - start).total_seconds()
    rts = [e.request_time for e in entries if e.request_time is not None]
    nbytes = [e.nbytes for e in entries if e.nbytes is not None]
    total_bytes = sum(nbytes) if nbytes else 0

    status_counts: Counter = Counter()
    method_counts: Counter = Counter()
    path_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"hits": 0, "bytes": 0, "times": []})
    ip_counts: Counter = Counter()
    ua_counts: Counter = Counter()
    ref_counts: Counter = Counter()
    err_paths: Dict[str, Counter] = defaultdict(Counter)
    bot_hits = 0

    for e in entries:
        if e.status is not None:
            status_counts[e.status] += 1
        if e.method:
            method_counts[e.method] += 1
        key = display_path(e, normalize, keep_query)
        st = path_stats[key]
        st["hits"] += 1
        st["bytes"] += e.nbytes or 0
        if e.request_time is not None:
            st["times"].append(e.request_time)
        if e.ip:
            ip_counts[e.ip] += 1
        if e.ua and e.ua != "-":
            ua_counts[e.ua] += 1
            if is_bot(e.ua):
                bot_hits += 1
        if e.referer and e.referer not in ("-", ""):
            ref_counts[e.referer] += 1
        if e.status is not None and e.status >= 400:
            err_paths[key][e.status] += 1

    def path_rows(items: Iterable[Tuple[str, Dict[str, Any]]], n: int) -> List[Dict[str, Any]]:
        rows = []
        for path, st in items:
            avg = (sum(st["times"]) / len(st["times"])) if st["times"] else None
            rows.append({
                "path": path,
                "hits": st["hits"],
                "bytes": st["bytes"],
                "avg_time": avg,
            })
        rows.sort(key=lambda r: (-r["hits"], -r["bytes"], r["path"]))
        return rows[:n]

    slowest = []
    if rts:
        ranked = sorted(
            (e for e in entries if e.request_time is not None),
            key=lambda e: e.request_time or 0.0,
            reverse=True,
        )
        for e in ranked[:top]:
            slowest.append({
                "time": format_dt(e.time, tz) if e.time else None,
                "request_time": e.request_time,
                "status": e.status,
                "method": e.method,
                "path": display_path(e, normalize, keep_query),
                "ip": e.ip,
            })

    hist = build_histogram(times, tz)

    err_rows = []
    for path, counts in err_paths.items():
        err_rows.append({
            "path": path,
            "hits": sum(counts.values()),
            "statuses": {str(k): v for k, v in sorted(counts.items())},
        })
    err_rows.sort(key=lambda r: (-r["hits"], r["path"]))

    return {
        "sources": report.sources,
        "parsed": report.parsed,
        "skipped": report.skipped,
        "warnings": report.warnings,
        "range_start": format_dt(start, tz) if start else None,
        "range_end": format_dt(end, tz) if end else None,
        "span_seconds": span,
        "requests": len(entries),
        "bytes": total_bytes,
        "avg_time": (sum(rts) / len(rts)) if rts else None,
        "p50": percentile(rts, 50) if rts else None,
        "p95": percentile(rts, 95) if rts else None,
        "p99": percentile(rts, 99) if rts else None,
        "status": {str(k): v for k, v in sorted(status_counts.items())},
        "methods": dict(method_counts.most_common()),
        "top_paths": path_rows(path_stats.items(), top),
        "slowest": slowest,
        "errors": err_rows[:top],
        "top_ips": [{"ip": ip, "hits": n} for ip, n in ip_counts.most_common(top)],
        "top_user_agents": [{"ua": ua, "hits": n, "bot": is_bot(ua)} for ua, n in ua_counts.most_common(top)],
        "top_referers": [{"referer": r, "hits": n} for r, n in ref_counts.most_common(top)],
        "bot_hits": bot_hits,
        "histogram": hist,
        "has_request_time": bool(rts),
    }


def build_histogram(times: List[datetime], tz) -> List[Dict[str, Any]]:
    if not times:
        return []
    start, end = min(times), max(times)
    span = max((end - start).total_seconds(), 1.0)
    if span <= 30 * 60:
        step = 5 * 60
        fmt = "%H:%M"
    elif span <= 2 * 86400:
        step = 3600
        fmt = "%m-%d %H:00"
    else:
        step = 86400
        fmt = "%Y-%m-%d"

    # align buckets in display timezone
    local_times = [t.astimezone(tz) for t in times]
    buckets: Counter = Counter()
    labels_order: List[str] = []

    def bucket_key(dt: datetime) -> Tuple[str, datetime]:
        if step == 86400:
            aligned = dt.replace(hour=0, minute=0, second=0, microsecond=0)
        elif step == 3600:
            aligned = dt.replace(minute=0, second=0, microsecond=0)
        else:
            minute = (dt.minute // 5) * 5
            aligned = dt.replace(minute=minute, second=0, microsecond=0)
        return aligned.strftime(fmt), aligned

    aligned_set = {}
    for dt in local_times:
        label, aligned = bucket_key(dt)
        buckets[label] += 1
        aligned_set[label] = aligned

    if not aligned_set:
        return []
    first = min(aligned_set.values())
    last = max(aligned_set.values())
    cur = first
    # cap bucket count
    max_buckets = 48
    guessed = int(span / step) + 1
    if guessed > max_buckets and step < 86400:
        # fall back to coarser already handled by span; just cap display
        pass
    while cur <= last and len(labels_order) < 64:
        label = cur.strftime(fmt)
        labels_order.append(label)
        if step == 86400:
            cur = cur + timedelta(days=1)
        else:
            cur = cur + timedelta(seconds=step)
        # dst / uniqueness
        if labels_order and labels_order[-1] == label and cur <= last and label in buckets:
            pass

    # unique preserve
    seen = set()
    uniq = []
    for lab in labels_order:
        if lab in seen:
            continue
        seen.add(lab)
        uniq.append(lab)
    return [{"bucket": lab, "hits": buckets[lab]} for lab in uniq if buckets.get(lab, 0)]


def render_text(summary: Dict[str, Any]) -> str:
    lines: List[str] = []
    sources = summary["sources"]
    src = sources[0] if len(sources) == 1 else "%d files" % len(sources)
    if len(sources) > 1:
        src += " (" + ", ".join(sources[:5]) + (", ..." if len(sources) > 5 else "") + ")"
    lines.append("Source:     %s" % src)
    shown = summary["requests"]
    parsed = summary["parsed"]
    skipped = summary["skipped"]
    if shown != parsed:
        lines.append(
            "Lines:      parsed %d   shown %d   skipped %d" % (parsed, shown, skipped)
        )
    else:
        lines.append("Lines:      parsed %d   skipped %d" % (parsed, skipped))
    if summary["range_start"]:
        span = summary.get("span_seconds")
        span_s = ""
        if span is not None:
            span_s = "  (%s)" % format_duration(span)
        lines.append("Range:      %s  →  %s%s" % (summary["range_start"], summary["range_end"], span_s))
    else:
        lines.append("Range:      (no timestamps)")
    lines.append("Requests:   %d" % summary["requests"])
    lines.append("Bytes:      %s" % format_bytes(summary["bytes"]))
    if summary["has_request_time"]:
        lines.append(
            "Time:       avg %s   p50 %s   p95 %s   p99 %s"
            % (
                format_duration(summary["avg_time"]),
                format_duration(summary["p50"]),
                format_duration(summary["p95"]),
                format_duration(summary["p99"]),
            )
        )
    if summary["requests"] and summary.get("bot_hits"):
        pct = 100.0 * summary["bot_hits"] / summary["requests"]
        lines.append("Bots:       %d  (%.1f%% of requests, by User-Agent keyword)" % (summary["bot_hits"], pct))

    status = summary["status"]
    if status:
        lines.append("")
        lines.append("Status")
        total = summary["requests"] or 1
        for code, n in status.items():
            pct = 100.0 * n / total
            lines.append("  %-4s %6d  %-16s  %5.1f%%" % (code, n, bar(n, total), pct))

    methods = summary["methods"]
    if methods:
        lines.append("")
        lines.append("Methods")
        for name, n in methods.items():
            lines.append("  %-6s %6d" % (name, n))

    if summary["top_paths"]:
        lines.append("")
        lines.append("Top paths")
        has_t = any(r["avg_time"] is not None for r in summary["top_paths"])
        if has_t:
            lines.append("    hits      bytes    avg  path")
        else:
            lines.append("    hits      bytes  path")
        for r in summary["top_paths"]:
            if has_t:
                lines.append(
                    "  %7d  %10s  %6s  %s"
                    % (r["hits"], format_bytes(r["bytes"]), format_duration(r["avg_time"]), r["path"])
                )
            else:
                lines.append(
                    "  %7d  %10s  %s" % (r["hits"], format_bytes(r["bytes"]), r["path"])
                )

    if summary["slowest"]:
        lines.append("")
        lines.append("Slowest")
        for r in summary["slowest"]:
            lines.append(
                "  %7s  %3s  %-4s  %s  %s"
                % (
                    format_duration(r["request_time"]),
                    r["status"] if r["status"] is not None else "-",
                    r["method"] or "-",
                    r["path"],
                    r["ip"] or "",
                )
            )

    if summary["errors"]:
        lines.append("")
        lines.append("4xx / 5xx paths")
        for r in summary["errors"]:
            detail = ", ".join("%s×%s" % (v, k) for k, v in r["statuses"].items())
            lines.append("  %7d  %s  (%s)" % (r["hits"], r["path"], detail))

    if summary["top_ips"]:
        lines.append("")
        lines.append("Top clients")
        for r in summary["top_ips"]:
            lines.append("  %7d  %s" % (r["hits"], r["ip"]))

    if summary["top_user_agents"]:
        lines.append("")
        lines.append("Top User-Agents")
        for r in summary["top_user_agents"]:
            tag = "  [bot]" if r["bot"] else ""
            lines.append("  %7d  %s%s" % (r["hits"], short_ua(r["ua"]), tag))

    if summary["top_referers"]:
        lines.append("")
        lines.append("Top referers")
        for r in summary["top_referers"]:
            lines.append("  %7d  %s" % (r["hits"], r["referer"]))

    hist = summary.get("histogram") or []
    if hist and any(b["hits"] for b in hist):
        lines.append("")
        lines.append("Traffic")
        peak = max(b["hits"] for b in hist) or 1
        width = 24
        for b in hist:
            # skip empty buckets at a long tail? keep all for continuity but maybe collapse
            marks = "█" * int(round(width * b["hits"] / float(peak))) if b["hits"] else ""
            lines.append("  %-14s %6d  %s" % (b["bucket"], b["hits"], marks))

    if summary["warnings"]:
        lines.append("")
        lines.append("Warnings")
        for w in summary["warnings"]:
            lines.append("  - %s" % w)
    return "\n".join(lines) + "\n"


def json_ready(summary: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(summary)
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="access-sum",
        description="Summarize HTTP access logs locally (Combined / Common / Nginx timed / JSON lines).",
    )
    p.add_argument("paths", nargs="*", help="log files, or - for stdin (default: stdin)")
    p.add_argument("--top", type=int, default=10, help="how many rows in top/slowest lists (default 10)")
    p.add_argument(
        "--normalize",
        action="store_true",
        help="group paths by replacing numeric / UUID / long hex segments with :id",
    )
    p.add_argument(
        "--keep-query",
        action="store_true",
        help="keep query strings in path grouping (default: strip them)",
    )
    p.add_argument("--since", metavar="TIME", help="only entries at or after this time (ISO, Apache, or epoch)")
    p.add_argument("--until", metavar="TIME", help="only entries at or before this time")
    p.add_argument("--status", metavar="LIST", help="filter by status, comma-separated (200,404,5xx)")
    p.add_argument("--method", metavar="LIST", help="filter by method, comma-separated (GET,POST)")
    p.add_argument("--tz", default="UTC", help="display timezone (UTC, +0800, or IANA such as Asia/Shanghai)")
    p.add_argument("--json", action="store_true", dest="as_json", help="machine-readable JSON")
    p.add_argument(
        "--strict",
        action="store_true",
        help="exit 1 if any line could not be parsed, or a file could not be read",
    )
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.top < 1:
        parser.error("--top must be >= 1")
    since = parse_cli_time(args.since) if args.since else None
    if args.since and since is None:
        parser.error("cannot parse --since %r" % args.since)
    until = parse_cli_time(args.until) if args.until else None
    if args.until and until is None:
        parser.error("cannot parse --until %r" % args.until)
    if since and until and since > until:
        parser.error("--since is after --until")
    try:
        tz = load_timezone(args.tz)
    except argparse.ArgumentTypeError as exc:
        parser.error(str(exc))
        return USAGE_EXIT

    paths = list(args.paths)
    if not paths and sys.stdin.isatty():
        parser.print_help()
        return USAGE_EXIT

    report = load_reports(
        paths,
        normalize=args.normalize,
        keep_query=args.keep_query,
        since=since,
        until=until,
        statuses=parse_csv_list(args.status),
        methods=parse_csv_list(args.method),
    )
    summary = summarize(report, normalize=args.normalize, keep_query=args.keep_query, top=args.top, tz=tz)
    if args.as_json:
        sys.stdout.write(json.dumps(json_ready(summary), ensure_ascii=False, indent=2) + "\n")
    else:
        sys.stdout.write(render_text(summary))

    if args.strict and (report.skipped or any("cannot read" in w for w in report.warnings)):
        return FAIL_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main())
