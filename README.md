# php2shell-detect

### Defensive Detector + Bounded Offensive Impact-Evidence Builder for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

<p align="center">
  <strong>v3.5</strong> &nbsp;•&nbsp;
  <strong>Python 3.8+</strong> &nbsp;•&nbsp;
  <strong>Zero dependencies</strong> &nbsp;•&nbsp;
  <strong>MIT License</strong>
</p>

---

## Table of Contents

- [Overview](#overview)
- [The PHP2Shell Vulnerabilities](#the-php2shell-vulnerabilities)
- [Design Philosophy: Defensive-First, Bounded Offensive](#design-philosophy-defensive-first-bounded-offensive)
- [Safe Versions Table](#safe-versions-table)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Detection Modes (Passive / Defensive)](#detection-modes-passive--defensive)
- [Impact Modes (Active, Lab-Only)](#impact-modes-active-lab-only)
- [Offensive Modes (Bounded, Double Opt-In)](#offensive-modes-bounded-double-opt-in)
- [Offensive RCE Modes (Proves Code Execution)](#offensive-rce-modes-proves-code-execution)
- [Profiles](#profiles)
- [Complete CLI Reference](#complete-cli-reference)
- [Usage Examples](#usage-examples)
- [Exit Codes for CI/CD](#exit-codes-for-cicd)
- [Output Formats](#output-formats)
- [ASAN Reproduction Guide](#asan-reproduction-guide)
- [Ethical Use & Legal](#ethical-use--legal)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`php2shell-detect` is a single-file Python tool that triages, proves, and
documents the impact of two related PHP memory-corruption vulnerabilities
in the multipart form-data parser (`main/rfc1867.c`) and the session
upload-progress handler (`ext/session/session_upload_progress.c`).

The tool is **defensive-first**: the default profile runs only passive
checks that never send a single byte of payload to the target. A bounded
**offensive layer** (v3.4) and a **bounded RCE-proof layer** (v3.5) are
available behind a double opt-in (`--i-own-this-target` +
`--enable-offensive`) for operators who need to prove concrete attacker
impact — up to and including code execution — on infrastructure they own
or are authorized to test.

**What this tool IS:**
- A defender's triage kit for "is my PHP vulnerable?"
- A blue-team evidence-gathering tool for incident response
- A patch-validation tool (run before/after upgrade)
- A bounded impact-proof tool for authorized penetration tests (up to RCE proof)
- A CI/CD gate (deterministic exit codes, JSON output)

**What this tool is NOT:**
- A weaponized exploit
- A webshell dropper
- A credential exfiltrator
- A lateral-movement framework

---

## The PHP2Shell Vulnerabilities

| CVE | CVSS | Component | Bug Class |
|-----|------|-----------|-----------|
| **CVE-2026-109618** | 9.2 | `main/rfc1867.c` multipart parser | heap-use-after-free / OOM when many empty-filename parts are sent |
| **CVE-2026-109619** | 9.2 | `ext/session/session_upload_progress.c` | session file poisoning + cross-session leak triggered by the crash primitive |

**Crash trigger:** a multipart POST containing many parts with
`filename=""` (empty filename). The parser allocates per-part state but
the cleanup path can free the same pointer twice, or the session upload
progress handler writes attacker-controlled data into the wrong session
file when the worker crashes mid-request.

**Impact chain (v3.5 covers all 5 levels):**
1. **Availability** — repeated crashes = bounded DoS
2. **Integrity** — attacker-controlled marker persists in session files
3. **Confidentiality** — marker from session A can appear in session B (cross-session leak)
4. **Code Execution (read primitive)** — session file is includable via LFI / path-traversal sinks
5. **Code Execution (RCE proof)** — planted PHP code actually executes; filter-chain / phar / tmpfile / log-poisoning RCE vectors confirmed

---

## Design Philosophy: Defensive-First, Bounded Offensive

```
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1 — Passive Detection (default, no payloads)         │
│  remote / surface / deep-fingerprint / local /              │
│  logs / audit / asan / error-signature / differential / ioc │
│  → "Is the target vulnerable?"                              │
├─────────────────────────────────────────────────────────────┤
│  LAYER 2 — Active Lab Verification (--i-own-this-target)    │
│  lab-verify / crash-repro / impact-session-write /          │
│  impact-session-poison / impact-worker-leak /               │
│  impact-bounded-dos / impact-memory-disclosure              │
│  → "Does the crash primitive actually fire?"                │
├─────────────────────────────────────────────────────────────┤
│  LAYER 3 — Bounded Offensive (+ --enable-offensive)         │
│  offensive-session-lfi / offensive-session-traversal /      │
│  offensive-upload-bypass-verify / offensive-race-poison     │
│  → "What read primitive does the attacker get?"             │
├─────────────────────────────────────────────────────────────┤
│  LAYER 4 — Bounded RCE Proof (+ --enable-offensive) [v3.5]  │
│  offensive-phpcode-exec-proof / offensive-filter-chain-rce  │
│  offensive-phar-deserialization / offensive-tmpfile-race    │
│  offensive-log-poisoning                                    │
│  → "Can the attacker actually execute PHP code?"            │
└─────────────────────────────────────────────────────────────┘
```

All offensive and RCE-proof layers are **bounded**:
- They plant a **random marker string** or `<?php echo 'MARKER'; ?>` ONLY
- They never call `system()`, `exec()`, `shell_exec()`, `passthru()`, `file_put_contents()`, or any dangerous function
- They never install persistent backdoors
- They never execute remote commands
- They never pivot to other hosts

---

## Safe Versions Table

| PHP Branch | First Patched Version |
|------------|----------------------|
| 8.5.x      | **8.5.12**           |
| 8.4.x      | **8.4.27**           |
| 8.3.x      | **8.3.36**           |
| 8.2.x      | **8.2.35**           |
| < 8.2      | not supported — upgrade immediately |

---

## Installation

### Option 1: Direct download (zero install)

```bash
curl -O https://raw.githubusercontent.com/NULL200OK/php2shell-detect/main/php2shell-detect.py
chmod +x php2shell-detect.py
./php2shell-detect.py --version
```

### Option 2: Clone the repository

```bash
git clone https://github.com/NULL200OK/php2shell-detect.git
cd php2shell-detect
python3 php2shell-detect.py --version
```

### Requirements

- **Python 3.8+** (uses only the standard library — no pip install needed)
- Optional for `offensive-phar-deserialization`: `php` CLI in `PATH` (for phar generation)
- Works on Linux, macOS, and WSL

---

## Quick Start

### 1. Quick remote triage (passive, no payload)

```bash
python3 php2shell-detect.py -t https://example.com --profile quick
```

### 2. Standard triage (passive, includes local + logs)

```bash
python3 php2shell-detect.py -t https://example.com --profile standard \
  --log-files /var/log/nginx/access.log,/var/log/php/error.log
```

### 3. Local-only scan on a PHP server you administer

```bash
python3 php2shell-detect.py --local \
  --log-files /var/log/nginx/access.log \
  --audit-file /var/log/nginx/audit.log \
  --output local-report.json --markdown local-report.md
```

### 4. Lab impact proof (you own the target)

```bash
python3 php2shell-detect.py -t http://lab.local --profile impact \
  --i-own-this-target --rounds 10 --workers 8 \
  --output impact.json --markdown impact.md
```

### 5. Bounded offensive read-primitive proof (authorized pentest)

```bash
python3 php2shell-detect.py -t http://lab.local --profile offensive \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --evidence-bundle ./evidence
```

### 6. Full RCE proof (authorized pentest, maximum impact proof) — NEW in v3.5

```bash
python3 php2shell-detect.py -t http://lab.local --profile offensive-rce \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --include-params "include,page,file,template,src,doc" \
  --rounds 30 --workers 8 \
  --evidence-bundle ./rce-evidence \
  --impact-report ./rce-impact.md
```

---

## Detection Modes (Passive / Defensive)

These modes send **only standard HTTP GET/HEAD requests** (or read local
files). They never send multipart POST payloads. Safe to run against any
target without authorization concerns.

### `remote`
Fetches the target URL and extracts the PHP version from:
- `X-Powered-By` header (`PHP/x.y.z`)
- `Server` header
- `PHPSESSID` cookie presence (confirms PHP is in use)
- `phpinfo()`-style output in the response body
- Optionally probes `/phpinfo.php`, `/info.php`, `/test.php` with `--probe-phpinfo`

Automatic HTTPS → HTTP fallback if TLS fails.

### `surface`
Crawls `/`, `/contact.php`, `/contact`, `/upload.php`, `/upload` looking for:
- `<form enctype="multipart/form-data">` forms
- `<input type="file">` fields
- POST forms

> **Defensive insight:** the multipart parser (where CVE-2026-109618 lives)
> runs on **every** multipart submission, **before** application code. So the
> mere existence of a multipart form means the vulnerable code path is
> reachable.

### `deep-fingerprint`
Probes 17 sensitive paths for version disclosure and exposure:

```
/  /index.php  /phpinfo.php  /info.php  /test.php
/wp-login.php  /admin.php  /composer.json  /composer.lock
/.env  /Dockerfile  /docker-compose.yml  /backup.zip
/.git/HEAD  /server-status  /server-info
```

Reports inconsistent version disclosures.

### `local`
Scans the local host for:
- PHP binaries in `PATH` (`php`, `php8.x`, `php-fpm8.x`)
- Running `php-fpm` workers via `pgrep`
- Debian/Ubuntu changelogs in `/usr/share/doc/php*/changelog.*.gz`
- RPM changelogs via `rpm -q --changelog`

### `logs`
Parses Apache/nginx access logs for OOM, UAF, segfault, double-free, timeouts,
and POST-5xx grouped by client IP. Flags IPs that exceed `--post-500-threshold`.

### `audit`
Scans audit/sensor logs for `Content-Disposition: form-data; ... filename=""`
entries — the **golden indicator** of CVE-2026-109618 exploitation attempts.

### `asan`
Parses AddressSanitizer report files. Extracts error type and stack frames.

### `error-signature`
Classifies log entries into 6 categories and builds **temporal correlations**:
if the same client IP emits errors from two different categories within a
30-line window, that's a strong signal of successful exploitation.

### `differential`
Compares two targets (e.g. patched vs unpatched) across 5 probes and reports
differences in status code, body hash, and `X-Powered-By`.

### `ioc`
Walks a directory tree and flags webshell filenames and PHP files whose
first 8KB contain `eval(base64_decode(...))` and similar patterns.

---

## Impact Modes (Active, Lab-Only)

These modes send multipart POST payloads that trigger the crash primitive.
They require `--i-own-this-target`. They are **concurrent** (configurable
with `--workers`).

| Mode | Proves |
|------|--------|
| `lab-verify` | Crash primitive fires (5xx / reset / timeout) |
| `crash-repro` | Same, with per-round forensic signatures |
| `impact-session-write` | Write primitive (marker in session file) |
| `impact-session-poison` | Integrity impact (marker reflected in follow-up) |
| `impact-worker-leak` | Confidentiality impact (cross-session leak) |
| `impact-bounded-dos` | Availability impact (crash rate + recovery time) |
| `impact-memory-disclosure` | Memory disclosure patterns in crash responses |

---

## Offensive Modes (Bounded, Double Opt-In)

These modes prove concrete attacker capabilities. They are gated behind
**both** `--i-own-this-target` **and** `--enable-offensive`.

> ⚠️ **BOUNDED BY DESIGN**
>
> These modes plant a **random marker string** and try to read it back.
> They do **NOT** execute remote commands, drop webshells, read
> `/etc/passwd`, exfiltrate user data, or pivot to other hosts.

### `offensive-session-lfi` (enhanced in v3.5)
**Proves:** the write primitive (planted marker) is reachable via file-include
sinks AND via `php://filter` wrappers — proving both read primitive AND
filter-chain reachability.

**v3.5 enhancement:** now tests `php://filter/convert.base64-encode/resource=...`
and `php://filter/read=string.rot13/resource=...` in addition to plain LFI.
A hit on a filter wrapper means the Synacktiv filter-chain RCE technique
applies.

### `offensive-session-traversal`
**Proves:** the planted marker is reachable via path-traversal on download
/ file-serving endpoints, expanding the attack surface beyond LFI sinks.

### `offensive-upload-bypass-verify` (enhanced in v3.5)
**Proves:** file-upload extension validation can be bypassed during the
corrupted window — a direct code-execution impact vector.

**v3.5 enhancement:** now tests **8 extensions** (`.php`, `.phtml`, `.phar`,
`.pht`, `.php5`, `.php7`, `.php8`, `.shtml`) across 7 upload directories.
Many Apache/Nginx configs block `.php` but miss `.phtml`/`.phar`/`.pht`.

### `offensive-race-poison-confirm`
**Proves:** the crash primitive defeats `session.upload_progress.cleanup`,
making poisoned session content persistent — a stepping stone toward
LFI → RCE chains.

---

## Offensive RCE Modes (Proves Code Execution)

> 🆕 **NEW in v3.5** — These modes prove **actual PHP code execution**,
> not just file read. They are gated behind the same double opt-in
> (`--i-own-this-target` + `--enable-offensive`).

Each mode plants `<?php echo 'MARKER'; ?>` (a benign PHP snippet that ONLY
prints a marker string — no `system()`, no `file_put_contents()`, no
persistence) and tries to get PHP to execute it. If the marker appears in
a response **without** the surrounding `<?php ?>` tags, the code executed.

### `offensive-phpcode-exec-proof`
**Proves:** RCE via session file inclusion.

1. Plants `<?php echo 'RCECONFIRMED_<rand>'; ?>` in a session file via the crash primitive
2. Tries to include the session file via LFI sinks (plain + `php://filter`)
3. If marker appears WITHOUT `<?php` tags → **code executed**

**Distinguishing logic:**
- `marker present, <?php absent` → **RCE CONFIRMED** (code executed)
- `marker present, <?php present` → file read but NOT executed
- `<?php payload raw` → file not even read

### `offensive-filter-chain-rce`
**Proves:** the Synacktiv filter-chain RCE technique applies.

Tests whether `php://filter/convert.base64-encode/resource=php://input` and
`php://filter/read=string.rot13/resource=php://input` are reachable through
LFI sinks. If the base64/rot13 of our marker appears, the filter chain is
being evaluated — meaning an attacker can generate arbitrary PHP code
byte-by-byte via `convert.iconv.*` filters without needing any controllable
file on disk.

**Reference:** [Synacktiv — PHP filter chains: file read from arbitrary to RCE](https://www.synacktiv.com/en/publications/php-filter-chains-file-read-from-arbitrary-to-rce.html)

### `offensive-phar-deserialization`
**Proves:** PHAR deserialization RCE.

1. Generates a minimal `.phar` file locally (requires `php` CLI; falls back
   to a stub if unavailable) whose metadata class has a `__destruct()` method
   that echoes a marker
2. Uploads the `.phar` via the upload endpoint (racing the crash primitive)
3. Probes LFI/file sinks with `phar://` URLs pointing at the uploaded file
4. If marker appears → **`__destruct()` executed → deserialization RCE confirmed**

**Real-world implication:** an attacker can replace the echo with a gadget
chain (Monolog/RCE1, Doctrine, etc.) for arbitrary command execution.

### `offensive-tmpfile-race`
**Proves:** RCE via PHP temporary upload file race.

When PHP handles a multipart upload, it writes the uploaded file to
`/tmp/php<XXXXXX>` before moving it. If the worker crashes mid-upload
(CVE-2026-109618), the temp file may linger. An attacker can race to
include that temp file via LFI before PHP cleans it up.

This mode races the crash primitive against LFI inclusion attempts at
guessed `/tmp/php*` paths (20 guesses per round). If the planted PHP code
executes, RCE is confirmed.

**Advantage:** works even when no session file is writable — only requires
an LFI sink and the crash primitive to linger temp files.

### `offensive-log-poisoning`
**Proves:** RCE via access log poisoning + LFI.

1. Sends requests with `User-Agent: <?php echo 'LOGRCE_<rand>'; ?>` (poisons the access log)
2. Tries to include common log paths via LFI:
   - `/var/log/nginx/access.log`
   - `/var/log/apache2/access.log`
   - `/var/log/httpd/access_log`
   - `/var/log/access.log`
   - `/var/log/php/error.log`
   - `/var/log/php-fpm/error.log`
   - `/proc/self/fd/0`
3. If marker appears WITHOUT `<?php` tags → **log poisoned + executed**

**Advantage:** requires no file upload capability — only an LFI sink and a
readable log path.

---

## Profiles

A **profile** is a preset bundle of modes. Use `--profile <name>` to run
one, or `--mode mode1,mode2,...` for a custom list.

| Profile | Modes | Use Case |
|---------|-------|----------|
| `quick` | `remote`, `surface` | Fast triage, no payload |
| `standard` | + `local`, `logs`, `audit` | Default passive check |
| `deep` | + `deep-fingerprint`, `asan`, `error-signature` | Full passive investigation |
| `impact` | `lab-verify`, `crash-repro`, `impact-memory-disclosure` | Lab impact proof |
| `offensive` | 4 bounded offensive modes (read primitive) | Authorized read-impact proof |
| **`offensive-rce`** 🆕 | 5 RCE-proof modes | Authorized RCE-impact proof |
| `full` | All defensive + all impact | Most comprehensive non-offensive |
| `full+offensive` | Everything in `full` + 4 bounded offensive | + read primitive |
| **`full+rce`** 🆕 | Everything in `full+offensive` + 5 RCE-proof | Maximum coverage |
| `local-only` | `local`, `logs`, `audit`, `asan`, `error-signature` | Server self-scan, no target needed |

---

## Complete CLI Reference

### Target & Mode Selection

| Flag | Description |
|------|-------------|
| `-t, --target URL` | Target URL (e.g. `https://example.com`) |
| `--profile NAME` | Preset profile (see [Profiles](#profiles)) |
| `--mode CSV` | Comma-separated explicit mode list (overrides `--profile`) |
| `--local` | Shortcut for `--profile local-only` |
| `--target-b URL` | Second target for `--mode differential` |

### Network Options

| Flag | Default | Description |
|------|---------|-------------|
| `--timeout SECONDS` | `15.0` | Per-request timeout |
| `--user-agent, --ua STRING` | `php2shell-detect/3.5 (+defensive triage; ...)` | Custom User-Agent |
| `--insecure, -k` | off | Disable TLS certificate verification |
| `--probe-phpinfo` | off | Probe `/phpinfo.php`, `/info.php`, `/test.php` for version |

### Local Input Options

| Flag | Description |
|------|-------------|
| `--log-files CSV` | Comma-separated access/error log paths (`--mode logs`) — also reused by `offensive-log-poisoning` |
| `--audit-file PATH` | Audit/sensor log path (`--mode audit`) |
| `--asan-files CSV` | Comma-separated ASAN report paths (`--mode asan`) |
| `--signature-files CSV` | Comma-separated error log paths (`--mode error-signature`) |
| `--ioc-dir DIR` | Directory to scan for webshell IOCs (`--mode ioc`) |

### Impact / Offensive Authorization (Double Opt-In)

| Flag | Description |
|------|-------------|
| `--i-own-this-target` | **Required for impact AND offensive modes.** Confirms you own the target or have written authorization. |
| `--enable-offensive` | **Second required flag for offensive modes only.** Double opt-in: `--i-own-this-target` alone is not enough. |

### Impact / Offensive Tuning

| Flag | Default | Description |
|------|---------|-------------|
| `--rounds N` | `5` | Rounds for `lab-verify` / `crash-repro` / `offensive-tmpfile-race` |
| `--fields N` | `200` | Empty multipart parts per round |
| `--workers N` | `4` | Concurrent workers (use `1` for ASAN runs) |
| `--session-id SID` | random | PHPSESSID for `impact-session-write` |
| `--marker STRING` | random | Custom marker for session tests |
| `--session-file PATH` | — | Server-side session file to check for marker |

### Offensive-Specific Options

| Flag | Description |
|------|-------------|
| `--upload-endpoint PATH` | Upload endpoint for `offensive-upload-bypass-verify` and `offensive-phar-deserialization` (e.g. `/upload.php`) |
| `--include-params CSV` | Custom LFI parameter names for all offensive-* modes (default: `include,page,file,path,template,doc,view,load,module`) |
| `--docroot-guesses CSV` | Custom file endpoints for `offensive-session-traversal` (default: `/download.php,/file.php,/getfile.php,/fetch.php,/index.php,/files.php,/read.php`) |

### Thresholds

| Flag | Default | Description |
|------|---------|-------------|
| `--max-log-lines N` | `500000` | Max lines per log file |
| `--post-500-threshold N` | `5` | POST-5xx count to flag IP as suspicious |
| `--empty-parts-threshold N` | `3` | Empty-filename parts to flag audit as vulnerable |
| `--ioc-max-files N` | `200000` | Max files for IOC scan |

### Output Options

| Flag | Description |
|------|-------------|
| `-o, --output PATH` | Write JSON report to file |
| `-m, --markdown PATH` | Write Markdown report to file |
| `--asan-outdir DIR` | Directory for `--mode generate-asan-repro` output |
| `--evidence-bundle DIR` | Write evidence bundle (`report.json` + `raw/` + `README.md`) |
| `--impact-report PATH` | Write dedicated impact report (Markdown) |
| `--quiet, -q` | Suppress progress/log output (still writes reports) |
| `--dry-run` | Plan only; impact modes will not send requests |
| `--json` | Print full JSON to stdout (overrides human-readable) |
| `--version` | Show version and exit |
| `-h, --help` | Show help and exit |

---

## Usage Examples

### Passive Detection (no authorization needed)

**Quick remote version check:**
```bash
python3 php2shell-detect.py -t https://example.com --profile quick
```

**Standard triage with log analysis:**
```bash
python3 php2shell-detect.py -t https://example.com --profile standard \
  --log-files /var/log/nginx/access.log,/var/log/php-fpm/error.log \
  --audit-file /var/log/nginx/audit.log \
  -o report.json -m report.md
```

**Deep fingerprint + sensitive file exposure:**
```bash
python3 php2shell-detect.py -t https://example.com --profile deep \
  --probe-phpinfo -o deep-report.json
```

**Local server self-scan:**
```bash
python3 php2shell-detect.py --local \
  --log-files /var/log/nginx/access.log \
  --audit-file /var/log/nginx/audit.log \
  --evidence-bundle ./local-evidence
```

**Webshell IOC hunt after suspected compromise:**
```bash
python3 php2shell-detect.py --mode ioc --ioc-dir /var/www/html \
  --ioc-max-files 500000 -o ioc-report.json
```

**Differential: patched vs unpatched:**
```bash
python3 php2shell-detect.py --mode differential \
  -t http://vuln.lab.local --target-b http://patched.lab.local \
  -o diff.json
```

### Impact Proof (requires `--i-own-this-target`)

**Lab crash verification:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode lab-verify \
  --i-own-this-target --rounds 10 --fields 300 --workers 8 \
  -o lab.json
```

**Dry-run preview (no requests sent):**
```bash
python3 php2shell-detect.py -t http://lab.local --mode lab-verify \
  --i-own-this-target --dry-run --rounds 5 --fields 200
```

**Full impact profile:**
```bash
python3 php2shell-detect.py -t http://lab.local --profile impact \
  --i-own-this-target --rounds 20 --workers 8 \
  --evidence-bundle ./impact-evidence \
  --impact-report ./impact.md
```

### Bounded Offensive Proof (requires double opt-in)

**LFI read primitive proof (now with php://filter support):**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-session-lfi \
  --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template,src,doc" \
  -o lfi-proof.json
```

**Path-traversal read primitive proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-session-traversal \
  --i-own-this-target --enable-offensive \
  --docroot-guesses "/download.php,/file.php,/getfile.php,/read.php" \
  -o traversal-proof.json
```

**Upload bypass → code execution proof (now tests 8 extensions):**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-upload-bypass-verify \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --rounds 30 --workers 8 \
  -o upload-bypass.json
```

**Race condition → persistent session poisoning proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-race-poison-confirm \
  --i-own-this-target --enable-offensive \
  --rounds 100 --workers 16 \
  -o race-proof.json
```

### RCE Proof (requires double opt-in) — NEW in v3.5

**Direct PHP code execution proof via session LFI:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-phpcode-exec-proof \
  --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template,src,doc" \
  -o rce-proof.json
```

**Filter-chain RCE reachability proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-filter-chain-rce \
  --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template" \
  -o filter-chain-proof.json
```

**PHAR deserialization RCE proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-phar-deserialization \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --include-params "include,page,file,template" \
  --rounds 20 --workers 8 \
  -o phar-rce-proof.json
```

**Temp file race RCE proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-tmpfile-race \
  --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template" \
  --rounds 100 --workers 16 \
  -o tmpfile-rce-proof.json
```

**Access log poisoning RCE proof:**
```bash
python3 php2shell-detect.py -t http://lab.local --mode offensive-log-poisoning \
  --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template" \
  --log-files "/var/log/nginx/access.log,/var/log/apache2/access.log" \
  -o log-rce-proof.json
```

**Full RCE profile (all 5 RCE-proof modes):**
```bash
python3 php2shell-detect.py -t http://lab.local --profile offensive-rce \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --include-params "include,page,file,template,src,doc" \
  --rounds 30 --workers 8 \
  --evidence-bundle ./rce-evidence \
  --impact-report ./rce-impact.md
```

### Full Coverage (defensive + impact + offensive + RCE)

**Maximum coverage — everything:**
```bash
python3 php2shell-detect.py -t http://lab.local --profile full+rce \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --include-params "include,page,file,template,src,doc" \
  --log-files /var/log/nginx/access.log \
  --rounds 30 --workers 8 \
  --evidence-bundle ./full-evidence \
  --impact-report ./full-impact.md
```

### CI/CD Integration

**Pipeline gate (fail build if vulnerable):**
```bash
python3 php2shell-detect.py -t https://staging.example.com --profile quick \
  --json -o ci-report.json
exit_code=$?

if [ $exit_code -eq 2 ]; then
  echo "FAILED: target is vulnerable to PHP2Shell"
  cat ci-report.json | jq '.summary'
  exit 1
elif [ $exit_code -eq 1 ]; then
  echo "WARNING: inconclusive, manual review needed"
  exit 0
else
  echo "OK: target appears safe"
  exit 0
fi
```

### Generating the ASAN Reproduction Guide

```bash
python3 php2shell-detect.py --mode generate-asan-repro \
  --asan-outdir ./asan-guide
cat ./asan-guide/asan-repro.md
```

---

## Exit Codes for CI/CD

| Code | Meaning | Action |
|------|---------|--------|
| `0` | Safe | Continue pipeline |
| `1` | Unknown / inconclusive | Manual review |
| `2` | Vulnerable | Fail pipeline, alert |
| `3` | Error (tool failure) | Investigate |

Example GitHub Actions step:

```yaml
- name: PHP2Shell triage
  run: |
    python3 php2shell-detect.py -t https://staging.example.com \
      --profile quick --json -o php2shell-report.json
    EXIT=$?
    if [ $EXIT -eq 2 ]; then
      echo "::error::Target is VULNERABLE to PHP2Shell"
      cat php2shell-report.json | jq '.summary'
      exit 1
    fi
```

---

## Output Formats

### JSON Report (`--output`)
Machine-readable, suitable for SIEM ingestion or CI/CD parsing. Includes
`summary`, `evidence_chain`, and full per-mode `results`.

### Markdown Report (`--markdown`)
Human-readable, suitable for sharing with management or attaching to tickets.

### Evidence Bundle (`--evidence-bundle`)
A directory containing:
- `report.json` — full JSON report
- `README.md` — executive summary
- `raw/<mode>.json` — per-mode raw output (one file per mode)

Ideal for incident response handoff.

### Impact Report (`--impact-report`)
Dedicated Markdown report focused on impact proofs (integrity, confidentiality,
availability, memory-corruption, offensive proofs, RCE proofs).

### stdout JSON (`--json`)
Prints the full JSON report to stdout, suppressing human-readable output.

---

## ASAN Reproduction Guide

```bash
python3 php2shell-detect.py --mode generate-asan-repro --asan-outdir ./asan-guide
```

Writes `./asan-guide/asan-repro.md` with 7 sections covering building PHP
with ASAN, sending the crash trigger, reading/interpreting ASAN reports,
and confirming CVE-2026-109619.

> 💡 When running `--mode lab-verify` against an ASAN build, always use
> `--workers 1` — concurrent requests hide the single-threaded bug location
> in the stack trace.

---

## Ethical Use & Legal

### Authorization

- **Passive modes**: send only standard GET/HEAD requests or read local
  files. Generally safe to run against any target, but always respect the
  target's `robots.txt`, ToS, and local laws.

- **Impact modes**: send multipart POST payloads that can crash PHP workers.
  **Only run against infrastructure you own or have explicit written
  authorization to test.** The `--i-own-this-target` flag is required.

- **Offensive modes** (read primitive + RCE proof): prove concrete attacker
  capabilities including code execution. **Only run against infrastructure
  you own or have explicit written authorization to test.** Both
  `--i-own-this-target` AND `--enable-offensive` are required (double opt-in).

### What the offensive/RCE modes will NOT do

- ❌ Execute remote commands (`system()`, `shell_exec()`, `passthru()`, etc.)
- ❌ Drop persistent backdoors or webshells
- ❌ Read system files (`/etc/passwd`, config files, etc.)
- ❌ Exfiltrate user data, credentials, or session content from other users
- ❌ Pivot to other hosts on the network
- ❌ Anything beyond planting `<?php echo 'MARKER'; ?>` and checking if it executed

The uploaded probe in `offensive-upload-bypass-verify` and the planted code
in `offensive-phpcode-exec-proof` / `offensive-tmpfile-race` /
`offensive-log-poisoning` contains only `<?php echo '<marker>'; ?>` — no
backdoor, no command execution. The operator is responsible for deleting
any probe files after testing:

```bash
rm /var/www/html/uploads/php2shell_probe_*.php
rm /var/www/html/uploads/php2shell_phar_*.phar
```

### Responsible Disclosure

If you discover a previously-unknown vulnerability using this tool,
disclose it responsibly to the vendor before publishing any details.

---

## Contributing

Contributions are welcome. Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes with a clear message
4. Open a pull request

**Bug reports** should include:
- Tool version (`python3 php2shell-detect.py --version`)
- Python version (`python3 --version`)
- OS and PHP version (if relevant)
- The exact command you ran
- The JSON report (`--output report.json`) with any sensitive data redacted

**Pull requests** that add new detection modes, improve accuracy, or
enhance the offensive impact proofs (within the bounded philosophy) are
especially welcome.

---

## License

MIT License — see [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2026 NULL200OK

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Acknowledgments

- The PHP Security Team for their ongoing work on the parser
- The AddressSanitizer project for the instrumentation that makes
  memory-corruption bugs reproducible
- Synacktiv for the PHP filter-chain RCE research
- The defensive security community for feedback on detection patterns

---

<p align="center">
  <sub>Built by <a href="https://github.com/NULL200OK">NULL200OK</a> — stay defensive, stay authorized.</sub>
</p>

