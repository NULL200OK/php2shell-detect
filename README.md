# php2shell-detect

### Defensive Detector + Bounded Offensive Impact-Evidence Builder for CVE-2026-109618 / CVE-2026-109619 ("PHP2Shell")

<p align="center">
  <strong>v3.4</strong> &nbsp;•&nbsp;
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
**offensive layer** is available behind a double opt-in (`--i-own-this-target`
+ `--enable-offensive`) for operators who need to prove concrete attacker
impact on infrastructure they own or are authorized to test.

**What this tool IS:**
- A defender's triage kit for "is my PHP vulnerable?"
- A blue-team evidence-gathering tool for incident response
- A patch-validation tool (run before/after upgrade)
- A bounded impact-proof tool for authorized penetration tests
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

**Impact chain:**
1. **Availability** — repeated crashes = bounded DoS
2. **Integrity** — attacker-controlled marker persists in session files
3. **Confidentiality** — marker from session A can appear in session B (cross-session leak)
4. **Code Execution** (in some configs) — session file is includable via LFI / path-traversal sinks, or extension checks fail during the corrupted window

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
│  → "What real-world attacker capability does this unlock?"  │
└─────────────────────────────────────────────────────────────┘
```

The offensive layer is **bounded**:
- It plants a **random marker string** (never PHP code)
- It only reads back **its own marker** (never system files)
- It never installs persistent backdoors
- It never executes remote commands
- It never pivots to other hosts

---

## Safe Versions Table

| PHP Branch | First Patched Version |
|------------|----------------------|
| 8.5.x      | **8.5.12**           |
| 8.4.x      | **8.4.27**           |
| 8.3.x      | **8.3.36**           |
| 8.2.x      | **8.2.35**           |
| < 8.2      | not supported — upgrade immediately |

The tool's `verdict()` function compares the detected version against this
table. Versions below the branch minimum are reported as `vulnerable`.

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
- Works on Linux, macOS, and WSL
- Optional for local modes: `php` / `php-fpm` binaries in `PATH`, `pgrep`, `rpm`

Verify your environment:

```bash
python3 --version        # must be >= 3.8
python3 -c "import ssl; print(ssl.OPENSSL_VERSION)"
```

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

### 5. Full defensive + offensive impact proof (authorized pentest)

```bash
python3 php2shell-detect.py -t http://lab.local --profile full+offensive \
  --i-own-this-target --enable-offensive \
  --rounds 30 --workers 8 \
  --evidence-bundle ./evidence-2026-10-21 \
  --impact-report ./impact.md
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

```bash
python3 php2shell-detect.py --mode remote -t https://example.com --probe-phpinfo
```

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

Reports inconsistent version disclosures (e.g. header says 8.3.30 but
phpinfo body says 8.3.28 — a sign of a reverse-proxy version-masking
misconfiguration).

### `local`
Scans the local host for:
- PHP binaries in `PATH` (`php`, `php8.x`, `php-fpm8.x`)
- Running `php-fpm` workers via `pgrep`
- Debian/Ubuntu changelogs in `/usr/share/doc/php*/changelog.*.gz` (CVE mentions)
- RPM changelogs via `rpm -q --changelog`

### `logs`
Parses Apache/nginx access logs (Common Log Format) for:
- `Allowed memory size of N bytes exhausted` (OOM)
- `use-after-free`, `heap-buffer`, `segmentation fault`, `zend_mm_heap corrupted`, `double free` (UAF/corruption)
- `Maximum execution time` (timeout)
- POST requests returning 5xx, grouped by client IP

Flags IPs that exceed `--post-500-threshold` (default: 5) POST-5xx as suspicious.

### `audit`
Scans audit/sensor logs for `Content-Disposition: form-data; ... filename=""`
entries — the **golden indicator** of CVE-2026-109618 exploitation attempts.
Flags as `vulnerable` when count exceeds `--empty-parts-threshold` (default: 3).

### `asan`
Parses AddressSanitizer report files. Extracts:
- Error type (`heap-use-after-free`, `heap-buffer-overflow`, `double-free`, etc.)
- Stack frames (up to 15)

```bash
python3 php2shell-detect.py --mode asan --asan-files /tmp/asan.1234,/tmp/asan.5678
```

### `error-signature`
Classifies log entries into 6 categories (`oom`, `uaf`, `heap_corrupt`,
`segfault`, `invalid_ptr`, `double_free`) and builds **temporal correlations**:
if the same client IP emits errors from two different categories within a
30-line window, that's a strong signal of successful exploitation.

### `differential`
Compares two targets (e.g. patched vs unpatched) across 5 probes and reports
differences in status code, body hash, and `X-Powered-By`. Useful for
validating that a patch actually changed behavior.

```bash
python3 php2shell-detect.py --mode differential \
  -t http://vuln.lab.local --target-b http://patched.lab.local
```

### `ioc`
Walks a directory tree and flags:
- Filenames matching webshell patterns (`shell.php`, `c99.php`, `wso.php`,
  `b374k.php`, `alfa.php`, etc.)
- PHP files whose first 8KB contain `eval(base64_decode(...))`,
  `eval(gzinflate(...))`, `eval(str_rot13(...))`, or
  `eval($_POST/GET/REQUEST[...])`

```bash
python3 php2shell-detect.py --mode ioc --ioc-dir /var/www/html --ioc-max-files 500000
```

---

## Impact Modes (Active, Lab-Only)

These modes send multipart POST payloads that trigger the crash primitive.
They require `--i-own-this-target`. They are **concurrent** (configurable
with `--workers`).

### `lab-verify`
Sends `--rounds` POST requests, each containing `--fields` empty-filename
multipart parts. Counts crashes (5xx / connection reset / timeout).

- ≥2 crashes → `vulnerable`
- 1 crash → `unknown`
- 0 crashes → `safe`

Supports `--dry-run` to preview without sending.

### `crash-repro`
Like `lab-verify` but records a per-round signature (`status:error:elapsed`)
for forensic comparison across runs.

### `impact-session-write`
Plants a marker via `PHP_SESSION_UPLOAD_PROGRESS`, then checks a server-side
session file (`--session-file`) for the marker. Proves the write primitive.

### `impact-session-poison`
Three-step chain: establish session → poison with marker + crash trigger →
read back. If marker is reflected, integrity impact is confirmed.

### `impact-worker-leak`
Writes a marker into session A, then reads session B (different SID). If the
marker appears in B's response, cross-session memory leak is confirmed —
the most severe confidentiality impact.

### `impact-bounded-dos`
20+ concurrent crash requests, then waits up to 30s for recovery. Reports
`crash_rate_pct`, `median_response_s`, `recovered_after_s`.

### `impact-memory-disclosure`
Triggers crash responses and scans response bodies for memory-disclosure
patterns (NULL bytes, pointers, Zend internals, session IDs from other
users). Reports pattern counts only — never raw leaked content.

---

## Offensive Modes (Bounded, Double Opt-In)

These modes prove concrete attacker capabilities. They are gated behind
**both** `--i-own-this-target` **and** `--enable-offensive`. Either flag
alone is insufficient — the mode will be skipped.

> ⚠️ **BOUNDED BY DESIGN**
>
> These modes plant a **random marker string** and try to read it back.
> They do **NOT** execute remote commands, drop webshells, read
> `/etc/passwd`, exfiltrate user data, or pivot to other hosts.

### `offensive-session-lfi`
**Proves:** the write primitive (planted marker) is reachable via file-include
sinks, turning it into a read primitive.

**How:**
1. Plant a marker in a session file via the crash primitive
2. Try common LFI parameter names (`include`, `page`, `file`, `path`,
   `template`, `doc`, `view`, `load`, `module`) pointing at the session
   file path (`/tmp/sess_<sid>`, `/var/lib/php/sessions/sess_<sid>`)
3. If the marker appears in any response, the read primitive is confirmed

**Real-world implication:** an attacker can include attacker-controlled
session files into PHP execution context. Combined with PHP filter wrappers
(`php://filter/...`), this is a known RCE vector.

```bash
python3 php2shell-detect.py --mode offensive-session-lfi \
  -t http://lab.local --i-own-this-target --enable-offensive \
  --include-params "include,page,file,template,src"
```

### `offensive-session-traversal`
**Proves:** the planted marker is reachable via path-traversal on download
/ file-serving endpoints, expanding the attack surface beyond LFI sinks.

**How:**
1. Plant marker via crash primitive
2. Probe endpoints (`/download.php`, `/file.php`, `/getfile.php`, `/fetch.php`,
   `/files.php`, `/read.php`, `/index.php`) with parameters
   (`file`, `name`, `path`, `f`, `id`, `doc`, `src`)
3. Use traversal prefixes (`../` repeated 1-7 times) pointing at the session file
4. If marker appears, secondary read vector confirmed

**Bounded:** only points at our own session file, never at `/etc/passwd`,
config files, or other sensitive paths.

```bash
python3 php2shell-detect.py --mode offensive-session-traversal \
  -t http://lab.local --i-own-this-target --enable-offensive \
  --docroot-guesses "/download.php,/file.php,/getfile.php"
```

### `offensive-upload-bypass-verify`
**Proves:** file-upload extension validation can be bypassed during the
corrupted window — a direct code-execution impact vector.

**How:**
1. Fire the crash primitive and a benign `.php` upload **near-simultaneously**
   (race the corrupted window)
2. The uploaded probe contains **only** `<?php echo '<marker>'; phpinfo(); ?>`
   — no backdoor, no command execution
3. After successful upload (2xx), fetch the probe at common upload paths
   (`/uploads/`, `/files/`, `/upload/`, `/`)
4. If the marker is visible, the probe was uploaded **and executed** —
   code-execution impact confirmed

**Bounded:** the probe is a `phpinfo()` call with a random marker. The
operator must manually delete the probe file after testing.

```bash
python3 php2shell-detect.py --mode offensive-upload-bypass-verify \
  -t http://lab.local --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php --rounds 20 --workers 8
```

> 🧹 **Cleanup reminder:** if the probe lands, delete it:
> ```bash
> rm /var/www/html/uploads/php2shell_probe_*.php
> ```

### `offensive-race-poison-confirm`
**Proves:** the crash primitive defeats `session.upload_progress.cleanup`,
making poisoned session content persistent — a stepping stone toward
LFI → RCE chains.

**How:**
1. Fire 50+ concurrent plant+crash requests, each writing a marker via
   `PHP_SESSION_UPLOAD_PROGRESS`
2. After all requests complete, scan the local session directories
   (`/tmp`, `/var/lib/php/sessions`, `/var/lib/php`) for any `sess_*` file
   containing the marker
3. If the marker survived cleanup, the race was won

**Bounded:** only checks if **our own** marker is present in any `sess_*`
file. Does not read content of session files belonging to other users.

```bash
python3 php2shell-detect.py --mode offensive-race-poison-confirm \
  -t http://lab.local --i-own-this-target --enable-offensive \
  --rounds 100 --workers 16
```

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
| `offensive` | All 4 offensive modes | Authorized impact proof |
| `full` | All defensive + all impact | Most comprehensive non-offensive |
| `full+offensive` | Everything | Maximum coverage (double opt-in required) |
| `local-only` | `local`, `logs`, `audit`, `asan`, `error-signature` | Server self-scan, no target needed |

```bash
# List available profiles
python3 php2shell-detect.py --help | grep -A2 profile
```

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
| `--user-agent, --ua STRING` | `php2shell-detect/3.4 (+defensive triage; ...)` | Custom User-Agent |
| `--insecure, -k` | off | Disable TLS certificate verification |
| `--probe-phpinfo` | off | Probe `/phpinfo.php`, `/info.php`, `/test.php` for version |

### Local Input Options

| Flag | Description |
|------|-------------|
| `--log-files CSV` | Comma-separated access/error log paths (`--mode logs`) |
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
| `--rounds N` | `5` | Rounds for `lab-verify` / `crash-repro` |
| `--fields N` | `200` | Empty multipart parts per round |
| `--workers N` | `4` | Concurrent workers (use `1` for ASAN runs) |
| `--session-id SID` | random | PHPSESSID for `impact-session-write` |
| `--marker STRING` | random | Custom marker for session tests |
| `--session-file PATH` | — | Server-side session file to check for marker |

### Offensive-Specific Options

| Flag | Description |
|------|-------------|
| `--upload-endpoint PATH` | Upload endpoint for `offensive-upload-bypass-verify` (e.g. `/upload.php`) |
| `--include-params CSV` | Custom LFI parameter names for `offensive-session-lfi` (default: `include,page,file,path,template,doc,view,load,module`) |
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

**Session write primitive proof (requires server-side file access):**
```bash
python3 php2shell-detect.py -t http://lab.local --mode impact-session-write \
  --i-own-this-target \
  --session-file /var/lib/php/sessions/sess_<PHPSESSID> \
  -o session-write.json
```

### Offensive Impact Proof (requires double opt-in)

**LFI read primitive proof:**
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

**Upload bypass → code execution proof:**
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

**Full offensive profile (all 4 modes):**
```bash
python3 php2shell-detect.py -t http://lab.local --profile offensive \
  --i-own-this-target --enable-offensive \
  --upload-endpoint /upload.php \
  --rounds 30 --workers 8 \
  --evidence-bundle ./offensive-evidence \
  --impact-report ./offensive-impact.md
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

**JSON output for parsing:**
```bash
python3 php2shell-detect.py --local --json | \
  jq '.summary | {final_verdict, severity, confidence}'
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
Machine-readable, suitable for SIEM ingestion or CI/CD parsing:

```json
{
  "tool": "php2shell-detect",
  "version": "3.4",
  "generated_at": "2026-10-21T20:24:15Z",
  "meta": { "target": "...", "profile": "...", "offensive_enabled": false },
  "summary": {
    "final_verdict": "vulnerable",
    "severity": "critical",
    "confidence": 0.85,
    "total_modes": 5,
    "verdicts": { "vulnerable": 2, "unknown": 1, "safe": 2 },
    "vulnerable_modes": ["impact-session-poison", "offensive-session-lfi"]
  },
  "evidence_chain": [
    { "label": "remote", "verdict": "vulnerable", "detail": "PHP 8.3.30" },
    ...
  ],
  "results": [ ... ]
}
```

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
availability, memory-corruption, offensive proofs).

### stdout JSON (`--json`)
Prints the full JSON report to stdout, suppressing human-readable output.
Useful for piping to `jq` or another tool.

---

## ASAN Reproduction Guide

The tool can generate a complete guide for reproducing the memory-corruption
proof under AddressSanitizer:

```bash
python3 php2shell-detect.py --mode generate-asan-repro --asan-outdir ./asan-guide
```

This writes `./asan-guide/asan-repro.md` with:
1. Building PHP from source with `-fsanitize=address`
2. Starting a sandboxed PHP CGI server with ASAN
3. Sending the crash trigger (using this tool's `--mode lab-verify`)
4. Reading and interpreting the ASAN report
5. Triaging the stack trace to identify the vulnerable function
6. Confirming CVE-2026-109619 (cross-session leak)
7. Patching and re-verifying

> 💡 When running `--mode lab-verify` against an ASAN build, always use
> `--workers 1` — concurrent requests hide the single-threaded bug location
> in the stack trace.

---

## Ethical Use & Legal

### Authorization

- **Passive modes** (`remote`, `surface`, `deep-fingerprint`, `local`,
  `logs`, `audit`, `asan`, `error-signature`, `differential`, `ioc`):
  These send only standard GET/HEAD requests or read local files. They are
  generally safe to run against any target, but always respect the target's
  `robots.txt`, ToS, and local laws.

- **Impact modes** (`lab-verify`, `crash-repro`, `impact-*`): These send
  multipart POST payloads that can crash PHP workers. **Only run against
  infrastructure you own or have explicit written authorization to test.**
  The `--i-own-this-target` flag is required.

- **Offensive modes** (`offensive-*`): These prove concrete attacker
  capabilities. **Only run against infrastructure you own or have explicit
  written authorization to test.** Both `--i-own-this-target` AND
  `--enable-offensive` are required (double opt-in).

### What the offensive modes will NOT do

- ❌ Execute remote commands (`system()`, `shell_exec()`, `passthru()`, etc.)
- ❌ Drop persistent backdoors or webshells
- ❌ Read system files (`/etc/passwd`, config files, etc.)
- ❌ Exfiltrate user data, credentials, or session content from other users
- ❌ Pivot to other hosts on the network
- ❌ Anything beyond planting and reading back a random marker string

The uploaded probe in `offensive-upload-bypass-verify` contains only
`<?php echo '<marker>'; phpinfo(); ?>` — no backdoor, no command execution.
The operator is responsible for deleting the probe file after testing.

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
- The defensive security community for feedback on detection patterns

---

<p align="center">
  <sub>Built by <a href="https://github.com/NULL200OK">NULL200OK</a> — stay defensive, stay authorized.</sub>
</p>
