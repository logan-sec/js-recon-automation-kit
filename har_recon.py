#!/usr/bin/env python3
"""
har_recon.py — Full JS recon pipeline from a .har file

What it does:
  1. Extracts all JS files from the HAR
  2. Beautifies each one (jsbeautifier, falls back to prettier for large files)
  3. Runs LinkFinder on each beautified file       → lf_out.txt
  4. Runs SecretFinder on each beautified file     → sf_out.txt
  5. Runs triage pattern matching across all JS    → gf_out/

Usage:
  python3 har_recon.py <file.har> [options]

Options:
  --output DIR          Output folder (default: recon_<harname>)
  --linkfinder PATH     Path to linkfinder.py  (default: ~/LinkFinder/linkfinder.py)
  --secretfinder PATH   Path to SecretFinder.py (default: ~/SecretFinder/SecretFinder.py)
  --skip-lf             Skip LinkFinder
  --skip-sf             Skip SecretFinder
  --skip-gf             Skip gf/triage pattern matching

Output structure:
  recon_<target>/
    js/                    Beautified JS files for manual review
    lf_out.txt             LinkFinder results
    sf_out.txt             SecretFinder results
    gf_out/
      [manual review buckets - primary]
        idor.txt
        oauth_redirects.txt
        authz.txt
        secrets.txt
        high_value_endpoints.txt
        file_uploads.txt
        exports.txt
        webhooks.txt
        admin_flags.txt
      [vuln class buckets - secondary]
        ssrf.txt
        sqli.txt
        redirect.txt
        xss.txt
        rce.txt
        lfi.txt
"""

import json
import os
import re
import sys
import base64
import argparse
import subprocess
import tempfile
from urllib.parse import urlparse
from collections import defaultdict


# ── Triage pattern definitions ────────────────────────────────────────────────
# Each bucket has a list of regex patterns.
# Matches are deduplicated, annotated with filename + line number + context.

TRIAGE_BUCKETS = {
    # ── Manual review buckets (primary) ──
    "idor": [
        r'/api/.*?/\{?id\}?',
        r'[?&](id|user_id|account_id|object_id|resource_id|item_id|record_id|doc_id)=',
        r'\b(getUserById|getAccountById|fetchById|loadById|findById)\b',
        r'\.get\(["\'].*?/:id',
        r'(user|account|order|invoice|ticket|document|profile|record)\s*[=:]\s*["\']?\d+',
    ],
    "oauth_redirects": [
        r'redirect_uri\s*[=:]\s*["\']?https?://',
        r'(oauth|auth|callback|authorize|token)\s*[=:]\s*["\']?https?://',
        r'[?&](redirect|return_to|next|goto|continue|destination|url|return_url)=',
        r'\b(window\.location|location\.href|location\.replace)\s*=\s*.*?(redirect|callback|return)',
        r'response_type\s*=\s*["\']?(code|token)',
        r'(client_id|client_secret)\s*[=:]\s*["\']',
    ],
    "authz": [
        r'\b(role|permission|scope|privilege|acl|policy|access_level|is_admin|is_superuser)\b',
        r'(canRead|canWrite|canEdit|canDelete|canAccess|hasPermission|hasRole|isAuthorized|checkAccess)\s*\(',
        r'Authorization\s*:\s*["\']?(Bearer|Basic|Token)',
        r'(admin|superuser|root|moderator|staff)\s*[=:=]\s*(true|1|["\']true["\'])',
        r'\b(jwt|token|bearer|session_id|api_key)\b.*?[=:]\s*["\']',
        r'if\s*\(.*?(role|permission|admin|auth).*?\)',
    ],
    "secrets": [
        r'(api_key|apikey|api_secret|secret_key|private_key|access_key|auth_token)\s*[=:]\s*["\'][^"\']{8,}',
        r'(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}',
        r'(aws_|AWS_)(ACCESS|SECRET|TOKEN)',
        r'(sk_live|pk_live|rk_live)_[a-zA-Z0-9]+',
        r'(ghp_|github_pat_)[a-zA-Z0-9]+',
        r'-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----',
        r'(AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        r'(xox[baprs]-[0-9a-zA-Z]{10,})',
    ],
    "high_value_endpoints": [
        r'["\']/(api|v\d+|graphql|rest|internal|private|backend)/',
        r'["\']/(admin|dashboard|manage|console|control|panel|staff|superuser)/',
        r'["\']/(auth|login|logout|signin|signup|register|oauth|sso|saml)/',
        r'["\']/(payment|checkout|billing|invoice|subscription|refund|charge)/',
        r'["\']/(user|account|profile|settings|preferences|config)/',
        r'["\']/(upload|import|export|download|file|attachment|media)/',
        r'["\']/(webhook|event|notify|notification|callback)/',
        r'fetch\(["\`].*?(api|internal|admin|auth)',
        r'axios\.(get|post|put|patch|delete)\(["\`]',
        r'\$\.(get|post|ajax)\(["\`].*?(api|internal)',
    ],
    "file_uploads": [
        r'(multipart/form-data|Content-Type.*?multipart)',
        r'(file|upload|attachment|document)\s*[=:]\s*(input|FormData|File|Blob)',
        r'new\s+FormData\s*\(',
        r'\binput\s*\[.*?type\s*=\s*["\']file["\']',
        r'(\.upload|uploadFile|handleUpload|processUpload|sendFile)\s*\(',
        r'(\.pdf|\.doc|\.xls|\.csv|\.zip|\.tar|\.xml)\b',
    ],
    "exports": [
        r'(export|download|generate)\s*.*?(csv|xlsx|pdf|json|xml|report)',
        r'Content-Disposition.*?attachment',
        r'(exportData|exportReport|exportCSV|exportPDF|generateReport|downloadFile)\s*\(',
        r'["\']/(export|download|report|generate)',
        r'(Blob|createObjectURL|saveAs)\s*\(',
    ],
    "webhooks": [
        r'webhook',
        r'(ngrok|requestbin|hookbin|pipedream)',
        r'(callback_url|hook_url|endpoint_url|notify_url|postback_url)\s*[=:]\s*["\']?https?://',
        r'["\']/(webhook|hook|callback|event|notify|postback)/',
        r'(X-Webhook|X-Hook|X-Signature|X-Hub-Signature)',
    ],
    "admin_flags": [
        r'\b(is_admin|isAdmin|admin_mode|adminMode|superuser|is_superuser|isSuperuser)\s*[=:=]\s*(true|1)',
        r'(admin|staff|internal|debug|dev_mode|devMode)\s*[=:=]\s*(true|1|["\']true["\'])',
        r'["\']/(admin|staff|internal|debug|devtools|__debug__)/',
        r'(console\.log|debugger|DEBUG)\s*.*?(token|key|secret|password|auth)',
        r'feature_flag|featureFlag|flag_enabled|flagEnabled',
        r'(beta|experimental|hidden|internal|undocumented)\s*[=:]\s*(true|1)',
    ],

    # ── Vuln class buckets (secondary) ──
    "ssrf": [
        r'[?&](url|uri|path|dest|redirect|proxy|load|fetch|request|source|target|resource|host|endpoint)=https?://',
        r'(fetch|axios|http\.get|request)\s*\(.*?(req\.(query|body|params)|user_input)',
        r'(ssrf|server.side.request|internal.request)',
    ],
    "sqli": [
        r'(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|WHERE)\s+.*?\+',
        r'["\`]\s*(SELECT|INSERT|UPDATE|DELETE)\s+.*?\$\{',
        r'(query|execute|rawQuery|db\.run)\s*\(\s*["\`].*?\+',
        r'(sql|query)\s*=\s*["\`].*?(WHERE|FROM|INTO).*?\$\{',
    ],
    "redirect": [
        r'[?&](redirect|return|next|goto|continue|destination|url|return_url|back)=https?://',
        r'(window\.location|location\.href|location\.replace)\s*=\s*.*?(req\.|query\.|params\.)',
        r'res\.(redirect|location)\s*\(.*?(req\.|query\.|params\.)',
    ],
    "xss": [
        r'(innerHTML|outerHTML|document\.write|insertAdjacentHTML)\s*[=+]\s*.*?(req\.|query\.|params\.|user)',
        r'(dangerouslySetInnerHTML)\s*=\s*\{\s*\{.*?\}\s*\}',
        r'eval\s*\(.*?(req\.|query\.|params\.|user_input)',
        r'\$\s*\(\s*["\`].*?\$\{',
    ],
    "rce": [
        r'(exec|spawn|execSync|spawnSync|child_process)\s*\(.*?(req\.|query\.|params\.|user)',
        r'(eval|Function)\s*\(.*?(req\.|query\.|params\.|user_input)',
        r'(os\.system|subprocess\.call|popen)\s*\(.*?\+',
    ],
    "lfi": [
        r'(readFile|readFileSync|createReadStream|require)\s*\(.*?(req\.|query\.|params\.|user)',
        r'[?&](file|path|dir|folder|include|page|template|load|read)=\.\.',
        r'(fs\.(read|open|access)|path\.join)\s*\(.*?(req\.|query\.|params\.)',
    ],
}

# Which buckets are "manual review" vs "vuln class"
MANUAL_BUCKETS = [
    "idor", "oauth_redirects", "authz", "secrets",
    "high_value_endpoints", "file_uploads", "exports", "webhooks", "admin_flags"
]
VULN_BUCKETS = ["ssrf", "sqli", "redirect", "xss", "rce", "lfi"]


# ── Helpers ───────────────────────────────────────────────────────────────────

def sanitize_filename(name, max_len=80):
    name = re.sub(r'[<>:"/\\|?*]', '_', name)
    return name[:max_len] if len(name) > max_len else name


def is_minified(code, threshold=500):
    return any(len(line) > threshold for line in code.splitlines())


def beautify_with_prettier(content, ext=".js"):
    parser_map = {".js": "babel", ".css": "css", ".html": "html", ".json": "json"}
    parser = parser_map.get(ext, "babel")
    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
            tmp.write(content)
            tmp_path = tmp.name
        proc = subprocess.run(
            ["prettier", "--parser", parser, "--write", tmp_path],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            with open(tmp_path, "r", encoding="utf-8") as f:
                return f.read()
        else:
            print(f"    [!] prettier error: {proc.stderr.strip()[:200]}")
    except FileNotFoundError:
        print("    [!] prettier not found — install with: sudo npm install -g prettier")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)
    return None


def beautify_js(content):
    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.wrap_line_length = 0
        opts.max_preserve_newlines = 0
        result = jsbeautifier.beautify(content, opts)
        if is_minified(result):
            print("    [~] Still minified after jsbeautifier, trying prettier...")
            fallback = beautify_with_prettier(content)
            if fallback:
                return fallback, "prettier"
            print("    [!] Both beautifiers failed — saving as-is")
            return content, "raw"
        return result, "jsbeautifier"
    except ImportError:
        print("    [!] jsbeautifier not found, trying prettier...")
        fallback = beautify_with_prettier(content)
        if fallback:
            return fallback, "prettier"
        return content, "raw"


# ── Extraction ────────────────────────────────────────────────────────────────

def extract_js_from_har(har_path, js_dir):
    print(f"\n[1/4] Extracting JS from {os.path.basename(har_path)}...")
    with open(har_path, "r", encoding="utf-8", errors="replace") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    print(f"      {len(entries)} total HAR entries")

    saved = []
    for i, entry in enumerate(entries):
        url = entry.get("request", {}).get("url", "")
        content = entry.get("response", {}).get("content", {})
        mime = content.get("mimeType", "").split(";")[0].strip()
        text = content.get("text", "")
        encoding = content.get("encoding", "")

        if "javascript" not in mime or not text:
            continue

        if encoding == "base64":
            try:
                text = base64.b64decode(text).decode("utf-8", errors="replace")
            except Exception:
                continue

        parsed = urlparse(url)
        url_file = parsed.path.split("/")[-1].split("?")[0]
        if not url_file or "." not in url_file:
            url_file = f"entry_{i}.js"
        else:
            url_file = sanitize_filename(url_file)
            if not url_file.endswith(".js"):
                url_file += ".js"

        filepath = os.path.join(js_dir, f"{i:04d}_{url_file}")

        print(f"    [+] {os.path.basename(filepath)}")
        beautified, method = beautify_js(text)
        print(f"        beautified via {method}")

        with open(filepath, "w", encoding="utf-8") as out:
            out.write(beautified)

        saved.append((filepath, url))

    print(f"\n      Done — {len(saved)} JS files saved to {js_dir}/")
    return saved


# ── LinkFinder / SecretFinder ─────────────────────────────────────────────────

def run_tool(tool_name, tool_path, js_file, out_file):
    tool_path = os.path.expanduser(tool_path)
    if not os.path.isfile(tool_path):
        print(f"    [!] {tool_name} not found at {tool_path} — skipping")
        return

    try:
        proc = subprocess.run(
            ["python3", tool_path, "-i", js_file, "-o", "cli"],
            capture_output=True, text=True, timeout=120
        )
        output = proc.stdout.strip()
        if output:
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"FILE: {js_file}\n")
                f.write(f"{'='*60}\n")
                f.write(output + "\n")
            print(f"        → {output.count(chr(10)) + 1} findings")
        else:
            print(f"        → no findings")
    except subprocess.TimeoutExpired:
        print(f"    [!] {tool_name} timed out on {os.path.basename(js_file)}")
    except Exception as e:
        print(f"    [!] {tool_name} error: {e}")


def run_recon(js_files, out_dir, args):
    lf_out = os.path.join(out_dir, "lf_out.txt")
    sf_out = os.path.join(out_dir, "sf_out.txt")

    total = len(js_files)
    for idx, (js_file, url) in enumerate(js_files, 1):
        name = os.path.basename(js_file)
        print(f"\n  [{idx}/{total}] {name}")

        if not args.skip_lf:
            print(f"      LinkFinder...")
            run_tool("LinkFinder", args.linkfinder, js_file, lf_out)

        if not args.skip_sf:
            print(f"      SecretFinder...")
            run_tool("SecretFinder", args.secretfinder, js_file, sf_out)

    return lf_out, sf_out


# ── Triage pattern matching ───────────────────────────────────────────────────

def get_context(lines, lineno, context=1):
    """Return surrounding lines as context."""
    start = max(0, lineno - context)
    end = min(len(lines), lineno + context + 1)
    return lines[start:end]


def run_triage(js_files, gf_dir):
    print(f"\n[4/4] Running triage pattern matching across {len(js_files)} JS files...")
    os.makedirs(gf_dir, exist_ok=True)

    # bucket -> list of (filename, lineno, matched_line, context_lines)
    # use a set per bucket to deduplicate on (filename, lineno)
    bucket_hits = defaultdict(list)
    bucket_seen = defaultdict(set)  # (filename, lineno) dedup keys

    compiled = {
        bucket: [re.compile(p, re.IGNORECASE) for p in patterns]
        for bucket, patterns in TRIAGE_BUCKETS.items()
    }

    for js_file, _ in js_files:
        fname = os.path.basename(js_file)
        try:
            with open(js_file, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except Exception as e:
            print(f"    [!] Could not read {fname}: {e}")
            continue

        for lineno, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue
            for bucket, patterns in compiled.items():
                for pattern in patterns:
                    if pattern.search(stripped):
                        dedup_key = (fname, lineno)
                        if dedup_key not in bucket_seen[bucket]:
                            bucket_seen[bucket].add(dedup_key)
                            ctx = [l.rstrip() for l in get_context(lines, lineno - 1)]
                            bucket_hits[bucket].append((fname, lineno, stripped, ctx))
                        break  # one match per line per bucket is enough

    # Write output files — sorted by filename then lineno
    written = []
    manual_hits = 0
    vuln_hits = 0

    all_buckets = MANUAL_BUCKETS + VULN_BUCKETS
    for bucket in all_buckets:
        hits = bucket_hits.get(bucket, [])
        if not hits:
            continue

        hits.sort(key=lambda x: (x[0], x[1]))
        out_path = os.path.join(gf_dir, f"{bucket}.txt")

        with open(out_path, "w", encoding="utf-8") as f:
            f.write(f"# {bucket.upper().replace('_', ' ')} — {len(hits)} matches\n")
            f.write(f"# {'='*56}\n\n")

            current_file = None
            for fname, lineno, matched_line, ctx in hits:
                if fname != current_file:
                    if current_file is not None:
                        f.write("\n")
                    f.write(f"── {fname} {'─'*max(0, 54-len(fname))}\n\n")
                    current_file = fname

                f.write(f"  Line {lineno}:\n")
                for i, ctx_line in enumerate(ctx):
                    # mark the matched line with >>
                    rel = lineno - len(ctx) + i
                    marker = ">>" if ctx_line.strip() == matched_line else "  "
                    f.write(f"  {marker} {rel:5d} | {ctx_line}\n")
                f.write("\n")

        count = len(hits)
        if bucket in MANUAL_BUCKETS:
            manual_hits += count
            label = "manual"
        else:
            vuln_hits += count
            label = "vuln"

        print(f"      [+] {bucket:<24s} {count:>4d} hits  [{label}]  → gf_out/{bucket}.txt")
        written.append(bucket)

    print(f"\n      Triage complete")
    print(f"      Manual review buckets : {sum(1 for b in written if b in MANUAL_BUCKETS)} files, {manual_hits} total hits")
    print(f"      Vuln class buckets    : {sum(1 for b in written if b in VULN_BUCKETS)} files, {vuln_hits} total hits")

    return written


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Full JS recon pipeline from a .har file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument("har", help="Path to .har file")
    parser.add_argument("--output",       metavar="DIR",  help="Output folder")
    parser.add_argument("--linkfinder",   metavar="PATH", default="~/LinkFinder/linkfinder.py")
    parser.add_argument("--secretfinder", metavar="PATH", default="~/SecretFinder/SecretFinder.py")
    parser.add_argument("--skip-lf",      action="store_true", help="Skip LinkFinder")
    parser.add_argument("--skip-sf",      action="store_true", help="Skip SecretFinder")
    parser.add_argument("--skip-gf",      action="store_true", help="Skip triage pattern matching")
    args = parser.parse_args()

    if not os.path.isfile(args.har):
        print(f"[!] File not found: {args.har}")
        sys.exit(1)

    base_name = os.path.splitext(os.path.basename(args.har))[0]
    out_dir   = args.output or f"recon_{sanitize_filename(base_name)}"
    js_dir    = os.path.join(out_dir, "js")
    gf_dir    = os.path.join(out_dir, "gf_out")
    os.makedirs(js_dir, exist_ok=True)

    print(f"[*] Target HAR : {args.har}")
    print(f"[*] Output dir : {out_dir}/")

    # Step 1 — Extract + beautify
    js_files = extract_js_from_har(args.har, js_dir)
    if not js_files:
        print("[!] No JS files found in HAR. Exiting.")
        sys.exit(1)

    # Steps 2 & 3 — LinkFinder + SecretFinder
    print(f"\n[2/4] Running LinkFinder...")
    print(f"[3/4] Running SecretFinder...")
    lf_out, sf_out = run_recon(js_files, out_dir, args)

    # Step 4 — Triage
    written = []
    if not args.skip_gf:
        written = run_triage(js_files, gf_dir)
    else:
        print("\n[4/4] Skipping triage (--skip-gf)")

    # Summary
    print(f"\n{'='*50}")
    print(f"[*] All done! Results in ./{out_dir}/\n")
    print(f"    js/        → {len(js_files)} beautified JS files")
    if not args.skip_lf and os.path.exists(lf_out):
        n = open(lf_out).read().count("FILE:")
        print(f"    lf_out.txt → {n} files scanned by LinkFinder")
    if not args.skip_sf and os.path.exists(sf_out):
        n = open(sf_out).read().count("FILE:")
        print(f"    sf_out.txt → {n} files scanned by SecretFinder")
    if written:
        manual = [b for b in written if b in MANUAL_BUCKETS]
        vuln   = [b for b in written if b in VULN_BUCKETS]
        print(f"    gf_out/    → {len(written)} non-empty buckets")
        if manual:
            print(f"      manual : {', '.join(manual)}")
        if vuln:
            print(f"      vuln   : {', '.join(vuln)}")


if __name__ == "__main__":
    main()
