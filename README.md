# JS Recon Automation Kit

A small HAR-based JavaScript recon automation kit for bug bounty hunters.

This kit is built around one idea:

**Messy recon creates missed attack surface.**

The goal is not to automatically find bugs. The goal is to organize JavaScript recon output so manual review becomes faster, cleaner, and less chaotic.

---

## What This Kit Does

The main script, `har_recon.py`, takes a `.har` file and:

- Extracts JavaScript files from the HAR
- Beautifies the JavaScript for manual review
- Runs LinkFinder against the JS files
- Runs SecretFinder against the JS files
- Runs local regex-based triage checks
- Organizes the output into review buckets

Example output:

```txt
recon_target/
├── js/
│   └── beautified JavaScript files
├── lf_out.txt
├── sf_out.txt
└── gf_out/
    ├── idor.txt
    ├── oauth_redirects.txt
    ├── authz.txt
    ├── secrets.txt
    ├── high_value_endpoints.txt
    ├── file_uploads.txt
    ├── exports.txt
    ├── webhooks.txt
    ├── admin_flags.txt
    ├── ssrf.txt
    ├── sqli.txt
    ├── redirect.txt
    ├── xss.txt
    ├── rce.txt
    └── lfi.txt
```
## Example Output Note

The `recon_example/` folder contains fake sample output to show what a completed run looks like.

Real output will usually be much noisier.

Files like `lf_out.txt`, `sf_out.txt`, and `gf_out/` are review buckets, not confirmed vulnerabilities. Expect false positives, weird strings, framework noise, duplicate endpoints, and low-value matches.

The point of this kit is not to make recon perfect.

The point is to organize messy JavaScript recon so manual review is easier.

---

## Who This Is For

This is for bug bounty hunters who manually review JavaScript and want cleaner recon output.

This is useful if you:

- Export HAR files during manual recon
- Review JavaScript for endpoints, secrets, and client-side attack surface
- Want organized files instead of scattered terminal output
- Prefer manual review but want automation to remove boring cleanup work

This is **not** a one-click bug finder.

---

## Quickstart

Clone the repo:

```bash
git clone https://github.com/logan-sec/js-recon-automation-kit.git
cd js-recon-automation-kit
```

Install Python requirements:

```bash
pip install -r requirements.txt
```

Run the HAR recon script:

```bash
python3 scripts/har_recon.py target.har
```

Or choose a custom output folder:

```bash
python3 scripts/har_recon.py target.har --output recon_target
```

---

## How To Get a HAR File

1. Open the target in your browser
2. Open DevTools
3. Go to the Network tab
4. Click JS
5. Enable Preserve log
6. Browse important app flows
7. Export as HAR
8. Run the HAR through this kit

Good flows to capture:

- Login
- Signup
- Account settings
- Billing
- Profile updates
- Upload/download features
- Integrations
- Webhooks
- OAuth/SSO flows

Bad input creates bad output. If your HAR barely contains anything useful, the kit will not magically fix that.

---

## Main Script

### `har_recon.py`

Extract JS from a HAR file, beautify it, run LinkFinder, SecretFinder, and local triage pattern checks.

Usage:

```bash
python3 scripts/har_recon.py <file.har>
```

Options:

```bash
python3 scripts/har_recon.py <file.har> --output recon_target
python3 scripts/har_recon.py <file.har> --skip-lf
python3 scripts/har_recon.py <file.har> --skip-sf
python3 scripts/har_recon.py <file.har> --skip-gf
```

Custom LinkFinder / SecretFinder paths:

```bash
python3 scripts/har_recon.py target.har \
  --linkfinder ~/LinkFinder/linkfinder.py \
  --secretfinder ~/SecretFinder/SecretFinder.py
```

By default, the script looks for:

```txt
~/LinkFinder/linkfinder.py
~/SecretFinder/SecretFinder.py
```

---

## Other Scripts

### `test_all_keys.sh`

Quick triage script for testing possible exposed API keys from SecretFinder output.

Supported checks:

- Heroku
- Square
- Twilio
- Google

Usage:

```bash
bash scripts/test_all_keys.sh sf_out.txt recon_target/
```

Important:

Only run key validation when it is allowed by the program scope and rules.

Some programs allow validation. Some do not. Do not blindly test third-party keys without permission.

This script is for triage, not exploitation.

---

## Planned for V2

### Surface Recon Script

A planned workflow for broader attack surface mapping using tools like:

- gau
- waybackurls
- katana
- httpx
- deduplication
- endpoint sorting
- attack surface mapping

This is not included in V1 because I do not want to rush a workflow I am not actively using yet.

V1 is focused on the HAR-based JavaScript recon flow.

---

## Requirements

Install Python requirements:

```bash
pip install -r requirements.txt
```

Current `requirements.txt`:

```txt
jsbeautifier>=1.15.1
```

System tools used by the kit:

```bash
sudo apt update
sudo apt install -y curl python3 grep gawk
```

Optional:

```bash
sudo npm install -g prettier
```

External tools:

- LinkFinder
- SecretFinder

You need to install LinkFinder and SecretFinder separately if you want those parts of the pipeline to run.

If they are missing, `har_recon.py` will skip them and continue.

---

## What To Review First

Start with these files:

```txt
gf_out/high_value_endpoints.txt
gf_out/idor.txt
gf_out/authz.txt
gf_out/oauth_redirects.txt
gf_out/secrets.txt
lf_out.txt
sf_out.txt
```

Good things to look for:

- User/account IDs
- Billing endpoints
- Admin/internal routes
- OAuth callback or redirect parameters
- Webhook URLs
- Upload/download routes
- API keys or tokens
- Hidden feature flags
- GraphQL endpoints
- Client-side auth or role checks

The triage buckets are not proof of vulnerabilities. They are leads for manual review.

---

## Common Issues

### No JS files found

Your HAR may not contain JavaScript responses.

Try again with:

- Preserve log enabled
- Cache disabled
- More app flows visited
- A logged-in session if allowed

### LinkFinder not found

Install LinkFinder or pass the path manually:

```bash
python3 scripts/har_recon.py target.har --linkfinder ~/LinkFinder/linkfinder.py
```

### SecretFinder not found

Install SecretFinder or pass the path manually:

```bash
python3 scripts/har_recon.py target.har --secretfinder ~/SecretFinder/SecretFinder.py
```

### `ModuleNotFoundError: jsbeautifier`

Run:

```bash
pip install -r requirements.txt
```

### Prettier not found

Prettier is optional. Install it with:

```bash
sudo npm install -g prettier
```

If Prettier is missing, the script will still try to use `jsbeautifier`.

---

## Notes

This kit is part of my personal bug bounty workflow.

It exists to make JavaScript recon easier to review, not to replace manual testing.

Automation should organize the mess.

The hunting still has to be done manually.

---

## Disclaimer

Only use this on programs and assets where you have permission to test.

You are responsible for following the target’s scope, rules, and legal boundaries.

---

## License

MIT
