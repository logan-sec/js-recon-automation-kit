# JS Recon Automation Kit

A small collection of scripts I use during bug bounty JavaScript recon.

This kit is built around one idea:

Messy recon creates missed attack surface.

The goal is not to automatically find bugs.
The goal is to organize JavaScript recon output so manual review becomes faster and cleaner.

## Included Scripts

### har_recon.py

Takes a `.har` file and creates an organized recon folder containing:

- downloaded JavaScript files
- beautified JavaScript files
- LinkFinder output
- SecretFinder output
- gf-filtered attack surface

### test_all_keys.sh

A helper script for testing possible secrets found during JavaScript recon.

## Quickstart

```bash
git clone https://github.com/logan-sec/js-recon-automation-kit.git
cd js-recon-automation-kit
pip install -r requirements.txt
python3 scripts/har_recon.py examples/example.har
```
```md
## Basic Workflow

1. Open target in browser
2. Open DevTools → Network
3. Click JS
4. Enable Preserve log
5. Browse important app flows
6. Export HAR file
7. Run the kit
8. Manually review endpoints, secrets, and gf output
```

## Common Issues

### `ModuleNotFoundError`
Run:

```bash
pip install -r requirements.txt
