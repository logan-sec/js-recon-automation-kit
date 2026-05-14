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

## Basic Usage

```bash
python3 scripts/har_recon.py target.har

bash scripts/test_all_keys.sh recon_target/sf_out.txt
