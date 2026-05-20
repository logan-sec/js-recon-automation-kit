# Sample Commands

Basic HAR recon:

```bash
python3 scripts/har_recon.py target.har
```

Custom output directory:

```bash
python3 scripts/har_recon.py target.har --output recon_target
```

Skip LinkFinder:

```bash
python3 scripts/har_recon.py target.har --skip-lf
```

Skip SecretFinder:

```bash
python3 scripts/har_recon.py target.har --skip-sf
```

Skip local triage buckets:

```bash
python3 scripts/har_recon.py target.har --skip-gf
```

Use custom LinkFinder and SecretFinder paths:

```bash
python3 scripts/har_recon.py target.har \
  --linkfinder ~/LinkFinder/linkfinder.py \
  --secretfinder ~/SecretFinder/SecretFinder.py
```

Run API key triage against SecretFinder output:

```bash
bash scripts/test_all_keys.sh recon_target/sf_out.txt recon_target/
```
