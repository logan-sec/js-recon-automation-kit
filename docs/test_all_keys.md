# `test_all_keys.sh`

`test_all_keys.sh` is a quick API key triage script.

It parses SecretFinder output and checks whether certain possible exposed keys appear to be active.

Supported checks:

- Heroku
- Square
- Twilio
- Google

This script is for **triage only**, not exploitation.

---

## Usage

Basic usage:

```bash
bash scripts/test_all_keys.sh sf_out.txt
```

Custom output directory:

```bash
bash scripts/test_all_keys.sh sf_out.txt recon_target/
```

Expected arguments:

```txt
bash scripts/test_all_keys.sh [sf_out_file] [output_dir]
```

Defaults:

```txt
sf_out_file = sf_out.txt
output_dir  = current directory
```

---

## What It Creates

Depending on what it finds, the script may create files like:

```txt
heroku_keys.txt
square_keys.txt
twilio_sids.txt
twilio_tokens.txt
google_keys.txt
valid_heroku_keys.txt
valid_square_keys.txt
valid_twilio_keys.txt
valid_google_keys.txt
```

The `valid_*.txt` files are only created when a key appears to validate successfully.

---

## Supported Checks

### Heroku

Looks for possible Heroku API keys in SecretFinder output and checks:

```txt
https://api.heroku.com/account
```

---

### Square

Looks for possible Square access tokens and checks:

```txt
https://connect.squareup.com/v2/merchants/me
```

---

### Twilio

Looks for possible Twilio Account SIDs and Auth Tokens.

It checks SID/token pairs against:

```txt
https://api.twilio.com/2010-04-01/Accounts/{sid}.json
```

---

### Google

Looks for Google API-key-shaped values and checks basic Google Maps API behavior.

It may also test whether the key appears usable against other Google APIs.

---

## Important Scope Warning

Only run this script when key validation is allowed by the program rules.

Some bug bounty programs allow safe validation of exposed keys.

Some do not.

Do not blindly test third-party keys just because they appear in JavaScript.

If the program rules are unclear, do not validate the key. Report the exposed secret carefully or ask the program/triager for guidance.

---

## Why This Script Exists

SecretFinder output can be noisy.

This script helps quickly separate:

- Obviously dead values
- False positives
- Real-looking keys
- Possibly valid keys that need careful handling

It is meant to save time during JavaScript-heavy recon.

---

## Requirements

This is a Bash script.

It uses common system tools:

```txt
bash
grep
awk
wc
curl
python3
```

Install common dependencies on Debian/Kali/Ubuntu:

```bash
sudo apt update
sudo apt install -y curl python3 grep gawk
```

---

## Example

Run against SecretFinder output from a recon folder:

```bash
bash scripts/test_all_keys.sh recon_target/sf_out.txt recon_target/
```

Example output files:

```txt
recon_target/google_keys.txt
recon_target/valid_google_keys.txt
recon_target/twilio_sids.txt
recon_target/twilio_tokens.txt
```

---

## Reminder

A valid key does not automatically mean impact.

Impact depends on:

- What the key can access
- Whether it is restricted
- Whether it belongs to the target
- Whether the program allows validation
- Whether the exposed key creates real security risk

Validate carefully. Report responsibly.
