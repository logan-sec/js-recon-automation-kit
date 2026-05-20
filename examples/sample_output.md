# Sample Output

The `recon_example/` folder contains fake sample output showing what a completed run may look like.

Example structure:

```txt
recon_example/
├── gf_out/
│   ├── high_value_endpoints.txt
│   ├── idor.txt
│   └── oauth_redirects.txt
├── js/
│   ├── 0001_app.js
│   └── 0002_dashboard.js
├── lf_out.txt
└── sf_out.txt
```

## Important Note

The sample output is intentionally fake.

Real output will usually be noisier and less clean.

Expect:

- False positives
- Duplicate endpoints
- Framework strings
- Random library paths
- Low-value matches
- Output that requires manual review

The files created by this kit are not confirmed vulnerabilities.

They are organized leads for manual testing.
