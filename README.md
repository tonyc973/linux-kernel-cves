# Linux kernel CVEs, labeled for triage

Since 2024 the Linux kernel gets more than 25 new CVEs a day, and most of them come with no useful severity
information. This project builds a dataset of all ~22,000 Linux kernel CVEs in NVD and labels each one with what
kind of bug it is, who can trigger it, and what an attacker can get out of it.

- **The proposal**: [`docs/data-proposal.md`](docs/data-proposal.md): why this dataset, sources and licenses,
  sensitive data, schema, and how we will show it is useful.
- **A sample**: [`docs/sample.jsonl`](docs/sample.jsonl): 30 real records.

## Rebuild the data

```bash
python collect.py   # NVD -> data/raw.jsonl (about 5 minutes, no API key, standard library only)
pip install pytest && pytest
```

`data/` is not committed: it is 32 MB and the script rebuilds it.

## Credits

CVE records © The MITRE Corporation, used under the [CVE Program Terms of Use](https://www.cve.org/Legal/TermsOfUse).
This product uses the NVD API but is not endorsed or certified by the NVD.
