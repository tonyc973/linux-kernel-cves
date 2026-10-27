"""Download every CVE whose description mentions the Linux kernel from the NVD API -> data/raw.jsonl
and write a small random sample of it to docs/sample.jsonl. No API key needed; takes a few minutes.
data/raw.jsonl is not committed (tens of MB): run this script to rebuild it."""
import json
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEYWORD = "Linux kernel"
HEADER = "In the Linux kernel, the following vulnerability has been resolved:"  # how kernel.org starts every CVE it issues
SOURCES = {"nvd@nist.gov": "NVD", "416baaa9-dc9f-4396-8d5f-8c081fb06d67": "kernel.org",
           "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA-ADP", "cve@mitre.org": "MITRE", "secalert@redhat.com": "Red Hat"}
FIX_URL = "https://git.kernel.org/stable/c/"
EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")  # developers' addresses in commit messages: personal data


def get_json(url, tries=5):
    for _ in range(tries - 1):
        try:
            return json.load(urllib.request.urlopen(url, timeout=120))
        except (urllib.error.URLError, TimeoutError) as e:  # NVD often answers 5xx for a minute
            print(f"  NVD error: {e}; retrying in 30 s")
            time.sleep(30)
    return json.load(urllib.request.urlopen(url, timeout=120))  # last try: let the error surface


def fetch(keyword):
    items, start = [], 0
    while True:
        url = f"{API}?keywordSearch={urllib.parse.quote(keyword)}&keywordExactMatch&resultsPerPage=2000&startIndex={start}"
        page = get_json(url)
        time.sleep(6)  # NVD allows 5 requests per 30 seconds without an API key
        items += page["vulnerabilities"]
        start += page["resultsPerPage"]
        print(f"  {min(start, page['totalResults'])}/{page['totalResults']}")
        if start >= page["totalResults"]:
            return items


def parse(item):
    cve = item["cve"]
    metrics = cve.get("metrics", {})
    text = EMAIL.sub("<email>", next(d["value"] for d in cve["descriptions"] if d["lang"] == "en"))
    # kernel.org descriptions are the fix's commit message; its first line is "subsystem: what was fixed"
    title = text.removeprefix(HEADER).strip().split("\n")[0] if text.startswith(HEADER) else None
    cvss = {}
    for version in ("cvssMetricV2", "cvssMetricV30", "cvssMetricV31", "cvssMetricV40"):  # newest version wins per source
        for m in metrics.get(version, []):
            cvss[SOURCES.get(m["source"], m["source"])] = m["cvssData"]["baseScore"]
    ssvc = {k: v for m in metrics.get("ssvcV203", []) for option in m["ssvcData"]["options"] for k, v in option.items()}
    return {
        "id": cve["id"],
        "published": cve["published"][:10],
        "source": SOURCES.get(cve["sourceIdentifier"], cve["sourceIdentifier"]),
        "title": title,
        "subsystem": title.split(":")[0] if title and ":" in title else None,
        "description": text,
        "cwes": sorted({d["value"] for w in cve.get("weaknesses", []) for d in w["description"]} - {"NVD-CWE-Other", "NVD-CWE-noinfo"}),
        "cvss": cvss,
        "exploitation": ssvc.get("exploitation"),  # CISA's verdict: none, poc or active
        "fix_commits": sorted({r["url"].removeprefix(FIX_URL) for r in cve.get("references", []) if r["url"].startswith(FIX_URL)}),
    }


if __name__ == "__main__":
    cves = [parse(i) for i in fetch(KEYWORD) if i["cve"]["vulnStatus"] != "Rejected"]
    cves.sort(key=lambda c: c["id"])
    with open("data/raw.jsonl", "w") as f:
        f.writelines(json.dumps(c) + "\n" for c in cves)
    with open("docs/sample.jsonl", "w") as f:
        f.writelines(json.dumps(c) + "\n" for c in sorted(random.Random(42).sample(cves, 30), key=lambda c: c["id"]))
    print(f"{len(cves)} CVEs -> data/raw.jsonl, 30 of them -> docs/sample.jsonl")
