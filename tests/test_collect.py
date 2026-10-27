from collect import parse

KERNEL_ORG = "416baaa9-dc9f-4396-8d5f-8c081fb06d67"
CISA = "134c704f-9b21-4f2e-91b3-4a467353bcc0"
ITEM = {"cve": {  # the real NVD record for CVE-2023-52433, shortened, plus an email, NVD scores and a non-fix link to test
    "id": "CVE-2023-52433",
    "sourceIdentifier": KERNEL_ORG,
    "published": "2024-02-20T13:15:08.140",
    "descriptions": [
        {"lang": "en", "value": "In the Linux kernel, the following vulnerability has been resolved:\n\n"
                                "netfilter: nft_set_rbtree: skip sync GC for new elements in this transaction\n\n"
                                "New elements in this transaction might expired before such transaction\nends.\n"
                                "Reported-by: Jane Doe <jane.doe@example.co.uk>"},
        {"lang": "es", "value": "En el kernel de Linux, se resolvió la siguiente vulnerabilidad: ..."}],
    "metrics": {
        "cvssMetricV2": [{"source": "nvd@nist.gov", "cvssData": {"baseScore": 2.1}}],
        "cvssMetricV31": [{"source": KERNEL_ORG, "cvssData": {"baseScore": 7.8}},
                          {"source": CISA, "cvssData": {"baseScore": 4.4}},
                          {"source": "nvd@nist.gov", "cvssData": {"baseScore": 5.5}}],
        "ssvcV203": [{"source": CISA, "ssvcData": {"options": [
            {"exploitation": "none"}, {"automatable": "no"}, {"technicalImpact": "partial"}]}}]},
    "weaknesses": [{"source": CISA, "description": [{"lang": "en", "value": "CWE-273"}]},
                   {"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "NVD-CWE-noinfo"}]}],
    "references": [{"url": "https://git.kernel.org/stable/c/9db9feb841f7449772f9393c16b9ef4536d8c127"},
                   {"url": "https://git.kernel.org/stable/c/03caf75da1059f0460666c826e9f50e13dfd0017"},
                   {"url": "https://lore.kernel.org/some-thread"}],
}}


def test_parse_a_kernel_org_cve():
    c = parse(ITEM)
    assert (c["id"], c["published"], c["source"]) == ("CVE-2023-52433", "2024-02-20", "kernel.org")
    assert c["title"] == "netfilter: nft_set_rbtree: skip sync GC for new elements in this transaction"
    assert c["subsystem"] == "netfilter"
    assert c["description"].startswith("In the Linux kernel")  # the English text, kept whole
    assert c["description"].endswith("Reported-by: Jane Doe <<email>>")  # but no personal email addresses
    assert c["cwes"] == ["CWE-273"]
    assert c["cvss"] == {"NVD": 5.5, "kernel.org": 7.8, "CISA-ADP": 4.4}  # one score per source, CVSS 3.1 over 2.0
    assert c["exploitation"] == "none"
    assert c["fix_commits"] == ["03caf75da1059f0460666c826e9f50e13dfd0017", "9db9feb841f7449772f9393c16b9ef4536d8c127"]


def test_parse_an_old_style_cve_without_scores():
    old = {"cve": {**ITEM["cve"], "sourceIdentifier": "cve@mitre.org", "metrics": {}, "weaknesses": [], "references": [],
                   "descriptions": [{"lang": "en", "value": "The foo function in the Linux kernel before 4.1 allows ..."}]}}
    c = parse(old)
    assert (c["source"], c["title"], c["subsystem"]) == ("MITRE", None, None)
    assert (c["cvss"], c["exploitation"], c["cwes"], c["fix_commits"]) == ({}, None, [], [])
