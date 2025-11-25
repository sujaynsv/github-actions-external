import json
from collections import defaultdict
from pathlib import Path

def load_report(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)



def summarize(vulns):
    summary = defaultdict(list)
    for v in vulns:
        item = {
            "pkg": v.get("PkgName"),
            "installed": v.get("InstalledVersion"),
            "fixed": v.get("FixedVersion"),
            "cve": v.get("VulnerabilityID"),
            "severity": v.get("Severity"),
            "title": v.get("Title"),
            "url": v.get("PrimaryURL"),
        }
        summary[item["severity"]].append(item)
    return summary

def extract_all_vulns(report):
    vulns = []
    for result in report.get("Results", []):
        for v in result.get("Vulnerabilities", []):
            vulns.append(v)
    return vulns

def print_mitigation(summary):
    print("# Mitigation summary")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        items = summary.get(severity, [])
        if not items:
            continue
        print(f"\n## {severity} issues ({len(items)})")
        for it in items:
            print(f"- Package: {it['pkg']} | Installed: {it['installed']} | CVE: {it['cve']}")
            if it["fixed"]:
                print(f"  Action: Upgrade to fixed version {it['fixed']}")
            else:
                print("  Action: No fixed version. Consider mitigations: patch upstream, replace package, or add runtime controls.")
            print(f"  Title: {it['title']}")
            if it["url"]:
                print(f"  Ref: {it['url']}")

    print("\n### General hardening actions")
    print("- Use slim/maintained base images and keep OS packages minimal.")
    print("- Pin and update Python dependencies; run `pip install --upgrade` and consider `pip-audit` during CI.")
    print("- Drop root privileges and enable least privilege in the container.")
    print("- Rebuild after updates and re-scan to confirm resolution.")

if __name__ == "__main__":
    report_path = Path("trivy-report.json")
    if not report_path.exists():
        raise SystemExit("trivy-report.json not found. Download the artifact locally first.")
    report = load_report(report_path)
    vulns = extract_all_vulns(report)
    summary = summarize(vulns)
    print_mitigation(summary)
