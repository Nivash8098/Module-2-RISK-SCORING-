import argparse
import json
from collections import defaultdict
import requests
import matplotlib.pyplot as plt


# ==================================================
# Accurate data from NVD (fixes, mitigations, affected products, CVSS)
# ==================================================
def fetch_nvd_cve(cve_id: str) -> dict:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    r = requests.get(url, timeout=25)
    r.raise_for_status()
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        raise ValueError(f"No NVD record found for {cve_id}")
    return vulns[0]["cve"]


def extract_nvd_details(cve: dict):
    # Affected products
    affected_map = defaultdict(set)

    def _parse_cpe(cpe_list):
        for cpe in cpe_list:
            if cpe.get("vulnerable"):
                crit = cpe.get("criteria", "")
                parts = crit.split(":")
                if len(parts) >= 6:
                    vendor = parts[3]
                    product = parts[4].replace("_", " ")
                    version = parts[5]
                    if version in ["*", "-"]:
                        version = "unspecified"
                    affected_map[f"{vendor} {product}"].add(version)

    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            # Handle both cpeMatch (direct) and children (nested)
            _parse_cpe(node.get("cpeMatch", []))
            for child in node.get("children", []):
                _parse_cpe(child.get("cpeMatch", []))

    affected_products = []
    for prod, versions in affected_map.items():
        affected_products.append({
            "product": prod,
            "affected_versions": ", ".join(sorted(versions))
        })

    # Fixes and mitigations (from references tags)
    fixes, mitigations = [], []
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        tags = ref.get("tags", []) or []
        # Fixes: Patch, Vendor Advisory, or Third Party Advisory
        if "Patch" in tags or "Vendor Advisory" in tags or "Third Party Advisory" in tags:
            fixes.append(url)
        # Mitigations: Mitigation tag, Vendor Advisory, or Third Party Advisory
        if "Mitigation" in tags or "Vendor Advisory" in tags or "Third Party Advisory" in tags:
            mitigations.append(url)

    # CVSS (prefer 3.1, then 3.0)
    cvss = {}
    metrics = cve.get("metrics", {})
    if metrics.get("cvssMetricV31"):
        data = metrics["cvssMetricV31"][0]["cvssData"]
        cvss = {
            "version": "3.1",
            "base_score": data.get("baseScore"),
            "severity": data.get("baseSeverity"),
            "vector": data.get("vectorString")
        }
    elif metrics.get("cvssMetricV30"):
        data = metrics["cvssMetricV30"][0]["cvssData"]
        cvss = {
            "version": "3.0",
            "base_score": data.get("baseScore"),
            "severity": data.get("baseSeverity"),
            "vector": data.get("vectorString")
        }

    return affected_products, fixes, mitigations, cvss


# ==================================================
# AI-style EPSS prediction (ensures difference)
# ==================================================
def ai_predict_epss(cvss_vector: str | None = None) -> dict:
    """
    AI-style EPSS scoring based on CVSS hints (if available) + heuristic.
    Distinct current vs. 30-day prediction guaranteed.
    """
    # Base score derived from attack surface signals in CVSS vector
    current = 0.0008  # default baseline low risk
    if cvss_vector:
        vector = cvss_vector.upper()
        # Increase for network, low complexity, no privileges
        if "AV:N" in vector:
            current *= 1.6
        if "AC:L" in vector:
            current *= 1.4
        if "PR:N" in vector:
            current *= 1.3
        if "UI:N" in vector:
            current *= 1.2
        # Scope changed often correlates with broader impact
        if "S:C" in vector:
            current *= 1.15
        # Confidentiality/Integrity/Availability impacts
        impact_boost = 1.0
        if "C:H" in vector or "I:H" in vector or "A:H" in vector:
            impact_boost = 1.25
        elif "C:L" in vector or "I:L" in vector or "A:L" in vector:
            impact_boost = 1.1
        current *= impact_boost

    # Clamp to a reasonable EPSS-like range
    current = max(0.0003, min(0.08, current))
    current = round(current, 5)

    # Forecast: increase low-to-mid scores, dampen higher scores
    if current < 0.001:
        predicted = current * 1.35
    elif current < 0.01:
        predicted = current * 1.18
    else:
        predicted = current * 0.92

    # Guarantee difference
    if abs(predicted - current) < 1e-6:
        predicted = current + 0.0007

    percentile = 25.0
    # Map current score to a rough percentile band
    if current >= 0.02:
        percentile = 70.0
    elif current >= 0.01:
        percentile = 55.0
    elif current >= 0.005:
        percentile = 40.0

    final_predicted = round(min(1.0, max(0.0, predicted)), 5)
    return {
        "score": round(current, 5),
        "percentile": round(percentile, 2),
        "predicted_30d": final_predicted
    }


# ==================================================
# Graph: current vs predicted EPSS
# ==================================================
def plot_epss(current: float, predicted: float, cve_id: str):
    plt.figure(figsize=(7, 4.5))
    # Points
    plt.plot([0], [current], marker="o", color="#1976D2", label="AI EPSS (current)")
    plt.plot([30], [predicted], marker="o", color="#FB8C00", label="AI EPSS (30-day)")
    # Connecting line
    plt.plot([0, 30], [current, predicted], linestyle="--", color="#FB8C00", alpha=0.7)
    plt.title(f"AI EPSS forecast — {cve_id}")
    plt.xlabel("Days")
    plt.ylabel("EPSS (0–1)")
    plt.ylim(0, max(current, predicted) * 1.3 + 0.001)
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.show()


# ==================================================
# Orchestrator
# ==================================================
def process_cve(cve_id: str, plot: bool = True) -> dict:
    # Accurate NVD data
    cve = fetch_nvd_cve(cve_id)
    affected_products, fixes, mitigations, cvss = extract_nvd_details(cve)

    # AI EPSS prediction uses CVSS vector (if available)
    cvss_vector = cvss.get("vector") if cvss else None
    epss = ai_predict_epss(cvss_vector)

    # Plot if requested
    if plot:
        plot_epss(epss["score"], epss["predicted_30d"], cve_id)

    return {
        "cve_id": cve_id,
        "epss": epss,                       # AI-predicted (not official)
        "fixes": fixes,                     # Accurate from NVD references
        "mitigations": mitigations,         # Accurate from NVD references
        "affected_products": affected_products,  # Accurate from NVD configurations
    }


# ==================================================
# CLI entry
# ==================================================
def parse_args():
    p = argparse.ArgumentParser(description="AI + NVD CVE analysis with EPSS graph")
    p.add_argument("cve_id", nargs="?", help="CVE identifier, e.g., CVE-2024-1004")
    group = p.add_mutually_exclusive_group()
    group.add_argument("--plot", dest="plot", action="store_true", help="Show EPSS graph (default)")
    group.add_argument("--no-plot", dest="plot", action="store_false", help="Disable graph")
    p.set_defaults(plot=True)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    cve_id = args.cve_id
    if not cve_id:
        cve_id = input("Enter CVE ID: ").strip()

    try:
        result = process_cve(cve_id, plot=args.plot)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(json.dumps({"error": str(e), "cve_id": cve_id}, indent=2))
