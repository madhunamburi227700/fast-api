import subprocess
import os


def scan_sbom_cyclonedx(sbom_input="sbom.json", cyclonedx_output="sbom_p.json"):
    """Generate CycloneDX SBOM vulnerability report."""
    if not os.path.exists(sbom_input):
        print(f"❌ SBOM file '{sbom_input}' not found.")
        return

    print(f"\n🔍 Scanning SBOM for vulnerabilities (CycloneDX format)...")

    subprocess.run([
        "trivy", "sbom", sbom_input,
        "--format", "cyclonedx",
        "--scanners", "vuln",
        "-o", cyclonedx_output
    ], check=True)

    print(f"✅ CycloneDX vulnerability report saved to '{cyclonedx_output}'")


def scan_sbom_json(sbom_input="sbom.json", json_output="trivy_report.json"):
    """Generate Trivy native JSON vulnerability report."""
    if not os.path.exists(sbom_input):
        print(f"❌ SBOM file '{sbom_input}' not found.")
        return

    print(f"\n🔍 Scanning SBOM for vulnerabilities (JSON format)...")

    subprocess.run([
        "trivy", "sbom", sbom_input,
        "--format", "json",
        "--scanners", "vuln",
        "-o", json_output
    ], check=True)

    print(f"✅ JSON vulnerability report saved to '{json_output}'")

def scan_sbom_table(sbom_input="sbom.json", table_output="table_trivy.txt"):
    """Generate Trivy SBOM vulnerability report in table format."""
    if not os.path.exists(sbom_input):
        print(f"❌ SBOM file '{sbom_input}' not found.")
        return

    print(f"\n🔍 Scanning SBOM for vulnerabilities (Table format)...")

    subprocess.run([
        "trivy", "sbom", sbom_input,
        "--format", "table",
        "--scanners", "vuln",
        "-o", table_output
    ], check=True)

    print(f"✅ Table vulnerability report saved to '{table_output}'")
