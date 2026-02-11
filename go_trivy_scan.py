import subprocess
from pathlib import Path

def scan_trivy(sbom_file: Path, current_folder: Path):
    """Scan SBOM with Trivy in multiple formats (CycloneDX, JSON, Table)."""
    print("🔍 Scanning SBOM with Trivy...")

    # CycloneDX format
    trivy_cyclonedx = current_folder / "sbom_trivy_cyclonedx.json"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "cyclonedx",
        "--scanners", "vuln",
        "-o", str(trivy_cyclonedx)
    ], check=True)
    print(f"✅ CycloneDX vulnerability report saved to {trivy_cyclonedx}")

    # JSON format
    trivy_json = current_folder / "sbom_trivy.json"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "json",
        "--scanners", "vuln",
        "-o", str(trivy_json)
    ], check=True)
    print(f"✅ JSON vulnerability report saved to {trivy_json}")

    # Table format
    trivy_table = current_folder / "sbom_trivy_table.txt"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "table",
        "--scanners", "vuln",
        "-o", str(trivy_table)
    ], check=True)
    print(f"✅ Table vulnerability report saved to {trivy_table}")

    # Return all three paths
    return {
        "cyclonedx": trivy_cyclonedx,
        "json": trivy_json,
        "table": trivy_table
    }
