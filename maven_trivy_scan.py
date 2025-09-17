import subprocess
from pathlib import Path

def scan_sbom(sbom_file: Path, output_dir: Path = None):
    """
    Scan SBOM with Trivy in multiple formats (CycloneDX, JSON, Table).
    Outputs files directly in the provided output_dir (default = SBOM folder).
    """
    output_dir = Path(output_dir or sbom_file.parent)
    print("🔍 Scanning SBOM with Trivy...")

    # CycloneDX format
    trivy_cyclonedx = output_dir / "sbom_trivy_cyclonedx.json"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "cyclonedx",
        "--scanners", "vuln",
        "-o", str(trivy_cyclonedx)
    ], check=True)
    print(f"✅ CycloneDX report saved: {trivy_cyclonedx}")

    # JSON format
    trivy_json = output_dir / "sbom_trivy.json"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "json",
        "--scanners", "vuln",
        "-o", str(trivy_json)
    ], check=True)
    print(f"✅ JSON report saved: {trivy_json}")

    # Table format
    trivy_table = output_dir / "sbom_trivy_table.txt"
    subprocess.run([
        "trivy", "sbom", str(sbom_file),
        "--format", "table",
        "--scanners", "vuln",
        "-o", str(trivy_table)
    ], check=True)
    print(f"✅ Table report saved: {trivy_table}")

    # Return paths to all generated reports
    return {
        "cyclonedx": trivy_cyclonedx,
        "json": trivy_json,
        "table": trivy_table
    }
