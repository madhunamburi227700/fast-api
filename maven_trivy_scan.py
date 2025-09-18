# maven_trivy_scan.py
import subprocess
from pathlib import Path

def scan_sbom(sbom_file: Path, output_dir: Path = None) -> dict:
    """
    Scan SBOM with Trivy in multiple formats: CycloneDX, JSON, Table.
    Outputs files directly in the provided output_dir (default = SBOM folder).
    Returns a dictionary with paths to all generated reports.
    """
    output_dir = Path(output_dir or sbom_file.parent)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("🔍 Scanning SBOM with Trivy...")

    # -------------------- CycloneDX --------------------
    trivy_cyclonedx = output_dir / "sbom_trivy_cyclonedx.json"
    try:
        subprocess.run([
            "trivy", "sbom", str(sbom_file),
            "--format", "cyclonedx",
            "--scanners", "vuln",
            "-o", str(trivy_cyclonedx)
        ], check=True)
        print(f"✅ CycloneDX report saved: {trivy_cyclonedx}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ CycloneDX scan failed: {e}")

    # -------------------- JSON --------------------
    trivy_json = output_dir / "sbom_trivy.json"
    try:
        subprocess.run([
            "trivy", "sbom", str(sbom_file),
            "--format", "json",
            "--scanners", "vuln",
            "-o", str(trivy_json)
        ], check=True)
        print(f"✅ JSON report saved: {trivy_json}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ JSON scan failed: {e}")

    # -------------------- Table --------------------
    trivy_table = output_dir / "sbom_trivy_table.txt"
    try:
        subprocess.run([
            "trivy", "sbom", str(sbom_file),
            "--format", "table",
            "--scanners", "vuln",
            "-o", str(trivy_table)
        ], check=True)
        print(f"✅ Table report saved: {trivy_table}")
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Table scan failed: {e}")

    return {
        "cyclonedx": trivy_cyclonedx.resolve(),
        "json": trivy_json.resolve(),
        "table": trivy_table.resolve()
    }
