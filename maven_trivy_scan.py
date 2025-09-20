import subprocess
from pathlib import Path

def scan_sbom(sbom_file: Path, output_dir: Path = None) -> dict:
    """
    Scan SBOM with Trivy in CycloneDX, JSON, and Table formats.
    """
    output_dir = Path(output_dir or sbom_file.parent)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("🔍 Scanning SBOM with Trivy...")

    outputs = {}

    formats = {
        "cyclonedx": "sbom_trivy_cyclonedx.json",
        "json": "sbom_trivy.json",
        "table": "sbom_trivy_table.txt"
    }

    for fmt, filename in formats.items():
        out_file = output_dir / filename
        try:
            subprocess.run([
                "trivy", "sbom", str(sbom_file),
                "--format", fmt if fmt != "cyclonedx" else "cyclonedx",
                "--scanners", "vuln",
                "-o", str(out_file)
            ], check=True)
            print(f"✅ {fmt.upper()} report saved: {out_file}")
            outputs[fmt] = out_file.resolve()
        except subprocess.CalledProcessError as e:
            print(f"⚠️ Trivy {fmt} scan failed: {e}")

    return outputs
