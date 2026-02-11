import subprocess
from pathlib import Path

def generate_sbom(repo_path: Path, current_folder: Path):
    """Generate CycloneDX SBOM"""
    print("Generating SBOM...")
    sbom_file = current_folder / "sbom.json"
    cmd = [
        "cyclonedx-gomod",
        "mod",
        "-json",
        "-output", str(sbom_file),
        "."
    ]
    subprocess.run(cmd, cwd=repo_path, check=True)
    print(f"SBOM saved to {sbom_file}")
    return sbom_file