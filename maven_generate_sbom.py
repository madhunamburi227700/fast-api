import subprocess
from pathlib import Path
import shutil

from maven_setup import get_mvn_path

def run_maven_sbom(repo_path: Path, mvn_bin: str | Path | None = None):
    """
    Run Maven CycloneDX plugin to generate SBOM in JSON format.
    """
    mvn_path = Path(mvn_bin) if mvn_bin else get_mvn_path()

    if not mvn_path.exists():
        raise FileNotFoundError(f"❌ Maven binary not found: {mvn_path}")

    cmd = [
        str(mvn_path),
        "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
        "-DoutputFormat=json"
    ]

    print(f"🔧 Maven binary path: {mvn_path}")
    print(f"📁 Working directory: {repo_path}")
    print(f"📦 Running command: {' '.join(cmd)}")

    subprocess.run(cmd, cwd=repo_path, check=True)


def copy_sbom(repo_path: Path) -> Path:
    """
    Copy generated JSON BOM to repo root.
    """
    bom_file = repo_path / "target" / "bom.json"
    if not bom_file.exists():
        raise FileNotFoundError(f"❌ JSON BOM not found at {bom_file}")

    dest = repo_path / "sbom.json"
    shutil.copy(bom_file, dest)
    print(f"✅ SBOM copied to {dest}")
    return dest
