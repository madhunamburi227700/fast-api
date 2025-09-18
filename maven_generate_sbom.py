# maven_generate_sbom.py
import subprocess
from pathlib import Path
import platform
import shutil

def run_maven_sbom(maven_home: Path, repo_path: Path, mvn_bin: str | None = None):
    """
    Run Maven CycloneDX plugin to generate SBOM in JSON format.
    mvn_bin: optional Maven executable name (mvn or mvn.cmd)
    """
    mvn_bin = mvn_bin or ("mvn.cmd" if platform.system() == "Windows" else "mvn")
    mvn_path = Path(maven_home) / "bin" / mvn_bin
    mvn_path = str(mvn_path.resolve())

    cmd = [
        mvn_path,
        "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom",
        "-DoutputFormat=json"  # <-- generate JSON instead of XML
    ]
    subprocess.run(cmd, cwd=repo_path, check=True)
    print("✅ Maven SBOM generated in JSON format")

def copy_sbom(repo_path: Path) -> Path:
    """
    Copy generated JSON BOM to a standard location.
    """
    bom_file = repo_path / "target" / "bom.json"  # JSON file now
    if not bom_file.exists():
        raise FileNotFoundError(f"JSON BOM not found at {bom_file}")
    dest = repo_path / "sbom.json"  # consistent with other flows
    shutil.copy(bom_file, dest)
    return dest
