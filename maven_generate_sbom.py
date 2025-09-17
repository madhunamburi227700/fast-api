import os
import platform
import subprocess
import shutil

def run_maven_sbom(maven_home: str, project_dir: str):
    mvn_cmd = "mvn.cmd" if platform.system() == "Windows" else "mvn"
    mvn_path = os.path.join(maven_home, "bin", mvn_cmd)
    cmd = [mvn_path, "org.cyclonedx:cyclonedx-maven-plugin:2.9.1:makeAggregateBom"]
    print(f"🚀 Running: {' '.join(cmd)} in {project_dir}")

    result = subprocess.run(cmd, cwd=project_dir)
    if result.returncode != 0:
        raise RuntimeError("❌ Maven SBOM generation failed")

def copy_sbom(project_dir: str, dest_dir: str = None) -> str:
    target_json = os.path.join(project_dir, "target", "bom.json")
    if not os.path.exists(target_json):
        raise FileNotFoundError("SBOM JSON not found. Did Maven build succeed?")

    dest_dir = dest_dir or project_dir
    dest_path = os.path.join(dest_dir, "sbom.json")
    shutil.copy(target_json, dest_path)
    print(f"✅ SBOM copied to {dest_path}")
    return dest_path
