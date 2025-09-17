import subprocess
from pathlib import Path

def run_command(cmd, cwd=None):
    """Run a shell command in a specific directory"""
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr)
        raise Exception(f"Command failed: {' '.join(cmd)}")
    return result.stdout.strip()


def prepare_dependencies(repo_path: Path, current_folder: Path):
    """Run go mod tidy inside repo and generate upgradefile.txt in current folder"""
    print("Running go mod tidy...")
    run_command(["go", "mod", "tidy"], cwd=repo_path)

    print("Generating upgradefile.txt...")
    upgrade_file = current_folder / "upgradefile.txt"
    output = run_command(["go", "list", "-u", "-m", "-json", "all"], cwd=repo_path)
    upgrade_file.write_text(output)
    print(f"Upgrade file created at {upgrade_file}")
    return upgrade_file


def install_deptree():
    """Install deptree if not installed"""
    print("Installing deptree from vc60er/deptree...")
    run_command(["go", "install", "github.com/vc60er/deptree@latest"])
    print("Deptree installed.")


def generate_dependency_tree(repo_path: Path, current_folder: Path):
    """Generate dependency tree JSON using deptree"""
    print("Generating dependency tree...")

    # Run go mod graph inside repo
    graph_output = run_command(["go", "mod", "graph"], cwd=repo_path)

    # Run deptree with stdin
    deptree_cmd = ["deptree", "-json"]
    proc = subprocess.Popen(
        deptree_cmd,
        cwd=repo_path,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    stdout, stderr = proc.communicate(input=graph_output)
    if proc.returncode != 0:
        print(stderr)
        raise Exception("Deptree command failed")

    # Save JSON output in current folder
    t_file = current_folder / "t.json"
    t_file.write_text(stdout)
    print(f"Dependency tree saved to {t_file}")
    return t_file
