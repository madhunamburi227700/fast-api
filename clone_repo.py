import subprocess
from pathlib import Path

def run_command(cmd, cwd=None):
    result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stderr)
        raise Exception(f"Command failed: {' '.join(cmd)}")
    return result.stdout.strip()

def clone_repo(repo_with_branch: str, target_dir: Path):
    """
    Clone a git repository.
    Argument format: repo_url@branch (branch optional)
    """
    # Split repo URL and branch
    if "@" in repo_with_branch:
        git_url, branch = repo_with_branch.split("@", 1)
    else:
        git_url = repo_with_branch
        branch = None

    if target_dir.exists():
        print(f"{target_dir} already exists. Skipping clone.")
        return

    cmd = ["git", "clone"]
    if branch:
        cmd += ["-b", branch]
    cmd += [git_url, str(target_dir)]

    run_command(cmd)
    print(f"Repo cloned to {target_dir}")
