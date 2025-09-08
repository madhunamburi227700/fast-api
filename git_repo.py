import subprocess
import os

def clone_and_checkout(repo_with_branch: str) -> str:
    """
    Clone a git repo and switch to the given branch if it's not main/master.
    
    Args:
        repo_with_branch (str): Git repo in one of the formats:
            - <repo_url>
            - <repo_url>@<branch>
    
    Returns:
        str: Path to the cloned repository.
    """

    # Ensure exactly one argument is provided
    if not isinstance(repo_with_branch, str) or not repo_with_branch.strip():
        raise ValueError("❌ You must provide exactly one argument: '<repo_url>' or '<repo_url>@<branch>'")

    # Parse repo and branch
    if "@" in repo_with_branch:
        repo_url, branch = repo_with_branch.split("@", 1)
    else:
        repo_url, branch = repo_with_branch, "main"  # default branch

    repo_name = os.path.splitext(os.path.basename(repo_url))[0]

    # Clone repo if not exists
    if not os.path.exists(repo_name):
        print(f"📥 Cloning repository {repo_url} ...")
        subprocess.run(["git", "clone", repo_url], check=True)
    else:
        print(f"✔ Repository '{repo_name}' already exists. Skipping clone.")

    # Move into repo directory
    os.chdir(repo_name)

    # Checkout branch if not main/master
    if branch.lower() not in ["main", "master"]:
        print(f"🔄 Switching to branch: {branch}")
        subprocess.run(["git", "checkout", branch], check=True)
    else:
        print(f"✔ Staying on default branch: {branch}")

    return os.getcwd()

