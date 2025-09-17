from pathlib import Path

def is_golang_project(repo_path: Path) -> bool:
    """Check if a folder contains go.mod and go.sum"""
    go_mod = repo_path / "go.mod"
    go_sum = repo_path / "go.sum"
    return go_mod.exists() and go_sum.exists()
