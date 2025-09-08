import os
import sys

# Use tomllib if Python >= 3.11
if sys.version_info >= (3, 11):
    import tomllib
else:
    tomllib = None  # fallback if older Python

def detect_language(repo_path: str) -> str:
    """
    Detects the main programming language of a repo.
    Currently supports: Python, Java, Go
    """
    extensions = {
        "Python": [".py"],
        "Java": [".java"],
        "Go": [".go"]
    }

    counts = {lang: 0 for lang in extensions}
    
    for root, _, files in os.walk(repo_path):
        for file in files:
            for lang, exts in extensions.items():
                if any(file.endswith(ext) for ext in exts):
                    counts[lang] += 1

    # Choose language with most files
    language = max(counts, key=counts.get)
    if counts[language] == 0:
        return "Unknown"
    return language

def detect_dependency_manager(repo_path: str, language: str) -> str:
    """
    Detects the dependency manager used based on language.
    Recursively searches all subfolders for lock files first, then config files.
    Uses tomllib for pyproject.toml if available.
    """
    manager = "Unknown"

    if language == "Python":
        for root, _, files in os.walk(repo_path):
            files_lower = [f.lower() for f in files]

            # Check lock files first
            if "poetry.lock" in files_lower:
                return "poetry"
            elif "uv.lock" in files_lower:
                return "uv"
            elif "pipfile.lock" in files_lower:
                return "pipenv"

            # Check config files
            if "requirements.txt" in files_lower:
                return "pip"
            elif "pipfile" in files_lower:
                return "pipenv"
            elif "setup.py" in files_lower:
                return "setuptools"
            elif "pyproject.toml" in files_lower and tomllib:
                pyproject_file = os.path.join(root, "pyproject.toml")
                try:
                    with open(pyproject_file, "rb") as f:
                        data = tomllib.load(f)
                    tool_keys = data.get("tool", {})
                    if "poetry" in tool_keys:
                        return "poetry"
                    elif "uv" in tool_keys:
                        return "uv"
                    elif "flit" in tool_keys:
                        return "flit"
                    else:
                        return "pyproject"
                except Exception:
                    return "pyproject"

    elif language == "Java":
        for root, _, files in os.walk(repo_path):
            if "pom.xml" in files:
                return "maven"
            elif "build.gradle" in files:
                return "gradle"

    elif language == "Go":
        for root, _, files in os.walk(repo_path):
            if "go.mod" in files:
                return "go modules"

    return manager
