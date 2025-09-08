import os
from os_detect import detect_os
from git_repo import clone_and_checkout
from venv_manager import setup, remove_venv
from deps import install_dependencies
from dep_convert import convert_json
from cyclo import generate_sbom, get_python_exec
from trivy import scan_sbom_cyclonedx, scan_sbom_json, scan_sbom_table
from compare_trivy_dep import compare
from language_detector import detect_language, detect_dependency_manager

def main():
    env_name = "sbom-env"

    # Step 0: Ask for GitHub repo + branch
    repo_with_branch = input(
        "Enter the GitHub repo URL with branch (e.g. https://github.com/user/repo.git@branch): "
    ).strip()
    if not repo_with_branch:
        print("❌ Repo URL required.")
        return

    # Step 1: Detect OS
    system = detect_os()

    # Step 2: Clone GitHub repo
    repo_path = clone_and_checkout(repo_with_branch)
    print(f"\n➡ Repo cloned at: {repo_path}")

    # Step 3: Detect language and dependency manager
    language = detect_language(repo_path)
    manager = detect_dependency_manager(repo_path, language)
    print(f"📌 Detected language: {language}")
    print(f"📌 Detected dependency manager: {manager}")

    # Step 4: Create virtual environment only if Python
    venv_path = None
    if language == "Python":
        venv_path = setup(env_name=env_name, project_path=repo_path)
        print(f"\n➡ Virtual environment created at: {venv_path}")

        # Step 5: Install dependencies
        install_dependencies(env_name, repo_path)

    # Step 6: Normalize dets.json → normalized_deps.json
    if os.path.exists("dets.json"):
        convert_json("dets.json", "normalized_deps.json")
    else:
        print("⚠️ dets.json not found. Skipping normalization.")

    # Step 7: Generate SBOM from dependency files
    dep_file = None
    for f in ["all-dep.txt", "a.txt"]:
        if os.path.exists(f):
            dep_file = f
            break

    if dep_file:
        generate_sbom(env_name, dep_file, "sbom.json")
    else:
        print("⚠️ No dependency file found for SBOM generation.")

    # Step 8: Scan SBOM with Trivy
    if os.path.exists("sbom.json"):
        scan_sbom_cyclonedx("sbom.json", "sbom_p.json")
        scan_sbom_json("sbom.json", "trivy_report.json")
        scan_sbom_table("sbom.json", "table_trivy.txt")

        # Step 9: Compare Trivy results with normalized_deps.json
        if os.path.exists("normalized_deps.json"):
            compare("sbom_p.json", "normalized_deps.json")

    # Step 10: Optionally remove venv
    if venv_path:
        remove = input(
            f"\nDo you want to remove the virtual environment '{venv_path}'? (y/n): "
        ).strip().lower()
        if remove == "y":
            remove_venv(venv_path)
        else:
            print(f"ℹ Virtual environment '{venv_path}' retained.")

if __name__ == "__main__":
    main()
