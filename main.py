import os
from pathlib import Path
from os_detect import detect_os
from git_repo import clone_and_checkout
from venv_manager import setup, remove_venv
from deps import install_dependencies
from dep_convert import convert_json
from cyclo import generate_sbom as generate_python_sbom
from trivy import scan_sbom_cyclonedx, scan_sbom_json, scan_sbom_table
from compare_trivy_dep import compare
from language_detector import detect_language, detect_dependency_manager
from golang_check import is_golang_project
from go_dependency_tree import prepare_dependencies, install_deptree, generate_dependency_tree
from sbom_generator import generate_sbom as generate_go_sbom
from go_trivy_scan import scan_trivy
from go_compare import generate_comparison

# Java / Maven
from maven_generate_sbom import run_maven_sbom, copy_sbom
from maven_setup import download_maven, extract_maven
from maven_trivy_scan import scan_sbom as scan_maven_sbom


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
    repo_path = Path(clone_and_checkout(repo_with_branch))
    print(f"\n➡ Repo cloned at: {repo_path}")

    # Step 3: Detect language and dependency manager
    language = detect_language(repo_path)
    manager = detect_dependency_manager(repo_path, language)
    print(f"📌 Detected language: {language}")
    print(f"📌 Detected dependency manager: {manager}")

    current_folder = Path.cwd()

    if language == "Python":
        # Python-specific flow
        venv_path = setup(env_name=env_name, project_path=repo_path)
        print(f"\n➡ Virtual environment created at: {venv_path}")

        # Install dependencies
        install_dependencies(env_name, repo_path)

        # Normalize dets.json
        dets_file = repo_path / "dets.json"
        if dets_file.exists():
            convert_json(dets_file, repo_path / "normalized_deps.json")
        else:
            print("⚠️ dets.json not found. Skipping normalization.")

        # Generate SBOM from dependency files
        dep_file = next((repo_path / f for f in ["all-dep.txt", "a.txt"] if (repo_path / f).exists()), None)

        if dep_file:
            generate_python_sbom(env_name, dep_file, repo_path / "sbom.json")
        else:
            print("⚠️ No dependency file found for SBOM generation.")

        # Scan SBOM with Trivy
        sbom_file = repo_path / "sbom.json"
        if sbom_file.exists():
            scan_sbom_cyclonedx(sbom_file, repo_path / "sbom_p.json")
            scan_sbom_json(sbom_file, repo_path / "trivy_report.json")
            scan_sbom_table(sbom_file, repo_path / "table_trivy.txt")

            # Compare Trivy results with normalized_deps.json
            norm_deps = repo_path / "normalized_deps.json"
            if norm_deps.exists():
                compare(repo_path / "sbom_p.json", norm_deps)

        # Automatically remove the virtual environment
        remove_venv(venv_path)
        print(f"✅ Virtual environment '{venv_path}' removed automatically.")

    elif language == "Go":
        # Go-specific flow
        print("\n➡ Starting Go-specific flow...")

        # Prepare dependencies
        upgrade_file = prepare_dependencies(repo_path, current_folder)

        # Install deptree and generate dependency tree
        install_deptree()
        deps_file = generate_dependency_tree(repo_path, current_folder)

        # SBOM generation
        sbom_file = generate_go_sbom(repo_path, current_folder)

        # Trivy scan
        trivy_file = scan_trivy(sbom_file, current_folder)

        # Comparison
        comparison_file = current_folder / "comparison.txt"
        generate_comparison(deps_file, sbom_file, comparison_file)

        print("\n🎉 All steps completed successfully!")
        print(f"Dependency tree: {deps_file}")
        print(f"SBOM: {sbom_file}")
        print(f"Trivy report: {trivy_file}")
        print(f"Comparison: {comparison_file}")

    elif language == "Java" and manager == "maven":
        print("\n➡ Starting Java/Maven-specific flow...")

        install_dir = current_folder / "maven_setup"
        install_dir.mkdir(exist_ok=True)
        zip_path = download_maven(install_dir)
        maven_home = extract_maven(zip_path, install_dir)

        # Generate SBOM
        run_maven_sbom(maven_home, repo_path)
        sbom_path = copy_sbom(repo_path)
        print(f"✅ SBOM generated at: {sbom_path}")

        # Scan SBOM with Trivy
        scan_maven_sbom(sbom_path, repo_path)

    else:
        print(f"⚠️ Unsupported language: {language}. No specific flow defined.")


if __name__ == "__main__":
    main()
