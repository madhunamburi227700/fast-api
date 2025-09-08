import os
import subprocess
import shutil
import platform

def setup(env_name="sbom-env", project_path=None):
    """
    Create a virtual environment using uv.
    Returns the path to the created venv.
    """
    if not project_path:
        project_path = os.getcwd()

    venv_path = os.path.join(project_path, env_name)

    # Step 1: Check Python version
    print("\n=== Step 1: Check Python version ===")
    subprocess.run(["python", "--version"], check=True)

    # Step 2: Create venv using uv
    if not os.path.exists(venv_path):
        print(f"\n=== Step 2: Creating venv '{env_name}' with uv ===")
        subprocess.run(["uv", "venv", venv_path], check=True)
    else:
        print(f"\n✔ Virtual environment already exists at: {venv_path}")

    # Step 3: Find the Python executable inside the venv
    system = platform.system()
    python_exec = os.path.join(
        venv_path,
        "Scripts" if system == "Windows" else "bin",
        "python.exe" if system == "Windows" else "python"
    )

    print(f"\n✔ Virtual environment ready. Python executable: {python_exec}")
    return venv_path


def remove_venv(venv_path):
    if os.path.exists(venv_path):
        print(f"\n🗑 Removing virtual environment at: {venv_path}")
        shutil.rmtree(venv_path, ignore_errors=True)
        print("✔ Virtual environment removed successfully.")
    else:
        print(f"\n⚠️ Virtual environment not found at: {venv_path}")
