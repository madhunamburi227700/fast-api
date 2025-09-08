import os
import subprocess
import platform

def install_dependencies(env_name, project_path):
    system = platform.system()
    env_path = os.path.join(os.getcwd(), env_name)
    bin_dir = "Scripts" if system == "Windows" else "bin"
    python_exec = os.path.join(env_path, bin_dir, "python.exe" if system == "Windows" else "python")
    pip_exec = os.path.join(env_path, bin_dir, "pip.exe" if system == "Windows" else "pip")
    pipgrip_exec = os.path.join(env_path, bin_dir, "pipgrip.exe" if system == "Windows" else "pipgrip")

    # Install pipgrip
    print("\n🔧 Installing pipgrip inside the virtual environment...")
    try:
        subprocess.run(["uv", "pip", "install", "--upgrade", "pip", "pipgrip", "--python", python_exec], check=True)
    except subprocess.CalledProcessError:
        subprocess.run([python_exec, "-m", "pip", "install", "--upgrade", "pip", "pipgrip"], check=True)

    # Determine how to call pipgrip
    if os.path.exists(pipgrip_exec):
        pipgrip_cmd = [pipgrip_exec]
    else:
        # fallback for Windows: call the CLI module directly
        pipgrip_cmd = [python_exec, "-m", "pipgrip.cli"]

    # Locate dependency files
    venv_dirs = {"venv", ".venv", "env", ".env"}
    site_packages_dirs = {"Lib", "lib", "site-packages"}

    pyproject_files = []
    requirements_files = []

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in venv_dirs and not any(sp in root for sp in site_packages_dirs)]
        if "pyproject.toml" in files:
            pyproject_files.append(os.path.join(root, "pyproject.toml"))
        if "requirements.txt" in files:
            requirements_files.append(os.path.join(root, "requirements.txt"))

    # Process pyproject.toml
    if pyproject_files:
        for pyproject in pyproject_files:
            subprocess.run(["uv", "pip", "compile", "--all-extras", pyproject, "-o", "all-dep.txt"], check=True)
            subprocess.run(pipgrip_cmd + ["--tree-json-exact", "-r", "all-dep.txt"], stdout=open("dets.json", "w"), check=True)
    # Process requirements.txt
    elif requirements_files:
        for req_file in requirements_files:
            with open(req_file) as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            if not lines:
                continue
            subprocess.run(["uv", "pip", "compile", req_file, "-o", "all-dep.txt"], check=True)
            subprocess.run(pipgrip_cmd + ["--tree-json-exact", "-r", "all-dep.txt"], stdout=open("dets.json", "w"), check=True)
