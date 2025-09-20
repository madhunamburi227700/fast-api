import shutil
import subprocess
import platform
from pathlib import Path

def get_mvn_path() -> Path:
    """
    Find system-installed Maven on Windows, Linux, or macOS.
    Returns Path to mvn/mvn.cmd if available.
    """
    mvn_bin = "mvn.cmd" if platform.system() == "Windows" else "mvn"
    mvn_path = shutil.which(mvn_bin)

    if not mvn_path:
        raise FileNotFoundError(
            f"❌ Maven not found on PATH. Please install Maven and ensure '{mvn_bin}' is available."
        )

    # verify it works
    result = subprocess.run([mvn_path, "-v"], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"❌ Maven found at {mvn_path} but failed to run.")

    print(f"✅ Using system Maven: {mvn_path}")
    print(result.stdout.splitlines()[0])
    return Path(mvn_path)
