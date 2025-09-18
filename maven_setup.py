import os
import sys
import platform
import urllib.request
import zipfile

MAVEN_VERSION = "3.9.9"
MAVEN_BASE_URL = f"https://archive.apache.org/dist/maven/maven-3/{MAVEN_VERSION}/binaries"
MAVEN_ZIP = f"apache-maven-{MAVEN_VERSION}-bin.zip"

def download_maven(install_dir: str) -> str:
    zip_path = os.path.join(install_dir, MAVEN_ZIP)
    if os.path.exists(zip_path):
        print(f"📦 Maven zip already exists at {zip_path}")
        return zip_path

    url = f"{MAVEN_BASE_URL}/{MAVEN_ZIP}"
    print(f"⬇️ Downloading Maven {MAVEN_VERSION} from {url} ...")
    try:
        urllib.request.urlretrieve(url, zip_path)
        print("✅ Download complete")
    except Exception as e:
        print(f"❌ Failed to download Maven: {e}")
        sys.exit(1)
    return zip_path

def extract_maven(zip_path: str, install_dir: str) -> str:
    extract_path = os.path.join(install_dir, f"apache-maven-{MAVEN_VERSION}")
    if os.path.exists(extract_path):
        print(f"📂 Maven already extracted at {extract_path}")
        return extract_path

    print(f"📂 Extracting Maven to {install_dir} ...")
    with zipfile.ZipFile(zip_path, "r") as zip_ref:
        zip_ref.extractall(install_dir)

    # Make mvn and all bin files executable (Linux/macOS)
    if platform.system() != "Windows":
        bin_dir = os.path.join(extract_path, "bin")
        if os.path.exists(bin_dir):
            for f in os.listdir(bin_dir):
                os.chmod(os.path.join(bin_dir, f), 0o755)  # rwxr-xr-x

    print("✅ Extraction complete and binaries made executable")
    return extract_path
