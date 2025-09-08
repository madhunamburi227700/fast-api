import json
import re

def normalize_name(name):
    name = name.lower().replace("_", ".").replace("-", ".")
    name = re.sub(r"\.+", ".", name)
    return name.strip(".")

def load_sbom(sbom_file):
    """Load SBOM JSON and return dict: normalized package name -> version"""
    with open(sbom_file, encoding="utf-8") as f:
        data = json.load(f)

    result = {}
    for comp in data.get("components", []):
        name = comp.get("name")
        version = comp.get("version")
        if name and version:
            result[normalize_name(name)] = version
    return result

def load_deps(deps_file):
    """Load dependency JSON and return dict: normalized package name -> version"""
    with open(deps_file, encoding="utf-8") as f:
        data = json.load(f)

    result = {}

    def walk(deps):
        for dep in deps:
            pkg_name = dep.get("package_name") or dep.get("name") or "unknown"
            pkg_ver = dep.get("installed_version") or dep.get("version")
            if pkg_name and pkg_ver:
                result[normalize_name(pkg_name)] = pkg_ver

            # Recurse into nested dependencies
            if "dependencies" in dep and dep["dependencies"]:
                walk(dep["dependencies"])

    walk(data.get("dependencies", []))
    return result

def compare(sbom_file, deps_file, output_file="comparison.txt"):
    sbom = load_sbom(sbom_file)
    deps = load_deps(deps_file)

    missing_in_sbom = []
    version_mismatches = []
    exact_matches = []

    for pkg, dep_ver in deps.items():
        sbom_ver = sbom.get(pkg)
        if sbom_ver is None:
            missing_in_sbom.append(pkg)
        elif sbom_ver != dep_ver:
            version_mismatches.append((pkg, dep_ver, sbom_ver))
        else:
            exact_matches.append((pkg, dep_ver))

    with open(output_file, "w", encoding="utf-8") as f:
        f.write("====== Missing in SBOM ========\n")
        f.write("\n".join(f"- {pkg}" for pkg in missing_in_sbom) or "None")
        f.write("\n\n====== Version mismatches ========\n")
        f.write("\n".join(f"- {pkg}: deps={dep_v}, sbom={sbom_v}" 
                          for pkg, dep_v, sbom_v in version_mismatches) or "None")
        f.write("\n\n====== Exact matches ========\n")
        f.write("\n".join(f"- {pkg}: {ver}" for pkg, ver in exact_matches) or "None")

    print(f"Comparison results saved in '{output_file}'")

