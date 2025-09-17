import json

def load_dependency_tree(path):
    """Load dependencies from deptree output (t.json)."""
    with open(path, "r") as f:
        content = f.read().strip()
        if not content:
            raise ValueError(f"Dependency tree file {path} is empty")

        # deptree sometimes adds logs before JSON, keep only from first '{'
        if "{" in content:
            content = content[content.index("{") :]
        else:
            raise ValueError(f"No JSON object found in {path}")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {path}: {e}")

    deps = {}

    if not isinstance(data, dict) or "packages" not in data:
        raise ValueError(f"Unexpected JSON format in {path}, expected {{'packages': [...]}}")

    for pkg in data["packages"]:
        # Add the package itself
        name = pkg.get("name")
        if name and "@" in name:
            lib, version = name.rsplit("@", 1)
            deps[lib] = version

        # Add its children
        for child in pkg.get("children", []):
            if "@" in child:
                lib, version = child.rsplit("@", 1)
                deps[lib] = version

    return deps



def load_sbom(path):
    """Load dependencies from CycloneDX SBOM (sbom.json)."""
    with open(path, "r") as f:
        content = f.read().strip()
        if not content:
            raise ValueError(f"SBOM file {path} is empty")

        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {path}: {e}")

    deps = {}
    components = data.get("components", [])
    for comp in components:
        name = comp.get("name")
        version = comp.get("version")
        if name and version:
            deps[name] = version
    return deps


def compare(deptree_deps, sbom_deps):
    missing_in_sbom = []
    version_mismatch = []
    same = []
    extra_in_sbom = []

    for name, ver in deptree_deps.items():
        if name not in sbom_deps:
            missing_in_sbom.append(f"{name}@{ver}")
        else:
            sbom_ver = sbom_deps[name]
            if sbom_ver != ver:
                version_mismatch.append(f"{name} (deptree: {ver}, sbom: {sbom_ver})")
            else:
                same.append(f"{name}@{ver}")

    for name, ver in sbom_deps.items():
        if name not in deptree_deps:
            extra_in_sbom.append(f"{name}@{ver}")

    return missing_in_sbom, version_mismatch, same, extra_in_sbom


def generate_comparison(deptree_file, sbom_file, output_file):
    deptree_deps = load_dependency_tree(deptree_file)
    sbom_deps = load_sbom(sbom_file)
    missing_in_sbom, version_mismatch, same, extra_in_sbom = compare(deptree_deps, sbom_deps)

    with open(output_file, "w") as f:
        f.write("=== Dependencies missing in SBOM ===\n")
        f.write("\n".join(missing_in_sbom) + "\n" if missing_in_sbom else "None\n")

        f.write("\n=== Version mismatches ===\n")
        f.write("\n".join(version_mismatch) + "\n" if version_mismatch else "None\n")

        f.write("\n=== Dependencies same in both ===\n")
        f.write("\n".join(same) + "\n" if same else "None\n")

        f.write("\n=== Extra dependencies in SBOM (not in deptree) ===\n")
        f.write("\n".join(extra_in_sbom) + "\n" if extra_in_sbom else "None\n")

    print(f"📄 Comparison written to {output_file}")
