import os
import json

def load_dependencies_from_json(file_path):
    """Load dependencies directly from pipgrip's --tree-json-exact output."""
    if not os.path.exists(file_path):
        print(f"❌ Error: File '{file_path}' not found.")
        return {}

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"❌ Error: File '{file_path}' is not valid JSON.")
        return {}

    return data  # dict with "pkg==version": {deps...}


def convert_json(json_input="dets.json", json_output="normalized_deps.json"):
    """
    Convert pipgrip JSON output (tree-json-exact) into normalized format:
    {
      "dependencies": [
        {
          "package_name": "foo",
          "installed_version": "1.2.3",
          "required_version": "Any",
          "dependencies": [...]
        }
      ]
    }
    """
    raw_data = load_dependencies_from_json(json_input)

    def normalize(node_dict):
        deps = []
        for key, subdeps in node_dict.items():
            # key looks like "package==1.2.3"
            if "==" in key:
                pkg, ver = key.split("==", 1)
            else:
                pkg, ver = key, ""

            deps.append({
                "package_name": pkg,
                "installed_version": ver,
                "required_version": "Any",
                "dependencies": normalize(subdeps) if isinstance(subdeps, dict) else []
            })
        return deps

    normalized = normalize(raw_data)

    with open(json_output, "w", encoding="utf-8") as f:
        json.dump({"dependencies": normalized}, f, indent=2)

    print(f"✅ Normalized dependencies saved to {json_output}")
    return normalized

