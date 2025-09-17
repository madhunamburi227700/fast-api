from __future__ import annotations
import os
import json
import shutil
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

# -------------------- IMPORT HELPERS --------------------
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
from maven_generate_sbom import run_maven_sbom, copy_sbom
from maven_setup import download_maven, extract_maven
from maven_trivy_scan import scan_sbom as scan_maven_sbom

# -------------------- FASTAPI APP --------------------
app = FastAPI(title="SBOM Scanner API", version="3.0.0")

JOBS: Dict[str, Dict[str, Any]] = {}
BASE_DIR = Path(os.getcwd()).resolve()
JOBS_DIR = BASE_DIR / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)

# -------------------- Pydantic Models --------------------
class ScanRequest(BaseModel):
    id: str = Field(..., description="Unique job ID")
    giturl: str = Field(..., description="Git repo URL with optional branch")

class ScanStatus(BaseModel):
    id: str
    status: str
    language: Optional[str] = None
    dependency_manager: Optional[str] = None
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    report: Optional[Dict[str, Any]] = None

# -------------------- UTILS --------------------
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

class WorkDir:
    def __init__(self, path: Path):
        self.path = path
        self._prev = Path.cwd()

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=True)
        os.chdir(self.path)
        return self.path

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.chdir(self._prev)

# -------------------- PIPELINE --------------------
def run_pipeline(repo_with_branch: str, job_dir: Path) -> Dict[str, Any]:
    env_name = "sbom-env"
    artifacts: Dict[str, Any] = {}
    results: Dict[str, Any] = {}

    with WorkDir(job_dir):
        # Detect OS
        artifacts["system"] = detect_os()

        # Clone repo
        repo_path = Path(clone_and_checkout(repo_with_branch)).resolve()
        artifacts["repo_path"] = str(repo_path)

        # Detect language + dependency manager
        language = detect_language(repo_path)
        manager = detect_dependency_manager(repo_path, language)
        artifacts["language"] = language
        artifacts["dependency_manager"] = manager

        current_folder = Path.cwd()

        # Initialize artifact paths
        artifacts.update({
            "venv_path": None,
            "normalized_deps_path": None,
            "dep_file_path": None,
            "sbom_path": None,
            "trivy_json_path": None,
            "trivy_cyclonedx_path": None,
            "trivy_table_path": None,
            "deps_file": None,
            "comparison_file": None
        })

        # -------------------- PYTHON FLOW --------------------
        if language == "Python":
            venv_path = setup(env_name, repo_path)
            artifacts["venv_path"] = venv_path
            install_dependencies(env_name, repo_path)

            # Normalize dets.json
            dets_file = repo_path / "dets.json"
            if dets_file.exists():
                convert_json(dets_file, repo_path / "normalized_deps.json")
                artifacts["normalized_deps_path"] = str((repo_path / "normalized_deps.json").resolve())

            # Dependency file
            dep_file = next((repo_path / f for f in ["all-dep.txt", "a.txt"] if (repo_path / f).exists()), None)
            if dep_file:
                artifacts["dep_file_path"] = str(dep_file)
                generate_python_sbom(env_name, dep_file, repo_path / "sbom.json")
                artifacts["sbom_path"] = str((repo_path / "sbom.json").resolve())

                # Trivy scan
                sbom_p = repo_path / "sbom_p.json"
                trivy_json = repo_path / "trivy_report.json"
                table_trivy = repo_path / "table_trivy.txt"

                scan_sbom_cyclonedx(repo_path / "sbom.json", sbom_p)
                scan_sbom_json(repo_path / "sbom.json", trivy_json)
                scan_sbom_table(repo_path / "sbom.json", table_trivy)

                artifacts["trivy_cyclonedx_path"] = str(sbom_p.resolve())
                artifacts["trivy_json_path"] = str(trivy_json.resolve())
                artifacts["trivy_table_path"] = str(table_trivy.resolve())

                # Load Trivy & CycloneDX results
                try:
                    results["trivy_report_json"] = json.loads(trivy_json.read_text("utf-8"))
                except Exception:
                    results["trivy_report_json"] = None
                try:
                    results["trivy_cyclonedx_json"] = json.loads(sbom_p.read_text("utf-8"))
                except Exception:
                    results["trivy_cyclonedx_json"] = None

                # Compare normalized
                if artifacts["normalized_deps_path"]:
                    compare(sbom_p, repo_path / "normalized_deps.json")

            remove_venv(venv_path)

        # -------------------- GO FLOW --------------------
        elif language == "Go":
            upgrade_file = prepare_dependencies(repo_path, current_folder)
            install_deptree()
            deps_file = generate_dependency_tree(repo_path, current_folder)
            sbom_file = generate_go_sbom(repo_path, current_folder)

            # Trivy scan
            trivy_file = scan_trivy(sbom_file, current_folder)  # This generates sbom_trivy.json
            trivy_cyclonedx_file = current_folder / "sbom_trivy_cyclonedx.json"  # Assuming scan_trivy creates this

            # Generate comparison
            comparison_file = current_folder / "comparison.txt"
            generate_comparison(deps_file, sbom_file, comparison_file)

            # Update artifacts
            artifacts.update({
                "deps_file": str(deps_file),
                "sbom_path": str(sbom_file),
                "trivy_json_path": str(trivy_file),
                "trivy_cyclonedx_path": str(trivy_cyclonedx_file),
                "comparison_file": str(comparison_file)
            })

            # Load Trivy results into results
            try:
                results["trivy_report_json"] = json.loads(trivy_file.read_text("utf-8"))
            except Exception:
                results["trivy_report_json"] = None

            try:
                results["trivy_cyclonedx_json"] = json.loads(trivy_cyclonedx_file.read_text("utf-8"))
            except Exception:
                results["trivy_cyclonedx_json"] = None


        # -------------------- JAVA / MAVEN FLOW --------------------
        elif language == "Java" and manager == "maven":
            install_dir = current_folder / "maven_setup"
            install_dir.mkdir(exist_ok=True)
            zip_path = download_maven(install_dir)
            maven_home = extract_maven(zip_path, install_dir)
            run_maven_sbom(maven_home, repo_path)
            sbom_path = copy_sbom(repo_path)
            scan_maven_sbom(sbom_path, repo_path)
            artifacts.update({"sbom_path": str(sbom_path)})

        else:
            artifacts["error"] = f"Unsupported language: {language}"

    report = {
        "repo": repo_with_branch,
        "artifacts": artifacts,
        "results": results,
        "generated_at": now_iso()
    }

    (job_dir / "report.json").write_text(json.dumps(report, indent=2), "utf-8")
    return report

# -------------------- BACKGROUND TASK --------------------
def _process_job(job_id: str, giturl: str):
    job_dir = JOBS_DIR / job_id
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["started_at"] = now_iso()
    try:
        report = run_pipeline(giturl, job_dir)
        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["finished_at"] = now_iso()
        JOBS[job_id]["report_path"] = str((job_dir / "report.json").resolve())
        JOBS[job_id]["error"] = None
    except Exception:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["finished_at"] = now_iso()
        err = traceback.format_exc()
        JOBS[job_id]["error"] = err
        (job_dir / "error.txt").write_text(err, "utf-8")

# -------------------- API ENDPOINTS --------------------
@app.post("/api/scan_repo", response_model=ScanStatus)
def scan_repo(req: ScanRequest, background: BackgroundTasks):
    job_id = req.id
    if job_id in JOBS and JOBS[job_id]["status"] in {"pending", "running"}:
        raise HTTPException(status_code=409, detail=f"Job '{job_id}' already exists")
    JOBS[job_id] = {
        "status": "pending",
        "started_at": None,
        "finished_at": None,
        "error": None,
        "report_path": None
    }
    background.add_task(_process_job, job_id, req.giturl)
    return ScanStatus(id=job_id, status="pending")

@app.get("/api/getReport", response_model=ScanStatus)
def get_report(ID: str = Query(..., description="Job ID")):
    job_id = ID
    if job_id not in JOBS:
        job_dir = JOBS_DIR / job_id
        report_path = job_dir / "report.json"
        error_path = job_dir / "error.txt"
        if report_path.exists():
            report = json.loads(report_path.read_text("utf-8"))
            return ScanStatus(id=job_id, status="completed", report=report)
        if error_path.exists():
            return ScanStatus(id=job_id, status="failed", error=error_path.read_text("utf-8"))
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    record = JOBS[job_id]
    report: Optional[Dict[str, Any]] = None
    if record.get("report_path") and Path(record["report_path"]).exists():
        report = json.loads(Path(record["report_path"]).read_text("utf-8"))
    return ScanStatus(
        id=job_id,
        status=record["status"],
        language=report.get("artifacts", {}).get("language") if report else None,
        dependency_manager=report.get("artifacts", {}).get("dependency_manager") if report else None,
        started_at=record.get("started_at"),
        finished_at=record.get("finished_at"),
        error=record.get("error"),
        report=report
    )

@app.delete("/api/job/{job_id}")
def delete_job(job_id: str):
    job_dir = JOBS_DIR / job_id
    if job_id in JOBS:
        if JOBS[job_id]["status"] in {"running", "pending"}:
            raise HTTPException(status_code=400, detail="Cannot delete a running job")
        JOBS.pop(job_id, None)
    if job_dir.exists():
        shutil.rmtree(job_dir)
    return {"ok": True}
