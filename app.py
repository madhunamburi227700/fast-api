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

# -------------------- HELPERS --------------------
from os_detect import detect_os
from git_repo import clone_and_checkout
from venv_manager import setup, remove_venv
from deps import install_dependencies
from dep_convert import convert_json
from cyclo import generate_sbom as generate_python_sbom
from trivy import scan_sbom_cyclonedx, scan_sbom_json, scan_sbom_table
from compare_trivy_dep import compare
from language_detector import detect_language, detect_dependency_manager

# Go helpers
from clone_repo import clone_repo
from golang_check import is_golang_project
from go_dependency_tree import prepare_dependencies, install_deptree, generate_dependency_tree
from sbom_generator import generate_sbom as generate_go_sbom
from go_trivy_scan import scan_trivy
from go_compare import generate_comparison

# -------------------- FASTAPI APP --------------------
app = FastAPI(title="SBOM Scanner API", version="2.0.0")

JOBS: Dict[str, Dict[str, Any]] = {}
BASE_DIR = Path(os.getcwd()).resolve()
JOBS_DIR = BASE_DIR / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)


class ScanRequest(BaseModel):
    id: str = Field(..., description="Unique job ID for tracking.")
    giturl: str = Field(
        ...,
        description="Git repo URL with optional branch (e.g. https://github.com/user/repo.git@branch)",
    )


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
class WorkDir:
    """Context manager to temporarily chdir into a directory and restore afterward."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self._prev = Path.cwd()

    def __enter__(self):
        self.path.mkdir(parents=True, exist_ok=True)
        os.chdir(self.path)
        return self.path

    def __exit__(self, exc_type, exc, tb):
        os.chdir(self._prev)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# -------------------- CORE PIPELINE WRAPPER --------------------
def _safe_load_json(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return None


def run_scan_pipeline(repo_with_branch: str, job_dir: Path) -> Dict[str, Any]:
    """
    Unified pipeline for Python & Go repos.
    All side-effect files are written inside job_dir.
    Final report includes file paths and parsed JSON results where available.
    """
    env_name = "sbom-env"
    artifacts: Dict[str, Any] = {}
    results: Dict[str, Any] = {}
    result_files: Dict[str, str] = {}

    # Ensure job_dir exists
    job_dir.mkdir(parents=True, exist_ok=True)

    with WorkDir(job_dir):
        # Step 1: Detect OS
        system = detect_os()
        artifacts["system"] = system

        # Step 2: Clone repo (clone_and_checkout will create a folder inside job_dir)
        repo_path = Path(clone_and_checkout(repo_with_branch)).resolve()
        artifacts["repo_path"] = str(repo_path)

        # Step 3: Detect language and dependency manager
        language = detect_language(str(repo_path))
        manager = detect_dependency_manager(str(repo_path), language)
        artifacts["language"] = language
        artifacts["dependency_manager"] = manager

        # Initialize common paths (they will be created in CWD which is job_dir)
        sbom_path = job_dir / "sbom.json"
        sbom_p_path = job_dir / "sbom_p.json"  # cyclonedx processed
        trivy_json_path = job_dir / "trivy_report.json"
        trivy_table_path = job_dir / "table_trivy.txt"
        normalized_deps_path = job_dir / "normalized_deps.json"
        comparison_path = job_dir / "comparison.txt"

        # -------------------- PYTHON FLOW --------------------
        if language == "Python":
            # venv + install
            venv_path = setup(env_name=env_name, project_path=str(repo_path))
            artifacts["venv_path"] = venv_path
            install_dependencies(env_name, str(repo_path))

            # Normalize dets.json -> normalized_deps.json if present (dets.json created by your pipeline)
            if Path("dets.json").exists():
                convert_json("dets.json", str(normalized_deps_path))
                artifacts["normalized_deps_path"] = str(normalized_deps_path.resolve())
            else:
                artifacts["normalized_deps_path"] = None

            # Generate SBOM from dependency file if present
            dep_file = None
            for f in ["all-dep.txt", "a.txt"]:
                if Path(f).exists():
                    dep_file = f
                    break
            if dep_file:
                generate_python_sbom(env_name, dep_file, str(sbom_path.name))
                artifacts["sbom_path"] = str(sbom_path.resolve())
                result_files["sbom"] = str(sbom_path.resolve())
            else:
                artifacts["sbom_path"] = None

            # Trivy scans (cyclonedx + json + table)
            if sbom_path.exists():
                scan_sbom_cyclonedx(str(sbom_path.name), str(sbom_p_path.name))
                scan_sbom_json(str(sbom_path.name), str(trivy_json_path.name))
                scan_sbom_table(str(sbom_path.name), str(trivy_table_path.name))

                artifacts["trivy_table_path"] = str(trivy_table_path.resolve())
                artifacts["sbom_cyclonedx_path"] = str(sbom_p_path.resolve())
                artifacts["trivy_json_path"] = str(trivy_json_path.resolve())

                # Load JSON results where possible
                results["trivy_report_json"] = _safe_load_json(trivy_json_path)
                results["trivy_cyclonedx_json"] = _safe_load_json(sbom_p_path)

                result_files["trivy_report_json"] = str(trivy_json_path.resolve())
                result_files["trivy_cyclonedx_json"] = str(sbom_p_path.resolve())
                result_files["trivy_table"] = str(trivy_table_path.resolve())

                # Comparison (if normalized_deps.json exists) - compare may write out or return stuff
                if normalized_deps_path.exists():
                    try:
                        # If compare writes to stdout/file, try to detect/output file
                        compare(str(sbom_p_path.name), str(normalized_deps_path.name))
                    except Exception:
                        # ignore compare exceptions but continue
                        pass

                    # try to find common comparison outputs
                    if comparison_path.exists():
                        artifacts["comparison_path"] = str(comparison_path.resolve())
                        result_files["comparison"] = str(comparison_path.resolve())
                    else:
                        # place a marker if compare didn't generate a file
                        artifacts["comparison_path"] = None
                else:
                    artifacts["comparison_path"] = None
            else:
                artifacts["trivy_table_path"] = None
                artifacts["trivy_json_path"] = None
                artifacts["sbom_cyclonedx_path"] = None
                results["trivy_report_json"] = None
                results["trivy_cyclonedx_json"] = None

        # -------------------- GO FLOW --------------------
        elif language == "Go":
            current_folder = Path(os.getcwd())

            # Prepare dependencies and generate dependency tree
            try:
                upgrade_file = prepare_dependencies(str(repo_path), current_folder)
                artifacts["prepared_dependencies"] = str(Path(upgrade_file).resolve()) if upgrade_file else None
            except Exception:
                artifacts["prepared_dependencies"] = None

            install_deptree()
            deps_file = generate_dependency_tree(str(repo_path), current_folder)
            artifacts["deps_file"] = str(Path(deps_file).resolve()) if deps_file else None
            result_files["deps_file"] = artifacts["deps_file"]

            # Generate Go SBOM
            sbom_file = generate_go_sbom(str(repo_path), current_folder)
            artifacts["sbom_path"] = str(Path(sbom_file).resolve()) if sbom_file else None
            if sbom_file:
                result_files["sbom"] = str(Path(sbom_file).resolve())

            # Trivy scan for Go SBOM
            try:
                trivy_out = scan_trivy(str(sbom_file), current_folder)  # expected to return path
                artifacts["trivy_json_path"] = str(Path(trivy_out).resolve()) if trivy_out else None
                result_files["trivy_report_json"] = artifacts["trivy_json_path"]
                results["trivy_report_json"] = _safe_load_json(Path(trivy_out)) if trivy_out else None
            except Exception:
                artifacts["trivy_json_path"] = None
                results["trivy_report_json"] = None

            # Comparison
            comp_file = current_folder / "comparison.txt"
            try:
                generate_comparison(str(deps_file), str(sbom_file), str(comp_file))
            except Exception:
                pass
            if comp_file.exists():
                artifacts["comparison_path"] = str(comp_file.resolve())
                result_files["comparison"] = str(comp_file.resolve())
            else:
                artifacts["comparison_path"] = None

        else:
            artifacts["unsupported"] = True

    # Aggregate final report: include artifact paths and parsed results (if any)
    report: Dict[str, Any] = {
        "repo": repo_with_branch,
        "artifacts": artifacts,
        "result_files": result_files,  # explicit mapping of result file names -> absolute paths
        "results": results,  # parsed JSON outputs for convenience (when available)
        "generated_at": now_iso(),
    }

    # Persist report.json for GET retrieval
    report_path = job_dir / "report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    # also return path in artifacts for convenience
    report["report_path"] = str(report_path.resolve())
    return report


# -------------------- BACKGROUND TASK --------------------
def _process_job(job_id: str, giturl: str):
    job_dir = JOBS_DIR / job_id
    JOBS[job_id] = JOBS.get(job_id, {})
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["started_at"] = now_iso()

    try:
        report = run_scan_pipeline(giturl, job_dir)
        JOBS[job_id]["status"] = "completed"
        JOBS[job_id]["finished_at"] = now_iso()
        JOBS[job_id]["report_path"] = report.get("report_path")
        JOBS[job_id]["error"] = None
    except Exception:
        JOBS[job_id]["status"] = "failed"
        JOBS[job_id]["finished_at"] = now_iso()
        err = traceback.format_exc()
        JOBS[job_id]["error"] = err
        (job_dir / "error.txt").write_text(err, encoding="utf-8")


# -------------------- ENDPOINTS --------------------
@app.post("/api/scan_repo", response_model=ScanStatus)
def scan_repo(req: ScanRequest, background: BackgroundTasks):
    job_id = req.id

    # Reject duplicate active IDs
    if job_id in JOBS and JOBS[job_id].get("status") in {"pending", "running"}:
        raise HTTPException(
            status_code=409, detail=f"Job '{job_id}' already exists and is {JOBS[job_id]['status']}"
        )

    # Initialize job record
    JOBS[job_id] = {
        "status": "pending",
        "started_at": None,
        "finished_at": None,
        "error": None,
        "report_path": None,
    }

    # Start background processing
    background.add_task(_process_job, job_id, req.giturl)

    return ScanStatus(id=job_id, status="pending")


@app.get("/api/getReport", response_model=ScanStatus)
def get_report(ID: str = Query(..., description="Job ID")):
    job_id = ID

    # If job not in memory, try to load from disk
    if job_id not in JOBS:
        job_dir = JOBS_DIR / job_id
        report_path = job_dir / "report.json"
        error_path = job_dir / "error.txt"
        if report_path.exists():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            artifacts = report.get("artifacts", {})
            return ScanStatus(
                id=job_id,
                status="completed",
                language=artifacts.get("language"),
                dependency_manager=artifacts.get("dependency_manager"),
                report=report,
            )
        if error_path.exists():
            return ScanStatus(id=job_id, status="failed", error=error_path.read_text(encoding="utf-8"))
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    record = JOBS[job_id]
    report: Optional[Dict[str, Any]] = None
    language: Optional[str] = None
    dependency_manager: Optional[str] = None

    if record.get("report_path") and Path(record["report_path"]).exists():
        try:
            report = json.loads(Path(record["report_path"]).read_text(encoding="utf-8"))
            artifacts = report.get("artifacts", {})
            language = artifacts.get("language")
            dependency_manager = artifacts.get("dependency_manager")
        except Exception:
            report = None

    return ScanStatus(
        id=job_id,
        status=record.get("status", "unknown"),
        language=language,
        dependency_manager=dependency_manager,
        started_at=record.get("started_at"),
        finished_at=record.get("finished_at"),
        error=record.get("error"),
        report=report,
    )


# -------------------- OPTIONAL CLEANUP ENDPOINTS --------------------
@app.delete("/api/job/{job_id}")
def delete_job(job_id: str):
    """Delete a job's files and in-memory record."""
    job_dir = JOBS_DIR / job_id
    if job_id in JOBS:
        if JOBS[job_id].get("status") in {"running", "pending"}:
            raise HTTPException(status_code=400, detail="Cannot delete a running job")
        JOBS.pop(job_id, None)

    if job_dir.exists():
        shutil.rmtree(job_dir)
    return {"ok": True}
