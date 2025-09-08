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

# -------------------- YOUR EXISTING HELPERS --------------------
# These come from your current project. Make sure they are importable.
from os_detect import detect_os
from git_repo import clone_and_checkout
from venv_manager import setup, remove_venv
from deps import install_dependencies
from dep_convert import convert_json
from cyclo import generate_sbom
from trivy import scan_sbom_cyclonedx, scan_sbom_json, scan_sbom_table
from compare_trivy_dep import compare
from language_detector import detect_language, detect_dependency_manager


# -------------------- FASTAPI APP --------------------
app = FastAPI(title="SBOM Scanner API", version="1.0.0")

JOBS: Dict[str, Dict[str, Any]] = {}
BASE_DIR = Path(os.getcwd()).resolve()
JOBS_DIR = BASE_DIR / "jobs"
JOBS_DIR.mkdir(parents=True, exist_ok=True)


class ScanRequest(BaseModel):
    id: str = Field(..., description="Unique job ID for tracking.")
    giturl: str = Field(
        ..., description="Git repo URL with optional branch (e.g. https://github.com/user/repo.git@branch)"
    )


class ScanStatus(BaseModel):
    id: str
    status: str
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
def run_scan_pipeline(repo_with_branch: str, job_dir: Path) -> Dict[str, Any]:
    """
    Wraps your CLI pipeline into a function that returns a JSON report.
    All side-effect files are written inside job_dir to avoid collisions.
    """
    env_name = "sbom-env"
    artifacts: Dict[str, Any] = {}

    with WorkDir(job_dir):
        # Step 1: Detect OS
        system = detect_os()
        artifacts["system"] = system

        # Step 2: Clone repo
        repo_path = Path(clone_and_checkout(repo_with_branch)).resolve()
        artifacts["repo_path"] = str(repo_path)

        # Step 3: Detect language and dependency manager
        language = detect_language(str(repo_path))
        manager = detect_dependency_manager(str(repo_path), language)
        artifacts["language"] = language
        artifacts["dependency_manager"] = manager

        # Step 4 & 5: Python venv + install deps (only if Python)
        venv_path: Optional[str] = None
        if language == "Python":
            venv_path = setup(env_name=env_name, project_path=str(repo_path))
            install_dependencies(env_name, str(repo_path))
            artifacts["venv_path"] = venv_path

        # Step 6: Normalize dets.json → normalized_deps.json (optional)
        if Path("dets.json").exists():
            convert_json("dets.json", "normalized_deps.json")
            artifacts["normalized_deps_path"] = str((job_dir / "normalized_deps.json").resolve())
        else:
            artifacts["normalized_deps_path"] = None

        # Step 7: Generate SBOM if dep file exists
        dep_file = None
        for f in ["all-dep.txt", "a.txt"]:
            if Path(f).exists():
                dep_file = f
                break

        if dep_file:
            generate_sbom(env_name, dep_file, "sbom.json")
            artifacts["sbom_path"] = str((job_dir / "sbom.json").resolve())
        else:
            artifacts["sbom_path"] = None

        # Step 8: Scan SBOM with Trivy
        trivy_json: Optional[Dict[str, Any]] = None
        trivy_cyclonedx: Optional[Dict[str, Any]] = None

        if Path("sbom.json").exists():
            scan_sbom_cyclonedx("sbom.json", "sbom_p.json")
            scan_sbom_json("sbom.json", "trivy_report.json")
            scan_sbom_table("sbom.json", "table_trivy.txt")

            artifacts["trivy_table_path"] = str((job_dir / "table_trivy.txt").resolve())

            # Load JSON outputs (best-effort)
            try:
                trivy_json = json.loads(Path("trivy_report.json").read_text("utf-8"))
            except Exception:
                trivy_json = None
            try:
                trivy_cyclonedx = json.loads(Path("sbom_p.json").read_text("utf-8"))
            except Exception:
                trivy_cyclonedx = None
        else:
            artifacts["trivy_table_path"] = None

        # Step 9: Compare Trivy results with normalized_deps.json (optional)
        compare_result: Optional[Any] = None
        if Path("sbom_p.json").exists() and Path("normalized_deps.json").exists():
            try:
                # If your compare() returns data, capture it; if it writes files/prints, that's fine.
                compare_result = compare("sbom_p.json", "normalized_deps.json")
            except Exception as e:
                compare_result = {"error": str(e)}

        # Step 10: DO NOT remove venv automatically inside the API; caller can clean later.

    # Aggregate final report
    report: Dict[str, Any] = {
        "repo": repo_with_branch,
        "artifacts": artifacts,
        "results": {
            "trivy_report_json": trivy_json,
            "trivy_cyclonedx_json": trivy_cyclonedx,
            "compare_result": compare_result,
        },
        "generated_at": now_iso(),
    }

    # Persist report.json for GET retrieval
    (job_dir / "report.json").write_text(json.dumps(report, indent=2), "utf-8")
    return report


# -------------------- BACKGROUND TASK --------------------

def _process_job(job_id: str, giturl: str):
    job_dir = JOBS_DIR / job_id
    JOBS[job_id]["status"] = "running"
    JOBS[job_id]["started_at"] = now_iso()

    try:
        report = run_scan_pipeline(giturl, job_dir)
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


# -------------------- ENDPOINTS --------------------
@app.post("/api/scan_repo", response_model=ScanStatus)
def scan_repo(req: ScanRequest, background: BackgroundTasks):
    job_id = req.id

    # Reject duplicate active IDs
    if job_id in JOBS and JOBS[job_id]["status"] in {"pending", "running"}:
        raise HTTPException(status_code=409, detail=f"Job '{job_id}' already exists and is {JOBS[job_id]['status']}")

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

    return ScanStatus(id=job_id, status="pending", started_at=None, finished_at=None, error=None, report=None)


@app.get("/api/getReport", response_model=ScanStatus)
def get_report(ID: str = Query(..., description="Job ID")):
    job_id = ID

    if job_id not in JOBS:
        # If API was restarted, try loading existing report from disk
        job_dir = JOBS_DIR / job_id
        report_path = job_dir / "report.json"
        error_path = job_dir / "error.txt"
        if report_path.exists():
            report = json.loads(report_path.read_text("utf-8"))
            return ScanStatus(
                id=job_id,
                status="completed",
                started_at=None,
                finished_at=None,
                error=None,
                report=report,
            )
        if error_path.exists():
            return ScanStatus(
                id=job_id,
                status="failed",
                started_at=None,
                finished_at=None,
                error=error_path.read_text("utf-8"),
                report=None,
            )
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")

    # If job exists in memory, include report if completed
    record = JOBS[job_id]
    report: Optional[Dict[str, Any]] = None
    if record.get("report_path") and Path(record["report_path"]).exists():
        try:
            report = json.loads(Path(record["report_path"]).read_text("utf-8"))
        except Exception:
            report = None

    return ScanStatus(
        id=job_id,
        status=record["status"],
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
        if JOBS[job_id]["status"] in {"running", "pending"}:
            raise HTTPException(status_code=400, detail="Cannot delete a running job")
        JOBS.pop(job_id, None)

    if job_dir.exists():
        shutil.rmtree(job_dir)
    return {"ok": True}


# -------------------- HOW TO RUN --------------------
# 1) pip install fastapi uvicorn
# 2) Make sure git and trivy are installed and available on PATH.
# 3) uvicorn app:app --host 0.0.0.0 --port 5000 --reload
# 4) Start a job:
#    curl -X POST http://localhost:5000/api/scan_repo \
#      -H 'Content-Type: application/json' \
#      -d '{"id":"job123","giturl":"https://github.com/user/repo.git@branch"}'
# 5) Poll for report:
#    curl 'http://localhost:5000/api/getReport?ID=job123'
