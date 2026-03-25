"""
Report & Paper-Ready Export Engine
===================================

Generates publication-quality exports from experiment data:
  - LaTeX tables (copy-paste into papers)
  - CSV structured reports
  - JSON structured reports
  - MITRE ATT&CK mapping exports
"""

import csv
import datetime
import io
import json
import logging
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse, StreamingResponse, JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from auth import require_auth
from database import get_db

logger = logging.getLogger("robustidps.reports")

router = APIRouter(prefix="/api/reports", tags=["Reports"])


# ── MITRE ATT&CK Mapping ────────────────────────────────────────────────

MITRE_MAPPING = {
    "DDoS-TCP_Flood":          {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-UDP_Flood":          {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-ICMP_Flood":         {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-HTTP_Flood":         {"technique": "T1499.002", "tactic": "Impact", "name": "Service Exhaustion Flood"},
    "DDoS-SYN_Flood":          {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-SlowLoris":          {"technique": "T1499.002", "tactic": "Impact", "name": "Service Exhaustion Flood"},
    "DDoS-RSTFIN_Flood":       {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-Pshack_Flood":       {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-ACK_Flood":          {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-UDP_Fragmentation":  {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "DDoS-ICMP_Fragmentation": {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "Recon-PortScan":          {"technique": "T1046",     "tactic": "Discovery", "name": "Network Service Discovery"},
    "Recon-OSScan":            {"technique": "T1082",     "tactic": "Discovery", "name": "System Information Discovery"},
    "Recon-HostDiscovery":     {"technique": "T1018",     "tactic": "Discovery", "name": "Remote System Discovery"},
    "Recon-PingSweep":         {"technique": "T1018",     "tactic": "Discovery", "name": "Remote System Discovery"},
    "BruteForce-SSH":          {"technique": "T1110.001", "tactic": "Credential Access", "name": "Password Guessing"},
    "BruteForce-FTP":          {"technique": "T1110.001", "tactic": "Credential Access", "name": "Password Guessing"},
    "BruteForce-HTTP":         {"technique": "T1110.001", "tactic": "Credential Access", "name": "Password Guessing"},
    "BruteForce-Dictionary":   {"technique": "T1110.002", "tactic": "Credential Access", "name": "Password Cracking"},
    "Spoofing-ARP":            {"technique": "T1557.002", "tactic": "Credential Access", "name": "ARP Cache Poisoning"},
    "Spoofing-DNS":            {"technique": "T1557.002", "tactic": "Credential Access", "name": "DNS Poisoning"},
    "Spoofing-IP":             {"technique": "T1036",     "tactic": "Defense Evasion", "name": "Masquerading"},
    "WebAttack-SQLi":          {"technique": "T1190",     "tactic": "Initial Access", "name": "Exploit Public-Facing App"},
    "WebAttack-XSS":           {"technique": "T1189",     "tactic": "Initial Access", "name": "Drive-by Compromise"},
    "WebAttack-CommandInjection": {"technique": "T1059", "tactic": "Execution", "name": "Command and Scripting Interpreter"},
    "WebAttack-BrowserHijacking": {"technique": "T1185", "tactic": "Collection", "name": "Browser Session Hijacking"},
    "Malware-Backdoor":        {"technique": "T1059.001", "tactic": "Persistence", "name": "Backdoor"},
    "Malware-Ransomware":      {"technique": "T1486",     "tactic": "Impact", "name": "Data Encrypted for Impact"},
    "Malware-Trojan":          {"technique": "T1204.002", "tactic": "Execution", "name": "Malicious File"},
    "DoS-Slowhttptest":        {"technique": "T1499.002", "tactic": "Impact", "name": "Service Exhaustion Flood"},
    "DoS-Hulk":                {"technique": "T1499.002", "tactic": "Impact", "name": "Service Exhaustion Flood"},
    "Mirai-greeth_flood":      {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
    "Mirai-greip_flood":       {"technique": "T1498.001", "tactic": "Impact", "name": "Direct Network Flood"},
}


# ── LaTeX generation helpers ─────────────────────────────────────────────

def _escape_latex(s: str) -> str:
    """Escape special LaTeX characters."""
    for ch in ("\\", "&", "%", "$", "#", "_", "{", "}", "~", "^"):
        s = s.replace(ch, f"\\{ch}" if ch != "\\" else "\\textbackslash{}")
    return s


def _metrics_to_latex_table(experiments: list[dict], metric_keys: list[str]) -> str:
    """Generate a LaTeX tabular comparing experiments on key metrics."""
    n = len(experiments)
    col_spec = "l" + "r" * n
    lines = [
        "% Auto-generated by RobustIDPS.AI — copy into your LaTeX document",
        f"% Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Experiment comparison — RobustIDPS.AI}",
        "\\label{tab:experiment-comparison}",
        f"\\begin{{tabular}}{{{col_spec}}}",
        "\\toprule",
    ]

    # Header row
    header = "\\textbf{Metric}"
    for exp in experiments:
        name = _escape_latex(exp.get("name", exp.get("experiment_id", "?")))
        header += f" & \\textbf{{{name}}}"
    header += " \\\\"
    lines.append(header)
    lines.append("\\midrule")

    # Data rows
    for key in metric_keys:
        row = _escape_latex(key.replace("_", " ").title())
        for exp in experiments:
            val = (exp.get("metrics") or {}).get(key)
            if val is None:
                row += " & --"
            elif isinstance(val, float):
                row += f" & {val:.4f}"
            else:
                row += f" & {val}"
        row += " \\\\"
        lines.append(row)

    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


def _per_class_to_latex(per_class: dict, caption: str = "Per-class classification metrics") -> str:
    """Generate a LaTeX table from per_class_metrics."""
    lines = [
        "% Auto-generated by RobustIDPS.AI",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        f"\\caption{{{_escape_latex(caption)}}}",
        "\\label{tab:per-class-metrics}",
        "\\begin{tabular}{lrrr}",
        "\\toprule",
        "\\textbf{Class} & \\textbf{Precision} & \\textbf{Recall} & \\textbf{F1} \\\\",
        "\\midrule",
    ]
    for cls_name, vals in sorted(per_class.items()):
        if not isinstance(vals, dict):
            continue
        p = vals.get("precision", 0)
        r = vals.get("recall", 0)
        f = vals.get("f1", 0)
        lines.append(f"{_escape_latex(cls_name)} & {p:.4f} & {r:.4f} & {f:.4f} \\\\")

    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


def _confusion_to_latex(matrix: list[list], labels: list[str]) -> str:
    """Generate a LaTeX confusion matrix."""
    n = len(labels)
    col_spec = "l" + "r" * n
    lines = [
        "% Auto-generated by RobustIDPS.AI",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Confusion Matrix}",
        "\\label{tab:confusion-matrix}",
        "\\scriptsize",
        f"\\begin{{tabular}}{{{col_spec}}}",
        "\\toprule",
    ]
    # Header
    header = "\\textbf{True $\\backslash$ Pred}"
    for lbl in labels:
        short = _escape_latex(lbl[:12])
        header += f" & \\rotatebox{{90}}{{\\textbf{{{short}}}}}"
    header += " \\\\"
    lines.append(header)
    lines.append("\\midrule")

    for i, row in enumerate(matrix):
        lbl = _escape_latex(labels[i][:15]) if i < len(labels) else str(i)
        row_str = f"\\textbf{{{lbl}}}"
        for val in row:
            row_str += f" & {val}"
        row_str += " \\\\"
        lines.append(row_str)

    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return "\n".join(lines)


# ── API Endpoints ────────────────────────────────────────────────────────

class LaTeXComparisonRequest(BaseModel):
    experiment_ids: list[str] = Field(..., min_length=2, max_length=6)


@router.post("/latex/comparison", summary="Generate LaTeX comparison table from experiments")
def generate_latex_comparison(
    body: LaTeXComparisonRequest,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    experiments = db.query(Experiment).filter(
        Experiment.experiment_id.in_(body.experiment_ids),
        Experiment.user_id == user.id,
    ).all()

    if len(experiments) < 2:
        raise HTTPException(400, "Need at least 2 valid experiments")

    exp_dicts = []
    all_keys = set()
    for exp in experiments:
        d = {
            "experiment_id": exp.experiment_id,
            "name": exp.name,
            "metrics": exp.metrics or {},
        }
        all_keys.update(d["metrics"].keys())
        exp_dicts.append(d)

    latex = _metrics_to_latex_table(exp_dicts, sorted(all_keys))
    return PlainTextResponse(latex, media_type="text/x-latex")


class LaTeXExperimentRequest(BaseModel):
    experiment_id: str
    include_confusion: bool = True
    include_per_class: bool = True


@router.post("/latex/experiment", summary="Generate LaTeX tables for a single experiment")
def generate_latex_experiment(
    body: LaTeXExperimentRequest,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == body.experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")

    results = exp.results or {}
    sections = []

    # Summary metrics table
    metrics = exp.metrics or {}
    if metrics:
        summary_latex = _metrics_to_latex_table(
            [{"experiment_id": exp.experiment_id, "name": exp.name, "metrics": metrics}],
            sorted(metrics.keys()),
        )
        sections.append(summary_latex)

    # Per-class metrics
    if body.include_per_class and results.get("per_class_metrics"):
        sections.append(_per_class_to_latex(
            results["per_class_metrics"],
            caption=f"Per-class metrics — {exp.name}",
        ))

    # Confusion matrix
    if body.include_confusion and results.get("confusion_matrix") and results.get("class_labels"):
        sections.append(_confusion_to_latex(
            results["confusion_matrix"],
            results["class_labels"],
        ))

    latex = "\n\n".join(sections) if sections else "% No exportable data found in this experiment."
    return PlainTextResponse(latex, media_type="text/x-latex")


class CSVReportRequest(BaseModel):
    experiment_ids: list[str] = Field(..., min_length=1, max_length=20)


@router.post("/csv", summary="Export experiments as a structured CSV report")
def generate_csv_report(
    body: CSVReportRequest,
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    experiments = db.query(Experiment).filter(
        Experiment.experiment_id.in_(body.experiment_ids),
        Experiment.user_id == user.id,
    ).all()
    if not experiments:
        raise HTTPException(404, "No experiments found")

    # Collect all metric keys
    all_keys = set()
    for exp in experiments:
        all_keys.update((exp.metrics or {}).keys())
    metric_keys = sorted(all_keys)

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    header = ["experiment_id", "name", "task_type", "model", "dataset", "created_at"] + metric_keys
    writer.writerow(header)

    for exp in experiments:
        metrics = exp.metrics or {}
        row = [
            exp.experiment_id,
            exp.name,
            exp.task_type,
            exp.model_used,
            exp.dataset_name,
            exp.created_at.isoformat() if exp.created_at else "",
        ]
        for key in metric_keys:
            val = metrics.get(key, "")
            row.append(val)
        writer.writerow(row)

    output.seek(0)
    return StreamingResponse(
        output,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=robustidps_experiments_report.csv"},
    )


@router.get("/mitre-mapping", summary="Get MITRE ATT&CK mapping for detected threats")
def get_mitre_mapping(
    experiment_id: Optional[str] = Query(None, description="Optional: map threats from a specific experiment"),
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    if experiment_id:
        from database import Experiment
        exp = db.query(Experiment).filter(
            Experiment.experiment_id == experiment_id,
            Experiment.user_id == user.id,
        ).first()
        if not exp:
            raise HTTPException(404, "Experiment not found")

        results = exp.results or {}
        attack_dist = results.get("attack_distribution", {})

        mapped = []
        for label, count in attack_dist.items():
            if label == "Benign":
                continue
            mitre = MITRE_MAPPING.get(label, {})
            mapped.append({
                "threat_label": label,
                "count": count,
                "mitre_technique": mitre.get("technique", "N/A"),
                "mitre_tactic": mitre.get("tactic", "N/A"),
                "mitre_name": mitre.get("name", "N/A"),
            })
        return {"experiment_id": experiment_id, "mappings": mapped}

    # Return full mapping catalogue
    return {"mappings": MITRE_MAPPING}


@router.post("/latex/mitre", summary="Generate LaTeX MITRE ATT&CK mapping table")
def generate_latex_mitre(
    experiment_id: str = Body(..., embed=True),
    user=Depends(require_auth),
    db: Session = Depends(get_db),
):
    from database import Experiment
    exp = db.query(Experiment).filter(
        Experiment.experiment_id == experiment_id,
        Experiment.user_id == user.id,
    ).first()
    if not exp:
        raise HTTPException(404, "Experiment not found")

    results = exp.results or {}
    attack_dist = results.get("attack_distribution", {})

    lines = [
        "% Auto-generated MITRE ATT\\&CK mapping by RobustIDPS.AI",
        "",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\caption{Detected threats mapped to MITRE ATT\\&CK}",
        "\\label{tab:mitre-mapping}",
        "\\small",
        "\\begin{tabular}{llllr}",
        "\\toprule",
        "\\textbf{Threat} & \\textbf{Technique} & \\textbf{Tactic} & \\textbf{Name} & \\textbf{Count} \\\\",
        "\\midrule",
    ]

    for label, count in sorted(attack_dist.items()):
        if label == "Benign":
            continue
        mitre = MITRE_MAPPING.get(label, {})
        lines.append(
            f"{_escape_latex(label)} & "
            f"{mitre.get('technique', 'N/A')} & "
            f"{_escape_latex(mitre.get('tactic', 'N/A'))} & "
            f"{_escape_latex(mitre.get('name', 'N/A'))} & "
            f"{count} \\\\"
        )

    lines += [
        "\\bottomrule",
        "\\end{tabular}",
        "\\end{table}",
    ]
    return PlainTextResponse("\n".join(lines), media_type="text/x-latex")
