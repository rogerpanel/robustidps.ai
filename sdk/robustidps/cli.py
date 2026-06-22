"""
RobustIDPS CLI — command-line interface for batch experiments and automation.

Usage:
    robustidps login --url https://robustidps.example.com --email user@example.com
    robustidps predict traffic.csv --model surrogate --uncertainty
    robustidps redteam traffic.csv --attacks fgsm,pgd --epsilon 0.1
    robustidps ablation traffic.csv --mode pairwise
    robustidps experiments list --tag baseline
    robustidps experiments compare exp1_id exp2_id
    robustidps report latex exp1_id exp2_id --output table.tex
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from tabulate import tabulate

from robustidps.client import Client, APIError

console = Console()

# ── Config file for stored credentials ───────────────────────────────────

CONFIG_DIR = Path.home() / ".robustidps"
CONFIG_FILE = CONFIG_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        return json.loads(CONFIG_FILE.read_text())
    return {}


def _save_config(data: dict):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(data, indent=2))
    CONFIG_FILE.chmod(0o600)


def _get_client(url: str | None = None, token: str | None = None) -> Client:
    config = _load_config()
    base_url = url or os.environ.get("ROBUSTIDPS_URL") or config.get("url", "http://localhost:8000")
    jwt = token or os.environ.get("ROBUSTIDPS_TOKEN") or config.get("token")
    return Client(base_url=base_url, token=jwt)


# ── Main CLI group ───────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="robustidps")
def main():
    """RobustIDPS.AI — CLI for intrusion detection research automation."""
    pass


# ── Login ────────────────────────────────────────────────────────────────

@main.command()
@click.option("--url", required=True, help="Platform URL (e.g. https://robustidps.example.com)")
@click.option("--email", required=True, help="Account email")
@click.option("--password", prompt=True, hide_input=True, help="Account password")
def login(url: str, email: str, password: str):
    """Authenticate and store credentials locally."""
    client = Client(base_url=url)
    try:
        data = client.login(email, password)
        _save_config({"url": url, "token": data["token"], "email": email})
        console.print(f"[green]Logged in as {email}[/green]")
        console.print(f"  Role: {data.get('user', {}).get('role', 'unknown')}")
        console.print(f"  Config saved to {CONFIG_FILE}")
    except APIError as e:
        console.print(f"[red]Login failed: {e.detail}[/red]")
        sys.exit(1)


# ── Health check ─────────────────────────────────────────────────────────

@main.command()
@click.option("--url", default=None)
def health(url: str | None):
    """Check API health status."""
    client = _get_client(url)
    try:
        data = client.health()
        console.print(f"[green]Backend: {data.get('status', 'unknown')}[/green]")
        console.print(f"  Model loaded: {data.get('model_loaded', False)}")
    except Exception as e:
        console.print(f"[red]Backend unreachable: {e}[/red]")
        sys.exit(1)


# ── Predict ──────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--model", default=None, help="Model ID (surrogate, neural_ode, etc.)")
@click.option("--uncertainty", is_flag=True, help="Enable MC Dropout uncertainty")
@click.option("--export", "export_path", default=None, help="Export results to CSV file")
@click.option("--url", default=None)
def predict(file: str, model: str | None, uncertainty: bool, export_path: str | None, url: str | None):
    """Run prediction on a CSV or PCAP file."""
    client = _get_client(url)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task("Analysing...", total=None)
        try:
            result = client.predict(file, model=model, uncertainty=uncertainty)
        except APIError as e:
            console.print(f"[red]Error: {e.detail}[/red]")
            sys.exit(1)

    console.print(f"\n[bold]Results for {Path(file).name}[/bold]")
    console.print(f"  Job ID:   {result.get('job_id', 'N/A')}")
    console.print(f"  Flows:    {result.get('n_flows', 0)}")
    console.print(f"  Threats:  [red]{result.get('n_threats', 0)}[/red]")
    console.print(f"  Benign:   [green]{result.get('n_benign', 0)}[/green]")

    if uncertainty and "ece" in result:
        console.print(f"  ECE:      {result['ece']:.4f}")

    # Attack distribution
    dist = result.get("attack_distribution", {})
    if dist:
        table = Table(title="Attack Distribution")
        table.add_column("Class", style="cyan")
        table.add_column("Count", justify="right")
        for cls, count in sorted(dist.items(), key=lambda x: -x[1]):
            style = "green" if cls == "Benign" else "red"
            table.add_row(cls, str(count), style=style)
        console.print(table)

    if export_path:
        out = client.export_csv(result["job_id"], export_path)
        console.print(f"\n[green]Results exported to {out}[/green]")


# ── Red Team ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--attacks", default="fgsm,pgd", help="Comma-separated attacks: fgsm,pgd,deepfool,gaussian,feature_mask")
@click.option("--epsilon", default=0.1, type=float, help="Perturbation budget")
@click.option("--samples", default=500, type=int, help="Number of samples")
@click.option("--model", default=None)
@click.option("--url", default=None)
def redteam(file: str, attacks: str, epsilon: float, samples: int, model: str | None, url: str | None):
    """Run adversarial robustness evaluation."""
    client = _get_client(url)
    attack_list = [a.strip() for a in attacks.split(",")]

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task(f"Running {len(attack_list)} attacks...", total=None)
        try:
            result = client.redteam(file, attacks=attack_list, epsilon=epsilon, n_samples=samples, model=model)
        except APIError as e:
            console.print(f"[red]Error: {e.detail}[/red]")
            sys.exit(1)

    console.print(f"\n[bold]Red Team Results[/bold]")
    if "robustness_score" in result:
        score = result["robustness_score"]
        color = "green" if score > 0.7 else "yellow" if score > 0.4 else "red"
        console.print(f"  Robustness Score: [{color}]{score:.4f}[/{color}]")

    attack_results = result.get("attacks", {})
    if attack_results:
        table = Table(title="Per-Attack Results")
        table.add_column("Attack", style="cyan")
        table.add_column("Acc Before", justify="right")
        table.add_column("Acc After", justify="right")
        table.add_column("Flip Rate", justify="right")
        for name, data in attack_results.items():
            if not isinstance(data, dict):
                continue
            before = f"{data.get('accuracy_before', 0):.4f}"
            after = f"{data.get('accuracy_after', 0):.4f}"
            flip = f"{data.get('flip_rate', 0):.4f}"
            table.add_row(name, before, after, flip)
        console.print(table)


# ── Ablation ─────────────────────────────────────────────────────────────

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--mode", default="single", type=click.Choice(["single", "pairwise", "incremental"]))
@click.option("--model", default=None)
@click.option("--url", default=None)
def ablation(file: str, mode: str, model: str | None, url: str | None):
    """Run branch ablation study."""
    client = _get_client(url)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        progress.add_task(f"Running {mode} ablation...", total=None)
        try:
            result = client.ablation(file, mode=mode, model=model)
        except APIError as e:
            console.print(f"[red]Error: {e.detail}[/red]")
            sys.exit(1)

    console.print(f"\n[bold]Ablation Study ({mode})[/bold]")
    console.print(f"  Baseline accuracy: {result.get('baseline_accuracy', 'N/A')}")

    impact = result.get("branch_impact", {})
    if impact:
        table = Table(title="Branch Impact")
        table.add_column("Branch", style="cyan")
        table.add_column("Accuracy Drop", justify="right", style="red")
        for branch, drop in sorted(impact.items(), key=lambda x: -abs(x[1]) if isinstance(x[1], (int, float)) else 0):
            table.add_row(branch, f"{drop:.4f}" if isinstance(drop, float) else str(drop))
        console.print(table)


# ── Experiments ──────────────────────────────────────────────────────────

@main.group()
def experiments():
    """Manage experiment records."""
    pass


@experiments.command("list")
@click.option("--task-type", default=None, help="Filter by task type")
@click.option("--tag", default=None, help="Filter by tag")
@click.option("--search", default=None, help="Search name/description")
@click.option("--url", default=None)
def exp_list(task_type: str | None, tag: str | None, search: str | None, url: str | None):
    """List saved experiments."""
    client = _get_client(url)
    filters = {}
    if task_type:
        filters["task_type"] = task_type
    if tag:
        filters["tag"] = tag
    if search:
        filters["search"] = search

    try:
        data = client.list_experiments(**filters)
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)

    exps = data.get("experiments", [])
    if not exps:
        console.print("[dim]No experiments found[/dim]")
        return

    table = Table(title=f"Experiments ({data.get('total', len(exps))})")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Model")
    table.add_column("Tags")
    table.add_column("Created")
    for e in exps:
        table.add_row(
            e["experiment_id"],
            e["name"],
            e.get("task_type", ""),
            e.get("model_used", ""),
            ", ".join(e.get("tags", [])),
            (e.get("created_at") or "")[:19],
        )
    console.print(table)


@experiments.command("compare")
@click.argument("ids", nargs=-1, required=True)
@click.option("--url", default=None)
def exp_compare(ids: tuple[str, ...], url: str | None):
    """Compare 2-4 experiments side by side."""
    client = _get_client(url)
    try:
        data = client.compare_experiments(list(ids))
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)

    exps = data.get("experiments", [])
    metric_table = data.get("metric_table", {})

    # Build tabulate data
    headers = ["Metric"] + [e["name"] for e in exps]
    rows = []
    for key in data.get("metric_keys", []):
        row = [key.replace("_", " ")]
        vals = metric_table.get(key, {})
        num_vals = [v for v in vals.values() if isinstance(v, (int, float))]
        best = max(num_vals) if num_vals else None
        for e in exps:
            v = vals.get(e["experiment_id"])
            if v is None:
                row.append("--")
            elif isinstance(v, float):
                row.append(f"{v:.4f}")
            else:
                row.append(str(v))
        rows.append(row)

    console.print(tabulate(rows, headers=headers, tablefmt="rounded_grid"))


@experiments.command("create")
@click.option("--name", required=True, help="Experiment name")
@click.option("--tags", default="", help="Comma-separated tags")
@click.option("--task-type", default="", help="Task type")
@click.option("--url", default=None)
def exp_create(name: str, tags: str, task_type: str, url: str | None):
    """Create a new experiment record."""
    client = _get_client(url)
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    try:
        data = client.create_experiment(name, tags=tag_list, task_type=task_type)
        console.print(f"[green]Created experiment {data['experiment_id']}: {name}[/green]")
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)


# ── Reports ──────────────────────────────────────────────────────────────

@main.group()
def report():
    """Generate reports and exports."""
    pass


@report.command("latex")
@click.argument("ids", nargs=-1, required=True)
@click.option("--output", "-o", default=None, help="Output file (default: stdout)")
@click.option("--url", default=None)
def report_latex(ids: tuple[str, ...], output: str | None, url: str | None):
    """Generate LaTeX comparison table from experiment IDs."""
    client = _get_client(url)
    try:
        if len(ids) == 1:
            latex = client.latex_experiment(ids[0])
        else:
            latex = client.latex_comparison(list(ids))
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)

    if output:
        Path(output).write_text(latex)
        console.print(f"[green]LaTeX written to {output}[/green]")
    else:
        console.print(latex)


@report.command("csv")
@click.argument("ids", nargs=-1, required=True)
@click.option("--output", "-o", default="report.csv")
@click.option("--url", default=None)
def report_csv(ids: tuple[str, ...], output: str, url: str | None):
    """Export experiments as CSV report."""
    client = _get_client(url)
    try:
        out = client.csv_report(list(ids), output)
        console.print(f"[green]CSV report saved to {out}[/green]")
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)


# ── Tasks ────────────────────────────────────────────────────────────────

@main.group()
def tasks():
    """Monitor background tasks."""
    pass


@tasks.command("list")
@click.option("--status", default=None, type=click.Choice(["queued", "running", "completed", "failed"]))
@click.option("--url", default=None)
def task_list(status: str | None, url: str | None):
    """List background tasks."""
    client = _get_client(url)
    try:
        data = client.list_tasks(status=status)
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)

    tasks_list = data.get("tasks", [])
    if not tasks_list:
        console.print("[dim]No tasks found[/dim]")
        return

    table = Table(title=f"Tasks ({data.get('total', len(tasks_list))})")
    table.add_column("ID", style="dim")
    table.add_column("Name", style="cyan")
    table.add_column("Type")
    table.add_column("Status")
    table.add_column("Progress", justify="right")
    table.add_column("Created")
    for t in tasks_list:
        status_style = {
            "completed": "green", "failed": "red",
            "running": "blue", "queued": "dim",
        }.get(t["status"], "")
        table.add_row(
            t["task_id"],
            t["name"],
            t["task_type"],
            f"[{status_style}]{t['status']}[/{status_style}]",
            f"{t.get('progress', 0)}%",
            (t.get("created_at") or "")[:19],
        )
    console.print(table)


@tasks.command("wait")
@click.argument("task_id")
@click.option("--interval", default=2.0, type=float, help="Poll interval in seconds")
@click.option("--url", default=None)
def task_wait(task_id: str, interval: float, url: str | None):
    """Wait for a background task to complete."""
    client = _get_client(url)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
        ptask = progress.add_task(f"Waiting for {task_id}...", total=None)
        try:
            result = client.wait_for_task(task_id, poll_interval=interval)
        except APIError as e:
            console.print(f"[red]Error: {e.detail}[/red]")
            sys.exit(1)
        except TimeoutError as e:
            console.print(f"[red]{e}[/red]")
            sys.exit(1)

    if result["status"] == "completed":
        console.print(f"[green]Task {task_id} completed[/green]")
        if result.get("result"):
            console.print_json(json.dumps(result["result"], indent=2, default=str))
    else:
        console.print(f"[red]Task {task_id} failed: {result.get('error', 'Unknown error')}[/red]")
        sys.exit(1)


# ── Models ───────────────────────────────────────────────────────────────

@main.command("models")
@click.option("--url", default=None)
def list_models(url: str | None):
    """List available IDS models."""
    client = _get_client(url)
    try:
        data = client.models()
    except APIError as e:
        console.print(f"[red]Error: {e.detail}[/red]")
        sys.exit(1)

    models = data.get("models", [])
    table = Table(title="Models")
    table.add_column("ID", style="cyan")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Active")
    for m in models:
        status = "[green]enabled[/green]" if m.get("enabled") else "[dim]disabled[/dim]"
        active = "[bold green]>>>>[/bold green]" if m.get("active") else ""
        table.add_row(m.get("id", ""), m.get("name", ""), status, active)
    console.print(table)


# ── Agent Studio — wrappers over the /api/agent-studio/* endpoints ──────

@main.group()
def agent():
    """Agent Studio operations (scan, eval, red-team, supply-chain, dossier, keys)."""
    pass


def _agent_base() -> str:
    return (os.environ.get("ROBUSTIDPS_API_BASE")
            or _load_config().get("agent_api_base")
            or _load_config().get("url")
            or "http://localhost:8000").rstrip("/")


def _agent_headers() -> dict:
    key = os.environ.get("ROBUSTIDPS_API_KEY") or _load_config().get("api_key")
    h = {"Content-Type": "application/json"}
    if key:
        h["Authorization"] = f"Bearer {key}"
    return h


def _agent_admin_headers() -> dict:
    tok = os.environ.get("ROBUSTIDPS_ADMIN_TOKEN") or _load_config().get("admin_token")
    h = {"Content-Type": "application/json"}
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _agent_request(method: str, path: str, *, admin: bool = False,
                   json_body: dict | None = None,
                   params: dict | None = None) -> dict:
    import httpx
    url = _agent_base() + path
    headers = _agent_admin_headers() if admin else _agent_headers()
    try:
        with httpx.Client(timeout=15.0) as client:
            resp = client.request(method, url, headers=headers,
                                  json=json_body, params=params)
            resp.raise_for_status()
            return resp.json()
    except httpx.HTTPStatusError as e:
        console.print(f"[red]HTTP {e.response.status_code}: {e.response.text[:300]}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Request failed: {e}[/red]")
        sys.exit(1)


@agent.command("scan")
@click.argument("file", type=click.Path(exists=True))
@click.option("--kind", "input_kind",
              type=click.Choice(["mcp_manifest", "tool_list", "system_prompt", "agent_card"]),
              default="mcp_manifest")
def agent_scan(file: str, input_kind: str):
    """Run the free MCP/agent scanner against a JSON/text file."""
    text = Path(file).read_text()
    out = _agent_request("POST", "/api/agent-studio/scanner/run",
                         json_body={"text": text, "input_kind": input_kind})
    sev = out.get("severity_breakdown", {})
    n = out.get("n_findings", 0)
    color = "red" if any(sev.get(s, 0) for s in ("critical", "high")) else "green"
    console.print(f"[bold]Scanner findings:[/bold] [{color}]{n}[/{color}]  ({sev})")
    for r in out.get("results", []):
        if r.get("triggered"):
            console.print(f"  [{r['severity']}] {r['code']} — {r['title']}")


@agent.command("eval")
@click.argument("file", type=click.Path(exists=True))
def agent_eval(file: str):
    """Run the 5-eval pre-flight harness against an agent spec JSON."""
    spec = json.loads(Path(file).read_text())
    out = _agent_request("POST", "/api/agent-studio/eval/run",
                         json_body={"agent_spec": spec})
    tone = {"pass": "green", "warn": "yellow", "fail": "red"}.get(out["overall_verdict"], "")
    console.print(f"[bold]{out['agent_name']}[/bold]  → "
                  f"[{tone}]{out['overall_verdict'].upper()}[/{tone}] "
                  f"({out['overall_score']*100:.0f}%)")
    for r in out.get("results", []):
        rt = {"pass": "green", "warn": "yellow", "fail": "red"}.get(r["verdict"], "")
        console.print(f"  [{rt}]{r['verdict']}[/{rt}]  {r['name']}  {r['score']*100:.0f}%  — {r['detail']}")


@agent.command("red-team")
@click.argument("file", type=click.Path(exists=True))
@click.option("--garak", is_flag=True, help="Use the Garak adapter (else deterministic harness).")
def agent_red_team(file: str, garak: bool):
    """Fire the red-team probe suite at a target spec JSON."""
    spec = json.loads(Path(file).read_text())
    path = "/api/agent-studio/red-team/garak" if garak else "/api/agent-studio/red-team/run"
    out = _agent_request("POST", path, json_body={"target_spec": spec})
    sev = out.get("severity_breakdown", {})
    n = out.get("n_findings", 0)
    chain = " → ".join(out.get("atlas_chain", [])) or "(none)"
    color = "red" if sev.get("critical") or sev.get("high") else "green"
    console.print(f"[bold]Findings:[/bold] [{color}]{n}[/{color}]  {sev}")
    console.print(f"[bold]ATLAS chain:[/bold] {chain}")
    for r in out.get("results", []):
        if r.get("triggered"):
            console.print(f"  [{r['severity']}] {r['code']} ({r['owasp_agentic']}/{r['atlas_tactic']}) — {r['name']}")


@agent.command("supply-chain")
@click.argument("model_id")
@click.option("--spec", "spec_file", type=click.Path(exists=True),
              help="Optional JSON file with licence/files/dependencies.")
@click.option("--live", is_flag=True, help="Enrich with live HuggingFace Hub metadata.")
def agent_supply_chain(model_id: str, spec_file: str | None, live: bool):
    """Scan a model's supply chain (licence + CVEs + format risks + SBOM)."""
    spec = json.loads(Path(spec_file).read_text()) if spec_file else {}
    path = "/api/agent-studio/supply-chain/scan-live" if live else "/api/agent-studio/supply-chain/scan"
    out = _agent_request("POST", path, json_body={"model_id": model_id, "spec": spec})
    tone = {"safe": "green", "low": "green", "medium": "yellow",
            "high": "red", "critical": "red"}.get(out.get("risk_level", ""), "")
    console.print(f"[bold]{model_id}[/bold]  → "
                  f"[{tone}]{out['risk_level'].upper()}[/{tone}] "
                  f"({out['risk_score']*100:.0f}%)")
    console.print(f"  licence={out['licence']} · {len(out.get('cve_matches', []))} CVE(s) · "
                  f"{len(out.get('format_risks', []))} format risk(s)")
    for r in (out.get("rationale") or [])[:10]:
        console.print(f"  · {r}")


@agent.command("dossier")
@click.option("--vertical", default="agent_studio")
@click.option("--output", "-o", default=None, help="Write JSON to file (else stdout).")
def agent_dossier(vertical: str, output: str | None):
    """Fetch the assurance dossier JSON for a vertical."""
    out = _agent_request("GET", f"/api/dossier/{vertical}", params={"format": "json"})
    text = json.dumps(out, indent=2)
    if output:
        Path(output).write_text(text)
        console.print(f"[green]Dossier written to {output}[/green]")
    else:
        console.print(text)


@agent.command("templates")
@click.option("--tier", default=None,
              type=click.Choice(["A", "B", "C", "blank"]))
def agent_templates(tier: str | None):
    """List the Quickstart agent templates."""
    out = _agent_request("GET", "/api/agent-studio/templates",
                         params={"tier": tier} if tier else None)
    tbl = Table(title=f"Templates ({len(out['templates'])})")
    tbl.add_column("id", style="cyan")
    tbl.add_column("tier")
    tbl.add_column("category")
    tbl.add_column("summary")
    for t in out["templates"]:
        tbl.add_row(t["id"], t["tier"], t["category"], t["summary"])
    console.print(tbl)


@agent.command("template")
@click.argument("template_id")
@click.option("--spec-only", is_flag=True, help="Print just the spec block (forkable JSON).")
def agent_template_show(template_id: str, spec_only: bool):
    """Print a template (full record, or --spec-only for the agent JSON)."""
    out = _agent_request("GET", f"/api/agent-studio/templates/{template_id}")
    console.print(json.dumps(out["spec"] if spec_only else out, indent=2))


# ── Agent Studio · API-key management ─────────────────────────────────

@agent.group()
def key():
    """Issue / revoke API keys for a customer (self-service)."""
    pass


@key.command("issue")
@click.option("--customer", "customer_id", required=True)
@click.option("--label", default="cli-token")
def key_issue(customer_id: str, label: str):
    """Issue a new API key (returns the plaintext ONCE)."""
    out = _agent_request("POST", "/api/agent-studio/api-keys/issue",
                         json_body={"customer_id": customer_id, "label": label})
    console.print(f"[green]Issued:[/green] {out['key_id']}  ({label})")
    console.print(f"[bold yellow]Save this now — shown ONCE:[/bold yellow]\n  {out['api_key']}")


@key.command("revoke")
@click.option("--customer", "customer_id", required=True)
@click.option("--key-id", required=True)
def key_revoke(customer_id: str, key_id: str):
    """Revoke an API key by id."""
    out = _agent_request("POST", "/api/agent-studio/api-keys/revoke",
                         json_body={"customer_id": customer_id, "key_id": key_id})
    console.print(f"[green]{out}[/green]" if out.get("ok") else f"[red]{out}[/red]")


@agent.command("whoami")
@click.option("--customer", "customer_id", required=True)
def agent_whoami(customer_id: str):
    """Show customer record (requires self key OR admin token)."""
    out = _agent_request("GET", f"/api/agent-studio/customers/{customer_id}")
    console.print_json(json.dumps(out, indent=2))


# ── Agent Studio · admin grants (side-channel licensing) ──────────────

@agent.group()
def admin():
    """Admin-only ops (requires ROBUSTIDPS_ADMIN_TOKEN)."""
    pass


@admin.command("grant")
@click.option("--email", required=True)
@click.option("--tier", default="pro", type=click.Choice(["pro", "enterprise"]))
@click.option("--months", default=12, type=int, help="0 = perpetual / comp.")
@click.option("--rail", "payment_rail", default="comp",
              type=click.Choice(["wire", "crypto", "yoomoney", "qiwi", "sbp",
                                 "bank_card_offshore", "comp", "sponsorship", "other"]))
@click.option("--note", default="")
@click.option("--granted-by", default="admin")
def admin_grant(email: str, tier: str, months: int,
                payment_rail: str, note: str, granted_by: str):
    """Issue a licence without Stripe (Russia/Crimea/wire/crypto)."""
    out = _agent_request("POST", "/api/agent-studio/admin/grants", admin=True,
                         json_body={
                             "email": email, "tier": tier, "months": months,
                             "payment_rail": payment_rail, "note": note,
                             "granted_by": granted_by,
                         })
    console.print(f"[green]Granted[/green] {out['grant_id']}  customer={out['customer_id']}  tier={tier}  rail={payment_rail}")
    console.print(f"[bold yellow]API key (shown ONCE):[/bold yellow]\n  {out['api_key']}")
    if out.get("expires_at"):
        console.print(f"  expires: {out['expires_at']}")


@admin.command("list")
@click.option("--include-revoked/--active-only", default=True)
def admin_list(include_revoked: bool):
    """List all admin-issued grants."""
    out = _agent_request("GET", "/api/agent-studio/admin/grants", admin=True,
                         params={"include_revoked": include_revoked})
    stats = out.get("stats", {})
    console.print(f"[bold]{stats.get('n_active', 0)} active[/bold] · "
                  f"{stats.get('n_revoked', 0)} revoked · "
                  f"by rail: {stats.get('by_payment_rail', {})}")
    tbl = Table(title=f"Grants ({len(out['grants'])})")
    for col in ("grant_id", "email", "tier", "rail", "months", "granted_at", "expires", "revoked"):
        tbl.add_column(col)
    for g in out["grants"]:
        tbl.add_row(
            g["grant_id"], g["email"], g["tier"], g["payment_rail"],
            str(g["months"]), g["granted_at"][:10],
            g.get("expires_at") or "—",
            "yes" if g.get("revoked_at") else "no",
        )
    console.print(tbl)


@admin.command("revoke")
@click.argument("grant_id")
def admin_revoke(grant_id: str):
    """Revoke a grant (and all of its keys)."""
    out = _agent_request("POST", f"/api/agent-studio/admin/grants/{grant_id}/revoke",
                         admin=True)
    tone = "green" if out.get("ok") else "red"
    console.print(f"[{tone}]{out}[/{tone}]")


@admin.command("whoami")
def admin_whoami_cmd():
    """Verify the admin token is recognised."""
    out = _agent_request("GET", "/api/agent-studio/admin/whoami", admin=True)
    console.print(f"[green]Admin: {out}[/green]")


if __name__ == "__main__":
    main()
