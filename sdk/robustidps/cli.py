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


if __name__ == "__main__":
    main()
