import click
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box

console = Console()

BANNER = r"""
[bold cyan]
  _   _                   _     _____         
 | | | |__ ___      _____| | __|  ___|   _  ___ 
 | |_| / _` \ \ /\ / / __| |/ /| |_  | | |/ _ \
 |  _  | (_| |\ V  V /\__ \   < |  _| | |_|  __/
 |_| |_|\__,_| \_/\_/ |___/_|\_\|_|   \__, |\___|
                                        |___/     
[/bold cyan]
[dim]  AI-Assisted Bug Hunting Framework  ·  v1.0.0[/dim]
[dim]  Built by Kalpin Patel  ·  github.com/kalpin05[/dim]
"""

DISCLAIMER = "[bold red]⚠  For authorized testing only.[/bold red] [dim]Only scan systems you own or have written permission to test.[/dim]"

def print_banner():
    console.print(BANNER)
    console.print(Panel(DISCLAIMER, border_style="red", padding=(0, 2)))
    console.print()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}

def severity_badge(severity: str) -> Text:
    sev = severity.lower()
    color = SEVERITY_COLORS.get(sev, "white")
    return Text(f" {sev.upper()} ", style=color)

def print_findings_table(findings: list, module_name: str):
    if not findings:
        console.print(f"[green]✔  No issues found by {module_name}[/green]\n")
        return

    table = Table(
        title=f"[bold]{module_name} Findings[/bold]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=True,
        header_style="bold cyan",
    )
    table.add_column("Severity", width=10)
    table.add_column("Check",    width=28)
    table.add_column("Detail",   width=52)

    for f in findings:
        table.add_row(
            severity_badge(f.get("severity", "info")),
            f.get("check", "—"),
            f.get("detail", "—"),
        )
    console.print(table)
    console.print()

def print_summary(all_findings: list, target: str, elapsed: float):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info").lower()
        counts[sev] = counts.get(sev, 0) + 1

    risk = (
        "CRITICAL" if counts["critical"] > 0 else
        "HIGH"     if counts["high"]     > 0 else
        "MEDIUM"   if counts["medium"]   > 0 else
        "LOW"      if counts["low"]      > 0 else
        "CLEAN"
    )
    risk_color = {
        "CRITICAL": "bold red", "HIGH": "red",
        "MEDIUM": "yellow", "LOW": "cyan", "CLEAN": "green",
    }[risk]

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary.add_column(style="dim")
    summary.add_column()
    summary.add_row("Target",     f"[bold]{target}[/bold]")
    summary.add_row("Risk Level", f"[{risk_color}]{risk}[/{risk_color}]")
    summary.add_row("Total",      str(len(all_findings)))
    summary.add_row("Critical",   f"[bold red]{counts['critical']}[/bold red]")
    summary.add_row("High",       f"[red]{counts['high']}[/red]")
    summary.add_row("Medium",     f"[yellow]{counts['medium']}[/yellow]")
    summary.add_row("Low",        f"[cyan]{counts['low']}[/cyan]")
    summary.add_row("Scan time",  f"{elapsed:.1f}s")

    console.print(Panel(summary, title="[bold cyan]Scan Summary[/bold cyan]", border_style="cyan"))
    console.print()


@click.group()
@click.version_option("1.0.0", prog_name="HawkEye")
def hawkeye():
    """
    \b
    HawkEye — AI-Assisted Bug Hunting Framework
    Scan targets for web, network, and API vulnerabilities.
    """
    pass


@hawkeye.command()
@click.option("--target",  "-t", required=True, help="Target URL or IP")
@click.option("--all",     "-a", is_flag=True,  help="Run all modules")
@click.option("--headers", "-H", is_flag=True,  help="HTTP header & SSL checker")
@click.option("--network", "-n", is_flag=True,  help="Network & port scanner")
@click.option("--web",     "-w", is_flag=True,  help="Web vulnerability scanner")
@click.option("--api",     "-A", is_flag=True,  help="API security tester")
@click.option("--ai",            is_flag=True,  help="Enable AI triage")
@click.option("--output",  "-o", default="table",
              type=click.Choice(["table", "json", "html", "pdf"]),
              help="Output format")
@click.option("--fast",          is_flag=True,  help="Fast mode (top 100 ports)")
def scan(target, all, headers, network, web, api, ai, output, fast):
    """
    Scan a target for security vulnerabilities.

    \b
    Examples:
      hawkeye scan --target https://example.com --all
      hawkeye scan --target https://example.com --headers --web
      hawkeye scan --target 192.168.1.1 --network --fast
      hawkeye scan --target https://api.example.com --api --ai --output pdf
    """
    print_banner()

    if not any([all, headers, network, web, api]):
        console.print("[bold red]Error:[/bold red] Select at least one module. Use --all to run everything.\n")
        console.print("  [dim]hawkeye scan --target example.com --all[/dim]\n")
        sys.exit(1)

    modules_to_run = {
        "headers": all or headers,
        "network": all or network,
        "web":     all or web,
        "api":     all or api,
    }
    active = [k for k, v in modules_to_run.items() if v]

    console.print(f"[bold]Target:[/bold]    [cyan]{target}[/cyan]")
    console.print(f"[bold]Modules:[/bold]   [cyan]{', '.join(active)}[/cyan]")
    console.print(f"[bold]Output:[/bold]    [cyan]{output}[/cyan]")
    console.print(f"[bold]AI Triage:[/bold] {'[green]ON[/green]' if ai else '[dim]OFF[/dim]'}")
    console.print()

    all_findings = []
    start_time = time.time()

    if modules_to_run["headers"]:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running header & SSL checker..."), transient=True) as p:
            p.add_task("scan"); time.sleep(0.5)
        try:
            from modules.header_checker import scan_headers
            findings = scan_headers(target)
            all_findings.extend(findings)
            print_findings_table(findings, "Header & SSL Checker")
        except NotImplementedError:
            console.print("[yellow]⏳  Header checker — coming in Sprint 2[/yellow]\n")

    if modules_to_run["network"]:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running network scanner..."), transient=True) as p:
            p.add_task("scan"); time.sleep(0.5)
        try:
            from modules.network_scanner import scan_network
            findings = scan_network(target, fast=fast)
            all_findings.extend(findings)
            print_findings_table(findings, "Network Scanner")
        except NotImplementedError:
            console.print("[yellow]⏳  Network scanner — coming in Sprint 3[/yellow]\n")

    if modules_to_run["web"]:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running web vulnerability scanner..."), transient=True) as p:
            p.add_task("scan"); time.sleep(0.5)
        try:
            from modules.web_scanner import scan_web
            findings = scan_web(target)
            all_findings.extend(findings)
            print_findings_table(findings, "Web Vulnerability Scanner")
        except NotImplementedError:
            console.print("[yellow]⏳  Web scanner — coming in Sprint 4 & 5[/yellow]\n")

    if modules_to_run["api"]:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running API security tester..."), transient=True) as p:
            p.add_task("scan"); time.sleep(0.5)
        try:
            from modules.api_tester import scan_api
            findings = scan_api(target)
            all_findings.extend(findings)
            print_findings_table(findings, "API Security Tester")
        except NotImplementedError:
            console.print("[yellow]⏳  API tester — coming in Sprint 6[/yellow]\n")

    if ai and all_findings:
        with Progress(SpinnerColumn(), TextColumn("[cyan]Running AI triage..."), transient=True) as p:
            p.add_task("triage"); time.sleep(0.5)
        try:
            from modules.ai_triage import triage_findings
            all_findings = triage_findings(all_findings)
        except NotImplementedError:
            console.print("[yellow]⏳  AI triage — coming in Sprint 7[/yellow]\n")

    elapsed = time.time() - start_time

    if all_findings:
        print_summary(all_findings, target, elapsed)
    else:
        console.print(f"[dim]Scan completed in {elapsed:.1f}s — modules populate from Sprint 2 onwards.[/dim]\n")

    if output != "table" and all_findings:
        try:
            from modules.reporter import generate_json, generate_html, generate_pdf
            if output == "json":   generate_json(all_findings)
            elif output == "html": generate_html(all_findings)
            elif output == "pdf":  generate_pdf(all_findings)
        except NotImplementedError:
            console.print("[yellow]⏳  Report generator — coming in Sprint 8[/yellow]\n")


@hawkeye.command()
@click.option("--file", "-f", required=True, type=click.Path(exists=True), help="Path to findings JSON")
def triage(file):
    """Run AI triage on an existing findings JSON file."""
    print_banner()
    console.print(f"[cyan]Loading findings from:[/cyan] {file}\n")
    console.print("[yellow]⏳  AI triage engine — coming in Sprint 7[/yellow]\n")


@hawkeye.command()
@click.option("--port", "-p", default=8080, help="Port for the dashboard (default: 8080)")
def dashboard(port):
    """Launch the HawkEye web dashboard."""
    print_banner()
    console.print(f"[cyan]Starting dashboard on port {port}...[/cyan]")
    console.print("[yellow]⏳  Web dashboard — coming in Sprint 9[/yellow]\n")


if __name__ == "__main__":
    hawkeye()