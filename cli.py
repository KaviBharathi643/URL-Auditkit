import json
import typer
from rich.table import Table
from rich.console import Console
from rich import box
from dotenv import load_dotenv

from url_audit.runner import run_all, summarize

app = typer.Typer(help="URL Audit Kit — 41 checks + local LLM (Ollama)")

@app.command()
def main(url: str, json_out: str = typer.Option(None, "--json", help="Write full JSON report here")):
    load_dotenv(override=True)
    console = Console()
    results = run_all(url)
    counts = summarize(results)

    table = Table(title=f"Audit Results for {url}", box=box.SIMPLE_HEAVY)
    table.add_column("ID", justify="right")
    table.add_column("Check")
    table.add_column("Status")
    table.add_column("Evidence", overflow="fold")
    table.add_column("Details", overflow="fold")
    for r in results:
        evidence = r.evidence or "(no evidence)"
        details = "(no extra data)"
        if r.data:
            try:
                details_json = json.dumps(r.data, default=str, ensure_ascii=False)
            except (TypeError, ValueError):
                details_json = str(r.data)
            details = details_json if len(details_json) <= 300 else f"{details_json[:297]}..."
        table.add_row(str(r.id), r.name, r.status, evidence, details)

    console.print(table)
    console.print(f"[bold]Summary[/bold]: {counts}")

    if json_out:
        with open(json_out, "w") as f:
            json.dump([r.__dict__ for r in results], f, indent=2, default=str)
        console.print(f"Wrote JSON report to: {json_out}")

@app.command()
def ollama_info():
    """
    Prints Ollama connectivity, configured model, and available models.
    """
    load_dotenv(override=True)
    import os, requests
    console = Console()

    host = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")

    console.print(f"[bold]Configured[/bold] OLLAMA_HOST={host}  OLLAMA_MODEL={model}")

    # Installed models via HTTP API
    try:
        r = requests.get(f"{host}/api/tags", timeout=10)
        if r.ok:
            console.print("[bold]Installed models (via /api/tags):[/bold]")
            console.print_json(data=r.json())
        else:
            console.print(f"[red]HTTP error calling /api/tags:[/red] {r.status_code}")
    except Exception as e:
        console.print(f"[red]Failed to call Ollama HTTP API:[/red] {e}")

    # Minimal Python client test
    try:
        from ollama import Client
        c = Client(host=host)
        resp = c.generate(model=model, prompt="Respond with the single word: ok", options={"num_predict": 1, "temperature": 0})
        console.print("[bold]Python client test response:[/bold]")
        console.print_json(data=resp if isinstance(resp, dict) else {"response": str(resp)})
    except Exception as e:
        console.print(f"[yellow]Python client test failed:[/yellow] {e}")

if __name__ == "__main__":
    app()
