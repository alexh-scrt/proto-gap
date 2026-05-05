"""Typer-based CLI entry point for proto_gap.

Provides the 'proto-gap' command which accepts a repository path and output
format flags, runs the scanner, and displays or writes the report.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

from proto_gap import __version__
from proto_gap.scanner import scan_repository
from proto_gap.renderer import OutputFormat, render

app = typer.Typer(
    name="proto-gap",
    help=(
        "Statically analyze an AI-generated prototype codebase and produce "
        "a prioritized production-readiness gap checklist."
    ),
    add_completion=True,
    rich_markup_mode="rich",
)

console = Console()
err_console = Console(stderr=True)


def version_callback(value: bool) -> None:
    """Print the version and exit when --version is passed."""
    if value:
        typer.echo(f"proto-gap {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    repo_path: Path = typer.Argument(
        default=Path("."),
        help="Path to the repository directory to analyze.",
        exists=True,
        file_okay=False,
        dir_okay=True,
        readable=True,
        resolve_path=True,
    ),
    output: str = typer.Option(
        "terminal",
        "--output",
        "-o",
        help="Output format: terminal, markdown, or json.",
        metavar="FORMAT",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-f",
        help="Write report to this file instead of stdout (for markdown/json formats).",
        writable=True,
    ),
    max_file_size: int = typer.Option(
        1_000_000,
        "--max-file-size",
        help="Maximum file size in bytes to scan (default: 1 MB).",
    ),
    version: Optional[bool] = typer.Option(
        None,
        "--version",
        "-V",
        help="Show the version and exit.",
        callback=version_callback,
        is_eager=True,
    ),
) -> None:
    """Scan a repository for production-readiness gaps.

    Analyzes the target directory for missing authentication, error handling,
    environment configuration, security vulnerabilities, database migration
    strategies, logging, and test coverage.

    Examples:

    \b
        proto-gap ./my-prototype
        proto-gap ./my-prototype --output markdown --output-file report.md
        proto-gap ./my-prototype --output json | jq '.findings'
    """
    valid_formats = ("terminal", "markdown", "json")
    if output not in valid_formats:
        err_console.print(
            f"[bold red]Error:[/bold red] Invalid output format {output!r}. "
            f"Choose from: {', '.join(valid_formats)}"
        )
        raise typer.Exit(code=1)

    output_format: OutputFormat = output  # type: ignore[assignment]

    if output_format == "terminal":
        console.print(f"[dim]Scanning [bold]{repo_path}[/bold]...[/dim]")
    else:
        typer.echo(f"Scanning {repo_path}...", err=True)

    try:
        report = scan_repository(
            repo_path=repo_path,
            max_file_size_bytes=max_file_size,
        )
    except ValueError as exc:
        err_console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1) from exc
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[bold red]Unexpected error during scan:[/bold red] {exc}")
        raise typer.Exit(code=2) from exc

    result = render(report, output_format=output_format, console=console)

    if result is not None:
        if output_file is not None:
            try:
                output_file.write_text(result, encoding="utf-8")
                typer.echo(f"Report written to {output_file}", err=True)
            except OSError as exc:
                err_console.print(
                    f"[bold red]Error writing output file:[/bold red] {exc}"
                )
                raise typer.Exit(code=1) from exc
        else:
            typer.echo(result)

    # Exit with non-zero code if critical findings were found
    if report.critical_count > 0:
        raise typer.Exit(code=3)
    elif report.high_count > 0:
        raise typer.Exit(code=2)


def main() -> None:
    """Entry point for the proto-gap CLI command."""
    app()


if __name__ == "__main__":
    main()
