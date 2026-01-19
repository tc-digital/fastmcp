"""CLI commands for CIMD (Client ID Metadata Documents) management."""

import json
import sys
from typing import Annotated

import cyclopts
from cyclopts import Parameter
from rich.console import Console

from fastmcp.server.auth.cimd import create_cimd_document, validate_cimd_document

console = Console()

# Create the CIMD app
cimd_app = cyclopts.App(
    name="cimd",
    help="Manage CIMD (Client ID Metadata Documents) for OAuth authentication",
)


@cimd_app.command
def create(
    name: Annotated[
        str,
        Parameter(help="Human-readable name of your client"),
    ],
    redirect_uris: Annotated[
        list[str],
        Parameter(
            help="Redirect URIs (can be specified multiple times, use 'http://localhost:*/callback' for wildcards)"
        ),
    ],
    *,
    client_uri: Annotated[
        str | None,
        Parameter(help="Homepage URL of your client"),
    ] = None,
    logo_uri: Annotated[
        str | None,
        Parameter(help="Logo URL of your client"),
    ] = None,
    scope: Annotated[
        str | None,
        Parameter(help="Space-separated list of scopes"),
    ] = None,
    output: Annotated[
        str | None,
        Parameter("--output", help="Output file path (default: stdout)"),
    ] = None,
    pretty: Annotated[
        bool,
        Parameter("--pretty", help="Pretty-print JSON output"),
    ] = True,
) -> None:
    """Create a CIMD document JSON for your OAuth client.

    This generates a valid CIMD document that you can host at an HTTPS URL.
    That URL becomes your client_id for OAuth authentication.

    Examples:
        # Create a basic CIMD document
        fastmcp cimd create --name "My App" --redirect-uris "http://localhost:*/callback"

        # Create with additional metadata
        fastmcp cimd create \\
            --name "My App" \\
            --redirect-uris "http://localhost:*/callback" \\
            --client-uri "https://myapp.com" \\
            --logo-uri "https://myapp.com/logo.png" \\
            --scope "read write"

        # Save to file
        fastmcp cimd create \\
            --name "My App" \\
            --redirect-uris "http://localhost:*/callback" \\
            --output client-metadata.json
    """
    try:
        # Create the CIMD document
        document = create_cimd_document(
            client_name=name,
            redirect_uris=redirect_uris,
            client_uri=client_uri,
            logo_uri=logo_uri,
            scope=scope,
        )

        # Format as JSON
        json_output = json.dumps(document, indent=2 if pretty else None)

        # Output to file or stdout
        if output:
            with open(output, "w") as f:
                f.write(json_output)
                f.write("\n")
            console.print(f"[green]✓[/green] CIMD document written to {output}")
            console.print(
                "\n[dim]Next steps:[/dim]",
                "\n1. Host this file at an HTTPS URL (e.g., https://myapp.com/client.json)",
                "\n2. Use that URL as your client_id when connecting to MCP servers",
            )
        else:
            console.print(json_output)

    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cimd_app.command
def validate(
    file: Annotated[
        str,
        Parameter(help="Path to CIMD document JSON file to validate"),
    ],
) -> None:
    """Validate a CIMD document JSON file.

    Checks that the document conforms to the CIMD specification and
    contains all required fields with valid values.

    Examples:
        # Validate a CIMD document
        fastmcp cimd validate client-metadata.json
    """
    try:
        # Read the file
        with open(file) as f:
            data = json.load(f)

        # Validate the document
        is_valid, error = validate_cimd_document(data)

        if is_valid:
            console.print(f"[green]✓[/green] {file} is a valid CIMD document")

            # Show summary
            if "client_name" in data:
                console.print(f"\n[dim]Client Name:[/dim] {data['client_name']}")
            if "redirect_uris" in data:
                console.print(
                    f"[dim]Redirect URIs:[/dim] {', '.join(data['redirect_uris'])}"
                )
            if "client_uri" in data:
                console.print(f"[dim]Client URI:[/dim] {data['client_uri']}")
        else:
            console.print(f"[red]✗[/red] {file} is not a valid CIMD document")
            console.print(f"[red]Error:[/red] {error}")
            sys.exit(1)

    except FileNotFoundError:
        console.print(f"[red]Error:[/red] File not found: {file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        console.print(
            f"[red]Error:[/red] Invalid JSON: {e}",
            file=sys.stderr,
        )
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
