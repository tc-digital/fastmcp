"""CIMDRoute for servers that act as OAuth clients.

When a FastMCP server also acts as an MCP client (e.g., an aggregator calling
upstream servers), it needs its own CIMD document for authentication. This route
helper makes it easy to self-host the CIMD document directly from the server.
"""

from __future__ import annotations

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from fastmcp.server.auth.cimd import create_cimd_document


class CIMDRoute:
    """Route helper for self-hosting CIMD documents.

    This allows a FastMCP server to host its own CIMD document, which is useful
    when the server also acts as a client to other MCP servers.

    Example:
        ```python
        from fastmcp import FastMCP
        from fastmcp.client.auth import CIMDRoute

        mcp = FastMCP("My Aggregator")

        # Self-host CIMD document
        cimd_route = CIMDRoute(
            client_name="My Aggregator",
            redirect_uris=["http://localhost:*/callback"],
            client_uri="https://my-aggregator.com",
        )
        mcp.add_route(cimd_route.as_starlette_route())

        # Now use that URL as your client identity when connecting to upstream servers
        ```
    """

    def __init__(
        self,
        client_name: str,
        redirect_uris: list[str],
        *,
        client_uri: str | None = None,
        logo_uri: str | None = None,
        grant_types: list[str] | None = None,
        scope: str | None = None,
        path: str = "/.well-known/mcp-client.json",
    ):
        """Initialize CIMD route.

        Args:
            client_name: Human-readable name of your client
            redirect_uris: List of redirect URIs (use "http://localhost:*/callback" for wildcards)
            client_uri: Optional homepage URL
            logo_uri: Optional logo URL
            grant_types: OAuth grant types (default: ["authorization_code"])
            scope: Space-separated scopes
            path: Path to serve the CIMD document at (default: /.well-known/mcp-client.json)
        """
        self.client_name = client_name
        self.redirect_uris = redirect_uris
        self.client_uri = client_uri
        self.logo_uri = logo_uri
        self.grant_types = grant_types or ["authorization_code"]
        self.scope = scope
        self.path = path

        # Pre-generate the CIMD document
        self._document = create_cimd_document(
            client_name=client_name,
            redirect_uris=redirect_uris,
            client_uri=client_uri,
            logo_uri=logo_uri,
            grant_types=grant_types,
            scope=scope,
        )

    async def handle(self, request: Request) -> JSONResponse:
        """Handle requests for the CIMD document.

        Returns the pre-generated CIMD document as JSON with appropriate headers.
        """
        return JSONResponse(
            content=self._document,
            headers={
                "Cache-Control": "public, max-age=86400",  # 24 hours
                "Content-Type": "application/json",
            },
        )

    def as_starlette_route(self) -> Route:
        """Convert to a Starlette Route object.

        This can be added to a FastMCP server using `mcp.add_route()`.

        Returns:
            Starlette Route object configured to serve the CIMD document
        """
        return Route(
            path=self.path,
            endpoint=self.handle,
            methods=["GET"],
            name="cimd-document",
        )

    def get_client_id_url(self, base_url: str) -> str:
        """Get the full client_id URL for this CIMD document.

        Args:
            base_url: Base URL of your server (e.g., "https://my-aggregator.com")

        Returns:
            Full URL to the CIMD document (your client_id)

        Example:
            ```python
            cimd_route = CIMDRoute(client_name="My App", redirect_uris=[...])
            client_id = cimd_route.get_client_id_url("https://my-aggregator.com")
            # Returns: "https://my-aggregator.com/.well-known/mcp-client.json"
            ```
        """
        base = base_url.rstrip("/")
        path = self.path if self.path.startswith("/") else f"/{self.path}"
        return f"{base}{path}"
