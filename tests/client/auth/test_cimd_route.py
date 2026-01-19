"""Tests for CIMDRoute."""

import json

import pytest
from starlette.applications import Starlette
from starlette.testclient import TestClient

from fastmcp.client.auth.cimd_route import CIMDRoute


def test_cimd_route_initialization():
    """Test basic CIMDRoute initialization."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:8080/callback"],
    )

    assert route.client_name == "Test Client"
    assert route.redirect_uris == ["http://localhost:8080/callback"]
    assert route.path == "/.well-known/mcp-client.json"
    assert route.grant_types == ["authorization_code"]


def test_cimd_route_custom_path():
    """Test CIMDRoute with custom path."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
        path="/custom/cimd.json",
    )

    assert route.path == "/custom/cimd.json"


def test_cimd_route_with_metadata():
    """Test CIMDRoute with full metadata."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
        client_uri="https://example.com",
        logo_uri="https://example.com/logo.png",
        scope="read write",
    )

    assert route.client_uri == "https://example.com"
    assert route.logo_uri == "https://example.com/logo.png"
    assert route.scope == "read write"


def test_cimd_route_document_generation():
    """Test that route pre-generates valid CIMD document."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
        client_uri="https://example.com",
    )

    doc = route._document
    assert doc["client_name"] == "Test Client"
    assert doc["redirect_uris"] == ["http://localhost:*/callback"]
    assert doc["client_uri"] == "https://example.com"
    assert doc["grant_types"] == ["authorization_code"]
    assert doc["token_endpoint_auth_method"] == "none"


@pytest.mark.asyncio
async def test_cimd_route_handle():
    """Test CIMDRoute request handling."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:8080/callback"],
    )

    # Create a mock request
    from starlette.requests import Request

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/.well-known/mcp-client.json",
        "query_string": b"",
        "headers": [],
    }

    request = Request(scope)
    response = await route.handle(request)

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "max-age=86400" in response.headers["cache-control"]

    # Parse response body
    body = json.loads(response.body.decode())  # type: ignore[union-attr]
    assert body["client_name"] == "Test Client"
    assert body["redirect_uris"] == ["http://localhost:8080/callback"]


def test_cimd_route_as_starlette_route():
    """Test converting CIMDRoute to Starlette Route."""
    cimd_route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:8080/callback"],
    )

    starlette_route = cimd_route.as_starlette_route()

    assert starlette_route.path == "/.well-known/mcp-client.json"
    assert starlette_route.methods and "GET" in starlette_route.methods
    assert starlette_route.name == "cimd-document"


def test_cimd_route_in_starlette_app():
    """Test CIMDRoute integrated in a Starlette app."""
    cimd_route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:8080/callback"],
        client_uri="https://example.com",
    )

    app = Starlette(
        routes=[cimd_route.as_starlette_route()],
    )

    with TestClient(app) as client:
        response = client.get("/.well-known/mcp-client.json")

        assert response.status_code == 200
        assert response.headers["content-type"] == "application/json"

        data = response.json()
        assert data["client_name"] == "Test Client"
        assert data["redirect_uris"] == ["http://localhost:8080/callback"]
        assert data["client_uri"] == "https://example.com"


def test_cimd_route_get_client_id_url():
    """Test getting the full client_id URL."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
    )

    client_id = route.get_client_id_url("https://my-server.com")
    assert client_id == "https://my-server.com/.well-known/mcp-client.json"

    # Test with trailing slash
    client_id2 = route.get_client_id_url("https://my-server.com/")
    assert client_id2 == "https://my-server.com/.well-known/mcp-client.json"


def test_cimd_route_get_client_id_url_custom_path():
    """Test getting client_id URL with custom path."""
    route = CIMDRoute(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
        path="/custom/path.json",
    )

    client_id = route.get_client_id_url("https://my-server.com")
    assert client_id == "https://my-server.com/custom/path.json"
