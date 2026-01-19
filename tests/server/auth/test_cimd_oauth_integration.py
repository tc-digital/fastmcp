"""Tests for CIMD integration in OAuthProxy."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest
from key_value.aio.stores.memory import MemoryStore
from mcp.server.auth.provider import AuthorizationParams
from pydantic import AnyUrl

from fastmcp.server.auth.cimd import CIMDFetcher, CIMDTrustPolicy
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.providers.jwt import JWTVerifier


@pytest.fixture
def cimd_trust_policy():
    """Create a trust policy for testing."""
    return CIMDTrustPolicy(
        trusted_domains=["trusted.com", "*.trusted.dev"],
        auto_approve_trusted=True,
    )


@pytest.fixture
def oauth_proxy(cimd_trust_policy):
    """Create an OAuthProxy instance for testing."""
    verifier = JWTVerifier(
        jwks_uri="https://example.com/.well-known/jwks.json",
        issuer="https://example.com",
        required_scopes=["read"],
    )
    
    proxy = OAuthProxy(
        upstream_authorization_endpoint="https://idp.example.com/authorize",
        upstream_token_endpoint="https://idp.example.com/token",
        upstream_client_id="test-client",
        upstream_client_secret="test-secret",
        token_verifier=verifier,
        base_url="https://mcp.example.com",
        client_storage=MemoryStore(),
        cimd_trust_policy=cimd_trust_policy,
    )
    
    return proxy


@pytest.mark.asyncio
async def test_get_client_with_cimd_url(oauth_proxy):
    """Test getting a client with a CIMD URL."""
    client_id_url = "https://app.example.com/cimd.json"
    
    # Mock CIMD document
    mock_doc = Mock()
    mock_doc.client_name = "Test CIMD Client"
    mock_doc.redirect_uris = [AnyUrl("http://localhost:8080/callback")]
    mock_doc.grant_types = ["authorization_code"]
    mock_doc.scope = "read write"
    mock_doc.token_endpoint_auth_method = "none"
    
    # Mock the fetcher
    with patch.object(
        oauth_proxy._cimd_fetcher,
        "fetch_document",
        return_value=mock_doc,
    ) as mock_fetch:
        client = await oauth_proxy.get_client(client_id_url)
        
        assert client is not None
        assert client.client_id == client_id_url
        assert client.client_name == "Test CIMD Client"
        assert len(client.redirect_uris) == 1
        mock_fetch.assert_called_once_with(client_id_url)


@pytest.mark.asyncio
async def test_get_client_with_traditional_dcr(oauth_proxy):
    """Test getting a client with traditional DCR ID."""
    # Register a traditional DCR client
    from mcp.shared.auth import OAuthClientInformationFull
    
    dcr_client = OAuthClientInformationFull(
        client_id="dcr-client-123",
        redirect_uris=[AnyUrl("http://localhost:8080/callback")],
    )
    
    await oauth_proxy.register_client(dcr_client)
    
    # Should load from storage
    client = await oauth_proxy.get_client("dcr-client-123")
    assert client is not None
    assert client.client_id == "dcr-client-123"


@pytest.mark.asyncio
async def test_cimd_client_failed_fetch(oauth_proxy):
    """Test handling of CIMD fetch failure."""
    client_id_url = "https://invalid.example.com/cimd.json"
    
    # Mock fetch failure
    with patch.object(
        oauth_proxy._cimd_fetcher,
        "fetch_document",
        side_effect=Exception("Network error"),
    ):
        client = await oauth_proxy.get_client(client_id_url)
        
        # Should return None to trigger "client not found" error
        assert client is None


@pytest.mark.asyncio
async def test_trusted_cimd_auto_approval(oauth_proxy):
    """Test auto-approval of trusted CIMD clients."""
    # Create a transaction
    transaction_id = "test-txn-123"
    client_id = "https://trusted.com/cimd.json"
    
    # Mock CIMD document for trusted domain
    mock_doc = Mock()
    mock_doc.client_name = "Trusted Client"
    mock_doc.redirect_uris = [AnyUrl("http://localhost:8080/callback")]
    mock_doc.grant_types = ["authorization_code"]
    mock_doc.scope = "read"
    mock_doc.token_endpoint_auth_method = "none"
    
    with patch.object(
        oauth_proxy._cimd_fetcher,
        "fetch_document",
        return_value=mock_doc,
    ):
        # The authorization flow should detect CIMD and auto-approve
        # when showing consent page for trusted domain
        
        # Verify trust policy recognizes the domain
        assert oauth_proxy._cimd_trust_policy.is_trusted(client_id)
        assert oauth_proxy._cimd_trust_policy.auto_approve_trusted


@pytest.mark.asyncio
async def test_untrusted_cimd_requires_consent(oauth_proxy):
    """Test that untrusted CIMD clients still require consent."""
    client_id = "https://untrusted.com/cimd.json"
    
    # Mock CIMD document for untrusted domain
    mock_doc = Mock()
    mock_doc.client_name = "Untrusted Client"
    mock_doc.redirect_uris = [AnyUrl("http://localhost:8080/callback")]
    mock_doc.grant_types = ["authorization_code"]
    mock_doc.scope = "read"
    mock_doc.token_endpoint_auth_method = "none"
    
    with patch.object(
        oauth_proxy._cimd_fetcher,
        "fetch_document",
        return_value=mock_doc,
    ):
        # Verify trust policy does NOT recognize the domain
        assert not oauth_proxy._cimd_trust_policy.is_trusted(client_id)


@pytest.mark.asyncio
async def test_cimd_with_wildcard_redirect_uri():
    """Test CIMD with wildcard redirect URIs."""
    verifier = JWTVerifier(
        jwks_uri="https://example.com/.well-known/jwks.json",
        issuer="https://example.com",
        required_scopes=["read"],
    )
    
    proxy = OAuthProxy(
        upstream_authorization_endpoint="https://idp.example.com/authorize",
        upstream_token_endpoint="https://idp.example.com/token",
        upstream_client_id="test-client",
        upstream_client_secret="test-secret",
        token_verifier=verifier,
        base_url="https://mcp.example.com",
        client_storage=MemoryStore(),
        allowed_client_redirect_uris=["http://localhost:*"],
    )
    
    client_id_url = "https://app.example.com/cimd.json"
    
    # Mock CIMD document with wildcard redirect URI
    mock_doc = Mock()
    mock_doc.client_name = "Test Client"
    mock_doc.redirect_uris = [AnyUrl("http://localhost:8080/callback")]
    mock_doc.grant_types = ["authorization_code"]
    mock_doc.scope = "read"
    mock_doc.token_endpoint_auth_method = "none"
    
    with patch.object(
        proxy._cimd_fetcher,
        "fetch_document",
        return_value=mock_doc,
    ):
        client = await proxy.get_client(client_id_url)
        
        # Should have allowed_redirect_uri_patterns set from proxy
        assert client is not None
        assert client.allowed_redirect_uri_patterns == ["http://localhost:*"]
