"""Tests for CIMD (Client ID Metadata Documents) support."""

import json
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest
from pydantic import AnyHttpUrl

from fastmcp.server.auth.cimd import (
    CIMDDocument,
    CIMDFetcher,
    CIMDTrustPolicy,
    create_cimd_document,
    is_cimd_client_id,
    validate_cimd_document,
)


# -------------------------------------------------------------------------
# CIMDDocument Tests
# -------------------------------------------------------------------------


def test_cimd_document_minimal():
    """Test CIMD document with minimal required fields."""
    doc = CIMDDocument(
        client_name="Test Client",
        redirect_uris=[AnyHttpUrl("http://localhost:8080/callback")],
    )
    assert doc.client_name == "Test Client"
    assert len(doc.redirect_uris) == 1
    assert doc.token_endpoint_auth_method == "none"
    assert doc.grant_types == ["authorization_code"]


def test_cimd_document_full():
    """Test CIMD document with all fields."""
    doc = CIMDDocument(
        client_name="Test Client",
        client_uri=AnyHttpUrl("https://example.com"),
        logo_uri=AnyHttpUrl("https://example.com/logo.png"),
        redirect_uris=[
            AnyHttpUrl("http://localhost:8080/callback"),
            AnyHttpUrl("https://example.com/callback"),
        ],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
        token_endpoint_auth_method="none",
    )
    assert doc.client_name == "Test Client"
    assert str(doc.client_uri) == "https://example.com/"
    assert len(doc.redirect_uris) == 2
    assert doc.scope == "read write"


def test_cimd_document_requires_redirect_uris():
    """Test that redirect_uris is required."""
    with pytest.raises(ValueError, match="At least one redirect_uri is required"):
        CIMDDocument(
            client_name="Test Client",
            redirect_uris=[],
        )


def test_cimd_document_validates_auth_method():
    """Test that invalid auth method is rejected."""
    with pytest.raises(ValueError, match="Invalid token_endpoint_auth_method"):
        CIMDDocument(
            client_name="Test Client",
            redirect_uris=[AnyHttpUrl("http://localhost/callback")],
            token_endpoint_auth_method="invalid",
        )


# -------------------------------------------------------------------------
# CIMDTrustPolicy Tests
# -------------------------------------------------------------------------


def test_trust_policy_empty():
    """Test empty trust policy."""
    policy = CIMDTrustPolicy()
    assert not policy.is_trusted("https://example.com/cimd.json")
    assert not policy.is_blocked("https://example.com/cimd.json")


def test_trust_policy_trusted_domains():
    """Test trusted domain matching."""
    policy = CIMDTrustPolicy(
        trusted_domains=["example.com", "trusted.org"],
    )
    assert policy.is_trusted("https://example.com/cimd.json")
    assert policy.is_trusted("https://trusted.org/client.json")
    assert not policy.is_trusted("https://evil.com/cimd.json")


def test_trust_policy_wildcard_subdomain():
    """Test wildcard subdomain matching."""
    policy = CIMDTrustPolicy(
        trusted_domains=["*.example.com"],
    )
    assert policy.is_trusted("https://app.example.com/cimd.json")
    assert policy.is_trusted("https://api.example.com/client.json")
    assert not policy.is_trusted("https://example.com/cimd.json")  # No wildcard for apex
    assert not policy.is_trusted("https://evil.com/cimd.json")


def test_trust_policy_blocklist():
    """Test domain blocklist."""
    policy = CIMDTrustPolicy(
        trusted_domains=["example.com"],
        domain_blocklist=["evil.com", "*.spam.com"],
    )
    assert not policy.is_trusted("https://evil.com/cimd.json")
    assert policy.is_blocked("https://evil.com/cimd.json")
    assert policy.is_blocked("https://scam.spam.com/cimd.json")
    
    # Blocklist takes precedence over trusted
    policy2 = CIMDTrustPolicy(
        trusted_domains=["evil.com"],
        domain_blocklist=["evil.com"],
    )
    assert not policy2.is_trusted("https://evil.com/cimd.json")
    assert policy2.is_blocked("https://evil.com/cimd.json")


# -------------------------------------------------------------------------
# CIMDFetcher Tests
# -------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_fetcher_valid_document():
    """Test fetching a valid CIMD document."""
    fetcher = CIMDFetcher()
    
    # Mock HTTP response
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {
        "client_name": "Test Client",
        "redirect_uris": ["http://localhost:8080/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Mock SSRF check to bypass DNS resolution
        with patch.object(fetcher, "_check_ssrf", return_value=None):
            doc = await fetcher.fetch_document("https://example.com/cimd.json")
            
            assert doc.client_name == "Test Client"
            assert len(doc.redirect_uris) == 1


@pytest.mark.asyncio
async def test_fetcher_caching():
    """Test that fetcher caches documents."""
    fetcher = CIMDFetcher(cache_max_age=60)
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"cache-control": "max-age=30"}
    mock_response.json.return_value = {
        "client_name": "Test Client",
        "redirect_uris": ["http://localhost:8080/callback"],
    }
    
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Mock SSRF check
        with patch.object(fetcher, "_check_ssrf", return_value=None):
            # First fetch - should hit network
            doc1 = await fetcher.fetch_document("https://example.com/cimd.json")
            assert mock_client.get.call_count == 1
            
            # Second fetch - should use cache
            doc2 = await fetcher.fetch_document("https://example.com/cimd.json")
            assert mock_client.get.call_count == 1  # Still 1
            
            assert doc1.client_name == doc2.client_name


@pytest.mark.asyncio
async def test_fetcher_skip_cache():
    """Test skipping cache."""
    fetcher = CIMDFetcher()
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.return_value = {
        "client_name": "Test Client",
        "redirect_uris": ["http://localhost:8080/callback"],
    }
    
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Mock SSRF check
        with patch.object(fetcher, "_check_ssrf", return_value=None):
            await fetcher.fetch_document("https://example.com/cimd.json")
            assert mock_client.get.call_count == 1
            
            # Skip cache - should hit network again
            await fetcher.fetch_document("https://example.com/cimd.json", skip_cache=True)
            assert mock_client.get.call_count == 2


@pytest.mark.asyncio
async def test_fetcher_rejects_http():
    """Test that fetcher rejects non-HTTPS URLs."""
    fetcher = CIMDFetcher()
    
    with pytest.raises(ValueError, match="Invalid CIMD URL"):
        await fetcher.fetch_document("http://example.com/cimd.json")


@pytest.mark.asyncio
async def test_fetcher_rejects_fragment():
    """Test that fetcher rejects URLs with fragments."""
    fetcher = CIMDFetcher()
    
    with pytest.raises(ValueError, match="Invalid CIMD URL"):
        await fetcher.fetch_document("https://example.com/cimd.json#frag")


@pytest.mark.asyncio
async def test_fetcher_ssrf_protection_private_ip():
    """Test SSRF protection against private IPs."""
    fetcher = CIMDFetcher()
    
    # Mock DNS resolution to return a private IP
    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.168.1.1", 443)),
        ]
        with pytest.raises(ValueError, match="SSRF protection.*private IP"):
            await fetcher.fetch_document("https://private.example.com/cimd.json")


@pytest.mark.asyncio
async def test_fetcher_ssrf_protection_loopback():
    """Test SSRF protection against loopback addresses."""
    fetcher = CIMDFetcher()
    
    # Mock DNS resolution to return loopback IP
    with patch("socket.getaddrinfo") as mock_getaddrinfo:
        mock_getaddrinfo.return_value = [
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with pytest.raises(ValueError, match="SSRF protection"):
            await fetcher.fetch_document("https://localhost.example.com/cimd.json")


@pytest.mark.asyncio
async def test_fetcher_blocklist():
    """Test domain blocklist."""
    policy = CIMDTrustPolicy(domain_blocklist=["evil.com"])
    fetcher = CIMDFetcher(trust_policy=policy)
    
    with pytest.raises(ValueError, match="blocked"):
        await fetcher.fetch_document("https://evil.com/cimd.json")


@pytest.mark.asyncio
async def test_fetcher_invalid_json():
    """Test handling of invalid JSON."""
    fetcher = CIMDFetcher()
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.side_effect = json.JSONDecodeError("test", "doc", 0)
    
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Mock SSRF check
        with patch.object(fetcher, "_check_ssrf", return_value=None):
            with pytest.raises(ValueError, match="Failed to parse CIMD document JSON"):
                await fetcher.fetch_document("https://example.com/cimd.json")


@pytest.mark.asyncio
async def test_fetcher_invalid_document():
    """Test handling of invalid CIMD document."""
    fetcher = CIMDFetcher()
    
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.return_value = {
        "client_name": "Test",
        "redirect_uris": [],  # Empty list should fail validation
    }
    
    with patch("httpx.AsyncClient") as mock_client_class:
        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.return_value = mock_response
        mock_client_class.return_value = mock_client
        
        # Mock SSRF check
        with patch.object(fetcher, "_check_ssrf", return_value=None):
            with pytest.raises(ValueError, match="Invalid CIMD document"):
                await fetcher.fetch_document("https://example.com/cimd.json")


# -------------------------------------------------------------------------
# Helper Function Tests
# -------------------------------------------------------------------------


def test_is_cimd_client_id():
    """Test CIMD client ID detection."""
    assert is_cimd_client_id("https://example.com/cimd.json")
    assert is_cimd_client_id("https://api.example.com/client-metadata")
    
    assert not is_cimd_client_id("http://example.com/cimd.json")  # Not HTTPS
    assert not is_cimd_client_id("random-client-id")
    assert not is_cimd_client_id("client_12345")


def test_create_cimd_document():
    """Test CIMD document creation helper."""
    doc = create_cimd_document(
        client_name="Test Client",
        redirect_uris=["http://localhost:*/callback"],
        client_uri="https://example.com",
        scope="read write",
    )
    
    assert doc["client_name"] == "Test Client"
    assert doc["redirect_uris"] == ["http://localhost:*/callback"]
    assert doc["client_uri"] == "https://example.com"
    assert doc["scope"] == "read write"
    assert doc["grant_types"] == ["authorization_code"]
    assert doc["token_endpoint_auth_method"] == "none"


def test_validate_cimd_document_valid():
    """Test validation of valid CIMD document."""
    doc = {
        "client_name": "Test",
        "redirect_uris": ["http://localhost:8080/callback"],
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    
    is_valid, error = validate_cimd_document(doc)
    assert is_valid
    assert error is None


def test_validate_cimd_document_invalid():
    """Test validation of invalid CIMD document."""
    doc = {
        "client_name": "Test",
        # Missing redirect_uris (required field)
        "redirect_uris": [],  # Empty list should fail
    }
    
    is_valid, error = validate_cimd_document(doc)
    assert not is_valid
    assert error is not None
