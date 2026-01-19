"""Client ID Metadata Documents (CIMD) support for OAuth authentication.

This module implements CIMD (SEP-991) - a simpler alternative to Dynamic Client
Registration where clients host a static JSON document at an HTTPS URL, and that
URL becomes their client_id.

References:
- SEP-991: https://github.com/modelcontextprotocol/modelcontextprotocol/issues/991
- IETF Draft: https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/
- MCP SDK v1.23.0: https://github.com/modelcontextprotocol/python-sdk/releases/tag/v1.23.0
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import AnyHttpUrl, BaseModel, Field, field_validator

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)


# -------------------------------------------------------------------------
# CIMD Document Model
# -------------------------------------------------------------------------


class CIMDDocument(BaseModel):
    """Client ID Metadata Document per IETF draft.
    
    This document is hosted at an HTTPS URL which becomes the client_id.
    It contains metadata about the OAuth client including redirect URIs,
    grant types, and other OAuth client properties.
    """
    
    client_name: str | None = Field(
        None,
        description="Human-readable name of the client",
    )
    client_uri: AnyHttpUrl | None = Field(
        None,
        description="URL of the client's homepage",
    )
    logo_uri: AnyHttpUrl | None = Field(
        None,
        description="URL of the client's logo image",
    )
    redirect_uris: list[AnyHttpUrl] = Field(
        default_factory=list,
        description="Array of redirect URIs for this client",
    )
    grant_types: list[str] = Field(
        default=["authorization_code"],
        description="OAuth grant types this client uses",
    )
    response_types: list[str] = Field(
        default=["code"],
        description="OAuth response types this client uses",
    )
    scope: str | None = Field(
        None,
        description="Space-separated list of scope values",
    )
    token_endpoint_auth_method: str = Field(
        default="none",
        description="Authentication method for token endpoint",
    )
    
    @field_validator("redirect_uris")
    @classmethod
    def validate_redirect_uris(cls, v: list[AnyHttpUrl]) -> list[AnyHttpUrl]:
        """Validate redirect URIs."""
        if not v:
            raise ValueError("At least one redirect_uri is required")
        return v
    
    @field_validator("token_endpoint_auth_method")
    @classmethod
    def validate_auth_method(cls, v: str) -> str:
        """Validate token endpoint auth method.
        
        CIMD clients typically use 'none' since they don't have secrets.
        """
        valid_methods = ["none", "client_secret_post", "client_secret_basic"]
        if v not in valid_methods:
            raise ValueError(
                f"Invalid token_endpoint_auth_method: {v}. "
                f"Must be one of: {', '.join(valid_methods)}"
            )
        return v


# -------------------------------------------------------------------------
# CIMD Trust Policy
# -------------------------------------------------------------------------


class CIMDTrustPolicy(BaseModel):
    """Configuration for trusting CIMD clients.
    
    Allows server operators to configure which CIMD clients should be
    automatically approved without showing a consent screen.
    """
    
    trusted_domains: list[str] = Field(
        default_factory=list,
        description="List of trusted domain names (e.g., 'claude.ai', 'cursor.com')",
    )
    auto_approve_trusted: bool = Field(
        default=False,
        description="Automatically approve authorization for trusted domains",
    )
    domain_blocklist: list[str] = Field(
        default_factory=list,
        description="List of blocked domain names that will be rejected",
    )
    
    def is_trusted(self, client_id_url: str) -> bool:
        """Check if a client_id URL is from a trusted domain.
        
        Args:
            client_id_url: The client_id URL to check
            
        Returns:
            True if the domain is trusted, False otherwise
        """
        try:
            parsed = urlparse(client_id_url)
            domain = parsed.hostname
            if not domain:
                return False
            
            # Check blocklist first
            if any(self._domain_matches(domain, blocked) for blocked in self.domain_blocklist):
                logger.debug("Client ID domain %s is blocklisted", domain)
                return False
            
            # Check trusted domains
            return any(self._domain_matches(domain, trusted) for trusted in self.trusted_domains)
        except Exception as e:
            logger.warning("Error checking trust for client_id %s: %s", client_id_url, e)
            return False
    
    def is_blocked(self, client_id_url: str) -> bool:
        """Check if a client_id URL is from a blocked domain.
        
        Args:
            client_id_url: The client_id URL to check
            
        Returns:
            True if the domain is blocked, False otherwise
        """
        try:
            parsed = urlparse(client_id_url)
            domain = parsed.hostname
            if not domain:
                return False
            
            return any(self._domain_matches(domain, blocked) for blocked in self.domain_blocklist)
        except Exception as e:
            logger.warning("Error checking blocklist for client_id %s: %s", client_id_url, e)
            return False
    
    @staticmethod
    def _domain_matches(domain: str, pattern: str) -> bool:
        """Check if a domain matches a pattern.
        
        Supports exact matches and wildcard subdomains (e.g., '*.example.com').
        """
        domain = domain.lower()
        pattern = pattern.lower()
        
        # Exact match
        if domain == pattern:
            return True
        
        # Wildcard subdomain match (*.example.com matches app.example.com)
        if pattern.startswith("*."):
            base = pattern[2:]
            return domain.endswith(f".{base}")
        
        return False


# -------------------------------------------------------------------------
# CIMD Fetcher
# -------------------------------------------------------------------------


class CIMDFetcher:
    """Fetches and validates CIMD documents with security features.
    
    Features:
    - SSRF protection (blocks private/loopback addresses)
    - HTTP caching with header respect (max 24hr per spec)
    - Domain blocklists
    - Timeout and retry handling
    """
    
    def __init__(
        self,
        trust_policy: CIMDTrustPolicy | None = None,
        cache_max_age: int = 24 * 60 * 60,  # 24 hours
        timeout: int = 10,
        max_size_bytes: int = 100 * 1024,  # 100KB
    ):
        """Initialize CIMD fetcher.
        
        Args:
            trust_policy: Optional trust policy for domain validation
            cache_max_age: Maximum cache age in seconds (default 24 hours)
            timeout: HTTP request timeout in seconds
            max_size_bytes: Maximum document size in bytes
        """
        self.trust_policy = trust_policy or CIMDTrustPolicy()
        self.cache_max_age = cache_max_age
        self.timeout = timeout
        self.max_size_bytes = max_size_bytes
        
        # Simple in-memory cache: {url: (document, expires_at)}
        self._cache: dict[str, tuple[CIMDDocument, float]] = {}
    
    async def fetch_document(
        self,
        client_id_url: str,
        skip_cache: bool = False,
    ) -> CIMDDocument:
        """Fetch and validate a CIMD document.
        
        Args:
            client_id_url: The client_id URL to fetch
            skip_cache: If True, bypass the cache and fetch fresh
            
        Returns:
            Validated CIMDDocument
            
        Raises:
            ValueError: If the URL is invalid or document is malformed
            httpx.HTTPError: If the fetch fails
        """
        # Validate URL format
        if not self._is_valid_cimd_url(client_id_url):
            raise ValueError(f"Invalid CIMD URL: {client_id_url}")
        
        # Check blocklist
        if self.trust_policy.is_blocked(client_id_url):
            raise ValueError(f"CIMD URL domain is blocked: {client_id_url}")
        
        # Check cache
        if not skip_cache:
            cached = self._get_cached(client_id_url)
            if cached:
                logger.debug("Using cached CIMD document for %s", client_id_url)
                return cached
        
        # Perform SSRF checks before fetching
        await self._check_ssrf(client_id_url)
        
        # Fetch document
        logger.info("Fetching CIMD document from %s", client_id_url)
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.get(client_id_url, follow_redirects=True)
            response.raise_for_status()
            
            # Check size
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > self.max_size_bytes:
                raise ValueError(
                    f"CIMD document too large: {content_length} bytes "
                    f"(max {self.max_size_bytes})"
                )
            
            # Parse JSON
            try:
                data = response.json()
            except Exception as e:
                raise ValueError(f"Failed to parse CIMD document JSON: {e}") from e
            
            # Validate document
            try:
                document = CIMDDocument(**data)
            except Exception as e:
                raise ValueError(f"Invalid CIMD document: {e}") from e
        
        # Cache the document
        cache_control = response.headers.get("cache-control", "")
        cache_age = self._parse_cache_age(cache_control)
        self._cache_document(client_id_url, document, cache_age)
        
        logger.info(
            "Successfully fetched and validated CIMD document for %s (cached for %d seconds)",
            client_id_url,
            cache_age,
        )
        return document
    
    def _is_valid_cimd_url(self, url: str) -> bool:
        """Check if a URL is valid for CIMD.
        
        CIMD URLs must:
        - Use HTTPS (for security)
        - Have a valid hostname
        - Not contain fragments
        """
        try:
            parsed = urlparse(url)
            
            # Must use HTTPS
            if parsed.scheme != "https":
                logger.warning("CIMD URL must use HTTPS: %s", url)
                return False
            
            # Must have a hostname
            if not parsed.hostname:
                logger.warning("CIMD URL missing hostname: %s", url)
                return False
            
            # Must not have a fragment
            if parsed.fragment:
                logger.warning("CIMD URL must not contain fragment: %s", url)
                return False
            
            return True
        except Exception as e:
            logger.warning("Invalid CIMD URL format: %s (%s)", url, e)
            return False
    
    async def _check_ssrf(self, url: str) -> None:
        """Check for SSRF vulnerabilities.
        
        Blocks requests to:
        - Private IP addresses (RFC 1918)
        - Loopback addresses
        - Link-local addresses
        - Multicast addresses
        
        Raises:
            ValueError: If the URL would result in SSRF
        """
        parsed = urlparse(url)
        hostname = parsed.hostname
        
        if not hostname:
            raise ValueError("Invalid URL: missing hostname")
        
        # Resolve hostname to IP address
        try:
            # Use getaddrinfo to resolve hostname
            import socket
            
            # Get address info
            addr_info = socket.getaddrinfo(
                hostname,
                parsed.port or 443,
                family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM,
            )
            
            # Check all resolved addresses
            for family, _, _, _, sockaddr in addr_info:
                ip_str = sockaddr[0]
                try:
                    ip = ipaddress.ip_address(ip_str)
                    
                    # Check for private/special addresses
                    if ip.is_private:
                        raise ValueError(
                            f"SSRF protection: Cannot fetch from private IP address: {ip}"
                        )
                    if ip.is_loopback:
                        raise ValueError(
                            f"SSRF protection: Cannot fetch from loopback address: {ip}"
                        )
                    if ip.is_link_local:
                        raise ValueError(
                            f"SSRF protection: Cannot fetch from link-local address: {ip}"
                        )
                    if ip.is_multicast:
                        raise ValueError(
                            f"SSRF protection: Cannot fetch from multicast address: {ip}"
                        )
                    if ip.is_reserved:
                        raise ValueError(
                            f"SSRF protection: Cannot fetch from reserved address: {ip}"
                        )
                except ValueError as e:
                    # Re-raise our SSRF errors
                    if "SSRF protection" in str(e):
                        raise
                    # Ignore invalid IP string format errors
                    logger.debug("Could not parse IP address %s: %s", ip_str, e)
        
        except OSError as e:
            raise ValueError(f"Failed to resolve hostname {hostname}: {e}") from e
    
    def _parse_cache_age(self, cache_control: str) -> int:
        """Parse max-age from Cache-Control header.
        
        Returns the minimum of:
        - max-age from Cache-Control header
        - self.cache_max_age (24 hours by default per spec)
        """
        # Default to configured max age
        max_age = self.cache_max_age
        
        # Try to parse max-age directive
        if cache_control:
            match = re.search(r"max-age=(\d+)", cache_control)
            if match:
                try:
                    header_max_age = int(match.group(1))
                    # Use the minimum of header and configured max
                    max_age = min(header_max_age, self.cache_max_age)
                except ValueError:
                    pass
        
        return max_age
    
    def _cache_document(
        self,
        url: str,
        document: CIMDDocument,
        cache_age: int,
    ) -> None:
        """Store document in cache.
        
        Args:
            url: The URL to cache
            document: The document to cache
            cache_age: Cache duration in seconds
        """
        expires_at = time.time() + cache_age
        self._cache[url] = (document, expires_at)
        logger.debug("Cached CIMD document for %s (expires at %f)", url, expires_at)
    
    def _get_cached(self, url: str) -> CIMDDocument | None:
        """Get document from cache if valid.
        
        Args:
            url: The URL to look up
            
        Returns:
            Cached document if valid, None otherwise
        """
        if url not in self._cache:
            return None
        
        document, expires_at = self._cache[url]
        
        # Check if expired
        if time.time() > expires_at:
            logger.debug("Cached CIMD document for %s has expired", url)
            del self._cache[url]
            return None
        
        return document
    
    def clear_cache(self) -> None:
        """Clear all cached documents."""
        self._cache.clear()
        logger.debug("Cleared CIMD document cache")


# -------------------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------------------


def is_cimd_client_id(client_id: str) -> bool:
    """Check if a client_id is a CIMD URL.
    
    CIMD client IDs are HTTPS URLs that point to a JSON document.
    
    Args:
        client_id: The client_id to check
        
    Returns:
        True if it looks like a CIMD URL, False otherwise
    """
    try:
        parsed = urlparse(client_id)
        return parsed.scheme == "https" and bool(parsed.hostname)
    except Exception:
        return False


def create_cimd_document(
    client_name: str,
    redirect_uris: list[str],
    client_uri: str | None = None,
    logo_uri: str | None = None,
    grant_types: list[str] | None = None,
    scope: str | None = None,
) -> dict[str, Any]:
    """Create a CIMD document dictionary.
    
    This helper makes it easy to generate a valid CIMD document that can be
    hosted at an HTTPS URL to serve as your client_id.
    
    Args:
        client_name: Human-readable name of your client
        redirect_uris: List of redirect URIs (use "http://localhost:*/callback" for wildcards)
        client_uri: Optional homepage URL
        logo_uri: Optional logo URL
        grant_types: OAuth grant types (default: ["authorization_code"])
        scope: Space-separated scopes
        
    Returns:
        Dictionary that can be JSON-serialized and hosted
        
    Example:
        >>> doc = create_cimd_document(
        ...     client_name="My App",
        ...     redirect_uris=["http://localhost:*/callback"],
        ...     client_uri="https://myapp.com",
        ... )
        >>> import json
        >>> print(json.dumps(doc, indent=2))
    """
    # Build document dict directly to avoid pydantic validation of wildcards
    document_dict: dict[str, Any] = {
        "client_name": client_name,
        "redirect_uris": redirect_uris,
        "grant_types": grant_types or ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    
    if client_uri:
        document_dict["client_uri"] = client_uri
    if logo_uri:
        document_dict["logo_uri"] = logo_uri
    if scope:
        document_dict["scope"] = scope
    
    return document_dict


def validate_cimd_document(data: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate a CIMD document dictionary.
    
    Args:
        data: Dictionary to validate
        
    Returns:
        Tuple of (is_valid, error_message)
        
    Example:
        >>> doc = {"client_name": "My App", "redirect_uris": ["http://localhost/callback"]}
        >>> is_valid, error = validate_cimd_document(doc)
        >>> if not is_valid:
        ...     print(f"Invalid: {error}")
    """
    try:
        CIMDDocument(**data)
        return True, None
    except Exception as e:
        return False, str(e)
