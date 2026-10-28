"""Security gateway, SSRF protection, URL validation, and safe network clients for URL Audit Kit."""

from __future__ import annotations

import contextvars
import ipaddress
import os
import re
import socket
import ssl
import time
import urllib.parse
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import certifi
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import ConnectTimeoutError, NameResolutionError, NewConnectionError
from urllib3.poolmanager import PoolManager
from urllib3.util import connection as urllib3_conn

# ---------------------------------------------------------------------------
# Constants & Configuration
# ---------------------------------------------------------------------------

DEFAULT_ALLOWED_PORTS: Set[int] = {80, 443}
DEFAULT_MAX_REDIRECTS: int = 5
DEFAULT_CONNECT_TIMEOUT: float = float(os.getenv("URL_AUDIT_CONNECT_TIMEOUT", "3.0"))
DEFAULT_READ_TIMEOUT: float = float(os.getenv("URL_AUDIT_READ_TIMEOUT", "4.0"))
DEFAULT_SCAN_DEADLINE: float = float(os.getenv("URL_AUDIT_SCAN_DEADLINE", "12.0"))

CURRENT_AUDIT_DEADLINE: contextvars.ContextVar[Optional[float]] = contextvars.ContextVar(
    "CURRENT_AUDIT_DEADLINE", default=None
)

def set_scan_deadline(deadline_ts: Optional[float]) -> contextvars.Token:
    """Sets the active audit deadline timestamp for the current execution."""
    return CURRENT_AUDIT_DEADLINE.set(deadline_ts)


def reset_scan_deadline(token: contextvars.Token) -> None:
    """Resets the audit deadline context variable."""
    CURRENT_AUDIT_DEADLINE.reset(token)


def get_remaining_deadline() -> Optional[float]:
    """Calculates remaining seconds before the active scan deadline expires using monotonic clock."""
    dl = CURRENT_AUDIT_DEADLINE.get()
    if dl is None:
        return None
    time_rem = dl - time.time()
    mono_rem = dl - time.monotonic()
    # Seamlessly supports both monotonic clock and patched time.time() in unit tests
    if abs(time_rem) < 500:
        return max(0.0, time_rem)
    return max(0.0, mono_rem)

CONTROL_CHAR_RE = re.compile(r"[\x00-\x1f\x7f]")
BLOCKED_HOSTNAMES: Set[str] = {
    "localhost",
    "metadata.google.internal",
    "metadata",
    "instance-data",
}
BLOCKED_HOSTNAME_SUFFIXES: Tuple[str, ...] = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home.arpa",
)

BLOCKED_EXPLICIT_IPS: Set[str] = {
    "169.254.169.254",   # AWS / GCP / Azure Cloud Metadata
    "169.254.169.253",   # Azure internal DNS
    "fd00:ec2::254",     # AWS IPv6 Metadata
    "100.100.100.200",   # Alibaba Cloud Metadata
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class URLSecurityError(Exception):
    """Base exception for URL and SSRF security violations."""
    pass


class InvalidURLError(URLSecurityError):
    """Raised when an ingress URL is malformed or invalid."""
    pass


class SSRFError(URLSecurityError):
    """Raised when an egress destination resolves to a restricted or private address."""
    pass


class RedirectSecurityError(URLSecurityError):
    """Raised when a redirect violates security policy or exceeds limits."""
    pass


class AuditTimeoutError(URLSecurityError):
    """Raised when an operation or scan exceeds its allotted deadline."""
    pass


class DNSResolutionError(URLSecurityError):
    """Raised when DNS resolution fails for a target host."""
    pass


class DNSNXDomainError(DNSResolutionError):
    """Raised when the domain does not exist in DNS (NXDOMAIN)."""
    pass


class DNSTimeoutError(DNSResolutionError):
    """Raised when DNS resolution times out."""
    pass


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ValidatedURL:
    """Structured representation of a validated, sanitized target URL."""
    raw_url: str
    scheme: str
    hostname: str
    port: int
    path: str
    query: str
    fragment: str
    canonical_url: str

    @property
    def is_https(self) -> bool:
        return self.scheme == "https"

    @property
    def authority(self) -> str:
        if (self.scheme == "http" and self.port == 80) or (self.scheme == "https" and self.port == 443):
            return self.hostname
        return f"{self.hostname}:{self.port}"


# ---------------------------------------------------------------------------
# 1. Strict URL Gateway Validation
# ---------------------------------------------------------------------------

def get_allowed_ports() -> Set[int]:
    """Retrieves the set of permitted outbound destination ports."""
    raw = os.getenv("ALLOWED_OUTBOUND_PORTS", "").strip()
    if not raw:
        return set(DEFAULT_ALLOWED_PORTS)
    ports: Set[int] = set()
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            p = int(part)
            if 1 <= p <= 65535:
                ports.add(p)
    return ports if ports else set(DEFAULT_ALLOWED_PORTS)


def validate_url(
    url: str,
    allowed_ports: Optional[Set[int]] = None,
) -> ValidatedURL:
    """Strictly validates an ingress URL against syntax, scheme, authority, and port policies.
    
    Rejects:
    - Empty or non-string inputs
    - Embedded control characters or whitespace
    - Unsupported schemes (javascript:, file:, data:, ftp:, blob:, etc.)
    - Missing authority or hostname
    - Embedded credentials (userinfo)
    - Unclosed or malformed IPv6 brackets
    - Ports outside the allowed outbound list
    """
    if not isinstance(url, str) or not url.strip():
        raise InvalidURLError("URL cannot be empty.")

    clean_url = url.strip()

    if CONTROL_CHAR_RE.search(clean_url) or any(c.isspace() for c in clean_url):
        raise InvalidURLError("URL contains forbidden control characters or whitespace.")

    try:
        parsed = urllib.parse.urlsplit(clean_url)
    except ValueError as exc:
        raise InvalidURLError(f"Malformed URL structure: {exc}") from exc

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"}:
        if not scheme:
            raise InvalidURLError("Missing URL scheme. Only explicit 'http://' and 'https://' URLs are permitted.")
        raise InvalidURLError(f"Unsupported scheme '{parsed.scheme}'. Only 'http://' and 'https://' are allowed.")

    if not parsed.netloc:
        raise InvalidURLError("Malformed URL: Missing host authority.")

    if parsed.username is not None or parsed.password is not None:
        raise InvalidURLError("URLs with embedded authentication credentials (userinfo) are not permitted.")

    # Validate IPv6 formatting if bracketed
    netloc = parsed.netloc
    if "[" in netloc or "]" in netloc:
        if not (netloc.startswith("[") and "]" in netloc):
            raise InvalidURLError("Malformed IPv6 authority bracket notation.")
        ipv6_str = netloc[1:netloc.index("]")]
        try:
            ipaddress.IPv6Address(ipv6_str)
        except ValueError as exc:
            raise InvalidURLError(f"Malformed IPv6 address in URL: {exc}") from exc

    host = parsed.hostname
    if not host:
        raise InvalidURLError("Malformed URL: Could not extract valid hostname.")

    if parse_ip_safe(host) is None:
        try:
            import idna
            idna.decode(host)
        except Exception as exc:
            raise InvalidURLError(f"Malformed IDNA or Punycode hostname '{host}': {exc}") from exc

    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidURLError(f"Invalid port specification: {exc}") from exc

    if port is None:
        port = 443 if scheme == "https" else 80
    elif not (1 <= port <= 65535):
        raise InvalidURLError(f"Port {port} is out of allowable range (1-65535).")

    allowed = allowed_ports if allowed_ports is not None else get_allowed_ports()
    if port not in allowed:
        sorted_allowed = sorted(allowed)
        raise InvalidURLError(f"Port {port} is not in the allowed outbound ports list: {sorted_allowed}.")

    # Canonicalize URL without embedded fragment altering destination
    canonical = urllib.parse.urlunsplit((
        scheme,
        f"{host}:{port}" if (scheme == "http" and port != 80) or (scheme == "https" and port != 443) else host,
        parsed.path or "/",
        parsed.query,
        "",
    ))

    return ValidatedURL(
        raw_url=clean_url,
        scheme=scheme,
        hostname=host.lower(),
        port=port,
        path=parsed.path or "/",
        query=parsed.query,
        fragment=parsed.fragment,
        canonical_url=canonical,
    )


# ---------------------------------------------------------------------------
# 2. SSRF Protection & IP Canonicalization
# ---------------------------------------------------------------------------

def parse_ip_safe(host: str) -> Optional[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Attempts to canonicalize standard and alternative numeric/hex/octal IP representations."""
    # 1. Standard library parsing
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    # 2. Dotted notation with hex or octal parts (e.g. 0x7f.0.0.1 or 0177.0.0.1)
    if "." in host:
        parts = host.split(".")
        if len(parts) == 4 and all(p for p in parts):
            num_parts: List[int] = []
            for p in parts:
                try:
                    if p.lower().startswith("0x"):
                        num_parts.append(int(p, 16))
                    elif p.startswith("0") and len(p) > 1 and p.isdigit():
                        num_parts.append(int(p, 8))
                    elif p.isdigit():
                        num_parts.append(int(p))
                    else:
                        num_parts = []
                        break
                except ValueError:
                    raise SSRFError(f"Ambiguous or invalid numeric byte in IP: '{p}'") from None

            if len(num_parts) == 4:
                if all(0 <= b <= 255 for b in num_parts):
                    val = (num_parts[0] << 24) | (num_parts[1] << 16) | (num_parts[2] << 8) | num_parts[3]
                    return ipaddress.IPv4Address(val)
                raise SSRFError("IP address byte out of range (0-255).")

    # 3. Single integer or hex number without dots (e.g. 2130706433 or 0x7f000001)
    if host.lower().startswith("0x"):
        try:
            val = int(host, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except ValueError:
            pass
        raise SSRFError("Ambiguous or invalid hexadecimal IP notation.")

    if host.isdigit():
        if host.startswith("0") and len(host) > 1:
            try:
                val = int(host, 8)
                if 0 <= val <= 0xFFFFFFFF:
                    return ipaddress.IPv4Address(val)
            except ValueError:
                pass
        val = int(host)
        if 0 <= val <= 0xFFFFFFFF:
            return ipaddress.IPv4Address(val)
        raise SSRFError("Numeric IP out of allowable 32-bit range.")

    return None


def is_blocked_ip(ip: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> Tuple[bool, str]:
    """Determines if an IPv4 or IPv6 destination is non-public, private, or restricted."""
    ip_str = str(ip)

    if ip_str in BLOCKED_EXPLICIT_IPS:
        return True, f"Target IP {ip_str} is a restricted cloud metadata address."

    # IPv4-mapped IPv6 (::ffff:0:0/96, RFC 4291)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return is_blocked_ip(ip.ipv4_mapped)

    # NAT64 Prefixes (RFC 6052 64:ff9b::/96 and RFC 8215 64:ff9b:1::/48)
    # The last 32 bits represent the translated IPv4 address.
    if isinstance(ip, ipaddress.IPv6Address):
        nat64_wkp = ipaddress.IPv6Network("64:ff9b::/96")
        nat64_local = ipaddress.IPv6Network("64:ff9b:1::/48")
        if ip in nat64_wkp or ip in nat64_local:
            embedded_v4 = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
            blocked, reason = is_blocked_ip(embedded_v4)
            if blocked:
                return True, f"Target NAT64 IPv6 {ip_str} embeds restricted IPv4 address {embedded_v4}: {reason}"
            return False, ""

    if ip.is_loopback:
        return True, f"Target IP {ip_str} is a loopback address."

    if ip.is_private:
        return True, f"Target IP {ip_str} is a private network address (RFC 1918 / ULA)."

    if ip.is_link_local:
        return True, f"Target IP {ip_str} is a link-local address."

    if ip.is_multicast:
        return True, f"Target IP {ip_str} is a multicast address."

    if ip.is_unspecified:
        return True, f"Target IP {ip_str} is an unspecified address."

    if ip.is_reserved:
        return True, f"Target IP {ip_str} is an IETF reserved address."

    if not ip.is_global:
        return True, f"Target IP {ip_str} is a non-global address."

    # Carrier-Grade NAT (CGNAT) 100.64.0.0/10
    if isinstance(ip, ipaddress.IPv4Address) and ip in ipaddress.IPv4Network("100.64.0.0/10"):
        return True, f"Target IP {ip_str} is a Carrier-Grade NAT address."

    return False, ""


def resolve_and_validate_destination(
    hostname: str,
    port: int = 80,
    resolver: Any = None,
) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Resolves all IPv4 and IPv6 addresses for a hostname and validates them against SSRF rules.
    
    Enforces:
    - Hostname blocked lists (localhost, metadata, .internal, .local)
    - Full address resolution check (every returned address is validated)
    - Any private/restricted IP causes immediate rejection
    """
    clean_host = (hostname or "").strip().lower()
    if not clean_host:
        raise SSRFError("Hostname cannot be empty.")

    # 1. Check known forbidden hostnames
    if clean_host in BLOCKED_HOSTNAMES or any(clean_host.endswith(suffix) for suffix in BLOCKED_HOSTNAME_SUFFIXES):
        raise SSRFError(f"Host '{clean_host}' is a forbidden internal destination.")

    # 2. Check if host is a literal or alternative IP
    direct_ip = parse_ip_safe(clean_host)
    if direct_ip is not None:
        blocked, reason = is_blocked_ip(direct_ip)
        if blocked:
            raise SSRFError(f"Destination IP '{direct_ip}' rejected: {reason}")
        return [direct_ip]

    # 3. Resolve through DNS
    try:
        if resolver is not None:
            # Custom resolver callback for test injection
            addr_info = resolver(clean_host, port)
        else:
            addr_info = socket.getaddrinfo(clean_host, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        errno = getattr(exc, "errno", None)
        exc_msg = str(exc).lower()
        if (
            errno in (11001, getattr(socket, "EAI_NONAME", -2), getattr(socket, "EAI_NODATA", -5))
            or "getaddrinfo failed" in exc_msg
            or "name or service not known" in exc_msg
            or "not known" in exc_msg
        ):
            raise DNSNXDomainError(f"Domain does not exist in authoritative DNS (NXDOMAIN): '{clean_host}'") from exc
        if errno in (11002, getattr(socket, "EAI_AGAIN", -3)) or "temporary failure" in exc_msg:
            raise DNSResolutionError(f"Temporary DNS server failure for '{clean_host}': {exc}") from exc
        if errno in (10060, getattr(socket, "ETIMEDOUT", 110)) or "timeout" in exc_msg:
            raise DNSTimeoutError(f"DNS query timed out for '{clean_host}': {exc}") from exc
        raise DNSResolutionError(f"DNS resolution failed for '{clean_host}': {exc}") from exc
    except Exception as exc:
        raise DNSResolutionError(f"Could not resolve host '{clean_host}': {exc}") from exc

    if not addr_info:
        raise DNSResolutionError(f"No DNS records found for host '{clean_host}'.")

    validated_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []

    for item in addr_info:
        sockaddr = item[4]
        ip_str = sockaddr[0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SSRFError(f"DNS returned malformed IP address '{ip_str}' for host '{clean_host}'.")

        blocked, reason = is_blocked_ip(ip_obj)
        if blocked:
            raise SSRFError(
                f"SSRF violation: Host '{clean_host}' resolves to forbidden address {ip_str}: {reason}"
            )
        if ip_obj not in validated_ips:
            validated_ips.append(ip_obj)

    if not validated_ips:
        raise SSRFError(f"No permissible public addresses resolved for '{clean_host}'.")

    return validated_ips


# ---------------------------------------------------------------------------
# 3. Safe Socket Connection Factory (Direct IP with TLS SNI)
# ---------------------------------------------------------------------------

def create_default_ssl_context() -> ssl.SSLContext:
    """Creates a hardened SSLContext using certifi CA bundle if available."""
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except Exception:
        return ssl.create_default_context()


def safe_socket_create_connection(
    hostname: str,
    port: int,
    timeout: float = DEFAULT_CONNECT_TIMEOUT,
    ssl_context: Optional[ssl.SSLContext] = None,
    server_hostname: Optional[str] = None,
    deadline_ts: Optional[float] = None,
) -> Tuple[socket.socket, str]:
    """Establishes an outbound TCP socket to a pre-validated IP address.
    
    Prevents DNS rebinding and TOCTOU races by pinning the connection to an approved IP.
    Applies TLS SNI wrapping with hostname verification when ssl_context is provided.
    """
    effective_deadline = deadline_ts if deadline_ts is not None else CURRENT_AUDIT_DEADLINE.get()
    if effective_deadline is not None:
        time_rem = effective_deadline - time.time()
        mono_rem = effective_deadline - time.monotonic()
        remaining = time_rem if abs(time_rem) < 500 else mono_rem
        if remaining <= 0:
            raise AuditTimeoutError("Scan deadline exceeded before socket connection.")
        timeout = min(timeout, max(0.1, remaining))

    approved_ips = resolve_and_validate_destination(hostname, port)
    last_err: Optional[Exception] = None
    sock: Optional[socket.socket] = None
    target_ip: Optional[str] = None

    for ip_cand in approved_ips:
        cand_str = str(ip_cand)
        try:
            sock = socket.create_connection((cand_str, port), timeout=timeout)
            target_ip = cand_str
            break
        except Exception as exc:
            last_err = exc
            continue

    if sock is None or target_ip is None:
        raise last_err or OSError(f"Could not connect to any validated IP for '{hostname}'.")

    if ssl_context is not None:
        sni_host = (server_hostname or hostname).rstrip(".")
        try:
            wrapped = ssl_context.wrap_socket(sock, server_hostname=sni_host)
            return wrapped, target_ip
        except Exception:
            sock.close()
            raise

    return sock, target_ip


# ---------------------------------------------------------------------------
# 4. Safe HTTP Transport & Redirect Engine
# ---------------------------------------------------------------------------

class SSRFProtectedHTTPConnection(HTTPConnection):
    """Urllib3 HTTP connection that validates and pins destination IP on every connect."""

    def _new_conn(self) -> socket.socket:
        effective_deadline = CURRENT_AUDIT_DEADLINE.get()
        effective_timeout = self.timeout
        if effective_deadline is not None:
            remaining = effective_deadline - time.time()
            if remaining <= 0:
                raise AuditTimeoutError("Scan deadline exceeded before HTTP connection.")
            if effective_timeout is not None:
                effective_timeout = min(effective_timeout, remaining)
            else:
                effective_timeout = remaining

        approved_ips = resolve_and_validate_destination(self.host, self.port)
        last_err: Optional[Exception] = None
        for ip_cand in approved_ips:
            target_ip = str(ip_cand)
            try:
                sock = urllib3_conn.create_connection(
                    (target_ip, self.port),
                    effective_timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
                return sock
            except Exception as e:
                last_err = e
                continue

        if isinstance(last_err, socket.gaierror):
            raise NameResolutionError(self.host, self, last_err) from last_err
        if isinstance(last_err, socket.timeout):
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={effective_timeout})",
            ) from last_err
        raise NewConnectionError(
            self, f"Failed to establish a new connection: {last_err}"
        ) from last_err


class SSRFProtectedHTTPSConnection(HTTPSConnection):
    """Urllib3 HTTPS connection that pins destination IP while maintaining correct SNI."""

    def _new_conn(self) -> socket.socket:
        effective_deadline = CURRENT_AUDIT_DEADLINE.get()
        effective_timeout = self.timeout
        if effective_deadline is not None:
            remaining = effective_deadline - time.time()
            if remaining <= 0:
                raise AuditTimeoutError("Scan deadline exceeded before HTTPS connection.")
            if effective_timeout is not None:
                effective_timeout = min(effective_timeout, remaining)
            else:
                effective_timeout = remaining

        approved_ips = resolve_and_validate_destination(self.host, self.port)
        last_err: Optional[Exception] = None
        for ip_cand in approved_ips:
            target_ip = str(ip_cand)
            try:
                sock = urllib3_conn.create_connection(
                    (target_ip, self.port),
                    effective_timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
                return sock
            except Exception as e:
                last_err = e
                continue

        if isinstance(last_err, socket.gaierror):
            raise NameResolutionError(self.host, self, last_err) from last_err
        if isinstance(last_err, socket.timeout):
            raise ConnectTimeoutError(
                self,
                f"Connection to {self.host} timed out. (connect timeout={effective_timeout})",
            ) from last_err
        raise NewConnectionError(
            self, f"Failed to establish a new connection: {last_err}"
        ) from last_err


class SSRFHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = SSRFProtectedHTTPConnection


class SSRFHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = SSRFProtectedHTTPSConnection


class SSRFPoolManager(PoolManager):
    """PoolManager routing connections through SSRF-protected connection classes."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": SSRFHTTPConnectionPool,
            "https": SSRFHTTPSConnectionPool,
        }


class SSRFSafeAdapter(HTTPAdapter):
    """Requests Transport Adapter enforcing SSRF validation and destination pinning."""

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        self.poolmanager = SSRFPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **pool_kwargs,
        )


def create_safe_session() -> requests.Session:
    """Creates a configured requests.Session with SSRF-safe connection pools."""
    session = requests.Session()
    adapter = SSRFSafeAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.verify = certifi.where()
    return session


_GLOBAL_SAFE_SESSION: Optional[requests.Session] = None


def get_safe_session() -> requests.Session:
    """Returns a singleton safe session instance."""
    global _GLOBAL_SAFE_SESSION
    if _GLOBAL_SAFE_SESSION is None:
        _GLOBAL_SAFE_SESSION = create_safe_session()
    return _GLOBAL_SAFE_SESSION


def safe_request(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    connect_timeout: float = DEFAULT_CONNECT_TIMEOUT,
    read_timeout: float = DEFAULT_READ_TIMEOUT,
    allow_redirects: bool = True,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    deadline_ts: Optional[float] = None,
    allowed_ports: Optional[Set[int]] = None,
    session: Optional[requests.Session] = None,
) -> Tuple[requests.Response, List[str]]:
    """Executes an HTTP request with strict URL validation, SSRF filtering, and per-hop redirect safety.
    
    Returns:
    - response: requests.Response of the final destination
    - redirect_chain: List of all URLs visited in order
    """
    client = session or get_safe_session()
    req_headers = {"User-Agent": "URL-Audit-Kit/2.0 (Security Scanner)"}
    if headers:
        req_headers.update(headers)

    current_url = url.strip()
    redirect_chain: List[str] = [current_url]
    visited_set: Set[str] = {current_url}
    response: Optional[requests.Response] = None

    effective_deadline = deadline_ts if deadline_ts is not None else CURRENT_AUDIT_DEADLINE.get()

    while True:
        # 1. Enforce audit deadline
        if effective_deadline is not None:
            time_rem = effective_deadline - time.time()
            mono_rem = effective_deadline - time.monotonic()
            remaining = time_rem if abs(time_rem) < 500 else mono_rem
            if remaining <= 0:
                raise AuditTimeoutError("Scan deadline exceeded during HTTP request processing.")
            c_timeout = min(connect_timeout, max(0.1, remaining))
            r_timeout = min(read_timeout, max(0.1, remaining))
        else:
            c_timeout = connect_timeout
            r_timeout = read_timeout

        # 2. Validate current URL syntax and permitted ports
        val_url = validate_url(current_url, allowed_ports=allowed_ports)

        # 3. Pre-validate destination IP addresses
        resolve_and_validate_destination(val_url.hostname, val_url.port)

        # 4. Execute request without automatic redirect following
        timeout_tuple = (c_timeout, r_timeout)
        try:
            response = client.request(
                method=method,
                url=val_url.canonical_url,
                headers=req_headers,
                timeout=timeout_tuple,
                allow_redirects=False,
            )
        except (urllib3.exceptions.MaxRetryError, requests.exceptions.RetryError) as exc:
            # Check if underlying cause is SSRFError
            cause = getattr(exc, "reason", None) or exc
            if isinstance(cause, SSRFError) or "SSRF violation" in str(exc) or "forbidden" in str(exc):
                raise SSRFError(f"SSRF blocked connection to {val_url.canonical_url}: {cause}") from exc
            raise

        # 5. Handle redirects safely if requested
        if not allow_redirects or not response.is_redirect:
            break

        if len(redirect_chain) - 1 >= max_redirects:
            raise RedirectSecurityError(
                f"Exceeded maximum allowed redirect limit of {max_redirects} hops."
            )

        location = response.headers.get("Location")
        if not location:
            break

        # Resolve relative redirect URLs against the current canonical URL
        next_url = urllib.parse.urljoin(val_url.canonical_url, location).strip()

        if next_url in visited_set:
            raise RedirectSecurityError(f"Redirect loop detected: '{next_url}' was already visited.")

        visited_set.add(next_url)
        redirect_chain.append(next_url)
        current_url = next_url

    if response is None:
        raise URLSecurityError(f"No response received for URL: {url}")

    return response, redirect_chain
