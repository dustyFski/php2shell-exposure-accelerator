"""
PHP2Shell Checker API - an Azure port of the logic in OpenAI's
php2shell-checker (Apache-2.0), extended with remediation/WAF advice and an
Azure App Service inventory. Defensive only: reads response headers and
platform metadata, never sends exploit payloads. Modified from the original; see NOTICE.
"""
import os
import re
import socket
import asyncio
import ipaddress
from typing import List, Optional
from urllib.parse import urlparse

import httpx
import httpcore
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field

CHECKER_VERSION = "1.0.0-azure"
TABLE_AS_OF = "2026-10-21"

# Vulnerable-through patch levels, identical to openai/php2shell-checker (2026-10-20).
VULNERABLE_THROUGH = {
    "5.4": 45, "5.5": 38, "5.6": 40,
    "7.0": 33, "7.1": 33, "7.2": 34, "7.3": 33, "7.4": 33,
    "8.0": 30, "8.1": 34, "8.2": 34, "8.3": 35, "8.4": 26, "8.5": 11,
}
FIXED = {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"}
EOL_BRANCHES = {"5.4", "5.5", "5.6", "7.0", "7.1", "7.2", "7.3", "7.4", "8.0", "8.1"}
SOURCE_BACKPORT = {"7.4", "8.0", "8.1"}

VERSION_RE = re.compile(r"\bPHP[ /]([^\s,;)]+)", re.IGNORECASE)
STRICT_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)([-+~].*)?$")
PRERELEASE_RE = re.compile(r"(?:^|[-+~.])(?:dev|alpha|beta|rc)", re.IGNORECASE)


def patch_status(version: Optional[str]) -> str:
    m = STRICT_RE.match(version or "")
    if not m:
        return "unknown"
    branch = f"{int(m.group(1))}.{int(m.group(2))}"
    cutoff = VULNERABLE_THROUGH.get(branch)
    if cutoff is None:
        return "unknown"
    if int(m.group(3)) <= cutoff:
        return "vulnerable"
    if PRERELEASE_RE.search(m.group(4) or ""):
        return "unknown"
    return "ok"


def branch_of(version: Optional[str]) -> Optional[str]:
    m = STRICT_RE.match(version or "")
    return f"{int(m.group(1))}.{int(m.group(2))}" if m else None


def pick_version(text: str):
    """Worst status wins, so an OK banner cannot hide a vulnerable one."""
    version, status = None, "unknown"
    for m in VERSION_RE.finditer(text):
        cand = m.group(1)
        cs = patch_status(cand)
        if version is None or cs == "vulnerable" or status == "ok":
            version, status = cand, cs
        if status == "vulnerable":
            break
    return version, status


class UrlResult(BaseModel):
    target: str
    patch_status: str = Field(description="ok | vulnerable | unknown")
    php_version: Optional[str] = None
    branch: Optional[str] = None
    reason: str
    server_header: Optional[str] = None
    x_powered_by: Optional[str] = None
    http_status: Optional[int] = None
    recommended_version: Optional[str] = None
    end_of_life: Optional[bool] = None


ALLOWED_PORTS = {80, 443, 8080, 8443}
MAX_CONCURRENT_PROBES = int(os.environ.get("MAX_CONCURRENT_PROBES", "10"))
MAX_INVENTORY_PROBES = int(os.environ.get("MAX_INVENTORY_PROBES", "200"))
MAX_INVENTORY_ROWS = int(os.environ.get("MAX_INVENTORY_ROWS", "5000"))
_probe_slots: Optional[asyncio.Semaphore] = None


class BlockedDestination(Exception):
    pass


_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")  # RFC 6052 well-known prefix: IPv4 in the last 32 bits
_NAT64_LOCAL = ipaddress.ip_network("64:ff9b:1::/48")  # RFC 8215 local-use: operator-defined embedding, never public


def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip.split("%", 1)[0])
    if isinstance(addr, ipaddress.IPv6Address):
        # IPv6 forms that embed an IPv4 address are judged by the embedded address.
        if addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        elif addr in _NAT64_LOCAL:
            return False
        elif addr in _NAT64_WKP:
            addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
        elif addr.sixtofour:
            addr = addr.sixtofour
        elif addr.teredo:
            return False
    return addr.is_global and not addr.is_multicast


async def resolve_public(host: str, port: int) -> List[str]:
    """Resolve host and refuse loopback, private, link-local (incl. 169.254.169.254) and other non-public targets."""
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(i[4][0] for i in infos))
    if not ips or not all(_is_public(ip) for ip in ips):
        raise BlockedDestination("Destination is not a public internet address")
    return ips


class PublicOnlyBackend(httpcore.AsyncNetworkBackend):
    """Resolves and validates every connection, then connects to the validated IP so DNS cannot be re-bound.
    TLS still uses the original hostname for SNI and certificate validation."""

    def __init__(self):
        self._inner = httpcore.AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if port not in ALLOWED_PORTS:
            raise BlockedDestination(f"Port {port} is not allowed")
        last = None
        for ip in await resolve_public(host, port):
            try:
                return await self._inner.connect_tcp(ip, port, timeout=timeout, local_address=local_address,
                                                     socket_options=socket_options)
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as e:
                last = e
        raise last or httpcore.ConnectError("no address")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise BlockedDestination("Unix sockets are not allowed")

    async def sleep(self, seconds):
        await self._inner.sleep(seconds)


def _public_transport() -> httpx.AsyncHTTPTransport:
    t = httpx.AsyncHTTPTransport(verify=True, retries=0)
    pool = getattr(t, "_pool", None)
    if pool is None or not hasattr(pool, "_network_backend"):
        raise RuntimeError("Unsupported httpx/httpcore version: cannot enforce public-only destinations")
    pool._network_backend = PublicOnlyBackend()
    return t


def _clean_header(v: Optional[str]) -> Optional[str]:
    if v is None:
        return None
    return re.sub(r"[\x00-\x1f\x7f]", " ", v)[:200]


def _normalise(address: str) -> str:
    address = address.strip()
    if len(address) > 2048:
        raise ValueError("URL is too long")
    if not re.match(r"^https?://", address, re.I):
        address = "https://" + address
    if re.search(r"[\x00-\x20\x7f]", address):
        raise ValueError("URL contains spaces or control characters")
    u = urlparse(address)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Use an http:// or https:// URL")
    if u.username or u.password or u.fragment:
        raise ValueError("URL credentials and fragments are not supported")
    try:
        port = u.port or (443 if u.scheme == "https" else 80)
    except ValueError:
        raise ValueError("Invalid port")
    if port not in ALLOWED_PORTS:
        raise ValueError(f"Only ports {sorted(ALLOWED_PORTS)} are checked")
    return address


async def check_url(address: str, timeout: float = 10.0) -> UrlResult:
    global _probe_slots
    try:
        url = _normalise(address)
    except ValueError as e:
        return UrlResult(target=address, patch_status="unknown", reason=str(e))
    if _probe_slots is None:
        _probe_slots = asyncio.Semaphore(MAX_CONCURRENT_PROBES)
    server = xpb = None
    status_code = None
    try:
        async with _probe_slots:
            async with httpx.AsyncClient(transport=_public_transport(), follow_redirects=False, timeout=timeout,
                                         trust_env=False,
                                         headers={"User-Agent": "PHP2Shell-Checker-Azure/1.0 (defensive version check)"}) as client:
                for method in ("HEAD", "GET"):
                    # Stream so only the status line and headers are read; the body is never downloaded.
                    async with client.stream(method, url) as r:
                        status_code = r.status_code
                        server = r.headers.get("server") or server
                        xpb = r.headers.get("x-powered-by") or xpb
                    if status_code not in (405, 501):
                        break
    except BlockedDestination as e:
        return UrlResult(target=url, patch_status="unknown", reason=f"Not checked: {e}")
    except Exception as e:  # network errors -> unknown, never "ok"
        if isinstance(e.__context__, BlockedDestination) or isinstance(e.__cause__, BlockedDestination):
            return UrlResult(target=url, patch_status="unknown", reason="Not checked: Destination is not a public internet address")
        return UrlResult(target=url, patch_status="unknown", reason=f"Request failed: {e.__class__.__name__}")
    server, xpb = _clean_header(server), _clean_header(xpb)
    version, status = pick_version("\n".join([server or "", xpb or ""]))
    br = branch_of(version)
    return UrlResult(
        target=url, patch_status=status, php_version=version, branch=br,
        reason=("PHP " + version) if version else "PHP version not found in Server / X-Powered-By headers (hidden is NOT the same as patched)",
        server_header=server, x_powered_by=xpb, http_status=status_code,
        recommended_version=FIXED.get(br) if br else None,
        end_of_life=(br in EOL_BRANCHES) if br else None,
    )


# ---------------- Remediation / WAF advice -----------------

HOSTING = {
    "app-service-linux": "Azure App Service (Linux, built-in PHP stack)",
    "app-service-windows": "Azure App Service (Windows)",
    "container": "Custom container (App Service / AKS / Container Apps)",
    "vm": "IaaS VM / on-premises / Azure Arc",
    "unknown": "Unknown hosting",
}


def advise(version: Optional[str], hosting: str = "unknown", edge: str = "none") -> dict:
    status = patch_status(version) if version else "unknown"
    br = branch_of(version)
    steps: List[str] = []
    if status == "ok":
        steps.append(f"Version {version} is above the vulnerable cutoff for {br}. Confirm on the server (php -v / phpinfo for the SAPI actually serving requests) and check vendor backport notes.")
    else:
        if br in FIXED:
            steps.append(f"Upgrade to PHP {FIXED[br]} or later (fixed release for the {br} branch).")
        elif br in SOURCE_BACKPORT:
            steps.append(f"PHP {br} is end-of-life. Upgrade to 8.3/8.4 (preferred), use a distro/LTS vendor package with the backported fix, or build from PHP's minimal source backport for {br}.")
        elif br in EOL_BRANCHES:
            steps.append(f"PHP {br} is end-of-life with no upstream fix. Migrate to 8.3/8.4, or isolate the workload (private access / VPN / take offline) until migrated.")
        else:
            steps.append("Version unknown. Verify on the server which PHP binary and SAPI serve requests (php-fpm -v, phpinfo, package manager). Treat as vulnerable until proven otherwise.")
    hosting_notes = {
        "app-service-linux": "App Service applies PHP patch versions on built-in Linux stacks during platform updates. Check the running version via SSH/Kudu (php -v). End-of-life stacks (<=8.1) are not patched: change the stack to 8.3/8.4 in Configuration > General settings.",
        "app-service-windows": "PHP on Windows App Service is out of support since Nov 2022 (7.4). Move to App Service Linux or a container, or restrict access.",
        "container": "Rebuild the image on a patched base image and redeploy. Updating the host does not update PHP inside the image.",
        "vm": "Install the patched distro/vendor package or upstream build, then restart php-fpm / Apache so the new binary is actually serving.",
        "unknown": "Identify who owns the runtime (platform, vendor, agency) and confirm the patched build is actually serving traffic.",
    }
    interim = [
        "php.net partial mitigations (not complete): memory_limit=-1 enforced via php_admin_value; low post_max_size (8M, or 32M if uploads needed); session.upload_progress.enabled=0 in php.ini/pool config then restart workers; on 8.5 set fatal_error_backtraces=0.",
    ]
    waf = {
        "front-door": "Azure Front Door WAF: enable managed rule 99006001 (group MS-ThreatIntel-Response-CVEs, DRS 2.0/2.1/2.2). Off by default; works only when action is Block on anomaly; strips malicious response elements, no log entries. Rollout completes ~28 Oct 2026; contact Microsoft Support to expedite.",
        "app-gateway": "Application Gateway WAF v2: add a rewrite rule that deletes the Set-Cookie response header when it matches ^PHPSESSID=(?:[a-zA-Z0-9\\-]|%2[Cc])*(?:[^a-zA-Z0-9\\-;%]|%(?!2[Cc]))+[a-zA-Z0-9\\-]*[^;]+; - managed rule to follow.",
        "agc": "Application Gateway for Containers: header rewrite not supported; upgrade PHP.",
        "none": "No Azure WAF in front: consider placing internet-facing PHP behind Azure Front Door WAF (rule 99006001) or Application Gateway WAF v2 (rewrite rule) as a temporary layer while patching.",
    }
    return {
        "php_version": version, "branch": br, "patch_status": status,
        "end_of_life": (br in EOL_BRANCHES) if br else None,
        "recommended_version": FIXED.get(br) if br else "8.4.27 (or 8.3.36)",
        "hosting": HOSTING.get(hosting, hosting),
        "priority": "P1 - patch now" if status != "ok" else "P3 - verify",
        "remediation": steps,
        "hosting_guidance": hosting_notes.get(hosting, hosting_notes["unknown"]),
        "interim_mitigations": interim,
        "azure_waf": waf.get(edge, waf["none"]),
        "detection": "Hunt for PHP worker processes (php-fpm, php-cgi, httpd, apache2) spawning shells/interpreters/download tools since 20 Oct 2026; enable Defender for App Service (web shell alerts) and Defender for Servers/Endpoint on Linux.",
        "sources": [
            "https://www.php.net/archive/2026.php#2026-10-21-5",
            "https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/addressing-php2shell-cve-2026-109618-and-cve-2026-109619-upgrade-guidance-and-az/4566623",
            "https://github.com/openai/php2shell-checker",
        ],
        "disclaimer": "Version comparison only. Headers can be hidden or changed and vendor backports may fix older version numbers. UNKNOWN does not mean patched.",
    }


# ---------------- Azure inventory (Resource Graph) -----------------

ARG_QUERY = """
resources
| where type =~ 'microsoft.web/sites'
| mv-expand p = properties.siteProperties.properties
| extend pname = tostring(p.name), pvalue = tostring(p.value)
| summarize linuxFx = max(iff(pname =~ 'LinuxFxVersion', pvalue, '')), windowsFx = max(iff(pname =~ 'WindowsFxVersion', pvalue, ''))
    by id, name, resourceGroup, subscriptionId, location, appKind = tostring(['kind']),
       hostName = tostring(properties.defaultHostName), state = tostring(properties.state)
| where linuxFx startswith 'PHP' or linuxFx startswith 'DOCKER' or windowsFx startswith 'PHP'
| extend phpWin = iff(windowsFx startswith 'PHP', replace_string(windowsFx, 'PHP|', ''), '')
| project subscriptionId, resourceGroup, name, location, appKind, state, hostName, linuxFx, phpWin
"""


GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def allowed_subscriptions() -> set:
    return {s.strip().lower() for s in os.environ.get("ALLOWED_SUBSCRIPTION_IDS", "").split(",") if s.strip()}


def authorise_subscriptions(subscription_ids: List[str]) -> List[str]:
    """Server-side scope check: only subscriptions configured at deployment time may be inventoried."""
    allowed = allowed_subscriptions()
    if not allowed:
        raise HTTPException(403, "Inventory is disabled: ALLOWED_SUBSCRIPTION_IDS is not configured")
    subs = [s.strip().lower() for s in subscription_ids]
    bad = [s for s in subs if not GUID_RE.match(s) or s not in allowed]
    if bad:
        raise HTTPException(403, "Subscription(s) not enabled for this deployment: " + ", ".join(b[:40] for b in bad[:5]))
    return list(dict.fromkeys(subs))


async def azure_inventory(subscription_ids: List[str]):
    from azure.identity import DefaultAzureCredential
    cred = DefaultAzureCredential(exclude_interactive_browser_credential=True)
    token = (await asyncio.to_thread(cred.get_token, "https://management.azure.com/.default")).token
    rows, skip, truncated = [], None, False
    async with httpx.AsyncClient(timeout=60) as c:
        while True:
            options = {"resultFormat": "objectArray", "$top": 1000}
            if skip:
                options["$skipToken"] = skip
            body = {"subscriptions": subscription_ids, "query": ARG_QUERY, "options": options}
            r = await c.post("https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01",
                             json=body, headers={"Authorization": "Bearer " + token})
            if r.status_code >= 400:
                raise HTTPException(r.status_code, r.text[:500])
            data = r.json()
            rows.extend(data.get("data", []))
            skip = data.get("$skipToken")
            if not skip:
                truncated = truncated or str(data.get("resultTruncated", "false")).lower() == "true"
                break
            if len(rows) >= MAX_INVENTORY_ROWS:
                truncated = True
                break
    rows = rows[:MAX_INVENTORY_ROWS]
    out = []
    for row in rows:
        lfx = row.get("linuxFx") or ""
        if lfx.upper().startswith("PHP|"):
            branch = lfx.split("|", 1)[1]
            hosting = "app-service-linux"
        elif row.get("phpWin"):
            branch = row["phpWin"]
            hosting = "app-service-windows"
        else:
            branch = None
            hosting = "container"
        eol = branch in EOL_BRANCHES if branch else None
        if hosting == "app-service-windows":
            platform = "Not patched by platform (PHP on Windows App Service is out of support)"
        elif hosting == "app-service-linux" and not eol:
            platform = "Platform applies PHP patch versions on built-in Linux stacks - verify running version"
        elif hosting == "app-service-linux":
            platform = "End-of-life stack - platform does not patch; change stack to 8.3/8.4"
        else:
            platform = "Self-managed image - rebuild on patched base image"
        out.append({**row, "php_branch": branch, "hosting": hosting, "end_of_life": eol,
                    "recommended_version": FIXED.get(branch or "", "8.4.27"),
                    "platform_patching": platform,
                    "url": f"https://{row.get('hostName')}" if row.get("hostName") else None})
    return out, truncated


# ---------------- API -----------------

app = FastAPI(
    title="PHP2Shell Checker API (Azure)",
    version=CHECKER_VERSION,
    description="Defensive PHP2Shell (CVE-2026-109618 / CVE-2026-109619) exposure checks. Port of OpenAI php2shell-checker logic plus Azure remediation, WAF guidance and App Service inventory. Never sends exploit payloads.",
    servers=[{"url": os.environ.get("PUBLIC_BASE_URL", "http://localhost:8000")}],
)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


class BatchRequest(BaseModel):
    urls: List[str] = Field(..., max_length=50, description="List of URLs or hostnames to check (max 50)")


class InventoryRequest(BaseModel):
    subscription_ids: List[str] = Field(..., min_length=1, max_length=20,
                                        description="Azure subscription IDs to inventory (must be enabled for this deployment)")
    probe: bool = Field(True, description="Also run the header check against each app's default hostname")


@app.get("/check/url", response_model=UrlResult, operation_id="checkUrl",
         summary="Check the PHP version advertised by one URL/hostname and classify it as ok, vulnerable or unknown")
async def api_check_url(url: str = Query(..., description="URL or hostname, e.g. https://example.com")):
    return await check_url(url)


@app.post("/check/batch", response_model=List[UrlResult], operation_id="checkBatch",
          summary="Check up to 50 URLs/hostnames in parallel")
async def api_check_batch(req: BatchRequest):
    return await asyncio.gather(*(check_url(u) for u in req.urls))


@app.get("/check/version", operation_id="checkVersion",
         summary="Classify a PHP version string (e.g. from php -v on the server) as ok, vulnerable or unknown")
async def api_check_version(version: str = Query(..., description="PHP version, e.g. 8.3.35")):
    br = branch_of(version)
    return {"php_version": version, "branch": br, "patch_status": patch_status(version),
            "recommended_version": FIXED.get(br) if br else None, "end_of_life": (br in EOL_BRANCHES) if br else None}


@app.get("/advise", operation_id="getRemediationAdvice",
         summary="Get remediation, interim mitigation and Azure WAF guidance for a PHP version and hosting model")
async def api_advise(version: Optional[str] = Query(None, description="PHP version if known, e.g. 8.1.20"),
                     hosting: str = Query("unknown", description="app-service-linux | app-service-windows | container | vm | unknown"),
                     edge: str = Query("none", description="front-door | app-gateway | agc | none")):
    return advise(version, hosting, edge)


@app.post("/inventory/azure", operation_id="inventoryAzurePhpApps",
          summary="List PHP web apps in the given Azure subscriptions (via Resource Graph) and optionally header-check each one")
async def api_inventory(req: InventoryRequest):
    subs = authorise_subscriptions(req.subscription_ids)
    apps, truncated = await azure_inventory(subs)
    probed = 0
    if req.probe:
        targets = [a["url"] for a in apps if a.get("url")][:MAX_INVENTORY_PROBES]
        probed = len(targets)
        results = await asyncio.gather(*(check_url(u) for u in targets))
        by_url = {r.target.rstrip('/'): r for r in results}
        for a in apps:
            r = by_url.get((a.get("url") or "").rstrip('/'))
            if r:
                a["advertised_version"] = r.php_version
                a["header_status"] = r.patch_status
    notes = []
    if truncated:
        notes.append(f"Inventory is INCOMPLETE: more than {MAX_INVENTORY_ROWS} apps or the query result was truncated.")
    if req.probe and probed < sum(1 for a in apps if a.get("url")):
        notes.append(f"Only the first {MAX_INVENTORY_PROBES} apps were header-checked.")
    return {"count": len(apps), "complete": not truncated, "probed": probed, "notes": notes, "apps": apps}


@app.get("/vulnerable-table", operation_id="getVulnerableTable", summary="Return the vulnerable version table and fixed versions used by the checker")
async def api_table():
    return {"as_of": TABLE_AS_OF, "vulnerable_through": {k: f"{k}.0 - {k}.{v}" for k, v in VULNERABLE_THROUGH.items()},
            "fixed": FIXED, "end_of_life_branches": sorted(EOL_BRANCHES)}


@app.get("/healthz", include_in_schema=False)
async def health():
    return {"ok": True, "version": CHECKER_VERSION}


STATIC = os.path.join(os.path.dirname(__file__), "static")


@app.get("/", include_in_schema=False)
async def index():
    p = os.path.join(STATIC, "index.html")
    if os.path.exists(p):
        return FileResponse(p)
    return HTMLResponse("<h1>PHP2Shell Checker API</h1><p>See <a href='/docs'>/docs</a></p>")
