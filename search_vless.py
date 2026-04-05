#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# whitevless — async vless/reality parser-validator
# runs on github actions (outside RU), targets 200+ keys for russian users
# deps: pip install aiohttp
#
# rkn/tspu status (2025-2026, source: habr.com/en/articles/990236):
#   - tspu deployed at all major isps (mts, megafon, beeline, tele2)
#   - port 443 + reality = throttled/dropped by heuristics on mts
#   - high ports (10000+) bypass tspu on most isps
#   - xhttp transport currently not matched by rkn signatures
#   - empty sni or go-default fp bypasses in some regions
#   - grpc still works on megafon/beeline
#   - digitalocean/hetzner ips blocked by tele2

import asyncio
import aiohttp
import re
import base64
import time
import os
import struct
import socket
import subprocess
import tempfile
import json
import logging
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from typing import Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("whitevless")

# ── paths ────────────────────────────────────────────────────────────────────
BASE_DIR        = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE     = os.path.join(BASE_DIR, "filtered_vless_keys.txt")

SOURCES_DIR     = os.path.join(BASE_DIR, "sources")
DIRECT_FILE     = os.path.join(SOURCES_DIR, "direct.txt")
DORKS_FILE      = os.path.join(SOURCES_DIR, "github_dorks.txt")

CONFIG_DIR      = os.path.join(BASE_DIR, "config")
IP_PREFIXES_F   = os.path.join(CONFIG_DIR, "ip_prefixes.txt")
RU_CIDR_F       = os.path.join(CONFIG_DIR, "ru_cidr.txt")
SNI_WHITELIST_F = os.path.join(CONFIG_DIR, "sni_whitelist.txt")

HXEHEX_CIDR_URL = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/cidrwhitelist.txt"
HXEHEX_SNI_URL  = "https://raw.githubusercontent.com/hxehex/russia-mobile-internet-whitelist/refs/heads/main/whitelist.txt"

SNI_DIR   = os.path.join(BASE_DIR, "sni")
SNI_FILES = {
    "mts":           os.path.join(SNI_DIR, "mts",           "sni.txt"),
    "beeline":       os.path.join(SNI_DIR, "beeline",       "sni.txt"),
    "megafon":       os.path.join(SNI_DIR, "megafon",       "sni.txt"),
    "t2":            os.path.join(SNI_DIR, "t2",            "sni.txt"),
    "yota":          os.path.join(SNI_DIR, "yota",          "sni.txt"),
    "all_operators": os.path.join(SNI_DIR, "all_operators", "sni.txt"),
}

BLACKLIST_FILE = os.path.join(BASE_DIR, "blacklist", "vless_blacklist.txt")
HOSTS_FILE     = os.path.join(BASE_DIR, "ip", "hosts.txt")

# ── limits ───────────────────────────────────────────────────────────────────
MAX_RU_KEYS      = 150
MAX_FAST_KEYS    = 20
MAX_FOREIGN_KEYS = 30
TCP_TIMEOUT      = 3.0
CONCURRENCY      = 80
# FIX: parallel L7 tests capped to avoid spawning hundreds of singbox processes
L7_CONCURRENCY   = 10
GITHUB_TOKEN     = os.environ.get("GITHUB_TOKEN", "")

# ── l7 hardcore mode (optional, skip if binary not set) ──────────────────────
SINGBOX_BIN  = os.environ.get("SINGBOX_BIN", "")
V2RAY_BIN    = os.environ.get("V2RAY_BIN", "")
# FIX: raised threshold — 10KB is too small to detect DPI reliably
L7_MIN_BYTES = 50 * 1024
L7_TIMEOUT   = 15

# ── runtime state ────────────────────────────────────────────────────────────
RU_IP_PREFIXES:    list[str]       = []
RU_CIDR_RANGES:    list[tuple]     = []
SNI_POOL:          list[str]       = []
OPERATOR_SNI:      dict[str, list] = {}
TRUSTED_HOSTS:     set[str]        = set()
# FIX: domain → country cache populated by geo batch lookup
DOMAIN_COUNTRY:    dict[str, str]  = {}
BLOCKLIST_EXACT:   set[str]        = set()
BLOCKLIST_PARTIAL: set[str]        = set()

FAST_HOSTERS = [
    "cloudflare", "fastly", "akamai", "amazon", "google",
    "hetzner", "ovh", "leaseweb", "vultr", "linode",
    "digitalocean", "contabo", "serverius", "datacamp",
]

T2_BLOCKED_ISPS = ("digitalocean", "hetzner", "linode")

AD_PATTERN = re.compile(
    r'(t\.me|telegram\.(me|org|dog)|https?://|@[\w_]{3,}|купить|прода|promo|sale|free|premium)',
    re.I,
)
ARABIC_RE = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
UUID_RE   = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)


# ── config loading ────────────────────────────────────────────────────────────

def _lines(path: str) -> list[str]:
    if not os.path.exists(path):
        log.warning(f"missing: {path}")
        return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def load_sources() -> tuple[list[tuple[str, str]], list[str]]:
    direct: list[tuple[str, str]] = []
    for line in _lines(DIRECT_FILE):
        parts = line.split("|")
        url = parts[0].strip()
        if not url.startswith("http"):
            continue
        accept = parts[2].strip() if len(parts) > 2 else "text/plain, */*"
        direct.append((url, accept))
    dorks = _lines(DORKS_FILE)
    log.info(f"sources: direct={len(direct)}, dorks={len(dorks)}")
    return direct, dorks

def load_config():
    global RU_IP_PREFIXES, OPERATOR_SNI, TRUSTED_HOSTS, SNI_POOL
    RU_IP_PREFIXES = _lines(IP_PREFIXES_F)
    log.info(f"ip prefixes: {len(RU_IP_PREFIXES)}")
    for op, path in SNI_FILES.items():
        OPERATOR_SNI[op] = _lines(path)
        log.info(f"sni [{op}]: {len(OPERATOR_SNI[op])}")
    for line in _lines(HOSTS_FILE):
        ip = line.split("|")[0].strip()
        if ip:
            TRUSTED_HOSTS.add(ip)
    log.info(f"trusted hosts: {len(TRUSTED_HOSTS)}")
    _rebuild_sni_pool()

def _rebuild_sni_pool():
    global SNI_POOL
    seen: set[str] = set()
    pool: list[str] = []
    for d in OPERATOR_SNI.get("all_operators", []):
        if d not in seen:
            seen.add(d)
            pool.append(d)
    for op, domains in OPERATOR_SNI.items():
        if op == "all_operators":
            continue
        for d in domains:
            if d not in seen:
                seen.add(d)
                pool.append(d)
    for d in _lines(SNI_WHITELIST_F):
        d = d.strip().lower()
        if d and d not in seen:
            seen.add(d)
            pool.append(d)
    SNI_POOL = pool
    log.info(f"sni pool total: {len(SNI_POOL)}")

def load_blocklist():
    for path in (BLACKLIST_FILE,):
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("vless://"):
                    BLOCKLIST_EXACT.add(line)
                else:
                    BLOCKLIST_PARTIAL.add(line)
    log.info(f"blocklist: exact={len(BLOCKLIST_EXACT)}, partial={len(BLOCKLIST_PARTIAL)}")


# ── cidr helpers ──────────────────────────────────────────────────────────────

def _cidr_to_range(cidr: str) -> Optional[tuple[int, int]]:
    try:
        net, bits = cidr.strip().split("/")
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        net_int = struct.unpack("!I", socket.inet_aton(net))[0]
        return (net_int & mask, mask)
    except Exception:
        return None

def _load_cidr_file(path: str) -> list[tuple[int, int]]:
    ranges = []
    for line in _lines(path):
        r = _cidr_to_range(line)
        if r:
            ranges.append(r)
    return ranges

def _ip_in_cidr(ip: str, ranges: list[tuple[int, int]]) -> bool:
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        return any((ip_int & mask) == net for net, mask in ranges)
    except Exception:
        return False

async def fetch_hxehex_whitelist(session: aiohttp.ClientSession):
    global RU_CIDR_RANGES, SNI_POOL
    log.info("fetching hxehex cidr whitelist...")
    try:
        async with session.get(HXEHEX_CIDR_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                with open(RU_CIDR_F, "w", encoding="utf-8") as f:
                    f.write("# auto-cached from hxehex/russia-mobile-internet-whitelist\n")
                    f.write(text)
                RU_CIDR_RANGES = _load_cidr_file(RU_CIDR_F)
                log.info(f"cidr ranges loaded: {len(RU_CIDR_RANGES)}")
    except Exception as e:
        log.warning(f"cidr fetch failed: {e}, using cache")
        if os.path.exists(RU_CIDR_F):
            RU_CIDR_RANGES = _load_cidr_file(RU_CIDR_F)
            log.info(f"cidr from cache: {len(RU_CIDR_RANGES)}")

    log.info("fetching hxehex sni whitelist...")
    try:
        async with session.get(HXEHEX_SNI_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                with open(SNI_WHITELIST_F, "w", encoding="utf-8") as f:
                    f.write("# auto-cached from hxehex/russia-mobile-internet-whitelist\n")
                    f.write(text)
                log.info("sni whitelist cached")
    except Exception as e:
        log.warning(f"sni whitelist fetch failed: {e}, using cache")

    _rebuild_sni_pool()


# ── helpers ───────────────────────────────────────────────────────────────────

def b64d(s: str) -> str:
    try:
        s = s.strip() + "=" * (-len(s.strip()) % 4)
        return base64.b64decode(s).decode("utf-8", errors="ignore")
    except Exception:
        return ""

def b64e(s: str) -> str:
    return base64.b64encode(s.encode()).decode()

def cc_flag(cc: str) -> str:
    if len(cc) != 2:
        return "🏳️"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)

def is_ip(host: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))

def is_ru_ip(host: str) -> bool:
    """Check if an IP belongs to RU hosters via prefix list, trusted hosts, or CIDR."""
    if any(host.startswith(p) for p in RU_IP_PREFIXES) or host in TRUSTED_HOSTS:
        return True
    if RU_CIDR_RANGES and is_ip(host):
        return _ip_in_cidr(host, RU_CIDR_RANGES)
    return False

def is_ru_host(host: str) -> bool:
    """
    FIX: parser runs outside RU — domains must be resolved via geo lookup cache.
    IP hosts use prefix/CIDR check; domain hosts use DOMAIN_COUNTRY populated
    after geo batch lookup.
    """
    if is_ip(host):
        return is_ru_ip(host)
    # domain: check geo cache populated after get_geo_batch_with_domains()
    return DOMAIN_COUNTRY.get(host, "").upper() == "RU"

def is_blocked(key: str) -> bool:
    kl = key.lower()
    return kl in BLOCKLIST_EXACT or any(p in kl for p in BLOCKLIST_PARTIAL)

def extract_host(link: str) -> str:
    try:
        return urlparse(link).hostname or ""
    except Exception:
        return ""

def extract_port(link: str) -> int:
    try:
        p = urlparse(link).port
        return p if p and 1 <= p <= 65535 else 0
    except Exception:
        return 0

def extract_params(link: str) -> dict:
    try:
        return {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
    except Exception:
        return {}

def is_valid_uuid(u: str) -> bool:
    return bool(UUID_RE.match(u)) if u else False

def inject_fp_sni(link: str) -> str:
    parsed = urlparse(link)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    if params.get("security") != "reality":
        return link
    changed = False
    if "fp" not in params:
        params["fp"] = "chrome"
        changed = True
    if not params.get("sni"):
        mts_sni = OPERATOR_SNI.get("mts", [])
        pool = mts_sni if mts_sni else SNI_POOL
        params["sni"] = pool[0] if pool else "www.google.com"
        changed = True
    if not changed:
        return link
    return urlunparse(parsed._replace(query=urlencode(params)))

def validate_vless(key: str) -> bool:
    if not key.startswith("vless://"):
        return False
    try:
        p = urlparse(key)
        if not is_valid_uuid(p.username or ""):
            return False
        if not p.hostname or not p.port:
            return False
        if not (1 <= p.port <= 65535):
            return False
        if "type" not in parse_qs(p.query):
            return False
        return True
    except Exception:
        return False

def clean_key(raw: str) -> Optional[str]:
    key = raw.strip()
    if not key.startswith("vless://"):
        return None
    base = ARABIC_RE.sub("", key.split("#")[0])
    if AD_PATTERN.search(base):
        return None
    if is_blocked(key):
        return None
    if not validate_vless(base):
        return None
    return inject_fp_sni(base)


# ── key collection ────────────────────────────────────────────────────────────

def _parse_keys(text: str) -> list[str]:
    keys = []
    for line in text.splitlines():
        line = line.strip()
        targets = [line] if line.startswith("vless://") else re.findall(r'vless://[^\s\'"<>\]\[]+', line)
        for t in targets:
            k = clean_key(t)
            if k:
                keys.append(k)
    return keys

async def fetch_url(session: aiohttp.ClientSession, url: str,
                    accept: str = "text/plain, */*") -> str:
    try:
        hdrs = {"Accept": accept}
        async with session.get(url, headers=hdrs,
                               timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200:
                return await r.text(errors="ignore")
    except Exception as e:
        log.debug(f"fetch {url}: {e}")
    return ""

async def fetch_direct(session: aiohttp.ClientSession,
                       sources: list[tuple[str, str]]) -> list[str]:
    texts = await asyncio.gather(*[fetch_url(session, url, accept)
                                   for url, accept in sources])
    keys = [k for t in texts for k in _parse_keys(t)]
    log.info(f"direct sources: {len(keys)} keys")
    return keys

async def github_search(session: aiohttp.ClientSession, query: str) -> list[str]:
    gh_headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN:
        gh_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    else:
        log.warning("GITHUB_TOKEN not set — GitHub API limited to 10 req/hr, results may be incomplete")
    keys = []
    url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
    for attempt in range(3):
        try:
            async with session.get(url, headers=gh_headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 403:
                    retry_after = int(r.headers.get("Retry-After", 30))
                    wait = max(retry_after, 30)
                    log.warning(f"github_search rate limited (403) '{query[:45]}' — waiting {wait}s (attempt {attempt+1}/3)")
                    await asyncio.sleep(wait)
                    continue
                if r.status == 422:
                    log.debug(f"github_search '{query[:45]}': unprocessable query, skipping")
                    return keys
                if r.status != 200:
                    log.debug(f"github_search '{query[:45]}': status {r.status}")
                    return keys
                data = await r.json(content_type=None)
                raw_urls = []
                for item in data.get("items", []):
                    raw = (item.get("html_url", "")
                           .replace("github.com", "raw.githubusercontent.com")
                           .replace("/blob/", "/"))
                    if raw:
                        raw_urls.append(raw)
                texts = await asyncio.gather(*[fetch_url(session, u) for u in raw_urls[:20]])
                for t in texts:
                    keys.extend(_parse_keys(t))
                return keys
        except Exception as e:
            log.debug(f"github_search '{query}': {e}")
            return keys
    log.warning(f"github_search '{query[:45]}' — all retries exhausted")
    return keys

async def collect_all_keys(session: aiohttp.ClientSession,
                           direct_sources: list[tuple[str, str]],
                           dorks: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []

    def add(keys: list[str]):
        for k in keys:
            base = k.split("#")[0]
            if base not in seen:
                seen.add(base)
                result.append(k)

    add(await fetch_direct(session, direct_sources))

    # GitHub Search API: 10 req/min authenticated → 6s between requests
    gh_delay = 6.0 if GITHUB_TOKEN else 10.0
    log.info(f"github search: {len(dorks)} dorks (delay={gh_delay}s)")
    for i, dork in enumerate(dorks):
        if i > 0:
            await asyncio.sleep(gh_delay)
        found = await github_search(session, dork)
        add(found)
        log.info(f"  [{i+1}/{len(dorks)}] '{dork[:45]}' +{len(found)} total={len(result)}")

    log.info(f"collected unique keys: {len(result)}")
    return result


# ── tcp + tls check ───────────────────────────────────────────────────────────

async def tcp_check(host: str, port: int) -> float:
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT
        )
        lat = (time.monotonic() - start) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return lat
    except Exception:
        return -1.0

async def tls_check(host: str, port: int, sni: str) -> bool:
    """
    Attempt a TLS handshake to verify the server is actually alive and responding.
    A successful handshake (even with cert mismatch) means the server is up.
    This filters out servers that accept TCP but are dead/misconfigured as VLESS.
    """
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=sni or host),
            timeout=TCP_TIMEOUT + 1.0
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False

async def check_keys_tcp(keys: list[str], sem: asyncio.Semaphore) -> list[tuple[float, str]]:
    async def _one(key: str):
        host, port = extract_host(key), extract_port(key)
        if not host or not port:
            return None
        params = extract_params(key)
        sec = params.get("security", "")
        sni = params.get("sni", "")
        async with sem:
            lat = await tcp_check(host, port)
            if lat < 0:
                return None
            # for TLS/Reality keys: verify TLS handshake to weed out dead servers
            if sec in ("tls", "reality"):
                ok = await tls_check(host, port, sni)
                if not ok:
                    log.debug(f"tls handshake failed: {host}:{port}")
                    return None
        return (lat, key)

    results = await asyncio.gather(*[_one(k) for k in keys])
    return sorted([r for r in results if r], key=lambda x: x[0])


# ── l7 hardcore mode ──────────────────────────────────────────────────────────

def _singbox_transport(params: dict) -> dict:
    tp = params.get("type", "tcp")
    if tp == "ws":
        return {"type": "ws", "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", "")}}
    if tp == "grpc":
        return {"type": "grpc", "service_name": params.get("serviceName", "")}
    if tp in ("xhttp", "http"):
        return {"type": "http", "path": params.get("path", "/")}
    return {}

def _make_singbox_config(key: str, socks_port: int) -> Optional[str]:
    try:
        p      = urlparse(key)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in",
                          "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [{
                "type": "vless", "tag": "proxy",
                "server": p.hostname, "server_port": p.port,
                "uuid": p.username,
                "flow": params.get("flow", ""),
                "tls": {
                    "enabled": params.get("security") in ("tls", "reality"),
                    "server_name": params.get("sni", ""),
                    "reality": {
                        "enabled":    params.get("security") == "reality",
                        "public_key": params.get("pbk", ""),
                        "short_id":   params.get("sid", ""),
                    },
                    "utls": {
                        "enabled":     bool(params.get("fp")),
                        "fingerprint": params.get("fp", "chrome"),
                    },
                },
                "transport": _singbox_transport(params),
            }],
        }
        return json.dumps(cfg)
    except Exception as e:
        log.debug(f"singbox config: {e}")
        return None

async def l7_test(key: str, sem: asyncio.Semaphore) -> bool:
    """
    FIX: accepts semaphore to cap parallel singbox processes (L7_CONCURRENCY).
    FIX: L7_MIN_BYTES raised to 50KB for more reliable DPI detection.
    """
    binary = SINGBOX_BIN or V2RAY_BIN
    if not binary or not os.path.exists(binary):
        return True

    async with sem:
        socks_port = 10800 + (abs(hash(key)) % 1000)
        cfg_json   = _make_singbox_config(key, socks_port)
        if not cfg_json:
            return True

        cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json",
                                               delete=False, encoding="utf-8")
        cfg_file.write(cfg_json)
        cfg_file.close()
        proc = None
        try:
            cmd = ([binary, "run", "-c", cfg_file.name] if SINGBOX_BIN
                   else [binary, "-c", cfg_file.name])
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            await asyncio.sleep(2)

            downloaded = 0
            proxy = f"socks5://127.0.0.1:{socks_port}"
            connector = aiohttp.ProxyConnector.from_url(proxy)
            try:
                async with aiohttp.ClientSession(connector=connector) as s:
                    # FIX: use a larger resource to properly test throughput
                    async with s.get("https://speed.cloudflare.com/__down?bytes=102400",
                                     timeout=aiohttp.ClientTimeout(total=L7_TIMEOUT)) as resp:
                        async for chunk in resp.content.iter_chunked(4096):
                            downloaded += len(chunk)
                            if downloaded >= L7_MIN_BYTES:
                                break
            except Exception as e:
                log.debug(f"l7 download: {e}")

            passed = downloaded > 0
            log.debug(f"l7 {extract_host(key)}: {downloaded}b {'ok' if passed else 'dpi!'}")
            return passed
        except Exception as e:
            log.debug(f"l7 proc: {e}")
            return True
        finally:
            if proc:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
            try:
                os.unlink(cfg_file.name)
            except Exception:
                pass


# ── geo via ip-api.com ────────────────────────────────────────────────────────

async def get_geo_batch(session: aiohttp.ClientSession, hosts: list[str]) -> dict:
    """
    FIX: accepts both IPs and domain names — ip-api.com resolves domains too.
    Populates DOMAIN_COUNTRY for domain hosts so is_ru_host() works correctly
    when the parser runs outside RU.
    """
    global DOMAIN_COUNTRY
    cache: dict = {}
    unique = list(dict.fromkeys(hosts))  # preserve order, deduplicate
    for i in range(0, len(unique), 100):
        chunk = unique[i:i + 100]
        try:
            payload = [{"query": h, "fields": "query,countryCode,isp,org"} for h in chunk]
            async with session.post("http://ip-api.com/batch", json=payload,
                                    timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    for item in await r.json(content_type=None):
                        host = item.get("query", "")
                        cc   = item.get("countryCode", "UN")
                        isp  = item.get("isp", "") or item.get("org", "")
                        isp  = re.sub(r'\s*\(.*?\)', '', isp).strip()
                        isp  = " ".join(re.sub(r'[,;|]', ' ', isp).split())[:45]
                        cache[host] = {"flag": cc_flag(cc), "isp": isp, "country": cc}
                        # populate domain country cache for is_ru_host()
                        if not is_ip(host):
                            DOMAIN_COUNTRY[host] = cc
        except Exception as e:
            log.debug(f"geo_batch: {e}")
        await asyncio.sleep(0.3)
    return cache


# ── operator scoring (rkn/tspu knowledge base 2025) ──────────────────────────

def score_operators(key: str, isp: str = "") -> list[str]:
    params = extract_params(key)
    sec    = params.get("security", "")
    tp     = params.get("type", "tcp")
    fp     = params.get("fp", "")
    port   = extract_port(key)
    sni    = params.get("sni", "").lower()
    isp_l  = isp.lower()

    is_reality   = sec == "reality"
    is_grpc      = tp == "grpc"
    is_ws        = tp in ("ws", "websocket")
    is_xhttp     = tp == "xhttp"
    is_std_port  = port in (443, 80, 8443)
    is_high_port = port > 9999
    bad_t2       = any(x in isp_l for x in T2_BLOCKED_ISPS)

    mts_sni     = set(OPERATOR_SNI.get("mts", []))
    megafon_sni = set(OPERATOR_SNI.get("megafon", []))
    t2_sni      = set(OPERATOR_SNI.get("t2", []))
    all_op_sni  = set(OPERATOR_SNI.get("all_operators", []))

    sni_all_ops = sni in all_op_sni

    ops = []
    # FIX: МТС — accept any fp (not just chrome), chrome is preferred but not mandatory
    if is_reality and fp and (is_grpc or tp in ("tcp", "raw")):
        if sni in mts_sni or sni_all_ops or is_high_port:
            ops.append("МТС")
    # МегаФон/Yota: reality + port 443/80 or xhttp, confirmed sni
    if is_reality and (is_std_port or is_xhttp):
        if sni in megafon_sni or sni_all_ops:
            ops.append("МегаФон")
            ops.append("Yota")
    # Tele2: grpc/ws/xhttp, not on blocked isps, confirmed sni
    if (is_grpc or is_ws or is_xhttp) and not bad_t2:
        if sni in t2_sni or sni_all_ops:
            ops.append("Tele2")
    # Билайн: any reality with fp (softest dpi)
    if is_reality and fp:
        ops.append("Билайн")
    # fallback: sni confirmed for all operators
    if not ops and sni_all_ops and is_reality:
        ops = ["МТС", "МегаФон", "Tele2", "Yota", "Билайн"]
    return ops if ops else ["Универсальный"]

def transport_label(key: str) -> str:
    params = extract_params(key)
    tp  = params.get("type", "tcp")
    sec = params.get("security", "")
    fp  = params.get("fp", "")
    labels = {"grpc": "gRPC", "ws": "WebSocket", "websocket": "WebSocket",
              "xhttp": "XHTTP", "tcp": "TCP", "raw": "RAW"}
    t = labels.get(tp, tp.upper())
    if sec == "reality": t += "+Reality"
    elif sec == "tls":   t += "+TLS"
    if fp: t += f"/{fp}"
    return t

def build_remark(key: str, geo: dict, latency: float, is_fast: bool = False) -> str:
    fl  = geo.get("flag", "🏳️")
    isp = geo.get("isp") or extract_host(key)
    # shorten isp: first word only, max 15 chars
    isp_short = isp.split()[0][:15] if isp else "?"
    lat = f"{latency:.0f}ms"
    if is_fast:
        return f"⚡{fl}{isp_short} {lat}"
    ops = score_operators(key, isp)
    ops_short = ",".join(ops) if ops != ["Универсальный"] else "🌐"
    return f"{fl}{isp_short} {ops_short} {lat}"


# ── diverse transport selection ───────────────────────────────────────────────

def select_diverse(alive: list[tuple[float, str]], max_count: int) -> list[tuple[float, str]]:
    """
    FIX: use fixed per_bucket cap of 25 instead of dividing max_count by bucket count.
    This prevents rare transports from crowding out reliable tcp+reality keys.
    """
    buckets: dict[str, list] = {}
    for lat, key in alive:
        p   = extract_params(key)
        tp  = p.get("type", "tcp")
        sec = p.get("security", "none")
        fp  = "_chrome" if p.get("fp") == "chrome" else ""
        buckets.setdefault(f"{tp}_{sec}{fp}", []).append((lat, key))

    selected: list[tuple[float, str]] = []
    # FIX: fixed cap per bucket — don't let rare transports dominate
    per_bucket = 25
    for items in buckets.values():
        selected.extend(items[:per_bucket])

    seen = {k for _, k in selected}
    for lat, key in alive:
        if len(selected) >= max_count:
            break
        if key not in seen:
            selected.append((lat, key))
            seen.add(key)
    return selected[:max_count]


# ── output ────────────────────────────────────────────────────────────────────

def write_output(final_keys: list[str]):
    announce = (
        "Как пользоваться:\n"
        "1. Нажмите «Подключить в Happ» — приложение откроется само\n"
        "2. Нажмите «Добавить» и подтвердите импорт подписки\n"
        "3. Выберите сервер и нажмите ▶ Старт\n"
        "Обновление: Happ → Подписки → кнопка Обновить (авто каждые 2 часа)\n"
        "⚡ ИГРОВОЙ — скорость от 100 Мбит/с, низкий пинг\n"
        "Эфф: МТС/МегаФон/Tele2/Билайн — для каких операторов работает лучше"
    )
    header = "\n".join([
        f"#profile-title: base64:{b64e('⚡ WhiteVless — Россия')}",
        "#profile-update-interval: 2",
        # FIX: removed fake subscription-userinfo — clients show it to users
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{b64e(announce)}",
        "",
    ])
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for k in final_keys:
            f.write(k + "\n")
    log.info(f"written {len(final_keys)} keys → {OUTPUT_FILE}")


# ── main ──────────────────────────────────────────────────────────────────────

async def main():
    load_config()
    load_blocklist()
    direct_sources, dorks = load_sources()

    connector = aiohttp.TCPConnector(limit=120, ssl=False)
    ua = {"User-Agent": "Mozilla/5.0 (compatible; WhiteVless/4.0)"}

    async with aiohttp.ClientSession(connector=connector, headers=ua) as session:

        await fetch_hxehex_whitelist(session)

        raw_keys = await collect_all_keys(session, direct_sources, dorks)

        # ── FIX: geo lookup BEFORE ru/foreign split ───────────────────────────
        # Parser runs outside RU — domain hosts can't be classified without geo.
        # We resolve all unique hosts (IPs + domains) via ip-api batch first,
        # then is_ru_host() uses the populated DOMAIN_COUNTRY cache.
        all_hosts = list(dict.fromkeys(extract_host(k) for k in raw_keys if extract_host(k)))
        log.info(f"pre-split geo lookup for {len(all_hosts)} hosts...")
        pre_geo = await get_geo_batch(session, all_hosts)
        # DOMAIN_COUNTRY is now populated — is_ru_host() works for domains too

        ru_keys      = [k for k in raw_keys if is_ru_host(extract_host(k))]
        foreign_keys = [k for k in raw_keys if not is_ru_host(extract_host(k))]
        log.info(f"split: ru={len(ru_keys)} foreign={len(foreign_keys)}")

        # ── FIX: deduplicate by host:port to avoid multiple keys per server ──
        def dedup_by_endpoint(keys: list[str]) -> list[str]:
            seen_ep: set[str] = set()
            out: list[str] = []
            for k in keys:
                ep = f"{extract_host(k)}:{extract_port(k)}"
                if ep not in seen_ep:
                    seen_ep.add(ep)
                    out.append(k)
            return out

        ru_keys      = dedup_by_endpoint(ru_keys)
        foreign_keys = dedup_by_endpoint(foreign_keys)
        log.info(f"after dedup: ru={len(ru_keys)} foreign={len(foreign_keys)}")

        # tcp check
        sem = asyncio.Semaphore(CONCURRENCY)
        ru_alive      = await check_keys_tcp(ru_keys, sem)
        foreign_alive = await check_keys_tcp(foreign_keys, sem)
        log.info(f"alive: ru={len(ru_alive)} foreign={len(foreign_alive)}")

        selected_ru = select_diverse(ru_alive, MAX_RU_KEYS)

        fast_pool     = [(lat, k) for lat, k in foreign_alive if lat < 80]
        selected_fast = fast_pool[:MAX_FAST_KEYS]
        fast_set      = {k for _, k in selected_fast}

        selected_foreign = [(lat, k) for lat, k in foreign_alive
                            if k not in fast_set][:MAX_FOREIGN_KEYS]

        all_selected = selected_ru + selected_fast + selected_foreign
        log.info(f"selected: ru={len(selected_ru)} fast={len(selected_fast)} "
                 f"foreign={len(selected_foreign)} total={len(all_selected)}")

        # ── l7 hardcore mode ─────────────────────────────────────────────────
        binary = SINGBOX_BIN or V2RAY_BIN
        if binary and os.path.exists(binary):
            log.info("l7 hardcore mode: running stress tests...")
            # FIX: semaphore caps parallel singbox processes
            l7_sem = asyncio.Semaphore(L7_CONCURRENCY)
            l7_ok  = await asyncio.gather(*[l7_test(k, l7_sem) for _, k in all_selected])
            before = len(all_selected)
            all_selected = [item for item, ok in zip(all_selected, l7_ok) if ok]
            log.info(f"l7: removed {before - len(all_selected)} dpi-detected keys")
        else:
            log.info("l7 skipped (set SINGBOX_BIN or V2RAY_BIN to enable)")

        # ── final geo lookup (for selected keys only, reuse pre_geo cache) ───
        remaining_hosts = [extract_host(k) for _, k in all_selected
                           if extract_host(k) not in pre_geo and is_ip(extract_host(k))]
        if remaining_hosts:
            extra_geo = await get_geo_batch(session, remaining_hosts)
            pre_geo.update(extra_geo)

        # build final list with remarks
        final: list[str] = []
        for lat, key in all_selected:
            host   = extract_host(key)
            info   = pre_geo.get(host, {"flag": "🏳️", "isp": host, "country": "UN"})
            remark = build_remark(key, info, lat, key in fast_set)
            final.append(f"{key.split('#')[0]}#{quote(remark)}")

        write_output(final)
        log.info(f"done: {len(final)} keys")


if __name__ == "__main__":
    asyncio.run(main())
