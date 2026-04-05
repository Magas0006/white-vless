#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# whitevless — async vless/reality parser-validator
# runs on github actions (outside RU), targets 200+ keys for russian users
# deps: pip install aiohttp

import asyncio
import aiohttp
import re
import base64
import time
import os
import ssl
import struct
import socket
import subprocess
import tempfile
import json
import logging
from html import unescape as html_unescape
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from typing import Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("whitevless")

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
CLASH_FILE     = os.path.join(BASE_DIR, "clash.yaml")

MAX_RU_KEYS    = 200
TCP_TIMEOUT    = 6.0
CONCURRENCY    = 80
L7_CONCURRENCY = 10
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
SINGBOX_BIN    = os.environ.get("SINGBOX_BIN", "")
V2RAY_BIN      = os.environ.get("V2RAY_BIN", "")
XRAY_BIN       = os.environ.get("XRAY_BIN", "")
BOOTSTRAP_KEY  = os.environ.get("BOOTSTRAP_KEY", "")  # known-good RU key for validation proxy
L7_MIN_BYTES   = 50 * 1024
L7_TIMEOUT     = 15

RU_IP_PREFIXES:    list[str]       = []
RU_CIDR_RANGES:    list[tuple]     = []
SNI_POOL:          list[str]       = []
OPERATOR_SNI:      dict[str, list] = {}
TRUSTED_HOSTS:     set[str]        = set()
DOMAIN_COUNTRY:    dict[str, str]  = {}
BLOCKLIST_EXACT:   set[str]        = set()
BLOCKLIST_PARTIAL: set[str]        = set()
BOOTSTRAP_SOCKS:   str             = ""

T2_BLOCKED_ISPS = ("digitalocean", "hetzner", "linode")
AD_PATTERN = re.compile(r'(t\.me|telegram\.(me|org|dog)|@[\w_]{3,}|купить|прода)', re.I)
ARABIC_RE  = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
UUID_RE    = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

TRUSTED_SOURCE_PATTERNS = (
    "igareck/vpn-configs-for-russia",
    "SilentGhostCodes/WhiteListVpn",
    "RKPchannel/RKP_bypass_configs",
    "zieng2/wl",
    "AvenCores/goida-vpn-configs",
)

def _lines(path):
    if not os.path.exists(path):
        log.warning(f"missing: {path}"); return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def load_sources():
    direct = []
    for line in _lines(DIRECT_FILE):
        parts = line.split("|"); url = parts[0].strip()
        if not url.startswith("http"): continue
        accept = parts[2].strip() if len(parts) > 2 else "text/plain, */*"
        trusted = any(p in url for p in TRUSTED_SOURCE_PATTERNS)
        direct.append((url, accept, trusted))
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
        if ip: TRUSTED_HOSTS.add(ip)
    log.info(f"trusted hosts: {len(TRUSTED_HOSTS)}")
    _rebuild_sni_pool()

def _rebuild_sni_pool():
    global SNI_POOL
    seen, pool = set(), []
    for op_key in ["all_operators", "mts", "beeline", "megafon", "t2", "yota"]:
        for d in OPERATOR_SNI.get(op_key, []):
            if d not in seen: seen.add(d); pool.append(d)
    for d in _lines(SNI_WHITELIST_F):
        d = d.strip().lower()
        if d and d not in seen: seen.add(d); pool.append(d)
    SNI_POOL = pool
    log.info(f"sni pool total: {len(SNI_POOL)}")

def load_blocklist():
    if not os.path.exists(BLACKLIST_FILE): return
    with open(BLACKLIST_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"): continue
            if line.startswith("vless://"): BLOCKLIST_EXACT.add(line)
            else: BLOCKLIST_PARTIAL.add(line)
    log.info(f"blocklist: exact={len(BLOCKLIST_EXACT)}, partial={len(BLOCKLIST_PARTIAL)}")

def _cidr_to_range(cidr):
    try:
        net, bits = cidr.strip().split("/")
        mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
        net_int = struct.unpack("!I", socket.inet_aton(net))[0]
        return (net_int & mask, mask)
    except Exception: return None

def _load_cidr_file(path):
    return [r for line in _lines(path) for r in [_cidr_to_range(line)] if r]

def _ip_in_cidr(ip, ranges):
    try:
        ip_int = struct.unpack("!I", socket.inet_aton(ip))[0]
        return any((ip_int & mask) == net for net, mask in ranges)
    except Exception: return False

async def fetch_hxehex_whitelist(session):
    global RU_CIDR_RANGES
    log.info("fetching hxehex cidr whitelist...")
    try:
        async with session.get(HXEHEX_CIDR_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                with open(RU_CIDR_F, "w", encoding="utf-8") as f:
                    f.write("# auto-cached\n"); f.write(text)
                RU_CIDR_RANGES = _load_cidr_file(RU_CIDR_F)
                log.info(f"cidr ranges: {len(RU_CIDR_RANGES)}")
    except Exception as e:
        log.warning(f"cidr fetch failed: {e}")
        if os.path.exists(RU_CIDR_F):
            RU_CIDR_RANGES = _load_cidr_file(RU_CIDR_F)
    try:
        async with session.get(HXEHEX_SNI_URL, timeout=aiohttp.ClientTimeout(total=30)) as r:
            if r.status == 200:
                text = await r.text()
                with open(SNI_WHITELIST_F, "w", encoding="utf-8") as f:
                    f.write("# auto-cached\n"); f.write(text)
    except Exception as e:
        log.warning(f"sni whitelist fetch failed: {e}")
    _rebuild_sni_pool()

def b64e(s): return base64.b64encode(s.encode()).decode()
def cc_flag(cc):
    if len(cc) != 2: return "🏳️"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)
def is_ip(host): return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', host))

def is_ru_ip(host):
    if any(host.startswith(p) for p in RU_IP_PREFIXES) or host in TRUSTED_HOSTS: return True
    if RU_CIDR_RANGES and is_ip(host): return _ip_in_cidr(host, RU_CIDR_RANGES)
    return False

def is_ru_host(host, trusted=False):
    if is_ip(host): return is_ru_ip(host)
    cc = DOMAIN_COUNTRY.get(host, "")
    # RU confirmed → pass; unknown geo → pass (domain may resolve to RU IP but geo DB misses it)
    # explicitly non-RU → reject
    return cc.upper() == "RU" or cc == ""

def is_blocked(key):
    kl = key.lower()
    return kl in BLOCKLIST_EXACT or any(p in kl for p in BLOCKLIST_PARTIAL)

def extract_host(link):
    try: return urlparse(link).hostname or ""
    except: return ""

def extract_port(link):
    try:
        p = urlparse(link).port
        return p if p and 1 <= p <= 65535 else 0
    except: return 0

def extract_params(link):
    try: return {k: v[0] for k, v in parse_qs(urlparse(link).query).items()}
    except: return {}

def is_valid_uuid(u):
    return bool(UUID_RE.match(u)) if u else False

def inject_fp_sni(link):
    parsed = urlparse(link)
    params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
    if params.get("security") != "reality": return link
    changed = False
    if "fp" not in params: params["fp"] = "chrome"; changed = True
    if not params.get("sni"):
        # prefer all_operators pool, then mts, then generic RU SNI
        pool = OPERATOR_SNI.get("all_operators") or OPERATOR_SNI.get("mts") or SNI_POOL
        params["sni"] = pool[0] if pool else "www.gosuslugi.ru"; changed = True
    return urlunparse(parsed._replace(query=urlencode(params))) if changed else link

def validate_vless(key):
    if not key.startswith("vless://"): return False
    try:
        p = urlparse(key)
        if not is_valid_uuid(p.username or ""): return False
        if not p.hostname or not p.port: return False
        if not (1 <= p.port <= 65535): return False
        # 'type' is optional — defaults to 'tcp' per VLESS spec
        return True
    except: return False

def clean_key(raw):
    key = raw.strip()
    if not key.startswith("vless://"): return None
    base = ARABIC_RE.sub("", key.split("#")[0])
    if AD_PATTERN.search(base): return None
    if is_blocked(key): return None
    if not validate_vless(base): return None
    return inject_fp_sni(base)

def _parse_keys(text):
    keys = []
    # decode HTML entities (&amp; → &, &amp%3B → & etc.)
    text = html_unescape(text)
    # also handle percent-encoded HTML entities like amp%3B
    text = re.sub(r'&amp%3B', '&', text, flags=re.I)
    text = re.sub(r'%26amp%3B', '&', text, flags=re.I)
    for line in text.splitlines():
        line = line.strip()
        targets = [line] if line.startswith("vless://") else re.findall(r'vless://[^\s\'"<>\]\[]+', line)
        for t in targets:
            k = clean_key(t)
            if k: keys.append(k)
    return keys

async def fetch_url(session, url, accept="text/plain, */*"):
    try:
        async with session.get(url, headers={"Accept": accept}, timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200: return await r.text(errors="ignore")
    except Exception as e: log.debug(f"fetch {url}: {e}")
    return ""

async def fetch_direct(session, sources):
    texts = await asyncio.gather(*[fetch_url(session, url, accept) for url, accept, _ in sources])
    keys = []
    for (url, _, trusted_src), text in zip(sources, texts):
        trusted = trusted_src or any(p in url for p in TRUSTED_SOURCE_PATTERNS)
        found = _parse_keys(text)
        for k in found: keys.append((k, trusted))
        if found:
            log.info(f"  direct {url.split('/')[-1][:40]}: {len(found)} keys (trusted={trusted})")
    log.info(f"direct sources: {len(keys)} keys")
    return keys

async def github_search(session, query):
    gh_headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN: gh_headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    keys = []
    url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
    for attempt in range(3):
        try:
            async with session.get(url, headers=gh_headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 403:
                    wait = max(int(r.headers.get("Retry-After", 30)), 30)
                    log.warning(f"github rate limit '{query[:40]}' — wait {wait}s (attempt {attempt+1}/3)")
                    await asyncio.sleep(wait); continue
                if r.status == 422: return keys
                if r.status != 200: return keys
                data = await r.json(content_type=None)
                raw_urls = []
                for item in data.get("items", []):
                    raw = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    if raw: raw_urls.append(raw)
                texts = await asyncio.gather(*[fetch_url(session, u) for u in raw_urls[:20]])
                for t in texts: keys.extend([(k, False) for k in _parse_keys(t)])
                return keys
        except Exception as e: log.debug(f"github_search '{query}': {e}"); return keys
    return keys

async def collect_all_keys(session, direct_sources, dorks):
    seen, result = set(), []
    def add(keys):
        for k, trusted in keys:
            base = k.split("#")[0]
            if base not in seen: seen.add(base); result.append((k, trusted))
    add(await fetch_direct(session, direct_sources))
    gh_delay = 8.0 if GITHUB_TOKEN else 12.0
    log.info(f"github search: {len(dorks)} dorks (delay={gh_delay}s)")
    for i, dork in enumerate(dorks):
        if i > 0: await asyncio.sleep(gh_delay + (i % 3) * 2.0)
        found = await github_search(session, dork)
        add(found)
        log.info(f"  [{i+1}/{len(dorks)}] '{dork[:45]}' +{len(found)} total={len(result)}")
    log.info(f"collected unique keys: {len(result)}")
    return result
async def tcp_check(host, port):
    try:
        start = time.monotonic()
        if BOOTSTRAP_SOCKS:
            connector = aiohttp.ProxyConnector.from_url(BOOTSTRAP_SOCKS)
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.get(f"http://{host}:{port}", timeout=aiohttp.ClientTimeout(total=TCP_TIMEOUT)) as _: pass
        else:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
            writer.close()
            try: await writer.wait_closed()
            except: pass
        return (time.monotonic() - start) * 1000
    except: return -1.0

async def tls_check(host, port, sni):
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    if BOOTSTRAP_SOCKS:
        try:
            connector = aiohttp.ProxyConnector.from_url(BOOTSTRAP_SOCKS)
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.get(f"https://{host}:{port}", ssl=ctx, timeout=aiohttp.ClientTimeout(total=TCP_TIMEOUT + 2)) as resp:
                    return resp.status < 600
        except: return False
    else:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host), timeout=TCP_TIMEOUT + 1.0)
            writer.close()
            try: await writer.wait_closed()
            except: pass
            return True
        except: return False

async def check_keys_tcp(keys, sem):
    async def _one(key, trusted):
        host, port = extract_host(key), extract_port(key)
        if not host or not port: return None
        params = extract_params(key); sec = params.get("security", ""); sni = params.get("sni", "")
        async with sem:
            lat = await tcp_check(host, port)
            if lat < 0: return None
            # reality uses its own handshake — standard TLS check will always fail,
            # so only run tls_check for plain TLS (not reality)
            if not trusted and sec == "tls":
                if not await tls_check(host, port, sni):
                    log.debug(f"tls failed: {host}:{port}"); return None
        return (lat, key)
    results = await asyncio.gather(*[_one(k, t) for k, t in keys])
    return sorted([r for r in results if r], key=lambda x: x[0])

def _start_proxy_proc(binary: str, cfg_path: str) -> subprocess.Popen:
    """Start xray or sing-box with the given config file."""
    if "xray" in os.path.basename(binary).lower():
        cmd = [binary, "-c", cfg_path]
    else:
        cmd = [binary, "run", "-c", cfg_path]
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def _get_binary() -> str:
    for b in (XRAY_BIN, SINGBOX_BIN, V2RAY_BIN):
        if b and os.path.exists(b):
            return b
    return ""

def _make_proxy_config(key: str, socks_port: int) -> Optional[str]:
    """Generate xray-core config (falls back to sing-box format if only singbox available)."""
    try:
        p = urlparse(key)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        tp  = params.get("type", "tcp")
        sec = params.get("security", "")

        # xray config format
        if XRAY_BIN and os.path.exists(XRAY_BIN):
            stream = {"network": tp if tp not in ("raw",) else "tcp"}
            if tp == "ws":
                stream["wsSettings"] = {"path": params.get("path", "/"), "headers": {"Host": params.get("host", "")}}
            elif tp == "grpc":
                stream["grpcSettings"] = {"serviceName": params.get("serviceName", "")}
            elif tp in ("xhttp", "http"):
                stream["httpSettings"] = {"path": params.get("path", "/")}

            if sec == "reality":
                stream["security"] = "reality"
                stream["realitySettings"] = {
                    "serverName": params.get("sni", ""),
                    "fingerprint": params.get("fp", "chrome"),
                    "publicKey":   params.get("pbk", ""),
                    "shortId":     params.get("sid", ""),
                }
            elif sec == "tls":
                stream["security"] = "tls"
                stream["tlsSettings"] = {"serverName": params.get("sni", ""), "allowInsecure": True}

            cfg = {
                "log": {"loglevel": "none"},
                "inbounds": [{"tag": "socks", "port": socks_port, "listen": "127.0.0.1",
                              "protocol": "socks", "settings": {"auth": "noauth", "udp": False}}],
                "outbounds": [{"tag": "proxy", "protocol": "vless",
                    "settings": {"vnext": [{"address": p.hostname, "port": p.port,
                        "users": [{"id": p.username, "flow": params.get("flow", ""),
                                   "encryption": "none"}]}]},
                    "streamSettings": stream}],
            }
            return json.dumps(cfg)

        # fallback: sing-box format
        tp_cfg = {}
        if tp == "ws":
            tp_cfg = {"type": "ws", "path": params.get("path", "/"), "headers": {"Host": params.get("host", "")}}
        elif tp == "grpc":
            tp_cfg = {"type": "grpc", "service_name": params.get("serviceName", "")}
        elif tp in ("xhttp", "http"):
            tp_cfg = {"type": "http", "path": params.get("path", "/")}
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [{"type": "vless", "tag": "proxy",
                "server": p.hostname, "server_port": p.port, "uuid": p.username,
                "flow": params.get("flow", ""),
                "tls": {"enabled": sec in ("tls", "reality"), "server_name": params.get("sni", ""),
                    "reality": {"enabled": sec == "reality", "public_key": params.get("pbk", ""),
                                "short_id": params.get("sid", "")},
                    "utls": {"enabled": bool(params.get("fp")), "fingerprint": params.get("fp", "chrome")}},
                "transport": tp_cfg}],
        }
        return json.dumps(cfg)
    except Exception as e:
        log.debug(f"proxy config error: {e}")
        return None

class BootstrapManager:
    """
    Keeps a live RU socks5 proxy running throughout the entire parser session.
    - Prefers Selectel/YandexCloud/AEZA keys (stable RU hosters)
    - Auto-heals: if proxy dies mid-run, finds a new one from remaining candidates
    - All TCP/TLS checks and speed tests route through it → real RU-side validation
    """
    def __init__(self):
        self.socks_url: str = ""
        self._proc: Optional[subprocess.Popen] = None
        self._cfg_path: str = ""
        self._port: int = 10700
        self._candidates: list[str] = []
        self._used: set[str] = set()
        self._binary: str = ""

    def _is_ru_hoster(self, key: str) -> bool:
        host = extract_host(key)
        # Selectel, YandexCloud, VK, Adman, EdgeCenter, Timeweb, Beget,
        # JustHost, Ahost, SpaceWeb, RuVDS, H2Nexus — без AEZA (нестабильна)
        RU_STABLE = (
            "45.89.", "45.147.", "77.234.", "94.103.", "2.58.68.", "2.58.69.",  # Selectel
            "51.250.", "84.201.", "158.160.", "130.193.", "51.244.", "89.169.", # YandexCloud
            "217.69.", "94.100.", "95.213.", "87.240.", "93.186.", "178.154.",  # VK
            "91.200.12.", "91.200.13.", "185.141.",                              # Adman
            "92.223.", "185.209.", "92.38.",                                     # EdgeCenter
            "185.185.", "193.233.", "82.146.", "176.114.",                       # Timeweb
            "185.4.", "194.58.",                                                  # Beget
            "91.201.", "185.120.",                                                # JustHost
            "91.222.", "185.93.",                                                 # Ahost
            "91.207.", "185.26.",                                                 # SpaceWeb
            "45.128.176.", "45.128.177.", "45.128.178.", "45.128.179.",          # RuVDS
            "45.132.252.", "45.132.253.",                                         # RuVDS
            "2.59.253.", "45.144.52.", "144.31.", "64.188.91.",                  # H2Nexus
            "77.91.124.", "81.31.192.", "81.31.193.",                            # H2Nexus
        )
        return any(host.startswith(p) for p in RU_STABLE) or host in TRUSTED_HOSTS

    def setup(self, candidates: list[str]):
        self._binary = _get_binary()
        # stable RU hosters first, then rest
        stable  = [k for k in candidates if self._is_ru_hoster(k)]
        rest    = [k for k in candidates if not self._is_ru_hoster(k)]
        self._candidates = stable + rest
        log.info(f"bootstrap candidates: {len(stable)} stable-RU + {len(rest)} other")

    async def _try_key(self, key: str, port: int = 0) -> bool:
        global BOOTSTRAP_SOCKS
        if not self._binary or not os.path.exists(self._binary):
            return False
        use_port = port or self._port
        cfg_json = _make_proxy_config(key, use_port)
        if not cfg_json:
            return False
        cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        cfg_file.write(cfg_json); cfg_file.close()
        proc = _start_proxy_proc(self._binary, cfg_file.name)
        await asyncio.sleep(3.5)
        ok = False
        try:
            proxy = f"socks5://127.0.0.1:{use_port}"
            connector = aiohttp.ProxyConnector.from_url(proxy)
            # retry up to 3 times — xray may need a moment to fully start
            for attempt in range(3):
                try:
                    async with aiohttp.ClientSession(connector=connector) as s:
                        async with s.get("https://api.myip.com", timeout=aiohttp.ClientTimeout(total=8)) as resp:
                            if resp.status == 200:
                                data = await resp.json(content_type=None)
                                if data.get("cc") == "RU":
                                    self._proc = proc
                                    self._cfg_path = cfg_file.name
                                    self.socks_url = proxy
                                    BOOTSTRAP_SOCKS = proxy
                                    log.info(f"bootstrap RU proxy: {extract_host(key)}:{extract_port(key)}")
                                    ok = True
                                    break
                                else:
                                    log.debug(f"bootstrap non-RU cc={data.get('cc')} {extract_host(key)}")
                                    break  # server works but not RU — no point retrying
                except Exception as e:
                    log.debug(f"bootstrap attempt {attempt+1} {extract_host(key)}: {e}")
                    if attempt < 2:
                        await asyncio.sleep(2.0)
        except Exception as e:
            log.debug(f"bootstrap try {extract_host(key)}: {e}")
        if not ok:
            proc.terminate()
            try: proc.wait(timeout=3)
            except: proc.kill()
            try: os.unlink(cfg_file.name)
            except: pass
        else:
            try: os.unlink(cfg_file.name)
            except: pass
        return ok

    async def start(self) -> bool:
        # try candidates in parallel batches of 5 — each gets its own port
        candidates = [k for k in self._candidates if k not in self._used][:120]
        base_port = self._port
        batch_num = 0
        for i in range(0, len(candidates), 5):
            if self.socks_url:  # already found by previous batch
                break
            batch = candidates[i:i+5]
            ports = [base_port + batch_num * 5 + j for j in range(len(batch))]
            batch_num += 1
            await asyncio.gather(*[self._try_key(k, p) for k, p in zip(batch, ports)])
            self._used.update(batch)
            if self.socks_url:
                return True
        if not self.socks_url:
            log.warning("bootstrap: no RU proxy found — validation runs from GitHub IP")
        return bool(self.socks_url)

    async def ensure_alive(self) -> bool:
        """Check if proxy is still up, restart with next candidate if not."""
        global BOOTSTRAP_SOCKS
        if not self.socks_url:
            return False
        try:
            connector = aiohttp.ProxyConnector.from_url(self.socks_url)
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.get("https://api.myip.com", timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if data.get("cc") == "RU":
                            return True
        except Exception:
            pass
        log.warning("bootstrap proxy died — finding replacement...")
        self.stop()
        return await self.start()

    def stop(self):
        global BOOTSTRAP_SOCKS
        if self._proc:
            self._proc.terminate()
            try: self._proc.wait(timeout=3)
            except: self._proc.kill()
            self._proc = None
        self.socks_url = ""
        BOOTSTRAP_SOCKS = ""


async def start_bootstrap_proxy(candidates):
    """Legacy wrapper — returns BootstrapManager instead of Popen."""
    mgr = BootstrapManager()
    mgr.setup(candidates)
    await mgr.start()
    return mgr

async def l7_test(key, sem):
    """
    Real speed test: start singbox, download 1MB through it, measure speed.
    Returns (passed: bool, speed_mbps: float).
    Minimum threshold: 1 Mbit/s — below that the key is discarded.
    """
    binary = _get_binary()
    if not binary:
        return True, 0.0
    async with sem:
        socks_port = 11000 + (abs(hash(key)) % 4000)
        cfg_json = _make_proxy_config(key, socks_port)
        if not cfg_json:
            return True, 0.0
        cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        cfg_file.write(cfg_json); cfg_file.close()
        proc = None
        try:
            proc = _start_proxy_proc(binary, cfg_file.name)
            await asyncio.sleep(2)
            downloaded = 0
            start = time.monotonic()
            connector = aiohttp.ProxyConnector.from_url(f"socks5://127.0.0.1:{socks_port}")
            try:
                async with aiohttp.ClientSession(connector=connector) as s:
                    # download 2MB to get a reliable speed measurement
                    async with s.get("https://speed.cloudflare.com/__down?bytes=2097152",
                                     timeout=aiohttp.ClientTimeout(total=L7_TIMEOUT)) as resp:
                        async for chunk in resp.content.iter_chunked(8192):
                            downloaded += len(chunk)
                            if downloaded >= 2 * 1024 * 1024:
                                break
            except Exception as e:
                log.debug(f"l7 download {extract_host(key)}: {e}")
            elapsed = time.monotonic() - start
            if downloaded < 32768 or elapsed < 0.01:
                return False, 0.0
            speed_mbps = (downloaded * 8) / elapsed / 1_000_000
            passed = speed_mbps >= 0.3
            log.debug(f"l7 {extract_host(key)}: {speed_mbps:.1f} Mbit/s {'ok' if passed else 'slow'}")
            return passed, speed_mbps
        except Exception as e:
            log.debug(f"l7 proc: {e}")
            return True, 0.0
        finally:
            if proc:
                proc.terminate()
                try: proc.wait(timeout=3)
                except: proc.kill()
            try: os.unlink(cfg_file.name)
            except: pass

async def get_geo_batch(session, hosts):
    global DOMAIN_COUNTRY
    cache = {}
    unique = list(dict.fromkeys(hosts))
    for i in range(0, len(unique), 100):
        chunk = unique[i:i+100]
        try:
            payload = [{"query": h, "fields": "query,countryCode,isp,org"} for h in chunk]
            async with session.post("http://ip-api.com/batch", json=payload, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    for item in await r.json(content_type=None):
                        host = item.get("query", ""); cc = item.get("countryCode", "UN")
                        isp = item.get("isp", "") or item.get("org", "")
                        isp = re.sub(r'\s*\(.*?\)', '', isp).strip()
                        isp = " ".join(re.sub(r'[,;|]', ' ', isp).split())[:45]
                        cache[host] = {"flag": cc_flag(cc), "isp": isp, "country": cc}
                        if not is_ip(host): DOMAIN_COUNTRY[host] = cc
        except Exception as e: log.debug(f"geo_batch: {e}")
        await asyncio.sleep(1.0)  # ip-api.com rate limit: 100 req/min free tier
    return cache

def score_operators(key, isp=""):
    params = extract_params(key)
    sec = params.get("security", ""); tp = params.get("type", "tcp")
    fp = params.get("fp", ""); port = extract_port(key)
    sni = params.get("sni", "").lower(); isp_l = isp.lower()
    is_reality = sec == "reality"; is_grpc = tp == "grpc"
    is_ws = tp in ("ws", "websocket"); is_xhttp = tp == "xhttp"
    is_std_port = port in (443, 80, 8443); is_high_port = port > 9999
    bad_t2 = any(x in isp_l for x in T2_BLOCKED_ISPS)
    mts_sni = set(OPERATOR_SNI.get("mts", []))
    megafon_sni = set(OPERATOR_SNI.get("megafon", []))
    t2_sni = set(OPERATOR_SNI.get("t2", []))
    all_op_sni = set(OPERATOR_SNI.get("all_operators", []))
    sni_all = sni in all_op_sni
    beeline_sni = set(OPERATOR_SNI.get("beeline", []))
    ops = []
    if is_reality and fp and tp in ("tcp", "raw", "grpc"):
        if sni in mts_sni or sni_all or is_high_port: ops.append("МТС")
    if is_reality and (is_std_port or is_xhttp):
        if sni in megafon_sni or sni_all: ops.extend(["МегаФон", "Yota"])
    if (is_grpc or is_ws or is_xhttp) and not bad_t2:
        if sni in t2_sni or sni_all: ops.append("Tele2")
    if is_reality and fp and (sni in beeline_sni or sni_all): ops.append("Билайн")
    if not ops and sni_all and is_reality: ops = ["МТС", "МегаФон", "Tele2", "Yota", "Билайн"]
    return ops if ops else ["Универсальный"]

def _is_mts_compatible(key):
    params = extract_params(key)
    if params.get("security") != "reality" or not params.get("fp"): return False
    if params.get("type", "tcp") not in ("tcp", "raw", "grpc"): return False
    sni = params.get("sni", "").lower()
    all_op_sni = set(OPERATOR_SNI.get("all_operators", []))
    mts_sni = set(OPERATOR_SNI.get("mts", []))
    return sni in mts_sni or sni in all_op_sni or extract_port(key) > 9999

_remark_counters: dict = {}

# label variants by operator combo — mimics the style from the screenshot
_OP_LABELS = {
    "МТС":                          "🇷🇺 LTE МТС",
    "МТС|Билайн":                   "🇷🇺 LTE МТС + Билайн",
    "МТС|МегаФон|Tele2|Билайн":     "🇷🇺 LTE Все операторы",
    "МТС|МегаФон|Yota|Tele2|Билайн":"🇷🇺 LTE Все операторы",
    "МегаФон":                      "🇷🇺 LTE МегаФон",
    "МегаФон|Yota":                 "🇷🇺 LTE МегаФон + Yota",
    "Tele2":                        "🇷🇺 LTE Tele2",
    "Билайн":                       "🇷🇺 LTE Билайн",
    "Универсальный":                "🇷🇺 LTE Обход",
}

def build_remark(key, geo, latency, speed_mbps=0.0):
    ops = score_operators(key, geo.get("isp", ""))
    priority = ["МТС", "МегаФон", "Tele2", "Yota", "Билайн"]
    ops_sorted = sorted(set(ops), key=lambda x: priority.index(x) if x in priority else 99)
    ops_key = "|".join(ops_sorted)
    label = _OP_LABELS.get(ops_key) or _OP_LABELS.get(ops_sorted[0] if ops_sorted else "Универсальный", "🇷🇺 LTE Обход")

    isp = geo.get("isp") or extract_host(key)
    isp_short = isp.split()[0][:12] if isp else "?"

    if speed_mbps >= 50:
        label = "⚡ Игровой"
    
    _remark_counters[label] = _remark_counters.get(label, 0) + 1
    n = _remark_counters[label]
    return f"{label} | {isp_short} | #{n}"

def select_keys(alive, max_count):
    # MTS-compatible first, then rest — deduplicated by endpoint
    mts   = [(lat, k) for lat, k in alive if _is_mts_compatible(k)]
    other = [(lat, k) for lat, k in alive if not _is_mts_compatible(k)]
    seen, selected = set(), []
    for lat, key in mts + other:
        if len(selected) >= max_count: break
        ep = f"{extract_host(key)}:{extract_port(key)}"
        if ep not in seen: seen.add(ep); selected.append((lat, key))
    return selected

def _key_to_clash_proxy(key: str, name: str) -> Optional[dict]:
    """Convert a vless:// URI to a Clash Meta proxy dict."""
    try:
        p = urlparse(key)
        params = {k: v[0] for k, v in parse_qs(p.query).items()}
        sec = params.get("security", "")
        tp  = params.get("type", "tcp")

        proxy: dict = {
            "name":     name,
            "type":     "vless",
            "server":   p.hostname,
            "port":     p.port,
            "uuid":     p.username,
            "udp":      True,
            "flow":     params.get("flow", ""),
        }

        if sec == "reality":
            proxy["tls"] = True
            proxy["servername"] = params.get("sni", "")
            proxy["reality-opts"] = {
                "public-key": params.get("pbk", ""),
                "short-id":   params.get("sid", ""),
            }
            if params.get("fp"):
                proxy["client-fingerprint"] = params.get("fp")
        elif sec == "tls":
            proxy["tls"] = True
            proxy["servername"] = params.get("sni", "")
            proxy["skip-cert-verify"] = True

        if tp == "ws":
            proxy["network"] = "ws"
            proxy["ws-opts"] = {
                "path":    params.get("path", "/"),
                "headers": {"Host": params.get("host", p.hostname)},
            }
        elif tp == "grpc":
            proxy["network"] = "grpc"
            proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName", "")}
        elif tp in ("xhttp", "http"):
            proxy["network"] = "http"
            proxy["http-opts"] = {"path": [params.get("path", "/")]}

        # remove empty flow
        if not proxy["flow"]:
            del proxy["flow"]

        return proxy
    except Exception as e:
        log.debug(f"clash proxy convert: {e}")
        return None

def write_clash(final_keys: list[str]):
    """Generate clash.yaml with urltest group — client auto-picks fastest proxy."""
    import re as _re

    proxies = []
    names   = []
    for key in final_keys:
        # extract remark as name
        if "#" in key:
            raw_name = key.split("#", 1)[1]
            from urllib.parse import unquote as _unquote
            name = _unquote(raw_name)
        else:
            name = extract_host(key)
        # ensure unique name
        base, n = name, 1
        while name in names:
            name = f"{base} ({n})"
            n += 1
        clean = key.split("#")[0]
        proxy = _key_to_clash_proxy(clean, name)
        if proxy:
            proxies.append(proxy)
            names.append(name)

    if not proxies:
        log.warning("clash: no proxies to write")
        return

    def _scalar(v):
        if isinstance(v, bool): return "true" if v else "false"
        if isinstance(v, (int, float)): return str(v)
        s = str(v)
        if any(c in s for c in ':{}[]|>&*!,#?@`\'"') or s != s.strip() or not s:
            return '"' + s.replace('"', '\\"') + '"'
        return s

    def _to_yaml(obj, indent=0):
        pad = "  " * indent
        if isinstance(obj, dict):
            lines = []
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    lines.append(_to_yaml(v, indent + 1))
                else:
                    lines.append(f"{pad}{k}: {_scalar(v)}")
            return "\n".join(lines)
        elif isinstance(obj, list):
            lines = []
            for item in obj:
                if isinstance(item, dict):
                    items = list(item.items())
                    first_k, first_v = items[0]
                    if isinstance(first_v, (dict, list)):
                        lines.append(f"{pad}- {first_k}:")
                        lines.append(_to_yaml(first_v, indent + 2))
                    else:
                        lines.append(f"{pad}- {first_k}: {_scalar(first_v)}")
                    for k, v in items[1:]:
                        if isinstance(v, (dict, list)):
                            lines.append(f"{pad}  {k}:")
                            lines.append(_to_yaml(v, indent + 2))
                        else:
                            lines.append(f"{pad}  {k}: {_scalar(v)}")
                else:
                    lines.append(f"{pad}- {_scalar(item)}")
            return "\n".join(lines)
        else:
            return f"{pad}{_scalar(obj)}"

    cfg = {
        "mixed-port":       7890,
        "allow-lan":        False,
        "mode":             "rule",
        "log-level":        "warning",
        "external-controller": "127.0.0.1:9090",
        "proxies":          proxies,
        "proxy-groups": [
            {
                "name":     "🚀 Авто",
                "type":     "url-test",
                "proxies":  names,
                "url":      "https://www.gstatic.com/generate_204",
                "interval": 180,
                "tolerance": 50,
            },
            {
                "name":    "🔀 Выбор",
                "type":    "select",
                "proxies": ["🚀 Авто"] + names,
            },
        ],
        "rules": [
            "GEOIP,RU,DIRECT",
            "MATCH,🔀 Выбор",
        ],
    }

    with open(CLASH_FILE, "w", encoding="utf-8") as f:
        f.write("# WhiteVless — Clash Meta / Mihomo config\n")
        f.write("# Импорт: вставить URL в Hiddify/Clash Meta\n\n")
        f.write(_to_yaml(cfg) + "\n")
    log.info(f"written clash config: {len(proxies)} proxies → {CLASH_FILE}")


def write_output(final_keys):
    announce = (
        "Как пользоваться:\n1. Нажмите на иконку где 2 стрелки \n2. Нажмите на иконку правее.\n"
        "3. Выберите сервер где меньше всего ms (100ms)\n"
        "Не заходите на рф сервисы через VPN!"
    )
    header = "\n".join([
        f"#profile-title: base64:{b64e('👾WhiteVless')}",
        "#profile-update-interval: 2",
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{b64e(announce)}", "",
    ])
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for k in final_keys: f.write(k + "\n")
    log.info(f"written {len(final_keys)} keys → {OUTPUT_FILE}")
    write_clash(final_keys)

async def main():
    load_config(); load_blocklist()
    direct_sources, dorks = load_sources()
    connector = aiohttp.TCPConnector(limit=120, ssl=False)
    ua = {"User-Agent": "Mozilla/5.0 (compatible; WhiteVless/4.0)"}

    async with aiohttp.ClientSession(connector=connector, headers=ua) as session:
        await fetch_hxehex_whitelist(session)
        raw_keys = await collect_all_keys(session, direct_sources, dorks)

        # geo lookup — needed for domain hosts (parser runs outside RU)
        all_hosts = list(dict.fromkeys(extract_host(k) for k, _ in raw_keys if extract_host(k)))
        log.info(f"geo lookup for {len(all_hosts)} hosts...")
        pre_geo = await get_geo_batch(session, all_hosts)

        NON_RU_CC = {
            "IR", "CN", "US", "DE", "NL", "FR", "GB", "SG", "JP", "KR",
            "TR", "IN", "UA", "PL", "FI", "SE", "NO", "AT", "CH", "CA",
            "AU", "HK", "TW", "VN", "TH", "MY", "ID", "AE", "SA", "IL",
        }

        def _keep_key(host, trusted):
            if trusted: return True  # trusted sources are pre-validated, skip geo check
            if is_ip(host): return is_ru_ip(host)
            cc = DOMAIN_COUNTRY.get(host, "").upper()
            if cc == "RU": return True
            if cc in NON_RU_CC: return False
            return False  # unknown geo — untrusted sources don't pass without confirmed RU

        # SNI quality filter — reality keys must have a known RU SNI
        sni_pool_set = set(SNI_POOL)
        def _has_ru_sni(key):
            params = extract_params(key)
            if params.get("security") != "reality": return True
            sni = params.get("sni", "").lower()
            if not sni: return False
            return sni in sni_pool_set or sni.endswith(".ru") or sni.endswith(".рф")

        # Trusted sources are pre-validated from Russia — skip SNI filter for them
        # Untrusted sources get full geo+SNI filter + TCP check
        trusted_raw   = [(k, t) for k, t in raw_keys if t     and _keep_key(extract_host(k), t)]
        untrusted_raw = [(k, t) for k, t in raw_keys if not t and _keep_key(extract_host(k), t) and _has_ru_sni(k)]

        # dedup trusted by endpoint
        seen_ep: set = set()
        trusted_dedup = []
        for k, t in trusted_raw:
            ep = f"{extract_host(k)}:{extract_port(k)}"
            if ep not in seen_ep: seen_ep.add(ep); trusted_dedup.append(k)
        log.info(f"trusted keys (pre-validated): {len(trusted_dedup)}")

        # Step 1: find bootstrap RU proxy from trusted keys
        # This gives us a Russian IP to validate everything else through
        log.info("bootstrap: searching for RU proxy in trusted keys...")
        bootstrap_mgr = await start_bootstrap_proxy(trusted_dedup[:120])
        if bootstrap_mgr.socks_url:
            log.info("bootstrap: RU proxy found — all TCP checks will run through it")
        else:
            log.warning("bootstrap: no RU proxy found — TCP checks run from GitHub IP (less reliable)")

        # dedup untrusted against trusted endpoints
        untrusted_dedup = []
        for k, t in untrusted_raw:
            ep = f"{extract_host(k)}:{extract_port(k)}"
            if ep not in seen_ep: seen_ep.add(ep); untrusted_dedup.append((k, t))
        log.info(f"untrusted candidates for TCP check: {len(untrusted_dedup)}")

        # Step 2: TCP-check untrusted keys — routes through bootstrap RU proxy if available
        sem = asyncio.Semaphore(CONCURRENCY)
        untrusted_alive = await check_keys_tcp(untrusted_dedup, sem)
        log.info(f"untrusted alive: {len(untrusted_alive)}")

        # trusted keys get synthetic latency 1ms so they sort first
        trusted_alive = [(1.0, k) for k in trusted_dedup]
        ru_alive = trusted_alive + untrusted_alive
        log.info(f"total pool: {len(ru_alive)}")

        selected = select_keys(ru_alive, MAX_RU_KEYS)
        log.info(f"selected: {len(selected)}")

        # bootstrap for l7 — best-effort, use trusted keys as candidates
        bootstrap_mgr = await start_bootstrap_proxy([k for _, k in trusted_alive[:120]])

        # l7 speed test — only if bootstrap RU proxy is up
        speed_map: dict[str, float] = {}
        binary = _get_binary()
        if binary and bootstrap_mgr.socks_url:
            log.info(f"l7 speed tests running (binary: {os.path.basename(binary)})...")
            await bootstrap_mgr.ensure_alive()
            l7_sem = asyncio.Semaphore(L7_CONCURRENCY)
            l7_results = await asyncio.gather(*[l7_test(k, l7_sem) for _, k in selected])
            before = len(selected)
            filtered = []
            for (lat, key), (passed, spd) in zip(selected, l7_results):
                if passed:
                    speed_map[key] = spd
                    filtered.append((lat, key))
            selected = filtered
            log.info(f"l7: kept {len(selected)}/{before} keys")
        else:
            log.info("l7 skipped — bootstrap proxy not available")

        # build remarks
        _remark_counters.clear()
        final = []
        for lat, key in selected:
            host = extract_host(key)
            info = pre_geo.get(host, {"flag": "🏳️", "isp": host, "country": "UN"})
            spd  = speed_map.get(key, 0.0)
            remark = build_remark(key, info, lat, spd)
            final.append(f"{key.split('#')[0]}#{quote(remark)}")

        write_output(final)

        # stats
        trusted_final = sum(1 for _, k in selected if k in {kk for kk in trusted_dedup})
        log.info(f"done: {len(final)} keys ({trusted_final} from trusted sources, {len(final)-trusted_final} from untrusted+TCP-checked)")
        # show top hosters
        from collections import Counter
        hoster_counts = Counter(pre_geo.get(extract_host(k), {}).get("isp", extract_host(k))[:30] for _, k in selected)
        for isp, cnt in hoster_counts.most_common(10):
            log.info(f"  hoster: {isp} — {cnt} keys")

        if bootstrap_mgr:
            bootstrap_mgr.stop()
            log.info("bootstrap proxy stopped")

if __name__ == "__main__":
    asyncio.run(main())
