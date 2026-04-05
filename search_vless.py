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

MAX_RU_KEYS    = 200
TCP_TIMEOUT    = 3.0
CONCURRENCY    = 80
L7_CONCURRENCY = 10
GITHUB_TOKEN   = os.environ.get("GITHUB_TOKEN", "")
SINGBOX_BIN    = os.environ.get("SINGBOX_BIN", "")
V2RAY_BIN      = os.environ.get("V2RAY_BIN", "")
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
AD_PATTERN = re.compile(r'(t\.me|telegram\.(me|org|dog)|https?://|@[\w_]{3,}|купить|прода|promo|sale|free|premium)', re.I)
ARABIC_RE  = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
UUID_RE    = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)

TRUSTED_SOURCE_PATTERNS = (
    "igareck/vpn-configs-for-russia",
    "SilentGhostCodes/WhiteListVpn",
    "RKPchannel/RKP_bypass_configs",
    "zieng2/wl",
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

def is_ru_host(host):
    if is_ip(host): return is_ru_ip(host)
    return DOMAIN_COUNTRY.get(host, "").upper() == "RU"

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
        pool = OPERATOR_SNI.get("mts", []) or SNI_POOL
        params["sni"] = pool[0] if pool else "www.google.com"; changed = True
    return urlunparse(parsed._replace(query=urlencode(params))) if changed else link

def validate_vless(key):
    if not key.startswith("vless://"): return False
    try:
        p = urlparse(key)
        if not is_valid_uuid(p.username or ""): return False
        if not p.hostname or not p.port: return False
        if not (1 <= p.port <= 65535): return False
        if "type" not in parse_qs(p.query): return False
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
    texts = await asyncio.gather(*[fetch_url(session, url, accept) for url, accept in sources])
    keys = []
    for (url, _), text in zip(sources, texts):
        trusted = any(p in url for p in TRUSTED_SOURCE_PATTERNS)
        for k in _parse_keys(text): keys.append((k, trusted))
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
    gh_delay = 6.0 if GITHUB_TOKEN else 10.0
    log.info(f"github search: {len(dorks)} dorks (delay={gh_delay}s)")
    for i, dork in enumerate(dorks):
        if i > 0: await asyncio.sleep(gh_delay)
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
            if not trusted and sec in ("tls", "reality"):
                if not await tls_check(host, port, sni):
                    log.debug(f"tls failed: {host}:{port}"); return None
        return (lat, key)
    results = await asyncio.gather(*[_one(k, t) for k, t in keys])
    return sorted([r for r in results if r], key=lambda x: x[0])

def _make_singbox_config(key, socks_port):
    try:
        p = urlparse(key); params = {k: v[0] for k, v in parse_qs(p.query).items()}
        tp = params.get("type", "tcp")
        transport = {}
        if tp == "ws": transport = {"type": "ws", "path": params.get("path", "/"), "headers": {"Host": params.get("host", "")}}
        elif tp == "grpc": transport = {"type": "grpc", "service_name": params.get("serviceName", "")}
        elif tp in ("xhttp", "http"): transport = {"type": "http", "path": params.get("path", "/")}
        cfg = {
            "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socks_port}],
            "outbounds": [{"type": "vless", "tag": "proxy", "server": p.hostname, "server_port": p.port,
                "uuid": p.username, "flow": params.get("flow", ""),
                "tls": {"enabled": params.get("security") in ("tls", "reality"),
                    "server_name": params.get("sni", ""),
                    "reality": {"enabled": params.get("security") == "reality",
                        "public_key": params.get("pbk", ""), "short_id": params.get("sid", "")},
                    "utls": {"enabled": bool(params.get("fp")), "fingerprint": params.get("fp", "chrome")}},
                "transport": transport}],
        }
        return json.dumps(cfg)
    except Exception as e: log.debug(f"singbox config: {e}"); return None

async def start_bootstrap_proxy(candidates):
    global BOOTSTRAP_SOCKS
    binary = SINGBOX_BIN
    if not binary or not os.path.exists(binary):
        log.info("singbox not available — skipping bootstrap proxy"); return None
    socks_port = 10700
    for key in candidates[:30]:
        cfg_json = _make_singbox_config(key, socks_port)
        if not cfg_json: continue
        cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        cfg_file.write(cfg_json); cfg_file.close()
        proc = subprocess.Popen([binary, "run", "-c", cfg_file.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        await asyncio.sleep(2.5)
        try:
            proxy = f"socks5://127.0.0.1:{socks_port}"
            connector = aiohttp.ProxyConnector.from_url(proxy)
            async with aiohttp.ClientSession(connector=connector) as s:
                async with s.get("https://api.myip.com", timeout=aiohttp.ClientTimeout(total=8)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        if data.get("cc") == "RU":
                            BOOTSTRAP_SOCKS = proxy
                            log.info(f"bootstrap RU proxy ready: {extract_host(key)}:{extract_port(key)}")
                            try: os.unlink(cfg_file.name)
                            except: pass
                            return proc
        except Exception as e: log.debug(f"bootstrap {extract_host(key)}: {e}")
        proc.terminate()
        try: proc.wait(timeout=3)
        except: proc.kill()
        try: os.unlink(cfg_file.name)
        except: pass
    log.warning("bootstrap: no working RU proxy found — checks run from GitHub IP")
    return None

async def l7_test(key, sem):
    """
    Real speed test: start singbox, download 1MB through it, measure speed.
    Returns (passed: bool, speed_mbps: float).
    Minimum threshold: 1 Mbit/s — below that the key is discarded.
    """
    binary = SINGBOX_BIN or V2RAY_BIN
    if not binary or not os.path.exists(binary):
        return True, 0.0
    async with sem:
        socks_port = 10800 + (abs(hash(key)) % 1000)
        cfg_json = _make_singbox_config(key, socks_port)
        if not cfg_json:
            return True, 0.0
        cfg_file = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False, encoding="utf-8")
        cfg_file.write(cfg_json); cfg_file.close()
        proc = None
        try:
            proc = subprocess.Popen(
                [binary, "run", "-c", cfg_file.name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
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
            passed = speed_mbps >= 1.0
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
        await asyncio.sleep(0.3)
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
    ops = []
    if is_reality and fp and tp in ("tcp", "raw", "grpc"):
        if sni in mts_sni or sni_all or is_high_port: ops.append("МТС")
    if is_reality and (is_std_port or is_xhttp):
        if sni in megafon_sni or sni_all: ops.extend(["МегаФон", "Yota"])
    if (is_grpc or is_ws or is_xhttp) and not bad_t2:
        if sni in t2_sni or sni_all: ops.append("Tele2")
    if is_reality and fp: ops.append("Билайн")
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
    _remark_counters[label] = _remark_counters.get(label, 0) + 1
    n = _remark_counters[label]
    if speed_mbps >= 50:
        speed_tag = " [100МБ/С]"
    elif speed_mbps >= 10:
        speed_tag = " [10МБ/С]"
    else:
        speed_tag = ""
    return f"{label}{speed_tag} #{n}"

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

def write_output(final_keys):
    announce = (
        "Как пользоваться:\n1. Нажмите «Подключить в Happ»\n2. Нажмите «Добавить» и подтвердите\n"
        "3. Выберите сервер и нажмите ▶ Старт\nОбновление каждые 2 часа автоматически.\n"
        "МТС/МегаФон/Tele2/Билайн — для каких операторов работает лучше"
    )
    header = "\n".join([
        f"#profile-title: base64:{b64e('⚡ WhiteVless — Россия')}",
        "#profile-update-interval: 2",
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{b64e(announce)}", "",
    ])
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for k in final_keys: f.write(k + "\n")
    log.info(f"written {len(final_keys)} keys → {OUTPUT_FILE}")

async def main():
    load_config(); load_blocklist()
    direct_sources, dorks = load_sources()
    connector = aiohttp.TCPConnector(limit=120, ssl=False)
    ua = {"User-Agent": "Mozilla/5.0 (compatible; WhiteVless/4.0)"}

    async with aiohttp.ClientSession(connector=connector, headers=ua) as session:
        await fetch_hxehex_whitelist(session)
        raw_keys = await collect_all_keys(session, direct_sources, dorks)

        # geo lookup before split — needed for domain hosts (parser runs outside RU)
        all_hosts = list(dict.fromkeys(extract_host(k) for k, _ in raw_keys if extract_host(k)))
        log.info(f"pre-split geo lookup for {len(all_hosts)} hosts...")
        pre_geo = await get_geo_batch(session, all_hosts)

        ru_keys = [(k, t) for k, t in raw_keys if is_ru_host(extract_host(k))]
        log.info(f"ru keys: {len(ru_keys)}")

        # dedup by endpoint
        seen_ep, deduped = set(), []
        for k, t in ru_keys:
            ep = f"{extract_host(k)}:{extract_port(k)}"
            if ep not in seen_ep: seen_ep.add(ep); deduped.append((k, t))
        ru_keys = deduped
        log.info(f"after dedup: {len(ru_keys)}")

        # bootstrap: start RU proxy using trusted (igareck) keys first
        bootstrap_candidates = [k for k, t in ru_keys if t] + [k for k, t in ru_keys if not t]
        bootstrap_proc = await start_bootstrap_proxy(bootstrap_candidates)

        # tcp+tls check (through RU proxy if bootstrap succeeded)
        sem = asyncio.Semaphore(CONCURRENCY)
        ru_alive = await check_keys_tcp(ru_keys, sem)
        log.info(f"alive: {len(ru_alive)}")

        selected = select_keys(ru_alive, MAX_RU_KEYS)
        log.info(f"selected: {len(selected)}")

        # l7 speed test — requires singbox, filters keys < 1 Mbit/s
        speed_map: dict[str, float] = {}
        binary = SINGBOX_BIN or V2RAY_BIN
        if binary and os.path.exists(binary):
            log.info("l7 speed tests running...")
            l7_sem = asyncio.Semaphore(L7_CONCURRENCY)
            l7_results = await asyncio.gather(*[l7_test(k, l7_sem) for _, k in selected])
            before = len(selected)
            filtered = []
            for (lat, key), (passed, spd) in zip(selected, l7_results):
                if passed:
                    speed_map[key] = spd
                    filtered.append((lat, key))
            selected = filtered
            log.info(f"l7: kept {len(selected)}/{before} keys (min 1 Mbit/s)")
        else:
            log.info("l7 skipped — set SINGBOX_BIN to enable speed filtering")

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
        log.info(f"done: {len(final)} keys")

        if bootstrap_proc:
            bootstrap_proc.terminate()
            try: bootstrap_proc.wait(timeout=3)
            except: bootstrap_proc.kill()
            log.info("bootstrap proxy stopped")

if __name__ == "__main__":
    asyncio.run(main())
