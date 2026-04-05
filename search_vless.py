#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# whitevless — vless parser for russian users
# logic: collect → dedup → TCP check → write
# deps: pip install aiohttp

import asyncio
import aiohttp
import re
import base64
import os
import time
import logging
from html import unescape as html_unescape
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("whitevless")

# ── paths ────────────────────────────────────────────────────────────────────
BASE_DIR      = os.path.dirname(os.path.abspath(__file__))
OUTPUT_FILE   = os.path.join(BASE_DIR, "filtered_vless_keys.txt")
DIRECT_FILE   = os.path.join(BASE_DIR, "sources", "direct.txt")
DORKS_FILE    = os.path.join(BASE_DIR, "sources", "github_dorks.txt")
BLACKLIST_FILE= os.path.join(BASE_DIR, "blacklist", "vless_blacklist.txt")
CLASH_FILE    = os.path.join(BASE_DIR, "clash.yaml")

# ── settings ─────────────────────────────────────────────────────────────────
MAX_KEYS     = 200
TCP_TIMEOUT  = 8.0
CONCURRENCY  = 100
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

TRUSTED_SOURCE_PATTERNS = (
    "igareck/vpn-configs-for-russia",
    "SilentGhostCodes/WhiteListVpn",
    "RKPchannel/RKP_bypass_configs",
    "zieng2/wl",
    "AvenCores/goida-vpn-configs",
)

UUID_RE   = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$', re.I)
ARABIC_RE = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')
SPAM_RE   = re.compile(r'(t\.me|telegram\.(me|org|dog)|@[\w_]{3,}|купить|прода)', re.I)

BLOCKLIST_EXACT:   set[str] = set()
BLOCKLIST_PARTIAL: set[str] = set()

# ── SNI / operator data ───────────────────────────────────────────────────────
SNI_DIR      = os.path.join(BASE_DIR, "sni")
SNI_FILES    = {
    "mts":           os.path.join(SNI_DIR, "mts",           "sni.txt"),
    "beeline":       os.path.join(SNI_DIR, "beeline",       "sni.txt"),
    "megafon":       os.path.join(SNI_DIR, "megafon",       "sni.txt"),
    "t2":            os.path.join(SNI_DIR, "t2",            "sni.txt"),
    "yota":          os.path.join(SNI_DIR, "yota",          "sni.txt"),
    "all_operators": os.path.join(SNI_DIR, "all_operators", "sni.txt"),
}
OPERATOR_SNI: dict[str, list] = {}

def _lines(path):
    if not os.path.exists(path): return []
    with open(path, encoding="utf-8", errors="ignore") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]

def load_config():
    for op, path in SNI_FILES.items():
        OPERATOR_SNI[op] = _lines(path)
        log.info(f"sni [{op}]: {len(OPERATOR_SNI[op])}")

def load_blocklist():
    if not os.path.exists(BLACKLIST_FILE): return
    with open(BLACKLIST_FILE, encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip().lower()
            if not line or line.startswith("#"): continue
            if line.startswith("vless://"): BLOCKLIST_EXACT.add(line)
            else: BLOCKLIST_PARTIAL.add(line)
    log.info(f"blocklist: exact={len(BLOCKLIST_EXACT)}, partial={len(BLOCKLIST_PARTIAL)}")

# ── key parsing ───────────────────────────────────────────────────────────────
def _extract(link, part):
    try:
        p = urlparse(link)
        if part == "host": return p.hostname or ""
        if part == "port":
            return p.port if p.port and 1 <= p.port <= 65535 else 0
        if part == "params": return {k: v[0] for k, v in parse_qs(p.query).items()}
    except: pass
    return "" if part != "port" else 0

def _valid_uuid(u):
    return bool(UUID_RE.match(u)) if u else False

def _is_blocked(key):
    kl = key.lower()
    return kl in BLOCKLIST_EXACT or any(p in kl for p in BLOCKLIST_PARTIAL)

def _clean(raw):
    key = raw.strip()
    if not key.startswith("vless://"): return None
    # strip arabic / spam from base (before #)
    base = ARABIC_RE.sub("", key.split("#")[0])
    if SPAM_RE.search(base): return None
    if _is_blocked(key): return None
    try:
        p = urlparse(base)
        if not _valid_uuid(p.username or ""): return None
        if not p.hostname or not p.port: return None
        if not (1 <= p.port <= 65535): return None
    except: return None
    # inject fp for reality if missing
    params = {k: v[0] for k, v in parse_qs(urlparse(base).query).items()}
    if params.get("security") == "reality" and "fp" not in params:
        params["fp"] = "chrome"
        parsed = urlparse(base)
        base = urlunparse(parsed._replace(query=urlencode(params)))
    return base

def _parse_text(text):
    text = html_unescape(text)
    text = re.sub(r'&amp%3B|%26amp%3B', '&', text, flags=re.I)
    keys = []
    for line in text.splitlines():
        line = line.strip()
        candidates = [line] if line.startswith("vless://") else re.findall(r'vless://[^\s\'"<>\]\[]+', line)
        for c in candidates:
            k = _clean(c)
            if k: keys.append(k)
    return keys

# ── fetching ──────────────────────────────────────────────────────────────────
async def _get(session, url, accept="text/plain, */*"):
    try:
        async with session.get(url, headers={"Accept": accept},
                               timeout=aiohttp.ClientTimeout(total=20)) as r:
            if r.status == 200: return await r.text(errors="ignore")
    except Exception as e: log.debug(f"fetch {url}: {e}")
    return ""

async def fetch_direct(session):
    sources = []
    for line in _lines(DIRECT_FILE):
        parts = line.split("|"); url = parts[0].strip()
        if not url.startswith("http"): continue
        accept = parts[2].strip() if len(parts) > 2 else "text/plain, */*"
        trusted = any(p in url for p in TRUSTED_SOURCE_PATTERNS)
        sources.append((url, accept, trusted))
    log.info(f"direct sources: {len(sources)}")
    texts = await asyncio.gather(*[_get(session, url, acc) for url, acc, _ in sources])
    keys = []
    for (url, _, trusted), text in zip(sources, texts):
        found = _parse_text(text)
        if found: log.info(f"  {url.split('/')[-1][:45]}: {len(found)} (trusted={trusted})")
        for k in found: keys.append((k, trusted))
    return keys

async def _github_search(session, query):
    headers = {"Accept": "application/vnd.github+json"}
    if GITHUB_TOKEN: headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    url = f"https://api.github.com/search/code?q={quote(query)}&per_page=30"
    for attempt in range(3):
        try:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 403:
                    wait = max(int(r.headers.get("Retry-After", 30)), 30)
                    log.warning(f"rate limit '{query[:40]}' wait {wait}s")
                    await asyncio.sleep(wait); continue
                if r.status in (422, 401): return []
                if r.status != 200: return []
                data = await r.json(content_type=None)
                raw_urls = []
                for item in data.get("items", []):
                    raw = item.get("html_url","").replace("github.com","raw.githubusercontent.com").replace("/blob/","/")
                    if raw: raw_urls.append(raw)
                texts = await asyncio.gather(*[_get(session, u) for u in raw_urls[:20]])
                keys = []
                for t in texts: keys.extend(_parse_text(t))
                return [(k, False) for k in keys]
        except Exception as e: log.debug(f"github '{query}': {e}"); return []
    return []

async def fetch_github(session):
    dorks = _lines(DORKS_FILE)
    log.info(f"github dorks: {len(dorks)}")
    delay = 8.0 if GITHUB_TOKEN else 12.0
    keys = []
    for i, dork in enumerate(dorks):
        if i > 0: await asyncio.sleep(delay + (i % 3) * 2.0)
        found = await _github_search(session, dork)
        keys.extend(found)
        log.info(f"  [{i+1}/{len(dorks)}] '{dork[:45]}' +{len(found)} total={len(keys)}")
    return keys

# ── TCP check ─────────────────────────────────────────────────────────────────
async def tcp_check(host, port):
    try:
        start = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=TCP_TIMEOUT)
        writer.close()
        try: await writer.wait_closed()
        except: pass
        return (time.monotonic() - start) * 1000
    except: return -1.0

async def check_tcp_batch(keys, sem):
    async def _one(key):
        host = _extract(key, "host")
        port = _extract(key, "port")
        if not host or not port: return None
        async with sem:
            lat = await tcp_check(host, port)
            if lat < 0: return None
        return (lat, key)
    results = await asyncio.gather(*[_one(k) for k in keys])
    return sorted([r for r in results if r], key=lambda x: x[0])

# ── geo lookup ────────────────────────────────────────────────────────────────
GEO_CACHE: dict[str, dict] = {}

def _cc_flag(cc):
    if len(cc) != 2: return "🏳️"
    return chr(ord(cc[0]) + 127397) + chr(ord(cc[1]) + 127397)

async def geo_lookup(session, hosts):
    unique = list(dict.fromkeys(hosts))
    for i in range(0, len(unique), 100):
        chunk = unique[i:i+100]
        try:
            payload = [{"query": h, "fields": "query,countryCode,isp,org"} for h in chunk]
            async with session.post("http://ip-api.com/batch", json=payload,
                                    timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status == 200:
                    for item in await r.json(content_type=None):
                        h = item.get("query","")
                        cc = item.get("countryCode","")
                        isp = item.get("isp","") or item.get("org","")
                        isp = re.sub(r'\s*\(.*?\)','',isp).strip()[:45]
                        GEO_CACHE[h] = {"cc": cc, "isp": isp, "flag": _cc_flag(cc)}
        except Exception as e: log.debug(f"geo batch: {e}")
        await asyncio.sleep(1.0)

# ── operator scoring ──────────────────────────────────────────────────────────
_OP_LABELS = {
    "МТС":                           "🇷🇺 LTE МТС",
    "МТС|Билайн":                    "🇷🇺 LTE МТС + Билайн",
    "МТС|МегаФон|Tele2|Билайн":      "🇷🇺 LTE Все операторы",
    "МТС|МегаФон|Yota|Tele2|Билайн": "🇷🇺 LTE Все операторы",
    "МегаФон":                       "🇷🇺 LTE МегаФон",
    "МегаФон|Yota":                  "🇷🇺 LTE МегаФон + Yota",
    "Tele2":                         "🇷🇺 LTE Tele2",
    "Билайн":                        "🇷🇺 LTE Билайн",
    "Универсальный":                 "🇷🇺 LTE Обход",
}
_REMARK_COUNTERS: dict = {}

def _score_ops(key, isp=""):
    params = _extract(key, "params")
    sec = params.get("security",""); tp = params.get("type","tcp")
    fp = params.get("fp",""); port = _extract(key, "port")
    sni = params.get("sni","").lower(); isp_l = isp.lower()
    is_reality = sec == "reality"
    is_grpc = tp == "grpc"; is_ws = tp in ("ws","websocket"); is_xhttp = tp == "xhttp"
    is_std_port = port in (443, 80, 8443); is_high_port = port > 9999
    bad_t2 = any(x in isp_l for x in ("digitalocean","hetzner","linode"))
    mts_sni     = set(OPERATOR_SNI.get("mts",[]))
    megafon_sni = set(OPERATOR_SNI.get("megafon",[]))
    t2_sni      = set(OPERATOR_SNI.get("t2",[]))
    beeline_sni = set(OPERATOR_SNI.get("beeline",[]))
    all_op_sni  = set(OPERATOR_SNI.get("all_operators",[]))
    sni_all = sni in all_op_sni
    ops = []
    if is_reality and fp and tp in ("tcp","raw","grpc"):
        if sni in mts_sni or sni_all or is_high_port: ops.append("МТС")
    if is_reality and (is_std_port or is_xhttp):
        if sni in megafon_sni or sni_all: ops.extend(["МегаФон","Yota"])
    if (is_grpc or is_ws or is_xhttp) and not bad_t2:
        if sni in t2_sni or sni_all: ops.append("Tele2")
    if is_reality and fp and (sni in beeline_sni or sni_all): ops.append("Билайн")
    if not ops and sni_all and is_reality: ops = ["МТС","МегаФон","Tele2","Yota","Билайн"]
    return ops if ops else ["Универсальный"]

def _build_remark(key, lat):
    host = _extract(key, "host")
    geo  = GEO_CACHE.get(host, {})
    isp  = geo.get("isp", host)
    ops  = _score_ops(key, isp)
    priority = ["МТС","МегаФон","Tele2","Yota","Билайн"]
    ops_sorted = sorted(set(ops), key=lambda x: priority.index(x) if x in priority else 99)
    ops_key = "|".join(ops_sorted)
    label = _OP_LABELS.get(ops_key) or _OP_LABELS.get(ops_sorted[0] if ops_sorted else "Универсальный","🇷🇺 LTE Обход")
    isp_short = isp.split()[0][:12] if isp else "?"
    _REMARK_COUNTERS[label] = _REMARK_COUNTERS.get(label, 0) + 1
    n = _REMARK_COUNTERS[label]
    return f"{label} | {isp_short} | #{n}"

# ── output ────────────────────────────────────────────────────────────────────
def _b64e(s): return base64.b64encode(s.encode()).decode()

def write_output(keys_with_lat):
    announce = (
        "Как пользоваться:\n1. Нажмите на иконку где 2 стрелки \n2. Нажмите на иконку правее.\n"
        "3. Выберите сервер где меньше всего ms (100ms)\n"
        "Не заходите на рф сервисы через VPN!"
    )
    header = "\n".join([
        f"#profile-title: base64:{_b64e('👾WhiteVless')}",
        "#profile-update-interval: 2",
        "#support-url: https://github.com/plsn1337/white-vless/",
        "#profile-web-page-url: https://github.com/plsn1337/white-vless/",
        f"#announce: base64:{_b64e(announce)}", "",
    ])
    _REMARK_COUNTERS.clear()
    lines = []
    for lat, key in keys_with_lat:
        remark = _build_remark(key, lat)
        lines.append(f"{key}#{quote(remark)}")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write(header)
        for l in lines: f.write(l + "\n")
    log.info(f"written {len(lines)} keys → {OUTPUT_FILE}")

# ── clash output ──────────────────────────────────────────────────────────────
def write_clash(keys_with_lat):
    def _proxy(key, name):
        try:
            p = urlparse(key)
            params = {k: v[0] for k, v in parse_qs(p.query).items()}
            sec = params.get("security",""); tp = params.get("type","tcp")
            proxy = {"name": name, "type": "vless", "server": p.hostname,
                     "port": p.port, "uuid": p.username, "udp": True}
            flow = params.get("flow","")
            if flow: proxy["flow"] = flow
            if sec == "reality":
                proxy.update({"tls": True, "servername": params.get("sni",""),
                    "reality-opts": {"public-key": params.get("pbk",""), "short-id": params.get("sid","")},
                    "client-fingerprint": params.get("fp","chrome")})
            elif sec == "tls":
                proxy.update({"tls": True, "servername": params.get("sni",""), "skip-cert-verify": True})
            if tp == "ws":
                proxy["network"] = "ws"
                proxy["ws-opts"] = {"path": params.get("path","/"), "headers": {"Host": params.get("host", p.hostname)}}
            elif tp == "grpc":
                proxy["network"] = "grpc"
                proxy["grpc-opts"] = {"grpc-service-name": params.get("serviceName","")}
            elif tp in ("xhttp","http"):
                proxy["network"] = "http"
                proxy["http-opts"] = {"path": [params.get("path","/")]}
            return proxy
        except: return None

    def _to_yaml(obj, indent=0):
        pad = "  " * indent
        if isinstance(obj, dict):
            lines = []
            for k, v in obj.items():
                if isinstance(v, (dict, list)):
                    lines.append(f"{pad}{k}:")
                    lines.append(_to_yaml(v, indent+1))
                else:
                    lines.append(f"{pad}{k}: {_yaml_val(v)}")
            return "\n".join(lines)
        elif isinstance(obj, list):
            lines = []
            for item in obj:
                if isinstance(item, dict):
                    items = list(item.items())
                    fk, fv = items[0]
                    if isinstance(fv, (dict, list)):
                        lines.append(f"{pad}- {fk}:")
                        lines.append(_to_yaml(fv, indent+2))
                    else:
                        lines.append(f"{pad}- {fk}: {_yaml_val(fv)}")
                    for k, v in items[1:]:
                        if isinstance(v, (dict, list)):
                            lines.append(f"{pad}  {k}:")
                            lines.append(_to_yaml(v, indent+2))
                        else:
                            lines.append(f"{pad}  {k}: {_yaml_val(v)}")
                else:
                    lines.append(f"{pad}- {_yaml_val(item)}")
            return "\n".join(lines)
        return f"{pad}{_yaml_val(obj)}"

    proxies, names = [], []
    _REMARK_COUNTERS.clear()
    for lat, key in keys_with_lat:
        name = _build_remark(key, lat)
        base = name; n = 1
        while name in names: name = f"{base} ({n})"; n += 1
        px = _proxy(key, name)
        if px: proxies.append(px); names.append(name)

    if not proxies: return

    cfg = {
        "mixed-port": 7890, "allow-lan": False, "mode": "rule",
        "log-level": "warning", "external-controller": "127.0.0.1:9090",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "🚀 Авто", "type": "url-test", "proxies": names,
             "url": "https://www.gstatic.com/generate_204", "interval": 180, "tolerance": 50},
            {"name": "🔀 Выбор", "type": "select", "proxies": ["🚀 Авто"] + names},
        ],
        "rules": ["GEOIP,RU,DIRECT", "MATCH,🔀 Выбор"],
    }
    with open(CLASH_FILE, "w", encoding="utf-8") as f:
        f.write("# WhiteVless — Clash Meta config\n")
        f.write(_to_yaml(cfg) + "\n")
    log.info(f"written clash: {len(proxies)} proxies → {CLASH_FILE}")

def _yaml_val(v):
    if isinstance(v, bool): return "true" if v else "false"
    if isinstance(v, (int, float)): return str(v)
    s = str(v)
    if any(c in s for c in ':{}[]|>&*!,#?@`\'"') or not s: return f'"{s}"'
    return s

# ── main ──────────────────────────────────────────────────────────────────────
async def main():
    load_config()
    load_blocklist()

    connector = aiohttp.TCPConnector(limit=150, ssl=False)
    ua = {"User-Agent": "Mozilla/5.0 (compatible; WhiteVless/5.0)"}

    async with aiohttp.ClientSession(connector=connector, headers=ua) as session:
        # 1. collect from all sources
        direct_keys  = await fetch_direct(session)
        github_keys  = await fetch_github(session)
        all_keys = direct_keys + github_keys
        log.info(f"total collected: {len(all_keys)}")

        # 2. dedup by endpoint
        seen, deduped = set(), []
        for key, trusted in all_keys:
            ep = f"{_extract(key,'host')}:{_extract(key,'port')}"
            if ep not in seen:
                seen.add(ep)
                deduped.append((key, trusted))
        log.info(f"after dedup: {len(deduped)}")

        # 3. split: trusted sources are pre-validated by maintainers from Russia
        #    → no TCP check needed, take them directly
        #    untrusted → TCP check to filter dead servers
        trusted_keys   = [k for k, t in deduped if t]
        untrusted_keys = [k for k, t in deduped if not t]
        log.info(f"trusted (no TCP check): {len(trusted_keys)}, untrusted (TCP check): {len(untrusted_keys)}")

        sem = asyncio.Semaphore(CONCURRENCY)
        untrusted_alive = await check_tcp_batch(untrusted_keys, sem)
        log.info(f"untrusted alive after TCP: {len(untrusted_alive)}")

        # trusted get synthetic 1ms latency so they sort first
        trusted_alive = [(1.0, k) for k in trusted_keys]
        pool = trusted_alive + untrusted_alive
        log.info(f"total pool: {len(pool)}")

        # 4. dedup pool by endpoint (trusted already deduped, but untrusted may overlap)
        seen2, final_pool = set(), []
        for lat, key in pool:
            ep = f"{_extract(key,'host')}:{_extract(key,'port')}"
            if ep not in seen2:
                seen2.add(ep)
                final_pool.append((lat, key))

        # 5. select up to MAX_KEYS — MTS-compatible first
        def _is_mts(key):
            params = _extract(key, "params")
            if params.get("security") != "reality" or not params.get("fp"): return False
            if params.get("type","tcp") not in ("tcp","raw","grpc"): return False
            sni = params.get("sni","").lower()
            all_op = set(OPERATOR_SNI.get("all_operators",[]))
            mts    = set(OPERATOR_SNI.get("mts",[]))
            return sni in mts or sni in all_op or _extract(key,"port") > 9999

        mts_keys   = [(lat, k) for lat, k in final_pool if _is_mts(k)]
        other_keys = [(lat, k) for lat, k in final_pool if not _is_mts(k)]
        selected = (mts_keys + other_keys)[:MAX_KEYS]
        log.info(f"selected: {len(selected)} (mts-compatible: {len(mts_keys[:MAX_KEYS])})")

        # 6. geo lookup for remarks
        hosts = list(dict.fromkeys(_extract(k,"host") for _, k in selected))
        await geo_lookup(session, hosts)

        # 7. write output
        write_output(selected)
        write_clash(selected)
        log.info(f"done: {len(selected)} keys")

if __name__ == "__main__":
    asyncio.run(main())
