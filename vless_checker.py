import os, json, subprocess, requests, re, time, socket, base64
from urllib.parse import parse_qs
from datetime import datetime

# 🔧 
SOURCES = [
    "https://loginvkcom.vercel.app/sub",
]

#  WHITELIST_DOMAINS = ["cf-ip.com", "example.net"]
WHITELIST_DOMAINS = []

TEST_URLS = [
    "https://1.1.1.1",
    "https://httpbin.org/status/200"
]

TIMEOUT_TCP = 2
TIMEOUT_PROXY = 5
RESULT_FILE = "working_keys.txt"
LOG_FILE = "checker.log"

HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def fetch_keys():
    raw = ""
    for url in SOURCES:
        try:
            log(f"📥 Загрузка: {url}")
            r = requests.get(url, headers=HEADERS, timeout=10)
            r.raise_for_status()
            txt = r.text.strip()
            if txt and "\n" not in txt and re.match(r'^[A-Za-z0-9+/=]+$', txt):
                txt = base64.b64decode(txt).decode("utf-8", errors="ignore")
            raw += "\n" + txt
        except Exception as e:
            log(f"⚠️ Ошибка загрузки {url}: {e}")

    seen = set()
    valid = []
    vless_re = re.compile(r"^vless://[^@]+@[^:]+:\d+\?")
    for line in raw.splitlines():
        line = line.strip()
        if not line or line in seen or not vless_re.match(line):
            continue
        seen.add(line)
        valid.append(line)
    return valid

def parse_vless(url):
    m = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?(.*)", url)
    if not m: return None
    uuid, host, port, params = m.groups()
    qs = parse_qs(params)
    return {
        "uuid": uuid, "host": host, "port": int(port),
        "security": qs.get("security", ["none"])[0],
        "type": qs.get("type", ["tcp"])[0],
        "path": qs.get("path", ["/"])[0],
        "sni": qs.get("sni", [host])[0],
        "header": qs.get("host", [host])[0]
    }

def check_tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT_TCP) as s:
            return True
    except:
        return False

def make_sb_config(p):
    cfg = {
        "log": {"level": "warning"},
        "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": 10808}],
        "outbounds": [{
            "type": "vless", "tag": "test",
            "server": p["host"], "server_port": p["port"], "uuid": p["uuid"],
            "transport": {
                "type": p["type"],
                "path": p["path"],
                "headers": {"Host": p["header"]}
            },
            "tls": {
                "enabled": p["security"] == "tls",
                "server_name": p["sni"],
                "utls": {"enabled": True, "fingerprint": "chrome"}
            } if p["security"] == "tls" else None
        }]
    }
    return cfg

def check_proxy(key):
    p = parse_vless(key)
    if not p: return False

    cfg_path = f"/data/data/com.termux/files/usr/tmp/sb_{os.getpid()}.json"
    with open(cfg_path, "w") as f:
        json.dump(make_sb_config(p), f)

    proc = subprocess.Popen(
        ["sing-box", "run", "-c", cfg_path],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)  # ждём инициализации прокси

    ok = False
    for test_url in TEST_URLS:
        try:
            r = requests.head(
                test_url,
                proxies={"http": "http://127.0.0.1:10808", "https": "http://127.0.0.1:10808"},
                timeout=TIMEOUT_PROXY,
                allow_redirects=True
            )
            if 200 <= r.status_code < 400:
                ok = True
                break
        except:
            continue

    proc.terminate()
    try:
        proc.wait(timeout=2)
    except:
        pass
    if os.path.exists(cfg_path):
        os.remove(cfg_path)

    return ok

def git_push(count):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    os.system("git add .")
    msg = f"Auto update: {count} working keys | {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    rc = os.system(f'git diff --staged --quiet || git commit -m "{msg}"')
    if rc == 0:
        log("ℹ️ Нет изменений или ошибка коммита")
        return
    log("⬆️ Push на GitHub...")
    os.system("git push -q origin main")

def main():
    log("🚀 === ЗАПУСК ПАРСЕРА ===")
    keys = fetch_keys()
    if not keys:
        log("❌ Список пуст. Проверь источники и интернет.")
        return

    log(f"📋 Найдено уникальных валидных ключей: {len(keys)}")
    working = []
    total = len(keys)

    for i, k in enumerate(keys, 1):
        p = parse_vless(k)
        if not p:
            log(f"❌ [{i}/{total}] Мусорный формат: {k[:30]}...")
            continue

        if WHITELIST_DOMAINS and p["host"] not in WHITELIST_DOMAINS:
            log(f"🚫 [{i}/{total}] Не в вайтлисте: {p['host']}")
            continue

        log(f"🔌 [{i}/{total}] TCP {p['host']}:{p['port']}...")
        if not check_tcp(p["host"], p["port"]):
            log(f"⛔ TCP down → пропускаем")
            continue

        log(f"🌐 [{i}/{total}] Proxy HEAD...")
        if check_proxy(k):
            working.append(k)
            log(f"✅ РАБОЧИЙ!")
        else:
            log(f"❌ Proxy failed")
        time.sleep(0.2) 

    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(working))

    log(f"🏁 Готово. Рабочих: {len(working)}/{total}")
    git_push(len(working))
    log("✅ Скрипт завершил работу.")

if __name__ == "__main__":
    main()
