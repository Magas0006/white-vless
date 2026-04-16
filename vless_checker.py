import os, json, subprocess, requests, re, time
from urllib.parse import parse_qs
from datetime import datetime

RAW_URL = "https://loginvkcom.vercel.app/sub"
TEST_URL = "https://httpbin.org/status/200"
TIMEOUT = 5
RESULT_FILE = "working_keys.txt"

def get_keys():
    try:
        r = requests.get(RAW_URL, timeout=10)
        return [l.strip() for l in r.text.splitlines() if l.startswith("vless://")]
    except Exception as e:
        print(f"[!] Ошибка скачивания: {e}")
        return []

def parse_vless(url):
    match = re.match(r"vless://([^@]+)@([^:]+):(\d+)\?(.*)", url)
    if not match: return None
    uuid, host, port, params = match.groups()
    qs = parse_qs(params)
    return {
        "uuid": uuid, "host": host, "port": int(port),
        "security": qs.get("security", ["none"])[0],
        "type": qs.get("type", ["tcp"])[0],
        "path": qs.get("path", ["/"])[0],
        "sni": qs.get("sni", [host])[0],
        "header": qs.get("host", [host])[0]
    }

def make_config(p):
    cfg = {
        "log": {"level": "none"},
        "inbounds": [{"type": "http", "listen": "127.0.0.1", "listen_port": 10808}],
        "outbounds": [{
            "type": "vless", "tag": "test",
            "server": p["host"], "server_port": p["port"], "uuid": p["uuid"],
            "transport": {"type": p["type"], "path": p["path"], "headers": {"Host": p["header"]}},
            "tls": {"enabled": True, "server_name": p["sni"]} if p["security"] == "tls" else None
        }]
    }
    return cfg

def test_key(url):
    p = parse_vless(url)
    if not p: return False
    cfg_path = "/data/data/com.termux/files/usr/tmp/sb_test.json"
    with open(cfg_path, "w") as f: json.dump(make_config(p), f)
    proc = subprocess.Popen(["sing-box", "run", "-c", cfg_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    ok = False
    try:
        r = requests.head(TEST_URL, proxies={"http": "http://127.0.0.1:10808", "https": "http://127.0.0.1:10808"}, timeout=TIMEOUT)
        if r.status_code == 200: ok = True
    except: pass
    finally:
        proc.terminate()
        try: proc.wait(timeout=2)
        except: pass
        if os.path.exists(cfg_path): os.remove(cfg_path)
    return ok

def main():
    print("[*] Загрузка списка...")
    keys = get_keys()
    if not keys: print("[!] Список пуст"); return
    working = []
    for i, k in enumerate(keys, 1):
        print(f"[*] [{i}/{len(keys)}] Проверка: {k[:40]}...")
        if test_key(k):
            working.append(k)
            print("[+] Рабочий!")
        time.sleep(0.5)
    with open(RESULT_FILE, "w") as f: f.write("\n".join(working))
    print(f"[✓] Найдено рабочих: {len(working)}")
    os.system("git add .")
    msg = datetime.now().strftime("%Y-%m-%d %H:%M")
    os.system(f'git commit -m "Auto update {msg}" || true')
    os.system("git push -q origin main")
    print("[✓] Отправлено на GitHub")

if __name__ == "__main__":
    main()
