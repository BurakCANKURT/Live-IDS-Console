# 03 — ESP32 Live-Fire Orchestration Guide

The attacker device is now an **ESP32, not a Raspberry Pi**. An ESP32 is not a
Linux machine: `nmap`/`hydra`/`hping3`/`slowhttptest` do **not** run on it. Instead
each CICIDS scenario is written as a separate Arduino sketch (`.ino`). This guide
explains **in which order** the sketches are uploaded and run, and what to look at
in Mongo at each step.

> These tools generate attack-style traffic against **your own** lab machine, on a
> network you control. Use them against nothing you do not own and operate.

---

## 0. Once: Arduino IDE setup (if you are not experienced)

1. Install the **Arduino IDE** (2.x). In `File > Preferences > Additional Boards
   Manager URLs` add this line:
   `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
2. `Tools > Board > Boards Manager` → search "esp32" → install the **esp32 by
   Espressif** package.
3. `Tools > Board` → select **ESP32 Dev Module** (or your board's exact model:
   ESP32-WROOM, DevKitC, etc.). Connect it over USB, `Tools > Port` → select the
   board's COM port. (If Windows asks for a driver, install the CP210x / CH340
   driver.)
4. **No extra library is needed** — all five sketches (`esp32_portscan`,
   `esp32_connflood`, `esp32_slowloris`, `esp32_ftp_patator`, `esp32_webattack`)
   use only `WiFi.h` (ships with the ESP32 core).

### What to edit in each sketch
Wi-Fi and target values live in a local `secrets.h` (copy `secrets.example.h` into
the same folder as the sketch). Set only these:
- `SECRET_WIFI_SSID` / `SECRET_WIFI_PASS` → the Wi-Fi the ESP32 connects to (the
  **same LAN** as the Windows PC).
- `SECRET_TARGET_IP` → the LAN IP of the Windows IDS machine (`01_windows_setup.ps1`
  prints it). Format: `#define SECRET_TARGET_IP 192, 168, 1, 100`.
- Scenario-specific: `END_PORT`, `MODE_FAST`, `USERNAME`, etc. (per step below), in
  the `EDITABLE VARIABLES` block at the top of each `.ino`.

### Upload + monitor
- Write to the board with the right arrow (**Upload**). When the upload finishes,
  open `Tools > Serial Monitor` and set the baud to **115200**. The sketch runs the
  scenario **ONCE** in `setup()`, finishes and stops. **To run it again, press the
  board's RESET (EN) button** or Upload again.

---

## 1. Prepare the Windows side (target)

In an Administrator PowerShell:
```powershell
# For port/conn-flood/slowloris (HTTP 8080 + SSH reference):
.\01_windows_setup.ps1

# If you will also do FTP-Patator (needs pyftpdlib):
pip install pyftpdlib
.\01_windows_setup.ps1 -EnableFtp

# For WebAttack (esp32_webattack.ino) + the port-diversity campaign (needs Docker):
#   Vulnerable web app (DVWA:80 + Juice Shop:3000) + a 2nd SSH port (2222) + a 2nd FTP port (2121)
.\05_windows_webtarget_setup.ps1 -EnableWebApp -EnableSsh2222 -EnableFtp2121
```
> `esp32_webattack.ino` targets a real vulnerable web app, NOT a static
> `http.server` (a static server cannot respond to SQLi without a backend/DB). So if
> you do WebAttack, `05_windows_webtarget_setup.ps1` is REQUIRED. For DVWA the
> one-time DB setup step (setup.php > Create/Reset Database) is reminded on screen by
> that script.
Note the **LAN IP** from the output → all sketches set `SECRET_TARGET_IP` to it.
Then start the **IDS** (native dashboard / `process_pcap*.py`) as usual.

> **Important (for F1):** closed ports returning **RST/REJECT** speeds up the scan.
> The Windows Firewall default is **DROP**; this slows the ESP32 connect scan but
> **does not block is_scan** (the SYN packet still reaches the NIC, tshark captures
> it, distinct_ports counts it). Only the narrow-band version takes longer.

---

## 2. Run the scenarios in order

At each step: **upload the sketch → see it finish in the Serial Monitor → wait ~15 s
→ on Windows run `04_mongo_analysis.py --last N --attacker-ip <ESP32_IP>`**. The
ESP32 prints its IP in the first lines of the Serial Monitor (and `--attacker-ip`
needs it). Wait a little between steps to separate the windows.

| Order | Sketch | CICIDS class | Config note | Expected (Mongo) |
|---|---|---|---|---|
| A | `esp32_portscan.ino` | PortScan (baseline) | `END_PORT = 1000` | is_scan, `predicted_class=PortScan`, is_volumetric=True, `suppressed_by` EMPTY |
| B | `esp32_portscan.ino` | PortScan (**F1 narrow-band**) | `END_PORT = 100` | 40-149 port band; if `suppressed_by="scan_rf_benign"` + status!=ATTACK then an **F1 finding** (the FP-fix ate a real scan) |
| C | `esp32_connflood.ino` | DoS/DDoS | `TOTAL_CONNECT = 400` | is_flood or is_conn_flood, is_volumetric=True, status=ATTACK |
| D | `esp32_slowloris.ino` | DoS-slow (Slowloris) | `NUM_SOCKETS = 8` | non-volumetric/LSTM branch; inspect per-flow `suppressed_by`/`status`/`ood_distance` (**F4**, the low-volume caveat applies) |
| E | `esp32_ftp_patator.ino` | FTP-Patator (fast) | `MODE_FAST = true` | is_conn_flood/is_flood, is_volumetric=True, status=ATTACK |
| F | `esp32_ftp_patator.ino` | FTP-Patator (**F2 slow**) | `MODE_FAST = false` | non-volumetric; if `suppressed_by={committee_dissent\|ood\|immature_flow}` + status!=ATTACK then an **F2 finding** (a real brute force was suppressed) |
| G | `esp32_webattack.ino` | WebAttack (SQLi/XSS/LFI/CMDi) | `TARGET_PORT = 80` (DVWA / http bucket) | `predicted_class=WebAttack` is **variable** (model-dependent + a memorized class); inspect per-flow `suppressed_by`/`ood_distance`/`status`. Target: 05_windows_webtarget_setup.ps1 |
| H | `esp32_webattack.ino` | WebAttack (**ephemeral bucket**) | `TARGET_PORT = 3000` (Juice Shop) | same attack in the ephemeral bucket; compare with G → is the model tied to the port bucket? (the real goal is collecting diversity) |

> **F1 (B) and F2 (F)** are the highest-information steps — they measure whether the
> FP-suppressing mechanisms eat a real attack. The baseline variants (A, C, E)
> already give safe/known results.

To run the same sketch with two different configs: change the value → Upload again
(re-uploading is cleanest; RESET re-runs the old code).

---

## 2b. Multi-day / multi-tool DIVERSITY orchestration (for retraining)

> **Why:** the model has MEMORIZED CICIDS-2017's single-day + single-tool trace on
> the WebAttack / FTP-Patator / SSH-Patator classes (86-99% of test rows are within
> <0.1 distance of a training row — see the all-class single-session diversity
> audit). **Running a single tool on a single day produces new memorization.** So
> retraining data must be MULTI-TOOL + MULTI-DAY + MULTI-SOURCE-IP + MULTI-PORT. The
> plan below ensures this.

**Sources (producing the same class with a different signature):**
- **ESP32** = a hand-written embedded client (its own TCP stack / User-Agent /
  timing).
- **Pi / Linux host** = `05_pi_webattack_patator_scenarios.sh` (sqlmap, nikto,
  hydra-ftp, medusa, ncrack).
- **Port-bucket diversity** = collect the same attack on BOTH a standard AND an
  ephemeral port (Web 80/3000, FTP 21/2121, SSH 22/2222) → the model cannot
  over-attach to the port.

**Suggested schedule (>=3 different days; a different combination each day, do NOT
repeat a fixed one):**

| Day | WebAttack | FTP-Patator | SSH-Patator | Note |
|---|---|---|---|---|
| 1 | ESP32 `esp32_webattack` @80 | ESP32 `esp32_ftp_patator` FAST/SLOW @21 | (host) medusa @22 | embedded-client-heavy day |
| 2 | (host) sqlmap+nikto @80 & @3000 | (host) hydra-ftp @21 & @2121 | (host) hydra @22 + medusa @2222 | automated-tool-heavy day |
| 3 | ESP32 `esp32_webattack` @3000 | ESP32 @21 + (host) hydra-ftp @2121 | (host) ncrack @22 + medusa @2222 | ephemeral-bucket + third-tool day |

> Between days, CHANGE the wordlist / payload order / the `REQ_DELAY_MS`-`BRUTE_THREADS`
> speed (random/variable speed) — a fixed speed is memorized too. Each session,
> inspect that source's traffic separately with
> `04_mongo_analysis.py --attacker-ip <that source's IP>`; store the collected
> pcap/records tagged with day+tool+source (they become a new batch/family label in
> retraining). **Retrain/CSV/model are OUT OF SCOPE of this guide** — this stage only
> collects diverse raw traffic.

---

## 3. After the test + cleanup

```powershell
# Summarize the whole window (by the ESP32's IP):
python 04_mongo_analysis.py --start "2026-08-09 21:00:00" --end "2026-08-09 22:30:00" --attacker-ip <ESP32_IP>

# Undo the temporary changes (FTP server + firewall rules):
.\02_windows_cleanup.ps1

# If you did a WebAttack campaign (Docker/portproxy/2nd FTP), run this FIRST:
.\06_windows_webtarget_cleanup.ps1
```
`04_mongo_analysis.py` highlights the distinction between **BENIGN-miss**
(status=BENIGN, a silent miss = critical) and **UNKNOWN-gap** (still an alert). If
BENIGN-miss > 0, a new investigation round should be opened.

---

## 4. Realism summary with the ESP32 (what it can and cannot test)

| CICIDS class | With ESP32? | Explanation |
|---|---|---|
| **PortScan** | YES | `connect()` scan (nmap `-sT`-like). Not a raw SYN scan (`-sS`), but since the IDS's is_scan counter counts the first-SYN packets it is **triggered the same way**. Both baseline and F1 narrow-band are done. |
| **DoS/DDoS** | PARTLY (equivalent) | A raw SYN flood is impractical on the ESP32 (needs LWIP_RAW). Instead a **sequential connect+close flood**: it crosses the is_flood(150)/is_conn_flood(200) thresholds the same way and lands on the volumetric branch. Effect-equivalent, not signature-identical. |
| **DoS-slow (Slowloris)** | PARTLY (weak) | The Pi's `-c1000`/`-c150` level is **impossible** on the ESP32 (~10-16 socket limit). It opens ~8 concurrent slow connections → tests the behavioral/LSTM branch (F4) at **low volume**. No alert may mean "suppressed" or just "insufficient volume". |
| **FTP-Patator** | YES | Plaintext FTP (USER/PASS) is simple on the ESP32. It is already a separate class in CICIDS. FAST (volumetric) + SLOW (F2 behavioral) modes. |
| **SSH-Patator** | NO | A real SSH handshake/encryption is impractical on the ESP32. **FTP-Patator is used instead** (same "brute-force login" behavior class, plaintext). On the host side, medusa/ncrack (see the 05_pi script) collect SSH-Patator. |
| **WebAttack (XSS/SQLi)** | YES (`esp32_webattack.ino`) | Needs a vulnerable web app on the target (`05_windows_webtarget_setup.ps1` → DVWA:80 + Juice Shop:3000). The ESP32 sends SQLi/XSS/LFI/CMDi payloads over raw HTTP (GET+POST+header-injection). The goal is not EXPLOITATION but collecting diverse WebAttack TRAFFIC (features are network-level). |
