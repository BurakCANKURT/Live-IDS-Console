# Running the IDS Live-Fire Test System

This document walks through running the IDS (native dashboard) and the ESP32
attacker device end to end, step by step, from scratch (even if the Arduino IDE
has never been installed). For the scenario design/rationale see
`03_esp32_run_guide.md` — this document only collects the **run order** and the
**practical steps**.

> **SAFETY NOTE:** these tools generate attack-style traffic against **your own**
> lab machine, on a network you control. The Wi-Fi credentials go in a local
> `secrets.h` (copy `secrets.example.h` in each sketch folder). `secrets.h` is
> git-ignored and must never be committed — a real password in plain text must not
> go to the repo/GitHub. Point these tools at nothing you do not own and operate.

---

## 0) Prerequisites (once)

1. **MongoDB (optional)** — only needed for the detailed offline analysis in
   `04_mongo_analysis.py`. The live dashboard does not require it. If you want it,
   install it as a Windows service (`winget install MongoDB.Server`); the service
   starts automatically on boot. Check:
   ```powershell
   Get-Service -Name MongoDB | Select-Object Status,StartType
   ```
2. **Python dependencies** — `pymongo`, and (for the FTP-Patator scenario)
   `pyftpdlib`:
   ```powershell
   pip install pymongo pyftpdlib
   ```
3. **Arduino IDE** (2.x) with ESP32 board support:
   - `File > Preferences > Additional Boards Manager URLs`:
     `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`
   - `Tools > Board > Boards Manager` → search "esp32" → install the **esp32 by
     Espressif Systems** package.
   - No extra library is needed (the sketches use only `WiFi.h`, which ships with
     the ESP32 core).
4. **ESP32 board** connected over USB; on first connection a CP210x or CH340 driver
   may be requested (depending on the board's USB chip).

---

## 1) Start the IDS (Windows PC — target machine)

```powershell
cd C:\path\to\live-ids-console\console
.\build\ids_dashboard.exe
```

When the window opens:
- Top-left should show **PIPELINE ONLINE** (green dot).
- **Capture/Multiclass: UP** states should appear within a few seconds (the model
  loading window can take ~60 s; seeing "UP (n/a)" during that time is normal).

---

## 2) Prepare the Windows target services

In an **Administrator** PowerShell (right-click → "Run as administrator"):

```powershell
cd C:\path\to\live-ids-console\live_fire_test

# Baseline (for the PortScan/DDoS/Slowloris scenarios — HTTP 8080 target):
.\01_windows_setup.ps1

# If you will also do the FTP-Patator scenario:
.\01_windows_setup.ps1 -EnableFtp
```

Note your **LAN IP** from the output (e.g. `192.168.1.104`) — this is used as
`TARGET_IP` (via `secrets.h`) in all ESP32 sketches. This step only allows
connections from the local subnet (LocalSubnet) through the firewall; it exposes
nothing to the internet.

> If the test FTP server started with `-EnableFtp` fails due to a stale PID file
> from a previous session, you can start it by hand:
> ```powershell
> cd C:\path\to\live-ids-console\live_fire_test
> python -m pyftpdlib -p 21 -u testuser -P esp32test -d ftp_root -r 60000-60100
> ```
> (Note: the correct flag is `-r X-Y`, NOT `--passive-ports=X-Y` — pyftpdlib's CLI
> does not recognize the old one.)

---

## 3) Configure and upload the ESP32 in the Arduino IDE

Each scenario has its own `.ino` file (under `live_fire_test/esp32/`, each in a
folder of the same name — the Arduino IDE's rule):

| File | Scenario |
|---|---|
| `esp32_portscan/esp32_portscan.ino` | PortScan (baseline + F1 narrow-band) |
| `esp32_connflood/esp32_connflood.ino` | DoS/DDoS (connection flood) |
| `esp32_slowloris/esp32_slowloris.ino` | DoS-slow (Slowloris-like) |
| `esp32_ftp_patator/esp32_ftp_patator.ino` | FTP-Patator (slow/fast) |

Set your Wi-Fi and target values once in `secrets.h` (copy `secrets.example.h`
into the same folder as the sketch):

```cpp
#define SECRET_WIFI_SSID "your-lab-ssid"     // your own Wi-Fi network
#define SECRET_WIFI_PASS "your-lab-password" // your own Wi-Fi password
#define SECRET_TARGET_IP 192, 168, 1, 104    // the LAN IP from step 2
```

Scenario-specific editable variables (`END_PORT`, `MODE_FAST`, `USERNAME`, etc.)
are in the `EDITABLE VARIABLES` block at the top of each `.ino`.

Upload steps:
1. In the Arduino IDE, `File → Open` the relevant `.ino` file.
2. Make sure `Tools → Board → ESP32 Arduino → ESP32 Dev Module` (or your board's
   exact model) is selected.
3. `Tools → Port` → select the COM port the ESP32 is on.
4. Press the **Upload** (→) button at the top-left.
5. If the upload stalls at "Connecting.....", hold the board's **BOOT** button
   (until the connection is made), then release.
6. When the upload finishes, open `Tools → Serial Monitor` and set the baud rate to
   **115200**.

The sketch runs the scenario **once** in `setup()` and stops. To run it again,
press the board's **RESET/EN** button (no re-upload needed).

---

## 4) Run the scenarios in order

At each step: upload/reset the sketch → watch it finish in the Serial Monitor →
wait ~15 s → observe the result in the IDS panel.

| Order | Sketch | Config note |
|---|---|---|
| A | portscan | `END_PORT = 1000` (baseline) |
| B | portscan | `END_PORT = 100` (F1 narrow-band) |
| C | connflood | `TOTAL_CONNECT = 400` (default) |
| D | slowloris | `NUM_SOCKETS = 8`, `HOLD_SECONDS = 120` (takes about 2 min) |
| E-slow | ftp_patator | `MODE_FAST = false` (default, the important variant) |
| E-fast | ftp_patator | `MODE_FAST = true` |

For detailed scenario rationale (what the F1/F2/F3/F4 blind-spot tests measure) see
`03_esp32_run_guide.md`.

---

## 5) Verify the results

**On the dashboard (live):** the `TOTAL TRAFFIC`/`DETECTED ATTACKS` counters at the
top, the `RECENT ALERTS` table, the `TOP ATTACKER IPs` chart.

**In Mongo (detailed, by the IP the ESP32 prints in its Serial Monitor):**
```powershell
cd C:\path\to\live-ids-console\live_fire_test
python 04_mongo_analysis.py --last 200 --attacker-ip <ESP32_IP>
```
This looks at the `status`/`suppressed_by`/`ood_distance` fields to tell apart
whether a real attack was wrongly dropped to BENIGN (critical) or fell to UNKNOWN
(still an alert, an attribution gap).

---

## 6) Cleanup

```powershell
# In an Administrator PowerShell:
cd C:\path\to\live-ids-console\live_fire_test
.\02_windows_cleanup.ps1
```

This stops the test HTTP/FTP servers and removes the temporary firewall rules. If
you started the FTP server by hand as in step 2, the script may not find it — in
that case stop it by hand:
```powershell
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -like '*pyftpdlib*' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
```

Finally, close the dashboard window (or `Stop-Process -Name "ids_dashboard"`).
