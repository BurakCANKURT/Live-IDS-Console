# ============================================================================
#  10_run_mixed_client_campaign.ps1  --  KARMA ISTEMCI (WSL+Windows) kampanyasi
# ============================================================================
#  R49-v2 (2026-08-20) bulgusu: selfgen verisinin K1/genelleme sorunu TEK bir
#  ozellige indi -- Init_Win_bytes_forward=64240 TUM satirlarda sabitti,
#  cunku kampanyayi baslatan TEK istemci (WSL Ubuntu) TEK bir Linux kernel'i
#  paylasiyordu. Bu script 08_run_selfgen_campaign.ps1'in ayni WSL yarisini
#  KORUR, yanina GERCEKTEN farkli bir TCP-yigini (Windows Winsock, ampirik
#  olarak Init_Win=65535 dogrulandi -- bkz. bu oturumun notu) ekler:
#    1) Ayni 4 portu (mini_vuln_target.py :80/:3000, pyftpdlib :21/:2121) 8 AYRI
#       instance olarak SADECE 127.0.0.1 ve vEthernet(WSL) IP'sine baglar --
#       0.0.0.0 KULLANILMAZ (bkz. Adim 3 yorumu: bu makinede onceden var olan
#       bir python.exe/Public/Any-port firewall kurali, 0.0.0.0 ile birlesince
#       hedefleri Wi-Fi agina acik hale getiriyordu, ampirik olarak bulunup
#       kapatildi -- 08'deki 0.0.0.0 kullanimindan BILEREK farkli)
#    2) IKI ESZAMANLI tshark capture'i baslatir:
#       - vEthernet(WSL) arayuzu  -> WSL-kaynakli trafik (pcap_wsl)
#       - Loopback arayuzu        -> Windows-native-kaynakli trafik (pcap_win)
#       Interface izolasyonu SAYESINDE iki kaynak birbirine KARISMAZ (WSL
#       istemcisi asla Loopback'e, Windows istemcisi asla vEthernet(WSL)'e
#       dusmez).
#    3) WSL kampanyasini (07_selfgen_campaign_full.sh) TARGET_IP=vEthernet
#       IP'siyle calistirir -> phases_wsl.json
#    4) Windows-native kampanyasini (09_win_native_campaign.py) 127.0.0.1
#       ile calistirir -> phases_win.json
#    5) Iki capture'i + hedefleri durdurur
#    6) build_selfgen_dataset.py'yi IKI KEZ calistirir (her pcap/phases
#       cifti icin ayri batch_tag), SONRA Init_Win dagilimini OKUYUP
#       R49-v2 kabul kriterini (hicbir deger >%60 degil) DOGRULAR.
#
#  KULLANIM:
#    powershell -File "live_fire_test\10_run_mixed_client_campaign.ps1" -NCyclesWsl 15 -NCyclesWin 15
#
#  NOT (BOM/encoding): bu dosya BOM'suz UTF-8 olabilir -- WSL'e giden HICBIR
#  yol asla diyakritikli literal olarak yazilmaz, hep $PSScriptRoot + wslpath
#  ile dinamik cozulur (bkz. 08'deki ayni duzeltme, R49-v2 oncesi bulunan bug).
# ============================================================================
param(
    [int]$NCyclesWsl = 15,
    [int]$NCyclesWin = 15
)

$ErrorActionPreference = "Stop"
$RepoDir = $PSScriptRoot
$ScratchDir = "D:\tez_data\campaign_probes"
if (-not (Test-Path $ScratchDir)) { New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null }

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " KARMA ISTEMCI KAMPANYASI -- WSL:$NCyclesWsl dongu, Windows:$NCyclesWin dongu" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# --- 1) WSL NAT modu kontrolu ------------------------------------------------
$wslConfig = Get-Content "$env:USERPROFILE\.wslconfig" -Raw -ErrorAction SilentlyContinue
if ($wslConfig -notmatch "networkingMode=nat") {
    Write-Host "[HATA] .wslconfig'de networkingMode=nat degil!" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] WSL NAT modunda." -ForegroundColor Green

# --- 2) vEthernet(WSL) IP + tshark arayuz numaralari (DINAMIK) --------------
$wslAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Hyper-V Virtual Ethernet*" -and $_.Name -like "*WSL*" }
if (-not $wslAdapter) {
    Write-Host "[HATA] vEthernet(WSL) arayuzu bulunamadi." -ForegroundColor Red
    exit 1
}
$targetIp = (Get-NetIPAddress -InterfaceIndex $wslAdapter.ifIndex -AddressFamily IPv4).IPAddress
$adapterGuid = $wslAdapter.InterfaceGuid.Trim('{', '}')
Write-Host "[OK] vEthernet(WSL) IP: $targetIp" -ForegroundColor Green

$tsharkList = & "C:\Program Files\Wireshark\tshark.exe" -D
$wslLine = $tsharkList | Where-Object { $_ -match [regex]::Escape($adapterGuid) }
if (-not $wslLine) {
    Write-Host "[HATA] tshark vEthernet(WSL)'i gormuyor." -ForegroundColor Red
    exit 1
}
$tsharkIfNumWsl = ($wslLine -split '\.')[0].Trim()
$loopLine = $tsharkList | Where-Object { $_ -match 'NPF_Loopback' }
if (-not $loopLine) {
    Write-Host "[HATA] tshark Loopback'i gormuyor." -ForegroundColor Red
    exit 1
}
$tsharkIfNumWin = ($loopLine -split '\.')[0].Trim()
Write-Host "[OK] tshark arayuz no -- WSL:$tsharkIfNumWsl  Loopback(Win):$tsharkIfNumWin" -ForegroundColor Green

# --- 3) 8 hedef baslat (4 port x 2 SPESIFIK IP -- 0.0.0.0 KULLANILMAZ) --------
# GUVENLIK DUZELTMESI (bu oturum): 0.0.0.0 baglama, bu makinede onceden var
# olan "python.exe / Profile=Public / RemoteAddress=Any / LocalPort=Any"
# firewall ALLOW kuraliyla birlesince, hedefleri AYNI Wi-Fi agindaki HERHANGI
# bir cihaza acik hale getiriyordu (ampirik olarak dogrulandi, kapatildi).
# Duzeltme: LAN/Wi-Fi arayuzune HIC dokunmadan, her hedefi SADECE ihtiyaci olan
# spesifik IP'ye baglariz -- Windows-native istemci icin 127.0.0.1, WSL istemcisi
# icin vEthernet(WSL) IP'si ($targetIp). Firewall kuralina bagimli DEGILDIR.
Write-Host "[*] Hedefler baslatiliyor (8 instance, 0.0.0.0 KULLANILMIYOR)..." -ForegroundColor Yellow
$mvt = Join-Path $RepoDir "mini_vuln_target.py"
$targetProcs = @()
foreach ($bindIp in @("127.0.0.1", $targetIp)) {
    foreach ($webPort in @(80, 3000)) {
        $tag = "mvt_${webPort}_$($bindIp -replace '\.','_')"
        $targetProcs += Start-Process -FilePath "python" -ArgumentList "`"$mvt`"", "$webPort", "$bindIp" `
            -RedirectStandardOutput (Join-Path $ScratchDir "run_$tag.log") -RedirectStandardError (Join-Path $ScratchDir "run_${tag}err.log") -WindowStyle Hidden -PassThru
    }
}

$ftpPassiveRanges = @{ 21 = "60200-60250"; 2121 = "60260-60300" }
foreach ($bindIp in @("127.0.0.1", $targetIp)) {
    foreach ($ftpPort in @(21, 2121)) {
        $tag = "ftp_${ftpPort}_$($bindIp -replace '\.','_')"
        $ftpRoot = Join-Path $ScratchDir "ftp_root_$tag"
        New-Item -ItemType Directory -Path $ftpRoot -Force | Out-Null
        $targetProcs += Start-Process -FilePath "python" -ArgumentList "-m", "pyftpdlib", "-i", "$bindIp", "-p", "$ftpPort", "-u", "testuser", "-P", "esp32test", "-w", "-d", "`"$ftpRoot`"", "-r", $ftpPassiveRanges[$ftpPort] `
            -RedirectStandardOutput (Join-Path $ScratchDir "run_$tag.log") -RedirectStandardError (Join-Path $ScratchDir "run_${tag}err.log") -WindowStyle Hidden -PassThru
    }
}

Start-Sleep -Seconds 2
$listening = Get-NetTCPConnection -LocalPort 80, 3000, 21, 2121 -State Listen -ErrorAction SilentlyContinue
$badBind = $listening | Where-Object { $_.LocalAddress -notin @("127.0.0.1", $targetIp) }
if ($badBind) {
    Write-Host "[HATA] beklenmeyen bind adresi tespit edildi (0.0.0.0 dahil olabilir), TUM hedefler durduruluyor:" -ForegroundColor Red
    $badBind | Format-Table -AutoSize
    foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}
if (($listening | Measure-Object).Count -lt 8) {
    Write-Host "[HATA] 8 hedeften biri ayakta degil: $ScratchDir\run_*err.log" -ForegroundColor Red
    foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}
Write-Host "[OK] 8 hedef ayakta, SADECE 127.0.0.1 ve $targetIp uzerinde (0.0.0.0 YOK, dogrulandi)." -ForegroundColor Green

# --- 4) Iki eszamanli capture baslat -----------------------------------------
$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$pcapWsl = Join-Path $RepoDir "mixed_campaign_wsl_$ts.pcap"
$pcapWin = Join-Path $RepoDir "mixed_campaign_win_$ts.pcap"
$captureFilter = "tcp port 80 or tcp port 3000 or tcp port 21 or tcp port 2121"
Write-Host "[*] Capture'lar basliyor..." -ForegroundColor Yellow
$tsharkWsl = Start-Process -FilePath "C:\Program Files\Wireshark\tshark.exe" `
    -ArgumentList "-i", $tsharkIfNumWsl, "-f", "`"$captureFilter`"", "-w", "`"$pcapWsl`"" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_tshark_wsl.log") -RedirectStandardError (Join-Path $ScratchDir "run_tshark_wslerr.log") -WindowStyle Hidden -PassThru
$tsharkWin = Start-Process -FilePath "C:\Program Files\Wireshark\tshark.exe" `
    -ArgumentList "-i", $tsharkIfNumWin, "-f", "`"$captureFilter`"", "-w", "`"$pcapWin`"" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_tshark_win.log") -RedirectStandardError (Join-Path $ScratchDir "run_tshark_winerr.log") -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
Write-Host "[OK] tshark PID'leri -- WSL:$($tsharkWsl.Id)  Win:$($tsharkWin.Id)" -ForegroundColor Green

# --- 5) WSL yarisi (senkron) ---------------------------------------------------
$phasesWsl = Join-Path $RepoDir "phases_mixed_wsl_$ts.json"
Write-Host "[*] WSL yarisi calisiyor ($NCyclesWsl dongu, TARGET_IP=$targetIp)..." -ForegroundColor Yellow
$scriptWinPath = Join-Path $RepoDir "07_selfgen_campaign_full.sh"
$scriptRelPath = (& wsl.exe -d Ubuntu wslpath -a "$scriptWinPath").Trim()
if (-not $scriptRelPath -or -not ($scriptRelPath -match '^/mnt/')) {
    Write-Host "[HATA] wslpath cevirisi basarisiz: '$scriptRelPath'" -ForegroundColor Red
    exit 1
}
& wsl.exe -d Ubuntu -e bash -c "TARGET_IP=$targetIp bash '$scriptRelPath' $NCyclesWsl"
# 07 script'i PHASES_JSON'u kendi icinde REPO_WIN/phases_full.json'a sabit yazar --
# bu turda cakismasin diye calistiktan hemen sonra tasiyoruz.
$defaultPhasesOut = Join-Path $RepoDir "phases_full.json"
if (Test-Path $defaultPhasesOut) {
    Move-Item -Path $defaultPhasesOut -Destination $phasesWsl -Force
}
Write-Host "[OK] WSL yarisi bitti." -ForegroundColor Green

# --- 6) Windows-native yarisi (senkron) ---------------------------------------
$phasesWin = Join-Path $RepoDir "phases_mixed_win_$ts.json"
Write-Host "[*] Windows-native yarisi calisiyor ($NCyclesWin dongu, TARGET_IP=127.0.0.1)..." -ForegroundColor Yellow
$winScript = Join-Path $RepoDir "09_win_native_campaign.py"
python "$winScript" "127.0.0.1" "$NCyclesWin" "$phasesWin"
Write-Host "[OK] Windows-native yarisi bitti." -ForegroundColor Green

# --- 7) Capture + hedefleri durdur -------------------------------------------
Write-Host "[*] Temizlik: capture'lar + hedefler durduruluyor..." -ForegroundColor Yellow
Stop-Process -Id $tsharkWsl.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $tsharkWin.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
$stillUp = Get-NetTCPConnection -LocalPort 80, 3000, 21, 2121 -State Listen -ErrorAction SilentlyContinue
if ($stillUp) { Write-Host "[UYARI] hala dinleyen port var: $($stillUp.LocalPort -join ',')" -ForegroundColor Red }
else { Write-Host "[OK] tum hedefler/capture'lar kapatildi, port 80/3000/21/2121 bos." -ForegroundColor Green }

# --- 8) Ingestion: iki (pcap, phases) cifti ayri ayri --------------------------
$mcDir = Join-Path (Split-Path $RepoDir -Parent) "multiclass_training"
Write-Host "[*] build_selfgen_dataset.py -- WSL yarisi ingestion..." -ForegroundColor Yellow
python "$mcDir\build_selfgen_dataset.py" "$pcapWsl" "$phasesWsl" "selfgen_mixed_wsl_$ts"
Write-Host "[*] build_selfgen_dataset.py -- Windows yarisi ingestion..." -ForegroundColor Yellow
python "$mcDir\build_selfgen_dataset.py" "$pcapWin" "$phasesWin" "selfgen_mixed_win_$ts"

# --- 9) Init_Win dagilim kontrolu (R49-v2 kabul kriteri) -----------------------
# NOT: kontrol kasten burada DEGIL, orkestrasyondan SONRA ayri bir adimda
# yapilir -- PowerShell icine gomulu cok satirli Python string'i, bu oturumda
# bulunan BOM/kod-sayfasi bug'iyla AYNI kategoride kirilgan bir riskdi.

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " TAMAMLANDI. CSV: $mcDir\data\selfgen_dataset.csv" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
