# ============================================================================
#  08_run_selfgen_campaign.ps1  --  TEK KOMUTLA self-gen kampanyasini calistir
# ============================================================================
#  R49 duzeltmesi SONRASI hazirlanan, uctan-uca otomatik kampanya:
#    1) WSL2'nin NAT modunda oldugunu dogrular (mirrored'da Bwd paketler HIC
#       yakalanmiyordu -- bkz. .claude/agent-memory/cybersecurity-pipeline-
#       strategist/project_r49_selfgen_and_a3_retrain_verdict.md)
#    2) vEthernet(WSL) arayuzunun host-tarafi IP'sini ve tshark arayuz
#       numarasini DINAMIK olarak bulur (Hyper-V her WSL yeniden baslatmasinda
#       farkli IP/numara verebilir -- hardcode YOK)
#    3) 4 hedefi (mini_vuln_target.py :80/:3000, pyftpdlib :21/:2121) 0.0.0.0'a
#       baglar (SADECE WSL'in vEthernet'inden erisilir -- Windows Firewall
#       LAN/Wi-Fi tarafinda hicbir ALLOW kurali YOK, DefaultInboundAction
#       NotConfigured=varsayilan BLOK gecerli, dogrulandi)
#    4) tshark'i vEthernet(WSL) arayuzunde capture'a baslatir
#    5) WSL icinde 07_selfgen_campaign_full.sh'yi N_CYCLES ile calistirir
#       (TARGET_IP ortam degiskeniyle dogru IP'yi bilir)
#    6) Capture'i durdurur, TUM hedef process'lerini kapatir (temiz cikis)
#    7) multiclass_training/build_selfgen_dataset.py'yi OTOMATIK calistirip
#       sonucu ekrana basar
#
#  KULLANIM (yarin, tek satir):
#    powershell -File "live_fire_test\08_run_selfgen_campaign.ps1" -NCycles 30
#
#  ON-KOSUL: python (PATH'te), WSL2 Ubuntu distro'su (sqlmap/nikto/hydra/
#  medusa/curl/python3 kurulu -- bu oturumda zaten dogrulandi), tshark.
# ============================================================================
param(
    [int]$NCycles = 30
)

$ErrorActionPreference = "Stop"
$RepoDir = $PSScriptRoot
$ScratchDir = "D:\tez_data\campaign_probes"
if (-not (Test-Path $ScratchDir)) { New-Item -ItemType Directory -Path $ScratchDir -Force | Out-Null }

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " SELF-GEN KAMPANYASI -- $NCycles dongu" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# --- 1) WSL NAT modu kontrolu ------------------------------------------------
$wslConfig = Get-Content "$env:USERPROFILE\.wslconfig" -Raw -ErrorAction SilentlyContinue
if ($wslConfig -notmatch "networkingMode=nat") {
    Write-Host "[HATA] .wslconfig'de networkingMode=nat degil! Mirrored modda Bwd paketler" -ForegroundColor Red
    Write-Host "       yakalanamiyor (R49 bulgusu). Once .wslconfig'i duzelt, 'wsl --shutdown' yap." -ForegroundColor Red
    exit 1
}
Write-Host "[OK] WSL NAT modunda." -ForegroundColor Green

# --- 2) vEthernet(WSL) IP + tshark arayuz numarasi (DINAMIK) ----------------
$wslAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Hyper-V Virtual Ethernet*" -and $_.Name -like "*WSL*" }
if (-not $wslAdapter) {
    Write-Host "[HATA] vEthernet(WSL) arayuzu bulunamadi. WSL calisiyor mu? ('wsl -d Ubuntu -e echo ok')" -ForegroundColor Red
    exit 1
}
$targetIp = (Get-NetIPAddress -InterfaceIndex $wslAdapter.ifIndex -AddressFamily IPv4).IPAddress
$adapterGuid = $wslAdapter.InterfaceGuid.Trim('{', '}')
Write-Host "[OK] vEthernet(WSL) IP: $targetIp  (GUID: $adapterGuid)" -ForegroundColor Green

$tsharkList = & "C:\Program Files\Wireshark\tshark.exe" -D
$wslLine = $tsharkList | Where-Object { $_ -match [regex]::Escape($adapterGuid) }
if (-not $wslLine) {
    Write-Host "[HATA] tshark bu arayuzu gormuyor (Npcap WSL adaptorune henuz baglanmamis olabilir)." -ForegroundColor Red
    Write-Host "       'C:\Program Files\Wireshark\tshark.exe' -D  cikisini kontrol et." -ForegroundColor Red
    exit 1
}
$tsharkIfNum = ($wslLine -split '\.')[0].Trim()
Write-Host "[OK] tshark arayuz no: $tsharkIfNum" -ForegroundColor Green

# --- 3) 4 hedefi baslat (SADECE vEthernet(WSL) IP'sine -- 0.0.0.0 KULLANILMAZ) --
# GUVENLIK DUZELTMESI (2026-08-20, 10_run_mixed_client_campaign.ps1 ile birlikte):
# 0.0.0.0 baglama, bu makinede onceden var olan "python.exe / Profile=Public /
# RemoteAddress=Any / LocalPort=Any" firewall ALLOW kuraliyla birlesince,
# hedefleri AYNI Wi-Fi agindaki HERHANGI bir cihaza acik hale getiriyordu
# (ampirik olarak dogrulandi). Eskiden buradaki yorum "sadece vEthernet(WSL)'den
# erisilir" diyordu -- bu YANLISTI, firewall kuraline bakilmadan varsayilmisti.
# Duzeltme: $targetIp (vEthernet(WSL) IP'si) disinda hicbir adrese baglanmaz.
Write-Host "[*] Hedefler baslatiliyor (SADECE $targetIp -- 0.0.0.0 KULLANILMIYOR)..." -ForegroundColor Yellow
$mvt = Join-Path $RepoDir "mini_vuln_target.py"
$targetProcs = @()
$targetProcs += Start-Process -FilePath "python" -ArgumentList "`"$mvt`"", "80", "$targetIp" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_mvt80.log") -RedirectStandardError (Join-Path $ScratchDir "run_mvt80err.log") -WindowStyle Hidden -PassThru
$targetProcs += Start-Process -FilePath "python" -ArgumentList "`"$mvt`"", "3000", "$targetIp" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_mvt3000.log") -RedirectStandardError (Join-Path $ScratchDir "run_mvt3000err.log") -WindowStyle Hidden -PassThru

$ftpRoot21 = Join-Path $ScratchDir "ftp_root_21_run"
$ftpRoot2121 = Join-Path $ScratchDir "ftp_root_2121_run"
New-Item -ItemType Directory -Path $ftpRoot21 -Force | Out-Null
New-Item -ItemType Directory -Path $ftpRoot2121 -Force | Out-Null
$targetProcs += Start-Process -FilePath "python" -ArgumentList "-m", "pyftpdlib", "-i", "$targetIp", "-p", "21", "-u", "testuser", "-P", "esp32test", "-w", "-d", "`"$ftpRoot21`"", "-r", "60200-60250" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_ftp21.log") -RedirectStandardError (Join-Path $ScratchDir "run_ftp21err.log") -WindowStyle Hidden -PassThru
$targetProcs += Start-Process -FilePath "python" -ArgumentList "-m", "pyftpdlib", "-i", "$targetIp", "-p", "2121", "-u", "testuser", "-P", "esp32test", "-w", "-d", "`"$ftpRoot2121`"", "-r", "60260-60300" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_ftp2121.log") -RedirectStandardError (Join-Path $ScratchDir "run_ftp2121err.log") -WindowStyle Hidden -PassThru

Start-Sleep -Seconds 2
$listening = Get-NetTCPConnection -LocalPort 80, 3000, 21, 2121 -State Listen -ErrorAction SilentlyContinue
$badBind = $listening | Where-Object { $_.LocalAddress -ne $targetIp }
if ($badBind) {
    Write-Host "[HATA] beklenmeyen bind adresi tespit edildi (0.0.0.0 dahil olabilir), TUM hedefler durduruluyor:" -ForegroundColor Red
    $badBind | Format-Table -AutoSize
    foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}
if (($listening | Measure-Object).Count -lt 4) {
    Write-Host "[HATA] 4 hedeften biri ayakta degil, loglara bak: $ScratchDir\run_*err.log" -ForegroundColor Red
    foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    exit 1
}
Write-Host "[OK] 4 hedef ayakta, SADECE $targetIp uzerinde (0.0.0.0 YOK, dogrulandi)." -ForegroundColor Green

# --- 4) Capture baslat -------------------------------------------------------
$pcapOut = Join-Path $RepoDir ("selfgen_campaign_{0:yyyyMMdd_HHmmss}.pcap" -f (Get-Date))
Write-Host "[*] Capture basliyor: $pcapOut" -ForegroundColor Yellow
$tsharkProc = Start-Process -FilePath "C:\Program Files\Wireshark\tshark.exe" `
    -ArgumentList "-i", $tsharkIfNum, "-f", "`"tcp port 80 or tcp port 3000 or tcp port 21 or tcp port 2121`"", "-w", "`"$pcapOut`"" `
    -RedirectStandardOutput (Join-Path $ScratchDir "run_tshark.log") -RedirectStandardError (Join-Path $ScratchDir "run_tsharkerr.log") -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 2
Write-Host "[OK] tshark PID: $($tsharkProc.Id)" -ForegroundColor Green

# --- 5) WSL kampanyasini calistir (senkron -- bitene kadar bekler) ---------
$phasesOut = Join-Path $RepoDir "phases_full.json"
Write-Host "[*] WSL kampanyasi calisiyor ($NCycles dongu, TARGET_IP=$targetIp)... bu birkac dakika surer." -ForegroundColor Yellow
# NOT: WSL yolu asla dosyaya gomulu literal olarak yazilmaz -- bu .ps1 BOM'suz UTF-8
# oldugundan, Windows PowerShell 5.1 BOM'suz dosyalari sistem ANSI kod sayfasiyla (bu
# makinede Turkce/1254) okur ve "u" gibi non-ASCII karakterler bozulur (WSL "No such
# file or directory" verirdi). Bunun yerine $RepoDir (motor tarafindan $PSScriptRoot'tan
# doğru UTF-16 ile doldurulur, dosya metninden ayristirilmaz) 'wsl wslpath' ile cevrilir.
$scriptWinPath = Join-Path $RepoDir "07_selfgen_campaign_full.sh"
$scriptRelPath = (& wsl.exe -d Ubuntu wslpath -a "$scriptWinPath").Trim()
if (-not $scriptRelPath -or -not ($scriptRelPath -match '^/mnt/')) {
    Write-Host "[HATA] wslpath cevirisi basarisiz: '$scriptRelPath'" -ForegroundColor Red
    exit 1
}
& wsl.exe -d Ubuntu -e bash -c "TARGET_IP=$targetIp bash '$scriptRelPath' $NCycles"
Write-Host "[OK] WSL kampanyasi bitti." -ForegroundColor Green

# --- 6) Capture + hedefleri durdur -------------------------------------------
Write-Host "[*] Temizlik: capture + hedefler durduruluyor..." -ForegroundColor Yellow
Stop-Process -Id $tsharkProc.Id -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1
foreach ($p in $targetProcs) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 1
$stillUp = Get-NetTCPConnection -LocalPort 80, 3000, 21, 2121 -State Listen -ErrorAction SilentlyContinue
if ($stillUp) { Write-Host "[UYARI] hala dinleyen port var: $($stillUp.LocalPort -join ',')" -ForegroundColor Red }
else { Write-Host "[OK] tum hedefler/capture kapatildi, port 80/3000/21/2121 bos." -ForegroundColor Green }

# --- 7) Ingestion -------------------------------------------------------------
Write-Host "[*] build_selfgen_dataset.py calistiriliyor..." -ForegroundColor Yellow
$mcDir = Join-Path (Split-Path $RepoDir -Parent) "multiclass_training"
$batchTag = "selfgen_nat_{0:yyyyMMdd_HHmmss}" -f (Get-Date)
python "$mcDir\build_selfgen_dataset.py" "$pcapOut" "$phasesOut" "$batchTag"

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " TAMAMLANDI. CSV: $mcDir\data\selfgen_dataset.csv" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
