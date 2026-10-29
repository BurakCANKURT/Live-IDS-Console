# ============================================================================
#  06_windows_webtarget_cleanup.ps1  --  WebAttack/Patator hedef temizligi
# ============================================================================
#  05_windows_webtarget_setup.ps1 ile eklenen GECICI degisiklikleri geri alir:
#    1) Docker konteynerleri (lft-dvwa, lft-juice) durdur + sil.
#    2) netsh portproxy 2222->22 yonlendirmesini kaldir.
#    3) 2. pyftpdlib (2121) surecini durdur.
#    4) Bu kampanyanin firewall kurallarini sil (WEB-*/SSH-2222/FTP-2121/FTP2-PASV).
#
#  NOT: 02_windows_cleanup.ps1 zaten TUM 'LiveFireTest-*' firewall kurallarini
#  siler; bu script docker/portproxy/2.FTP gibi 02'nin BILMEDIGI eklentileri
#  toplar. Ikisini de calistirmak guvenlidir (idempotent).
#
#  Yonetici (Administrator) PowerShell gerektirir.
#  Docker IMAJLARINI silmez (tekrar test hizli olsun diye). Silmek istersen:
#     docker rmi vulnerables/web-dvwa bkimminich/juice-shop
# ============================================================================

# ----- Duzenlenebilir degiskenler -------------------------------------------
$FwRuleTag   = "LiveFireTest"
$Ssh2Port    = 2222
$Ftp2PidFile = Join-Path $PSScriptRoot "ftp2121_server.pid"
# ----------------------------------------------------------------------------

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " WEBATTACK/PATATOR HEDEF TEMIZLIK" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Yonetici PowerShell gerektirir. Cikiliyor." -ForegroundColor Red
    return
}

# --- 1) Docker konteynerleri ------------------------------------------------
Write-Host ""
Write-Host "[1] Docker web hedefleri durduruluyor/siliniyor (lft-dvwa, lft-juice)..." -ForegroundColor Yellow
$hasDocker = $false
try { docker info 2>$null | Out-Null; if ($LASTEXITCODE -eq 0) { $hasDocker = $true } } catch {}
if ($hasDocker) {
    foreach ($c in @("lft-dvwa", "lft-juice")) {
        $exists = (docker ps -a --filter "name=$c" --format "{{.Names}}") 2>$null
        if ($exists -eq $c) {
            docker rm -f $c 2>$null | Out-Null
            Write-Host "    [OK] konteyner silindi: $c" -ForegroundColor Green
        } else {
            Write-Host "    [i] '$c' konteyneri yok, atlandi." -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "    [i] Docker calismiyor; konteyner temizligi atlandi." -ForegroundColor DarkYellow
}

# --- 2) SSH portproxy (2222) ------------------------------------------------
Write-Host ""
Write-Host "[2] portproxy 2222->22 kaldiriliyor..." -ForegroundColor Yellow
netsh interface portproxy delete v4tov4 listenport=$Ssh2Port listenaddress=0.0.0.0 2>$null | Out-Null
Write-Host "    [OK] portproxy dinleyicisi kaldirildi (varsa)." -ForegroundColor Green

# --- 3) Ikinci FTP sunucusu (2121) ------------------------------------------
Write-Host ""
Write-Host "[3] 2. FTP sunucusu (2121) durduruluyor..." -ForegroundColor Yellow
if (Test-Path $Ftp2PidFile) {
    $ftp2Pid = Get-Content $Ftp2PidFile -ErrorAction SilentlyContinue
    if ($ftp2Pid -and (Get-Process -Id $ftp2Pid -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $ftp2Pid -Force -ErrorAction SilentlyContinue
        Write-Host "    [OK] 2. FTP sunucusu (PID $ftp2Pid) durduruldu." -ForegroundColor Green
    } else {
        Write-Host "    [i] Kayitli 2. FTP PID calismiyor, atlandi." -ForegroundColor DarkYellow
    }
    Remove-Item $Ftp2PidFile -ErrorAction SilentlyContinue
} else {
    Write-Host "    [i] 2. FTP PID dosyasi yok (baslatilmamis olabilir)." -ForegroundColor DarkYellow
}

# --- 4) Bu kampanyanin firewall kurallari -----------------------------------
Write-Host ""
Write-Host "[4] WebAttack/Patator firewall kurallari siliniyor..." -ForegroundColor Yellow
$patterns = @("$FwRuleTag-WEB-*", "$FwRuleTag-SSH-$Ssh2Port", "$FwRuleTag-FTP-2121", "$FwRuleTag-FTP2-PASV")
foreach ($pat in $patterns) {
    $rules = Get-NetFirewallRule -DisplayName $pat -ErrorAction SilentlyContinue
    foreach ($r in $rules) {
        Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction SilentlyContinue
        Write-Host "    [OK] silindi: $($r.DisplayName)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " WEB-HEDEF TEMIZLIK TAMAM." -ForegroundColor Cyan
Write-Host "   (Geri kalan 'LiveFireTest-*' kurallari icin: 02_windows_cleanup.ps1)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
