# ============================================================================
#  02_windows_cleanup.ps1  --  Canli-ates testi HEDEF temizlik
# ============================================================================
#  01_windows_setup.ps1 ile eklenen GECICI degisiklikleri geri alir:
#    1) Baslatilan python -m http.server surecini durdurur (PID dosyasindan).
#    2) LiveFireTest-* firewall kurallarini siler.
#    3) (Opsiyonel) sshd servisini durdurur -- varsayilan olarak DOKUNMAZ,
#       cunku OpenSSH'i sen kalici isteyebilirsin. Istersen $StopSshd=$true yap.
#
#  Yonetici (Administrator) PowerShell gerektirir.
# ============================================================================

# ----- Duzenlenebilir degiskenler -------------------------------------------
$FwRuleTag  = "LiveFireTest"   # 01_windows_setup.ps1 ile AYNI olmali
$PidFile    = Join-Path $PSScriptRoot "http_server.pid"
$FtpPidFile = Join-Path $PSScriptRoot "ftp_server.pid"   # -EnableFtp ile baslatilan FTP sunucusu
$StopSshd   = $false           # $true yaparsan sshd servisi de durdurulur
# ----------------------------------------------------------------------------

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " CANLI-ATES TESTI -- HEDEF TEMIZLIK" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Yonetici PowerShell gerektirir. Cikiliyor." -ForegroundColor Red
    return
}

# --- 1) http.server surecini durdur -----------------------------------------
Write-Host ""
Write-Host "[1] http.server durduruluyor..." -ForegroundColor Yellow
if (Test-Path $PidFile) {
    $httpPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($httpPid -and (Get-Process -Id $httpPid -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $httpPid -Force -ErrorAction SilentlyContinue
        Write-Host "    [OK] http.server (PID $httpPid) durduruldu." -ForegroundColor Green
    } else {
        Write-Host "    [i] Kayitli PID calismıyor, atlandi." -ForegroundColor DarkYellow
    }
    Remove-Item $PidFile -ErrorAction SilentlyContinue
} else {
    Write-Host "    [i] PID dosyasi yok (http_server.pid). Muhtemelen zaten kapali." -ForegroundColor DarkYellow
}

# --- 1b) Test FTP sunucusunu durdur (varsa) ---------------------------------
Write-Host ""
Write-Host "[1b] Test FTP sunucusu durduruluyor (varsa)..." -ForegroundColor Yellow
if (Test-Path $FtpPidFile) {
    $ftpPid = Get-Content $FtpPidFile -ErrorAction SilentlyContinue
    if ($ftpPid -and (Get-Process -Id $ftpPid -ErrorAction SilentlyContinue)) {
        Stop-Process -Id $ftpPid -Force -ErrorAction SilentlyContinue
        Write-Host "    [OK] Test FTP sunucusu (PID $ftpPid) durduruldu." -ForegroundColor Green
    } else {
        Write-Host "    [i] Kayitli FTP PID calismiyor, atlandi." -ForegroundColor DarkYellow
    }
    Remove-Item $FtpPidFile -ErrorAction SilentlyContinue
} else {
    Write-Host "    [i] FTP PID dosyasi yok (FTP baslatilmamis olabilir)." -ForegroundColor DarkYellow
}

# --- 2) Firewall kurallarini sil --------------------------------------------
Write-Host ""
Write-Host "[2] '$FwRuleTag-*' firewall kurallari siliniyor..." -ForegroundColor Yellow
$rules = Get-NetFirewallRule -DisplayName "$FwRuleTag-*" -ErrorAction SilentlyContinue
if ($rules) {
    foreach ($r in $rules) {
        Remove-NetFirewallRule -DisplayName $r.DisplayName -ErrorAction SilentlyContinue
        Write-Host "    [OK] silindi: $($r.DisplayName)" -ForegroundColor Green
    }
} else {
    Write-Host "    [i] '$FwRuleTag-*' ile eslesen kural bulunamadi." -ForegroundColor DarkYellow
}

# --- 3) sshd (opsiyonel) ----------------------------------------------------
Write-Host ""
if ($StopSshd) {
    Write-Host "[3] sshd servisi durduruluyor (StopSshd=`$true)..." -ForegroundColor Yellow
    Stop-Service -Name sshd -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType Manual -ErrorAction SilentlyContinue
    Write-Host "    [OK] sshd durduruldu ve baslangic tipi Manual yapildi." -ForegroundColor Green
} else {
    Write-Host "[3] sshd servisine DOKUNULMADI (StopSshd=`$false)." -ForegroundColor DarkYellow
    Write-Host "    Durdurmak istersen bu scriptin basinda `$StopSshd=`$true yap." -ForegroundColor DarkYellow
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " TEMIZLIK TAMAM. Geriye acik gecici degisiklik kalmadi." -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
