param(
    [switch]$EnableFtp   # ESP32 FTP-Patator senaryosu icin atilabilir bir FTP sunucusu baslatir
)

# ============================================================================
#  01_windows_setup.ps1  --  Canli-ates testi HEDEF (Windows PC) hazirlik
# ============================================================================
#  Bu makine = IDS'i (native dashboard / process_pcap*.py) calistiran hedef.
#  SALDIRGAN cihaz artik Raspberry Pi DEGIL, ESP32 (live_fire_test/esp32/*.ino).
#  Hedef ayni Windows PC oldugu icin hazirlik buyuk olcude aynidir.
#  Yaptiklari:
#    1) LAN IP'sini bulur ve ekrana yazar (ESP32 sketch'lerinde TARGET_IP'ye yaz).
#    2) HTTP hedef servisini (python -m http.server 8080) arka planda baslatir
#       (esp32_connflood.ino + esp32_slowloris.ino hedefi).
#    3) Windows Firewall'da 8080 (HTTP) + 22 (SSH) portlarini SADECE yerel
#       LAN'dan (LocalSubnet) gelen baglantiya GECICI olarak acar.
#    4) OpenSSH Server kurulu mu kontrol eder (referans; ESP32 SSH-Patator
#       YAPAMAZ, bunun yerine FTP-Patator kullanilir -- asagi bkz.).
#    5) -EnableFtp verilirse: pyftpdlib ile 21 portunda ATILABILIR bir test FTP
#       sunucusu (testuser hesabiyla) baslatir ve 21 portunu LocalSubnet'e acar
#       -- esp32_ftp_patator.ino hedefi.
#
#  ONEMLI: PowerShell'i "Yonetici olarak" ac (firewall + servis islemleri
#  admin gerektirir).  Testten sonra 02_windows_cleanup.ps1 calistir.
#
#  Kullanim:
#    .\01_windows_setup.ps1              # HTTP + SSH portlari (port/conn-flood/slowloris)
#    .\01_windows_setup.ps1 -EnableFtp   # ek olarak test FTP sunucusu (FTP-Patator)
# ============================================================================

# ----- Duzenlenebilir degiskenler -------------------------------------------
$HttpPort   = 8080          # connflood/slowloris hedef HTTP portu
$SshPort    = 22            # (referans; ESP32 SSH-Patator yapamaz)
$FtpPort    = 21            # ESP32 FTP-Patator hedef portu (-EnableFtp ile)
$FtpUser    = "testuser"    # atilabilir test FTP hesabi (ESP32 sketch ile AYNI olmali)
$FtpPass    = "esp32test"   # test hesabi parolasi (gercek parola DEGIL)
$FwRuleTag  = "LiveFireTest"  # eklenen tum firewall kurallarinin ortak on-eki
$PidFile    = Join-Path $PSScriptRoot "http_server.pid"  # cleanup icin PID kaydi
$FtpPidFile = Join-Path $PSScriptRoot "ftp_server.pid"   # FTP sunucusu PID kaydi
$FtpRoot    = Join-Path $PSScriptRoot "ftp_root"         # FTP sunucusu kok dizini (bos, test)
# ----------------------------------------------------------------------------

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " CANLI-ATES TESTI -- HEDEF (Windows) HAZIRLIK" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# --- Admin kontrolu ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Bu script Yonetici (Administrator) PowerShell gerektirir." -ForegroundColor Red
    Write-Host "       Firewall kurallari ve servis baslatma admin ister. Cikiliyor." -ForegroundColor Red
    return
}

# --- 1) LAN IP tespiti ------------------------------------------------------
# Wi-Fi/Ethernet uzerindeki, 169.254 (APIPA) ve loopback DISI IPv4 adresleri.
$lanIps = Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object {
        $_.IPAddress -notlike "127.*" -and
        $_.IPAddress -notlike "169.254.*" -and
        $_.PrefixOrigin -ne "WellKnown"
    } |
    Select-Object IPAddress, InterfaceAlias, PrefixLength

Write-Host ""
Write-Host "[1] Bu makinenin LAN IP adres(ler)i:" -ForegroundColor Yellow
$lanIps | Format-Table -AutoSize
Write-Host "    --> Pi scriptinde TARGET_IP bu adreslerden Pi ile ayni /24 agda" -ForegroundColor Yellow
Write-Host "        olanina ayarlanmalidir (genelde 192.168.x.y veya 10.x.y.z)." -ForegroundColor Yellow

# --- 2) HTTP hedef servisi (arka planda) ------------------------------------
Write-Host ""
Write-Host "[2] HTTP hedef servisi baslatiliyor: python -m http.server $HttpPort" -ForegroundColor Yellow
# Zaten calisiyorsa (onceki PID dosyasi) uyar, tekrar baslatma.
if (Test-Path $PidFile) {
    $oldPid = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($oldPid -and (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)) {
        Write-Host "    [i] http.server zaten calisiyor (PID $oldPid). Yeniden baslatilmadi." -ForegroundColor DarkYellow
    } else {
        Remove-Item $PidFile -ErrorAction SilentlyContinue
    }
}
if (-not (Test-Path $PidFile)) {
    # -WindowStyle Hidden: gorunmez arka plan; PID cleanup icin dosyaya yazilir.
    $proc = Start-Process -FilePath "python" `
        -ArgumentList "-m", "http.server", "$HttpPort" `
        -WindowStyle Hidden -PassThru
    if ($proc) {
        $proc.Id | Out-File -FilePath $PidFile -Encoding ascii
        Write-Host "    [OK] http.server baslatildi (PID $($proc.Id)) -> port $HttpPort" -ForegroundColor Green
    } else {
        Write-Host "    [HATA] python bulunamadi veya http.server baslatilamadi." -ForegroundColor Red
    }
}

# --- 3) Firewall kurallari (SADECE LocalSubnet) -----------------------------
# LocalSubnet = yalnizca ayni yerel ag; internetten erisimi ACMAZ.
Write-Host ""
Write-Host "[3] Firewall kurallari ekleniyor (SADECE LocalSubnet)..." -ForegroundColor Yellow

function Add-LanRule($name, $port) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Write-Host "    [i] '$name' zaten var, atlandi." -ForegroundColor DarkYellow
        return
    }
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $port -RemoteAddress LocalSubnet `
        -Profile Any | Out-Null
    Write-Host "    [OK] '$name' eklendi (TCP $port, RemoteAddress=LocalSubnet)." -ForegroundColor Green
}

Add-LanRule "$FwRuleTag-HTTP-$HttpPort" $HttpPort
Add-LanRule "$FwRuleTag-SSH-$SshPort"   $SshPort
if ($EnableFtp) {
    Add-LanRule "$FwRuleTag-FTP-$FtpPort" $FtpPort
    # Pasif-mod FTP veri portlari icin genis bir aralik da acilir (LocalSubnet).
    if (-not (Get-NetFirewallRule -DisplayName "$FwRuleTag-FTP-PASV" -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName "$FwRuleTag-FTP-PASV" -Direction Inbound -Action Allow `
            -Protocol TCP -LocalPort 60000-60100 -RemoteAddress LocalSubnet -Profile Any | Out-Null
        Write-Host "    [OK] '$FwRuleTag-FTP-PASV' eklendi (TCP 60000-60100 pasif-mod)." -ForegroundColor Green
    }
}

# --- 4) OpenSSH Server kontrolu (REFERANS -- ESP32 SSH-Patator YAPAMAZ) ------
# NOT: ESP32 gercek SSH el-sikismasi/sifreleme yapamaz; SSH-Patator ESP32 ile
# gerceklenmez. Bunun yerine ESP32 FTP-Patator (duz metin) kullanir (-EnableFtp).
# Bu blok, SSH'i baska bir amacla acik tutmak istersen diye REFERANS kaldi.
Write-Host ""
Write-Host "[4] OpenSSH Server durumu (REFERANS -- ESP32 icin GEREKMEZ):" -ForegroundColor Yellow
$sshFeature = Get-WindowsCapability -Online -Name "OpenSSH.Server*" -ErrorAction SilentlyContinue
if ($sshFeature -and $sshFeature.State -eq "Installed") {
    Write-Host "    [OK] OpenSSH.Server kurulu." -ForegroundColor Green
    # Servisi baslat + otomatik yap (kurulu ama durmus olabilir).
    Set-Service -Name sshd -StartupType Automatic -ErrorAction SilentlyContinue
    Start-Service -Name sshd -ErrorAction SilentlyContinue
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    Write-Host "    [i] sshd servis durumu: $($svc.Status)" -ForegroundColor Green
} else {
    Write-Host "    [!] OpenSSH.Server KURULU DEGIL." -ForegroundColor Red
    Write-Host "        SSH-Patator (hydra) senaryosu icin gereklidir." -ForegroundColor Red
    Write-Host "        Kurmak istersen (OTOMATIK CALISTIRILMADI, elle calistir):" -ForegroundColor Red
    Write-Host '        Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0' -ForegroundColor DarkGray
    Write-Host '        Start-Service sshd; Set-Service -Name sshd -StartupType Automatic' -ForegroundColor DarkGray
    Write-Host "        (Ardindan hydra icin atilabilir bir 'testuser' hesabi ac.)" -ForegroundColor DarkGray
}

# --- 5) Test FTP sunucusu (yalnizca -EnableFtp) -----------------------------
# esp32_ftp_patator.ino hedefi. pyftpdlib ile atilabilir bir FTP sunucusu;
# hicbir gercek dosya/hesap paylasmaz (bos kok dizin, tek test hesabi).
if ($EnableFtp) {
    Write-Host ""
    Write-Host "[5] Test FTP sunucusu (pyftpdlib) baslatiliyor (port $FtpPort)..." -ForegroundColor Yellow

    # pyftpdlib kurulu mu?
    $hasPyftp = $false
    try {
        python -c "import pyftpdlib" 2>$null
        if ($LASTEXITCODE -eq 0) { $hasPyftp = $true }
    } catch { $hasPyftp = $false }

    if (-not $hasPyftp) {
        Write-Host "    [!] pyftpdlib kurulu degil. Kurmak icin (OTOMATIK CALISTIRILMADI):" -ForegroundColor Red
        Write-Host "        pip install pyftpdlib" -ForegroundColor DarkGray
        Write-Host "    Kurduktan sonra bu scripti -EnableFtp ile tekrar calistir." -ForegroundColor DarkGray
    } else {
        if (-not (Test-Path $FtpRoot)) { New-Item -ItemType Directory -Path $FtpRoot | Out-Null }
        # Zaten calisiyorsa tekrar baslatma.
        $ftpAlready = $false
        if (Test-Path $FtpPidFile) {
            $oldFtpPid = Get-Content $FtpPidFile -ErrorAction SilentlyContinue
            if ($oldFtpPid -and (Get-Process -Id $oldFtpPid -ErrorAction SilentlyContinue)) {
                Write-Host "    [i] Test FTP sunucusu zaten calisiyor (PID $oldFtpPid)." -ForegroundColor DarkYellow
                $ftpAlready = $true
            } else { Remove-Item $FtpPidFile -ErrorAction SilentlyContinue }
        }
        if (-not $ftpAlready) {
            # pyftpdlib komut satiri: tek kullanici + parola + pasif port araligi.
            $ftpArgs = @(
                "-m", "pyftpdlib",
                "-p", "$FtpPort",
                "-u", "$FtpUser",
                "-P", "$FtpPass",
                "-d", "$FtpRoot",
                "-r", "60000-60100"
            )
            $ftpProc = Start-Process -FilePath "python" -ArgumentList $ftpArgs `
                -WindowStyle Hidden -PassThru
            if ($ftpProc) {
                $ftpProc.Id | Out-File -FilePath $FtpPidFile -Encoding ascii
                Write-Host "    [OK] Test FTP sunucusu baslatildi (PID $($ftpProc.Id))." -ForegroundColor Green
                Write-Host "         Hesap: $FtpUser / $FtpPass  (ESP32 sketch ile AYNI olmali)." -ForegroundColor Green
            } else {
                Write-Host "    [HATA] FTP sunucusu baslatilamadi." -ForegroundColor Red
            }
        }
    }
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " HAZIRLIK TAMAM. Simdi:" -ForegroundColor Cyan
Write-Host "   1) IDS'i (native dashboard / process_pcap) her zamanki gibi baslat." -ForegroundColor Cyan
Write-Host "   2) ESP32 sketch'lerinde TARGET_IP = yukaridaki LAN IP yap, sirayla" -ForegroundColor Cyan
Write-Host "      yukle/calistir (bkz. 03_esp32_run_guide.md)." -ForegroundColor Cyan
Write-Host "   3) Her senaryo sonrasi 04_mongo_analysis.py ile pencereyi incele." -ForegroundColor Cyan
Write-Host "   4) Test bitince 02_windows_cleanup.ps1 calistir." -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
