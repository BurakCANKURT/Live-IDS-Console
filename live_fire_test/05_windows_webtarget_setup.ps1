param(
    [switch]$EnableWebApp,    # Docker ile DVWA(80)+Juice Shop(3000) zafiyetli web hedefleri
    [switch]$EnableSsh2222,   # netsh portproxy ile 2222->22 (ephemeral-bucket SSH varyanti)
    [switch]$EnableFtp2121    # 2121 portunda ikinci pyftpdlib (ephemeral-bucket FTP varyanti)
)

# ============================================================================
#  05_windows_webtarget_setup.ps1  --  WebAttack + Patator VERI TOPLAMA hedefi
# ============================================================================
#  Bu makine = IDS'i calistiran HEDEF. 01_windows_setup.ps1'i TAMAMLAR (onu
#  degistirmez, DOKUNMAZ) -- 01'in 8080'deki static http.server'i
#  (connflood/slowloris hedefi) bu script CALISIRKEN de calisir durumda
#  kalabilir, cakisma YOK. Amac: modelin tek-oturum-ezberini kirmak icin
#  CESITLI hedefler:
#    * WebAttack : gercek zafiyetli app (DVWA + Juice Shop) -- static http.server
#                  SQLi'ye tepki veremez (backend/DB yok), bu yuzden Docker.
#    * PORT-BUCKET cesitliligi (kritik -- r24-port-bucket notu):
#        DVWA      -> 80    ("http" bucket -- CICIDS'in kendi WebAttack hedef
#                            portuyla AYNI, gercekci; 01'in 8080'iyle CAKISMAZ)
#        Juice Shop-> 3000  ("ephemeral" bucket)
#        SSH       -> 22 (mevcut) + 2222 ("ephemeral" bucket, portproxy)
#        FTP       -> 21 (mevcut) + 2121 ("ephemeral" bucket, 2. pyftpdlib)
#      Ayni saldiri farkli bucket'ta toplanirsa model port'a asiri-baglanamaz.
#
#  ONEMLI: PowerShell'i "Yonetici olarak" ac. Docker Desktop KURULU ve CALISIR
#  olmali (-EnableWebApp icin). Port 80 baska bir servis (IIS, Skype vb.)
#  tarafindan kullaniliyorsa DVWA baslatma HATA verir (asagida yakalanir) --
#  o durumda o servisi durdurup tekrar dene. Testten sonra
#  06_windows_webtarget_cleanup.ps1.
#
#  Kullanim:
#    .\05_windows_webtarget_setup.ps1 -EnableWebApp
#    .\05_windows_webtarget_setup.ps1 -EnableWebApp -EnableSsh2222 -EnableFtp2121
# ============================================================================

# ----- Duzenlenebilir degiskenler -------------------------------------------
$DvwaPort   = 80             # DVWA (http bucket) -- 01'deki 8080 static http.server'a DOKUNMAZ
$JuicePort  = 3000          # OWASP Juice Shop (ephemeral bucket)
$Ssh2Port   = 2222          # ikinci SSH portu (portproxy -> 22)
$Ftp2Port   = 2121          # ikinci FTP portu (2. pyftpdlib)
$FtpUser    = "testuser"    # atilabilir test FTP hesabi (ESP32/host ile AYNI)
$FtpPass    = "esp32test"   # test hesabi parolasi (gercek parola DEGIL)
$FwRuleTag  = "LiveFireTest"  # 01/02 ile AYNI on-ek (02_cleanup firewall'i da toplar)
$Ftp2PidFile = Join-Path $PSScriptRoot "ftp2121_server.pid" # 2. FTP PID (06_cleanup icin)
$Ftp2Root    = Join-Path $PSScriptRoot "ftp_root"           # bos test kok dizini (01 ile ayni)
# ----------------------------------------------------------------------------

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " CANLI-ATES -- WEBATTACK/PATATOR VERI TOPLAMA HEDEFI (Windows)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# --- Admin kontrolu ---------------------------------------------------------
$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[HATA] Yonetici (Administrator) PowerShell gerektirir. Cikiliyor." -ForegroundColor Red
    return
}

# --- LocalSubnet firewall kurali yardimcisi ---------------------------------
function Add-LanRule($name, $port) {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) {
        Write-Host "    [i] '$name' zaten var, atlandi." -ForegroundColor DarkYellow
        return
    }
    New-NetFirewallRule -DisplayName $name -Direction Inbound -Action Allow `
        -Protocol TCP -LocalPort $port -RemoteAddress LocalSubnet -Profile Any | Out-Null
    Write-Host "    [OK] '$name' eklendi (TCP $port, LocalSubnet)." -ForegroundColor Green
}

# ============================================================================
#  1) WEB HEDEFLERI (Docker: DVWA + Juice Shop)
# ============================================================================
if ($EnableWebApp) {
    Write-Host ""
    Write-Host "[1] Docker zafiyetli web hedefleri (DVWA:$DvwaPort + JuiceShop:$JuicePort)" -ForegroundColor Yellow

    # Docker var mi + calisiyor mu?
    $hasDocker = $false
    try {
        docker info 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { $hasDocker = $true }
    } catch { $hasDocker = $false }

    if (-not $hasDocker) {
        Write-Host "    [!] Docker bulunamadi VEYA Docker Desktop calismiyor." -ForegroundColor Red
        Write-Host "        Docker Desktop kur/baslat, sonra bu scripti tekrar calistir:" -ForegroundColor Red
        Write-Host "        https://www.docker.com/products/docker-desktop/" -ForegroundColor DarkGray
    } else {
        # DVWA port 80'de -- 01'in static http.server'i (8080) AYRI portta,
        # dokunulmuyor/durdurulmuyor; ikisi ayni anda calisabilir.

        # DVWA (apache+mysql tek konteyner, 80 -> $DvwaPort)
        $dvwaExists = (docker ps -a --filter "name=lft-dvwa" --format "{{.Names}}") 2>$null
        if ($dvwaExists -eq "lft-dvwa") {
            docker start lft-dvwa 2>$null | Out-Null
            Write-Host "    [i] DVWA konteyneri zaten var, baslatildi (lft-dvwa)." -ForegroundColor DarkYellow
        } else {
            Write-Host "    [i] DVWA cekiliyor/baslatiliyor (ilk sefer imaj indirir, sabir)..." -ForegroundColor DarkYellow
            docker run -d --name lft-dvwa -p "$($DvwaPort):80" vulnerables/web-dvwa 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [OK] DVWA calisiyor -> http://<LAN_IP>:$DvwaPort/  (login: admin/password)" -ForegroundColor Green
            } else {
                Write-Host "    [HATA] DVWA baslatilamadi (port $DvwaPort dolu olabilir)." -ForegroundColor Red
            }
        }

        # OWASP Juice Shop (self-contained, DB yok, 3000)
        $juiceExists = (docker ps -a --filter "name=lft-juice" --format "{{.Names}}") 2>$null
        if ($juiceExists -eq "lft-juice") {
            docker start lft-juice 2>$null | Out-Null
            Write-Host "    [i] Juice Shop konteyneri zaten var, baslatildi (lft-juice)." -ForegroundColor DarkYellow
        } else {
            Write-Host "    [i] Juice Shop cekiliyor/baslatiliyor..." -ForegroundColor DarkYellow
            docker run -d --name lft-juice -p "$($JuicePort):3000" bkimminich/juice-shop 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "    [OK] Juice Shop calisiyor -> http://<LAN_IP>:$JuicePort/" -ForegroundColor Green
            } else {
                Write-Host "    [HATA] Juice Shop baslatilamadi (port $JuicePort dolu olabilir)." -ForegroundColor Red
            }
        }

        Add-LanRule "$FwRuleTag-WEB-$DvwaPort"  $DvwaPort
        Add-LanRule "$FwRuleTag-WEB-$JuicePort" $JuicePort

        Write-Host ""
        Write-Host "    >>> DVWA icin TEK SEFERLIK ELLE ADIM (backend DB kurulumu):" -ForegroundColor Cyan
        Write-Host "        1) Tarayicidan http://localhost:$DvwaPort/setup.php ac" -ForegroundColor Cyan
        Write-Host "        2) En altta 'Create / Reset Database' butonuna bas" -ForegroundColor Cyan
        Write-Host "        3) admin/password ile giris yap, DVWA Security'yi 'Low' yap" -ForegroundColor Cyan
        Write-Host "        4) sqlmap icin cerezi al: F12 > Application > Cookies" -ForegroundColor Cyan
        Write-Host "           (PHPSESSID + security=low) -> 05_pi scriptindeki DVWA_COOKIE'ye yaz" -ForegroundColor Cyan
    }
}

# ============================================================================
#  2) IKINCI SSH PORTU (2222 -> 22, netsh portproxy)
# ============================================================================
if ($EnableSsh2222) {
    Write-Host ""
    Write-Host "[2] Ikinci SSH portu: $Ssh2Port -> 22 (netsh portproxy)" -ForegroundColor Yellow

    # 22'de sshd calisiyor mu? (portproxy 2222'yi yerel 22'ye yonlendirir)
    $svc = Get-Service -Name sshd -ErrorAction SilentlyContinue
    if (-not $svc -or $svc.Status -ne "Running") {
        Write-Host "    [!] sshd port 22'de CALISMIYOR. Once 01_windows_setup.ps1 ile OpenSSH'i" -ForegroundColor Red
        Write-Host "        kurup baslat; portproxy yalnizca 2222'yi yerel 22'ye tasir." -ForegroundColor Red
    }
    # Var olan ayni dinleyiciyi temizle, sonra ekle (idempotent).
    netsh interface portproxy delete v4tov4 listenport=$Ssh2Port listenaddress=0.0.0.0 2>$null | Out-Null
    netsh interface portproxy add v4tov4 listenport=$Ssh2Port listenaddress=0.0.0.0 `
        connectport=22 connectaddress=127.0.0.1 | Out-Null
    Write-Host "    [OK] portproxy eklendi: 0.0.0.0:$Ssh2Port -> 127.0.0.1:22" -ForegroundColor Green
    Add-LanRule "$FwRuleTag-SSH-$Ssh2Port" $Ssh2Port
    Write-Host "    [i] Saldiran taraf artik 'ssh://<LAN_IP>:$Ssh2Port' hedefler (ephemeral bucket)." -ForegroundColor Green
}

# ============================================================================
#  3) IKINCI FTP PORTU (2121, ikinci pyftpdlib)
# ============================================================================
if ($EnableFtp2121) {
    Write-Host ""
    Write-Host "[3] Ikinci FTP portu: $Ftp2Port (2. pyftpdlib)" -ForegroundColor Yellow

    $hasPyftp = $false
    try {
        python -c "import pyftpdlib" 2>$null
        if ($LASTEXITCODE -eq 0) { $hasPyftp = $true }
    } catch { $hasPyftp = $false }

    if (-not $hasPyftp) {
        Write-Host "    [!] pyftpdlib kurulu degil. Kur: pip install pyftpdlib, sonra tekrar calistir." -ForegroundColor Red
    } else {
        if (-not (Test-Path $Ftp2Root)) { New-Item -ItemType Directory -Path $Ftp2Root | Out-Null }
        $ftp2Already = $false
        if (Test-Path $Ftp2PidFile) {
            $oldPid = Get-Content $Ftp2PidFile -ErrorAction SilentlyContinue
            if ($oldPid -and (Get-Process -Id $oldPid -ErrorAction SilentlyContinue)) {
                Write-Host "    [i] 2. FTP sunucusu zaten calisiyor (PID $oldPid)." -ForegroundColor DarkYellow
                $ftp2Already = $true
            } else { Remove-Item $Ftp2PidFile -ErrorAction SilentlyContinue }
        }
        if (-not $ftp2Already) {
            # Pasif port araligi 01'in 21-sunucusuyla CAKISMASIN diye 60200-60300.
            $ftpArgs = @("-m", "pyftpdlib", "-p", "$Ftp2Port", "-u", "$FtpUser",
                         "-P", "$FtpPass", "-d", "$Ftp2Root", "-r", "60200-60300")
            $p = Start-Process -FilePath "python" -ArgumentList $ftpArgs -WindowStyle Hidden -PassThru
            if ($p) {
                $p.Id | Out-File -FilePath $Ftp2PidFile -Encoding ascii
                Write-Host "    [OK] 2. FTP sunucusu baslatildi (PID $($p.Id)) -> port $Ftp2Port." -ForegroundColor Green
                Write-Host "         Hesap: $FtpUser / $FtpPass (host/ESP32 ile AYNI)." -ForegroundColor Green
            } else {
                Write-Host "    [HATA] 2. FTP sunucusu baslatilamadi." -ForegroundColor Red
            }
        }
        Add-LanRule "$FwRuleTag-FTP-$Ftp2Port"     $Ftp2Port
        if (-not (Get-NetFirewallRule -DisplayName "$FwRuleTag-FTP2-PASV" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName "$FwRuleTag-FTP2-PASV" -Direction Inbound -Action Allow `
                -Protocol TCP -LocalPort 60200-60300 -RemoteAddress LocalSubnet -Profile Any | Out-Null
            Write-Host "    [OK] '$FwRuleTag-FTP2-PASV' eklendi (TCP 60200-60300 pasif-mod)." -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host " WEB-HEDEF HAZIRLIK TAMAM. Simdi:" -ForegroundColor Cyan
Write-Host "   1) (DVWA kullandiysan) yukaridaki TEK SEFERLIK DB kurulum adimini yap." -ForegroundColor Cyan
Write-Host "   2) IDS'i (native dashboard / process_pcap) her zamanki gibi baslat." -ForegroundColor Cyan
Write-Host "   3) ESP32 esp32_webattack.ino'yu 80 VE 3000 ile ayri ayri calistir," -ForegroundColor Cyan
Write-Host "      ayni sinifi host-tarafi 05_pi_webattack_patator_scenarios.sh ile de topla." -ForegroundColor Cyan
Write-Host "   4) Test bitince: 06_windows_webtarget_cleanup.ps1  (+ 02_windows_cleanup.ps1)" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
