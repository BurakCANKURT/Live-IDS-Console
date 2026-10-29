// ============================================================================
//  esp32_portscan.ino  --  CICIDS SINIFI: PortScan
// ============================================================================
//  YETKI: SADECE sana ait, ayni yerel LAN'daki Windows IDS makinesine karsi,
//  kontrollu/yetkilendirilmis dogrulama testi icindir. Baska bir hedefe
//  YONELTME.
//
//  NE YAPAR: Hedefe START_PORT..END_PORT arasindaki portlara SIRAYLA TCP
//  connect() dener. Bu bir "connect scan" (nmap -sT benzeri), nmap -sS (ham
//  SYN scan) DEGIL -- ESP32'de ham paket uretmek pratik degil. AMA IDS
//  acisindan fark yoktur: her connect() ilk pakette bir SYN-only paketi
//  (SYN=1, ACK=0) gonderir; pipeline'daki is_scan sayaci TAM DA bu SYN-only
//  paketleri sayar (process_pcap.py:896-900). Yani connect-scan de is_scan'i
//  aynen tetikler.
//
//  IDS'te beklenen yol (pre-test denetimi F1):
//    * END_PORT buyuk (orn. 1000) -> distinct_ports >> 150 -> is_scan latch,
//      scan_rf_benign vetosu (<150 port sarti) DEVREDE DEGIL -> PortScan alarmi
//      GUVENLE doner. Volumetrik dal: konsey vetosu YOK, OOD salt-gozlem.
//    * END_PORT dar (orn. 100) -> distinct_ports 40-149 bandi -> F1 KOR NOKTASI:
//      RF paket-basi BENIGN gorurse scan_rf_benign vetosu GERCEK taramayi
//      bastirabilir. Mongo'da suppressed_by="scan_rf_benign" + status!=ATTACK
//      gorursen = FP-fix gercek saldiriyi yedi (testin asil aradigi bulgu).
//
//  DAR-BANT (F1) TESTI ICIN: asagida END_PORT = 100 yap ve ayrica bir kez de
//  END_PORT = 1000 ile calistir; iki pencereyi Mongo'da karsilastir.
//
//  ARDUINO IDE: Board = "ESP32 Dev Module" (veya kartinin modeli). Ek kutuphane
//  GEREKMEZ (WiFi.h ESP32 cekirdegiyle gelir). Yukle -> Serial Monitor 115200.
//  Tarama setup()'ta BIR KEZ calisir, biter ve durur; tekrar icin RESET'e bas.
// ============================================================================

#include <WiFi.h>
#include "secrets.h"   // local, not in git: copy secrets.example.h

// ----- DUZENLENEBILIR DEGISKENLER (yalnizca burayi degistir) ----------------
const char* WIFI_SSID = SECRET_WIFI_SSID;   // set in secrets.h
const char* WIFI_PASS = SECRET_WIFI_PASS;   // set in secrets.h
IPAddress   TARGET_IP(SECRET_TARGET_IP);    // set in secrets.h (IDS machine LAN IP)

const uint16_t START_PORT = 1;             // taramaya baslangic portu
const uint16_t END_PORT   = 100;           // bitis portu. F1 dar-bant icin: 100
const int  CONNECT_TIMEOUT_MS   = 300;     // her port icin baglanti zaman asimi (kisa tut)
const int  DELAY_BETWEEN_PORTS  = 5;       // portlar arasi bekleme (ms) -- hiz siniri
// ----------------------------------------------------------------------------

void connectWiFi() {
  Serial.printf("[WiFi] '%s' agina baglaniliyor", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) {
    delay(400);
    Serial.print(".");
  }
  Serial.printf("\n[WiFi] Baglandi. ESP32 IP = %s\n", WiFi.localIP().toString().c_str());
  Serial.println("[i] Bu IP'yi 04_mongo_analysis.py --attacker-ip degerine yaz.");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n============================================================");
  Serial.println(" ESP32 CANLI-ATES -- CICIDS PortScan (connect scan)");
  Serial.println("============================================================");
  Serial.printf(" HEDEF        : %s\n", TARGET_IP.toString().c_str());
  Serial.printf(" PORT ARALIGI : %u - %u  (toplam %u port)\n",
                START_PORT, END_PORT, (unsigned)(END_PORT - START_PORT + 1));
  Serial.println(" YETKI        : yalnizca sana ait hedef, yetkili lab testi.");
  Serial.println("------------------------------------------------------------");

  connectWiFi();

  Serial.println("\n[>>>] Tarama basliyor... (durdurmak icin karti resetle/kapat)\n");
  uint16_t openCount = 0;

  for (uint32_t port = START_PORT; port <= END_PORT; port++) {
    WiFiClient client;
    // 3. arguman: zaman asimi (ms). connect() ilk pakette SYN-only gonderir.
    bool ok = client.connect(TARGET_IP, (uint16_t)port, CONNECT_TIMEOUT_MS);
    if (ok) {
      openCount++;
      Serial.printf("  [ACIK]  port %u\n", (unsigned)port);
      client.stop();
    }
    // Kapali/filtreli portlar sessizce atlanir (SYN yine de kabloya cikti,
    // IDS tarafinda distinct_ports icin sayildi).
    if ((port - START_PORT) % 50 == 0 && port != START_PORT) {
      Serial.printf("  ... %u portta tarandi\n", (unsigned)(port - START_PORT));
    }
    delay(DELAY_BETWEEN_PORTS);
  }

  Serial.println("\n============================================================");
  Serial.printf(" TARAMA BITTI. Acik port: %u.  Toplam denenen: %u.\n",
                openCount, (unsigned)(END_PORT - START_PORT + 1));
  Serial.println(" Simdi Windows'ta: 04_mongo_analysis.py --last N --attacker-ip <ESP32_IP>");
  Serial.println(" Beklenti: predicted_class=PortScan / is_volumetric=True (is_scan).");
  Serial.println("============================================================");
}

void loop() {
  // Tek seferlik senaryo; tekrar icin RESET.
  delay(10000);
}
