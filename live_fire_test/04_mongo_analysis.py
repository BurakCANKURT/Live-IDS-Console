# -*- coding: utf-8 -*-
"""
04_mongo_analysis.py  --  Canli-ates testi SONRASI Mongo analizi
================================================================
Belirli bir zaman araligindaki `predictions` kayitlarini ceker ve
    status / suppressed_by / ood_distance / ood_gate_applied /
    predicted_class / risk_score
dagilimlarini tablo halinde basar.

ASIL SORU: "gercek saldiri trafigi (SALDIRGAN cihazdan) YANLISLIKLA
status=UNKNOWN veya status=BENIGN'e dustu mu?"  -- bu satirlar vurgulanir.

Bu script SALDIRGAN CIHAZDAN BAGIMSIZDIR: --attacker-ip ile suzer. Saldirgan
Raspberry Pi de ESP32 de olsa ayni calisir. ESP32 senaryolarinin (bkz.
live_fire_test/esp32/) HACIM/ZAMANLAMA profili Pi'den FARKLIDIR, beklentiler:
  * esp32_portscan     -> is_scan / predicted_class=PortScan (volumetrik).
                          Dar-bant (END_PORT=100) surumunde 40-149 port bandi:
                          suppressed_by="scan_rf_benign" cikarsa F1 bulgusu.
  * esp32_connflood    -> is_flood/is_conn_flood, is_volumetric=True, ATTACK.
                          (ham SYN-flood degil, connect seli; ayni dala duser.)
  * esp32_slowloris    -> ~8 akis, conn_flood ALTINDA -> non-volumetrik/LSTM.
                          Dusuk hacim: alarm yoksa "bastirildi" kesin degil.
  * esp32_ftp_patator  -> SLOW modda non-volumetrik (F2 asil test): suppressed_by
                          {committee_dissent|ood|immature_flow}+status!=ATTACK
                          = gercek brute-force bastirildi. FAST modda volumetrik.

Yorumlama notu (OOD denetiminden):
  * status=BENIGN  -> SESSIZ KACIRMA (asil tehlikeli sonuc)
  * status=UNKNOWN -> atfetme boslugu, HALA bir alarmdir (kacirma DEGIL)

Baglanti: pipeline/mongo_logger.py ile ayni konvansiyon
  (MONGO_URI / MONGO_DB / MONGO_COLLECTION ortam degiskenleri; ayni varsayilanlar).

Kullanim ornekleri (Windows PowerShell, IDS makinesi):
  python 04_mongo_analysis.py --last 20
  python 04_mongo_analysis.py --start "2026-08-07 21:30:00" --end "2026-08-07 22:10:00"
  python 04_mongo_analysis.py --last 30 --attacker-ip 192.168.1.55   # <-- ESP32'nin IP'si
"""

import argparse
import os
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except ImportError:
    print("[HATA] pymongo kurulu degil. Kur: pip install pymongo")
    sys.exit(1)

# ----- Baglanti (mongo_logger.py ile ayni konvansiyon) ----------------------
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB = os.environ.get("MONGO_DB", "ids_db")
MONGO_COLLECTION = os.environ.get("MONGO_COLLECTION", "predictions")


def parse_local_dt(s):
    """Kullanicinin verdigi YEREL zamani UTC'ye cevirir (Mongo UTC saklar)."""
    fmt_candidates = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%H:%M:%S", "%H:%M"]
    for fmt in fmt_candidates:
        try:
            dt = datetime.strptime(s, fmt)
            # Sadece saat verildiyse bugunun tarihine yasla.
            if fmt in ("%H:%M:%S", "%H:%M"):
                today = datetime.now()
                dt = dt.replace(year=today.year, month=today.month, day=today.day)
            # Yerel -> UTC
            return dt.astimezone().astimezone(timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Zaman ayristirilamadi: '{s}' (orn. '2026-08-07 21:30:00')")


def print_dist(title, counter, total):
    """Bir sayac dagilimini hizali tablo olarak basar."""
    print(f"\n--- {title} ---")
    if not counter:
        print("  (kayit yok)")
        return
    width = max(len(str(k)) for k in counter.keys())
    for key, cnt in counter.most_common():
        pct = (100.0 * cnt / total) if total else 0.0
        print(f"  {str(key):<{width}}  {cnt:>6}  ({pct:5.1f}%)")


def summarize_numeric(title, values):
    """Sayisal alan (ood_distance / risk_score) icin ozet istatistik."""
    print(f"\n--- {title} ---")
    vals = [v for v in values if isinstance(v, (int, float))]
    if not vals:
        print("  (sayisal deger yok / hep None)")
        return
    vals_sorted = sorted(vals)
    n = len(vals_sorted)
    mn = vals_sorted[0]
    mx = vals_sorted[-1]
    med = vals_sorted[n // 2]
    avg = sum(vals_sorted) / n
    print(f"  n={n}  min={mn:.4f}  medyan={med:.4f}  ort={avg:.4f}  max={mx:.4f}")


def main():
    ap = argparse.ArgumentParser(description="Canli-ates sonrasi Mongo analizi")
    ap.add_argument("--start", help="Baslangic (yerel zaman, orn. '2026-08-07 21:30:00')")
    ap.add_argument("--end", help="Bitis (yerel zaman); verilmezse simdi")
    ap.add_argument("--last", type=int, help="Son N dakika (start/end yerine kisayol)")
    ap.add_argument("--attacker-ip", help="Pi'nin IP'si; bu IP'den gelen trafik 'gercek saldiri' sayilir")
    ap.add_argument("--source", default="live", help="source alani filtresi (varsayilan 'live'; 'all' = filtre yok)")
    args = ap.parse_args()

    # --- Zaman araligi ---
    if args.last is not None:
        end_utc = datetime.now(timezone.utc)
        start_utc = end_utc - timedelta(minutes=args.last)
    else:
        if not args.start:
            print("[HATA] --last N ya da --start/--end verilmeli.")
            sys.exit(1)
        start_utc = parse_local_dt(args.start)
        end_utc = parse_local_dt(args.end) if args.end else datetime.now(timezone.utc)

    # --- Baglan ---
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        client.admin.command("ping")
        coll = client[MONGO_DB][MONGO_COLLECTION]
    except PyMongoError as e:
        print(f"[HATA] MongoDB'ye baglanilamadi: {e}")
        sys.exit(1)

    query = {"timestamp": {"$gte": start_utc, "$lte": end_utc}}
    if args.source and args.source.lower() != "all":
        query["source"] = args.source

    docs = list(coll.find(query))
    total = len(docs)

    print("=" * 64)
    print(" CANLI-ATES SONRASI MONGO ANALIZI")
    print("=" * 64)
    print(f" Koleksiyon : {MONGO_DB}.{MONGO_COLLECTION}")
    print(f" Aralik(UTC): {start_utc.isoformat()}  ->  {end_utc.isoformat()}")
    print(f" source     : {args.source}")
    print(f" Kayit sayisi: {total}")
    if total == 0:
        print("\n[i] Bu aralikta kayit yok. --last degerini artir veya --source all dene.")
        return

    # --- Dagilimlar ---
    print_dist("status dagilimi", Counter(d.get("status") for d in docs), total)
    print_dist("predicted_class dagilimi", Counter(d.get("predicted_class") for d in docs), total)
    print_dist("suppressed_by dagilimi", Counter(d.get("suppressed_by") for d in docs), total)
    print_dist("ood_gate_applied dagilimi", Counter(d.get("ood_gate_applied") for d in docs), total)
    print_dist("is_volumetric dagilimi", Counter(d.get("is_volumetric") for d in docs), total)
    print_dist("attack_type dagilimi", Counter(d.get("attack_type") for d in docs), total)
    print_dist("detected_attack_name dagilimi", Counter(d.get("detected_attack_name") for d in docs), total)

    summarize_numeric("ood_distance ozeti", [d.get("ood_distance") for d in docs])
    summarize_numeric("risk_score ozeti", [d.get("risk_score") for d in docs])

    # --- Kaynak IP dagilimi (Pi trafigini ayirt etmek icin) ---
    print_dist("src_ip dagilimi", Counter(d.get("src_ip") for d in docs), total)

    # ========================================================================
    #  ASIL BULGU: gercek saldiri (Pi'den) yanlislikla UNKNOWN/BENIGN'e dustu mu?
    # ========================================================================
    print("\n" + "=" * 64)
    print(" ASIL SORU: gercek saldiri YANLISLIKLA bastirildi/kacirildi mi?")
    print("=" * 64)

    if args.attacker_ip:
        attack_docs = [d for d in docs if d.get("src_ip") == args.attacker_ip]
        print(f" Saldirgan IP '{args.attacker_ip}' -> {len(attack_docs)} kayit incelendi.")
    else:
        # attacker-ip verilmediyse: tum non-BENIGN-beklenen trafik yerine
        # tum kayitlar taranir, ama uyarilir.
        attack_docs = docs
        print(" [i] --attacker-ip verilmedi; TUM kayitlar taraniyor.")
        print("     Pi IP'sini verirsen (--attacker-ip) sadece saldiri trafigi suzulur.")

    # BENIGN = sessiz kacirma (tehlikeli); UNKNOWN = atfetme boslugu (hala alarm)
    benign_miss = [d for d in attack_docs if d.get("status") == "BENIGN"]
    unknown_gap = [d for d in attack_docs if d.get("status") == "UNKNOWN"]
    suppressed = [d for d in attack_docs if d.get("suppressed_by")]

    def show_rows(rows, limit=25):
        for d in rows[:limit]:
            ts = d.get("timestamp")
            ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
            print("   - {ts} | {src}:{sp} -> {dst}:{dp} | status={st} | "
                  "pred={pc} | supp={su} | ood={od} | gate={ga} | risk={rs}".format(
                      ts=ts_str,
                      src=d.get("src_ip"), sp=d.get("src_port"),
                      dst=d.get("dst_ip"), dp=d.get("dst_port"),
                      st=d.get("status"), pc=d.get("predicted_class"),
                      su=d.get("suppressed_by"),
                      od=(round(d["ood_distance"], 3) if isinstance(d.get("ood_distance"), (int, float)) else None),
                      ga=d.get("ood_gate_applied"),
                      rs=(round(d["risk_score"], 3) if isinstance(d.get("risk_score"), (int, float)) else None),
                  ))
        if len(rows) > limit:
            print(f"   ... ({len(rows) - limit} kayit daha)")

    print("\n>>> [KRITIK] status=BENIGN olan saldiri paketleri (SESSIZ KACIRMA):")
    if benign_miss:
        print(f"    {len(benign_miss)} kayit -- BU CIDDI: gercek saldiri BENIGN'e dustu.")
        show_rows(benign_miss)
    else:
        print("    Yok. (Hicbir saldiri paketi sessizce BENIGN'e dusmedi -- iyi.)")

    print("\n>>> [DIKKAT] status=UNKNOWN olan saldiri paketleri (ATFETME BOSLUGU, alarm sayilir):")
    if unknown_gap:
        print(f"    {len(unknown_gap)} kayit -- kacirma DEGIL; tespit var, sinif atfetme eksik.")
        show_rows(unknown_gap)
    else:
        print("    Yok.")

    print("\n>>> [INCELE] suppressed_by DOLU olan saldiri paketleri (bir kapi bastirdi):")
    if suppressed:
        print(f"    {len(suppressed)} kayit -- status!=ATTACK olanlar gercek-saldiri-bastirma adayidir.")
        show_rows(suppressed)
    else:
        print("    Yok. (Hicbir kapi tetiklenmedi.)")

    print("\n" + "=" * 64)
    print(" Ozet: BENIGN-kacirma={b}  UNKNOWN-bosluk={u}  bastirilan={s}".format(
        b=len(benign_miss), u=len(unknown_gap), s=len(suppressed)))
    print(" -> BENIGN-kacirma > 0 ise yeni bir R30 turu acilmali (asil bulgu).")
    print("=" * 64)


if __name__ == "__main__":
    main()
