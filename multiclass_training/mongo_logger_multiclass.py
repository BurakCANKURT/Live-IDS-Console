# -*- coding: utf-8 -*-
"""
mongo_logger_multiclass.py
============================
pipeline/mongo_logger.py'nin multiclass surumu (BAGIMSIZ KOPYA - ikili
mongo_logger.py degistirilmedi). process_pcap_multiclass.py'in skorladigi
HER paketi MongoDB'ye "saldiri-bazli" kayit olarak yazar. dashboard_api.py
BUNU import etmez - ayni MONGO_URI/MONGO_DB/MONGO_COLLECTION konvansiyonu
uzerinden ayni koleksiyonu okur.

TEK FARK (ikili mongo_logger.py'ye gore): predicted_class alani -- multiclass
dispatcher'in ham sinif tahminini (MC1 kapsami, 7 sinif: BENIGN/DDoS/DoS/
FTP-Patator/PortScan/SSH-Patator/WebAttack) tasir. Bot ve Infiltration
MC1'de kapsam disi birakildi.

NOT: asagidaki _classify_attack_type() SINIF ADINA gore degil, mekanizma
alt-dizelerine (Tarama/Hacimsel/Davranissal/LSTM) gore eslesir; bu yuzden
kapsam daralmasindan etkilenmez ve olu kod barindirmaz.

Kullanim (process_pcap_multiclass.py icinde):
    import mongo_logger_multiclass as mongo_logger
    mongo_logger.log_prediction(packet, src_ip, dst_ip, risk_score, status,
                                 ALERT_THRESHOLD, detected_attack_name,
                                 model_name, is_volumetric,
                                 alert_source=alert_source,
                                 predicted_class=predicted_class)

MongoDB erisilemezse `log_prediction` sessizce False doner (STATS['failures']
artar) - canli Kafka tuketimi bu yuzden DURMAZ.
"""

import atexit
import os
import queue
import threading
from datetime import datetime, timezone

from pymongo import MongoClient
from pymongo.errors import PyMongoError

MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.environ.get("MONGO_DB", "ids_db")
MONGO_COLLECTION = os.environ.get("MONGO_COLLECTION", "predictions")

try:
    _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
    _client.admin.command("ping")
    _collection = _client[MONGO_DB][MONGO_COLLECTION]
    print(f"[mongo_logger_multiclass] baglandi: {MONGO_URI} -> {MONGO_DB}.{MONGO_COLLECTION}")
except PyMongoError as e:
    print(f"[mongo_logger_multiclass] MongoDB'ye baglanilamadi, kayit devre disi: {e}")
    _collection = None

STATS = {"writes": 0, "failures": 0, "queued": 0, "dropped": 0, "max_depth": 0}

# ── ASENKRON YAZMA (parite -- bkz. pipeline/mongo_logger.py'deki uzun not) ──
# `insert_one` paket basina 0.68ms'lik SENKRON ag gidis-donusuydu ve tespit
# dongusunu bloke ediyordu. Artik dokuman kuyruga birakilir, ayri bir
# arka-plan thread'i yazar. GRUPLAMA DEGIL: her paket kendi tekil dokumanini
# alir; yazici yalnizca O AN hazir olani tek gidis-donuste gonderir, gecikme
# eklemek icin BEKLEMEZ. Risk: surec cokerse kuyruktaki birkac kayit kaybolur.
_QUEUE_MAX = int(os.environ.get("MONGO_QUEUE_MAX", "200000"))
_DRAIN_MAX = 256
_queue = queue.Queue(maxsize=_QUEUE_MAX)
_writer_thread = None
_STOP = object()


def _writer_loop():
    while True:
        item = _queue.get()
        if item is _STOP:
            _queue.task_done()
            return
        batch = [item]
        while len(batch) < _DRAIN_MAX:
            try:
                nxt = _queue.get_nowait()
            except queue.Empty:
                break
            if nxt is _STOP:
                _flush(batch)
                for _ in batch:
                    _queue.task_done()
                _queue.task_done()
                return
            batch.append(nxt)
        _flush(batch)
        for _ in batch:
            _queue.task_done()


def _flush(docs):
    if not docs or _collection is None:
        return
    try:
        if len(docs) == 1:
            _collection.insert_one(docs[0])
        else:
            _collection.insert_many(docs, ordered=False)
        STATS["writes"] += len(docs)
    except PyMongoError:
        STATS["failures"] += len(docs)


def _ensure_writer():
    global _writer_thread
    if _collection is None:
        return
    if _writer_thread is None or not _writer_thread.is_alive():
        _writer_thread = threading.Thread(target=_writer_loop,
                                           name="mongo-writer-multiclass", daemon=True)
        _writer_thread.start()


def flush_and_close(timeout=5.0):
    if _writer_thread is None or not _writer_thread.is_alive():
        return
    try:
        _queue.put_nowait(_STOP)
    except queue.Full:
        return
    _writer_thread.join(timeout=timeout)


atexit.register(flush_and_close)


def _to_int(value, default=0):
    try:
        if value is None or value == "":
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _classify_attack_type(detected_attack_name, dst_port, status, src_port=None):
    """Mekanizma-bazli kaba alt-siniflandirma (dashboard rozetleri icin).

    Multiclass'ta gercek saldiri sinifi zaten `predicted_class` alaninda var;
    bu fonksiyon ikili surumle AYNI kalir (dashboard_v2.html'in eski
    rozet kumesiyle uyumlu olsun diye) -- detected_attack_name string'leri
    (offline_test_multiclass.py ile ayni format: "Hacimsel/SYN-Flood -> X",
    "Port-Tarama -> X", "Zamansal Anomali -> LSTM: X") ayni alt-dizeleri
    (Tarama/Hacimsel/Davranışsal/LSTM) tasidigi icin eslesme degismiyor.

    src_port da kontrol edilir: bir akisin SUNUCU->ISTEMCI (yanit) yonundeki
    paketinde dst_port istemcinin DEGISEN efemer portudur, src_port ise
    sabit servis portudur (21/22/80/443). Sadece dst_port'a bakmak, FTP-Patator
    gibi iki-yonlu skorlanan saldirilarin yanit-yonu paketlerini "Sınıflandırılamadı"
    kovasina dusuruyordu (predicted_class dogru -- "FTP-Patator" -- olsa da).
    Bkz. canli Mongo kaniti: src_port=21/dst_port=55588 yanit paketleri."""
    if status == "BENIGN":
        return "BENIGN"
    # (R19/R20 parite -- bkz. pipeline/mongo_logger.py) OOD/kapsam-disi kapisi
    # tetiklendi -- risk_score ATTACK/BENIGN esigini gecmis olabilir ama nihai
    # karar kasitli olarak UNKNOWN'dir (adli inceleme icin ham skor korunur).
    if status == "UNKNOWN":
        return "Kapsam Dışı (OOD)"
    if "Tarama" in detected_attack_name:
        return "Çoklu-Port Tarama"
    if ("SYN-Flood" in detected_attack_name or "Hacimsel" in detected_attack_name):
        return "Hacimsel/Tekrarlı"
    if ("Davranışsal" in detected_attack_name or "Zamansal" in detected_attack_name or "LSTM" in detected_attack_name):
        ports = (dst_port, src_port) if src_port is not None else (dst_port,)
        if 21 in ports or 22 in ports:
            return "Davranışsal (Tekrarlı-İstek)"
        if 80 in ports or 443 in ports or 8080 in ports:
            return "Davranışsal (Web/Uygulama)"
    return "Sınıflandırılamadı"


# (parite -- bkz. pipeline/mongo_logger.py) HIGH/CRITICAL skor tabani.
HIGH_SEVERITY_SCORE = 0.7


def _severity_from_score(risk_score, alert_threshold, status=None,
                          is_volumetric=False):
    """Severity rozeti (ikili surumle BIREBIR parite -- bkz.
    pipeline/mongo_logger.py'deki uzun gerekce). CRITICAL MEKANIZMA-TABANLI:
    deterministik VOLUMETRIK imza (is_volumetric=True) VE skor >= HIGH tabani
    birlikte gerektirir; volumetrik-ama-dusuk-skorlu ya da yuksek-skorlu-ama-
    davranissal olaylar CRITICAL olmaz. Karar mantigini ETKILEMEZ."""
    # (R19/R20 parite -- bkz. pipeline/mongo_logger.py) OOD kapisi: risk_score
    # bilerek DOKUNULMADAN birakilir (adli inceleme icin ham model guveni),
    # ama HIGH/MEDIUM rozeti yanlis "bu kesin saldiri" izlenimi verir --
    # durum zaten ATTACK/BENIGN degil.
    if status == "UNKNOWN":
        return "INFO"
    if risk_score >= HIGH_SEVERITY_SCORE:
        return "CRITICAL" if is_volumetric else "HIGH"
    if risk_score >= alert_threshold:
        return "MEDIUM"
    return "LOW"


def log_prediction(packet, src_ip, dst_ip, risk_score, status, alert_threshold,
                    detected_attack_name, model_name, is_volumetric,
                    alert_source=None, predicted_class=None, source_mode=None,
                    ood_distance=None, suppressed_by=None, ood_pvalue=None,
                    ood_gate_applied=None, dst_is_multicast=None,
                    lstm_score=None, counter_score=None, prog_pkts=None,
                    susp_ratio=None, flow_dst_port=None,
                    flood_app_layer_ambiguous=None):
    """Tek bir skorlanmis paketi MongoDB'ye yazar. Basariliysa True doner.

    lstm_score/counter_score/prog_pkts/susp_ratio/flow_dst_port
    (N3 parite -- pipeline/mongo_logger.py'deki ayni alanlardan port edildi):
    sadece LSTM+Counter dalinda dolu gelir (volumetrik/RF dalinda None kalir).
    Onceden multiclass yalnizca birlesik risk_score'u yaziyordu -- bir
    multiclass alarminin LSTM'den mi Progressive Counter'dan mi geldigini
    Mongo'dan ayirt etmek IMKANSIZDI (ikili hatta bu alanlar vardi; ESP32
    canli-ates denetimi ikili 28490/28490 dolu, multiclass 0/28534 olcmustu).
    flow_dst_port, paketin kendi tcp/udp.dstport'undan (asagidaki dst_port)
    FARKLI olabilir: akisin CANONICAL (yon-duzeltmesinden sonraki) hedef
    portudur -- ikisi arasindaki fark, akis yonu tersine donmus mu diye
    dogrudan sorgulanabilir.

    source_mode (R17 parite -- bkz. pipeline/mongo_logger.py): "live"/"replay"/
    "unknown". Canli ve replay/NiFi kayitlarinin ayni koleksiyonda karisip
    FAR olcumunu kirletmemesi icin populasyon bazinda filtrelenebilir.
    ood_distance (R19/R20 parite): 1-NN mesafesi (adli inceleme icin).
    dst_is_multicast (R29/O3): hedef multicast/broadcast kesif araliginda mi
    (R23 kapisinin on-kosulu). Esik-alti kalan mDNS/SSDP/LLMNR paketlerini
    BENIGN yiginindan ayirmak icin -- onceden yalnizca bastirilmis olanlar
    (suppressed_by=="multicast") gorunuyordu.
    ood_gate_applied (R29/O4): mesafenin KARARA etki edip etmedigi.
    True -> non-volumetrik dal (R20 kapisi aktif, mesafe>esik ise UNKNOWN);
    False -> volumetrik dal, mesafe SADECE OLCULUP loglanir (karar
    deterministik hacimsel imzada kalir). O4 volumetrik dala olcum ekledigi
    icin bu ayrim zorunlu.
    ood_pvalue (S5 -- conformal p-deger): ood_distance'in kalibrasyon kumesine
    gore istatistiksel "olaganlik" olcusu (kucuk = olagandisi); risk_score/
    alarm mantigini ETKILEMEZ, sadece raporlanir.
    suppressed_by (S4 -- bkz. project-ids-generalization-strategist agent
    memory): risk_score esigi ASIP sonra bir kapi tarafindan bastirildiysa o
    kapinin adi ("immature_flow"/"unverified_orientation"/"multicast"/
    "port_bucket_veto"/"low_syn_dos_gate"/"webattack_abs_floor"/
    "argmax_consistency"/"ood"/"committee_dissent" [R26 Faz 1]/
    "scan_rf_benign" [R27, volumetrik dal Strateji-C]), aksi halde None.
    Aktif-ogrenme/inceleme kuyrugunun temeli:
    `analysis/review_suppressed_queue.py` ile sorgulanir.
    flood_app_layer_ambiguous (R37/D1): YALNIZCA hacimsel dalin RF-override
    kollarinda (imza etiketi KENDISI uretti) dolar; diger tum yollarda None.
    True -> akisin kanonik hedef portu APP_LAYER_FLOOD_PORTS icinde (80/443/
    3000/8000/8080/8443/8888), yani bu koldan uretilen "DoS"/"DDoS" etiketi
    ile bir WebAttack-flood AYIRT EDILEMEZ; predicted_class kanonik sozlukte
    kalir ama analist bu bayrakla belirsiz vakalari tek sorguda ayirabilir
    (R36 kok-neden notu: ESP32'nin port-80/3000 WebAttack'i bu kolda 1798 kez
    kosulsuz "DoS" etiketlenmisti)."""
    if _collection is None:
        return False

    dst_port = _to_int(packet.get("tcp.dstport") or packet.get("udp.dstport"), 0)
    src_port = _to_int(packet.get("tcp.srcport") or packet.get("udp.srcport"), 0)

    doc = {
        "timestamp": datetime.now(timezone.utc),
        "frame_number": packet.get("frame.number"),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "risk_score": float(risk_score),
        "status": status,
        "attack_type": _classify_attack_type(detected_attack_name, dst_port, status, src_port=src_port),
        "predicted_class": predicted_class,
        "severity": _severity_from_score(risk_score, alert_threshold, status=status,
                                          is_volumetric=bool(is_volumetric)),
        "is_volumetric": bool(is_volumetric),
        "model": model_name,
        "detected_attack_name": detected_attack_name,
        "ood_distance": ood_distance,
        "ood_pvalue": ood_pvalue,
        "ood_gate_applied": ood_gate_applied,
        "dst_is_multicast": dst_is_multicast,
        "alert_source": alert_source,
        "source": source_mode,
        "suppressed_by": suppressed_by,
        # (N3 parite) ikili hattaki ayni adli alanlar -- bkz. docstring.
        "lstm_score": lstm_score,
        "counter_score": counter_score,
        "prog_pkts": prog_pkts,
        "susp_ratio": susp_ratio,
        "flow_dst_port": flow_dst_port,
        # (R37/D1) bkz. docstring.
        "flood_app_layer_ambiguous": flood_app_layer_ambiguous,
    }
    # (ASENKRON parite) ag gidis-donusunu BEKLEME; kuyruga birak, hemen don.
    _ensure_writer()
    try:
        _queue.put_nowait(doc)
        STATS["queued"] += 1
        depth = _queue.qsize()
        if depth > STATS["max_depth"]:
            STATS["max_depth"] = depth
        return True
    except queue.Full:
        STATS["dropped"] += 1
        return False
