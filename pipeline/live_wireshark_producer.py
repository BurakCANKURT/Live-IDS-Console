# -*- coding: utf-8 -*-
"""
live_wireshark_producer.py
===========================
Gercek zamanli bir ag arayuzunden (Wi-Fi/Ethernet) CANLI paket yakalar
(tshark.exe, Npcap uzerinden) ve process_pcap.py'nin tukettigi
"network-traffic" Kafka topic'ine, NiFi'nin dosya-tabanli akisiyla AYNI
16 alanlik semada (+ R17 ile eklenen 3 IPv6 alani) JSON paketler olarak basar.

Bu script, NiFi'nin ListFile/FetchFile + "tshark -r <dosya>" (kayitli pcap
dosyasi oynatma) akisinin CANLI-YAKALAMA (tshark -i <arayuz>) karsiligidir.
Sema ve Kafka topic'i birebir ayni oldugundan process_pcap.py'de hicbir
degisiklik gerekmez.

Calistirma:
    python live_wireshark_producer.py --interface "Wi-Fi"
    python live_wireshark_producer.py --interface "Wi-Fi,Ethernet"   # ikisi birden

Kullanilabilir arayuz isimleri icin:
    "C:\\Program Files\\Wireshark\\tshark.exe" -D

--interface virgulle ayrilmis birden fazla arayuz adi alabilir; tshark her
biri icin ayri bir -i bayragi alir ve ikisini TEK sureçte, tek pcapng
ring'ine interleave ederek yakalar (frame.number global/monoton kalir --
bkz. asagidaki B1 yorumu). Boylece kullanici hangi arayuzun o an aktif
oldugunu (Wi-Fi mi Ethernet mi) onceden bilmek zorunda kalmaz; ikisi de
takipte olur, biri kopse/kablosuz gucu kesilse bile diger arayuz yakalamaya
devam eder.
"""
import argparse
import json
import os
import subprocess
import sys

TSHARK_PATH = os.environ.get("TSHARK", r"C:\Program Files\Wireshark\tshark.exe")

# (B1) Ham (raw) yakalama dizini -- Wireshark-tarzi "paketi ac/indir"
# ozelligi icin gerekli: -T fields sadece 19 turetilmis alani gonderiyor,
# ham baytlar hicbir yerde saklanmiyordu. tshark AYNI process'te hem -w
# (ham pcapng, ring-buffer) hem -T fields (mevcut JSON akisi) uretebiliyor
# -- ampirik olarak dogrulandi (tek process, dissection tek gecis; -w
# devredisi birakmaz). frame.number, ring dosyalari arasinda GLOBAL
# olarak artmaya devam eder (rotasyonla SIFIRLANMAZ) -- bu da ayni
# frame_number'in C++ tarafindan tek-paket sorgusu icin dogrudan
# kullanilabilmesini saglar (bkz. pipeline_orchestrator.cpp'deki B3).
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RING_DIR = os.path.join(_ROOT, "console", "capture_ring")
# MB cinsinden dosya basi boyut; 0 = ham yakalama KAPALI (sadece -T fields,
# eski davranis). Varsayilan 50MB x 10 dosya = ~500MB donen pencere.
RING_FILE_MB = int(os.environ.get("IDS_CAPTURE_RING_MB", "50"))
RING_FILE_COUNT = int(os.environ.get("IDS_CAPTURE_RING_FILES", "10"))

# (R17) TOPIC IZOLASYONU: canli yakalama ile NiFi dosya-replay'i AYNI topic'i
# paylasinca, process_pcap.py yeniden baslatildiginda eski replay saldiri
# paketleri yeniden tuketilip "taze canli alarm" gibi Mongo'ya yaziliyordu.
# Ayni env degiskeni (KAFKA_TOPIC) process_pcap.py tarafinda da okunur ->
# `set KAFKA_TOPIC=network-traffic-live` iki tarafi birlikte izole eder.
# Varsayilan DEGISMEDI (geriye uyumluluk).
TOPIC_NAME = os.environ.get("KAFKA_TOPIC", "network-traffic")

# NiFi'nin ExecuteStreamCommand (tshark) processor'undeki Command Arguments
# ile ayni alan listesi/sirasi -- process_pcap.py bu isimlerle
# packet.get(...) yapiyor (bkz. process_pcap.py _to_int/_to_float cagrilari).
#
# (R17) IPv6 ALANLARI EKLENDI (ipv6.src / ipv6.dst / ipv6.nxt).
# KOK NEDEN: process_pcap.py'nin _get_src_ip/_get_dst_ip fonksiyonlari IPv6
# fallback'i ICERIYORDU ama bu producer o alanlari tshark'tan HIC cekmiyordu
# -> fallback OLU KOD, STATS["ipv6_packets"] hep 0. Gercek Wi-Fi'da her IPv6
# paketi src=dst="0.0.0.0" olup TEK sahte akista/volumetrik sayacta birikiyordu.
# ipv6.nxt (Next Header) IPv6'nin ip.proto karsiligidir; onsuz tum IPv6
# trafigi TCP(6) varsayiliyordu (QUIC/UDP dahil).
# NiFi TARAFI: replay korpusu (CICIDS-2017 pcap'leri) SAF IPv4'tur; bu yuzden
# NiFi ExecuteStreamCommand + analysis/nifi_csvreader_schema.avsc semasi 16
# alanda BIRAKILDI (senkron degisiklik GEREKMIYOR). NiFi'ye IPv6 tasiyan bir
# capture beslenirse sema ve tshark argumanlari birlikte guncellenmelidir --
# process_pcap.py eksik alanlari packet.get() ile None gorup tolere eder.
FIELDS = [
    "frame.number", "frame.time_epoch", "frame.len",
    "ip.src", "ip.dst", "ip.proto", "ip.hdr_len",
    "tcp.srcport", "tcp.dstport", "tcp.len", "tcp.hdr_len",
    "udp.srcport", "udp.dstport", "udp.length",
    "tcp.flags", "tcp.window_size_value",
    "ipv6.src", "ipv6.dst", "ipv6.nxt",
]


def build_tshark_cmd(interfaces):
    cmd = [TSHARK_PATH]
    for iface in interfaces:
        cmd += ["-i", iface]  # tekrarlanan -i: tshark bunlari TEK sureçte interleave ederek yakalar
    cmd += ["-l"]  # -l: paket basina hemen flush (gercek-zamanli)
    if RING_FILE_MB > 0:
        os.makedirs(RING_DIR, exist_ok=True)
        cmd += ["-w", os.path.join(RING_DIR, "cap.pcapng")]
        cmd += ["-b", f"filesize:{RING_FILE_MB * 1024}", "-b", f"files:{RING_FILE_COUNT}"]
    cmd += ["-T", "fields"]
    for f in FIELDS:
        cmd += ["-e", f]
    cmd += ["-E", "header=n", "-E", "separator=,", "-E", "occurrence=f", "-E", "quote=n"]
    return cmd


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--interface", default="Wi-Fi,Ethernet",
                    help='tshark -D ciktisindaki arayuz adi/adlari, birden fazlaysa virgulle ayir '
                         '(varsayilan: "Wi-Fi,Ethernet" -- ikisi birden takip edilir)')
    ap.add_argument("--bootstrap-servers", default="127.0.0.1:9092")
    ap.add_argument("--topic", default=TOPIC_NAME,
                    help="Kafka topic (varsayilan: KAFKA_TOPIC env ya da 'network-traffic'). "
                         "Canli kosuyu replay'den ayirmak icin process_pcap.py ile AYNI degeri kullan.")
    # (C++ orkestrasyon parite) Kafka/Zookeeper/MongoDB/WSL2 bagimliligini
    # kaldirmak icin: --sink stdout ile bu script Kafka'ya HIC dokunmadan
    # (kafka-python import bile edilmez -- Windows'ta gozlemlenen flaky
    # selector hatasini da otomatik olarak ortadan kaldirir) her paketi TEK
    # SATIR JSON olarak stdout'a basar. ids_dashboard.exe bu stdout'u okuyup
    # process_pcap.py/process_pcap_multiclass.py'nin --input stdin moduna
    # fan-out eder (bkz. o dosyalardaki ayni degisiklik). Sema/alan sirasi
    # BIREBIR AYNI kaliyor -- tuketici tarafinda hicbir kod degismez.
    ap.add_argument("--sink", choices=["kafka", "stdout"], default="kafka",
                    help="kafka (varsayilan, geriye-uyumlu) veya stdout (C++ orkestrasyon icin)")
    args = ap.parse_args()
    topic = args.topic

    interfaces = [x.strip() for x in args.interface.split(",") if x.strip()]
    if not interfaces:
        print("[live_wireshark_producer] HATA: --interface bos/gecersiz", file=sys.stderr)
        sys.exit(1)

    cmd = build_tshark_cmd(interfaces)
    count = 0
    iface_label = ", ".join(interfaces)

    if args.sink == "stdout":
        print(f"[live_wireshark_producer] canli yakalama basliyor (stdout modu) -> arayuz(ler): {iface_label}",
              file=sys.stderr, flush=True)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        try:
            for line in proc.stdout:
                line = line.rstrip("\n")
                if not line or line.startswith("Capturing on"):
                    continue
                parts = line.split(",")
                if len(parts) != len(FIELDS):
                    continue
                packet = {name: (val if val != "" else None) for name, val in zip(FIELDS, parts)}
                sys.stdout.write(json.dumps(packet) + "\n")
                sys.stdout.flush()
                count += 1
        except KeyboardInterrupt:
            print(f"\n[live_wireshark_producer] durduruldu. Toplam: {count} paket", file=sys.stderr)
        finally:
            proc.terminate()
        return

    from kafka import KafkaProducer  # (stdout modunda hic import edilmez)
    print(f"[live_wireshark_producer] Kafka'ya baglaniliyor: {args.bootstrap_servers}")
    producer = KafkaProducer(
        bootstrap_servers=[args.bootstrap_servers],
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    print(f"[live_wireshark_producer] canli yakalama basliyor -> arayuz(ler): {iface_label}")
    print(f"[live_wireshark_producer] Kafka topic: {topic}")
    print("Durdurmak icin Ctrl+C\n")

    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)

    try:
        for line in proc.stdout:
            line = line.rstrip("\n")
            if not line or line.startswith("Capturing on"):
                continue
            parts = line.split(",")
            if len(parts) != len(FIELDS):
                continue
            packet = {name: (val if val != "" else None) for name, val in zip(FIELDS, parts)}
            producer.send(topic, packet)
            count += 1
            if count % 200 == 0:
                print(f"[live_wireshark_producer] {count} paket Kafka'ya gonderildi...")
    except KeyboardInterrupt:
        print(f"\n[live_wireshark_producer] kullanici tarafindan durduruldu. Toplam: {count} paket")
    finally:
        producer.flush()
        proc.terminate()


if __name__ == "__main__":
    main()
