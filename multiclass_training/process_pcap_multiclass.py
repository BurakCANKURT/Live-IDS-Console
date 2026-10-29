import json
import os
import sys
import time
import warnings
import zipfile
import io
import h5py
import pandas as pd
import numpy as np
from collections import defaultdict

# (C++ orkestrasyon) process_pcap.py'deki AYNI YEREL IPC deseni: Kafka/
# Zookeeper/MongoDB/WSL2 gerekmeden, ids_dashboard.exe'nin dogrudan
# spawn edip pipe ile besledigi/okudugu bir mod. Varsayilan degismedi
# (geriye uyumlu, INPUT_MODE=kafka/OUTPUT_MODE=mongo).
INPUT_MODE = os.environ.get("INPUT_MODE", "kafka")
OUTPUT_MODE = os.environ.get("OUTPUT_MODE", "mongo")
if INPUT_MODE == "kafka":
    from kafka import KafkaConsumer

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if OUTPUT_MODE == "stdout":
    # Mevcut TUM print() cagrilarini (ve mongo_logger'in kendi baglanti
    # mesajlarini) stderr'e yonlendirir -- stdout SADECE _emit_prediction()
    # ile yazilan tek-satir JSON tahminler icin temiz kalir (bkz. asagida).
    sys.stdout = sys.stderr
import mongo_logger_multiclass as mongo_logger


def _emit_prediction(doc):
    """(C++ orkestrasyon) OUTPUT_MODE=stdout ise, bu paketin tahminini TEK
    SATIR JSON olarak GERCEK stdout'a (sys.__stdout__, yonlendirmeden
    etkilenmez) yazar. mongo_logger'a PARALEL calisir, onun yerine gecmez --
    Mongo hala calisiyorsa (opsiyonel) kayit da olur."""
    if OUTPUT_MODE != "stdout":
        return
    sys.__stdout__.write(json.dumps(doc, default=str) + "\n")
    sys.__stdout__.flush()


def _emit_ready():
    """(B7 -- C++ orkestrasyon) Model yuklemesi bitip _packet_source()'un ilk
    paketi icin BLOKE OLMADAN HEMEN ONCE, tek seferlik bir kontrol satiri
    yazar: {"event":"ready"}. pipeline_orchestrator.cpp bunu gorunce tshark'i
    ANCAK O ZAMAN baslatir (bkz. ProducerLaunchWatcherLoop) -- ayni gerekce
    process_pcap.py'deki esdegeriyle (_emit_ready) birebir aynidir."""
    if OUTPUT_MODE != "stdout":
        return
    sys.__stdout__.write(json.dumps({"event": "ready"}) + "\n")
    sys.__stdout__.flush()

# ── 1. ORTAM HAZIRLIĞI ───────────────────────────────────────────────
warnings.filterwarnings("ignore", category=RuntimeWarning)

try:
    import joblib
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import LSTM, Dense, Dropout, Input
except ImportError as e:
    print(f"❌ Hata: Gerekli kütüphaneler yüklenemedi: {e}")
    sys.exit(1)

# =================================================================
# 2. MULTICLASS LSTM YÜKLEYİCİ -- process_pcap.py (ikili) ile AYNI teknik.
# tf.keras.models.load_model() bazı ortamlarda (Ubuntu canlı: yeni
# TF/Keras) eski .keras dosyasının LSTM config'indeki kaldırılmış
# kwarg'lara ("Unrecognized keyword arguments... time_major") takılıp
# hata verir. Bu yüzden config DESERIALIZE EDİLMEZ; H5 ağırlıkları
# çıkarılıp model SIFIRDAN (Sequential) çizilir ve ağırlıklar doğrudan
# set_weights ile şırınga edilir -- versiyon-bağımsız, deterministik.
# =================================================================
def build_and_load_dynamic_lstm(keras_path):
    """Multiclass LSTM mimarisi binary MainLSTM'den FARKLI (tek Dense değil,
    iki Dense katmanı var): Input(1,41) -> LSTM(64) -> Dropout -> Dense(32,
    relu) -> Dropout -> Dense(9, softmax). config.json ile doğrulandı.
    İsim-tabanlı eşleştirme (kernel/bias substring) bu modelde İŞE YARAMAZ --
    Keras 3 H5'inde ağırlıklar 'layers\\<ad>/vars/<i>' şeklinde indekslenmiş
    (kernel/bias adı yok). Bu yüzden katman adı ÖNEKİNE (lstm/cell, dense,
    dense_1) göre gruplanır; iki Dense önekinden alfabetik SONUNCUSU
    ("dense_1" > "dense") çıkış katmanıdır (process_pcap.py'deki
    dense_last_key=sorted(...)[-1] kuralıyla aynı mantık)."""
    print(f"🔧 H5 dosyasından dinamik mimari okunuyor (Multiclass LSTM)...")
    extracted = {}

    with zipfile.ZipFile(keras_path, 'r') as z:
        h5_file_name = next((name for name in z.namelist() if name.endswith('.h5')), None)
        with z.open(h5_file_name) as f:
            file_data = io.BytesIO(f.read())
            with h5py.File(file_data, 'r') as h5f:
                def visitor(name, node):
                    if isinstance(node, h5py.Dataset):
                        if "optimizer" not in name and "metrics" not in name:
                            extracted[name] = np.array(node)
                h5f.visititems(visitor)

    lstm_keys = sorted(k for k in extracted if "lstm" in k.lower() and "cell" in k.lower())
    lstm_k, lstm_r, lstm_b = (extracted[k] for k in lstm_keys[:3])

    dense_layer_names = sorted({k.split("/vars")[0] for k in extracted if "dense" in k.lower()})
    hidden_name, output_name = dense_layer_names[0], dense_layer_names[-1]
    hidden_k = extracted[f"{hidden_name}/vars/0"]
    hidden_b = extracted[f"{hidden_name}/vars/1"]
    output_k = extracted[f"{output_name}/vars/0"]
    output_b = extracted[f"{output_name}/vars/1"]

    n_feat = lstm_k.shape[0]
    units = lstm_b.shape[0] // 4
    hidden_units = hidden_k.shape[1]
    n_classes = output_k.shape[1]

    print(f"📐 Multiclass LSTM Keşfedildi: input_dim={n_feat}, lstm_units={units}, "
          f"hidden_units={hidden_units}, n_classes={n_classes}")

    model = Sequential([
        Input(shape=(1, n_feat)),
        LSTM(units),
        Dropout(0.3),
        Dense(hidden_units, activation='relu'),
        Dropout(0.3),
        Dense(n_classes, activation='softmax'),
    ])

    model.set_weights([lstm_k, lstm_r, lstm_b, hidden_k, hidden_b, output_k, output_b])
    print("✅ Multiclass LSTM başarıyla çizildi ve ağırlıklar %100 uyumla şırınga edildi!")
    return model


# =================================================================
# 3. MULTICLASS ÜRETİM MODELLERİNİ YÜKLEME
# =================================================================
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
MC_BUNDLE_PATH = os.path.join(THIS_DIR, "models", "MulticlassRF_bundle.joblib")
MC_RF_PATH = os.path.join(THIS_DIR, "models", "MulticlassRF.joblib")
MC_LSTM_PATH = os.path.join(THIS_DIR, "models", "MulticlassLSTM.keras")

print("🧠 MULTICLASS ÜRETİM MODELLERİ YÜKLENİYOR...")
print("=" * 70)

try:
    bundle = joblib.load(MC_BUNDLE_PATH)
    PIPELINE = bundle["pipeline"]
    RAW_COLUMNS = bundle["raw_columns"]
    CLASSES_LIST = bundle["classes"]
    N_CLASSES = bundle["n_classes"]
    BENIGN_INDEX = bundle["benign_index"]

    main_rf = joblib.load(MC_RF_PATH)
    if isinstance(main_rf, dict) and "model" in main_rf:
        main_rf = main_rf["model"]

    main_lstm = build_and_load_dynamic_lstm(MC_LSTM_PATH)

    # PERF (LSTM fast-path -- bkz. pipeline/process_pcap.py'deki ayni blok)
    # `.predict()` tek-paket cagrisinda ~90ms Python/callback overhead'i
    # ekliyor; tf.function icinde dogrudan cagri ~0.98ms (~92x). SADECE HIZ:
    # ayni agirliklar, ayni grafik, ayni float32 dtype -- sinif olasiliklari
    # ve dolayisiyla karar mantigi DEGISMEDI (dogrulama:
    # `analysis/verify_lstm_fastpath.py`, tolerans 1e-5).
    _LSTM_FAST = tf.function(
        lambda t: main_lstm(t, training=False),
        reduce_retracing=True,
    )

    print(f"   -> {N_CLASSES} sınıf: {CLASSES_LIST}")
    print(f"   -> BENIGN index: {BENIGN_INDEX}")
except Exception as e:
    print(f"❌ Kritik Hata: {e}")
    sys.exit(1)


def _feature_row(master_features):
    """(parite -- bkz. pipeline/process_pcap.py::_feature_row) master_features
    -> (1, n) numpy satiri, RAW_COLUMNS sirasinda. Tek-satir DataFrame ara
    katmanini kaldirir; giden dizi birebir aynidir."""
    return np.array([[float(master_features.get(col, 0.0)) for col in RAW_COLUMNS]],
                    dtype=np.float64)


def lstm_predict_fast(arr):
    """`main_lstm.predict(arr, verbose=0)` ile AYNI ciktiyi veren hizli yol.
    Hata durumunda sessizce eski yola duser (bkz. ikili hattaki ikizi)."""
    try:
        return np.asarray(_LSTM_FAST(tf.constant(arr, dtype=tf.float32)))
    except Exception:
        return main_lstm.predict(arr, verbose=0)

# =================================================================
# 3b. (R19/R20 parite) OOD/KAPSAM-DIŞI KAPISI -- yalnızca NON-VOLUMETRİK dal.
# process_pcap.py'nin OOD kapısıyla AYNI yöntem (1-NN Öklid, ham matvec), AYRI
# kalibrasyon: multiclass'ın KENDİ pipeline'ı (StandardScaler) binary'den
# farklı veriyle fit edildiği için binary'nin MainRF_v5__ood_reference.npz'i
# BU uzayda anlamsızdır -- referans multiclass_streaming_dataset.csv BENIGN
# (non-volumetrik-uygun maske: rate<500k | rate==1e6 | DNS bucket) satırlarından,
# multiclass PIPELINE'iyla ölçeklenerek YENİDEN üretildi (20.000 satır,
# analysis/mc_ood_calibrate.py kalibrasyon çıktısı, bkz. agent-memory notu).
# Ölçüm: BENIGN disjoint holdout p99.9=5.18/max=22.95 (0 eşik-üstü); eğitim
# ATK sınıfları max 5.4-52.6 (DDoS/DoS'ta 10-14/10000 eşik-üstü); GERÇEK
# HELD-OUT Wednesday Slowloris/Slowhttptest pcap (eğitim setinde YOK,
# fwd_packets>=1 filtresiyle) p99.9=9.58, 12/98785 (%0.012) eşik-üstü --
# binary R20'nin DoS-Hulk+ kaybıyla (11/60000) aynı büyüklük mertebesi.
# Eşik=30.0 (binary ile AYNI değer, AYRI ölçümle doğrulandı): BENIGN kuyruğunun
# rahatça üstünde, gerçek saldırı trafiğinin ezici çoğunluğunu kapsıyor.
# VARSAYIM (ÖLÇÜLEMEDİ): gerçek domain-shift trafiği (mDNS/SSDP/vb., R19'un
# Anthropic-akışı örneği) bu uzayda da rahatça 30'un üstünde kalır -- aynı v5
# öznitelik mühendisliği ve benzer (CICIDS tabanlı) benign dağılımı kullanıldığı
# için makul bir varsayım, ama binary'deki gibi gerçek bir "anchor" ölçümüyle
# DOĞRULANMADI. Referans dosyası yoksa kapı sessizce devre dışı kalır.
OOD_REF_PATH = os.path.join(THIS_DIR, "models", "MulticlassRF__ood_reference.npz")
OOD_DISTANCE_THRESHOLD = 30.0
OOD_REF = None
OOD_SQNORM = None
OOD_CALIB_SCORES = None  # (S5) conformal p-deger icin siralanmis kalibrasyon mesafeleri
if os.path.exists(OOD_REF_PATH):
    try:
        _ood_z = np.load(OOD_REF_PATH)
        OOD_REF = _ood_z["ref"].astype(np.float32)
        OOD_SQNORM = _ood_z["sqnorm"].astype(np.float32)
        if "calib_scores" in _ood_z:
            OOD_CALIB_SCORES = _ood_z["calib_scores"].astype(np.float32)
        print(f"🧭 OOD kapısı aktif: {os.path.basename(OOD_REF_PATH)} "
              f"({OOD_REF.shape[0]} referans nokta, eşik={OOD_DISTANCE_THRESHOLD}, "
              f"conformal-kalibrasyon={'var' if OOD_CALIB_SCORES is not None else 'yok'})")
    except Exception as _e:
        print(f"⚠️ OOD referansı yüklenemedi ({_e}); OOD kapısı DEVRE DIŞI.")
else:
    print(f"⚠️ OOD referans dosyası bulunamadı ({OOD_REF_PATH}); OOD kapısı DEVRE DIŞI.")


def ood_distance(scaled_row):
    """(R19/R20 parite) Ölçeklenmiş (41-d) öznitelik vektörünün multiclass
    eğitim-benign non-volumetrik manifolduna 1-NN Öklid mesafesi."""
    if OOD_REF is None:
        return None
    v = np.asarray(scaled_row, dtype=np.float32).ravel()
    d2 = OOD_SQNORM - 2.0 * (OOD_REF @ v) + float(v @ v)
    return float(np.sqrt(max(float(d2.min()), 0.0)))


def ood_pvalue(dist):
    """(S5 -- conformal p-değeri) `dist`in, GERÇEKTEN benign olduğu bilinen
    (referans noktalarının kendisinden AYRI) bir kalibrasyon kümesine göre ne
    kadar "olağan dışı" olduğunu standart conformal formülle ölçer:
        p = (1 + #{kalibrasyon_i : mesafe_i >= dist}) / (n_kalibrasyon + 1)
    Küçük p -> bu mesafe kalibrasyon kümesindeki NEREDEYSE HİÇBİR gerçek-benign
    noktadan daha uzak değil, yani "olağan dışı" (finite-sample garantili: rastgele
    bir yeni benign nokta için P(p <= α) <= α, α'dan bağımsız olarak -- bkz.
    Vovk/Gammerman/Shafer conformal prediction). risk_score/alarm mantığına
    DOKUNMAZ (OOD_DISTANCE_THRESHOLD hâlâ operasyonel karar) -- yalnızca adli
    inceleme/rapor için ek, istatistiksel olarak yorumlanabilir bir sayı.
    Referans yoksa None döner."""
    if OOD_CALIB_SCORES is None or dist is None:
        return None
    n = OOD_CALIB_SCORES.shape[0]
    # calib_scores sirali -> ">= dist" olanlarin sayisi = n - (dist'ten KUCUK
    # olanlarin sayisi, sol-taraftan arama).
    idx = int(np.searchsorted(OOD_CALIB_SCORES, dist, side="left"))
    exceed = n - idx
    return float((1 + exceed) / (n + 1))


# =================================================================
# 3c. (R26 Faz 1 + R27) ONNX MODELLERİ -- iki ayrı kullanım:
#   (a) Davranışsal-dal KONSEY VETOSU: LSTM'in kendine özgü hatalarını (bkz
#       WebAttack/CDN kök nedeni, agent-memory/ids-generalization-strategist/
#       project_r26_behavioral_committee.md) RF+HistGradientBoosting
#       mutabakatıyla süzer. Held-out ölçüm (n=127678): FAR 0.0300->0.0125,
#       MCC 0.9241->0.9502, TP kaybı ~sıfır. Tek model DEĞİL iki bağımsız
#       model şart -- RF adversarial olarak kırılgan (bkz
#       project_adversarial_robustness_test), tek üyeye veto yetkisi vermek
#       yeni bir zayıf halka yaratır.
#   (b) (R27) Volumetrik dalın BİRİNCİL sınıflandırıcısı da artık RF-ONNX
#       kullanır (joblib 26.6ms/paket -> ONNX 0.02ms, ~1180x; bkz.
#       project_r27_full_pipeline_audit_2026_08.md Yüksek-2) -- tam da
#       flood/scan anında, en çok hız gerektiği yerde. joblib main_rf hâlâ
#       yüklü ve ONNX yoksa/hata verirse OTOMATİK FALLBACK olarak kullanılır.
# RF ve HGB ONNX'i BİRBİRİNDEN BAĞIMSIZ yüklenir (R27: eskiden HGB yoksa RF
# ONNX'i de hiç yüklenmiyordu, volumetrik dal her zaman joblib'e düşüyordu).
# regresyon kapısı (analysis/convert_multiclass_committee_to_onnx.py):
# P(BENIGN)>=eşik veto-kararı değişimi=0/127678 (RF), argmax değişimi=0 (RF).
COMMITTEE_VETO_THRESHOLD = 0.95


def _load_onnx_session(path):
    """(R27) Oturumu + giriş/çıkış adlarını BİR KEZ çözüp tuple olarak
    döner (D1: eskiden her çağrıda get_inputs()/get_outputs() yeniden
    çözülüyordu). Dosya yoksa/yüklenemezse None -- çağıran taraf fail-safe
    davranmalı (fallback ya da no-op)."""
    if not os.path.exists(path):
        return None
    try:
        import onnxruntime as _ort
        so = _ort.SessionOptions()
        so.intra_op_num_threads = 1
        so.inter_op_num_threads = 1
        sess = _ort.InferenceSession(path, sess_options=so, providers=["CPUExecutionProvider"])
        return (sess, sess.get_inputs()[0].name, sess.get_outputs()[1].name)
    except Exception as _e:
        print(f"⚠️ ONNX yüklenemedi ({os.path.basename(path)}): {_e}")
        return None


_RF_ONNX = _load_onnx_session(os.path.join(THIS_DIR, "models", "MulticlassRF.onnx"))
_HGB_ONNX = _load_onnx_session(os.path.join(THIS_DIR, "models", "MulticlassHGB.onnx"))

if _RF_ONNX is not None:
    print(f"⚡ Volumetrik dal: RF-ONNX aktif (joblib fallback hazır).")
else:
    print(f"⚠️ RF-ONNX yok/yüklenemedi; volumetrik dal joblib main_rf kullanacak "
          f"(python analysis/convert_multiclass_committee_to_onnx.py ile üretilir).")
if _RF_ONNX is not None and _HGB_ONNX is not None:
    print(f"🗳️ Konsey vetosu aktif (eşik={COMMITTEE_VETO_THRESHOLD}).")
else:
    print(f"⚠️ Konsey vetosu DEVRE DIŞI (RF ve/veya HGB ONNX eksik).")


def _onnx_proba_row(onnx_tuple, scaled_row):
    """(onnx_tuple = (sess, in_name, prob_name)) tek satır için TAM olasılık
    vektörünü ([n_classes] float64) döner. Çağıran taraf hataları yakalamalı
    (bkz. committee_dissents/_rf_onnx_proba_or_none -- O2 fix: bu fonksiyonun
    kendisi try/except İÇERMEZ, çağıranlar fail-safe sorumludur)."""
    sess, in_name, prob_name = onnx_tuple
    x = np.ascontiguousarray(scaled_row.reshape(1, -1), dtype=np.float32)
    out = sess.run([prob_name], {in_name: x})[0]
    return np.asarray(out, dtype=np.float64)[0]


def _rf_onnx_proba_or_none(scaled_row):
    """(R27/Y2) Volumetrik dal için RF-ONNX çağrısı -- yükleme-zamanı VEYA
    çalışma-zamanı hatasında None döner, çağıran joblib'e düşer (O2 ile aynı
    fail-safe felsefesi: hata paketi düşürmemeli, daha yavaş ama doğru yola
    düşmeli)."""
    if _RF_ONNX is None:
        return None
    try:
        return _onnx_proba_row(_RF_ONNX, scaled_row)
    except Exception as _e:
        print(f"⚠️ RF-ONNX çalışma-zamanı hatası, joblib'e düşülüyor: {_e}")
        return None


def committee_dissents(scaled_row):
    """(R26 Faz 1) RF VE HGB ikisi de BENIGN'e >= eşik güvenle katılıyorsa
    True (LSTM'in alarmıyla ÇELİŞİYORLAR -> bastır). Konsey devre dışıysa
    (ONNX dosyaları yok) VEYA çalışma anında ONNX hatası olursa (O2 fix --
    eskiden bu durumda dıştaki except paketi komple düşürüyordu, alarm
    sessizce kayboluyordu) her zaman False -- gate no-op olur, alarm olduğu
    gibi geçer (fail-safe: bastırmamak, bastırmaktan daha güvenli varsayım)."""
    if _RF_ONNX is None or _HGB_ONNX is None:
        return False
    try:
        p_rf = _onnx_proba_row(_RF_ONNX, scaled_row)
        p_hgb = _onnx_proba_row(_HGB_ONNX, scaled_row)
    except Exception as _e:
        print(f"⚠️ Konsey ONNX çalışma-zamanı hatası, veto atlanıyor: {_e}")
        return False
    return p_rf[BENIGN_INDEX] >= COMMITTEE_VETO_THRESHOLD and p_hgb[BENIGN_INDEX] >= COMMITTEE_VETO_THRESHOLD


# (R34) early_attack MUAFİYETİNİ bloke etmek için konseyin iki üyesinin de
# BENIGN'e vermesi gereken minimum olasılık. 0.5 = "argmax BENIGN" eşdeğeri.
# R26'nın BASTIRMA vetosuyla (0.95) KARIŞTIRMA: orada bir alarmı SİLİYORUZ,
# burada bir GÜVENLİK KAPISINI ATLAMA hakkını geri çekiyoruz -- ikincisi için
# daha zayıf kanıt yeterlidir (asimetrik, muhafazakâr yönde).
COMMITTEE_WAIVER_BENIGN_P = 0.5


def committee_waives_early_attack(scaled_row):
    """(R34) True = RF VE HGB ikisi de bu paketi BENIGN sayıyor -> R12
    early_attack MUAFİYETİ VERİLMEZ (olgunluk kapısı + Strateji E + Strateji F
    yürürlükte kalır).

    KÖK NEDEN: update_progressive'de her TCP açılış SYN'i is_syn_only ->
    suspicious sayıldığı için `susp>=1` koşulu "yeni bağlantı açıldı" ile
    ÖZDEŞTİ; early_attack fiilen HER yeni bağlantıda tetikleniyor ve üç kapıyı
    birden atlatıyordu (bkz. EARLY_ATTACK_MIN_SUSP yorumu).

    AYIRT EDİCİ SİNYAL (ölçüldü, 2026-08-12):
      gerçek DoS-Hulk immature paketleri (n=138): HGB P(BENIGN) p50=0.0105,
        MAKS 0.0756 -- RF argmax DoS 77 / BENIGN 54 / WebAttack 7
      canlı meşru yeni bağlantı (n=12): HGB P(BENIGN) 0.9992-0.99999,
        RF ve HGB argmax'ı 12/12 BENIGN
    İki dağılım arasında 0.08-0.99 boşluğu var. RF TEK BAŞINA YETMEZ
    (0.765-0.864 vs maks 0.9247 -- iç içe); bu yüzden İKİ üye de şart.

    Fail-safe yön R26'nın TERSİDİR: konsey yoksa/hata verirse False döner,
    yani muafiyet ESKİ davranışla verilir (kapı no-op olur, alarm kaybolmaz)."""
    if _RF_ONNX is None or _HGB_ONNX is None:
        return False
    try:
        p_rf = _onnx_proba_row(_RF_ONNX, scaled_row)
        if p_rf[BENIGN_INDEX] < COMMITTEE_WAIVER_BENIGN_P:
            return False          # RF katılmıyor -> HGB'yi hiç çalıştırma (ucuz çıkış)
        p_hgb = _onnx_proba_row(_HGB_ONNX, scaled_row)
    except Exception as _e:
        print(f"⚠️ Konsey/muafiyet ONNX çalışma-zamanı hatası, atlanıyor: {_e}")
        return False
    return p_hgb[BENIGN_INDEX] >= COMMITTEE_WAIVER_BENIGN_P


# ── (R26 FAZ 2) DAVRANIŞSAL DALDA 3-ÜYE SOFT-VOTE ──────────────────────────
# NE YAPAR: davranışsal (non-volumetrik) dalın KARAR OLASILIK VEKTÖRÜNÜ artık
# tek başına LSTM değil, LSTM + MulticlassRF + MulticlassHGB olasılıklarının
# ağırlıklı ortalaması üretir. argmax (= predicted_class) ve lstm_score
# (= 1 - P(BENIGN)) bu ortalamadan türetilir.
#
# FAZ 1'DEN FARKI (karıştırma): committee_dissents() bir VETO'dur -- yalnızca
# ATTACK->BENIGN yönünde çalışır, HANGİ saldırı sınıfının seçildiğine hiç
# karışmaz. Ölçüldü (R38, 2026-08-14): dispatcher Thursday/WebAttack
# batch'lerinde paketlerin %99.94'ünü LSTM dalına veriyor; RF'in aynı veriyle
# ÇOK daha iyi olduğu durumlarda (XSS held-out recall RF .89 vs LSTM .76) bu
# üstünlük üretim kararına HİÇ ULAŞMIYOR. Faz 2 tam olarak bu mimari darboğazı
# hedefler.
#
# NEDEN BU 3 ÜYE (ölçülmüş, agent-memory .../project_r26_behavioral_committee.md
# "Kanıt 3/4"): çeşitlilik MİMARİ AİLEDEN gelir. GRU eklemek işlevsizdir
# (LSTM ile çift-hata 0.4901; DDoS FP'lerinin %99.7'sinde AYNI yanlış sınıf);
# ağaç/boosting ailesiyle çift-hata 0.175-0.183. 6 üyeli varyant (+ExtraTrees
# +MLP+GRU) ÖLÇÜLDÜ ve DAHA KÖTÜ çıktı -- ÜYE EKLEME.
#
# DÜRÜSTLÜK NOTU (aynı kaynaktan, korunuyor): kazancın bir kısmı "konsey
# bilgeliği" değil, EN ZAYIF ÜYENİN (LSTM) SEYRELTİLMESİDİR -- tek başına HGB
# 7-sınıf MCC'de 3-üyeli soft-vote ile zaten eşittir.
#
# KAPILARLA ETKİLEŞİM (kasıtlı olarak DOKUNULMADI): aşağıdaki floor'lar,
# early_attack, Strateji E/F ve K1 hepsi lstm_score/lstm_class_name üzerinden
# çalışır; soft-vote bu iki değişkenin KAYNAĞINI değiştirdiği için kapılar
# otomatik olarak yeni vektöre uyarlanır. Eşik sayıları BİLEREK sabit tutuldu
# ki ölçüm "sadece karar vektörü değişti" izole edilebilsin.
#   Yan etki (matematiksel, ölçülmedi ama zorunlu): soft-vote açıkken Faz 1
#   vetosu fiilen ÖLÜ KOD olur -- RF ve HGB ikisi de P(BENIGN)>=0.95 derse
#   ortalama P(BENIGN) >= (0.95+0.95+0)/3 = 0.633, yani lstm_score <= 0.367 <
#   ALERT_THRESHOLD(0.4); paket zaten eşiğin altındadır. Aynı şekilde R34
#   muafiyet-iptali de tetiklenemez (>=0.5 + >=0.5 -> lstm_score <= 0.667 <
#   EARLY_ATTACK_LSTM 0.85). İkisi de KALDIRILMADI: soft-vote kapalıyken
#   (varsayılan) tam yürürlükteler ve fail-safe yolda da gerekliler.
#
# VARSAYILAN KAPALI. `MC_R26_SOFTVOTE=1` ile açılır (A/B için; PILOT_R33 /
# MC_R37_D1-D3 ile aynı desen). Kapalıyken kod yolu bit-düzeyinde eskisidir.
MC_R26_SOFTVOTE = os.environ.get("MC_R26_SOFTVOTE", "0") == "1"
_SV_W = os.environ.get("MC_R26_SOFTVOTE_W", "")
if _SV_W:
    SOFTVOTE_WEIGHTS = tuple(float(x) for x in _SV_W.split(","))
    assert len(SOFTVOTE_WEIGHTS) == 3, "MC_R26_SOFTVOTE_W = w_lstm,w_rf,w_hgb"
else:
    SOFTVOTE_WEIGHTS = (1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0)


def softvote_proba(lstm_proba, scaled_row):
    """(R26 Faz 2) LSTM+RF+HGB olasılık vektörlerinin ağırlıklı ortalaması.

    Kapalıysa / ONNX dosyaları yoksa / çalışma-zamanı hatasında None döner ->
    çağıran SAF LSTM'e düşer, yani mevcut üretim davranışı aynen korunur
    (R26 Faz 1 ve R27/Y2 ile AYNI fail-safe felsefesi: hata paketi düşürmemeli,
    daha zayıf ama ÇALIŞAN yola düşmeli).

    MALİYET: Faz 1 vetosu yalnızca eşik-üstü paketlerde çağrılıyordu; bu
    fonksiyon HER non-volumetrik pakette çağrılır. Ölçülen ONNX tek-satır
    maliyeti RF 0.029ms + HGB 0.049ms = ~0.08ms; LSTM'in kendisi 1.45ms
    (project_compute_budget_latency) -> davranışsal dalın paket başı
    maliyetine ~%5 ekler."""
    if not MC_R26_SOFTVOTE or _RF_ONNX is None or _HGB_ONNX is None:
        return None
    try:
        p_rf = _onnx_proba_row(_RF_ONNX, scaled_row)
        p_hgb = _onnx_proba_row(_HGB_ONNX, scaled_row)
    except Exception as _e:
        print(f"⚠️ Soft-vote ONNX çalışma-zamanı hatası, saf LSTM'e düşülüyor: {_e}")
        STATS["softvote_fallback"] += 1
        return None
    w_l, w_r, w_h = SOFTVOTE_WEIGHTS
    STATS["softvote_applied"] += 1
    return (w_l * np.asarray(lstm_proba, dtype=np.float64)
            + w_r * p_rf + w_h * p_hgb)


if MC_R26_SOFTVOTE and _RF_ONNX is not None and _HGB_ONNX is not None:
    print(f"🗳️ R26 Faz 2 SOFT-VOTE AKTİF (ağırlık LSTM/RF/HGB={SOFTVOTE_WEIGHTS}).")
elif MC_R26_SOFTVOTE:
    print("⚠️ MC_R26_SOFTVOTE=1 ama RF/HGB ONNX eksik -> soft-vote NO-OP (saf LSTM).")


# ── (R37/D3) R34 KONSEY-MUAFİYETİNİN SINIF KAPSAMI ─────────────────────────
# BULGU (2026-08-13, ESP32 canlı-ateş + Mongo `ids_db.predictions`, n=16.322):
# R34'ün konsey güvencesi TÜM sınıflara koşulsuz uygulanıyordu, ama kanıt
# tabanı (138 DoS-Hulk immature paketi vs 12 canlı meşru bağlantı, tam ayrışma)
# YALNIZCA DoS üzerinde ölçülmüştü. Bir vetoyu, üzerinde hiç doğrulanmadığı
# sınıflara genişletmek aşırı-genellemedir; ölçülen bedeli şudur:
#
#   ESP32 FTP-Patator (port 21), suppressed_by="immature_flow": 1016 paket
#     lstm_score 0.8500-0.9444 (p50=0.9105), TAMAMI >= EARLY_ATTACK_LSTM(0.85)
#     susp_pkts = 1 (1016/1016) -> early_attack ADAYI idi
#     lstm_class = FTP-Patator -> effective_lstm_floor = DEFAULT (0.95)
#   Yani: kanıt R12'nin Slowloris tablosunun BİREBİR AYNISI (gerçek saldırı
#   paketleri floor'un HEMEN ALTINDA, 0.85-0.94 bandı, medyan ~0.91) ve R12
#   bunu tam olarak early_attack ile çözmüştü. R34'ün koşulsuz muafiyet-iptali
#   o çözümü bu sınıf için GERİ ALDI -- R34'ün held-out korpuslarında
#   ESP32-tarzı (gömülü istemci, her istek için yeni bağlantı) FTP-Patator
#   OLMADIĞI için ölçülmemişti.
#
# NEDEN BU, REDDEDİLEN `EARLY_ATTACK_MIN_SUSP=1->2`DEN FARKLI (kritik):
#   MIN_SUSP=2 bir SIKILAŞTIRMAYDI -> TP KAYBEDEBİLİR, ve kaybetti
#   (multiclass DR 0.9655->0.9205, 138 gerçek DoS-Hulk paketi). Bu değişiklik
#   ise bir GEVŞETMEDİR: muafiyet iptali kalkınca risk_score CLAMP'LENMEZ,
#   yani risk yalnızca ARTABİLİR. Matematiksel olarak TP ve FP monoton
#   artar/sabit kalır, ASLA azalmaz -> "gerçek DoS-Hulk paketi kaybetme"
#   riski bu değişiklikte YAPISAL OLARAK YOKTUR. Ölçülmesi gereken tek şey
#   FP bedelidir (aşağıdaki A/B).
#
# NEDEN SADECE FTP-Patator/SSH-Patator (DAR KAPSAM, kasıtlı):
#   * DoS/DDoS DIŞARIDA: R34'ün kanıtı ve canlı FP faydası (12->5) tam olarak
#     bu sınıflardaydı -- dokunmak R34'ü geri almak olurdu.
#   * WebAttack DIŞARIDA: R34'ün kalan 5 canlı FP'si ZATEN lstm_class=WebAttack
#     idi (CDN/port-80 örtüşmesi, bkz. webattack_cdn_fp_root_cause). Bu sınıfı
#     muaf tutmak o FP ailesini geri getirirdi.
#   * FTP-Patator/SSH-Patator İÇERİDE: bu iki aile, hattaki TEK bağımsız
#     YAPISAL (model-dışı) doğrulama kapısını taşır -- R24/K3 port_bucket_veto.
#     PortBucket_ftp/ssh uyuşmuyorsa alarm zaten ayrıca bastırılır; yani
#     muafiyet burada "kanıtsız" değil, port kimliğiyle korunuyor.
COMMITTEE_WAIVER_EXEMPT_CLASSES = (
    frozenset({"FTP-Patator", "SSH-Patator"})
    if os.environ.get("MC_R37_D3", "1") != "0" else frozenset()
)


print(f"✅ Sistem hazır.")
print("🚀 ANALİZE BAŞLADI! (MULTICLASS)")

# =================================================================
# 4. EVRENSEL REAL-TIME FLOW TABLE (ÖZNİTELİK ÜRETİCİ)
# process_pcap.py (ikili) ile BİREBİR AYNI -- v5 öznitelik/flow mantığı
# sınıf sayısından bağımsızdır, değiştirilmedi.
# =================================================================
def _to_float(value, default=0.0):
    try:
        if value is None or value == '':
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_int(value, default=0):
    try:
        if value is None or value == '':
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _parse_tcp_flags(value):
    if value is None or value == '':
        return 0
    try:
        if isinstance(value, str):
            s = value.strip()
            return int(s, 16) if s.lower().startswith('0x') else int(s)
        return int(value)
    except (TypeError, ValueError):
        return 0


def _welford_update(n, mean, m2, x):
    """Tek-gecisli, O(1) artimli ortalama/varyans (Welford).
    (n, mean, m2/n) her zaman sum([...])/len([...]) ve np.var([...]) (ddof=0)
    ile MATEMATIKSEL OLARAK AYNI sonucu verir -- sadece sinirsiz buyuyen
    fwd_lengths/bwd_lengths listelerini her pakette yeniden toplamayi
    (O(n), uzun akislarda O(n^2)) O(1)'e indirger."""
    n += 1
    delta = x - mean
    mean += delta / n
    m2 += delta * (x - mean)
    return n, mean, m2


def _get_src_ip(packet):
    v = packet.get("ip.src")
    if v is None or v == '':
        v = packet.get("ipv6.src")
    return v if v not in (None, '') else "0.0.0.0"


def _get_dst_ip(packet):
    v = packet.get("ip.dst")
    if v is None or v == '':
        v = packet.get("ipv6.dst")
    return v if v not in (None, '') else "0.0.0.0"


def _is_multicast_ip(ip_str):
    """(R23) Hedef IPv4 224.0.0.0/4 ya da IPv6 ff00::/8 multicast araliginda
    mi? Kok neden: 2026-08-06 canli dogrulamada mDNS (224.0.0.251:5353)
    trafigi MulticlassLSTM'de FTP-Patator/SSH-Patator'a benzer orta-guven
    (0.4-0.7) skorlar uretti -- OOD kapisi bunu YAKALAMADI (mesafe 1.4-2.3,
    egitim-benign kuyruguyla ayni mertebede, yani domain-shift DEGIL, duz
    yanlis-siniflandirma). mDNS/SSDP/LLMNR gibi link-local kesif protokolleri
    TANIM GEREGI bir "kurban"i hedef almaz (yayin yapar) -> multicast hedef
    TESPIT EDILDIGINDE alarm bastirilir. DAR KAPSAM: sadece HEDEF adresi
    multicast oldugunda; unicast trafik (or. port 8009'daki yerel IoT
    cihazi) bu garantiye sahip DEGIL, KASITLI OLARAK kapsam disi (daha fazla
    kanit gerekiyor, bkz. agent-memory/.../project_r23_multiclass_live_far_finding.md)."""
    if not ip_str:
        return False
    if ":" in ip_str:
        return ip_str.lower().startswith("ff")
    parts = ip_str.split(".")
    if len(parts) != 4:
        return False
    try:
        first = int(parts[0])
    except ValueError:
        return False
    return 224 <= first <= 239


def _is_broadcast_ip(ip_str, src_ip=None):
    """(R32 parite -- ASIL GEREKCE pipeline/process_pcap.py::_is_broadcast_ip
    yorumunda) R23 multicast istisnasinin EKSIK kardesi: 224.0.0.0/4 kontrolu
    IPv4 sinirli-yayin adresi 255.255.255.255'i KAPSAMIYOR. 2026-08-12 canli
    Ethernet kosusunda ikili hatta 10.1.9.245:5050 -> 255.255.255.255:5050
    periyodik kesif beacon'i 21 alarm uretti (tum alarmlarin %43'u);
    ayni kosuda MULTICLASS hat da 10.1.9.43 -> 255.255.255.255:8200
    yayinina "PortScan" dedi -> bu hat da ETKILENIYOR, salt-parite DEGIL.
    Yayin hedefinin cevabi olmadigi icin bwd_packets kalici 0 kalir ve vektor
    tek-yonlu/yanitsiz slow-DoS profiline dusuyor.

    (R52, 2026-08-21 canli bulgusu) ALT-AG YONLENDIRILMIS YAYIN artik da
    yakalaniyor -- R32'nin "maske bilgisi gerektirdigi icin kasitli kapsam
    disi" gerekcesi CURUDU: hicbir manuel ag-yapilandirmasi/sabit-kodlanmis
    IP GEREKMIYOR, sadece paketin KENDI src_ip'si kullaniliyor. Kural:
    dst_ip'nin son okteti 255 VE ilk 3 oktet src_ip ile AYNIYSA, bu --
    tanimi geregi -- src'nin kendi alt-agina yonelttigi bir yayindir (dogal
    deney: 192.168.1.102 -> 192.168.1.255, 117/117 kayitta suppressed_by=None
    -> PortScan; ayni cihazin ayni andaki 239.255.255.250 multicast'i ise
    zaten dogru sekilde bastiriliyordu). DAR KAPSAM: yalnizca /24 varsayiliyor
    (en yaygin LAN maskesi); /16, /25 gibi farkli maskelerde kacirilabilir."""
    if ip_str == "255.255.255.255":
        return True
    if src_ip:
        d = ip_str.split(".")
        s = src_ip.split(".")
        if len(d) == 4 and len(s) == 4 and d[3] == "255" and d[:3] == s[:3]:
            return True
    return False


def _get_proto(packet, default=6):
    """(R17 parite -- bkz. process_pcap.py) IPv4 (ip.proto) onceligi, yoksa
    IPv6 (ipv6.nxt) fallback'i."""
    v = packet.get("ip.proto")
    if v in (None, ''):
        v = packet.get("ipv6.nxt")
    return _to_int(v, default)


def _is_non_ip(packet):
    """(R17 parite -- bkz. process_pcap.py) Paketin hicbir IP katmani yoksa
    (ARP, saf L2...) True -- bu paketler akis tablosuna hic girmez."""
    return (
        packet.get("ip.src") in (None, '') and packet.get("ipv6.src") in (None, '')
        and packet.get("ip.dst") in (None, '') and packet.get("ipv6.dst") in (None, '')
    )


def _sanitize_matrix(arr):
    return np.nan_to_num(arr, nan=0.0, posinf=1e6, neginf=-1e6)


# =====================================================================
# DISPATCHER EŞİKLERİ (process_pcap.py ikili sürümle AYNI; flood/scan/
# progressive-counter/TTL eviction mantığı sınıf sayısından bağımsızdır)
# =====================================================================
# Dispatcher esikleri - process_pcap.py (binary pipeline) ile ayni mantik ve
# ayni degerler; ayrintili gerekce icin oradaki yorumlara bakiniz.
SYN_BURST_MIN = 100        # bir kaynaktan tek hedefe minimum SYN sayisi (flood imzasi)
SYN_RATIO_MIN = 0.5        # akistaki SYN-only paket orani esigi
ALERT_THRESHOLD = 0.4      # risk_score bu degeri gecince ATTACK sayilir
PORT_SCAN_MIN_PORTS = 40   # bu sayida farkli dst_port -> is_scan=True
PORT_SCAN_FULL_PORTS = 80  # bu sayida farkli portta scan_conf = 1.0
# (R28/O1.1-O1.3 parite -- gerekce/olcum process_pcap.py'de) hacimsel dal
# iyilestirmeleri: mutlak-SYN kolu + hedef-toplulastirmali baglanti seli.
SYN_ABS_MIN = 150          # oran sartindan BAGIMSIZ mutlak SYN esigi
SYN_ABS_FULL = 300         # mutlak kolun guveninin 1.0'a doydugu SYN sayisi
CONN_FLOOD_MIN = 200       # (dst_ip,dst_port)'a bu kadar farkli baglanti -> sel
CONN_FLOOD_FULL = 400      # bu kadar baglantida conn_conf = 1.0
SCAN_RF_VETO_MAX_PORTS = 150  # (R28/O1.2) bu port sayisinin ALTINDA RF vetosu gecerli
EVICT_CONN_FLOOD_MAX = 200_000

# ── (R28/Ö2.3) "KAYNAK AÇLIĞI" (starvation) TERİMİ: ÖLÇÜLDÜ, REDDEDİLDİ ─────
# ÖNERİ: Progressive Counter'a paket-sayısından BAĞIMSIZ, süre tabanlı bir
# terim eklemek -- istemci yönünde (a) uzun süredir açık, (b) gerçekten veri
# göndermiş, (c) ortalama ileri-yön yükü çok düşük, (d) karşı taraf hiç veri
# göndermemiş bir akışı slow-DoS saymak. Yapısal gerekçe makul görünüyordu:
# "bağlantıyı açık tutan taraf tanım gereği istemcidir".
#
# GERÇEK VERİDE TERS ÇALIŞIYOR. Wednesday Slowloris/Slowhttptest/GAP
# batch'lerinde, kapının ön-koşullarını sağlayan FORWARD paketler içinde
# (süre>=10s VE ileri-yön yük<=100 B/s) kapısının tetiklenme oranı:
#
#     batch grubu            ATTACK    BENIGN
#     Slowloris               %2.0      %32.7
#     Slowhttptest            %6.2      %57.0
#     GAP_clean (saldırı YOK)   --       %27.2
#
# Yani terim benign trafikte saldırıdan 10-25 KAT fazla tetikleniyor: çok
# sayıda MEŞRU istemci akışı da uzun ömürlü, tek yönlü ve düşük hızlıdır
# (idle keepalive, long-poll, yoklama istemcileri). Ölçülen Slowloris saldırı
# akışlarının p50 süresi zaten yalnızca 1.15s -- "slow" olan şey AKIŞ SÜRESİ
# değil PAKET-ARASI ZAMANLAMA'dır ve onu R21'in IAT kapısı ZATEN kullanıyor.
# KARAR: eklenmedi. Tekrar denenmeden önce bu ölçümü tekrarlayın.
VOL_WINDOW_SECONDS = 60    # (R17/R22 parite) process_pcap.py ile ayni deger
EPHEMERAL_PORT_MIN = 32768 # (R17 parite) akis-yonu tahmini icin efemeral-port araligi
PROG_WINDOW = 30           # Progressive Counter'in kayan pencere boyu (son N paket)
PROG_MIN_PKTS = 12         # bu paketten az akista counter_score = 0 (olgunlasmamis akis)
PROG_BASE_RATE = 0.35      # bu suspicious-oraninin ALTI benign sayilir (skor=0)
PROG_FULL_RATE = 0.85      # bu suspicious-oraninda counter_score = 1.0
TLS_PORTS = frozenset({443, 465, 563, 636, 853, 989, 990, 993, 995, 8443})
PSH_SLOW_IAT_US = 300_000  # (R21 parite) 0.3s -- bkz. process_pcap.py PSH_SLOW_IAT_US yorumu

# Flow-table TTL/eviction (canli calismada bellek korumasi; dispatcher mantigini
# etkilemez, sadece olu akislari ve sinirsiz buyuyen sayaclari temizler).
FLOW_TTL_SECONDS = 300              # 5 dk paket gormeyen akis "olu" sayilir
FLOW_TTL_US = FLOW_TTL_SECONDS * 1_000_000
EVICT_EVERY_N_PKTS = 5000           # her N pakette bir periyodik temizlik
EVICT_VOLUMETRIC_MAX = 200_000      # bu kadar sayactan sonra reset
EVICT_SCAN_MAX = 200_000            # bu kadar port-kumesinden sonra reset

VOLUMETRIC_FEATURE = bundle.get("volumetric_feature", "Flow Packets/s") if isinstance(bundle, dict) else "Flow Packets/s"
# 500_000: tek-paketlik-akis rate yapaylığını (R10 kok-neden duzeltmesi, bkz.
# process_pcap.py) asacak kadar yuksek, gercek volumetrik saldirilari kacirmayacak
# kadar dusuk esik.
VOLUMETRIC_THRESHOLD = 500_000

# ── (R33 parite) AKIS-BASI SABIT-PAYDALI PAKET HIZI PENCERESI ───────────────
# Gerekce + esik kalibrasyonu process_pcap.py'deki R33 yorumunda (olculen
# akis-basi 100 ms maksimumlari orada tablo halinde). Ozet: eski rate sinyali
# `total_pkts / (simdi - akis_dogusu)` idi -> payda akisin YASI oldugu icin ilk
# paketlerde clamp'lenip HIZ yerine "ilk iki paket ne kadar yakin geldi"
# tesadufunu olcuyordu. Payda artik SABIT pencere uzunlugudur.
RATE_WINDOW_SECONDS = 0.1
RATE_TRIGGER_PPS = 25_000.0
RATE_WIN_MIN_PKTS = int(RATE_TRIGGER_PPS * RATE_WINDOW_SECONDS)  # 2500 pkt/100ms

PORT_BUCKETS = ["ftp", "ssh", "http", "https", "dns", "other_wk", "ephemeral"]


def _port_bucket(port):
    p = int(port)
    if p == 21:
        return "ftp"
    if p == 22:
        return "ssh"
    if p in (80, 8080):
        return "http"
    if p == 443:
        return "https"
    if p == 53:
        return "dns"
    if p < 1024:
        return "other_wk"
    return "ephemeral"


class UniversalRealTimeFlowTable:
    def __init__(self):
        self.flows = {}
        self.volumetric = {}
        self.scan = {}
        # (R28/O1.3 parite -- bkz. process_pcap.py) (dst_ip, dst_port) ->
        # baglanti baslatan FARKLI (src_ip, src_port) kumesi.
        self.conn_flood = {}
        self._flag_counts = {}

    def update_volumetric(self, packet):
        src_ip = _get_src_ip(packet)
        dst_ip = _get_dst_ip(packet)
        dst_port = _to_int(packet.get("tcp.dstport") or packet.get("udp.dstport"), 0)
        flags_int = _parse_tcp_flags(packet.get("tcp.flags"))
        now_s = _to_float(packet.get("frame.time_epoch"), 0.0)

        key = (src_ip, dst_ip, dst_port)
        st = self.volumetric.get(key)
        if st is None:
            st = {"pkts": 0, "syn": 0, "win_start": now_s}
            self.volumetric[key] = st
        # (R17/R22 parite -- bkz. process_pcap.py) kayan zaman penceresi:
        # 7/24 canli calismada gunler icinde damla damla biriken SYN/port
        # sayaclari KALICI latch olusturmasin diye VOL_WINDOW_SECONDS'ta bir
        # sifirlanir. Bu ikili pipeline'daki R17/R22 fix'lerinin BİREBİR
        # portudur; multiclass hatti bu fix'ler olmadan yasiyordu.
        if now_s > 0 and (now_s - st.get("win_start", now_s)) > VOL_WINDOW_SECONDS:
            st["pkts"] = 0
            st["syn"] = 0
            st["win_start"] = now_s
        st["pkts"] += 1
        if (flags_int & 0x02) and not (flags_int & 0x10):
            st["syn"] += 1

        syn_ratio = st["syn"] / st["pkts"] if st["pkts"] else 0.0
        # (R28/O1.1 parite -- gerekce/olcum process_pcap.py SYN_ABS_MIN yorumunda)
        # kol-1 klasik yari-acik SYN-flood, kol-2 tam-baglantili baglanti seli.
        is_flood = (st["syn"] >= SYN_BURST_MIN and syn_ratio >= SYN_RATIO_MIN)             or (st["syn"] >= SYN_ABS_MIN)

        # (R28/O1.3 parite) hedef-toplulastirmali baglanti seli sayaci.
        cf_key = (dst_ip, dst_port)
        cst = self.conn_flood.get(cf_key)
        if cst is None:
            cst = {"conns": set(), "win_start": now_s}
            self.conn_flood[cf_key] = cst
        if now_s > 0 and (now_s - cst.get("win_start", now_s)) > VOL_WINDOW_SECONDS:
            cst["conns"] = set()
            cst["win_start"] = now_s
        if (flags_int & 0x02) and not (flags_int & 0x10):
            _sp_cf = _to_int(packet.get("tcp.srcport") or packet.get("udp.srcport"), 0)
            cst["conns"].add((src_ip, _sp_cf))
        distinct_conns = len(cst["conns"])
        is_conn_flood = distinct_conns >= CONN_FLOOD_MIN

        scan_key = (src_ip, dst_ip)
        sst = self.scan.get(scan_key)
        if sst is None:
            sst = {"ports": set(), "win_start": now_s}
            self.scan[scan_key] = sst
        if now_s > 0 and (now_s - sst.get("win_start", now_s)) > VOL_WINDOW_SECONDS:
            sst["ports"] = set()
            sst["win_start"] = now_s
        ports = sst["ports"]
        is_syn_only_pkt = bool((flags_int & 0x02) and not (flags_int & 0x10))
        if is_syn_only_pkt:
            ports.add(dst_port)
        distinct_ports = len(ports)
        is_scan = distinct_ports >= PORT_SCAN_MIN_PORTS

        return (is_flood, st["pkts"], st["syn"], syn_ratio, is_scan, distinct_ports,
                is_conn_flood, distinct_conns)

    def update_rate_window(self, flow_key, now_s):
        """(R33 parite) Akis-basi SABIT-PAYDALI kayan pencere paket sayaci.
        Sayac akis sozlugunun ICINDE yasar -> evict_stale ile birlikte gider."""
        f = self.flows.get(flow_key)
        if f is None:
            return 0
        st = f.get("rate_win")
        if st is None:
            st = {"pkts": 0, "win_start": now_s}
            f["rate_win"] = st
        if now_s > 0 and (now_s - st["win_start"]) > RATE_WINDOW_SECONDS:
            st["pkts"] = 0
            st["win_start"] = now_s
        st["pkts"] += 1
        return st["pkts"]

    def update_progressive(self, packet, flow):
        from collections import deque
        flags_int = _parse_tcp_flags(packet.get("tcp.flags"))
        payload = _to_float(packet.get("tcp.len"), 0.0)

        st = flow.get("_prog")
        if st is None:
            st = {"win": deque(maxlen=PROG_WINDOW)}
            flow["_prog"] = st

        is_syn_only = bool((flags_int & 0x02) and not (flags_int & 0x10))

        # (R17/R21 parite -- bkz. process_pcap.py) YON-DUYARLI KUCUK-PSH KURALI
        # + ZAMANLAMA (IAT) KAPISI. TLS_PORTS beyaz-listesi yerine "karsi yon
        # hic VERI gonderdi mi?" testi kullanilir (slow-DoS tek-yonlu sizinti,
        # benign keepalive karsilikli konusma) VE kucuk-PSH ancak KENDI
        # yonundeki en son IAT yavassa (>=PSH_SLOW_IAT_US) suspicious sayilir
        # (meshru hizli tek-yonlu streaming payload bandinda ortusur ama
        # zamanlamada 1000x+ farkli -- bkz. process_pcap.py R21 yorumu).
        _sk = f"{_get_src_ip(packet)}:{_to_int(packet.get('tcp.srcport') or packet.get('udp.srcport'), 0)}"
        is_fwd_now = (_sk == flow.get("fwd_src_key"))

        _own_iat_list = flow.get("fwd_iat_list") if is_fwd_now else flow.get("bwd_iat_list")
        _own_iat = _own_iat_list[-1] if _own_iat_list else None
        is_slow_cadence = (_own_iat is not None) and (_own_iat >= PSH_SLOW_IAT_US)
        is_psh_small = bool((flags_int & 0x08) and payload <= 200.0 and is_slow_cadence)

        if is_fwd_now:
            peer_data_pkts = flow.get("bwd_data_pkts", 0)
        else:
            peer_data_pkts = flow.get("fwd_data_pkts", 0)
        suspicious = is_syn_only or (is_psh_small and peer_data_pkts == 0)

        st["win"].append(1 if suspicious else 0)

        total_pkts = flow["fwd_packets"] + flow["bwd_packets"]
        win = st["win"]
        win_len = len(win)
        susp_count = sum(win)

        # Kucuk akislarda gurultuyu engelle: yeterli kanit yoksa skor=0.
        if total_pkts < PROG_MIN_PKTS or win_len < PROG_MIN_PKTS:
            return 0.0, susp_count, total_pkts, (susp_count / win_len if win_len else 0.0)

        susp_ratio = susp_count / win_len

        if susp_ratio <= PROG_BASE_RATE:
            counter_score = 0.0
        else:
            counter_score = (susp_ratio - PROG_BASE_RATE) / (PROG_FULL_RATE - PROG_BASE_RATE)
        counter_score = float(max(0.0, min(counter_score, 1.0)))
        return counter_score, susp_count, total_pkts, susp_ratio

    def evict_stale(self, now_epoch_us, ttl_us):
        removed_flows = 0
        for fk in list(self.flows.keys()):
            lt = self.flows[fk].get("last_time", now_epoch_us)
            if (now_epoch_us - lt) > ttl_us:
                del self.flows[fk]
                self._flag_counts.pop(fk, None)
                removed_flows += 1

        removed_vol = 0
        removed_scan = 0
        if len(self.volumetric) > EVICT_VOLUMETRIC_MAX:
            removed_vol = len(self.volumetric)
            self.volumetric.clear()
        if len(self.scan) > EVICT_SCAN_MAX:
            removed_scan = len(self.scan)
            self.scan.clear()
        return removed_flows, removed_vol, removed_scan

    def extract_universal_features(self, packet):
        try:
            src_ip = _get_src_ip(packet)
            dst_ip = _get_dst_ip(packet)
            src_port = _to_int(packet.get("tcp.srcport") or packet.get("udp.srcport"), 0)
            dst_port = _to_int(packet.get("tcp.dstport") or packet.get("udp.dstport"), 0)
            proto = _get_proto(packet, 6)   # (R17 parite) IPv6'da ipv6.nxt'e duser

            flow_key = tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"])) + (proto,)
            packet_len = _to_float(packet.get("frame.len"), 0.0)
            tcp_payload_len = _to_float(packet.get("tcp.len"), 0.0)
            time_epoch = _to_float(packet.get("frame.time_epoch"), 0.0) * 1_000_000

            src_key = f"{src_ip}:{src_port}"
            dst_key = f"{dst_ip}:{dst_port}"

            if flow_key not in self.flows:
                # (R17 parite -- bkz. process_pcap.py) AKIS-YONU (orientation).
                # "forward" = akisin ISTEMCI tarafi. Canli yakalama zaten acik
                # olan baglantilarin ORTASINA girebilir; ilk gorulen paket
                # sunucu->istemci yonundeyse "ilk paket = forward" varsayimi
                # yanlis olur ve TLS muafiyeti/PortBucket/fwd-bwd konvansiyonu
                # ayni anda bozulur. SYN bayragi kesin sinyaldir; yoksa
                # (mid-stream giris) efemeral-port araligina dusulur.
                flags_int0 = _parse_tcp_flags(packet.get("tcp.flags"))
                is_syn_only0 = bool((flags_int0 & 0x02) and not (flags_int0 & 0x10))
                is_syn_ack0 = bool((flags_int0 & 0x02) and (flags_int0 & 0x10))
                if is_syn_only0:
                    flip = False
                elif is_syn_ack0:
                    flip = True
                else:
                    dst_eph = dst_port >= EPHEMERAL_PORT_MIN
                    src_eph = src_port >= EPHEMERAL_PORT_MIN
                    if dst_eph != src_eph:
                        flip = dst_eph
                    else:
                        flip = src_port < dst_port

                self.flows[flow_key] = {
                    "start_time": time_epoch, "last_time": time_epoch,
                    # (R17 parite) flipped: akis mid-stream yakalandi, yon SYN
                    # yerine port sezgiseliyle TAHMIN edildi. R13/R18 kapilari kullanir.
                    "flipped": flip,
                    "fwd_src_key": dst_key if flip else src_key,
                    "fwd_packets": 0, "bwd_packets": 0,
                    # (kirpma-fix) sinirsiz-buyuyen listeler yerine O(1)
                    # artimli sayaclar -- bkz. _welford_update.
                    "fwd_sum": 0.0, "fwd_max": 0.0,
                    "bwd_sum": 0.0, "bwd_max": 0.0, "bwd_min": 0.0,
                    "bwd_var_n": 0, "bwd_var_mean": 0.0, "bwd_var_m2": 0.0,
                    "all_var_n": 0, "all_var_mean": 0.0, "all_var_m2": 0.0,
                    "dst_port": src_port if flip else dst_port,
                    "iat_list": [], "fwd_iat_list": [], "bwd_iat_list": [],
                    "last_fwd_time": None, "last_bwd_time": None,
                    "psh_count": 0, "ack_count": 0,
                    "init_win_fwd": None, "init_win_bwd": None,
                    # (R17 parite) bwd_data_pkts: update_progressive'in
                    # yon-duyarli kucuk-PSH kurali icin gerekli.
                    "fwd_data_pkts": 0, "bwd_data_pkts": 0,
                    # (R28/O2.3) ileri yon kumulatif TCP yuku (sayac, oznitelik DEGIL)
                    "fwd_payload_bytes": 0.0,
                }

            flow = self.flows[flow_key]
            diff = time_epoch - flow["last_time"]
            if diff > 0: flow["iat_list"].append(diff)
            flow["last_time"] = time_epoch
            if len(flow["iat_list"]) > 50: flow["iat_list"].pop(0)

            is_fwd = (src_key == flow["fwd_src_key"])

            if is_fwd:
                if flow["last_fwd_time"] is not None:
                    fdiff = time_epoch - flow["last_fwd_time"]
                    if fdiff > 0:
                        flow["fwd_iat_list"].append(fdiff)
                        if len(flow["fwd_iat_list"]) > 50: flow["fwd_iat_list"].pop(0)
                flow["last_fwd_time"] = time_epoch
            else:
                if flow["last_bwd_time"] is not None:
                    bdiff = time_epoch - flow["last_bwd_time"]
                    if bdiff > 0:
                        flow["bwd_iat_list"].append(bdiff)
                        if len(flow["bwd_iat_list"]) > 50: flow["bwd_iat_list"].pop(0)
                flow["last_bwd_time"] = time_epoch

            flags_int = _parse_tcp_flags(packet.get("tcp.flags"))
            if flags_int & 0x08: flow["psh_count"] += 1
            if flags_int & 0x10: flow["ack_count"] += 1

            win_size = _to_float(packet.get("tcp.window_size_value") or packet.get("tcp.window_size"), 8192.0)
            if win_size <= 0: win_size = 8192.0

            if is_fwd:
                flow["fwd_packets"] += 1
                flow["fwd_sum"] += packet_len
                if packet_len > flow["fwd_max"]:
                    flow["fwd_max"] = packet_len
                if flow["init_win_fwd"] is None:
                    flow["init_win_fwd"] = win_size
                if tcp_payload_len > 0:
                    flow["fwd_data_pkts"] += 1
                # (R28/O2.3) starvation terimi icin kumulatif ileri-yon yuku
                flow["fwd_payload_bytes"] = flow.get("fwd_payload_bytes", 0.0) + tcp_payload_len
            else:
                flow["bwd_packets"] += 1
                flow["bwd_sum"] += packet_len
                if flow["bwd_packets"] == 1:
                    flow["bwd_max"] = packet_len
                    flow["bwd_min"] = packet_len
                else:
                    if packet_len > flow["bwd_max"]:
                        flow["bwd_max"] = packet_len
                    if packet_len < flow["bwd_min"]:
                        flow["bwd_min"] = packet_len
                flow["bwd_var_n"], flow["bwd_var_mean"], flow["bwd_var_m2"] = _welford_update(
                    flow["bwd_var_n"], flow["bwd_var_mean"], flow["bwd_var_m2"], packet_len)
                if flow["init_win_bwd"] is None:
                    flow["init_win_bwd"] = win_size
                # (R17 parite) yon-duyarli kucuk-PSH kurali icin (bkz. update_progressive)
                if tcp_payload_len > 0:
                    flow["bwd_data_pkts"] += 1

            flow["all_var_n"], flow["all_var_mean"], flow["all_var_m2"] = _welford_update(
                flow["all_var_n"], flow["all_var_mean"], flow["all_var_m2"], packet_len)

            fwd_sum = flow["fwd_sum"]
            bwd_sum = flow["bwd_sum"]
            total_pkts = flow["fwd_packets"] + flow["bwd_packets"]

            fwd_mean = fwd_sum / flow["fwd_packets"] if flow["fwd_packets"] else 0
            bwd_len = flow["bwd_packets"]
            bwd_mean = bwd_sum / bwd_len if bwd_len > 0 else 0
            bwd_max = flow["bwd_max"] if bwd_len > 0 else 0
            bwd_min = flow["bwd_min"] if bwd_len > 0 else 0
            bwd_std = float(np.sqrt(flow["bwd_var_m2"] / bwd_len)) if bwd_len > 1 else 0.0

            max_pkt_len = max(flow["fwd_max"], flow["bwd_max"]) if total_pkts > 0 else 0
            mean_pkt_len = (fwd_sum + bwd_sum) / total_pkts if total_pkts > 0 else 0
            pkt_len_std = float(np.sqrt(flow["all_var_m2"] / total_pkts)) if total_pkts > 1 else 0.0
            pkt_len_var = float(flow["all_var_m2"] / total_pkts) if total_pkts > 1 else 0.0

            flow_duration_sec = max((time_epoch - flow["start_time"]) / 1_000_000.0, 1e-6)
            flow_bytes_per_s = float((fwd_sum + bwd_sum) / flow_duration_sec)
            flow_packets_per_s = float(total_pkts / flow_duration_sec)
            bwd_packets_per_s = float(bwd_len / flow_duration_sec)

            master_features = {
                "Destination Port": float(flow["dst_port"]),
                "Total Length of Fwd Packets": float(fwd_sum),
                "Fwd Packet Length Max": float(flow["fwd_max"] if flow["fwd_packets"] else 0),
                "Fwd Packet Length Mean": float(fwd_mean),
                "Bwd Packet Length Min": float(bwd_min),
                "Bwd Packet Length Max": float(bwd_max),
                "Bwd Packet Length Mean": float(bwd_mean),
                "Bwd Packet Length Std": bwd_std,
                "Packet Length Mean": float(mean_pkt_len),
                "Packet Length Std": float(pkt_len_std),
                "Packet Length Variance": float(pkt_len_var),
                "Average Packet Size": float(mean_pkt_len),
                "Avg Fwd Segment Size": float(fwd_mean),
                "Avg Bwd Segment Size": float(bwd_mean),
                "Subflow Fwd Bytes": float(fwd_sum),
                "Flow IAT Mean": float(np.mean(flow["iat_list"])) if flow["iat_list"] else 3.0,
                "Fwd IAT Max": float(max(flow["fwd_iat_list"]) if flow["fwd_iat_list"] else 0),
                "Bwd IAT Total": float(sum(flow["bwd_iat_list"])),
                "Bwd IAT Max": float(max(flow["bwd_iat_list"]) if flow["bwd_iat_list"] else 0),
                "Bwd Packets/s": bwd_packets_per_s,
                "PSH Flag Count": float(flow["psh_count"]),
                "ACK Flag Count": float(flow["ack_count"]),
                "Max Packet Length": float(max_pkt_len),
                "Init_Win_bytes_forward": float(flow["init_win_fwd"] if flow["init_win_fwd"] is not None else win_size),
                "Init_Win_bytes_backward": float(flow["init_win_bwd"] if flow["init_win_bwd"] is not None else 0.0),
                "act_data_pkt_fwd": float(flow["fwd_data_pkts"]),
                "Subflow Bwd Packets": float(bwd_len),
                "Active Max": 0.0, "Active Min": 0.0, "Flow IAT Max": float(max(flow["iat_list"]) if flow["iat_list"] else 0),
                "Flow Bytes/s": flow_bytes_per_s,
                "Flow Packets/s": flow_packets_per_s,
            }

            st = self._flag_counts.get(flow_key)
            if st is None:
                st = {"syn": 0, "fin": 0, "rst": 0}
                self._flag_counts[flow_key] = st
            if flags_int & 0x02: st["syn"] += 1
            if flags_int & 0x01: st["fin"] += 1
            if flags_int & 0x04: st["rst"] += 1

            bucket = _port_bucket(master_features["Destination Port"])
            for b in PORT_BUCKETS:
                master_features[f"PortBucket_{b}"] = 1.0 if b == bucket else 0.0

            master_features["SYN Flag Count"] = float(st["syn"])
            master_features["FIN Flag Count"] = float(st["fin"])
            master_features["RST Flag Count"] = float(st["rst"])
            master_features["Down/Up Ratio"] = float(flow["bwd_packets"] / max(flow["fwd_packets"], 1))
            master_features["Fwd/Bwd Byte Ratio"] = float(fwd_sum / max(bwd_sum, 1))

            return master_features, flow_key
        except Exception:
            return None, None


flow_table = UniversalRealTimeFlowTable()

STATS = {
    "total_packets": 0,
    "scored_packets": 0,
    "dropped_packets": 0,
    "anomaly_fallback": 0,
    "sanitized_features": 0,
    "ipv6_packets": 0,
    "non_ip_packets": 0,   # (R17 parite) hic IP katmani olmayan paket (ARP/L2)
    "evicted_flows": 0,
    "dns_devolumetric": 0,
    "early_attack_exception": 0,
    # (R34) early_attack muafiyeti konsey (RF+HGB ikisi de BENIGN) tarafindan
    # BLOKE edildi -> olgunluk/E/F kapilari yururlukte kaldi.
    "early_attack_committee_block": 0,
    # (R37/D3) lstm_class FTP/SSH-Patator oldugu icin R34 konsey-iptali HIC
    # calistirilmadi (muafiyet ayakta kaldi). Canli maruziyeti olcmek icin --
    # capraz-gun CICIDS korpusunda bu sayac 0'dir (tetikleyici yok), bulgu
    # tamamen ESP32 canli-atesinden gelir.
    "early_attack_class_exempt": 0,
    "ood_unknown": 0,       # (R19/R20 parite) egitim manifoldu disinda -> UNKNOWN
    "port_bucket_veto": 0,  # (R24/K3) SSH/FTP-Patator tahmini port-bucket uyumsuzlugu yuzunden bastirildi
    "committee_dissent": 0,  # (R26 Faz 1) RF+HGB ikisi de BENIGN'e >=0.95 katildigi icin LSTM alarmi bastirildi
    "ood_volumetric_observed": 0,  # (R29/O4) VOLUMETRIK dalda mesafe>esik -- SALT GOZLEM, karara etkisi YOK
    # (R26 Faz 2) davranissal dalda karar vektoru LSTM+RF+HGB ortalamasindan
    # uretildi. VARSAYILAN KAPALI -> uretimde bu sayac 0'dir.
    "softvote_applied": 0,
    # Soft-vote ACIK ama ONNX calisma-zamani hatasi -> saf LSTM'e dusuldu.
    # 0'dan buyukse konsey uyeleri sessizce devre disi kalmis demektir (alarm).
    "softvote_fallback": 0,
}
STATS_LOG_EVERY = 2000


def _log_stats(force=False):
    if force or (STATS["total_packets"] % STATS_LOG_EVERY == 0):
        print(
            f"📊 [İSTATİSTİK] toplam={STATS['total_packets']} "
            f"skorlanan={STATS['scored_packets']} "
            f"düşen={STATS['dropped_packets']} "
            f"anomali_fallback={STATS['anomaly_fallback']} "
            f"nan_temizlenen={STATS['sanitized_features']} "
            f"ipv6={STATS['ipv6_packets']} "
            f"ip_disi={STATS['non_ip_packets']} "
            f"silinen_akis={STATS['evicted_flows']} "
            f"dns_devol={STATS['dns_devolumetric']} "
            f"erken_saldiri={STATS['early_attack_exception']} "
            f"erken_saldiri_konsey_blok={STATS['early_attack_committee_block']} "
            f"erken_saldiri_sinif_muaf={STATS['early_attack_class_exempt']} "
            f"ood_unknown={STATS['ood_unknown']} "
            f"port_bucket_veto={STATS['port_bucket_veto']} "
            f"committee_dissent={STATS['committee_dissent']} "
            f"softvote={STATS['softvote_applied']} "
            f"softvote_fallback={STATS['softvote_fallback']} "
            f"ood_vol_gozlem={STATS['ood_volumetric_observed']} "
            f"aktif_flow={len(flow_table.flows)} "
            f"mongo_yazma={mongo_logger.STATS['writes']} "
            f"mongo_hata={mongo_logger.STATS['failures']}"
        )


# (R17 parite -- bkz. process_pcap.py) canli yakalama ve NiFi dosya-replay
# ayni topic'i paylasmasin diye KAFKA_TOPIC (veya eski adiyla KAFKA_IN_TOPIC),
# ve group_id gercekten calissin diye SOURCE_MODE=live -> SABIT grup
# ("ids-live-multiclass"), aksi halde kosuya ozgu benzersiz grup.
SOURCE_MODE = os.environ.get("SOURCE_MODE", "unknown")
TOPIC_NAME = os.environ.get("KAFKA_IN_TOPIC") or os.environ.get("KAFKA_TOPIC", "network-traffic")

if os.environ.get("KAFKA_GROUP_ID"):
    GROUP_ID = os.environ["KAFKA_GROUP_ID"]
elif SOURCE_MODE == "live":
    GROUP_ID = "ids-live-multiclass"
else:
    import uuid
    GROUP_ID = f"ids-replay-multiclass-{uuid.uuid4().hex[:8]}"

# Demo/izleme amaçlı yapay gecikme (ms). Tespit mantığı paketin kendi
# frame.time_epoch'una dayandığından (bkz. [[project_replay_speed_independence]]
# / SYN-burst, progressive counter, TTL hepsi paket-sayısı/gömülü-zaman bazlı,
# wall-clock OKUMAZ) bu gecikme eşik/skor kararlarını HİÇ etkilemez; sadece
# Mongo'ya yazma + dashboard'a görünme hızını yavaşlatır (terminalden ayarlanır):
#   REPLAY_DELAY_MS=200 python process_pcap_multiclass.py
REPLAY_DELAY_MS = float(os.environ.get("REPLAY_DELAY_MS", "0"))
if REPLAY_DELAY_MS > 0:
    print(f"🐢 REPLAY_DELAY_MS={REPLAY_DELAY_MS:.0f} -- her paket arasında yapay gecikme aktif.")

def _packet_source():
    """(C++ orkestrasyon) bkz. process_pcap.py::_packet_source -- BİREBİR
    AYNI desen. INPUT_MODE='stdin' iken live_wireshark_producer.py --sink
    stdout'un TEK-SATIR-JSON çıktısını okur (Kafka'ya hiç dokunulmaz)."""
    if INPUT_MODE == "stdin":
        print(f"📥 Yerel IPC: stdin'den paket okunuyor (source='{SOURCE_MODE}')")
        for line in sys.stdin:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
        return

    consumer = KafkaConsumer(
        TOPIC_NAME,
        bootstrap_servers=[os.environ.get("KAFKA_BOOTSTRAP", "127.0.0.1:9092")],
        group_id=GROUP_ID,
        auto_offset_reset='earliest',
        enable_auto_commit=True,
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )
    print(f"🔌 Kafka: topic='{TOPIC_NAME}' | group_id='{GROUP_ID}' | source='{SOURCE_MODE}'")
    for message in consumer:
        yield message.value


# =================================================================
# 5. ANA TÜKETİM DÖNGÜSÜ -- MULTICLASS DISPATCHER (Kafka veya yerel stdin)
# offline_test_multiclass.py'deki dispatcher/strateji katmanı (A/C/D/E/F)
# ile BİREBİR AYNI; process_pcap.py'in (ikili) tek farkı: RF/LSTM tek bir
# ATTACK riski değil, 7 sınıftan (BENIGN dahil; MC1 kapsamı) birini seçer, risk_score
# = 1 - P(BENIGN) olarak hesaplanır.
# =================================================================
LSTM_WEIGHT = 0.6
COUNTER_WEIGHT = 0.4
EARLY_ATTACK_LSTM = 0.85
# (R34 -- 2026-08-12) MIN_SUSP 1'de KALIR; kök neden susp eşiği DEĞİL, muafiyetin
# koşulsuz verilmesiydi -> committee_waives_early_attack() güvencesi eklendi.
# Gerekçe/ölçüm: analysis/pcap_validation_pilot.py'deki aynı adlı sabitin
# yorum bloğu (kanonik) -- MIN_SUSP=2 varyantı ÖLÇÜLDÜ VE REDDEDİLDİ
# (offline_test_multiclass DR 0.9655->0.9205, kaybedilen 138 paketin 138'i de
# gerçek DoS-Hulk, FP kazancı sıfır).
EARLY_ATTACK_MIN_SUSP = 1
INIT_WIN_CLIENT_MAX = 512
# (R34 ÖLÇÜMÜ -- yanlış hipotezi kapatmak için) INIT_WIN_CLIENT_MAX'ın modern
# trafiğe göre "ölü kod" olduğu hipotezi ÖLÇÜLDÜ ve KISMEN ÇÜRÜTÜLDÜ:
#   * GERÇEK SYN taşıyan akışlarda gerçekten ulaşılamaz: 2026-08-12
#     capture_ring'deki 3 ayrı yakalamada 224/224 istemci SYN'inde
#     tcp.window_size_value = 65535 (>> 512). Yani client_established bir
#     SYN paketini ASLA yakalayamaz -- ama zaten AMACI bu DEĞİL.
#   * Asıl hedefi (R13) capture'ın ORTASINDA yakalanan, SYN'i görülmemiş
#     akışların ilk paketidir; orada ham pencere ölçekli-küçük gelir.
#     AYNI yakalamada init_win_fwd<=512 olan paket 10.445/16.257 (%64) ve
#     client_established 25 pakette True. KOD CANLI VE İŞLEVSEL -- eşiği
#     yükseltmek YANLIŞ olurdu: saldırı araçlarının SYN'i 29200 (Linux
#     varsayılanı) olduğu için >=29200 herhangi bir eşik saldırıları da
#     "kurulu istemci" sayıp bastırırdı.

# Strateji B (revize): sınıfa özgü olgunluk-kapısı eşiği. Skor dokunulmaz;
# sadece hangi LSTM "floor"unun kullanılacağı sınıfa göre değişir. DDoS
# neredeyse her zaman volumetrik dalla yakalanır; LSTM temporal dalı için
# çok yüksek eşik (0.98) CDN/web trafiklerini kapıda tutar.
# MC1: "Bot" girdisi kaldirildi (sinif kapsam disi birakildi).
#
# (R34 ÖLÇÜMÜ -- "DoS neden 0.92, diğerlerinden düşük?" sorusunun cevabı,
# eşitlemeye ÇALIŞMADAN ÖNCE OKU) Asimetri KASITLIDIR ve dalın rolünden gelir:
#   * DDoS 0.98  -- DDoS'u zaten volumetrik dal (is_flood/SYN oranı) yakalar,
#                   davranışsal dal yedektir -> katı olabilir.
#   * WebAttack 0.97 -- port-80 CDN örtüşmesi yüksek (bkz. agent-memory/
#                   ids-generalization-strategist/project_webattack_cdn_fp_root_cause.md).
#   * DoS 0.92   -- davranışsal dal slow-DoS'un (Slowloris/Slowhttptest) BİRİNCİL
#                   dedektörüdür; R12 döneminde bu paketlerin lstm'i 0.85-0.94
#                   bandındaydı (medyan 0.916) -> 0.95 floor onları kesiyordu.
# (R34 YENİ ÖLÇÜM, v5+R28 yığını, validate_slow_attacks korpusu, olgunlaşmamış
# saldırı paketleri n=4909): dağılım ARTIK ÇOK DAHA KESKİN --
#   lstm [0.85,0.92)=80 | [0.92,0.95)=17 | [0.95,0.97)=25 | >=0.97=4197 (%85.5).
# Yani 0.92'nin koruduğu paket sayısı bugün ~97; orijinal gerekçe hâlâ geçerli
# ama ZAYIFLAMIŞ. 2026-08-12 canlı yanlış-pozitiflerinde bu eşiklerin HİÇBİRİ
# devreye girmiyordu (lstm 0.9765/0.9974, her ikisi de kendi floor'unun
# ÜSTÜNDE) -> floor kalibrasyonu o FP'lerin nedeni DEĞİLDİR, dokunulmadı.
LSTM_FLOOR_PER_CLASS = {
    "DDoS": 0.98,
    "DoS": 0.92,
    "WebAttack": 0.97,
}
DEFAULT_LSTM_FLOOR = 0.95

# ── (R26 FAZ 2) SOFT-VOTE İÇİN YENİDEN KALİBRE EDİLMİŞ FLOOR'LAR ───────────
# NEDEN GEREKİR: yukarıdaki eşikler LSTM'in DOYMUŞ (saturated) skor dağılımına
# göre seçildi -- LSTM gerçek saldırılara tipik olarak 0.97-0.99 verir. 3 üyeli
# ORTALAMA daha yumuşak bir dağılım üretir, dolayısıyla AYNI SAYISAL eşik çok
# daha sıkı bir operasyonel noktaya denk gelir. Ölçüldü (canli_trafik_kaydi.csv,
# DoS-Hulk, n=3071 GT saldırı paketi): lstm_score >= 0.85 oranı LSTM'de %93.0
# iken soft-vote'ta %82.3 -- yani eşiği DEĞİŞTİRMEDEN soft-vote'a geçmek gerçek
# DoS paketlerinin ~%11'ini olgunluk kapısına takılır hâle getirir.
#
# KALİBRASYON KURALI (eşiklerin DEĞERLENDİRME KORPUSUNA uydurulmasını önler --
# `scratchpad/calibrate_floors.py`): eşikler YALNIZCA eğitim split'inin
# held-out'unda (n=127.678) eşlenir ve kural "SALDIRI-tarafı eşdeğer
# geçirgenlik"tir: yeni eşik, eski eşiğin GERÇEK SALDIRI satırlarında
# reddettiği oranın AYNISINI reddedecek şekilde seçilir (recall-nötr hedefi).
# Benign taraftaki iyileşme o zaman "bedava kazanç" olarak okunabilir:
#     eski 0.85 -> 0.6669 | saldırı geçen %95.57 (aynı) | benign geçen %2.53 -> %0.45
#     eski 0.92 -> 0.7173 | saldırı geçen %94.19 (aynı) | benign geçen %2.14 -> %0.44
#     eski 0.95 -> 0.7458 | saldırı geçen %93.47 (aynı) | benign geçen %1.97 -> %0.43
#     eski 0.97 -> 0.7867 | saldırı geçen %92.73 (aynı) | benign geçen %1.72 -> %0.41
#     eski 0.98 -> 0.8669 | saldırı geçen %89.92 (aynı) | benign geçen %1.37 -> %0.35
# UYARI: held-out oturum-ezberlidir (bkz. project_r26_behavioral_committee.md
# Kanıt 1: saldırı sınıflarında 1-NN p50 ~0.002) -> ağaç modelleri burada
# yapay olarak iyi görünür. Bu yüzden bu set ÇAPRAZ-GÜN korpusunda AYRICA
# ölçülmeden üretime alınmamalıdır.
#
# REDDEDİLEN ALTERNATİF: "BENIGN-tarafı eşdeğer geçirgenlik" eşlemesi
# (0.85->0.31, 0.92->0.32, 0.95->0.33, 0.97->0.33) ÖLÇÜLDÜ ve ELENDİ --
# üretilen eşiklerin HEPSİ ALERT_THRESHOLD'un (0.4) ALTINDA kalıyor, yani
# olgunluk kapısını ve Strateji F'yi fiilen SİLİYOR. Tekrar önerme.
#
# VARSAYILAN KAPALI. Yalnızca MC_R26_SOFTVOTE=1 İKEN ve MC_R26_SOFTVOTE_FLOORS=1
# verilirse devreye girer; ikisi de kapalıyken ACTIVE_* isimleri yukarıdaki
# ORİJİNAL sabitlere bağlanır (bit-düzeyinde eski davranış).
MC_R26_SOFTVOTE_FLOORS = os.environ.get("MC_R26_SOFTVOTE_FLOORS", "0") == "1"
# ── (R26 FAZ 2 / EARLY-RAW) early_attack'i HAM LSTM skoruna bağlama seçeneği ──
# NEDEN VAR: soft-vote'un TEK ölçülmüş bedeli DoS-Hulk'un AÇILIŞ fazındaki
# alarm yoğunluğudur (canli_trafik_kaydi.csv: 179 paket, hepsi paket 2649-3350
# aralığında; ilk-alarm gecikmesi DEĞİŞMEZ, bin 3-21'de fark SIFIR). Kök neden
# ölçüldü: kaybedilen 179 paketin risk_score'u TAM 0.399 = eşik-altı clamp ->
# early_attack muafiyeti düştüğü için olgunluk kapısı + Strateji E devreye
# giriyor. R12'nin bu muafiyeti tam olarak bu senaryo için vardı.
#
# ÖLÇÜLDÜ VE REDDEDİLDİ (2026-08-14, canli_trafik_kaydi.csv):
#   base                     : DR .9655  FP   9  MCC .9730
#   soft-vote                : DR .9072  FP   0  MCC .9334
#   soft-vote + EARLY_RAW    : DR .9655  FP 109  MCC .9495   <- bu seçenek
#   soft-vote + yeni floor'lar: DR .9192 FP 100  MCC .9177
# EARLY_RAW gerçekten TÜM DoS TP'sini geri getiriyor (2965 = base ile birebir)
# AMA aynı dilimde FP'yi 9 -> 109 çıkarıyor: muafiyet ham LSTM'e bağlanınca
# LSTM'in kendi zayıf karar sınırı kapıları atlatma yetkisini geri kazanıyor.
# Net MCC hâlâ base'in ALTINDA -> ÜRETİM ADAYI DEĞİL, yalnızca A/B/teşhis için.
MC_R26_SOFTVOTE_EARLY_RAW = (os.environ.get("MC_R26_SOFTVOTE_EARLY_RAW", "0") == "1"
                             and MC_R26_SOFTVOTE)
SOFTVOTE_FLOOR_MAP = {"DDoS": 0.8669, "DoS": 0.7173, "WebAttack": 0.7867}
SOFTVOTE_DEFAULT_FLOOR = 0.7458
SOFTVOTE_EARLY_ATTACK_LSTM = 0.6669

if MC_R26_SOFTVOTE and MC_R26_SOFTVOTE_FLOORS:
    ACTIVE_FLOOR_MAP = SOFTVOTE_FLOOR_MAP
    ACTIVE_DEFAULT_FLOOR = SOFTVOTE_DEFAULT_FLOOR
    ACTIVE_EARLY_ATTACK_LSTM = SOFTVOTE_EARLY_ATTACK_LSTM
    print(f"🗳️ R26 Faz 2: floor'lar YENİDEN KALİBRE EDİLMİŞ setle çalışıyor "
          f"({SOFTVOTE_FLOOR_MAP}, default={SOFTVOTE_DEFAULT_FLOOR}, "
          f"early_attack={SOFTVOTE_EARLY_ATTACK_LSTM}).")
else:
    ACTIVE_FLOOR_MAP = LSTM_FLOOR_PER_CLASS
    ACTIVE_DEFAULT_FLOOR = DEFAULT_LSTM_FLOOR
    ACTIVE_EARLY_ATTACK_LSTM = EARLY_ATTACK_LSTM

# Strateji A: CDN / çok-hedefe-konuşan kaynak filtresi.
CDN_DST_THRESHOLD = 3

# Strateji D: DoS/DDoS kaynak sayısı disambiguasyonu.
DDOS_MIN_UNIQUE_SRC = 3

# ── (R37/D1) HACİMSEL DALDA PORT-FARKINDALIĞI ───────────────────────────────
# KÖK NEDEN (R36 ölçümü, agent-memory/cybersecurity-pipeline-strategist/
# project_r36_webattack_class_misattribution.md Kanıt-2a): hacimsel dalın
# "RF-override" kolu (`rf_class_name == "BENIGN"` iken imzanın etiketi KENDİSİ
# ÜRETTİĞİ durum) dst_port'u HİÇ görmüyordu. ESP32'nin port-80/3000 WebAttack
# trafiği bu kolda 1798 kez koşulsuz "DoS" etiketlendi; bu dalda WebAttack'a
# ulaşmanın TEK yolu RF'in kendisinin WebAttack demesidir, hiç demedi.
#
# NE DEĞİŞTİ / NE DEĞİŞMEDİ (kasıtlı olarak DAR kapsam):
#   * predicted_class KANONİK 7-sınıf sözlüğünde KALIR ("DoS"/"DDoS").
#     Yeni bir sınıf dizesi UYDURULMAZ -- dashboard_v2.html slug haritası,
#     mongo_logger_multiclass._classify_attack_type() ve
#     validate_all_days_multiclass.py'nin dispatch_vs_gt tablosu bu sözlüğe
#     bağlıdır. Etiketi "WebAttack"a çevirmek de YANLIŞ olurdu: bu kol RF'in
#     BENIGN dediği yerde çalışır, elinde WebAttack LEHİNE hiçbir kanıt yok.
#   * risk_score / status / alert_source / attack_type DEĞİŞMEZ -> DR/FAR/MCC
#     üzerinde YAPISAL OLARAK etkisizdir (ölçüldü, aşağıdaki nota bkz.).
#   * DEĞİŞEN: detected_attack_name artık portu ve "bu koldan DoS/DDoS ile
#     WebAttack-flood ayrımı YAPILAMAZ" belirsizliğini AÇIKÇA taşır; ayrıca
#     Mongo'ya sorgulanabilir `flood_app_layer_ambiguous` bayrağı yazılır.
#
# DoS-Hulk REGRESYON KONTROLÜ (kullanıcının açık talebi): Wednesday DoS-Hulk
# DE port 80 kullanır. Bu değişiklik onu "artık DoS değil" YAPMAZ --
# predicted_class hâlâ "DoS", alarm hâlâ üretilir; yalnızca ad alanına
# "port=80, ayrım belirsiz" notu eklenir. offline_test_multiclass.py'de
# (DoS-Hulk korpusu) ÖNCE/SONRA DR/FAR/MCC/TP BİREBİR AYNI ölçüldü.
#
# Port kümesi: yaygın HTTP(S)/uygulama-katmanı hizmet portları. 3000 ESP32
# testinde kullanılan Node/Grafana-tarzı port; 8000/8443/8888 aynı ailenin
# yaygın üyeleri. DİKKAT: buraya 21/22 EKLENMEZ -- FTP/SSH selleri gerçekten
# DoS/DDoS ailesidir, "WebAttack-flood" alternatifi yoktur.
APP_LAYER_FLOOD_PORTS = {80, 443, 3000, 8000, 8080, 8443, 8888}
R37_D1_PORT_AWARE_FLOOD = os.environ.get("MC_R37_D1", "1") != "0"


def _flood_override_name(prefix, flood_label, dst_port):
    """(R37/D1) İmzanın KENDİ ÜRETTİĞİ (RF-override) hacimsel etiket için
    port-farkındalıklı ad. `is_app_layer` ikinci dönüş değeri Mongo'ya
    `flood_app_layer_ambiguous` olarak yazılır."""
    port = _to_int(dst_port, 0)
    if not R37_D1_PORT_AWARE_FLOOD:
        return f"{prefix} -> {flood_label} (RF-override)", None
    if port in APP_LAYER_FLOOD_PORTS:
        return (f"{prefix} -> {flood_label} (RF-override, port={port}: uygulama-katmanı "
                f"seli -- {flood_label}/WebAttack-flood ayrımı BELİRSİZ)"), True
    return f"{prefix} -> {flood_label} (RF-override, port={port})", False

# Strateji izleme yapıları (canlı süreç boyunca kalıcı YAPI, ama İÇERİK
# VOL_WINDOW_SECONDS kayan penceresiyle sıfırlanır -- self.scan/self.volumetric
# (R17/R22) ile AYNI desen. (R27) ESKİDEN hiç sıfırlanmıyordu: 7/24 koşuda
# birkaç saat içinde neredeyse her src_ip "CDN" latch'ine düşüp gerçek DDoS'lar
# lstm_score*0.7 ile sürekli bastırılıyordu (Strateji A), VE bir (dst,port)
# çifti TARİHTE bir kez 3 farklı kaynaktan görülmüşse sonsuza dek "DDoS"
# etiketleniyordu (Strateji D) -- tek-kaynaklı bir DoS bile. Ayrıca sınırsız
# bellek büyümesi riski vardı; STRATEGY_DICT_MAX ile EVICT_VOLUMETRIC_MAX/
# EVICT_SCAN_MAX'la aynı güvenlik ağı eklendi (bkz. periyodik temizlik bloğu).
src_dst_universe: dict = defaultdict(lambda: {"dsts": set(), "win_start": 0.0})
attack_srcs_per_target: dict = defaultdict(lambda: {"srcs": set(), "win_start": 0.0})
STRATEGY_DICT_MAX = 200_000


def _is_cdn_source(src_ip, dst_ip, now_s):
    """Strateji A: src'nin gördüğü tüm dst'leri VOL_WINDOW_SECONDS kayan
    pencerede sayar (R27 fix -- yukarıdaki yorum)."""
    st = src_dst_universe[src_ip]
    if now_s > 0 and (now_s - st.get("win_start", now_s)) > VOL_WINDOW_SECONDS:
        st["dsts"] = set()
        st["win_start"] = now_s
    st["dsts"].add(dst_ip)
    return len(st["dsts"]) >= CDN_DST_THRESHOLD


# ── (R37/D2) STRATEJİ-D KAYNAK KÜMESİNDE PAKET-YÖNÜ KARIŞIKLIĞI ────────────
# KÖK NEDEN (R36 Kanıt-3): kümenin anahtarı `(dst_ip, dst_port)` idi; ama
#   dst_ip  = PAKETİN kendi hedefi (yön-duyarsız)
#   dst_port = master_features["Destination Port"] = AKIŞIN kanonik hedef portu
# yani anahtarın yarısı paket-düzeyi, yarısı akış-düzeyiydi. Sonuç: host'un
# KENDİ giden web trafiğine (ör. `192.168.1.102 -> CDN:80`) gelen YANIT
# paketlerinde paket-dst = 192.168.1.102 ve akış-dst-portu = 80 olduğu için
# uzak CDN sunucuları `(192.168.1.102, 80)` anahtarına "saldırgan kaynak"
# olarak yazılıyordu. Canlı Mongo doğrulaması 15+ farklı yabancı kaynak
# (Canonical, Akamai, Fastly, Google...) buldu -> DDOS_MIN_UNIQUE_SRC=3
# kolayca aşılıyor ve TEK KAYNAKLI bir DoS "DDoS"a yükseltiliyordu
# (R36'da 100 kayıt, hepsi tek gerçek saldırgandan).
#
# ÇÖZÜM: anahtar da, sayılan kaynak da AKIŞIN KANONİK YÖNÜNDEN (R17
# orientation düzeltmesinden sonraki istemci->hedef yönü) türetilir ve küme
# YALNIZCA ileri-yön (istemci->hedef, yani gerçek saldırı yönü) paketlerinde
# GÜNCELLENİR. Ters-yön paketler kümeyi OKUR ama KİRLETMEZ -- böylece bir
# saldırının yanıt-yönü paketleri hâlâ doğru etiketlenir.
#
# R28'in DDOS_MIN_UNIQUE_SRC=3 GEREKÇESİ BOZULMAZ: eşik ve semantiği aynen
# korunur; değişen yalnızca kümeye NEYİN yazıldığıdır. Gerçek bir DDoS'ta N
# saldırganın her biri kendi akışının ileri yönünde paket üretir -> hepsi
# `(kurban, port)` anahtarına yazılır, sayım eskisi gibi çalışır.
R37_D2_ORIENTED_DDOS_SRC = os.environ.get("MC_R37_D2", "1") != "0"


def _ddos_src_context(flow_table_obj, flow_key, src_ip, dst_ip, dst_port):
    """(R37/D2) Strateji-D için yön-farkındalıklı (anahtar, kaynak, ileri_yön_mü)
    üçlüsü. Akış tabloda yoksa (anomaly_fallback) R37 öncesi paket-düzeyi
    davranışa düşer -- fail-safe, davranış DEĞİŞMEZ."""
    if not R37_D2_ORIENTED_DDOS_SRC:
        return (dst_ip, dst_port), src_ip, True
    flow = flow_table_obj.flows.get(flow_key) if flow_key is not None else None
    if flow is None:
        return (dst_ip, dst_port), src_ip, True
    # fwd_src_key = "ip:port" (IPv6'da da son ':' port ayırıcısıdır)
    fwd_src_key = flow.get("fwd_src_key") or ""
    client_ip = fwd_src_key.rsplit(":", 1)[0] if ":" in fwd_src_key else src_ip
    is_fwd = (client_ip == src_ip)
    target_ip = dst_ip if is_fwd else src_ip
    return (target_ip, dst_port), client_ip, is_fwd


def _apply_dos_ddos_disambiguate(pred_class, key, src_for_set, is_fwd, now_s):
    """Strateji D: tahmin DDoS/DoS ise hedefe-saldıran benzersiz kaynak
    sayısına göre düzeltir (process_pcap.py ikili sürümde karşılığı yok --
    bu yalnızca multiclass'ta DoS vs DDoS ayrımı gerektiğinde devreye girer).
    (R27 fix) VOL_WINDOW_SECONDS kayan pencere.
    (R37/D2) anahtar/kaynak artık _ddos_src_context()'ten gelir ve küme
    yalnızca ileri-yön paketlerde güncellenir -- yukarıdaki uzun nota bkz."""
    if pred_class not in ("DDoS", "DoS"):
        return pred_class
    st = attack_srcs_per_target[key]
    if now_s > 0 and (now_s - st.get("win_start", now_s)) > VOL_WINDOW_SECONDS:
        st["srcs"] = set()
        st["win_start"] = now_s
    if is_fwd:
        st["srcs"].add(src_for_set)
    n_unique = len(st["srcs"])
    if pred_class == "DDoS" and n_unique < DDOS_MIN_UNIQUE_SRC:
        return "DoS"
    if pred_class == "DoS" and n_unique >= DDOS_MIN_UNIQUE_SRC:
        return "DDoS"
    return pred_class


def _second_best_class(proba):
    """Strateji G: argmax BENIGN olsa da risk_score (counter veya olasılık-
    kütlesi birden çok saldırı sınıfına dağılmış olabileceğinden) eşiği
    geçtiğinde, çelişkili "Tehdit Yok (BENIGN)" / "LSTM: BENIGN" etiketi
    yerine gösterilecek en olası İKİNCİ (BENIGN olmayan) sınıfı döndürür.
    Tuesday canlı koşusunda 70/2059 alarmda bu çelişki gözlendi (Counter
    eşiği aşıyor ama argmax hâlâ BENIGN) -- bkz. process_multiclass_live_pipeline notu."""
    order = np.argsort(proba)[::-1]
    for idx in order:
        if idx != BENIGN_INDEX:
            return CLASSES_LIST[idx]
    return CLASSES_LIST[BENIGN_INDEX]


print(f"🚀 Paket bekleniyor (MULTICLASS, INPUT_MODE='{INPUT_MODE}')...")
_emit_ready()
for packet in _packet_source():
    try:
        STATS["total_packets"] += 1

        if not isinstance(packet, dict):
            STATS["dropped_packets"] += 1
            print(f"⚠️ [DÜŞEN] dict olmayan mesaj atlandı (tip={type(packet).__name__})")
            _log_stats()
            continue

        # (R17 parite -- bkz. process_pcap.py) IP katmani olmayan paketleri
        # (ARP/saf L2) dusur -- akis tablosuna hic girmezler.
        if _is_non_ip(packet):
            STATS["non_ip_packets"] += 1
            _log_stats()
            continue

        packet_no = packet.get("frame.number", "Bilinmiyor")
        src_ip = _get_src_ip(packet)
        dst_ip = _get_dst_ip(packet)
        flags = packet.get("tcp.flags", "0x0000")

        if (packet.get("ip.src") in (None, '')) and (packet.get("ipv6.src") not in (None, '')):
            STATS["ipv6_packets"] += 1

        print(f"📥 [YAKALANDI] Paket No: {packet_no} | {src_ip} -> {dst_ip} | Bayrak: {flags}")

        now_s = _to_float(packet.get("frame.time_epoch"), 0.0)

        # Strateji A: src'nin gördüğü tüm dst'leri kaydet (CDN tespiti, R27: kayan pencere)
        is_cdn_src = _is_cdn_source(src_ip, dst_ip, now_s)

        # ── ÖZNİTELİK ÇIKARIMI ───────────────────────────────────────
        master_features, flow_key = flow_table.extract_universal_features(packet)
        if master_features is None:
            STATS["anomaly_fallback"] += 1
            print(f"⚠️ Uyarı: anomali içeriyor, varsayılan değerlerle işleniyor... "
                  f"(toplam anomali_fallback={STATS['anomaly_fallback']})")
            master_features = {col: 0.0 for col in RAW_COLUMNS}
            master_features["PSH Flag Count"] = 1.0
            master_features["Destination Port"] = 0.0
            flow_key = None

        dst_port = master_features.get("Destination Port", 0.0)

        # (R37/D2) Strateji-D kaynak kümesi için yön-farkındalıklı bağlam.
        # Paket başına BİR kez hesaplanır; hem _apply_dos_ddos_disambiguate
        # hem de hacimsel daldaki RF-override n_srcs sayımı AYNI anahtarı
        # kullanır (eskiden ikisi farklı anahtar üretebiliyordu).
        _ddos_key, _ddos_src, _ddos_is_fwd = _ddos_src_context(
            flow_table, flow_key, src_ip, dst_ip, dst_port)

        if STATS["total_packets"] % EVICT_EVERY_N_PKTS == 0:
            now_us = now_s * 1_000_000
            if now_us > 0:
                rf, rv, rs = flow_table.evict_stale(now_us, FLOW_TTL_US)
                STATS["evicted_flows"] += rf
                if rf or rv or rs:
                    print(f"🧹 [TEMİZLİK] ölü_akış={rf} volumetric_reset={rv} scan_reset={rs}")
            # (R27) src_dst_universe/attack_srcs_per_target guvenlik agi --
            # VOL_WINDOW_SECONDS penceresi her anahtarin KENDI icerigini
            # sifirlar ama artik dokunulmayan (dead) anahtarlar sozlukte
            # kalir; EVICT_VOLUMETRIC_MAX/EVICT_SCAN_MAX ile ayni desen.
            if len(src_dst_universe) > STRATEGY_DICT_MAX:
                src_dst_universe.clear()
                print(f"🧹 [TEMİZLİK] src_dst_universe sınırı aşıldı, temizlendi")
            if len(attack_srcs_per_target) > STRATEGY_DICT_MAX:
                attack_srcs_per_target.clear()
                print(f"🧹 [TEMİZLİK] attack_srcs_per_target sınırı aşıldı, temizlendi")

        rate_value = float(master_features.get(VOLUMETRIC_FEATURE, 0.0))

        (is_flood, vol_pkts, vol_syn, vol_ratio, is_scan, distinct_ports,
         is_conn_flood, distinct_conns) = flow_table.update_volumetric(packet)

        # (R33 parite) rate sinyali artik SABIT-PAYDALI pencereden gelir; R10'un
        # `flow_total_pkts >= 2` kosulu gereksizlesti (100 ms'de >=2500 paket
        # isteyen bir kapiyi tek-paketlik akis tanim geregi gecemez).
        # rate_value (oznitelik) DEGISMEZ -- yalnizca YONLENDIRME karari degisti.
        rate_win_pkts = (flow_table.update_rate_window(flow_key, now_s)
                         if flow_key is not None else 0)
        rate_trigger = rate_win_pkts >= RATE_WIN_MIN_PKTS
        # (R28/O1.3) dorduncu volumetrik tetikleyici.
        is_volumetric = bool(is_flood or is_scan or rate_trigger or is_conn_flood)

        _udp_sport = _to_int(packet.get("udp.srcport"), 0)
        _udp_dport = _to_int(packet.get("udp.dstport"), 0)
        _tcp_flags_int = _parse_tcp_flags(packet.get("tcp.flags"))
        is_dns_packet = (_udp_sport == 53 or _udp_dport == 53) and _tcp_flags_int == 0
        if is_dns_packet and is_volumetric:
            STATS["dns_devolumetric"] += 1
            is_volumetric = False

        # PERF (parite -- bkz. pipeline/process_pcap.py::_feature_row): tek
        # satirlik pandas DataFrame ara katmani kaldirildi. PIPELINE numpy
        # uzerinde fit edildi, DataFrame hicbir ise yaramadan paket basina
        # ~0.39ms tutuyordu. Giden dizi birebir ayni (sira + float64).
        scaled_input = PIPELINE.transform(_feature_row(master_features))
        if not np.isfinite(scaled_input).all():
            STATS["sanitized_features"] += 1
        scaled_input = _sanitize_matrix(scaled_input)

        predicted_class = None
        # (R37/D1) yalnizca hacimsel dalin RF-override kollarinda dolar;
        # diger tum yollarda None kalir ve Mongo'ya "bu paket icin anlamsiz"
        # olarak gecer (dst_is_multicast/ood_gate_applied ile ayni desen).
        flood_app_layer_ambiguous = None
        is_ood, ood_dist, ood_pval = False, None, None  # (R19/R20/S5 parite) yalnizca non-volumetrik dalda degerlendirilir
        suppressed_by = None  # (S4) yalnizca non-volumetrik dalda doldurulur
        # (N3 parite -- bkz. pipeline/process_pcap.py'deki ayni satir) Yalnizca
        # LSTM+Counter dalinda dolar; volumetrik dalda None kalir ve
        # mongo_logger'a "bu alan bu dalda anlamsiz" diye gecer. Bu alanlar
        # ikili hatta VARDI, multiclass'ta YOKTU: bir multiclass alarminin
        # LSTM'den mi Counter'dan mi geldigi ve akis yonunun ters donup
        # donmedigi Mongo'dan ayirt EDILEMIYORDU (canli-ates denetimi: ikili
        # 28490/28490 dolu, multiclass 0/28534).
        lstm_score = counter_score = prog_pkts = susp_ratio = None

        if is_volumetric:
            # ── (R29/O4 parite -- bkz. pipeline/process_pcap.py'deki uzun not)
            # VOLUMETRİK DALDA OOD ÖLÇÜMÜ, SALT GÖZLEM. Mesafe hesaplanıp
            # loglanır, is_ood False KALIR -> karar deterministik hacimsel
            # imzada. Mevcut (non-volumetrik) referans bu dal için de geçerli:
            # eğitimdeki volumetrik-uygun BENIGN satırların (2442, %0.37) bu
            # referansa mesafesi p50=0.90, p99=5.71, max=17.25 -> %0.00'ı
            # eşiği (30) aşıyor. Ayrı volumetrik referans ÖLÇÜLDÜ ve
            # REDDEDİLDİ (n=1221 çok küçük, ek dosya gereksiz).
            ood_dist = ood_distance(scaled_input[0])
            ood_pval = ood_pvalue(ood_dist)
            if ood_dist is not None and ood_dist > OOD_DISTANCE_THRESHOLD:
                STATS["ood_volumetric_observed"] += 1

            # ══ VOLUMETRİK DAL -> MulticlassRF ══
            # (R27/Y2) ONNX-öncelikli, joblib-yedekli: ONNX yoksa/hata
            # verirse main_rf.predict_proba'ya (26.6ms/paket, ölçüldü) düşer
            # -- yavaş ama doğru. Normalde ONNX (~0.02ms) kullanılır.
            model_name = "MulticlassRF (hacimsel sınıflandırıcı)"
            rf_proba = _rf_onnx_proba_or_none(scaled_input[0])
            if rf_proba is None:
                rf_proba = main_rf.predict_proba(scaled_input)[0]
            p_benign_rf = float(rf_proba[BENIGN_INDEX])
            rf_risk = 1.0 - p_benign_rf
            rf_class_idx = int(np.argmax(rf_proba))
            rf_class_name = CLASSES_LIST[rf_class_idx]

            rf_class_name = _apply_dos_ddos_disambiguate(
                rf_class_name, _ddos_key, _ddos_src, _ddos_is_fwd, now_s)

            if is_flood:
                # (R28/O1.1 parite) iki kollu guven -- oran-agirlikli klasik kol
                # ile oran-BAGIMSIZ mutlak-hacim rampasinin max()'i.
                flood_conf = float(max(
                    vol_ratio * min(vol_syn / (SYN_BURST_MIN * 3), 1.0),
                    min(vol_syn / SYN_ABS_FULL, 1.0) if vol_syn >= SYN_ABS_MIN else 0.0,
                ))
                risk_score = max(rf_risk, flood_conf)
                if rf_class_name == "BENIGN":
                    # Strateji C: flood imzası var ama RF BENIGN diyor -> kaynak
                    # sayısına göre RF'i override et (deterministik imza skoru korunur).
                    n_srcs = len(attack_srcs_per_target.get(_ddos_key, {src_ip}))
                    flood_label = "DoS" if n_srcs < DDOS_MIN_UNIQUE_SRC else "DDoS"
                    predicted_class = flood_label
                    # (R37/D1) port-farkındalıklı ad -- predicted_class DEĞİŞMEZ.
                    detected_attack_name, flood_app_layer_ambiguous = _flood_override_name(
                        "Hacimsel/SYN-Flood", flood_label, dst_port)
                else:
                    predicted_class = rf_class_name
                    detected_attack_name = f"Hacimsel/SYN-Flood -> {rf_class_name}"
                alert_source = "İmza+ML" if rf_risk >= ALERT_THRESHOLD else "İmza"
            elif is_conn_flood:
                # (R28/O1.3 parite) hedef-toplulastirmali baglanti seli.
                # Cok-kaynakli oldugu icin varsayilan etiket DDoS; tek kaynak
                # sayilirsa Strateji-D disambiguasyonu DoS'a cevirir.
                conn_conf = float(min(
                    max(distinct_conns - CONN_FLOOD_MIN, 0) /
                    max(CONN_FLOOD_FULL - CONN_FLOOD_MIN, 1), 1.0))
                risk_score = max(rf_risk, conn_conf)
                if rf_class_name == "BENIGN":
                    n_srcs = len(attack_srcs_per_target.get(_ddos_key, {src_ip}))
                    conn_label = "DoS" if n_srcs < DDOS_MIN_UNIQUE_SRC else "DDoS"
                    predicted_class = conn_label
                    # (R37/D1) bağlantı seli kolu da aynı port-farkındalığını alır.
                    detected_attack_name, flood_app_layer_ambiguous = _flood_override_name(
                        "Baglanti Seli", conn_label, dst_port)
                else:
                    predicted_class = rf_class_name
                    detected_attack_name = f"Baglanti Seli -> {rf_class_name}"
                alert_source = "İmza+ML" if rf_risk >= ALERT_THRESHOLD else "İmza"
            elif is_scan:
                scan_conf = float(min(
                    max(distinct_ports - PORT_SCAN_MIN_PORTS, 0) /
                    (PORT_SCAN_FULL_PORTS - PORT_SCAN_MIN_PORTS), 1.0))
                if rf_class_name == "BENIGN" and distinct_ports < SCAN_RF_VETO_MAX_PORTS:
                    # (R28/O1.2 pariteti) KOSULSUZ VETO -> distinct_ports-KAPILI.
                    # Eski davranis: is_scan iken RF BENIGN derse alarm HER ZAMAN
                    # bastiriliyordu. Ikili hatta olculdu ki bu KOSULSUZ hali
                    # gercek taramalari da siliyor (8512 TP); ayirt edici
                    # distinct_ports BUYUKLUGU: benign 'port cesitliligi' onlarca
                    # (p75=77), gercek nmap taramasi binlerce (p25=997) porta
                    # dokunuyor. Bu slice'ta koşulsuz veto 120 GERCEK saldiri
                    # paketini (ters-yon DoS) bastiriyordu -- O3.2'nin cift-yonlu
                    # GT'si onu gorunur kildi.
                    # Strateji C: scan imzası var ama RF BENIGN diyor -> RF'e güvenip bastır.
                    # (R27/O4 fix) S4 inceleme kuyruğu bu bastırmayı eskiden
                    # GÖREMİYORDU -- suppressed_by yalnızca non-volumetrik
                    # dalda dolduruluyordu. scan_conf zaten eşik-üstü
                    # olabileceği için (imza güçlü ama RF reddediyor) bu
                    # potansiyel-sinyal artık review_suppressed_queue.py'de görünür.
                    if scan_conf >= ALERT_THRESHOLD and suppressed_by is None:
                        suppressed_by = "scan_rf_benign"
                    risk_score = min(rf_risk, ALERT_THRESHOLD - 1e-3)
                    predicted_class = "BENIGN"
                    detected_attack_name = "Tehdit Yok (Scan+RF:BENIGN bastırıldı)"
                    alert_source = None
                else:
                    risk_score = max(rf_risk, scan_conf)
                    # (R28/O1.2) RF BENIGN diyor AMA port cesitliligi gercek-tarama
                    # bandinda (>=SCAN_RF_VETO_MAX_PORTS) -> imza RF'i ezer. Etiketi
                    # "BENIGN" birakmak celiskili olurdu (alarm var, sinif BENIGN);
                    # hacimsel daldaki RF-override deseniyle ayni sekilde imzanin
                    # kendi sinifi (PortScan) kullanilir.
                    if rf_class_name == "BENIGN":
                        predicted_class = "PortScan"
                        detected_attack_name = "Port-Tarama -> PortScan (RF-override)"
                    else:
                        predicted_class = rf_class_name
                        detected_attack_name = f"Port-Tarama -> {rf_class_name}"
                    alert_source = "İmza+ML" if rf_risk >= ALERT_THRESHOLD else "İmza"
            else:
                risk_score = rf_risk
                if rf_class_name == "BENIGN" and risk_score >= ALERT_THRESHOLD:
                    # Strateji G: argmax BENIGN ama 1-P(BENIGN) eşiği geçti (olasılık
                    # kütlesi birden çok saldırı sınıfına dağılmış) -> çelişkili
                    # "Tehdit Yok (BENIGN)" yerine ikincil sınıfı göster.
                    predicted_class = _second_best_class(rf_proba)
                    detected_attack_name = f"Hacimsel Anomali -> {predicted_class} (ikincil-sınıf, argmax=BENIGN)"
                    alert_source = "ML"
                elif rf_class_name == "BENIGN":
                    predicted_class = "BENIGN"
                    detected_attack_name = "Tehdit Yok (BENIGN)"
                    alert_source = None
                else:
                    predicted_class = rf_class_name
                    detected_attack_name = f"Hacimsel Anomali -> {rf_class_name}"
                    alert_source = "ML"

            yon_etiketi = "VOLUMETRİK"
            print(f"    🧭 Yönlendirme: {yon_etiketi} (SYN-burst={vol_syn}/{vol_pkts}, scan_ports={distinct_ports}, rate={rate_value:.0f}, pencere_pkt={rate_win_pkts}/{RATE_WIN_MIN_PKTS}) -> {model_name}")
            print(f"       RF_risk={rf_risk:.8f} | RF_class={rf_class_name} | is_flood={is_flood} | is_scan={is_scan} | is_conn_flood={is_conn_flood}")
            if risk_score >= ALERT_THRESHOLD:
                print(f"🚨 [ALERT - HACİMSEL SİBER SALDIRI!]")
                print(f"    📈 Sürekli Saldırı Skoru : {risk_score:.8f}")
                print(f"    💥 Tahmin                : {detected_attack_name}")
                print(f"    🧭 Tetikleyen            : {alert_source}")
                print(f"    🧠 Tespit Eden Yapı       : {model_name}")
            else:
                print(f"🟢 [NORMAL] RF -> BENIGN | Skor: {risk_score:.8f} | {detected_attack_name}")

        else:
            # ══ NON-VOLUMETRİK DAL -> MulticlassLSTM + Progressive Counter ══
            model_name = "MulticlassLSTM + Progressive Counter"
            # (S4) Bu dalin herhangi bir bastirma kapisi (immature-flow/R18/R23/
            # K3/Strateji-E/Strateji-F/K1) risk_score'u ESIGIN USTUNDEN ALTINA
            # cekerse, HANGI kapinin yaptigini kaydeder (ilk-bastiran-kazanir).
            # Amac: "sessizce BENIGN" ile "bir kapi tarafindan bastirilmis
            # potansiyel-sinyal" ayrimini Mongo'da gorunur kilmak -- aktif
            # ogrenme/inceleme kuyrugunun temeli. Bkz. mongo_logger_multiclass.py
            # suppressed_by alani.
            suppressed_by = None

            try:
                n_feat_expected = main_lstm.input_shape[-1]
            except Exception:
                n_feat_expected = scaled_input.shape[1]

            curr_feat = scaled_input.shape[1]
            if curr_feat < n_feat_expected:
                pad = np.zeros((scaled_input.shape[0], n_feat_expected - curr_feat))
                lstm_in_data = np.hstack([scaled_input, pad])
            else:
                lstm_in_data = scaled_input[:, :n_feat_expected]

            lstm_input = lstm_in_data.reshape(lstm_in_data.shape[0], 1, n_feat_expected)
            lstm_proba_raw = lstm_predict_fast(lstm_input)[0]
            if not np.isfinite(lstm_proba_raw).all():
                STATS["sanitized_features"] += 1
                lstm_proba_raw = np.zeros(N_CLASSES, dtype="float32")
                lstm_proba_raw[BENIGN_INDEX] = 1.0

            # (R26 Faz 2) KARAR VEKTÖRÜ -- bkz. softvote_proba() yorum bloğu.
            # Soft-vote KAPALI (varsayılan) iken decision_proba IS lstm_proba_raw
            # -> aşağıdaki her satır bit-düzeyinde eski davranıştır.
            _sv = softvote_proba(lstm_proba_raw, scaled_input[0])
            decision_proba = lstm_proba_raw if _sv is None else _sv
            # (R26 Faz 2 / EARLY-RAW) bkz. MC_R26_SOFTVOTE_EARLY_RAW yorumu.
            raw_lstm_score = 1.0 - float(lstm_proba_raw[BENIGN_INDEX])

            p_benign_lstm = float(decision_proba[BENIGN_INDEX])
            lstm_class_idx = int(np.argmax(decision_proba))
            lstm_class_name = CLASSES_LIST[lstm_class_idx]
            lstm_score = 1.0 - p_benign_lstm

            # Strateji A: CDN kaynağı + DDoS tahmini -> skoru hafifçe bastır.
            if lstm_class_name == "DDoS" and is_cdn_src:
                lstm_score = lstm_score * 0.7

            lstm_class_name = _apply_dos_ddos_disambiguate(
                lstm_class_name, _ddos_key, _ddos_src, _ddos_is_fwd, now_s)

            if flow_key is not None and flow_key in flow_table.flows:
                counter_score, susp_pkts, prog_pkts, susp_ratio = flow_table.update_progressive(
                    packet, flow_table.flows[flow_key]
                )
            else:
                counter_score, susp_pkts, prog_pkts, susp_ratio = 0.0, 0, 0, 0.0

            blended = LSTM_WEIGHT * lstm_score + COUNTER_WEIGHT * counter_score
            risk_score = float(max(lstm_score, counter_score, blended))

            effective_lstm_floor = ACTIVE_FLOOR_MAP.get(lstm_class_name, ACTIVE_DEFAULT_FLOOR)

            immature_flow = prog_pkts < PROG_MIN_PKTS and counter_score < ALERT_THRESHOLD
            _ea_score = (raw_lstm_score if MC_R26_SOFTVOTE_EARLY_RAW else lstm_score)
            _ea_floor = (EARLY_ATTACK_LSTM if MC_R26_SOFTVOTE_EARLY_RAW else ACTIVE_EARLY_ATTACK_LSTM)
            early_attack = (susp_pkts >= EARLY_ATTACK_MIN_SUSP) and (_ea_score >= _ea_floor)
            # (R34) KONSEY GÜVENCESİ -- bkz. committee_waives_early_attack().
            # Yalnızca muafiyet ADAYI paketlerde çağrılır (canlı ölçüm: 16.257
            # paketin 53'ü = %0.3), maliyet ihmal edilebilir.
            # (R37/D3) SINIF KAPSAMI -- bkz. COMMITTEE_WAIVER_EXEMPT_CLASSES.
            # Muaf sinifta konsey HIC CALISTIRILMAZ (R34'un ucuz-cikis
            # ozelligi korunur) ama olay sayilir -- canli maruziyet
            # "early_attack_committee_block" ile yan yana izlenebilsin.
            if early_attack and lstm_class_name in COMMITTEE_WAIVER_EXEMPT_CLASSES:
                STATS["early_attack_class_exempt"] += 1
            elif early_attack and committee_waives_early_attack(scaled_input[0]):
                early_attack = False
                STATS["early_attack_committee_block"] += 1
            if early_attack:
                STATS["early_attack_exception"] += 1
            init_win_fwd = float(master_features.get("Init_Win_bytes_forward", 0.0))
            # (R17/R18 parite -- bkz. process_pcap.py R13 yorumu) R13'un "pp<=1"
            # sarti "flow_table'in ILK GORDUGU paket" demekti. R17 flip'inden
            # sonra ayni artefakt (SYN'i gorulmemis akisin ilk ISTEMCI paketi)
            # pp>1'de olusur -- sunucu yonundeki paketler zaten sayilmistir.
            # Flip EDILMIS akislarda esdeger kosul "ilk forward paket"tir
            # (fwd_packets<=1); flip edilmemis akislarda eski davranis aynen korunur.
            _flow_now = flow_table.flows.get(flow_key) if flow_key is not None else None
            _fwd_pkts_now = _flow_now.get("fwd_packets", 0) if _flow_now is not None else 0
            _first_client_pkt = (prog_pkts <= 1) or (
                _flow_now is not None and _flow_now.get("flipped") and _fwd_pkts_now <= 1
            )
            client_established = _first_client_pkt and init_win_fwd <= INIT_WIN_CLIENT_MAX
            # (R28/O3.1 parite -- gerekce process_pcap.py IMMATURE_PENALTY_EXP)
            # R13 (client_established) = UYDURMA vektor -> sert clamp korunur.
            # R7/R8 (kanit zayif ama yok degil) -> olgunlukla olceklenen ceza.
            # (R28/O3.1) surekli olgunluk cezasi OLCULDU ve REDDEDILDI --
            # gerekce/olcum process_pcap.py'deki yorum blogunda. Iki-kollu
            # yapi ve ayri suppressed_by etiketleri KORUNDU (gozlemlenebilirlik).
            if immature_flow and (not early_attack):
                if client_established:
                    if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                        suppressed_by = "client_established"
                    risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)
                elif lstm_score < effective_lstm_floor:
                    if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                        suppressed_by = "immature_flow"
                    risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R18 parite -- bkz. process_pcap.py) YONU DOGRULANMAMIS AKIS KAPISI.
            # R17 flip'i uygulandigi ANDA akisin forward (istemci) tarafindan
            # henuz HIC paket gorulmemistir -> oznitelik vektorunun forward
            # yarisi UYDURMADIR (egitim dagiliminda karsiligi yok). DAR KAPSAM:
            # fwd_packets==0 SADECE flip edilmis akista olusabilir.
            if _flow_now is not None and _fwd_pkts_now == 0:
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "unverified_orientation"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R23) MULTICAST HEDEF ISTISNASI -- bkz. _is_multicast_ip yorumu.
            if _is_multicast_ip(dst_ip):
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "multicast"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R32/R52) SINIRLI-YAYIN + ALT-AG YAYINI HEDEF ISTISNASI -- bkz. _is_broadcast_ip.
            if _is_broadcast_ip(dst_ip, src_ip):
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "broadcast"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R24/K3 -- SAFE_EXCEPTIONS Tier C: delil-yetersizligi vetosu)
            # PORT-BUCKET DELIL-UYUMU KAPISI. Ablasyon (post-S1 model, agent-memory/
            # ids-generalization-strategist/project_r24_port_bucket_shortcut_root_cause.md):
            # SSH-Patator/FTP-Patator kararlari NEREDEYSE TAMAMEN port-bucket'a
            # dayanir -- PortBucket_ssh/ftp'yi BENIGN medyanina cekmek recall'i
            # 1.0000 -> 0.0000 dusuruyor (tam collapse); BENIGN davranis + dogru
            # bucket -> %99.76-99.77 guvenle SSH-Patator/FTP-Patator tahmin
            # ediliyor. Yani bu ailelerin karari PORT KIMLIGINE denk -- eger o
            # port kapali degilse (bucket uyusmuyorsa) egitim delili GECERSIZ.
            # DAR KAPSAM (sadece bu 2 aile): WebAttack AYRI olculdu ve AYNI
            # mekanizmayi TASIMIYOR -- ablasyon recall'i sadece 0.862->0.558
            # dusuruyor (kismi), ve "BENIGN davranis + http bucket" -> %83.7
            # BENIGN tahmin ediyor (SSH/FTP'nin tersine) -- WebAttack/CDN
            # ortusmesi bu kapiya EKLENMEDI (MC1'den beri bilinen, ayri bir
            # zayiflik, bkz. project-multiclass-overfitting-issues). DoS/DDoS/
            # PortScan ASLA bu kapiya girmez (port-agnostik saldirilar).
            # TELAFI KONTROLU YOK (S4 inceleme kuyrugu henuz kurulmadi) --
            # standart-disi porttaki (or. 2222) gercek SSH/FTP-Patator bu
            # kapiyla kacirilabilir, KABUL EDILEN risk (bkz. STATS sayaci).
            if lstm_class_name == "SSH-Patator" and master_features.get("PortBucket_ssh", 0.0) != 1.0:
                STATS["port_bucket_veto"] += 1
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "port_bucket_veto"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)
            elif lstm_class_name == "FTP-Patator" and master_features.get("PortBucket_ftp", 0.0) != 1.0:
                STATS["port_bucket_veto"] += 1
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "port_bucket_veto"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # Strateji E: düşük-SYN-sayısı kapısı (DoS/DDoS için).
            if lstm_class_name in ("DoS", "DDoS") and not is_flood and vol_syn < 20:
                if not early_attack:
                    if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                        suppressed_by = "low_syn_dos_gate"
                    risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # Strateji F: WebAttack mutlak skor eşiği (olgunluktan bağımsız).
            # MC1: "Bot" kapsam dışı bırakıldığı için bu kapıdan çıkarıldı.
            if lstm_class_name in ("WebAttack",):
                abs_floor = ACTIVE_FLOOR_MAP.get(lstm_class_name, ACTIVE_DEFAULT_FLOOR)
                if lstm_score < abs_floor and not early_attack:
                    if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                        suppressed_by = "webattack_abs_floor"
                    risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R24/K1 -- bkz. agent-memory/ids-generalization-strategist/
            # project_r24_port_bucket_shortcut_root_cause.md) ARGMAX-TUTARLILIK
            # KAPISI (eski "Strateji G"nin iptali). Eski davranis: argmax=BENIGN
            # iken risk_score (olasilik kutlesi 6 saldiri sinifina dagilip esigi
            # gectiginde) yine de "ikincil-sinif" olarak alarm veriyordu -- bu,
            # MODELIN KENDI KARARIYLA CELISEN bir etiketti (hicbir saldiri sinifi
            # argmax degil, ama toplamda alarm). Olculdu (test n=127678, LSTM
            # ciplak cikti): MCC 0.9196->0.9283, FAR 0.0513->0.0423 (781 FP
            # silindi), maliyet 201 TP (%0.49, kaybedilenin cogu zaten davranissal
            # dalda LSTM+counter ile ayrica yakalanan DoS). Canli 2026-08-06
            # kosusundaki FP'lerin %26'si bu kategoriydi. Ikili (binary) hattaki
            # ayni desen (rf_class_name=="BENIGN", ~satir 898) KASITLI
            # DOKUNULMADI -- ayri olcum gerektirir, bu R24 kapsaminda degil.
            if lstm_class_name == "BENIGN":
                if risk_score >= ALERT_THRESHOLD and suppressed_by is None:
                    suppressed_by = "argmax_consistency"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R26 Faz 1 -- bkz. yukarıdaki committee_dissents() yorumu)
            # DAVRANIŞSAL-DAL KONSEY VETOSU. Yalnızca hâlâ alarm eşiğinin
            # ÜSTÜNDE kalan paketlerde çağrılır (ucuz kapılar önce elenir,
            # ONNX maliyeti amortize <1ms/paket). RF VE HGB ikisi de BENIGN'e
            # güvenle katılıyorsa (LSTM'in kararıyla açıkça çelişiyorlarsa)
            # bastırılır.
            if risk_score >= ALERT_THRESHOLD and committee_dissents(scaled_input[0]):
                STATS["committee_dissent"] += 1
                if suppressed_by is None:
                    suppressed_by = "committee_dissent"
                risk_score = min(risk_score, ALERT_THRESHOLD - 1e-3)

            # (R19/R20 parite -- bkz. process_pcap.py) OOD/KAPSAM-DIŞI KAPISI.
            # scaled_input bu paket icin ustte (LSTM padding'inden ONCE) zaten
            # hesaplandi -> ek maliyet yok. risk_score'a BILEREK DOKUNULMAZ (ham
            # model guveni adli inceleme icin saklı kalsin); yalnizca NIHAI KARAR
            # (status/alert_source/detected_attack_name) UNKNOWN olur. Kosulsuz
            # uygulanir (R18 fwd==0 grubu dahil).
            ood_dist = ood_distance(scaled_input[0])
            ood_pval = ood_pvalue(ood_dist)  # (S5) sadece raporlanir, karari degistirmez
            is_ood = (ood_dist is not None) and (ood_dist > OOD_DISTANCE_THRESHOLD)
            if is_ood:
                STATS["ood_unknown"] += 1
                # (S4) status zaten ayrica UNKNOWN olacak; suppressed_by'a da
                # yazilir ki TEK alandan tum bastirma nedenleri sorgulanabilsin.
                if suppressed_by is None:
                    suppressed_by = "ood"

            if is_ood:
                predicted_class = "UNKNOWN"
                detected_attack_name = "Kapsam Dışı / Bilinmeyen Trafik (OOD)"
                alert_source = None
            elif risk_score >= ALERT_THRESHOLD:
                # (K1 sonrasi) lstm_class_name burada asla "BENIGN" olamaz --
                # yukaridaki kapi zaten o durumu esik-alti sabitledi.
                predicted_class = lstm_class_name
                detected_attack_name = f"Zamansal Anomali -> LSTM: {lstm_class_name}"
                alert_source = "LSTM+Counter"
            else:
                predicted_class = "BENIGN"
                detected_attack_name = "Tehdit Yok (BENIGN)"
                alert_source = None

            yon_etiketi = "ZAMANSAL/SIRALI"
            print(f"    🧭 Yönlendirme: {yon_etiketi} (rate={rate_value:.0f}) -> {model_name}")
            print(f"       LSTM={lstm_score:.8f} | LSTM_class={lstm_class_name} | Counter={counter_score:.8f} "
                  f"(şüpheli={susp_pkts}, pkt={prog_pkts}, şüpheli-oran={susp_ratio:.4f})")
            if is_ood:
                print(f"❓ [UNKNOWN - KAPSAM DIŞI] mesafe={ood_dist:.2f} (eşik={OOD_DISTANCE_THRESHOLD}) | risk_score(ham)={risk_score:.4f}")
            elif risk_score >= ALERT_THRESHOLD:
                print(f"🚨 [ALERT - SİBER SALDIRI RİSKİ YÜKSEK!]")
                print(f"    📈 Progressive Saldırı Skoru : {risk_score:.8f}")
                print(f"    💥 Tahmin                : {detected_attack_name}")
                print(f"    🧭 Tetikleyen            : {alert_source}")
                print(f"    🧠 Tespit Eden Yapı       : {model_name}")
            else:
                print(f"🟢 [NORMAL] Trafik Güvenli | Progressive Skor: {risk_score:.8f} | {detected_attack_name}")

        STATS["scored_packets"] += 1

        status = "UNKNOWN" if is_ood else ("ATTACK" if risk_score >= ALERT_THRESHOLD else "BENIGN")
        # (N3 parite -- bkz. pipeline/process_pcap.py) Akisin KANONIK (yon
        # duzeltmesinden sonraki) hedef portu. Paketin kendi tcp/udp.dstport'u
        # ile arasindaki fark, akis yonunun tersine donup donmedigini Mongo'dan
        # dogrudan sorgulanabilir kilar.
        flow_dst_port = (
            flow_table.flows[flow_key].get("dst_port")
            if flow_key is not None and flow_key in flow_table.flows
            else None
        )
        mongo_logger.log_prediction(
            packet, src_ip, dst_ip, risk_score, status, ALERT_THRESHOLD,
            detected_attack_name, model_name, is_volumetric,
            alert_source=alert_source, predicted_class=predicted_class,
            lstm_score=lstm_score, counter_score=counter_score,
            prog_pkts=prog_pkts, susp_ratio=susp_ratio,
            flow_dst_port=flow_dst_port,
            source_mode=SOURCE_MODE, ood_distance=ood_dist,
            suppressed_by=suppressed_by, ood_pvalue=ood_pval,
            # (R29/O4) mesafe artik HER IKI dalda dolu; bayrak "karara etki
            # etti mi" ayrimini tasir (volumetrik dalda False = salt gozlem).
            ood_gate_applied=(not is_volumetric),
            # (R29/O3) bkz. pipeline/process_pcap.py'deki ayni satir.
            dst_is_multicast=_is_multicast_ip(dst_ip),
            # (R37/D1) hacimsel RF-override etiketi uygulama-katmani portunda
            # mi uretildi (yani DoS/DDoS vs WebAttack-flood ayrimi belirsiz mi).
            flood_app_layer_ambiguous=flood_app_layer_ambiguous,
        )
        _emit_prediction({
            "ts": time.time(),
            # (B2) bkz. pipeline/process_pcap.py'deki ayni satir.
            "frame_number": packet.get("frame.number"),
            "model": model_name, "src_ip": src_ip, "dst_ip": dst_ip,
            # (R27/O1 fix) eskiden ham tshark STRING'i ("443") gonderiliyordu;
            # C++ tarafinda GetOr<int> bunu type_error ile 0'a dusuruyor ve
            # native UI'da her multiclass alarmi ":0" gosteriyordu (bkz.
            # project_r27_full_pipeline_audit_2026_08.md O1). Ikili hattin
            # flow_dst_port'u (Python int) ile AYNI desen: kanonik akis
            # portu (flip-farkinda), zaten int.
            "dst_port": _to_int(dst_port, 0),
            "risk_score": risk_score, "status": status,
            "threshold": ALERT_THRESHOLD,
            "detected_attack_name": detected_attack_name,
            "predicted_class": predicted_class,
            "is_volumetric": is_volumetric, "alert_source": alert_source,
            "ood_distance": ood_dist, "source_mode": SOURCE_MODE,
            "suppressed_by": suppressed_by, "ood_pvalue": ood_pval,
            "ood_gate_applied": (not is_volumetric),  # (R29/O4)
            "dst_is_multicast": _is_multicast_ip(dst_ip),  # (R29/O3)
            "flood_app_layer_ambiguous": flood_app_layer_ambiguous,  # (R37/D1)
        })

        _log_stats()
        print("-" * 70)
        if REPLAY_DELAY_MS > 0:
            time.sleep(REPLAY_DELAY_MS / 1000.0)
    except Exception as e:
        STATS["dropped_packets"] += 1
        try:
            _pno = packet.get("frame.number", "?") if isinstance(packet, dict) else "?"
        except Exception:
            _pno = "?"
        print(f"❌ [DÜŞEN] Paket işlenemedi (No={_pno}) "
              f"[{type(e).__name__}: {e}] toplam_düşen={STATS['dropped_packets']}")
        _log_stats()
