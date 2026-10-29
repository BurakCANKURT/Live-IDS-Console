# R31: ESP32 Live-Fire Test and Pipeline-Hardening Findings (2026-08-09)

This document summarizes the results of the live-fire test run on 2026-08-09
with the ESP32 attacker device, and the deeper pipeline analysis and fixes that
test triggered. For run instructions see `live_fire_test/HOW_TO_RUN.md`.

---

## 1. ESP32 live-fire campaign — result summary

Attacker: an ESP32 (standing in for a Raspberry Pi, with the attack scenarios
adapted to its hardware limits as Arduino sketches). Target: the same Windows PC,
over the LAN.

| Scenario | Result |
|---|---|
| PortScan (baseline, 1000 ports) | ATTACK/PortScan, clear |
| PortScan (F1, 100 ports — narrow-band blind-spot test) | ATTACK, not suppressed by the `scan_rf_benign` veto |
| DDoS/connection flood (400 connects) | ATTACK/DoS (via the behavioral branch; the ESP32's connection rate is hardware-capped at ~1/s, so it landed on the behavioral branch instead of the expected volumetric one — the attack was still not missed) |
| Slowloris (F4, 8 sockets / 120 s) | all 8 flows became ATTACK at least once, no persistent suppression |
| FTP-Patator (F2, slow — the most important variant) | 10/11 flows ATTACK, most of the correct type (`FTP-Patator`) |
| FTP-Patator (fast) | 84 ATTACK / 54 BENIGN, most of the correct type |

**Conclusion: in none of the 6 scenarios was a real attack wrongly dropped to
BENIGN by the false-positive-suppressing mechanisms (immature-clamp, the
`scan_rf_benign` veto, the R26 committee veto, the OOD gate).**

---

## 2. Architecture decision: binary + multiclass paths — both stay

A first, shallow post-campaign analysis concluded "the binary path's unique
contribution is zero"; that was **wrong**, because the ESP32 data contained no
Bot/Infiltration-like traffic at all. A cross-day validation
(`analysis/validate_all_days_multiclass.py` — written this round, reusing the
binary harness's bidirectional ground-truth matching, which also fixed an earlier
bug where the multiclass FAR had been measured 31x inflated) revealed the real
picture:

| Scope | Path | DR | FAR | MCC |
|---|---|---|---|---|
| All groups | binary | 0.9670 | 0.0069 | 0.9633 |
| All groups | multiclass | 0.8965 | 0.0058 | 0.9192 |
| In-scope (excl. Bot/Infiltration) | binary | 0.9674 | 0.0066 | 0.9644 |
| In-scope | multiclass | 0.9804 | 0.0060 | **0.9746** |

Multiclass is equal or better on 6/6 metrics across the 5 in-scope attack
families (DDoS/FTP-Patator/PortScan/SSH-Patator/WebAttack). **But its Bot DR
falls from 0.859 to 0.048 and its Infiltration DR from 0.978 to 0.000** —
multiclass **structurally cannot** produce those two classes (they were
deliberately left out of training scope in the MC1 round due to low quality). The
binary path catches 5751 attack packets on its own.

**Decision:** the binary path = open-set / out-of-scope attack detector (stays).
Multiclass = the primary classifier for the 7 classes. Latency does not affect
this decision (RF difference 8 microseconds, LSTM ~equal — measured).

The user's proposed "confidence-thresholded hybrid labeling" (show a generic
"ATTACK" label when the multiclass argmax is uncertain) was evaluated; Section 6
explains why it was not implemented.

---

## 3. N1: Silent, load-dependent packet loss

**Finding:** the native dashboard's (`pipeline_orchestrator.cpp`) 500-capacity
queue per detector was, when full, dropping the oldest packet **silently** (no
counter, log, or indicator).

**Real scope (measured):** this is not a new regression — it was **already present
in every earlier version, `r27` included**, it was simply never visible. Root
cause: the LSTM's live-path `.predict()` call took 85–90 ms/packet (~15
packets/s ceiling), while real capture under load could reach ~4453 packets/s →
the queue filled in ~0.1 s, and almost everything after that was dropped. Measured
loss: 1.4% at low load, **97–99.6%** at high load.

**Fixed (r33 dashboard build):** not the loss itself, but its visibility. It is
now shown as a percentage with the denominator (`Input loss: Binary 66.7%
(1370/2054)`), with rate-limited logging (once per 10 s).

---

## 4. LSTM speedup (addressing the root cause)

The `main_lstm.predict()` call was moved to the `tf.function` fast-path (on both
the binary and multiclass paths), with a safety net that silently falls back to
the old path on error.

**Numerical equivalence** (`analysis/verify_lstm_fastpath.py`, 300 real samples,
to the same "bit-for-bit identical" standard as the ONNX RF conversion):
- Multiclass: difference = 0 (bit-for-bit identical)
- Binary (MainLSTM_v5): max difference 5.96e-08 (float32 single-ULP, ~170x below
  the tolerance bound) — **no decision/argmax changed**

**Live measurement:** processing rate 14.6 → **146.2 packets/s (10x)**. At
realistic ESP32-style rates (8–17 pkt/s) the loss is effectively zeroed; at the
user's original test load (339 pkt/s) the loss dropped from ~96% to ~57%.

---

## 5. Asynchronous Mongo writes

The `log_prediction`/`insert_one` call was **blocking the main detection loop
synchronously** (0.68 ms/packet). Fix: at log time the record is dropped onto a
`queue.Queue`, and a separate background thread writes it to Mongo. **No
batching/buffering was added** — each packet still gets its own individual
document, only the write was decoupled from the main loop.

**Measurement:** call time 0.68 ms → 0.0037 ms (~180x). Zero loss in normal
operation (5000/5000). Median delay for a record to appear in Mongo 3.2 ms (near
real-time). Throughput +10% (146.2 → 160.6 pkt/s — the expected mathematical
corollary, since the real gain is not throughput but that the detection path is
no longer blocked on network I/O).

---

## 6. Proposals investigated but NOT implemented (and why)

**Gate relaxation (the binary path's low-rate recall weakness):** simulated on
held-out cross-day data (without changing code). Removing the immature-clamp
entirely raises DR by +1.76 pp but **triples** the FAR, and MCC drops — the
classic "R11 pattern" trap. Even with the clamp removed, Infiltration DR barely
changes (0.978→0.980) — so the binary path's real value does not come from these
gates. **Firm recommendation: relax no gate.**

**Volumetric-branch label-pipe fix (the rationale for "hybrid labeling"):** it was
first claimed that "on the volumetric branch the LSTM's correct-class decision is
never used, only 9.1% of the shown label is correct", and a fix was decided on.
**When checked before implementation, the basis of the proposal collapsed:**
1. A function that uses the correct-class information (`_apply_dos_ddos_
   disambiguate`) already existed.
2. On the full cross-day data, label accuracy is actually **58.8%**, and **98.5%**
   once the DoS/DDoS naming difference is excluded (the earlier "9.1%" came from a
   small/unrepresentative sample and was the wrong figure).
3. The sole source of "error": CICIDS's Friday-DDoS traffic has only 1 attacker
   IP; the code's own threshold (`at least 3 distinct source IPs = DDoS`)
   correctly says "DoS" — this is not a code bug, it is a terminological
   difference with the dataset's taxonomy. Fixing it would require re-adding the
   LSTM to the volumetric branch (giving back the newly won 0.44 ms), net gain
   ≈ 0.

**Conclusion: both proposals were investigated and shown to be unnecessary — they
should be counted as "closed/rejected proposals", not "open problems".**

---

## 7. Other minor fixes

- **`SOURCE_MODE=live`** is now set on the Python processes the native dashboard
  spawns (previously all records were `source="unknown"`, so the replay/live
  distinction was non-functional).
- **5 forensic-review fields** (`lstm_score`, `counter_score`, `prog_pkts`,
  `susp_ratio`, `flow_dst_port`) were moved to the multiclass logger (previously
  present on the binary path, absent on multiclass).
- **A CRITICAL severity level** was added (mechanism-based: `is_volumetric == True`
  AND `score >= 0.7` together). Side finding: the native dashboard's C++ side was
  computing severity with different thresholds than Mongo, which was aligned too.

---

## 8. Open items (as of end of 2026-08-09)

1. **Small, optional latency optimizations** — found in profiling but not
   implemented: removing the single-row pandas DataFrame setup (~0.39 ms),
   skipping the `tf.constant` conversion (~0.3–0.6 ms), running the OOD
   computation only on the branch that needs it (~0.27 ms). Estimated total gain:
   throughput ~146 → ~300 pkt/s.
2. Changed files at the time: the detector and Mongo-logger scripts, and the
   console sources under `console/src/` (`pipeline_orchestrator.cpp`, `main.cpp`,
   `theme.cpp`); new files: `analysis/validate_all_days_multiclass.py`,
   `analysis/verify_lstm_fastpath.py`, `live_fire_test/esp32/*`, this document and
   `HOW_TO_RUN.md`.
