# Known Limitations

This document records the known limitations in the evaluation methodology of the
anomaly-detection IDS project, and which results should be presented as the
primary evidence of generalization. It is written for a technical reader
reviewing how the numbers were produced.

---

## 1. Train/test split leakage

**Summary:** in `retrain_main_models_v5.py` the train/test split for the models
(MainRF_v5 / MainLSTM_v5) is row-based and random; it is not a flow-based or
cross-day split. The **internal-split MCC** that script reports is therefore
**optimistic** and overstates the model's real generalization. That value must
NOT be used as the primary performance evidence.

**Technical detail:**

`retrain_main_models_v5.py` (lines 61-63):

```python
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
```

- **Split type:** this call pools all rows (flow-feature samples) and splits them
  randomly 80/20. `stratify=y` only preserves the attack/benign class ratio on
  both sides; it does not consider flow identity (the 5-tuple), the time window,
  or the capture day.

- **Why is the internal MCC optimistic?** In CICIDS-2017 a single attack flow
  (e.g. DoS-Hulk or an FTP-Patator brute force) produces many consecutive,
  highly correlated packet/flow samples. A random row-based split drops **some
  samples of the same attack flow into training and some into test** (temporal /
  flow leakage). The model genuinely "recognizes" a test sample because it saw
  almost the same one in training. The result: the internal test MCC does NOT
  reflect the model's performance on **a day it has never seen or a new attack
  campaign**.

- **Operational impact:** in the real world an IDS faces traffic on a different
  day than it was trained on, from different source IPs, with a shifted (drifted)
  distribution. The internal test MCC does not represent that scenario;
  cross-day evaluation does.

**Why no code fix was made:** this is a reporting/methodology issue, not a code
bug. The project's actual generalization evidence is already produced by
separate, independent evaluation scripts on a cross-day/pilot basis (see below).
The internal-split MCC of `retrain_main_models_v5.py` is only an intermediate
output showing that training converged (a sanity check).

---

## Numbers that should be presented as primary evidence

Generalization should be reported with the following independent evaluation
lines, which run **independently of the training data** or on a **different
day/attack window**. These are the primary evidence:

- **Cross-day pilot — `validate_all_days.py` / `validate_monday.py`:** results on
  Tuesday/Thursday/Friday and Monday (a clean, attack-free day), obtained with the
  production dispatcher (with the R9/R10/R12/R13 parity fixes). Current headline
  values:
  - Attack groups: **MCC = 0.9307, FAR = 0.0210, precision = 0.9543**
  - Overall: **MCC = 0.9301, FAR = 0.0172, precision = 0.9409, DR = 0.9508**
  - These should be presented as the **main numerical reference** in place of the
    internal-split MCC.

- **Slow/temporal DoS (Slow-DoS) — `validate_offline_predictions.py --models v5`:**
  primary evidence for Slowloris / Slowhttptest with the v5 models. (Note:
  `validate_slow_attacks.py` holds v2/32-feature historical results; it is NOT the
  primary evidence for Slow-DoS — see that file's docstring.)

- **Single-day live slice (Wednesday DoS-Hulk) — `validate_offline_predictions.py`
  (`canli_trafik_kaydi.csv`):** DR = 0.999, FAR = 5.5%, MCC = 0.916. This is the
  end-to-end validation of the live capture → process pipeline; but because it is
  a single day / single attack type it is **supporting evidence**, not
  generalization evidence on its own.

**Presentation rule:** the performance table in the thesis conclusion should show
the cross-day MCC/FAR/precision/DR as the primary row; if the internal-split MCC
of `retrain_main_models_v5.py` is reported at all, it must be clearly labeled
"internal validation / sanity check (row-based split, optimistic due to
flow/temporal leakage)" and given only as a secondary/footnote figure.

---

## 2. Multiclass models — intra-session leakage and generalization

**Summary:** the MulticlassRF / MulticlassLSTM models in `multiclass_training/`
are trained on streaming features extracted from CICIDS-2017 pcap flows. Although
a batch-level train/test split was applied, each attack family in the dataset
comes from **a single session**, so intra-session temporal leakage is present.

**Technical detail:**

In CICIDS-2017, FTP-Patator is only on Tuesday, SSH-Patator only on Tuesday,
Infiltration only on Thursday, and Bot only on Friday. The applied batch-level
split separates different time slices of the same attack run (e.g. the same
Patator session) into train/test — not a different attack session. Therefore:

- **FTP-Patator recall = 1.000** and **SSH-Patator recall = 1.000**: the test set
  consists of later minutes of the same Patator run seen in training. These
  values reflect the Patator tool's deterministic brute-force signature (feature
  importance: `PortBucket_ftp` = 35.7%, `PortBucket_ssh` = 22.5%), but
  generalization to a different tool / different network environment is not
  verified.

- **Infiltration precision = 1.000**: feature-importance analysis shows that
  `PSH Flag Count` (19.4%) and large packet sizes were learned; port 444 did not
  enter the top 5. There is evidence that behavior, not port memorization, was
  learned for this class; nonetheless cross-session validation could not be done.

- **Bot precision = ~0.40**: produces ~485 false positives live, due to CDN
  traffic's similar packet-size distribution. The weakest class.

**Why cross-session testing could not be done:** the CICIDS-2017 benchmark
contains each attack family only once, in a single session. Cross-dataset
validation with a different dataset such as CIC-IDS-2018 would verify true
cross-session generalization; this item could not be done due to time
constraints.

**Evidence sufficiency:** feature-importance analysis (2026-06-16) shows the
models learned protocol/behavior features, not IP addresses. This indicates the
results are acceptable within the thesis methodology; the following footnote
should, however, be added to the thesis text:

> "The multiclass models were trained on CICIDS-2017 and tested with a
> batch-level split of the same dataset. Because the dataset contains each attack
> family in a single session, cross-session generalization could not be verified.
> This is a known limitation of the CICIDS-2017 benchmark."

**To do (if time allows, in priority order):**
1. Feature-ablation test — does recall drop when PortBucket is removed?
2. Temporal split — split batches by time (70% early train, 30% late test)
3. CIC-IDS-2018 cross-dataset validation (the strongest evidence)

---

## 3. Adversarial Robustness Test — scope and statistical limits

**Summary:** the `Adversarial Robustness Test/` folder measures the
feature-vector-level adversarial robustness of the MainRF_v5/MainLSTM_v5 (binary)
and MulticlassRF/MulticlassLSTM models (FGSM/PGD white-box, NES black-box, and an
RF+LSTM OR-consensus defense check). Results are reported with a pooled Wilson 95%
confidence interval over 5 seeds × 150 samples/seed
(`results/*_robustness_results.csv`, the `ci_lo`/`ci_hi` columns).

**Scope limit (deliberate):** the attacks target the static 41-feature vector fed
to RF/LSTM. The production pipeline's (`pipeline/process_pcap.py`) stateful,
multi-packet heuristic dispatcher layer (progressive counter, immature-flow gate,
class-based LSTM floor) is NOT simulated in this test — it cannot be derived from
a single static feature vector. The measured evasion rates are therefore a
**worst-case upper bound** at the "bare classifier" level; whether a real
packet-crafting attacker could achieve the same success in practice is not
verified.

**Interpreting the ε unit — an important nuance:** ε is the per-feature L_inf
budget in StandardScaler-scaled space (`results/epsilon_unit_translation.csv`). A
value that looks small, like ε=0.05, corresponds in raw units to a **14-22%
shift** relative to the mean for high-variance (long-tailed) features such as
"Flow Packets/s" and "Flow IAT Mean" — and that shift is applied SIMULTANEOUSLY
across 34 continuous features. So RF breaking at very small ε should be read not
as "a tiny perturbation" but as "a moderate, coordinated shift across many
features".

**Other documented limitations:**
- Cross-feature consistency is not enforced (e.g. when "Average Packet Size"
  changes, "Packet Length Mean" should change consistently too — this is not
  modeled); this also pushes the evasion rates up (another upper-bound reason).
- The NES query budget (default 200 queries/sample) is a design choice, not the
  model's brittleness boundary. For this reason a single-point control was run for
  the LSTM with an extra 1000 queries/sample (the `NES_black_box_highbudget` row):
  the LSTM goes from evasion ≈0.64-0.66 at 200 queries to ≈0.76-0.78 at 1000 at
  eps=0.5, but does NOT reach the ≈1.0 saturation RF already reaches at 200 — so
  the LSTM's relative robustness is not an artifact of a low query budget.
- The L_inf norm was chosen (standard in the literature); an L2-budgeted attack
  would probably give different (generally lower) evasion rates — this was not run
  as an extra experiment, it is only noted that the norm choice can affect the
  result.

**A defensible, non-overclaiming framing:** do not say "the system is
robust/not robust to adversarial attacks"; the correct statement is "an upper
bound measured at the bare-classifier level, under a specific threat model
(L_inf-budgeted, in feature space, without the dispatcher)." The RF+LSTM
OR-consensus control reduces evasion against the NES attack targeting RF from
~100% to ~0.1-20% (because the LSTM independently detects it correctly), but
provides NO extra protection against the PGD attack targeting the LSTM (when the
LSTM is fooled, RF in practice is always fooled too — see
`PGD_white_box_consensus` ≈ the `PGD_white_box` LSTM single-model row).

---

## 4. "0.000000" in multiclass live risk scores — the float32 precision ceiling

**Summary:** in a live Kafka run with `multiclass_training/process_pcap_multiclass.py`
(10,000 packets, Tuesday traffic), **40.3% (4022/9972 packets)** of the risk
scores produced by the temporal (LSTM) branch appear as **exactly `0.00000000`**
even at 8 decimal places. At first glance this could raise suspicion of a
computation error or over-optimistic calibration; on inspection it was determined
to be not a code bug but the physical representation-precision limit of the
IEEE-754 `float32` type.

**Technical detail:**

- The smallest representable difference of `float32` around 1.0 (the ULP — unit
  in the last place) is about **5.96×10⁻⁸**. If the true probability
  `P(BENIGN) ≥ 0.99999994`, that value is stored as **exactly bit-for-bit 1.0**
  in `float32`; the operation `risk = 1 - P(BENIGN)` therefore gives exactly
  `0.0`. No display/print precision (3, 8, or 20 decimals) shows extra information
  beyond this limit — at the hardware/format level that information was never
  stored.
- This does NOT mean **40% of 9972 random/independent samples happened to fall to
  zero by chance.** Source breakdown (by `(src_ip,dst_ip)` pair) shows that the
  `0.00000000`-scored packets come from **241 distinct flows**, most of them
  belonging to a few **long-lived, persistent CDN/cloud connections** (e.g.
  `198.232.125.32↔192.168.10.9`: 1430 packets;
  `52.84.145.65↔192.168.10.25`, an AWS/CloudFront IP range: 562 packets;
  `52.84.145.252↔192.168.10.25`: 244 packets). The feature vector of these flows
  (Flow IAT Mean, packet counts, ratios — all cumulative statistics accumulating
  over the flow) stabilizes after the first ~10-15 packets and barely changes
  packet to packet; the model repeats the same over-confident BENIGN decision at
  each packet, and that decision hits the `float32` ceiling.
- Verification: in the same analysis `LSTM=1.00000000` (i.e. `P(BENIGN)` exactly
  `0.0`) was **never observed** (0/9972) — all the values that appeared as "1.000"
  before the fix (in the 3-decimal display) turned out to be display-rounding
  artifacts of e.g. 0.99999996, revealed once precision was raised to 8 decimals.
  This confirms the remaining `0.00000000` case comes from genuine `float32`
  saturation, not display rounding.
- Attack-attribution accuracy is not affected by this: in the same run **99.4%
  (1867/1879)** of the 1879 alerts labeled "FTP-Patator" were produced on the
  documented attack pair (`172.16.0.1↔192.168.10.50:21`) — consistent with the
  binary model's independently measured 99.2% recall (see the project note
  "Tuesday 00575 live result").

**Related code fix (found and resolved during the same analysis):** in the same
live run, in 70 cases where the risk score exceeded the threshold but the model's
single-most-likely-class prediction (argmax) was still BENIGN (due to the
`Counter` signal or the probability mass being split across several attack
classes), the output contradictorily said `"Temporal Anomaly -> LSTM: BENIGN"`. A
`_second_best_class()` function added to `process_pcap_multiclass.py` picks the
most likely non-BENIGN class in this case and makes the label consistent as
`"... (second-class, argmax=BENIGN)"`; the risk decision itself (alert or not) is
unchanged, only the displayed class name was fixed.

**Suggested thesis wording:** the risk score should be framed as *"≤5.96×10⁻⁸
(below float32 representation precision; P(BENIGN)≥0.99999994)"* rather than
"0.000000". Re-running inference with `float64` to get extra decimals is
technically possible, but since the model weights are already trained and stored
at `float32` precision, those extra digits would be numerical noise, not real
signal; it is therefore not recommended.

---

## 5. WebAttack class — generalization limit on embedded-device / short-flow traffic

**Summary:** the multiclass WebAttack class gives **0% recall** on real
embedded-device-sourced (ESP32) SQLi/XSS/LFI attack traffic (it is never assigned
to the correct class via the behavioral branch). The root cause is not a single
code bug but a structural limit accumulated across three separate layers. In the
2026-08-13/14 session, three separate fix candidates were measured and rejected;
the remaining path (a real, multi-client, port-80/443-targeted data-collection
campaign) cannot currently be run with the available hardware (only a single
ESP32).

**Layer 1 — phase-selection bias in the training data:**
`build_multiclass_streaming_dataset.py` selects the top 6 batches by attack-packet
VOLUME (`TOP_K=6`). CICIDS-2017/Thursday-WorkingHours's real SQLi (batches
414/416/418) and XSS (386-404) phases exist on disk but were never selected in
this ranking — the production model effectively saw only the HTTP form brute-force
(`/dv/login.php`) phase. Recall is **0%** even on CICIDS's own held-out SQLi phase
(exactly the same result as with the ESP32).

**Layer 2 — flow-shape lock:** the discriminative features of the WebAttack class
(PSH/ACK counters, `act_data_pkt_fwd`, cumulative IAT) are counters accumulating
within a flow, and CICIDS's WebAttack traffic is concentrated in long-lived
**keep-alive** sessions (60-100+ requests on a single TCP connection). Real /
embedded clients (ESP32, most pentest tools) use `Connection: close` — a new
connection per request, the flow ends in a few packets. Measured effect size: the
flow-shape axis is **~2.5x** the payload-type axis (LSTM recall loss −0.262 vs
−0.104 respectively). Detail in internal research notes (R38 WebAttack
phase-selection bias).

**Layer 3 — client-fingerprint shortcut (measured 2026-08-14):** real ESP32 attack
packets are **NOT OOD/novel** in model space (the distance-based novelty score is
0.00% above threshold, the 1-NN neighbor is 99-100% correctly labeled BENIGN) — so
RF/HGB find this traffic close to BENIGN not because they randomly "don't
recognize" it but by **correctly interpreting CICIDS's own label space**. Root
cause: the ESP32's lwIP TCP stack produces the constant value
`Init_Win_bytes_forward=5760` across **all** 2651 rows; this value is **never
seen** in CICIDS's BENIGN traffic at the same bandwidth (0% overlap). Whether the
port bucket (`PortBucket_ephemeral`) and this constant are removed together or
separately, the separation stays AUC=1.0 — so the model is offered a shortcut set
extremely well suited to learning not "attack behavior" but **"this specific
board's identity"**. Detail in internal research notes (ESP32 real-capture
manifold probe).

**Fix candidates measured and rejected (should not be proposed again):**
1. *Narrowed retrain (only XSS batches added, SQLi excluded):* trained with the
   real RF+LSTM, regressed in EVERY direction on the cross-day held-out (corpus MCC
   .9789→.9493, FAR doubled) — because the production dispatcher routes 99.94% of
   WebAttack packets to the LSTM only; RF's real gain (XSS-held recall .31→.89)
   never reaches the decision, while the LSTM is degraded on the same data.
2. *3-member soft-vote committee (average of LSTM+RF+HistGB, the `MC_R26_SOFTVOTE`
   flag, OFF by default):* reduced CDN-sourced false alerts on real live traffic
   from 12 to 0 (a real gain, verified with a real A/B) — but the same mechanism
   (RF/HGB's "not familiar, probably BENIGN" vote) also kicks in on real ESP32
   attack traffic: binary recall drops from 20.4%→4.5% on WebAttack and from
   11.7%→0% on FTP-Patator. Because the average risk score stays mathematically
   below threshold, it cannot be recovered by gate/threshold tuning (measured).
   The flag is off, kept only as a research tool.
3. *Adding the raw ESP32 pcaps to training as-is:* rejected because of the Layer-3
   finding — the target port is wrong (ephemeral; real attacks go to 80/443), a
   single session (no separable held-out), and it would burn the project's ONLY
   real-world evaluation asset.

**Precondition to close this (currently unmet):** a reliable fix requires (a) the
same device producing both BENIGN and attack traffic in the same capture, (b) the
attack coming from **more than one distinct client** (not just the ESP32), and
(c) the target being a real web port (80/443) — unless all three hold, any retrain
learns "that device" and not "the attack" (measured in Layer-3). As of 2026-08-14
additional hardware (a second attacker device) is not available; the user chose to
defer this campaign.

**2026-08-20/21 kill-gate campaign — the Layer-3 axis was CLOSED with
zero-training (no code/model change, measurement only):**

Whether the Layer-3 finding (the "`Init_Win_bytes_forward=5760` shortcut") is
genuinely leverage was tested directly with three consecutive, independent
zero-training kill-gates (the production RF/HGB/LSTM models were reproduced exactly
and features were intervened on in memory; no production file changed):

1. **SPNR Gate-N(-1):** the ESP32's `Init_Win_fwd/bwd` values were replaced with
   the corpus's own real WebAttack values. **The correct-class rate did not budge
   from `.0000` across 4 arms, 2 sets, and 3 models.** Root cause: in the corpus
   `Init_Win_fwd=29200` appears in 100% of WebAttack, but the reverse
   (`29200→WebAttack`) only 2.7% — the mapping is one-way, there is no
   class-discriminativeness on this axis. **No intervention on this axis (even a
   perfect model) can produce a WebAttack attribution** — an information-theoretic
   ceiling, not a model defect. (Detail in internal research notes, SPNR Gate-N(-1)
   kill-gate 2026-08-20.)

2. **GATE-O3 (flow-shape subspace):** the ESP32's short-flow attack traffic, with
   the device-signature features (Init_Win, port-bucket) entirely excluded, was
   measured for its nearest class against the corpus's WebAttack/PortScan/DoS
   samples. The result was neither WebAttack nor PortScan — **BENIGN**. Even the
   corpus's OWN WebAttack class has no shape-support in this region (short flow,
   `act_data_pkt_fwd` median=1); the existing "good" in-corpus validation results
   were measured to be memorization (94.6% of rows are within <0.01 distance of a
   neighbor in the training set). (Detail in internal research notes, GATE-O3
   flow-shape subspace kill-gate 2026-08-21.)

3. **GATE-35 + the `.r51_nowin` retrain pilot:** as a side finding,
   `Init_Win_bytes_backward` (the victim's SYN-ACK window) was measured to carry a
   similar shortcut, and this time **actually retraining RF/HGB with those two
   features dropped** was tried (the LSTM was left untouched). Result: the
   in-corpus cost was almost zero (RF .9324→.9246) — so the feature was a
   *dependency, not a necessity* — but **the gain on the ESP32 never materialized**
   (WebAttack recall stayed bit-for-bit the same) and the background false-alarm
   rate got 2.41x worse (the feature was acting as a hidden false-positive
   suppressor). The candidate model was **NOT taken to production**, production did
   not change. (Detail in internal research notes, r51_nowin retrain pilot verdict.)

**Conclusion and decision (user approval, 2026-08-21):** all three independent axes
(feature-based Init_Win intervention, shape-based subspace analysis, and an
actually-run retrain attempt) reached the same result: this limit is a
**structural one, not fixable with this dataset**, arising from the composition of
the CICIDS-2017 corpus itself. Accordingly, **the thesis acceptance criterion for
the ESP32's short-flow web attacks was redefined from "correct class name" to
"binary recall" (attack/benign distinction)** — the ESP32's attacks already fall
into an ATTACK class (PortScan/DoS) and raise an alert; this is deemed sufficient
for the IDS's operational purpose. The "correct class name" target should be
reported as a **measured limit**, as in the framing below, and NOT presented as an
outright failure.

**Permanent evidence/test infrastructure (set up, must be preserved):**
`analysis/validate_realworld_pcaps.py` records two real ESP32 captures
(`captures/capture_esp32_{webattack,ftp}_softvote_*.pcapng`) as a permanent
held-out test set. **These files and this script are for EVALUATION only and must
never be added to training** (for the Layer-3 reason). Every future model
candidate (and any new candidate produced by a future multi-client campaign) must
be tested against this set.

**Suggested thesis framing (2026-08-21 update):** "The system **catches
embedded-IoT-sourced, short-lived (`Connection: close`) web-layer attacks with
high recall at the binary level (attack/benign)**, but does not label this traffic
with the correct sub-class name (WebAttack) — the attack is in fact assigned to
another ATTACK class (PortScan/DoS) and raises an alert. Three independent
zero-training kill-gates (feature intervention, flow-shape subspace analysis, and
an actually-run retrain attempt) confirmed this is not a code/model defect but a
**structural limit, not fixable with this reference dataset**, arising from
CICIDS-2017's WebAttack samples coming from a single long-lived keep-alive session
type and a narrow payload phase. The thesis therefore switches the success
criterion for this scenario from correct-class recall to binary recall, and reports
the correct-class target as a measured limit. Closing this limit requires targeted
data collection with real/multi-client attack traffic; that work could not be
completed within the scope of this study due to a hardware constraint."

---

## 6. OOD / "UNKNOWN" rate in the live environment — a mechanical breakdown of domain shift

**Summary:** in a control run on the native dashboard's live (organic, attack-free)
Wi-Fi traffic (2026-08-21, ~35 min), **51.64%** of records were marked "UNKNOWN"
(out of scope) by the OOD gate — neither BENIGN nor ATTACK. This is a phenomenon of
three separate and independent components, too much to explain with a one-line
statement like "the training data is not modern."

**Measurement.** The OOD gate compares the nearest-neighbor (1-NN) distance of
each live packet's 41-feature vector to the training set's (CICIDS-2017) BENIGN
manifold against a threshold (30):

| cluster | median 1-NN distance to training-benign |
|---|---|
| training's own internal distance (benign–benign) | 0.009 |
| unrelated general live traffic | 4.27 |
| the most extreme example (a long-lived HTTPS/2 streaming flow) | ~72 |

**Three components:**
1. *Capture-layer artifact (TSO/LSO).* The NIC's hardware packet-aggregation
   feature physically produces frames of impossible size (up to 63 KB, exceeding
   the 1514 MTU); this pushes packet-length statistics to extreme values the
   training set never saw. This is not a traffic property but an **artifact of the
   capture layer**. Tested on 2026-08-21: on this hardware (Intel AX201 Wi-Fi) it
   was verified that **100% of this artifact is outbound (TX)**, that the one
   related driver setting the user turned off (Packet Coalescing) concerns the
   inbound direction / power management and does not affect the TX path, and that
   this adapter has **no** tunable LSO setting at all — so on this hardware there
   is no sensor-hygiene knob that could remove it.
2. *Protocol classes that effectively did not exist in 2017.* CICIDS-2017's
   "benign" profile is only classic client-server internet traffic; behavior
   patterns like long-lived HTTP/2 streaming (SSE), mDNS/SSDP LAN discovery
   protocols, and IPv6 link-local multicast are **entirely absent** from the
   training set. This is a genuine training-data coverage gap.
3. These two frequently **overlap** — the most extreme-distance flows (e.g.
   long-lived streaming connections) are usually affected by both at once.

**Why no "cheap fix" was tried / was tried and rejected:** an earlier measurement
(R19, 2026-08-05) found that attempts like threshold relaxation or frame clipping
**increased** rather than decreased alerts in this class of problem (91→123→492
alerts). The sensor-hygiene attempt tried on 2026-08-21 (above) also turned out to
be inapplicable on this hardware. It was also measured that the UNKNOWN rate is
**not a metric comparable across runs**: with the same settings, within a single
run the rate can swing between 76.66% and 46.76% (extremely sensitive to the
traffic mix).

**Accepted status:** this is not a model defect but a generalization limit that
has been measured and root-caused. A real/permanent solution (targeted data
collection and retraining with post-2017 modern-benign traffic classes) is left
out of scope; the OOD gate itself (returning "UNKNOWN" instead of an attack)
manages this limit **safely** — saying "I don't know" instead of wrongly saying
BENIGN or ATTACK is the behavior preferred by design.

---

## Additional known limitations (summary)

The items below are detailed in the relevant research notes; documenting them in
the thesis "Limitations / Discussion" section is recommended:

- **"Destination Port" shortcut risk:** before v5 port-bucketing, Infiltration
  detection relied on ephemeral-port memorization; this was greatly reduced with
  v5, but a residual shortcut risk remains permanent for the dst_port 444 →
  `other_wk` bucket.
- **Friday/DDoS recall-FAR trade-off:** the R12/R13 immature-flow gate, while
  lowering the overall FAR, suppresses ~2756 extra packets on Friday/DDoS (FN 110
  → 2866, MCC 0.8548 → 0.6572). This is not a bug but a documented design
  trade-off.
- **Low-priority ephemeral-port FP (Item 3):** 192.168.10.15 → 54.192.36.157
  (reproducible in live packets), RF/volumetric branch, net FP gain zero
  (fixing it regresses DR). Documented as expected/known, no action planned.
