# R51–R53: Closing the ESP32 Short-Flow Generalization Limit, the Live-Dashboard False-Positive Campaign, and Performance Fixes (2026-08-21)

This document summarizes two independent research lines run in the 2026-08-21
session: (A) closing the last two possible technical levers of the problem of why
the multiclass model can never correctly classify embedded-device (ESP32)-sourced
short-lived WebAttack traffic (see R38, `docs/KNOWN_LIMITATIONS.md` Item 5), using
zero-training kill-gates and an actually-run retrain pilot; (B) finding the root
causes of the false-positive alerts the live native dashboard (`ids_dashboard.exe`)
produces on real/organic network traffic, fixing one of them, resolving a
performance defect, and mechanically diagnosing a remaining limitation (the
OOD/"UNKNOWN" rate). Some experimental model candidates were kept on disk for
reference only and not taken to production.

---

## Summary

| Topic | Result |
|---|---|
| SPNR (Init_Win intervention) | **Structural limit — closed.** Information-theoretic ceiling, not fixable. |
| GATE-O3 (flow-shape subspace) | **Structural limit — closed.** The corpus's own WebAttack class has no support in this region. |
| GATE-35 + `.r51_nowin` retrain pilot (Init_Win_bwd) | **Actually tried, rejected.** The shortcut was a dependency; removing it brought no gain and worsened FAR 2.41×. |
| Success-criterion decision | For the ESP32's short-flow attacks the target was redefined from **correct class** to **binary recall**. |
| `fwd_lengths`/`bwd_lengths` O(n) performance defect | **Fixed** (Welford O(1) incremental statistics), numerical equivalence verified. |
| Subnet directed-broadcast FP (72% of live alerts) | **Fixed**, verified live (162→0 alerts). |
| Port-80 OCSP/CRL/updater FP (28% of live alerts) | **Left open** — no cheap gain, a separate research topic. |
| UNKNOWN/OOD rate (~50%) | **Root-caused, cheap fix exhausted on current hardware** — accepted as a documented limit. |

---

## 1. Context and Motivation

In earlier sessions (R36–R50) it had been measured repeatedly that the multiclass
model (`MulticlassRF` / `MulticlassHGB` / `MulticlassLSTM`) cannot correctly name
the WebAttack and FTP-Patator classes on attack traffic collected from a real
ESP32 device. R38 showed this to be a structural limit accumulated across three
separate layers (phase-selection bias, flow-shape lock, client fingerprint); R50
proved that a domain-invariant training approach (conditional CORAL) does **not**
solve the problem, it only looks for leverage in the wrong layer. The one trackable
path R50 left was the idea of "support-preserving nuisance randomization" (SPNR) —
but before entering a full pilot (a six-gate, half-day experiment), a cheap
pre-kill-gate that could be run with zero training had been designed and left
half-finished in a previous session. This session continued from exactly that
unfinished point.

A separate axis also opened within today's session: after the user's performance
fix, observing the native dashboard on real/organic traffic directly raised a
long-known but unmeasured risk (live false-positive production).

---

## 2. Closing the ESP32 Short-Flow WebAttack Generalization Limit

### 2.1 SPNR Gate-N(-1) — the Init_Win axis

**Method.** Zero training: the existing production models (`MulticlassRF/HGB/LSTM`)
were run by exactly reproducing the metric computation of
`analysis/validate_realworld_pcaps.py`; the `Init_Win_bytes_forward/backward`
feature values of the ESP32's real attack packets were replaced in memory, at
scoring time, with the corpus's own real WebAttack values. No model was trained, no
production file changed.

**Result.** Across four intervention arms (forward only, backward only, both,
neither), two attack sets (`esp32_webattack`, `esp32_ftp_patator`), and all three
models, **the correct-class rate did not budge from `.0000`.** None of the 2651
attacker packets produced a WebAttack or FTP-Patator argmax in any arm.

**Root cause.** In the corpus, `Init_Win_fwd=29200` appears in 100% of the
WebAttack class, but the **reverse of that relationship does not hold**: only 2.7%
of traffic with this value is actually WebAttack (the rest is shared among DoS,
BENIGN, and other attack classes). The mapping is one-way; there is no
class-discriminativeness on this axis at all. This is an **information-theoretic
ceiling** that no model — not even a perfect one — can cross; it is not a model
defect.

**New rule (Rule 32):** a feature's *support* containing the target class's value
(Rule 26) is a necessary but **insufficient** condition; the reverse-conditional
information (`P(target_class | feature=value)`) must also be measured, because the
mapping can be one-way.

### 2.2 GATE-O3 — the flow-shape subspace

After SPNR was closed, the second and last axis the R38 chain pointed to was
tested: the ESP32's real short-lived (`Connection: close`) attack flow was
measured, **with the device-signature features (Init_Win, port-bucket) entirely
excluded**, for its proximity to the corpus's WebAttack, PortScan, and DoS classes
on the basis of flow "shape" alone (packet counts, PSH/ACK cumulative counters,
`act_data_pkt_fwd`, inter-packet-time ratios).

**Result.** The ESP32's attack traffic in this subspace was close to neither
WebAttack (proximity `.0000`, across six measurement combinations — a measured
exhaustion, not statistical noise) nor PortScan (it actually came out the
**farthest** class — showing that the three models saying "PortScan" comes not from
shape similarity but from another mechanism); the nearest class was **BENIGN**.

Two independent refutations were done: (i) the "device signature is confounding"
hypothesis was wrong — signature-free (Windows/WSL-client) short-flow attack data
also falls into the same BENIGN region; (ii) even the corpus's **own** WebAttack
class has no shape support in this region (short flow, `act_data_pkt_fwd`
median=1) — it was measured that the existing "good" in-corpus validation results
are in fact memorization (94.6% of rows are within <0.01 distance of a neighbor in
the training set).

**Side finding (relevant to production):** the unexplained 12.2× false-positive
increase in R49v3 was mechanistically explained by this measurement — adding
short-flow WebAttack data to training in fact means pasting an attack label onto
the dense region of BENIGN.

### 2.3 GATE-35 and the `.r51_nowin` retrain pilot — the Init_Win_bwd victim fingerprint

As a by-product of SPNR and GATE-O3, it was measured that the
`Init_Win_bytes_backward` feature carries a similar shortcut: in the corpus,
certain values of this feature (every value except `{28960, 29200, 0, 8192}`) came
out **100% BENIGN**. The framing fix: those four values are the SYN-ACK window of
CICIDS-2017's **victim VMs** — i.e. the feature encodes the victim, not the
attacker. The large majority of modern real traffic (Windows servers, 81–95% of
which use 65535) is entirely outside the corpus's narrow test-environment scope.

On this axis two critical differences separated it from SPNR/GATE-O3: (i) when this
feature was neutralized on the corpus's own test split, RF's binary recall
**collapsed from .9324 to .4113** (DDoS −99 points, WebAttack −89 points) — so a
large part of RF's "successful"-looking in-corpus results was victim-fingerprint
memorization; (ii) the LSTM was **nearly immune** to this shortcut — so it was
judged not an information-theoretic ceiling but a **fixable confound with a backup
signal**.

On that basis, with user approval, a retrain pilot named `.r51_nowin` was
**actually run**: only RF+HGB (leaving the LSTM untouched) were retrained with
`Init_Win_fwd` and `Init_Win_bwd` dropped, and passed through three pre-registered
gates:

| Gate | Criterion | Result |
|---|---|---|
| GATE-A (cost) | In-corpus binary recall ≥ .85 | **Passed, overwhelmingly** — RF .9324→.9246, HGB .9680→.9587 |
| GATE-B (gain) | ESP32 binary recall > .25 (both sets) | **Failed** — WebAttack bit-for-bit the same (.2035→.2035), FTP-Patator worse (.1172→.1136) |
| GATE-C (safety) | Background FAR ≤ 2× baseline | *(not run because stopped at gate B, but shown it would blow up: 2.41×)* |

**Conclusion: `.r51_nowin` was not taken to production.** GATE-A passing
overwhelmingly also partly refuted GATE-35's claim that "RF's success is
memorization" — when the feature was removed the other 39 features could carry the
same signal; the shortcut was a **dependency, not a necessity**. But the root cause
of GATE-B failing is instructive: the ESP32's real-world decision was already
formed independently of Init_Win (targets on an ephemeral port, PortBucket
dominant); the leverage GATE-35 measured in fact belonged to the **LSTM**, but this
pilot did not touch the LSTM — the gain was structurally unrealizable. Also, the
removed feature was acting as a hidden false-positive **suppressor** in the
background; with it removed, FAR worsened 2.41×.

**New rule (Rule 36):** counterfactual sensitivity does not imply the right
direction of intervention. (a) The counterfactual effect must be read through the
**own** argmax of the component the intervention targets (an end-to-end metric can
include the contribution of other, untouched components and be misleading). (b)
**Removing** a feature may not have the same effect as changing it
counterfactually — the removed feature may play a suppressor role.

### 2.4 Decision: redefining the success criterion

Three independent axes (feature-based Init_Win intervention, shape-based subspace
analysis, an actually-run retrain attempt) reached the same result: this limit is a
structural one, **not fixable with this dataset**, arising from the composition of
the CICIDS-2017 corpus itself. With user approval, **the thesis acceptance
criterion for the ESP32's short-flow web attacks was redefined from "correct class
name" to "binary recall" (attack/benign distinction)** — the ESP32's attacks
already fall into an ATTACK class (PortScan/DoS) and raise an alert; this is deemed
sufficient for the IDS's operational purpose. This decision and its rationale are
recorded in `docs/KNOWN_LIMITATIONS.md` Item 5.

---

## 3. Native Dashboard Performance Fix

In `multiclass_training/process_pcap_multiclass.py::extract_universal_features`,
each flow's `fwd_lengths`/`bwd_lengths` lists **grew without bound** and were
re-scanned from scratch with `sum()`/`max()`/`min()`/`np.std()` at every new
packet — on long-lived flows (e.g. CDN keep-alive connections, thousands of
packets) this meant O(n) per-packet cost per flow, O(n²) over the flow. This was
(partly) a source of the dashboard's known packet-loss problem — eased by removing
the binary detector from the live path, but not solved at the root.

**Fix:** the unbounded lists were removed and replaced with O(1) incremental
counters (running sum/max/min and incremental mean/variance via Welford's
algorithm). Numerical equivalence was verified with 4000 random scenarios
(sum/max/min bit-for-bit, std/var within floating-point tolerance, including
order-independence). Applied with parity across three files
(`process_pcap_multiclass.py` [live], `offline_test_multiclass.py` [the offline
copy the GATE tests use], `pipeline/process_pcap.py` [the retired binary detector,
offline only]).

This fix was later verified on **243k and 86k packets** in the R52/R53 live runs
with zero errors/NaNs/negative scores.

---

## 4. Live False-Positive Campaign

### 4.1 R52 — first live sweep and detection of two FP families

After the Welford fix, the dashboard was run on real Wi-Fi traffic (**no** attack
simulation, ~35 min, human-paced browsing + organic background traffic). At close:
**243,487 records, 162 alerts (0.067%)** — all false positives by definition.

| Family | Alert count (%) | Mechanism |
|---|---|---|
| A — subnet directed broadcast | 113 (72%) | `192.168.1.102:<new ephemeral port> → 192.168.1.255:15600`, a device-discovery beacon on a ~6 s period → **PortScan** |
| B — port 80 | 44 (28%) | OCSP/CRL (Microsoft-CryptoAPI), Microsoft-Delivery-Optimization, Steam → **WebAttack/DoS** |

No third family appeared at all (100% explainability).

**Family A's root cause:** `_is_broadcast_ip()` recognized only the exact
`255.255.255.255`; subnet directed broadcast (`x.x.x.255`) was entirely out of
scope. This was a case deliberately deferred in a previous session (R32) — R32's
deferral rationale ("not seen on this network, produced no alert") was **refuted**
by this measurement: it was seen on this network and made up 72% of all alerts. A
controlled natural experiment made it clear: a multicast packet
(`239.255.255.250`) sent by the same device at the same time correctly fell to
BENIGN, while the broadcast packet (`192.168.1.255`), differing only in the target
address class, went to ATTACK without passing any gate — so the problem was not the
model/threshold but a pure address-class gap.

**Family B** had already passed seven separate defense gates and a committee veto;
with no cheap gain left, it was left as a separate research topic.

### 4.2 The subnet-broadcast fix

Instead of hard-coding a fixed IP/netmask, a **zero-configuration rule derived from
the packet's own source IP** was applied: `_is_broadcast_ip(dst_ip, src_ip)` now
returns `True` if the last octet of `dst_ip` is `255` **and** its first three
octets are the same as `src_ip`. No person/organization has to enter their own
network range by hand — the rule works automatically on every network. Known and
accepted narrow scope: the rule assumes a /24 netmask; on a much larger subnet
(e.g. /20) it could rarely suppress by mistake a normal host address that genuinely
ends in `.255` — judged an acceptable trade-off against the measured 72% real cost.
The fix was applied with parity across three files and verified with an
eight-scenario unit test.

### 4.3 R53 — live verification

A second live run (~23 min, no attack) verified both this fix and a NIC change
described below, together. One of the cleanest controlled A/Bs in this repo was
obtained: the same device, the same beacon, bit-for-bit the same `ood_distance`
(the feature vector did not change at all) — the only difference being the gate
itself.

| | R52 (before fix) | R53 (after fix) |
|---|---|---|
| `192.168.1.255:15600` target | 74/74 packets, risk **.9809**, `suppressed_by=None` | 243/243 packets, risk **.399**, `suppressed_by=broadcast` |
| Status | **ATTACK/PortScan** | **BENIGN** |
| Total alerts in run | 162 | **0** |

The two arms of the natural experiment now agree: the multicast twin was already
BENIGN, and the directed broadcast is now BENIGN too. It was verified on the ring
pcap that the source device was active (246 packets) — ruling out a false-negative
possibility like "no alert because the device went quiet".

### 4.4 NIC-hygiene attempt and TX-side LSO diagnosis

R52 had also shown that **51.64% of live traffic** fell to "UNKNOWN" (OOD gate)
status — due to modern traffic patterns CICIDS-2017 does not represent. It was
thought that part of this could be due to the "super-frames" of physically
impossible size (up to 63 KB, far above the Ethernet MTU) produced by the NIC's
hardware packet-aggregation feature (TSO/LRO-like) (this finding was first
described in R19, 2026-08-05). The user turned off the one related setting on the
Wi-Fi adapter (the Intel AX201 driver's "Packet Coalescing" feature).

**Result: this was the wrong knob.** The R53 measurement showed that **100% of the
super-frame artifact is outbound (TX)** — i.e. in the traffic the sensor itself
sends; there was not a single sample in the inbound direction. The "Packet
Coalescing" that was turned off, on this hardware, concerns the **inbound direction
/ power management** and does not affect the send path. It was also verified that
this adapter has **no** tunable LSO (Large Send Offload) feature at all — so on this
hardware there is no way to turn off TX-side offload. The setting was reverted by
the user since it provided no benefit (returned to its default "Enabled" state).

It was also learned that the UNKNOWN rate is **not a metric comparable across
runs**: with the same NIC setting, within a single run the rate can swing from
76.66% to 46.76% (extremely sensitive to the traffic mix — especially to
high-volume single transfers). This confirmed R19's earlier estimate ("a
single-feature fix does not work in this class, the flow is OOD on several axes at
once").

---

## 5. Mechanical Analysis of the UNKNOWN/OOD Rate

The OOD gate measures the **nearest-neighbor (1-NN) distance** of each live
packet's 41-feature vector to the manifold formed by the training set's
(CICIDS-2017) BENIGN samples, and compares it to a threshold (30). This is not an
arbitrary threshold game — there is a large range among the measured distances:

| Cluster | median 1-NN distance to training-benign |
|---|---|
| Training's own internal distance (benign–benign) | 0.009 |
| Unrelated general live traffic | 4.27 |
| The most extreme example (a long-lived HTTPS/2 streaming flow) | ~72 |

"The dataset is not modern" alone is insufficient; the real mechanism consists of
three separate, independent components:

1. **Capture-layer artifact (TSO/LSO).** The NIC's hardware packet-aggregation
   feature produces frames of physically impossible size; this pushes features like
   Packet Length Variance/Std to extreme values the training set never saw. This is
   not a property of the traffic but a **capture-layer artifact** (as shown in
   §4.4, not fixable on this hardware).
2. **Protocol classes that effectively did not exist in 2017.** CICIDS-2017's
   "benign" profile is only classic client-server internet traffic; behavior
   patterns like long-lived HTTP/2 streaming (bursty/asymmetric connections such as
   an SSE token stream), LAN discovery protocols like mDNS/SSDP, and IPv6
   link-local multicast are **entirely absent** from the training set — the model
   never had a chance to learn them.
3. **The overlap of these two.** The most extreme-distance flows (e.g. long-lived
   streaming connections) are usually affected by both reasons at once, which is why
   their distances are so extreme.

This distinction matters because the two components are different in nature: (1) is
in theory fixable with a sensor/capture fix (but no knob to fix it was found on
this hardware); (2) is a genuine **training-data coverage gap**, closable only by
targeted new data collection and retraining. Earlier (R19) measured "cheap fix"
attempts (threshold relaxation, frame clipping) **increased rather than decreased**
alerts in this class of problem (91→123→492).

**Decision:** in this session the cheap/low-risk path (sensor hygiene) was tried
and found inapplicable on this hardware. The conclusion agreed with the user: this
is the point reachable with this dataset and this hardware; the UNKNOWN rate is
accepted as a documented limit, root-caused but not fixable within the current
scope.

---

## 6. Closed, Left-Open, and Deferred Topics

**Closed (brought to a final decision in this session):**
- SPNR (Init_Win intervention) — structural limit, should not be retried.
- GATE-O3 (flow-shape subspace) — structural limit, should not be retried.
- `.r51_nowin` (Init_Win_bwd retrain) — tried, rejected, not taken to production.
- Subnet directed-broadcast FP — code fixed, verified live.
- `fwd_lengths`/`bwd_lengths` O(n) performance defect — fixed.
- NIC-hygiene attempt — proven inapplicable on this hardware, setting reverted.

**Deliberately left open (by user decision):**
- Port-80 OCSP/CRL/updater WebAttack/DoS false positive (28%) — no cheap gain, to be
  addressed later as a separate research round.
- UNKNOWN/OOD rate (~50%) — root-caused, no cheap fix left with current hardware and
  dataset; accepted as a documented limit.

**Left out of scope of this session (future work):**
- System/service log analysis (auth, ftp, etc.) — the pipeline currently reads only
  network traffic.

---

## New rules (added this session)

- **Rule 32:** a feature's support containing the target class's value is necessary
  but insufficient; the reverse-conditional information
  (`P(target_class | feature=value)`) must also be measured.
- **Rule 33:** single-session batch-split evaluation does not measure
  generalization; the nearest-training-neighbor distance should be reported, and
  leave-batch-out preferred.
- **Rule 34:** a class may have *support* but no *region*; region ownership should be
  measured with balanced-1NN and natural-prior enrichment, with uncertainty
  clustered at the flow level.
- **Rule 35:** a feature carrying a high importance score does not mean it is a
  *causal* signal — it may be a victim/environment fingerprint; the
  reverse-conditional probability and cross-model consistency (whether a model is
  immune) must be checked.
- **Rule 36:** counterfactual sensitivity does not imply the right direction of
  intervention. The counterfactual effect must be read through the own argmax of the
  targeted component; removing a feature may not have the same effect as changing it
  counterfactually (the removed feature may be a suppressor).

---

Related internal documents: `docs/KNOWN_LIMITATIONS.md` (Item 5, updated by this
session's decision), and the internal research notes on the SPNR Gate-N(-1),
GATE-O3 flow-shape subspace, GATE-35 Init_Win_bwd victim-fingerprint, the
`.r51_nowin` retrain pilot verdict, and the R52/R53 live directed-broadcast
findings.
