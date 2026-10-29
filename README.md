# Live IDS Console

A real-time network intrusion detection console for Windows. A single native
`ids_dashboard.exe` starts the whole pipeline — live packet capture, a streaming
multiclass detector, and a SOC-style dashboard — from one program, with no Kafka,
no web server, and no manual setup between parts.

This is the **live/serving** side of the project. The models it runs, and all the
training and evaluation behind them, live in the companion repository:
[**IDS-Multiclass-Training**](https://github.com/BurakCANKURT/IDS-Multiclass-Training).

This started as my bachelor's thesis. The training repo answers *"can the models
detect attacks they have never seen?"*; this repo answers *"do they still work on
real, live traffic, in real time, on one machine?"*

Output classes: `BENIGN, DDoS, DoS, FTP-Patator, PortScan, SSH-Patator, WebAttack`,
from 41 streaming flow features computed incrementally as packets arrive.

## How it works

```
ids_dashboard.exe  (native C++ console, this repo)
   |
   |  spawns and owns every process below through one Windows Job Object,
   |  connected by local pipes — closing the window kills the whole tree.
   |
   +-- pipeline/live_wireshark_producer.py      one tshark process, N interfaces
   |        |   JSON packet lines (41 features) + a raw pcapng ring buffer
   |        v
   +-- multiclass_training/process_pcap_multiclass.py   RF + HGB + LSTM committee
            |   JSON prediction lines, aggregated straight into the UI
            v
     dashboard: live alert log, risk gauge, 24h timeline, top attackers/ports
```

- **No Kafka / Zookeeper / Flask / WSL2.** The transports those used to provide
  (fan-out and prediction delivery) are replaced by local pipes.
- **MongoDB is optional.** If a Mongo server is reachable, predictions are also
  logged there for offline review; the live console does not depend on it.

## Requirements

- **Windows** with [Npcap](https://npcap.com/) and
  [Wireshark](https://www.wireshark.org/) (`tshark.exe`, `mergecap.exe`).
- **Python 3.11** with `pip install -r requirements.txt`, on `PATH`.
- **The trained models.** They are not in git (too large). Download the model
  files from the latest release of
  [IDS-Multiclass-Training](https://github.com/BurakCANKURT/IDS-Multiclass-Training/releases)
  and place them in `multiclass_training/models/`:
  ```
  MulticlassRF_bundle.joblib   MulticlassRF.joblib   MulticlassRF.onnx
  MulticlassHGB.joblib         MulticlassHGB.onnx
  MulticlassLSTM.keras         MulticlassRF__ood_reference.npz
  ```
- To build the console from source: see [`console/README.md`](console/README.md)
  and [`console/BUILD.md`](console/BUILD.md) (MSYS2 + MinGW-w64, CMake).

## Running

```powershell
python -m pip install -r requirements.txt   # once
# put the model files in multiclass_training\models\  (see above)
console\build\ids_dashboard.exe
```

No other terminals. The console locates the repo root from its own `.exe` path,
starts the detector first, then starts capture once the models are loaded
(~30–40 s on first launch). If a subprocess fails, the health badge turns red and
the reason plus the log path (`console\logs\*.log`) is shown on screen.

- Capture interface defaults to `Wi-Fi,Ethernet`; override with
  `set IDS_CAPTURE_INTERFACE=Ethernet` before launching.
- If Wireshark is installed somewhere other than `C:\Program Files\Wireshark`,
  set `TSHARK` to the full path of `tshark.exe`.

## Live-fire testing

`live_fire_test/` holds the harness I used to confirm the detector works on real
traffic: ESP32 sketches and host-side scripts that generate CICIDS-style attack
traffic (port scan, connection flood, slow-loris, FTP brute force, web attacks)
and `04_mongo_analysis.py` to check whether any real attack was silently missed.

> **These tools drive traffic against your _own_ lab machine only.** They exist to
> measure a detector against known attacks in a closed network you control. Point
> them at nothing you do not own and operate. Wi-Fi credentials go in a local
> `secrets.h` (copy `secrets.example.h`); it is git-ignored and must never be
> committed. The IP addresses left in the scripts are examples from the original
> home lab — change them to your own.

See [`live_fire_test/HOW_TO_RUN.md`](live_fire_test/HOW_TO_RUN.md) for the full
procedure and [`docs/`](docs/) for the limitations and the findings these tests
produced.

## Repository layout

| Path | Contents |
|---|---|
| `console/` | native C++ IDS console (ImGui/ImPlot), build instructions |
| `pipeline/` | live tshark capture producer |
| `multiclass_training/` | the live detector + optional Mongo logging (models go here) |
| `live_fire_test/` | attack simulators for your own lab + post-test analysis |
| `docs/` | known limitations and live-fire findings |

## A note on the code

The READMEs and the documents under `docs/` are in English. Inline code comments are largely in Turkish — this was a solo thesis project and translating every comment was not worth the risk of changing working code. The logic each comment explains is described in English in the READMEs and `docs/`.

## How this was built

I designed the architecture, defined the experiments, and made the design
decisions. Most of the code was written with AI coding agents under my direction;
I reviewed and validated the results.

## License

MIT, see [LICENSE](LICENSE). CICIDS-2017 is provided by the Canadian Institute for
Cybersecurity under its own terms.
