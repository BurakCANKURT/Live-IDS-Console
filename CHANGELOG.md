# Changelog

All notable changes to this project are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-10-29
First public release. This repository is the **live/serving** side of the
anomaly-detection IDS; the training, evaluation and the trained models live in
the companion repository
[IDS-Multiclass-Training](https://github.com/BurakCANKURT/IDS-Multiclass-Training).

### Added
- **Native IDS console** (`console/`): a single, statically linked
  `ids_dashboard.exe` (Dear ImGui + ImPlot, GLFW/OpenGL3). On launch it starts
  the whole capture + detection pipeline itself and owns every child process
  through a Windows Job Object, so closing the window tears the full tree down.
- **Capture pipeline** (`pipeline/live_wireshark_producer.py`): a single tshark
  process captures on one or more interfaces into a rolling ring buffer and
  streams the 41-feature packet lines over stdout.
- **Live detector** (`multiclass_training/`): the streaming RF + HGB + LSTM
  committee with the OOD gate, reading packets on stdin and emitting JSON
  predictions on stdout. Loads the models produced by the training repo.
- **Optional MongoDB logging** of predictions for offline/forensic review. The
  live UI does not depend on it.
- **Live-fire test harness** (`live_fire_test/`): ESP32 sketches and host-side
  scripts that generate CICIDS-style traffic against the operator's **own** lab
  machine, plus `04_mongo_analysis.py` to check whether real attack traffic was
  silently missed (`status=BENIGN`) versus flagged as `UNKNOWN`.
- **Reproducible build**: `console/CMakeLists.txt` fetches ImGui v1.91.9 and
  ImPlot v0.16 at configure time (no vendored third-party trees), and the
  Wireshark path is overridable via the `TSHARK` environment variable.
- Documentation of known limitations and live-fire findings under `docs/`.
