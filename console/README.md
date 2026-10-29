# IDS Live Console (native)

A native C++ desktop client and the single UI for the live pipeline: one
dependency-free `ids_dashboard.exe` that starts the entire capture + detection
pipeline itself, so the operator runs one program and nothing else.

## Architecture

```
ids_dashboard.exe (this app)
   |
   +--> pipeline/live_wireshark_producer.py --sink stdout   (tshark capture)
   |         |  JSON packet lines
   |         v
   +--> multiclass_training/process_pcap_multiclass.py   (INPUT_MODE=stdin OUTPUT_MODE=stdout)
             |  JSON prediction lines
             v
   aggregated directly into DashboardState (no Mongo/Kafka/Flask/HTTP)
```

On launch, `PipelineOrchestrator` (`src/pipeline_orchestrator.{h,cpp}`) spawns the
Python scripts as child processes connected by local anonymous pipes: the
producer's captured-packet stream feeds the detector's stdin (replacing Kafka's
fan-out role), and the detector's JSON prediction stream is read off its stdout
and aggregated into the UI state (replacing MongoDB + a Flask API + HTTP polling).
All child processes (tshark included) are owned by a Windows Job Object, so
closing or killing `ids_dashboard.exe` in any way — clean exit, window close,
task-kill — takes the entire process tree down with it; nothing is ever left
orphaned capturing packets.

**No Kafka/Zookeeper/MongoDB/WSL2 is required.** MongoDB remains fully optional:
`mongo_logger_multiclass.py` still writes to it if reachable (for offline/forensic
review), but the live UI no longer depends on it.

The detection logic in `process_pcap_multiclass.py` is the same one evaluated in
the training repo — only its I/O transport changed (see that file's
`_packet_source()` / `_emit_prediction()`).

## Stack

- **Dear ImGui** (v1.91.9) + **ImPlot** (v0.16) for rendering — immediate-mode,
  GLFW + OpenGL3 backend. Both are fetched at configure time by CMake
  (`FetchContent`), so they are not vendored in this repo.
- **Win32 pipes/Job Objects** (`CreateProcessW` + anonymous pipes +
  `CreateJobObjectW`) for subprocess orchestration — see
  `src/pipeline_orchestrator.cpp`.
- **nlohmann/json** for parsing the detector's JSON prediction lines.
- Everything (GLFW included) is statically linked (`-static` + linking
  `libglfw3.a` directly) so the build output is a single ~6 MB
  `ids_dashboard.exe` with no MSYS2/mingw64 DLLs to bundle alongside it.

## Building

See [`BUILD.md`](BUILD.md). In short (MSYS2 + MinGW-w64 on `PATH`):

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j4
```

## Running

```
build\ids_dashboard.exe
```

No other setup, no other terminals. On launch it locates the repo root from its
own `.exe` path (`<repo_root>/console/build/`) and spawns the producer + detector
itself. `python` must be on `PATH` with this repo's dependencies installed (see
`requirements.txt` at the repo root), and Wireshark's `tshark.exe` must be
installed (default `C:\Program Files\Wireshark`; override with the `TSHARK`
environment variable). The trained models must be present in
`multiclass_training/models/` — see the repo-root README.

- Capture interface defaults to `Wi-Fi,Ethernet`; override with
  `set IDS_CAPTURE_INTERFACE=Ethernet` before launching.
- Each subprocess's full log is written to `console/logs/*_stderr.log` — check
  these first if the health badge shows a process as DOWN.
- The health badge (top-right) shows live/dead + last-event-age for capture and
  the detector individually.

## Layout

- `src/pipeline_orchestrator.{h,cpp}` — spawns and owns the Python subprocesses
  via `CreateProcessW` + anonymous pipes, feeds captured packets to the detector,
  parses its JSON prediction stream, and maintains the aggregated
  `DashboardState` (rolling alert log, per-hour buckets, risk sparkline, top
  attackers/ports, per-process health).
- `src/theme.{h,cpp}` — dark "SOC console" ImGui style + Segoe UI/Consolas font
  loading (falls back to ImGui's bundled font if those aren't present).
- `src/main.cpp` — GLFW/OpenGL3 window setup and all dashboard widgets (stat
  tiles, risk gauge + sparkline, 24 h alert timeline, recent-alerts table,
  predicted-class/top-attacker/port distribution charts); reads a fresh
  `orchestrator.snapshot()` once per rendered frame.
