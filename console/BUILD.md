# Building ids_dashboard.exe

Steps to (re)build `build\ids_dashboard.exe` from the sources in this folder.

## Prerequisites (once)

Install [MSYS2](https://www.msys2.org/) and the mingw64 toolchain packages:

```
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake \
          mingw-w64-x86_64-glfw mingw-w64-x86_64-nlohmann-json
```

`cmake` and `mingw32-make` must be on `PATH` (the MSYS2 MinGW64 `bin` folder).
You do not need to open the MSYS2 shell — a plain PowerShell works once the
folder is on `PATH`. `git` must also be on `PATH`: CMake uses it to fetch ImGui
and ImPlot at configure time.

> ImGui (v1.91.9) and ImPlot (v0.16) are **not** vendored in this repo. The first
> `cmake -S . -B build` downloads them via `FetchContent`; this needs network
> access once. To build fully offline, pass local checkouts with
> `-DIMGUI_DIR=... -DIMPLOT_DIR=...`.

> Build from a path **without** non-ASCII characters. The MinGW Makefiles
> generator mishandles paths containing characters like the Turkish `ü` in
> "Masaüstü". The compiled `.exe` itself has no such limit (it uses the wide
> `CreateProcessW` API) and runs fine from any path — this only affects the
> build step.

## 1) Incremental build (after editing src/*.cpp)

```powershell
cmake --build build -- -j4
```

Recompiles the changed `.cpp` files and relinks `build\ids_dashboard.exe`. ImGui
and ImPlot are already built, so this is fast.

## 2) Clean configure (if build/ is deleted or CMakeLists.txt changes)

```powershell
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -- -j4
```

If MSYS2 is not at `C:/msys64`, point CMake at it:
`-DMINGW_PREFIX=D:/msys64/mingw64`.

## 3) Running

```powershell
build\ids_dashboard.exe
```

- `python` must be on `PATH` with `requirements.txt` (repo root) installed.
- `tshark.exe` (Npcap/Wireshark) must be installed; set `TSHARK` if it is not at
  `C:\Program Files\Wireshark\tshark.exe`.
- The model files must be in `..\multiclass_training\models\` (see repo-root README).
- Capture interface: default `Wi-Fi,Ethernet`, override with
  `$env:IDS_CAPTURE_INTERFACE = "Ethernet"`.
- Subprocess logs: `logs\*_stderr.log` (check these if the health badge is red).

## Optional experimental variant

An A/B variant target exists (`ids_dashboard_r26_phase2_softvote`,
`EXCLUDE_FROM_ALL`) that passes `MC_R26_SOFTVOTE=1` to the detector. It is never
built by the default `cmake --build build` and never overwrites
`ids_dashboard.exe`. Build it explicitly only if needed:

```powershell
cmake --build build --target ids_dashboard_r26_phase2_softvote
```
