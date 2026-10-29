// IDS Live Console -- native C++ real-time operator dashboard.
//
// Fully self-contained: on launch, this process itself spawns the live
// capture + detection pipeline (tshark producer + the multiclass detector)
// via PipelineOrchestrator, feeds it via local pipes, and renders the
// aggregated result with Dear ImGui + ImPlot. No Kafka/Zookeeper/MongoDB/
// WSL2/Flask dependency -- the user only runs this one .exe. See
// pipeline_orchestrator.h for the subprocess/IPC architecture.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <GLFW/glfw3.h>
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"

#include "pipeline_orchestrator.h"
#include "theme.h"

#include <commdlg.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <cwchar>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#include <algorithm>

namespace {

// (B4) Full-page packet detail view state. A namespace-scope singleton, same
// pattern as the RecentAlertsTable's own `static int selected_alert_idx` --
// this is a single-window desktop app, one detail view can be open at a
// time. LookupPacket/ExtractPacketToFile shell out to tshark and can take
// up to a second or two on a large ring file, so both run on a background
// thread; `mtx` guards everything that thread writes and the render thread
// reads. `active`/`alert` are touched ONLY from the render/UI thread (the
// click that opens the page, and the page itself), so they need no lock.
struct PacketDetailState {
    bool active = false;
    Alert alert;

    std::mutex mtx;
    bool loading = false;
    bool found = false;
    std::string detail_text;
    std::string error;
    std::thread worker;

    bool download_in_progress = false;
    std::string download_result_msg;
    std::thread download_worker;
};
PacketDetailState g_detail;

// (B5) Background state for the alerts table's "Download All" button --
// same one-worker-at-a-time pattern as PacketDetailState::download_worker,
// just not tied to the full-page packet detail view (this one fires from
// the table header on the main dashboard).
struct BulkDownloadState {
    std::mutex mtx;
    bool in_progress = false;
    std::string result_msg;
    std::thread worker;
};
BulkDownloadState g_bulk_download;         // ATTACK alerts panel's "Download All"
BulkDownloadState g_bulk_download_unknown; // UNKNOWN/OOD alerts panel's "Download All" -- kept
                                            // separate so the two panels' progress/result
                                            // messages don't bleed into each other and both
                                            // bulk exports can legitimately run back to back.

// (B11) Background state for the capture toolbar's "Akisi Kaydet" button --
// same one-worker-at-a-time pattern as BulkDownloadState. Separate from it
// because the two can legitimately be wanted back to back (archive the whole
// ring, then export the alert rows) and neither should cancel the other.
struct RingSaveState {
    std::mutex mtx;
    bool in_progress = false;
    std::string result_msg;
    std::thread worker;
};
RingSaveState g_ring_save;

// Builds a small standalone JSON document from one Alert -- used by the
// detail page's "Export JSON" button. Deliberately independent of the
// process_pcap.py JSON schema (this is a UI-side snapshot of what the
// dashboard displayed, not a re-emission of the detector's own record).
std::string AlertToJson(const Alert& a) {
    nlohmann::json j = {
        {"timestamp", a.timestamp},
        {"status", a.status},
        {"risk_score", a.score},
        {"attack_type", a.attack_type},
        {"predicted_class", a.predicted_class},
        {"alert_source", a.alert_source},
        {"severity", a.severity},
        {"src_ip", a.src_ip},
        {"dst_ip", a.dst_ip},
        {"dst_port", a.has_dst_port ? nlohmann::json(a.dst_port) : nlohmann::json(nullptr)},
        {"frame_number", a.frame_number},
        {"capture_ts", a.capture_ts},
    };
    return j.dump(2);
}

// Blocking native "Save As" dialog (comdlg32) -- consistent with the rest of
// this app's direct Win32 API usage (see pipeline_orchestrator.cpp). Returns
// an empty path if the user cancelled.
std::wstring PromptSaveFile(const wchar_t* filter, const wchar_t* default_ext,
                             const wchar_t* default_name) {
    wchar_t file[MAX_PATH];
    wcsncpy(file, default_name, MAX_PATH - 1);
    file[MAX_PATH - 1] = L'\0';

    OPENFILENAMEW ofn{};
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFilter = filter;
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    ofn.lpstrDefExt = default_ext;
    if (!GetSaveFileNameW(&ofn)) return L"";
    return file;
}

// Prompts for a save path, then extracts every alert's packet and merges
// them into one pcapng on a background thread (each alert needs its own
// tshark lookup, so this can take a while over 50 rows -- never block the
// render thread on it). No-op if the user cancels the save dialog.
void TriggerBulkDownload(PipelineOrchestrator& orchestrator, const std::vector<Alert>& alerts,
                          BulkDownloadState& bulk_state,
                          const wchar_t* default_name = L"all_alerts.pcapng") {
    std::wstring out_path = PromptSaveFile(
        L"Wireshark Capture (*.pcapng)\0*.pcapng\0All Files\0*.*\0", L"pcapng", default_name);
    if (out_path.empty()) return;

    if (bulk_state.worker.joinable()) bulk_state.worker.join();
    {
        std::lock_guard<std::mutex> lock(bulk_state.mtx);
        bulk_state.in_progress = true;
        bulk_state.result_msg.clear();
    }
    PipelineOrchestrator* orch = &orchestrator;
    BulkDownloadState* state = &bulk_state;
    std::vector<Alert> snap = alerts; // detached copy: outlives this frame's DashboardState snapshot
    bulk_state.worker = std::thread([orch, snap, out_path, state]() {
        auto res = orch->ExtractAlertsToFile(snap, out_path);
        std::lock_guard<std::mutex> lock(state->mtx);
        state->in_progress = false;
        char buf[128];
        if (res.total == 0)
            state->result_msg = "Indirilecek paket yok (frame bilgisi olan uyari yok).";
        else if (res.found == 0)
            state->result_msg = "Hicbir paket bulunamadi/kaydedilemedi.";
        else {
            std::snprintf(buf, sizeof(buf), "%d/%d paket kaydedildi.", res.found, res.total);
            state->result_msg = buf;
        }
    });
}

// The exe ships at <repo_root>/console/build/ids_dashboard.exe
// -- resolve repo_root from the running exe's own path so the app works
// regardless of the current working directory it was launched from.
std::wstring ResolveRepoRoot() {
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring exe_path(path, len);
    size_t slash = exe_path.find_last_of(L"\\/");
    std::wstring exe_dir = (slash != std::wstring::npos) ? exe_path.substr(0, slash) : L".";
    std::wstring candidate = exe_dir + L"\\..\\..";

    wchar_t resolved[MAX_PATH];
    DWORD n = GetFullPathNameW(candidate.c_str(), MAX_PATH, resolved, nullptr);
    return (n > 0 && n < MAX_PATH) ? std::wstring(resolved) : candidate;
}

// (B11) Prompts for a destination, then merges the whole capture_ring into one
// pcapng on a background thread (mergecap over a full ~500MB ring takes
// seconds -- never block the render thread on it). Defaults into
// captures/, where offline analysis of saved captures already
// happens, with a timestamped name so repeated saves in one session don't
// silently overwrite each other. No-op if the user cancels.
void TriggerRingSave(PipelineOrchestrator& orchestrator, const std::wstring& repo_root) {
    std::wstring analyze_dir = repo_root + L"\\captures";
    CreateDirectoryW(analyze_dir.c_str(), nullptr); // harmless if it already exists

    wchar_t stamp[32];
    std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_s(&tmv, &now);
    std::wcsftime(stamp, 32, L"%Y%m%d_%H%M%S", &tmv);
    std::wstring suggested = analyze_dir + L"\\capture_" + stamp + L".pcapng";

    std::wstring out_path = PromptSaveFile(
        L"Wireshark Capture (*.pcapng)\0*.pcapng\0All Files\0*.*\0", L"pcapng", suggested.c_str());
    if (out_path.empty()) return;

    if (g_ring_save.worker.joinable()) g_ring_save.worker.join();
    {
        std::lock_guard<std::mutex> lock(g_ring_save.mtx);
        g_ring_save.in_progress = true;
        g_ring_save.result_msg.clear();
    }
    PipelineOrchestrator* orch = &orchestrator;
    g_ring_save.worker = std::thread([orch, out_path]() {
        auto res = orch->SaveRingToFile(out_path);
        std::lock_guard<std::mutex> lock(g_ring_save.mtx);
        g_ring_save.in_progress = false;
        if (res.ok) {
            char buf[128];
            std::snprintf(buf, sizeof(buf), "Kaydedildi: %d ring dosyasi birlestirildi.", res.merged_files);
            g_ring_save.result_msg = buf;
        } else {
            g_ring_save.result_msg = res.error;
        }
    });
}

// Capture interface override: `set IDS_CAPTURE_INTERFACE=Wi-Fi` before
// launch (or a comma-separated list, e.g. "Wi-Fi,Ethernet"). Defaults to
// both Wi-Fi and Ethernet -- live_wireshark_producer.py splits this on
// commas and passes one -i per interface to a SINGLE tshark process, which
// captures on all of them at once (interleaved into one ring, frame.number
// stays globally monotonic -- see that script's B1 comment). This way the
// dashboard keeps working whichever interface actually has a live link,
// without the user having to know in advance and set the env var per machine.
std::wstring ResolveInterface() {
    wchar_t buf[256];
    DWORD n = GetEnvironmentVariableW(L"IDS_CAPTURE_INTERFACE", buf, 256);
    if (n > 0 && n < 256) return std::wstring(buf, n);
    return L"Wi-Fi,Ethernet";
}

void GlfwErrorCallback(int error, const char* description) {
    std::fprintf(stderr, "[GLFW] error %d: %s\n", error, description);
}

std::string HourMinuteSecond(const std::string& iso_timestamp) {
    // "2026-08-04T10:32:01.123456+00:00" -> "10:32:01"
    if (iso_timestamp.size() >= 19) return iso_timestamp.substr(11, 8);
    return iso_timestamp;
}

char FormatBuf[64];
const char* FormatCount(long long v) {
    if (v >= 1000000) std::snprintf(FormatBuf, sizeof(FormatBuf), "%.1fM", v / 1000000.0);
    else if (v >= 1000) std::snprintf(FormatBuf, sizeof(FormatBuf), "%.1fK", v / 1000.0);
    else std::snprintf(FormatBuf, sizeof(FormatBuf), "%lld", v);
    return FormatBuf;
}

// The backend stores its "observed behavior" categories in Turkish (Mongo
// documents predate this UI and dashboard_v2.html already displays English
// labels for them via this same mapping) -- translate for display only, the
// raw value is still what filtering/coloring keys off of.
const char* DisplayLabel(const std::string& name) {
    static const std::pair<const char*, const char*> kMap[] = {
        {"Hacimsel/Tekrarlı",              "Volumetric/Repetitive"},
        {"Çoklu-Port Tarama",              "Multi-Port Scan"},
        {"Davranışsal (Tekrarlı-İstek)",   "Behavioral (Repeated Request)"},
        {"Davranışsal (Web/Uygulama)",     "Behavioral (Web/Application)"},
        {"Sınıflandırılamadı",             "Unclassified"},
        // R20: OOD gate verdict (mongo_logger._classify_attack_type)
        {"Kapsam Dışı (OOD)",              "Out-of-Distribution (Unknown)"},
    };
    for (auto& kv : kMap)
        if (name == kv.first) return kv.second;
    return name.c_str();
}

// Smoothly interpolates toward `target`, so widgets animate instead of
// snapping to a new value on every ~poll-interval update.
float SmoothTowards(float current, float target, float dt, float speed = 8.0f) {
    float t = 1.0f - std::exp(-speed * dt);
    return current + (target - current) * t;
}

// ── Reusable widgets ───────────────────────────────────────────────────

void StatTile(const char* label, const char* value, ImVec4 accent, const Fonts& fonts) {
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
    ImGui::BeginChild(label, ImVec2(0, 90), true, ImGuiWindowFlags_NoScrollbar);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    ImGui::TextUnformatted(label);
    ImGui::PopStyleColor();
    ImGui::PushFont(fonts.header);
    ImGui::PushStyleColor(ImGuiCol_Text, accent);
    ImGui::TextUnformatted(value);
    ImGui::PopStyleColor();
    ImGui::PopFont();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

const char* AgeStr(char* buf, size_t n, double age) {
    if (age < 0) std::snprintf(buf, n, "n/a");
    else std::snprintf(buf, n, "%.1fs ago", age);
    return buf;
}

void HealthBadge(const DashboardState& st, const Fonts& fonts) {
    int running_count = (st.health.producer.running ? 1 : 0) + (st.health.multiclass_detector.running ? 1 : 0);
    // (B11) A user-requested capture stop kills the producer on purpose, which
    // would otherwise read as "1 of 2 children down" -> DEGRADED, i.e. the app
    // reporting its own feature as a fault. Paused is its own state.
    ImVec4 dot = st.capture_paused ? theme::kWarning
                 : !st.reachable   ? theme::kDanger
                 : running_count == 2 ? theme::kSuccess
                                       : theme::kWarning;
    const char* label = st.capture_paused ? "CAPTURE PAUSED"
                         : !st.reachable  ? "PIPELINE OFFLINE"
                         : running_count == 2 ? "PIPELINE ONLINE"
                                              : "PIPELINE DEGRADED";

    // Drawn, not printed as a Unicode glyph: the loaded font's glyph range
    // doesn't cover the Geometric Shapes block, so a "●" character here
    // silently renders as ImGui's tofu/"?" fallback glyph instead.
    ImVec2 p = ImGui::GetCursorScreenPos();
    float r = ImGui::GetTextLineHeight() * 0.28f;
    ImVec2 center(p.x + r, p.y + ImGui::GetTextLineHeight() * 0.5f);
    ImGui::GetWindowDrawList()->AddCircleFilled(center, r, ImGui::ColorConvertFloat4ToU32(dot), 16);
    ImGui::Dummy(ImVec2(r * 2 + 6, ImGui::GetTextLineHeight()));
    ImGui::SameLine();
    ImGui::TextUnformatted(label);

    ImGui::SameLine(0, 24);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    if (!st.reachable && !st.last_error.empty()) {
        ImGui::TextUnformatted(st.last_error.c_str());
    } else {
        char cap_age[32], mc_age[32];
        char buf[220];
        std::snprintf(buf, sizeof(buf), "Capture: %s (%s)   |   Multiclass: %s (%s)",
                      st.health.producer.running ? "UP" : "DOWN",
                      AgeStr(cap_age, sizeof(cap_age), st.health.producer.last_event_age_seconds),
                      st.health.multiclass_detector.running ? "UP" : "DOWN",
                      AgeStr(mc_age, sizeof(mc_age), st.health.multiclass_detector.last_event_age_seconds));
        ImGui::TextUnformatted(buf);

        // (B8) Sync reference point for anyone running a standalone
        // Wireshark capture alongside this app to compare packet counts --
        // anything Wireshark counted before this HH:MM:SS arrived during the
        // model warm-up, before this app's own capture started, and isn't a
        // discrepancy (see DashboardState::capture_start_wallclock).
        if (!st.capture_start_wallclock.empty()) {
            char sbuf[96];
            std::snprintf(sbuf, sizeof(sbuf), "Yakalama baslangici: %s (Wireshark kiyasi icin referans)",
                          st.capture_start_wallclock.c_str());
            ImGui::TextUnformatted(sbuf);
        }

        // (A) Ingest-tier accounting: what the producer actually delivered in
        // the last 60s, measured BEFORE any per-detector queue drop (see the
        // loss indicator below for that separate, later tier). Answers "how
        // much data is coming in and how big are the packets" directly --
        // Gbit/60s matches the unit the user tracks by hand.
        char ibuf[160];
        std::snprintf(ibuf, sizeof(ibuf), "Ingest: %lld pkt/60s   |   %.2f Mbit/s (%.3f Gbit/60s)",
                      st.ingest_packets_60s, st.ingest_mbps, st.ingest_bytes_60s * 8.0 / 1e9);
        ImGui::TextUnformatted(ibuf);

        // (N1) Packets a detector never received because its bounded write
        // queue overflowed. Silent until now, and load-correlated -- so it
        // matters most exactly when a volumetric attack is in progress and
        // the deterministic SYN/connection counters need every packet.
        // Shown only once something has actually been dropped, and tinted
        // as a warning so a non-zero value cannot read as normal status.
        // Always rendered as a PERCENTAGE of offered packets: the bare count
        // is uninterpretable on its own (the same "6000" was ~6% loss on a
        // quiet Ethernet run and ~97% on a busy Wi-Fi one). Above 50% the
        // detector is effectively blind, so it escalates from amber to red.
        long long mc_drop = st.health.multiclass_detector.dropped_packets;
        long long mc_enq = st.health.multiclass_detector.enqueued_packets;
        if (mc_drop > 0) {
            double mc_pct = mc_enq ? (100.0 * mc_drop / mc_enq) : 0.0;
            char dbuf[220];
            std::snprintf(dbuf, sizeof(dbuf),
                          "Input loss (never analysed): Multiclass %.1f%% (%lld/%lld)",
                          mc_pct, mc_drop, mc_enq);
            ImGui::PushStyleColor(ImGuiCol_Text,
                                   mc_pct >= 50.0 ? theme::kDanger : theme::kWarning);
            ImGui::TextUnformatted(dbuf);
            ImGui::PopStyleColor();
        }
    }
    ImGui::PopStyleColor();
}

void RiskGauge(double score, const Fonts& fonts) {
    // Animate toward the latest polled value instead of snapping to it --
    // a bar that jumps once per poll cycle reads as "frozen" even when the
    // underlying data is updating fine.
    static float smoothed = 0.0f;
    smoothed = SmoothTowards(smoothed, static_cast<float>(score), ImGui::GetIO().DeltaTime);

    ImVec4 color = smoothed >= 70 ? theme::kDanger : (smoothed >= 40 ? theme::kWarning : theme::kSuccess);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    ImGui::TextUnformatted("LIVE RISK SCORE");
    ImGui::PopStyleColor();

    char overlay[32];
    std::snprintf(overlay, sizeof(overlay), "%.1f%%", smoothed);
    ImGui::PushStyleColor(ImGuiCol_PlotHistogram, color);
    ImGui::PushStyleColor(ImGuiCol_FrameBg, theme::kPanelAlt);
    ImGui::ProgressBar(smoothed / 100.0f, ImVec2(-1, 30), overlay);
    ImGui::PopStyleColor(2);
}

void RiskSparkline(const std::vector<float>& history, const std::vector<float>& times) {
    if (history.empty()) return;
    ImPlot::PushStyleColor(ImPlotCol_Line, theme::kAccent);
    ImPlot::PushStyleColor(ImPlotCol_Fill, ImVec4(theme::kAccent.x, theme::kAccent.y, theme::kAccent.z, 0.25f));
    ImPlotFlags pf = ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText | ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect;
    if (ImPlot::BeginPlot("##risk_spark", ImVec2(-1, 90), pf)) {
        ImPlotAxisFlags af = ImPlotAxisFlags_NoDecorations;
        ImPlot::SetupAxes(nullptr, nullptr, af, af);
        // A real "last 60 seconds" scrolling window: the right edge is
        // always "now", so the chart keeps flowing left even if the score
        // itself hasn't changed since the last sample.
        double right = times.back();
        ImPlot::SetupAxisLimits(ImAxis_X1, right - 60.0, right, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, 100, ImPlotCond_Always);
        ImPlot::PlotShaded("risk", times.data(), history.data(), (int)history.size(), 0.0);
        ImPlot::PlotLine("risk", times.data(), history.data(), (int)history.size());
        ImPlot::EndPlot();
    }
    ImPlot::PopStyleColor(2);
}

void HorizontalBarPlot(const char* plot_id, const std::vector<NamedCount>& data, ImVec4 color, int max_items = 8) {
    int n = std::min((int)data.size(), max_items);
    if (n <= 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted("No data in the last hour.");
        ImGui::PopStyleColor();
        return;
    }
    std::vector<double> values(n), positions(n);
    std::vector<std::string> label_storage(n);
    std::vector<const char*> labels(n);
    double max_val = 1.0;
    for (int i = 0; i < n; ++i) {
        values[i] = (double)data[i].count;
        positions[i] = i;
        label_storage[i] = data[i].name.empty() ? "UNKNOWN" : DisplayLabel(data[i].name);
        max_val = std::max(max_val, values[i]);
    }
    for (int i = 0; i < n; ++i) labels[i] = label_storage[i].c_str();

    float height = 26.0f * n + 40.0f;
    ImPlot::PushStyleColor(ImPlotCol_Fill, color);
    ImPlotFlags pf = ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText | ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect;
    if (ImPlot::BeginPlot(plot_id, ImVec2(-1, height), pf)) {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_None, ImPlotAxisFlags_Invert);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, max_val * 1.2, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, -0.5, n - 0.5, ImPlotCond_Always);
        ImPlot::SetupAxisTicks(ImAxis_Y1, positions.data(), n, labels.data());
        ImPlot::PlotBars("count", values.data(), positions.data(), n, 0.55, ImPlotBarsFlags_Horizontal);
        ImPlot::EndPlot();
    }
    ImPlot::PopStyleColor();
}

void AlertsTimelinePlot(const SeriesI& timeline) {
    int n = (int)timeline.values.size();
    if (n <= 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted("No timeline data yet.");
        ImGui::PopStyleColor();
        return;
    }
    std::vector<double> values(n), positions(n);
    std::vector<double> tick_pos;
    std::vector<std::string> tick_label_storage;
    std::vector<const char*> tick_labels;
    double max_val = 1.0;
    for (int i = 0; i < n; ++i) {
        values[i] = (double)timeline.values[i];
        positions[i] = i;
        max_val = std::max(max_val, values[i]);
        if (i % 4 == 0 && i < (int)timeline.labels.size()) {
            tick_pos.push_back(i);
            tick_label_storage.push_back(timeline.labels[i]);
        }
    }
    for (auto& s : tick_label_storage) tick_labels.push_back(s.c_str());

    ImPlot::PushStyleColor(ImPlotCol_Fill, theme::kAccent);
    ImPlotFlags pf = ImPlotFlags_NoLegend | ImPlotFlags_NoMouseText | ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect;
    if (ImPlot::BeginPlot("##alerts_timeline", ImVec2(-1, 170), pf)) {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_None, ImPlotAxisFlags_None);
        ImPlot::SetupAxisLimits(ImAxis_X1, -0.5, n - 0.5, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, max_val * 1.2, ImPlotCond_Always);
        if (!tick_pos.empty())
            ImPlot::SetupAxisTicks(ImAxis_X1, tick_pos.data(), (int)tick_pos.size(), tick_labels.data());
        ImPlot::PlotBars("alerts/h", values.data(), n, 0.7);
        ImPlot::EndPlot();
    }
    ImPlot::PopStyleColor();
}

// (B4) Kicks off the background LookupPacket() call and switches to the
// full-page detail view. Any previous worker thread is joined first (it
// will already have finished -- the only way back to the main dashboard is
// the detail page's own "back" button, which joins before clearing active).
void OpenPacketDetail(PipelineOrchestrator& orchestrator, const Alert& a) {
    if (g_detail.worker.joinable()) g_detail.worker.join();
    g_detail.active = true;
    g_detail.alert = a;
    {
        std::lock_guard<std::mutex> lock(g_detail.mtx);
        g_detail.loading = true;
        g_detail.found = false;
        g_detail.detail_text.clear();
        g_detail.error.clear();
        g_detail.download_result_msg.clear();
    }
    PipelineOrchestrator* orch = &orchestrator;
    g_detail.worker = std::thread([orch, a]() {
        auto result = orch->LookupPacket(a.frame_number, a.capture_ts, a.src_ip, a.dst_ip);
        std::lock_guard<std::mutex> lock(g_detail.mtx);
        g_detail.found = result.found;
        g_detail.detail_text = result.detail_text;
        g_detail.error = result.found ? std::string()
            : "Paket bulunamadi -- capture_ring donen penceresinden rotasyonla silinmis olabilir "
              "(varsayilan ~500MB/10 dosya; bkz. IDS_CAPTURE_RING_MB).";
        g_detail.loading = false;
    });
}

// `table_id` disambiguates ImGui's per-widget ID stack (table ID + per-row
// button IDs below) so this can be instantiated twice in the same window --
// once for ATTACK alerts, once for UNKNOWN/OOD ones -- without the two
// tables' row-selection/scroll state or button clicks bleeding into each
// other.
void RecentAlertsTable(const std::vector<Alert>& alerts, PipelineOrchestrator& orchestrator,
                        const Fonts& fonts, const char* table_id) {
    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                             ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable(table_id, 7, flags, ImVec2(0, 280))) return;

    ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 80);
    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 80);
    ImGui::TableSetupColumn("Attack Type");
    ImGui::TableSetupColumn("Flow (Src -> Dst:Port)");
    ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 90);
    // (B4) Satirin sonunda tek bir buton -- tiklaninca dogrudan tam sayfa
    // paket detayini acar (bkz. DrawPacketDetailPage). Eskiden satira tiklamak
    // satirin altina bir "PACKET INSPECTOR" paneli aciyordu; o ara-panel
    // kaldirildi, tek giris noktasi bu buton oldu.
    ImGui::TableSetupColumn("Detail", ImGuiTableColumnFlags_WidthFixed, 120);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    for (int i = 0; i < (int)alerts.size(); ++i) {
        const auto& a = alerts[i];
        ImGui::TableNextRow();

        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(HourMinuteSecond(a.timestamp).c_str());

        ImGui::TableSetColumnIndex(1);
        ImGui::PushStyleColor(ImGuiCol_Text, theme::StatusColor(a.status.c_str()));
        ImGui::TextUnformatted(a.status.c_str());
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(2);
        const std::string& shown = !a.predicted_class.empty() ? a.predicted_class : a.attack_type;
        ImGui::TextUnformatted(DisplayLabel(shown));

        ImGui::TableSetColumnIndex(3);
        char flow[160];
        if (a.has_dst_port)
            std::snprintf(flow, sizeof(flow), "%s -> %s:%d", a.src_ip.c_str(), a.dst_ip.c_str(), a.dst_port);
        else
            std::snprintf(flow, sizeof(flow), "%s -> %s", a.src_ip.c_str(), a.dst_ip.c_str());
        ImGui::TextUnformatted(flow);

        ImGui::TableSetColumnIndex(4);
        char score[16];
        std::snprintf(score, sizeof(score), "%.2f", a.score);
        ImGui::TextUnformatted(score);

        ImGui::TableSetColumnIndex(5);
        ImGui::PushStyleColor(ImGuiCol_Text, theme::SeverityColor(a.severity.c_str()));
        ImGui::TextUnformatted(a.severity.c_str());
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(6);
        bool has_frame = !a.frame_number.empty();
        if (!has_frame) ImGui::BeginDisabled();
        ImGui::PushStyleColor(ImGuiCol_Button, theme::kAccent);
        char btn_label[48];
        std::snprintf(btn_label, sizeof(btn_label), "Detay##pkt_%s_%d", table_id, i);
        if (ImGui::Button(btn_label)) {
            OpenPacketDetail(orchestrator, a);
        }
        ImGui::PopStyleColor();
        if (!has_frame) ImGui::EndDisabled();
    }
    ImGui::EndTable();
}

// Unfiltered feed -- every packet the detector scores, not just
// ATTACK-status ones (see RecentAlertsTable for the attack-only view).
// Fewer/narrower columns than RecentAlertsTable since this sits in a
// half-width split panel (severity dropped -- the Status color already
// carries that signal at a glance in a fast-scrolling raw feed).
void LiveTrafficTable(const std::vector<Alert>& feed) {
    ImGuiTableFlags flags = ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders |
                             ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable;
    if (!ImGui::BeginTable("live_traffic", 5, flags, ImVec2(0, 280))) return;

    ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 70);
    ImGui::TableSetupColumn("Class");
    ImGui::TableSetupColumn("Flow (Src -> Dst:Port)");
    ImGui::TableSetupColumn("Score", ImGuiTableColumnFlags_WidthFixed, 60);
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableHeadersRow();

    for (const auto& a : feed) {
        ImGui::TableNextRow();

        ImGui::TableSetColumnIndex(0);
        ImGui::TextUnformatted(HourMinuteSecond(a.timestamp).c_str());

        ImGui::TableSetColumnIndex(1);
        ImGui::PushStyleColor(ImGuiCol_Text, theme::StatusColor(a.status.c_str()));
        ImGui::TextUnformatted(a.status.c_str());
        ImGui::PopStyleColor();

        ImGui::TableSetColumnIndex(2);
        const std::string& shown = !a.predicted_class.empty() ? a.predicted_class : a.attack_type;
        ImGui::TextUnformatted(DisplayLabel(shown));

        ImGui::TableSetColumnIndex(3);
        char flow[160];
        if (a.has_dst_port)
            std::snprintf(flow, sizeof(flow), "%s -> %s:%d", a.src_ip.c_str(), a.dst_ip.c_str(), a.dst_port);
        else
            std::snprintf(flow, sizeof(flow), "%s -> %s", a.src_ip.c_str(), a.dst_ip.c_str());
        ImGui::TextUnformatted(flow);

        ImGui::TableSetColumnIndex(4);
        char score[16];
        std::snprintf(score, sizeof(score), "%.2f", a.score);
        ImGui::TextUnformatted(score);
    }
    ImGui::EndTable();
}

void PortDistributionPie(const PortDistribution& pd) {
    int n = (int)pd.ports.size();
    if (n <= 0) return;
    std::vector<double> values(n);
    std::vector<const char*> labels(n);
    double total = 0;
    for (int i = 0; i < n; ++i) { values[i] = (double)pd.counts[i]; total += values[i]; labels[i] = pd.ports[i].c_str(); }
    if (total <= 0) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted("No traffic in the last hour.");
        ImGui::PopStyleColor();
        return;
    }
    ImPlotFlags pf = ImPlotFlags_NoMouseText | ImPlotFlags_NoMenus | ImPlotFlags_NoBoxSelect;
    if (ImPlot::BeginPlot("##port_pie", ImVec2(-1, 220), pf)) {
        ImPlot::SetupAxes(nullptr, nullptr, ImPlotAxisFlags_NoDecorations, ImPlotAxisFlags_NoDecorations);
        ImPlot::SetupAxisLimits(ImAxis_X1, 0, 1, ImPlotCond_Always);
        ImPlot::SetupAxisLimits(ImAxis_Y1, 0, 1, ImPlotCond_Always);
        ImPlot::PlotPieChart(labels.data(), values.data(), n, 0.5, 0.5, 0.4, "%.0f");
        ImPlot::EndPlot();
    }
}

void SectionLabel(const char* text, const Fonts& fonts) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();
    ImGui::Separator();
}

// Same header look as SectionLabel, plus an action button pinned to the far
// (opposite) corner of the header row -- used by the alerts panel's
// "Download All" button. Returns true the frame the button is clicked.
bool SectionLabelWithButton(const char* text, const char* btn_label, bool btn_enabled) {
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    ImGui::TextUnformatted(text);
    ImGui::PopStyleColor();

    float btn_w = ImGui::CalcTextSize(btn_label).x + ImGui::GetStyle().FramePadding.x * 2;
    ImGui::SameLine(ImGui::GetWindowWidth() - btn_w - ImGui::GetStyle().WindowPadding.x);
    if (!btn_enabled) ImGui::BeginDisabled();
    ImGui::PushStyleColor(ImGuiCol_Button, theme::kAccent);
    bool clicked = ImGui::Button(btn_label);
    ImGui::PopStyleColor();
    if (!btn_enabled) ImGui::EndDisabled();

    ImGui::Separator();
    return clicked;
}

// Renders the "Xxx paket indiriliyor..." / "N/M paket kaydedildi." line right
// under a panel's SectionLabelWithButton -- shared by the attacks and
// UNKNOWN/OOD panels, each with its own BulkDownloadState instance so their
// progress/result text never bleeds into the other panel.
void DrawBulkDownloadStatus(BulkDownloadState& bulk_state) {
    bool bulk_in_progress;
    std::string bulk_msg;
    {
        std::lock_guard<std::mutex> lock(bulk_state.mtx);
        bulk_in_progress = bulk_state.in_progress;
        bulk_msg = bulk_state.result_msg;
    }
    if (bulk_in_progress || !bulk_msg.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted(bulk_in_progress ? "Tum paketler indiriliyor..." : bulk_msg.c_str());
        ImGui::PopStyleColor();
    }
}

// (B11) Wireshark-style capture toolbar: stop/resume the live capture, and
// archive the ring buffer to a permanent file.
//
// The two buttons are deliberately adjacent and in this order, because they
// are one workflow: the ring is a ~500MB overwriting buffer, so the moment an
// operator sees an attack worth keeping, the sequence is stop-then-save. Save
// stays enabled while capturing (the ring files are readable either way), but
// the tooltip points at the stop-first path since only that guarantees tshark
// isn't overwriting the evidence mid-merge.
void CaptureControls(const DashboardState& st, PipelineOrchestrator& orchestrator,
                      const std::wstring& repo_root) {
    bool paused = st.capture_paused;

    ImGui::PushStyleColor(ImGuiCol_Button, paused ? theme::kSuccess : theme::kDanger);
    if (ImGui::Button(paused ? "Yakalamayi Surdur" : "Yakalamayi Durdur", ImVec2(190, 0))) {
        // Both calls are synchronous but bounded (a process kill plus a join
        // on a thread that unblocks as soon as the pipe breaks) -- see
        // PipelineOrchestrator::PauseCapture's header comment.
        if (paused) orchestrator.ResumeCapture();
        else orchestrator.PauseCapture();
    }
    ImGui::PopStyleColor();
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
            "Sadece paket yakalamayi (tshark) durdurur/baslatir.\n"
            "Tespit modeli, Mongo yazimi ve ekrandaki tum veriler calismaya devam eder.\n"
            "Durdurmak, capture_ring'in uzerine yazilmasini engeller.");
    }

    ImGui::SameLine();

    bool saving;
    std::string save_msg;
    {
        std::lock_guard<std::mutex> lock(g_ring_save.mtx);
        saving = g_ring_save.in_progress;
        save_msg = g_ring_save.result_msg;
    }

    if (saving) ImGui::BeginDisabled();
    if (ImGui::Button("Akisi Kaydet (.pcapng)", ImVec2(200, 0)))
        TriggerRingSave(orchestrator, repo_root);
    if (saving) ImGui::EndDisabled();
    if (ImGui::IsItemHovered()) {
        ImGui::SetTooltip(
            "capture_ring'deki TUM yakalama dosyalarini tek bir .pcapng'de birlestirir\n"
            "(mergecap). Varsayilan konum: captures/\n"
            "Once 'Yakalamayi Durdur' demek onerilir -- aksi halde en yeni ring\n"
            "dosyasi yazilmaya devam ettigi icin sonu eksik kalabilir.");
    }

    ImGui::SameLine(0, 16);
    if (saving) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
        ImGui::TextUnformatted("Birlestiriliyor...");
        ImGui::PopStyleColor();
    } else if (!save_msg.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextUnformatted(save_msg.c_str());
        ImGui::PopStyleColor();
    } else if (paused) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
        ImGui::TextUnformatted("Yakalama durduruldu -- ring dosyalari korunuyor.");
        ImGui::PopStyleColor();
    }
}

void DrawDashboard(const DashboardState& st, PipelineOrchestrator& orchestrator,
                    const std::wstring& repo_root, const Fonts& fonts) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                              ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                              ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
    ImGui::Begin("MainWindow", nullptr, flags);

    // ── Header ──
    ImGui::PushFont(fonts.header);
    ImGui::TextUnformatted("IDS LIVE CONSOLE");
    ImGui::PopFont();
    ImGui::SameLine(0, 20);
    ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
    ImGui::TextUnformatted("Real-Time Anomaly Detection in Streaming Big Data Pipelines");
    ImGui::PopStyleColor();
    ImGui::SameLine(ImGui::GetWindowWidth() - 480);
    HealthBadge(st, fonts);
    ImGui::Separator();
    ImGui::Spacing();

    // ── (B11) Capture toolbar ──
    CaptureControls(st, orchestrator, repo_root);
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    // ── Stat tiles ──
    float avail = ImGui::GetContentRegionAvail().x;
    float tile_w = (avail - 4 * ImGui::GetStyle().ItemSpacing.x) / 5.0f;
    ImGui::PushItemWidth(tile_w);
    ImGui::BeginGroup();
    ImGui::Columns(5, "stat_cols", false);
    ImGui::SetColumnWidth(0, tile_w + 14); ImGui::SetColumnWidth(1, tile_w + 14);
    ImGui::SetColumnWidth(2, tile_w + 14); ImGui::SetColumnWidth(3, tile_w + 14);
    ImGui::SetColumnWidth(4, tile_w + 14);
    StatTile("TOTAL TRAFFIC", FormatCount(st.stats.total_traffic), theme::kAccent, fonts);
    ImGui::NextColumn();
    StatTile("DETECTED ATTACKS", FormatCount(st.stats.attack_count), theme::kDanger, fonts);
    ImGui::NextColumn();
    StatTile("NORMAL (BENIGN)", FormatCount(st.stats.benign_count), theme::kSuccess, fonts);
    ImGui::NextColumn();
    // R20: OOD gate -- distance-to-training-manifold verdict, distinct from
    // both confirmed BENIGN and ATTACK (see pipeline/process_pcap.py).
    StatTile("OUT-OF-DISTRIBUTION", FormatCount(st.stats.unknown_count), theme::kInfo, fonts);
    ImGui::NextColumn();
    StatTile("PACKETS (last 3s)", FormatCount(st.live_traffic_count), theme::kAccent, fonts);
    ImGui::Columns(1);
    ImGui::EndGroup();
    ImGui::PopItemWidth();

    ImGui::Spacing();
    ImGui::Spacing();

    // ── Two-column body (fixed height, leaves room for the full-width
    // traffic/alerts row below) + full-width bottom row ──
    constexpr float kBottomRowHeight = 340.0f;
    float top_row_h = ImGui::GetContentRegionAvail().y - kBottomRowHeight - ImGui::GetStyle().ItemSpacing.y;

    ImGui::BeginChild("top_row", ImVec2(0, top_row_h), false);
    {
        float left_w = ImGui::GetContentRegionAvail().x * 0.62f;
        ImGui::BeginChild("left_col", ImVec2(left_w, 0), false);
        {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
            ImGui::BeginChild("risk_panel", ImVec2(0, 180), true);
            RiskGauge(st.latest_score.score, fonts);
            RiskSparkline(st.risk_history, st.risk_time);
            ImGui::EndChild();
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
            ImGui::BeginChild("timeline_panel", ImVec2(0, 0), true);
            SectionLabel("ALERT TIMELINE (LAST 24H)", fonts);
            AlertsTimelinePlot(st.alerts_timeline);
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();

        ImGui::SameLine();

        ImGui::BeginChild("right_col", ImVec2(0, 0), false);
        {
            ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
            ImGui::BeginChild("predicted_panel", ImVec2(0, 260), true);
            SectionLabel("DETECTED CLASS DISTRIBUTION (1H)", fonts);
            HorizontalBarPlot("##predicted_class", st.predicted_class_distribution, theme::kInfo, 7);
            ImGui::EndChild();
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
            ImGui::BeginChild("top_sources_panel", ImVec2(0, 260), true);
            SectionLabel("TOP ATTACKER IPs (1H)", fonts);
            std::vector<NamedCount> src_named;
            for (size_t i = 0; i < st.top_sources.ips.size(); ++i)
                src_named.push_back({st.top_sources.ips[i], st.top_sources.counts[i]});
            HorizontalBarPlot("##top_sources", src_named, theme::kDanger, 7);
            ImGui::EndChild();
            ImGui::PopStyleColor();

            ImGui::Spacing();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
            ImGui::BeginChild("port_panel", ImVec2(0, 0), true);
            SectionLabel("PORT DISTRIBUTION (1H)", fonts);
            PortDistributionPie(st.port_distribution);
            ImGui::EndChild();
            ImGui::PopStyleColor();
        }
        ImGui::EndChild();
    }
    ImGui::EndChild();

    ImGui::Spacing();

    // ── Full-width bottom row: unfiltered live traffic, attack-only alerts,
    // and UNKNOWN/OOD-only alerts side by side -- all three always visible,
    // per user request, rather than a single filtered/tabbed view. ──
    ImGui::BeginChild("bottom_row", ImVec2(0, kBottomRowHeight), false);
    {
        float third_w = (ImGui::GetContentRegionAvail().x - 2 * ImGui::GetStyle().ItemSpacing.x) / 3.0f;

        ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
        ImGui::BeginChild("traffic_feed_panel", ImVec2(third_w, 0), true);
        SectionLabel("LIVE TRAFFIC (ALL)", fonts);
        LiveTrafficTable(st.live_traffic_feed);
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::SameLine();

        ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
        ImGui::BeginChild("alerts_panel", ImVec2(third_w, 0), true);
        if (SectionLabelWithButton("RECENT ALERTS", "Tumunu Indir (.pcapng)", !st.recent_alerts.empty()))
            TriggerBulkDownload(orchestrator, st.recent_alerts, g_bulk_download, L"all_alerts.pcapng");
        DrawBulkDownloadStatus(g_bulk_download);
        RecentAlertsTable(st.recent_alerts, orchestrator, fonts, "recent_alerts");
        ImGui::EndChild();
        ImGui::PopStyleColor();

        ImGui::SameLine();

        // R20 OOD gate verdict -- neither confirmed BENIGN nor ATTACK. Same
        // bulk/per-row pcapng download machinery as the attacks panel, just
        // fed from recent_unknown_alerts instead of recent_alerts.
        ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
        ImGui::BeginChild("unknown_panel", ImVec2(0, 0), true);
        if (SectionLabelWithButton("RECENT UNKNOWN (OOD)", "Tumunu Indir (.pcapng)", !st.recent_unknown_alerts.empty()))
            TriggerBulkDownload(orchestrator, st.recent_unknown_alerts, g_bulk_download_unknown, L"all_unknown.pcapng");
        DrawBulkDownloadStatus(g_bulk_download_unknown);
        RecentAlertsTable(st.recent_unknown_alerts, orchestrator, fonts, "recent_unknown");
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }
    ImGui::EndChild();

    ImGui::End();
}

// (B6) True once every subprocess has emitted its FIRST parsed event.
// last_event_age_seconds starts at -1 ("no event received yet", see the
// header's ProcHealth comment) and flips to a real, only-ever-growing value
// the moment ReaderLoop/FanoutLoop successfully parses one line from that
// child -- unlike ProcHealth::running, which just means "the OS process
// hasn't exited" and goes true within ~1s of spawn, long before the
// multiclass detector finishes loading its TF/sklearn models (empirically
// ~30-40s). This is the genuine "packets are now flowing into the tables"
// signal the startup screen waits on. Latched in a static so a later
// transient stall in one child can't flip the startup screen back on.
bool IsPipelineReady(const DashboardState& st) {
    static bool ever_ready = false;
    if (!ever_ready) {
        ever_ready = st.reachable &&
                     st.health.producer.last_event_age_seconds >= 0 &&
                     st.health.multiclass_detector.last_event_age_seconds >= 0;
    }
    return ever_ready;
}

// (B6) Shown instead of the dashboard until IsPipelineReady() -- otherwise
// the user sees an empty "0 packets" dashboard for the ~30-40s the detectors
// take to load their models and has no way to tell "still starting" apart
// from "something is wrong". Per-stage status lines double as the crash
// diagnostic that the old empty dashboard never surfaced either.
void DrawStartupScreen(const DashboardState& st, const Fonts& fonts) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                              ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                              ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
    ImGui::Begin("Startup", nullptr, flags);

    float panel_w = 620.0f;
    ImGui::SetCursorPos(ImVec2((io.DisplaySize.x - panel_w) * 0.5f, io.DisplaySize.y * 0.30f));
    ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanel);
    ImGui::BeginChild("startup_panel", ImVec2(panel_w, 260), true);

    ImGui::PushFont(fonts.header);
    ImGui::TextUnformatted("IDS LIVE CONSOLE");
    ImGui::PopFont();
    ImGui::Spacing();

    if (!st.reachable && !st.last_error.empty()) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kDanger);
        ImGui::TextWrapped("Pipeline baslatilamadi: %s", st.last_error.c_str());
        ImGui::PopStyleColor();
    } else {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kTextDim);
        ImGui::TextWrapped(
            "Lutfen bekleyin -- yakalama basladi, tespit modelleri yukleniyor. "
            "Bu ekran kapaninca paketler tablolara akmaya baslar (makineye "
            "bagli olarak ~30-40 saniye surebilir).");
        ImGui::PopStyleColor();
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    auto StatusRow = [](const char* label, bool running, double age) {
        ImGui::TextUnformatted(label);
        ImGui::SameLine(260);
        if (!running) {
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
            ImGui::TextUnformatted("baslatiliyor...");
        } else if (age < 0) {
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
            ImGui::TextUnformatted("surec ayakta, model yukleniyor...");
        } else {
            ImGui::PushStyleColor(ImGuiCol_Text, theme::kSuccess);
            ImGui::TextUnformatted("hazir");
        }
        ImGui::PopStyleColor();
    };
    StatusRow("Paket Yakalama (tshark):", st.health.producer.running,
               st.health.producer.last_event_age_seconds);
    StatusRow("Coklu-Sinif Tespit Modeli:", st.health.multiclass_detector.running,
               st.health.multiclass_detector.last_event_age_seconds);

    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::End();
}

// (B4) Full-page Wireshark-style packet detail: takes over the whole window
// (same full-window Begin() pattern as DrawDashboard) instead of a modal, so
// the hex dump + protocol tree have the full width to breathe -- per user
// request, this is a real "page", not a popup over the dashboard.
void DrawPacketDetailPage(PipelineOrchestrator& orchestrator, const Fonts& fonts) {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(0, 0));
    ImGui::SetNextWindowSize(io.DisplaySize);
    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
                              ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                              ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus;
    ImGui::Begin("PacketDetail", nullptr, flags);

    const Alert& a = g_detail.alert;

    if (ImGui::Button("<- Ana Panele Don")) {
        // Both workers are done or nearly done by the time a user reaches
        // for "back" (lookup is usually sub-second); joining here is what
        // makes it safe to overwrite g_detail from OpenPacketDetail() the
        // next time a row is clicked.
        if (g_detail.worker.joinable()) g_detail.worker.join();
        if (g_detail.download_worker.joinable()) g_detail.download_worker.join();
        g_detail.active = false;
        ImGui::End();
        return;
    }
    ImGui::SameLine(0, 24);
    ImGui::PushFont(fonts.header);
    ImGui::Text("PACKET DETAIL -- frame #%s", a.frame_number.c_str());
    ImGui::PopFont();
    ImGui::Separator();
    ImGui::Spacing();

    ImGui::Text("Zaman: %s   |   Durum: %s   |   Skor: %.4f   |   Onem: %s",
                a.timestamp.c_str(), a.status.c_str(), a.score, a.severity.c_str());
    if (a.has_dst_port)
        ImGui::Text("Akis: %s -> %s:%d", a.src_ip.c_str(), a.dst_ip.c_str(), a.dst_port);
    else
        ImGui::Text("Akis: %s -> %s", a.src_ip.c_str(), a.dst_ip.c_str());
    const std::string& label = !a.predicted_class.empty() ? a.predicted_class : a.attack_type;
    ImGui::Text("Tahmin: %s   |   Tetikleyen: %s", DisplayLabel(label),
                a.alert_source.empty() ? "-" : a.alert_source.c_str());

    ImGui::Spacing();
    ImGui::PushStyleColor(ImGuiCol_Button, theme::kAccent);
    if (ImGui::Button("Download PCAP (.pcapng)")) {
        std::wstring out_path = PromptSaveFile(
            L"Wireshark Capture (*.pcapng)\0*.pcapng\0All Files\0*.*\0", L"pcapng", L"packet.pcapng");
        if (!out_path.empty()) {
            if (g_detail.download_worker.joinable()) g_detail.download_worker.join();
            {
                std::lock_guard<std::mutex> lock(g_detail.mtx);
                g_detail.download_in_progress = true;
                g_detail.download_result_msg.clear();
            }
            PipelineOrchestrator* orch = &orchestrator;
            Alert snap = a;
            g_detail.download_worker = std::thread([orch, snap, out_path]() {
                bool ok = orch->ExtractPacketToFile(snap.frame_number, snap.capture_ts,
                                                     snap.src_ip, snap.dst_ip, out_path);
                std::lock_guard<std::mutex> lock(g_detail.mtx);
                g_detail.download_in_progress = false;
                g_detail.download_result_msg = ok ? "Kaydedildi." : "Paket bulunamadi / kaydedilemedi.";
            });
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Export JSON")) {
        std::wstring out_path = PromptSaveFile(
            L"JSON (*.json)\0*.json\0All Files\0*.*\0", L"json", L"alert.json");
        if (!out_path.empty()) {
            std::string j = AlertToJson(a);
            FILE* f = _wfopen(out_path.c_str(), L"wb");
            if (f) {
                std::fwrite(j.data(), 1, j.size(), f);
                std::fclose(f);
            }
        }
    }
    ImGui::PopStyleColor();

    bool loading, found, dl_in_progress;
    std::string detail_text, error, dl_msg;
    {
        std::lock_guard<std::mutex> lock(g_detail.mtx);
        loading = g_detail.loading;
        found = g_detail.found;
        detail_text = g_detail.detail_text;
        error = g_detail.error;
        dl_in_progress = g_detail.download_in_progress;
        dl_msg = g_detail.download_result_msg;
    }
    if (dl_in_progress) {
        ImGui::SameLine();
        ImGui::TextUnformatted("(indiriliyor...)");
    } else if (!dl_msg.empty()) {
        ImGui::SameLine();
        ImGui::TextUnformatted(dl_msg.c_str());
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    if (loading) {
        ImGui::TextUnformatted("Paket araniyor (capture_ring taraniyor)...");
    } else if (!found) {
        ImGui::PushStyleColor(ImGuiCol_Text, theme::kWarning);
        ImGui::TextUnformatted(error.empty() ? "Paket bulunamadi." : error.c_str());
        ImGui::PopStyleColor();
    } else {
        // tshark's own -V (protocol tree) + -x (hex+ASCII) output for this
        // one packet -- the same information Wireshark's packet detail pane
        // shows, as plain scrollable monospace text for v1 (a collapsible
        // tree view is a natural follow-up, not required for the "full
        // detail" ask itself).
        ImGui::PushStyleColor(ImGuiCol_ChildBg, theme::kPanelAlt);
        ImGui::BeginChild("packet_detail_text", ImVec2(0, 0), true);
        ImGui::PushFont(fonts.mono);
        ImGui::TextUnformatted(detail_text.c_str());
        ImGui::PopFont();
        ImGui::EndChild();
        ImGui::PopStyleColor();
    }

    ImGui::End();
}

} // namespace

int main() {
    glfwSetErrorCallback(GlfwErrorCallback);
    if (!glfwInit()) {
        std::fprintf(stderr, "Failed to initialize GLFW\n");
        return 1;
    }

    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);

    GLFWwindow* window = glfwCreateWindow(1500, 950,
        "IDS Live Console - Real-Time Anomaly Detection", nullptr, nullptr);
    if (!window) {
        std::fprintf(stderr, "Failed to create GLFW window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImPlot::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    Fonts fonts = theme::LoadFonts(io);
    theme::Apply();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // Spawns the capture producer + both detectors as subprocesses and
    // fans packets out to them -- see pipeline_orchestrator.h. Runs even if
    // start() fails to launch everything (health badge shows what's down;
    // the log files under console/logs explain why).
    PipelineOrchestrator orchestrator;
#ifdef IDS_R26_PHASE2_SOFTVOTE
    // (R26 Faz 2, 2026-08-14) CANLI A/B BUILD'I -- yalnizca ayri isimli
    // `ids_dashboard_r26_phase2_softvote.exe` hedefinde tanimli. VARSAYILAN
    // `ids_dashboard` hedefinde bu makro TANIMSIZ, dolayisiyla asagidaki blok
    // DERLENMEZ ve uretim binary'si bit-duzeyinde degismez.
    //
    // NEDEN BURADA (env degiskeni) VE C++'ta BASKA BIR SEY DEGIL: dedektor
    // Python surecleri SpawnDetector -> LaunchProcess -> CreateProcessW ile
    // lpEnvironment=nullptr olarak baslatilir, yani EBEVEYNIN ORTAMINI
    // DEVRALIRLAR. Bayragi burada set etmek, process_pcap_multiclass.py'nin
    // os.environ["MC_R26_SOFTVOTE"] okumasina birebir yeter -- orchestrator
    // veya Python tarafinda HICBIR degisiklik gerekmez.
    //
    // Bunu shell'den `set MC_R26_SOFTVOTE=1` ile yapmak da mumkundu; binary'ye
    // gomulmesinin sebebi ARTEFAKTIN KENDINI TANIMLAMASI: bu .exe cift
    // tiklandiginda da soft-vote'lu calisir, "hangi ortamda baslatildi"
    // belirsizligi kalmaz (2026-08-06'daki ids_dashboard_r26_committee.exe
    // ayrimiyla ayni gerekce).
    _wputenv_s(L"MC_R26_SOFTVOTE", L"1");
#endif
    // (B11) Kept in a local because the capture toolbar's "Akisi Kaydet"
    // button needs it too, to default the save dialog into captures/.
    const std::wstring repo_root = ResolveRepoRoot();
    orchestrator.start(repo_root, ResolveInterface());

    // orchestrator.snapshot() deep-copies the whole DashboardState (every
    // Alert's several std::strings, all the rolling-window vectors) under
    // the same mutex the reader/ticker threads use -- doing that at full
    // vsync framerate (up to ~60Hz) added avoidable lock contention on top
    // of the pipe-backpressure fix above. ~15Hz is still imperceptibly
    // "live" for a monitoring dashboard; frames in between just redraw the
    // last snapshot (GLFW/ImGui still render every vsync tick, so the
    // window stays smooth/responsive -- only the data refresh is throttled).
    DashboardState snapshot;
    auto last_snapshot_time = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    constexpr auto kSnapshotInterval = std::chrono::milliseconds(66);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        auto now = std::chrono::steady_clock::now();
        if (now - last_snapshot_time >= kSnapshotInterval) {
            snapshot = orchestrator.snapshot();
            last_snapshot_time = now;
        }
        // (B4/B6) g_detail.active toggles the whole window between the normal
        // dashboard and the full-page packet detail view; below that, the
        // startup screen gates the dashboard until packets are actually
        // flowing (see IsPipelineReady's comment for why ProcHealth::running
        // alone isn't a good enough signal for that).
        if (g_detail.active)
            DrawPacketDetailPage(orchestrator, fonts);
        else if (!IsPipelineReady(snapshot))
            DrawStartupScreen(snapshot, fonts);
        else
            DrawDashboard(snapshot, orchestrator, repo_root, fonts);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(theme::kBg.x, theme::kBg.y, theme::kBg.z, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    orchestrator.stop();

    // (B4) g_detail is a static-storage singleton; its worker threads are
    // normally joined by the detail page's "back" button, but if the window
    // was closed while a lookup/download was still running (or had finished
    // but was never explicitly joined), std::thread's destructor would call
    // std::terminate() on a still-joinable thread at static-destruction
    // time. Join both unconditionally here so exit is clean either way.
    if (g_detail.worker.joinable()) g_detail.worker.join();
    if (g_detail.download_worker.joinable()) g_detail.download_worker.join();
    if (g_bulk_download.worker.joinable()) g_bulk_download.worker.join();
    if (g_bulk_download_unknown.worker.joinable()) g_bulk_download_unknown.worker.join();
    if (g_ring_save.worker.joinable()) g_ring_save.worker.join(); // (B11) same reasoning

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImPlot::DestroyContext();
    ImGui::DestroyContext();

    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
