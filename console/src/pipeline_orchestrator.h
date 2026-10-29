// Local-process orchestrator: replaces api_client.h's HTTP polling of
// pipeline/dashboard_api.py (Flask) + MongoDB with direct subprocess/pipe
// IPC. On start(), this spawns two child processes:
//
//   live_wireshark_producer.py --sink stdout   (tshark capture -> JSON lines)
//   process_pcap_multiclass.py (INPUT_MODE=stdin OUTPUT_MODE=stdout)
//
// and fans out every captured packet (one JSON line) from the producer's
// stdout into the detector's stdin, then parses its stdout prediction stream
// directly into a DashboardState the UI can render, replacing Mongo+Flask+
// HTTP polling. No Kafka/Zookeeper/MongoDB/WSL2 is required for the app to
// run; MongoDB remains optional (the Python side still writes to it if
// reachable, see mongo_logger_multiclass.py's graceful no-op behavior).
//
// (B10) The binary pipeline (pipeline/process_pcap.py, MainRF_v5/MainLSTM_v5)
// is DELIBERATELY not spawned here anymore -- running two synchronous ML
// detectors per captured packet was measured to roughly double per-packet
// CPU cost, which is what R32 traced the ~92% queue-drop-under-load figure
// to. process_pcap.py itself is untouched and still used by the offline
// validation scripts (analysis/validate_offline_predictions.py etc.) for the
// thesis's binary-vs-multiclass comparison -- only this LIVE app stopped
// running it.
//
// All existing R1-R24/K1/K3/S1-S5 detection logic in the Python scripts is
// untouched -- only their I/O transport changed (see process_pcap_multiclass.py's
// _packet_source()/_emit_prediction()).
#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

struct Stats {
    long long total_traffic = 0;
    long long attack_count = 0;
    long long benign_count = 0;
    long long unknown_count = 0; // R20: OOD gate verdict, neither ATTACK nor BENIGN
};

struct Alert {
    std::string timestamp;    // HH:MM:SS, local wall-clock at time of receipt
    std::string status;       // "ATTACK" | "BENIGN" | "UNKNOWN"
    double score = 0.0;       // risk_score, 0..1
    std::string attack_type;
    std::string predicted_class; // multiclass class label, e.g. "DoS"/"PortScan"
    std::string alert_source;    // may be empty
    std::string severity;
    std::string src_ip;
    std::string dst_ip;
    int dst_port = 0;
    bool has_dst_port = false;
    // (B2) tshark frame.number for this packet, forwarded by process_pcap.py/
    // process_pcap_multiclass.py's _emit_prediction. Empty if absent (e.g. an
    // older detector build, or the packet came through before B2 shipped) --
    // the packet-detail view treats that as "unavailable" rather than "0".
    std::string frame_number;
    double capture_ts = 0.0; // == "ts" from the JSON event (epoch seconds)
};

struct NamedCount {
    std::string name;
    long long count = 0;
};

// Per-subprocess liveness, replacing the old "is Flask reachable" health
// check with "is each of our own child processes still running/producing".
struct ProcHealth {
    bool running = false;
    double last_event_age_seconds = -1.0; // -1 = no event received yet

    // (N1) Packets this child NEVER received because its bounded write queue
    // was full and EnqueueForChild dropped the oldest entry. Previously this
    // loss was completely silent: a live-fire session measured 6.2%/6.3% of
    // frames missing per detector, load-dependent (1.4% idle vs 9.1% under
    // load, 13.8% peak) -- i.e. worst exactly during a volumetric attack,
    // when the deterministic SYN/connection counters need every packet.
    // Surfaced here as pure measurement; the queue bound itself is unchanged.
    long long dropped_packets = 0;
    // Denominator for the above: total packets offered to this child. A bare
    // dropped count is uninterpretable -- measured live, the same absolute
    // number meant ~6% loss on a quiet Ethernet segment and ~97% on a busy
    // Wi-Fi one. Always render the two together.
    long long enqueued_packets = 0;
};

struct Health {
    ProcHealth producer;
    ProcHealth multiclass_detector;
};

struct LatestScore {
    double score = 0.0; // 0..100
    std::string status;
    std::string attack_type;
};

struct SeriesI {
    std::vector<std::string> labels;
    std::vector<long long> values;
};

struct TopSources {
    std::vector<std::string> ips;
    std::vector<long long> counts;
};

struct PortDistribution {
    std::vector<std::string> ports;
    std::vector<long long> counts;
};

// Everything the render thread needs, refreshed as JSON prediction lines
// arrive from the two detector subprocesses (push-based, not polled).
struct DashboardState {
    bool reachable = false; // true once orchestration has been start()-ed successfully
    std::string last_error;

    // (B8) Local HH:MM:SS the instant tshark (the producer) actually started
    // capturing -- i.e. once both detectors' models finished loading (see
    // ProducerLaunchWatcherLoop). Empty until then. Exists so a user running
    // a standalone Wireshark capture alongside this app for a 1:1 packet-
    // count comparison has an exact reference point: anything Wireshark
    // counted before this timestamp is traffic that arrived during the
    // model warm-up, which this app deliberately never captured, and
    // shouldn't be counted as a discrepancy.
    std::string capture_start_wallclock;

    // (B11) True while the user has stopped live capture from the UI
    // ("Yakalamayi Durdur"). Only the producer subtree (tshark) is gone --
    // the detector, Mongo writer and every UI aggregate stay alive and keep
    // showing what was already collected. Exists so the health badge can say
    // "PAUSED" instead of reporting the (deliberately) dead producer as a
    // fault, and so the toggle button knows which label to draw.
    bool capture_paused = false;

    Stats stats;
    std::vector<Alert> recent_alerts;      // ATTACK-status only
    std::vector<Alert> recent_unknown_alerts; // UNKNOWN-status only (R20 OOD gate verdict)
    std::vector<Alert> live_traffic_feed;  // every packet (BENIGN/ATTACK/UNKNOWN), newest first
    std::vector<NamedCount> predicted_class_distribution;
    Health health;
    long long live_traffic_count = 0; // packets in the last ~3s

    // (A) Ingest-tier accounting: every packet the producer emitted in the
    // last 60s, measured in FanoutLoop BEFORE any per-detector queue can
    // drop it (see ProcHealth::dropped_packets for that separate, later
    // tier). Answers "how much data actually arrived from tshark" --
    // frame.len summed gives real throughput, independent of whether either
    // detector could keep up.
    long long ingest_packets_60s = 0;
    double ingest_bytes_60s = 0.0;
    double ingest_mbps = 0.0; // bytes_60s * 8 / 60 / 1e6, i.e. average over the window

    LatestScore latest_score;
    PortDistribution port_distribution;
    SeriesI alerts_timeline;   // hourly buckets, last 24h
    TopSources top_sources;    // last 1h

    // Rolling client-side history for the live risk sparkline.
    // risk_time is wall-clock seconds since orchestration started, paired
    // 1:1 with risk_history, so the chart can scroll a real "last N
    // seconds" window instead of just plotting N samples regardless of age.
    std::vector<float> risk_history;
    std::vector<float> risk_time;
};

// Opaque implementation (owns HANDLEs/threads) so this header stays free of
// <windows.h>.
class PipelineOrchestrator {
public:
    PipelineOrchestrator();
    ~PipelineOrchestrator();

    PipelineOrchestrator(const PipelineOrchestrator&) = delete;
    PipelineOrchestrator& operator=(const PipelineOrchestrator&) = delete;

    // Spawns producer + binary + multiclass detector subprocesses with
    // piped local IPC. repo_root must contain pipeline/ and
    // multiclass_training/. `interface` is forwarded verbatim as the
    // producer's --interface value -- a single adapter name, or a
    // comma-separated list (e.g. "Wi-Fi,Ethernet") to capture on several at
    // once; live_wireshark_producer.py does the splitting, see its own
    // build_tshark_cmd(). Returns false (with an error in the next
    // snapshot()) if the python interpreter or a script can't be found.
    bool start(const std::wstring& repo_root, const std::wstring& interface);

    // Closes detector stdin (graceful EOF-triggered shutdown) then
    // terminates the whole spawned process tree (producer's tshark child
    // included) via a Windows Job Object, and joins all reader threads.
    void stop();

    // Thread-safe snapshot of the current aggregated state for rendering.
    DashboardState snapshot();

    // (B11) Wireshark-style stop/resume of the LIVE CAPTURE ONLY.
    //
    // PauseCapture() terminates the producer subtree (live_wireshark_producer.py
    // and its tshark child, which live in their own Job Object -- see
    // Impl::producer_job) and joins the fanout thread. Everything downstream --
    // the detector process, its Mongo writes, and every aggregate already in
    // DashboardState -- is left untouched and keeps rendering; there is simply
    // no new packet arriving. ResumeCapture() spawns a fresh producer and
    // restarts fanout.
    //
    // Killing tshark rather than just dropping packets in FanoutLoop is the
    // POINT, not an implementation detail: the capture_ring is a bounded
    // ring buffer (RING_FILE_MB x RING_FILE_COUNT, ~500MB by default) that
    // tshark keeps overwriting. Only stopping tshark freezes the ring's
    // contents long enough for SaveRingToFile() to archive an attack the user
    // just watched happen. A pause that left tshark running would let the
    // very evidence the user paused to keep get overwritten underneath them.
    //
    // Both are synchronous and fast (a process kill plus a join on a thread
    // that unblocks the moment the pipe breaks) -- safe to call from the
    // render thread. Serialized internally, so a double-click is a no-op.
    void PauseCapture();
    void ResumeCapture();
    bool IsCapturePaused() const;

    // (B11) Result of archiving the ring buffer. `merged_files` is how many
    // capture_ring pcapng files went into the output, so the UI can say
    // "7 dosya birlestirildi" rather than a bare success/failure.
    struct RingSaveResult {
        bool ok = false;
        int merged_files = 0;
        std::string error; // human-readable (Turkish), empty when ok
    };

    // Merges every capture_ring pcapng currently on disk into one standalone
    // pcapng at out_path via mergecap -- the same tool ExtractAlertsToFile
    // already uses. Blocking (mergecap over a full ~500MB ring takes seconds)
    // -- call from a background thread, never the render thread.
    //
    // Intended to be used right after PauseCapture(): with tshark stopped the
    // ring is a stable, complete record of the session's last ~500MB. Calling
    // it while capture is still running still works, but the newest ring file
    // is being appended to concurrently, so its tail may be short.
    RingSaveResult SaveRingToFile(const std::wstring& out_path);

    // (B3) Result of searching the raw capture_ring pcapng files (written by
    // live_wireshark_producer.py, see its B1 comment) for one packet.
    // frame.number resets at every ring-file rotation (empirically verified
    // -- it is NOT a globally unique key across the whole session), so
    // lookup narrows to the ring file active at capture_ts first and only
    // then applies the frame.number display filter within that one file;
    // src_ip/dst_ip further guard against a coincidental same-number match
    // in the wrong file.
    struct PacketLookupResult {
        bool found = false;
        std::string detail_text;   // tshark -V -x output for this one packet
        std::wstring source_file;  // which ring file it was found in
    };

    // Blocking (runs tshark synchronously) -- call from a background thread,
    // never the render thread. frame_number/capture_ts/src_ip/dst_ip come
    // from the Alert this lookup is for (see pipeline_orchestrator.h::Alert).
    PacketLookupResult LookupPacket(const std::string& frame_number, double capture_ts,
                                     const std::string& src_ip, const std::string& dst_ip);

    // Extracts the single matching packet into out_path as a standalone
    // pcapng (for the Download button). Blocking, same threading rule as
    // LookupPacket. Returns false if the packet can no longer be located
    // (e.g. it rotated out of the ring) or tshark failed.
    bool ExtractPacketToFile(const std::string& frame_number, double capture_ts,
                              const std::string& src_ip, const std::string& dst_ip,
                              const std::wstring& out_path);

    // (B5) Result of a bulk export -- "found" may be less than "total" if some
    // alerts predate B2 (no frame_number) or their packet already rotated out
    // of the ring, so the UI can report "38/50 paket kaydedildi" rather than a
    // bare pass/fail.
    struct BulkDownloadResult {
        int total = 0;
        int found = 0;
    };

    // Extracts every alert's matching packet (same per-packet lookup as
    // ExtractPacketToFile) and merges them into a single standalone pcapng at
    // out_path -- backs the "Download All" button on the alerts table header.
    // Blocking (runs tshark/mergecap synchronously, once per alert plus one
    // merge pass) -- call from a background thread, never the render thread.
    BulkDownloadResult ExtractAlertsToFile(const std::vector<Alert>& alerts,
                                            const std::wstring& out_path);

private:
    struct Impl;
    Impl* impl_;
};
