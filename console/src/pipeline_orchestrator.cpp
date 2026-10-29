#include "pipeline_orchestrator.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

using json = nlohmann::json;

namespace {

double NowEpoch() {
    using namespace std::chrono;
    return duration<double>(system_clock::now().time_since_epoch()).count();
}

// json::value(key, fallback) only substitutes fallback when the key is
// ABSENT -- if the key is present but JSON null (every nullable field here,
// e.g. alert_source/predicted_class on a BENIGN packet), .get<T>() on it
// throws and the *entire* OnEvent() call aborts before reaching the
// counters below (silently, since ReaderLoop wraps event handling in
// catch(...)). This mirrors the getOr() helper the now-removed
// api_client.cpp used for exactly the same reason.
template <typename T>
T GetOr(const json& j, const char* key, T fallback) {
    if (!j.contains(key) || j.at(key).is_null()) return fallback;
    try {
        return j.at(key).get<T>();
    } catch (...) {
        return fallback;
    }
}

// (R27/O1) int specialization: process_pcap_multiclass.py's _emit_prediction
// used to send dst_port as a raw tshark STRING ("443") -- the generic
// get<int>() throws type_error.302 on that, silently falling back to 0 while
// the caller still treats the field as present, so every multiclass alert
// showed ":0" in the port column (the Python side is now fixed to send an
// int too, but this stays as defense-in-depth against the same class of bug
// recurring for any future numeric-field producer). Falls back to parsing a
// numeric string before giving up.
template <>
int GetOr<int>(const json& j, const char* key, int fallback) {
    if (!j.contains(key) || j.at(key).is_null()) return fallback;
    const json& v = j.at(key);
    try {
        return v.get<int>();
    } catch (...) {
        if (v.is_string()) {
            try {
                return std::stoi(v.get<std::string>());
            } catch (...) {
            }
        }
        return fallback;
    }
}

std::string FormatHms(double epoch_seconds) {
    std::time_t t = static_cast<std::time_t>(epoch_seconds);
    std::tm tmv{};
    localtime_s(&tmv, &t);
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
    return buf;
}

// Mirrors mongo_logger.py/_severity_from_score's bucketing (see theme.cpp's
// SeverityColor for the CRITICAL -> deep red, HIGH -> red, MEDIUM -> amber,
// INFO -> violet mapping this feeds into).
//
// CRITICAL is MECHANISM-BASED, not a higher score band: it requires a
// deterministic volumetric signature (SYN-flood / connection-flood /
// multi-port scan -> is_volumetric) AND a score at or above the HIGH floor.
// A volumetric-but-weak signature stays HIGH/MEDIUM, and a high-scoring
// single behavioural flow stays HIGH -- both conditions are needed.
//
// These constants previously diverged from the Python side (0.8/0.6/0.4 here
// vs 0.7/alert_threshold there), so the same packet could be badged
// differently in the live UI and in Mongo. They now match
// mongo_logger.py::HIGH_SEVERITY_SCORE / ALERT_THRESHOLD.
constexpr double kHighSeverityScore = 0.7;
constexpr double kAlertThreshold = 0.4;

std::string SeverityFromScore(double score, bool is_unknown, bool is_volumetric) {
    if (is_unknown) return "INFO";
    if (score >= kHighSeverityScore) return is_volumetric ? "CRITICAL" : "HIGH";
    if (score >= kAlertThreshold) return "MEDIUM";
    return "LOW";
}

struct PipeEnds {
    HANDLE read = nullptr;
    HANDLE write = nullptr;
};

bool MakeInheritablePipe(PipeEnds& p) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    return CreatePipe(&p.read, &p.write, &sa, 0) != 0;
}

HANDLE OpenNul(bool forWrite) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    return CreateFileW(L"NUL", forWrite ? GENERIC_WRITE : GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
}

// Every child's stderr (all of the existing human-readable print() logging,
// see process_pcap.py's sys.stdout = sys.stderr redirect trick) goes to a
// log file rather than an unread pipe -- these scripts print several lines
// PER PACKET, so an undrained pipe would fill its OS buffer within seconds
// and silently block the child's detection loop.
HANDLE OpenLogFile(const std::wstring& path) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    return CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, &sa,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
}

// (B3) Path to the raw ring-buffer files written by live_wireshark_producer.py
// (see its B1 comment) -- same tshark.exe the Python side already uses.
// Override with the TSHARK environment variable (same variable the Python
// producer and the training repo use) if Wireshark lives elsewhere.
std::wstring ResolveTsharkPath() {
    wchar_t buf[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"TSHARK", buf, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return std::wstring(buf, n);
    return L"C:\\Program Files\\Wireshark\\tshark.exe";
}
const std::wstring kTsharkPath = ResolveTsharkPath();
// (B5) Ships alongside tshark.exe in every standard Wireshark install -- used
// by ExtractAlertsToFile to combine multiple single-packet pcapng files (one
// per alert) into one standalone capture for the "Download All" button.
// mergecap.exe sits next to tshark.exe in the same Wireshark folder.
std::wstring ResolveMergecapPath() {
    size_t slash = kTsharkPath.find_last_of(L"\\/");
    std::wstring dir = (slash != std::wstring::npos) ? kTsharkPath.substr(0, slash + 1) : L"";
    return dir + L"mergecap.exe";
}
const std::wstring kMergecapPath = ResolveMergecapPath();

struct RingFile {
    std::wstring path;
    double start_ts = 0.0; // parsed from the "..._YYYYMMDDHHMMSS.pcapng" suffix, local time
};

// Ring filenames are "cap_<seq>_<YYYYMMDDHHMMSS>.pcapng" (tshark's own
// auto-naming for -w base + -b ring-buffer options).
bool ParseRingFileStartTs(const std::wstring& filename, double& out_epoch) {
    size_t dot = filename.rfind(L".pcapng");
    if (dot == std::wstring::npos) return false;
    size_t us = filename.rfind(L'_', dot);
    if (us == std::wstring::npos) return false;
    std::wstring ts = filename.substr(us + 1, dot - us - 1);
    if (ts.size() != 14) return false;
    try {
        std::tm tmv{};
        tmv.tm_year = std::stoi(ts.substr(0, 4)) - 1900;
        tmv.tm_mon = std::stoi(ts.substr(4, 2)) - 1;
        tmv.tm_mday = std::stoi(ts.substr(6, 2));
        tmv.tm_hour = std::stoi(ts.substr(8, 2));
        tmv.tm_min = std::stoi(ts.substr(10, 2));
        tmv.tm_sec = std::stoi(ts.substr(12, 2));
        tmv.tm_isdst = -1;
        std::time_t t = std::mktime(&tmv); // local time, matches FormatHms/localtime_s elsewhere here
        if (t == -1) return false;
        out_epoch = static_cast<double>(t);
        return true;
    } catch (...) {
        return false;
    }
}

std::vector<RingFile> ListRingFiles(const std::wstring& ring_dir) {
    std::vector<RingFile> files;
    WIN32_FIND_DATAW fd;
    std::wstring pattern = ring_dir + L"\\cap_*.pcapng";
    HANDLE h = FindFirstFileW(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return files;
    do {
        double ts;
        if (ParseRingFileStartTs(fd.cFileName, ts))
            files.push_back({ring_dir + L"\\" + fd.cFileName, ts});
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(files.begin(), files.end(),
              [](const RingFile& a, const RingFile& b) { return a.start_ts < b.start_ts; });
    return files;
}

// The ring file active at capture_ts, plus its immediate neighbours -- a
// small safety margin against off-by-one at a rotation boundary (rotation
// granularity here is coarser than the filename's whole-second timestamp).
std::vector<RingFile> CandidateRingFiles(const std::vector<RingFile>& all, double capture_ts) {
    std::vector<RingFile> out;
    if (all.empty()) return out;
    int best = 0;
    for (int i = 0; i < (int)all.size(); ++i)
        if (all[i].start_ts <= capture_ts) best = i;
    out.push_back(all[best]);
    if (best + 1 < (int)all.size()) out.push_back(all[best + 1]);
    if (best - 1 >= 0) out.push_back(all[best - 1]);
    return out;
}

std::string BuildDisplayFilter(const std::string& frame_number, const std::string& src_ip,
                                const std::string& dst_ip) {
    std::string f = "frame.number==" + frame_number;
    // ip.addr matches either direction, so one clause per address is enough
    // (guards against a coincidental same-number match in the wrong file --
    // see PacketLookupResult's comment in the header).
    if (!src_ip.empty()) f += " && ip.addr==" + src_ip;
    if (!dst_ip.empty()) f += " && ip.addr==" + dst_ip;
    return f;
}

// Ascii-only strings (digits/dots/operators) -- safe to widen without a
// codepage-aware conversion.
std::wstring WidenAscii(const std::string& s) { return std::wstring(s.begin(), s.end()); }

bool LaunchProcess(const std::wstring& cmdline, const std::wstring& cwd,
                    HANDLE hIn, HANDLE hOut, HANDLE hErr, PROCESS_INFORMATION& pi) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdInput = hIn;
    si.hStdOutput = hOut;
    si.hStdError = hErr;

    // CreateProcessW may write into lpCommandLine -- must be a mutable buffer.
    std::vector<wchar_t> buf(cmdline.begin(), cmdline.end());
    buf.push_back(L'\0');

    return CreateProcessW(nullptr, buf.data(), nullptr, nullptr, /*bInheritHandles=*/TRUE,
                           CREATE_NO_WINDOW, nullptr, cwd.c_str(), &si, &pi) != 0;
}

// Runs a command line to completion and returns everything it wrote to
// stdout. Blocking -- callers run this off the render thread. stdin is /dev/
// null and stderr is discarded, matching how a one-shot tshark -r query
// (as opposed to the long-lived -i capture children) should behave.
std::string RunProcessCaptureStdout(const std::wstring& cmdline) {
    PipeEnds out_pipe;
    if (!MakeInheritablePipe(out_pipe)) return {};
    SetHandleInformation(out_pipe.read, HANDLE_FLAG_INHERIT, 0);
    HANDLE nul_in = OpenNul(false);
    HANDLE nul_err = OpenNul(true);

    PROCESS_INFORMATION pi{};
    bool ok = LaunchProcess(cmdline, L".", nul_in, out_pipe.write, nul_err, pi);
    CloseHandle(out_pipe.write);
    if (nul_in) CloseHandle(nul_in);
    if (nul_err) CloseHandle(nul_err);
    if (!ok) {
        CloseHandle(out_pipe.read);
        return {};
    }

    // (B9) A one-shot query against a ring file can hang tshark itself --
    // observed live: the "Download All" bulk export queries the ring file
    // the LIVE producer is still actively writing to (the newest file is
    // always a CandidateRingFiles() hit for a recent alert), and enough of
    // those queries piling up (up to ~4 tshark launches per alert x 50
    // alerts) froze the whole app hard enough for Windows to kill it
    // (AppHangB1). The ReadFile loop below has no timeout of its own and
    // previously the only bound (WaitForSingleObject 8000) was never even
    // reached if ReadFile itself never returns. This watchdog runs
    // CONCURRENTLY with that loop (not after it) specifically so a large-
    // output child can't deadlock against a full, undrained pipe buffer --
    // killing the child closes its stdout write-end, which is what
    // unblocks ReadFile below with EOF.
    constexpr DWORD kQueryTimeoutMs = 15000;
    std::thread watchdog([&pi]() {
        if (WaitForSingleObject(pi.hProcess, kQueryTimeoutMs) == WAIT_TIMEOUT)
            TerminateProcess(pi.hProcess, 1);
    });

    std::string result;
    char chunk[8192];
    DWORD read = 0;
    while (ReadFile(out_pipe.read, chunk, sizeof(chunk), &read, nullptr) && read > 0)
        result.append(chunk, read);

    watchdog.join();
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(out_pipe.read);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return result;
}

} // namespace

struct PipelineOrchestrator::Impl {
    // Owns the ENTIRE spawned tree (producer's own tshark child included --
    // Windows does not auto-kill descendants of a terminated process) so
    // stop()/destruction can never leak an orphaned live capture.
    HANDLE job = nullptr;

    // (B11) A SECOND job holding only the producer subtree (the python
    // producer plus its tshark child), so PauseCapture can kill exactly that
    // and nothing else. The producer is assigned to this job INSTEAD of the
    // main one -- a process may only be moved between jobs in a nested
    // hierarchy, and one flat job per lifetime-group is simpler than relying
    // on nested-job semantics. The safety guarantee the main job provides is
    // preserved because this job carries the same
    // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE flag (an app crash closes the handle
    // and takes tshark with it) AND StopInternal terminates it explicitly
    // alongside the main job. Recreated on every ResumeCapture, since a
    // terminated job cannot take new processes.
    HANDLE producer_job = nullptr;
    std::atomic<bool> capture_paused{false};
    // Serializes PauseCapture/ResumeCapture against each other so a
    // double-click can't spawn two producers or double-join fanout_thread.
    // Deliberately NOT `mtx` (that one guards `state` and is taken by every
    // reader loop at packet rate -- holding it across a process kill would
    // stall the whole pipeline).
    std::mutex capture_ctl_mtx;

    // (B3) repo_root + "\console\capture_ring" -- set
    // in start(), matches RING_DIR in live_wireshark_producer.py.
    std::wstring ring_dir;

    struct Child {
        PROCESS_INFORMATION pi{};
        HANDLE stdin_write = nullptr;  // parent's end; detectors only
        HANDLE stdout_read = nullptr;  // parent's end
        std::atomic<bool> alive{false};
        std::atomic<double> last_event_ts{0.0};
        // (B7) Detectors only. Set by ReaderLoop when it sees the one-shot
        // {"event":"ready"} control line process_pcap[_multiclass].py writes
        // to its REAL stdout right after model load finishes, BEFORE it
        // blocks reading its first packet from stdin -- see that script's
        // OUTPUT_MODE=="stdout" branch just above its `for packet in
        // _packet_source()` loop. Deliberately separate from `alive` (true
        // within ~1s of spawn, long before the TF/sklearn models are loaded)
        // and from last_event_ts (only sees a REAL prediction, which can't
        // happen until the producer -- deliberately not spawned yet at this
        // point, see ProducerLaunchWatcherLoop -- starts feeding packets).
        std::atomic<bool> model_ready{false};

        // Bounded, drop-oldest write queue (detectors only) -- decouples
        // this child's own processing speed from the producer and from the
        // OTHER detector. Without this, FanoutLoop's WriteFile() writes
        // straight into the (tiny, ~4-64KB) OS pipe buffer: if this child's
        // detection loop can't keep up with real capture rate (a synchronous
        // per-packet TF/Keras inference call easily costs tens of ms), that
        // WriteFile blocks once the buffer fills -- which blocks FanoutLoop
        // entirely, which stops draining the producer's own stdout pipe,
        // which blocks the producer's writes, all the way back to tshark.
        // The whole pipeline stalls in lockstep on whichever child is
        // slowest. A bounded per-child queue lets each detector fall behind
        // independently; dropping the OLDEST entry when full keeps it
        // processing roughly-current traffic (a live dashboard should show
        // "what's happening now", not slowly catch up on a growing backlog
        // of stale packets) instead of drifting further and further behind.
        std::deque<std::string> write_queue;
        std::mutex write_mtx;
        std::condition_variable write_cv;
        std::thread writer_thread;
        static constexpr size_t kMaxQueue = 500;

        // (N1) Count of lines dropped by EnqueueForChild because the queue
        // was already at kMaxQueue. The drop itself is deliberate (see the
        // comment above) but it used to be INVISIBLE -- no counter, no log,
        // no UI indicator -- so a detector could silently miss ~10% of
        // traffic under load while the dashboard still read "UP". This
        // counter only OBSERVES; kMaxQueue and the drop policy are unchanged.
        std::atomic<long long> dropped_count{0};
        // Total lines HANDED to this child's queue (dropped or not). Without
        // this denominator a raw "dropped=6000" is uninterpretable -- it could
        // be 5% or 95% of traffic. Measured live: on a quiet Ethernet segment
        // loss is ~6%, on a busy Wi-Fi segment ~97%, and only the ratio tells
        // those two apart.
        std::atomic<long long> enqueued_count{0};
        // Last value reported to the stderr log (rate-limited, see TickLoop).
        long long last_logged_drops = 0;
    };

    Child producer, multiclass_det;

    std::thread fanout_thread;
    std::thread multiclass_reader_thread;
    std::thread ticker_thread;
    // (B7) SpawnProducer's arguments, stashed by start() so
    // ProducerLaunchWatcherLoop can call it later -- once the detector's
    // model_ready flips true -- instead of start() spawning tshark
    // immediately alongside it. Read-only after start(), so no lock needed
    // for these.
    std::wstring pending_producer_python_exe;
    std::wstring pending_producer_script;
    std::wstring pending_producer_cwd;
    std::wstring pending_producer_interface;
    std::wstring pending_producer_log;
    std::thread producer_launch_thread;
    std::atomic<bool> running{false};
    double start_time = 0.0;
    // (N1) Rate-limit for the queue-loss stderr summary; TickLoop-only.
    double last_drop_log_ts = 0.0;

    std::mutex mtx;
    DashboardState state;

    // Raw rolling event logs (protected by mtx), recomputed into the
    // bucketed DashboardState views on every TickLoop() pass.
    std::deque<std::pair<double, Alert>> alert_log;              // last 24h, oldest first (ATTACK only)
    std::deque<std::pair<double, Alert>> unknown_log;             // last 24h, oldest first (UNKNOWN/OOD only)
    std::deque<std::pair<double, Alert>> traffic_log;             // every scored packet, capped by count (not time)
    std::deque<std::pair<double, std::string>> predicted_events; // last 1h
    std::deque<std::pair<double, std::string>> attacker_events;  // last 1h (ATTACK src_ip)
    std::deque<std::pair<double, int>> port_events;              // last 1h
    std::deque<double> traffic_events;                           // last 3s
    // (A) (timestamp, frame.len bytes) for every line FanoutLoop forwards --
    // pre-drop ingest accounting, trimmed to 60s in TickLoop.
    std::deque<std::pair<double, double>> ingest_log;

    bool SpawnDetector(Child& c, const std::wstring& python_exe, const std::wstring& script,
                        const std::wstring& cwd, const std::wstring& log_path);
    bool SpawnProducer(const std::wstring& python_exe, const std::wstring& script,
                        const std::wstring& cwd, const std::wstring& interface,
                        const std::wstring& log_path);
    void FanoutLoop();
    void EnqueueForChild(Child& c, const std::string& line);
    void WriterLoop(Child& c);
    void ReaderLoop(Child& c);
    void TickLoop();
    void OnEvent(const json& j);
    void StopInternal();
    // (B11) Kills the producer subtree and joins fanout_thread, leaving the
    // Child struct's handles closed and nulled so SpawnProducer can reuse it.
    // Caller must hold capture_ctl_mtx. No-op if no producer is running.
    void StopProducerSubtree();
    // (B7) Waits for the detector's model_ready, then spawns the producer
    // (tshark) and starts fanout_thread -- see the pending_producer_* fields
    // above for why this is deferred out of start() itself.
    void ProducerLaunchWatcherLoop();
};

bool PipelineOrchestrator::Impl::SpawnDetector(Child& c, const std::wstring& python_exe,
                                                const std::wstring& script, const std::wstring& cwd,
                                                const std::wstring& log_path) {
    PipeEnds stdin_pipe, stdout_pipe;
    if (!MakeInheritablePipe(stdin_pipe) || !MakeInheritablePipe(stdout_pipe)) return false;
    // Parent keeps stdin's write end and stdout's read end -- those must NOT
    // be inherited by the child (only the ends handed to STARTUPINFO should be).
    SetHandleInformation(stdin_pipe.write, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(stdout_pipe.read, HANDLE_FLAG_INHERIT, 0);

    HANDLE err_log = OpenLogFile(log_path);
    std::wstring cmdline = L"\"" + python_exe + L"\" \"" + script + L"\"";

    PROCESS_INFORMATION pi{};
    bool ok = LaunchProcess(cmdline, cwd, stdin_pipe.read, stdout_pipe.write, err_log, pi);

    // The child holds its own inherited duplicates now; the parent's copies
    // of the ends it doesn't use must be closed (closing stdout_pipe.write
    // here is what lets ReadFile on stdout_pipe.read see EOF once the child
    // exits -- if the parent kept it open, EOF would never arrive).
    CloseHandle(stdin_pipe.read);
    CloseHandle(stdout_pipe.write);
    if (err_log) CloseHandle(err_log);

    if (!ok) {
        CloseHandle(stdin_pipe.write);
        CloseHandle(stdout_pipe.read);
        return false;
    }

    if (job) AssignProcessToJobObject(job, pi.hProcess);

    c.pi = pi;
    c.stdin_write = stdin_pipe.write;
    c.stdout_read = stdout_pipe.read;
    c.alive.store(true);
    return true;
}

bool PipelineOrchestrator::Impl::SpawnProducer(const std::wstring& python_exe, const std::wstring& script,
                                                const std::wstring& cwd, const std::wstring& interface,
                                                const std::wstring& log_path) {
    PipeEnds stdout_pipe;
    if (!MakeInheritablePipe(stdout_pipe)) return false;
    SetHandleInformation(stdout_pipe.read, HANDLE_FLAG_INHERIT, 0);

    // (B11) Fresh job per producer generation -- TerminateJobObject leaves a
    // job permanently unable to accept new processes, so PauseCapture's kill
    // means the next ResumeCapture needs a new one. Created here rather than
    // in start() so both the first launch and every resume take one path.
    if (producer_job) {
        CloseHandle(producer_job);
        producer_job = nullptr;
    }
    producer_job = CreateJobObjectW(nullptr, nullptr);
    if (producer_job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jinfo{};
        jinfo.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(producer_job, JobObjectExtendedLimitInformation, &jinfo, sizeof(jinfo));
    }

    HANDLE nul_in = OpenNul(false);
    HANDLE err_log = OpenLogFile(log_path);
    std::wstring cmdline = L"\"" + python_exe + L"\" \"" + script + L"\" --interface \"" +
                            interface + L"\" --sink stdout";

    PROCESS_INFORMATION pi{};
    bool ok = LaunchProcess(cmdline, cwd, nul_in, stdout_pipe.write, err_log, pi);

    CloseHandle(stdout_pipe.write);
    if (nul_in) CloseHandle(nul_in);
    if (err_log) CloseHandle(err_log);

    if (!ok) {
        CloseHandle(stdout_pipe.read);
        return false;
    }

    // (B11) producer_job, NOT the shared `job` -- see Impl::producer_job.
    // Falls back to the shared job if job creation failed, which keeps the
    // no-orphaned-tshark guarantee at the cost of pause/resume (PauseCapture
    // refuses rather than killing the detectors too).
    if (producer_job) AssignProcessToJobObject(producer_job, pi.hProcess);
    else if (job) AssignProcessToJobObject(job, pi.hProcess);

    producer.pi = pi;
    producer.stdout_read = stdout_pipe.read;
    producer.alive.store(true);
    return true;
}

// (B11) Shared by PauseCapture and StopInternal. Terminating the job breaks
// the producer's stdout pipe, which makes FanoutLoop's blocking ReadFile
// return immediately -- that is what makes the join below bounded rather than
// a potential deadlock (same reasoning as StopInternal's terminate-then-join
// ordering, see its (R27/O7) comment).
void PipelineOrchestrator::Impl::StopProducerSubtree() {
    if (producer_job) TerminateJobObject(producer_job, 0);
    else if (producer.pi.hProcess) TerminateProcess(producer.pi.hProcess, 0);

    // Joined WITHOUT holding mtx: FanoutLoop takes mtx itself for its ingest
    // accounting, so joining under that lock would deadlock.
    if (fanout_thread.joinable()) fanout_thread.join();

    producer.alive.store(false);
    // TickLoop calls GetExitCodeProcess(producer.pi.hProcess) while holding
    // mtx (its stillActive() health check), so closing and nulling these
    // handles must happen under the same lock -- otherwise the ticker can be
    // mid-call on a handle this thread just closed. StopInternal doesn't need
    // this because it joins ticker_thread before its own closeAll().
    std::lock_guard<std::mutex> lock(mtx);
    if (producer.stdout_read) {
        CloseHandle(producer.stdout_read);
        producer.stdout_read = nullptr;
    }
    if (producer.pi.hProcess) {
        CloseHandle(producer.pi.hProcess);
        producer.pi.hProcess = nullptr;
    }
    if (producer.pi.hThread) {
        CloseHandle(producer.pi.hThread);
        producer.pi.hThread = nullptr;
    }
}

void PipelineOrchestrator::Impl::EnqueueForChild(Child& c, const std::string& line) {
    std::lock_guard<std::mutex> lock(c.write_mtx);
    // (N1) Denominator first: every line offered to this child counts, so the
    // UI/log can report a LOSS RATE rather than a bare cumulative number.
    c.enqueued_count.fetch_add(1, std::memory_order_relaxed);
    // Drop the OLDEST queued line, not the newest, when a detector can't
    // keep up -- keeps it working on roughly-current traffic instead of an
    // ever-growing backlog of stale packets (see Child::write_queue comment).
    if (c.write_queue.size() >= Child::kMaxQueue) {
        c.write_queue.pop_front();
        // (N1) Record the loss. Relaxed is enough: this is a monotonic
        // statistic read by TickLoop/UI, never a synchronization point.
        c.dropped_count.fetch_add(1, std::memory_order_relaxed);
    }
    c.write_queue.push_back(line);
    c.write_cv.notify_one();
}

void PipelineOrchestrator::Impl::WriterLoop(Child& c) {
    while (true) {
        std::string line;
        {
            std::unique_lock<std::mutex> lock(c.write_mtx);
            c.write_cv.wait(lock, [&] { return !c.write_queue.empty() || !running.load(std::memory_order_relaxed); });
            if (c.write_queue.empty()) break; // predicate satisfied via running==false -- nothing left to flush
            line = std::move(c.write_queue.front());
            c.write_queue.pop_front();
        }
        if (c.stdin_write) {
            DWORD written = 0;
            if (!WriteFile(c.stdin_write, line.data(), (DWORD)line.size(), &written, nullptr))
                break; // pipe broken -- child exited
        }
    }
    // (R27/O7 fix) Close our end of stdin from THIS (the writing) thread,
    // right as it's about to exit -- delivers EOF to the child's
    // `for packet in _packet_source():` stdin loop (graceful shutdown).
    // Moved here from StopInternal so no other thread ever closes this
    // handle while a WriteFile above might still be in flight (that used
    // to be safe only because StopInternal previously joined this thread
    // first -- which is exactly the ordering that could hang forever if a
    // child stopped reading its stdin; see StopInternal's comment).
    if (c.stdin_write) {
        CloseHandle(c.stdin_write);
        c.stdin_write = nullptr;
    }
}

void PipelineOrchestrator::Impl::FanoutLoop() {
    // Replaces Kafka's topic fan-out: every JSON packet line the producer
    // writes is queued for the detector (see EnqueueForChild/WriterLoop --
    // the detector drains its own queue on its own thread, so a slow
    // detector can never block this loop or the producer).
    std::string buf;
    char chunk[4096];
    while (true) {
        DWORD read = 0;
        BOOL ok = ReadFile(producer.stdout_read, chunk, sizeof(chunk), &read, nullptr);
        if (!ok || read == 0) {
            producer.alive.store(false);
            break;
        }
        buf.append(chunk, read);
        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, pos + 1); // keep trailing '\n'
            buf.erase(0, pos + 1);
            double now = NowEpoch();
            producer.last_event_ts.store(now);

            // (A) Ingest-tier accounting -- BEFORE the detector's queue gets
            // a chance to drop this line, so it measures what tshark
            // actually delivered, not what got analysed. frame.len arrives
            // as a raw tshark CSV string (or JSON null if the field was
            // empty), never a JSON number, since the producer forwards
            // tshark's fields verbatim (see live_wireshark_producer.py).
            try {
                json pj = json::parse(line);
                double len = 0.0;
                if (pj.contains("frame.len") && !pj.at("frame.len").is_null())
                    len = std::stod(pj.at("frame.len").get<std::string>());
                std::lock_guard<std::mutex> lock(mtx);
                ingest_log.push_back({now, len});
            } catch (...) {
                // Malformed producer line -- skip ingest accounting for it;
                // it's still forwarded below as-is (detectors tolerate bad
                // lines independently).
            }

            EnqueueForChild(multiclass_det, line);
        }
    }
}

void PipelineOrchestrator::Impl::ReaderLoop(Child& c) {
    std::string buf;
    char chunk[4096];
    while (true) {
        DWORD read = 0;
        BOOL ok = ReadFile(c.stdout_read, chunk, sizeof(chunk), &read, nullptr);
        if (!ok || read == 0) {
            c.alive.store(false);
            break;
        }
        buf.append(chunk, read);
        size_t pos;
        while ((pos = buf.find('\n')) != std::string::npos) {
            std::string line = buf.substr(0, pos);
            buf.erase(0, pos + 1);
            if (line.empty()) continue;
            try {
                json j = json::parse(line);
                // (B7) One-shot control message, not a prediction -- see
                // Child::model_ready's comment. Deliberately does NOT touch
                // last_event_ts (that must only reflect a REAL processed
                // packet) and never reaches OnEvent (which would otherwise
                // record a bogus all-defaults BENIGN row from GetOr's
                // fallbacks).
                if (j.is_object() && j.value("event", std::string()) == "ready") {
                    c.model_ready.store(true);
                    continue;
                }
                c.last_event_ts.store(NowEpoch());
                OnEvent(j);
            } catch (...) {
                // Malformed/partial line -- skip (mirrors _packet_source's tolerance
                // for bad JSON on the Python side).
            }
        }
    }
}

void PipelineOrchestrator::Impl::OnEvent(const json& j) {
    double ts = GetOr<double>(j, "ts", NowEpoch());
    std::string status = GetOr<std::string>(j, "status", "BENIGN");
    double risk = GetOr<double>(j, "risk_score", 0.0);
    std::string attack_name = GetOr<std::string>(j, "detected_attack_name", "");
    std::string predicted_class = GetOr<std::string>(j, "predicted_class", "");
    std::string alert_source = GetOr<std::string>(j, "alert_source", "");
    std::string src_ip = GetOr<std::string>(j, "src_ip", "");
    std::string dst_ip = GetOr<std::string>(j, "dst_ip", "");
    int dst_port = GetOr<int>(j, "dst_port", 0);
    bool has_port = j.contains("dst_port") && !j.at("dst_port").is_null();
    bool is_unknown = (status == "UNKNOWN");
    bool is_attack = (status == "ATTACK");
    // _emit_prediction() always includes this; absent -> false, which simply
    // keeps the old HIGH badge rather than inventing a CRITICAL.
    bool is_volumetric = GetOr<bool>(j, "is_volumetric", false);

    Alert a;
    a.timestamp = FormatHms(ts);
    a.status = status;
    a.score = risk;
    a.attack_type = attack_name;
    a.predicted_class = predicted_class;
    a.alert_source = alert_source;
    a.severity = SeverityFromScore(risk, is_unknown, is_volumetric);
    a.src_ip = src_ip;
    a.dst_ip = dst_ip;
    a.dst_port = dst_port;
    a.has_dst_port = has_port;
    // (B2) frame_number arrives as a JSON string OR number depending on how
    // tshark emitted it upstream (see live_wireshark_producer.py -- it's
    // whatever CSV token tshark produced, forwarded verbatim); dump() covers
    // both without a throwing get<string>() on a numeric JSON value.
    if (j.contains("frame_number") && !j.at("frame_number").is_null()) {
        const json& fn = j.at("frame_number");
        a.frame_number = fn.is_string() ? fn.get<std::string>() : fn.dump();
    }
    a.capture_ts = ts;

    std::lock_guard<std::mutex> lock(mtx);

    // (B10) Single detector stream now (multiclass only, see this file's top
    // comment) -- it is both the traffic counter AND the class-label source,
    // so what used to be two separate branches (binary counted traffic,
    // multiclass only fed predicted_class_distribution) collapses into one.
    state.stats.total_traffic++;
    if (is_attack) state.stats.attack_count++;
    else if (is_unknown) state.stats.unknown_count++;
    else state.stats.benign_count++;
    traffic_events.push_back(ts);
    if (has_port) port_events.push_back({ts, dst_port});

    // Unfiltered feed for the "LIVE TRAFFIC (ALL)" panel -- every packet,
    // not just alerts. Capped by count (not time) since this is a
    // fast-scrolling raw feed, not an hourly-bucketed summary.
    traffic_log.push_back({ts, a});
    while (traffic_log.size() > 500) traffic_log.pop_front();

    predicted_events.push_back({ts, predicted_class.empty() ? std::string("BENIGN") : predicted_class});

    state.latest_score.score = risk * 100.0;
    state.latest_score.status = status;
    state.latest_score.attack_type = predicted_class.empty() ? attack_name : predicted_class;

    if (is_attack) {
        alert_log.push_back({ts, a});
        attacker_events.push_back({ts, src_ip});
    } else if (is_unknown) {
        unknown_log.push_back({ts, a});
    }
}

void PipelineOrchestrator::Impl::TickLoop() {
    while (running.load(std::memory_order_relaxed)) {
        double now = NowEpoch();
        float elapsed = static_cast<float>(now - start_time);

        auto stillActive = [](PROCESS_INFORMATION& pi) {
            if (!pi.hProcess) return false;
            DWORD code = 0;
            if (!GetExitCodeProcess(pi.hProcess, &code)) return false;
            return code == STILL_ACTIVE;
        };

        {
            std::lock_guard<std::mutex> lock(mtx);

            while (!traffic_events.empty() && traffic_events.front() < now - 3.0) traffic_events.pop_front();
            while (!ingest_log.empty() && ingest_log.front().first < now - 60.0) ingest_log.pop_front();
            while (!predicted_events.empty() && predicted_events.front().first < now - 3600.0) predicted_events.pop_front();
            while (!attacker_events.empty() && attacker_events.front().first < now - 3600.0) attacker_events.pop_front();
            while (!port_events.empty() && port_events.front().first < now - 3600.0) port_events.pop_front();
            while (!alert_log.empty() && alert_log.front().first < now - 86400.0) alert_log.pop_front();
            while (alert_log.size() > 2000) alert_log.pop_front();
            while (!unknown_log.empty() && unknown_log.front().first < now - 86400.0) unknown_log.pop_front();
            while (unknown_log.size() > 2000) unknown_log.pop_front();
            // Hard count caps IN ADDITION to the 1h time trim above -- at
            // sustained real capture rates (tens of packets/sec) the time
            // trim alone lets these grow to tens/hundreds of thousands of
            // entries within an hour, which turns the O(n) grouping below
            // into a growing per-tick cost that eventually exceeds the
            // 250ms tick interval itself (ticks start backing up) and holds
            // this same mutex long enough to visibly stall both the reader
            // threads (packets appear to "arrive late") and the render
            // thread's snapshot() (visible stutter). 1h of events at even
            // 100 pkt/s is only ~360k -- these caps keep the window's
            // *effective* size bounded regardless of traffic rate/runtime.
            while (predicted_events.size() > 20000) predicted_events.pop_front();
            while (attacker_events.size() > 20000) attacker_events.pop_front();
            while (port_events.size() > 20000) port_events.pop_front();

            state.live_traffic_count = static_cast<long long>(traffic_events.size());

            {
                double bytes60 = 0.0;
                for (auto& kv : ingest_log) bytes60 += kv.second;
                state.ingest_packets_60s = static_cast<long long>(ingest_log.size());
                state.ingest_bytes_60s = bytes60;
                state.ingest_mbps = bytes60 * 8.0 / 60.0 / 1e6;
            }

            {
                std::vector<Alert> recent;
                for (auto it = alert_log.rbegin(); it != alert_log.rend() && recent.size() < 50; ++it)
                    recent.push_back(it->second);
                state.recent_alerts = std::move(recent);
            }

            {
                std::vector<Alert> recent_unknown;
                for (auto it = unknown_log.rbegin(); it != unknown_log.rend() && recent_unknown.size() < 50; ++it)
                    recent_unknown.push_back(it->second);
                state.recent_unknown_alerts = std::move(recent_unknown);
            }

            {
                // "LIVE TRAFFIC (ALL)" panel -- unfiltered, newest first.
                std::vector<Alert> feed;
                for (auto it = traffic_log.rbegin(); it != traffic_log.rend() && feed.size() < 100; ++it)
                    feed.push_back(it->second);
                state.live_traffic_feed = std::move(feed);
            }

            {
                std::vector<NamedCount> dist;
                for (auto& kv : predicted_events) {
                    auto it = std::find_if(dist.begin(), dist.end(),
                                            [&](const NamedCount& nc) { return nc.name == kv.second; });
                    if (it == dist.end()) dist.push_back({kv.second, 1});
                    else it->count++;
                }
                std::sort(dist.begin(), dist.end(), [](const NamedCount& a, const NamedCount& b) { return a.count > b.count; });
                state.predicted_class_distribution = std::move(dist);
            }

            {
                std::vector<NamedCount> tops;
                for (auto& kv : attacker_events) {
                    auto it = std::find_if(tops.begin(), tops.end(),
                                            [&](const NamedCount& nc) { return nc.name == kv.second; });
                    if (it == tops.end()) tops.push_back({kv.second, 1});
                    else it->count++;
                }
                std::sort(tops.begin(), tops.end(), [](const NamedCount& a, const NamedCount& b) { return a.count > b.count; });
                if (tops.size() > 10) tops.resize(10);
                TopSources ts;
                for (auto& nc : tops) {
                    ts.ips.push_back(nc.name);
                    ts.counts.push_back(nc.count);
                }
                state.top_sources = std::move(ts);
            }

            {
                std::vector<std::pair<int, long long>> counts;
                for (auto& kv : port_events) {
                    auto it = std::find_if(counts.begin(), counts.end(),
                                            [&](const std::pair<int, long long>& pc) { return pc.first == kv.second; });
                    if (it == counts.end()) counts.push_back({kv.second, 1});
                    else it->second++;
                }
                std::sort(counts.begin(), counts.end(),
                          [](const std::pair<int, long long>& a, const std::pair<int, long long>& b) { return a.second > b.second; });
                if (counts.size() > 10) counts.resize(10);
                PortDistribution pd;
                for (auto& pc : counts) {
                    pd.ports.push_back(std::to_string(pc.first));
                    pd.counts.push_back(pc.second);
                }
                state.port_distribution = std::move(pd);
            }

            {
                SeriesI series;
                series.labels.resize(24);
                series.values.assign(24, 0);
                for (int i = 0; i < 24; ++i) {
                    double bucket_start = now - (23 - i) * 3600.0;
                    std::time_t t = static_cast<std::time_t>(bucket_start);
                    std::tm tmv{};
                    localtime_s(&tmv, &t);
                    char lbuf[8];
                    std::snprintf(lbuf, sizeof(lbuf), "%02d:00", tmv.tm_hour);
                    series.labels[i] = lbuf;
                }
                for (auto& kv : alert_log) {
                    int bucket = static_cast<int>((kv.first - (now - 24 * 3600.0)) / 3600.0);
                    if (bucket >= 0 && bucket < 24) series.values[bucket]++;
                }
                state.alerts_timeline = std::move(series);
            }

            {
                // 250ms sampling cadence -- matches the old HTTP PollerThread's
                // rate, keeps the sparkline motion familiar.
                state.risk_history.push_back(static_cast<float>(state.latest_score.score));
                state.risk_time.push_back(elapsed);
                constexpr float kWindowSeconds = 60.0f;
                size_t cutoff = 0;
                while (cutoff < state.risk_time.size() && state.risk_time[cutoff] < elapsed - kWindowSeconds) ++cutoff;
                if (cutoff > 0) {
                    state.risk_time.erase(state.risk_time.begin(), state.risk_time.begin() + cutoff);
                    state.risk_history.erase(state.risk_history.begin(), state.risk_history.begin() + cutoff);
                }
            }

            state.health.producer.running = producer.alive.load() && stillActive(producer.pi);
            state.health.multiclass_detector.running = multiclass_det.alive.load() && stillActive(multiclass_det.pi);

            double pt = producer.last_event_ts.load();
            double mt = multiclass_det.last_event_ts.load();
            state.health.producer.last_event_age_seconds = pt > 0 ? now - pt : -1.0;
            state.health.multiclass_detector.last_event_age_seconds = mt > 0 ? now - mt : -1.0;

            state.reachable = state.health.producer.running || state.health.multiclass_detector.running;

            // (N1) Surface the detector's queue drops WITH their denominator.
            // The producer has no inbound queue of ours, so its counters stay
            // 0 by construction.
            long long mc_drops = multiclass_det.dropped_count.load(std::memory_order_relaxed);
            long long mc_enq = multiclass_det.enqueued_count.load(std::memory_order_relaxed);
            state.health.producer.dropped_packets = 0;
            state.health.producer.enqueued_packets = 0;
            state.health.multiclass_detector.dropped_packets = mc_drops;
            state.health.multiclass_detector.enqueued_packets = mc_enq;

            // Rate-limited summary. The first version logged on EVERY change,
            // which at a 250ms tick meant a wall of near-identical cumulative
            // lines that read like a crash loop while actually describing
            // steady-state behaviour. Log at most every kDropLogPeriod, and
            // report the INTERVAL delta plus the cumulative loss rate -- the
            // rate is what tells "mild backlog" apart from "detector is blind".
            constexpr double kDropLogPeriod = 10.0;
            bool moved = (mc_drops != multiclass_det.last_logged_drops);
            if (moved && (now - last_drop_log_ts) >= kDropLogPeriod) {
                long long mc_d = mc_drops - multiclass_det.last_logged_drops;
                double mc_pct = mc_enq ? (100.0 * mc_drops / mc_enq) : 0.0;
                std::fprintf(stderr,
                             "[orchestrator] detector input loss (queue full, packet never analysed): "
                             "multiclass +%lld -> %lld/%lld (%.1f%%)\n",
                             mc_d, mc_drops, mc_enq, mc_pct);
                std::fflush(stderr);
                multiclass_det.last_logged_drops = mc_drops;
                last_drop_log_ts = now;
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
}

// (B7) Deliberately doesn't spawn tshark until the detector's TF/sklearn
// models have finished loading (empirically ~30-40s) -- previously the
// producer started immediately alongside the detector, so every packet
// captured during that warm-up queued up (up to Child::kMaxQueue=500) and,
// the instant the detector finished loading, drained in one burst -- from
// the user's chair that looked like "500-odd packets arrive the moment the
// app opens", not a live feed. Capturing nothing until the model can
// actually consume it in real time is the fix, not a bigger queue.
void PipelineOrchestrator::Impl::ProducerLaunchWatcherLoop() {
    while (running.load(std::memory_order_relaxed)) {
        if (multiclass_det.model_ready.load()) break;
        // If the detector dies while loading (missing model files, import
        // error, ...) it will never report model_ready. Without this check
        // the startup screen waited forever on "baslatiliyor...".
        DWORD code = STILL_ACTIVE;
        if (multiclass_det.pi.hProcess &&
            GetExitCodeProcess(multiclass_det.pi.hProcess, &code) && code != STILL_ACTIVE) {
            std::lock_guard<std::mutex> lock(mtx);
            state.reachable = false;
            state.last_error =
                "Detector exited during startup (exit code " + std::to_string(code) +
                ") -- see console\\logs\\multiclass_stderr.log. "
                "Most common cause: model files missing in multiclass_training\\models\\.";
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    if (!running.load(std::memory_order_relaxed)) return; // shut down before models finished loading

    // (B11) The user can hit "Yakalamayi Durdur" during the model warm-up
    // (the startup screen is up, but the toggle is reachable if this window
    // is ever shown earlier). Honour that instead of racing them by starting
    // tshark anyway -- ResumeCapture is what launches the producer then.
    std::lock_guard<std::mutex> ctl(capture_ctl_mtx);
    if (capture_paused.load()) return;

    bool ok = SpawnProducer(pending_producer_python_exe, pending_producer_script, pending_producer_cwd,
                             pending_producer_interface, pending_producer_log);
    if (ok) {
        // (B8) Sync reference point for a side-by-side Wireshark comparison
        // -- see DashboardState::capture_start_wallclock's comment.
        {
            std::lock_guard<std::mutex> lock(mtx);
            state.capture_start_wallclock = FormatHms(NowEpoch());
        }
        fanout_thread = std::thread(&Impl::FanoutLoop, this);
    } else {
        std::lock_guard<std::mutex> lock(mtx);
        state.last_error =
            "Modeller hazir ama paket yakalama (tshark) baslatilamadi -- "
            "logs\\producer_stderr.log kontrol edin.";
    }
}

void PipelineOrchestrator::Impl::StopInternal() {
    if (!running.exchange(false)) return;

    // (B7) Join this FIRST, before TerminateJobObject below. running==false
    // makes the watcher's wait loop exit within ~200ms if it's still waiting
    // on model_ready; if it had already moved past that and is mid-
    // SpawnProducer (CreateProcessW + AssignProcessToJobObject), this join
    // blocks until that finishes -- guaranteeing that IF a producer process
    // gets created here, it is already a job member by the time
    // TerminateJobObject runs, so it's swept up like everything else instead
    // of potentially orphaned. Also required before touching fanout_thread
    // below: this thread is the one that assigns it, so joining first makes
    // that assignment visible instead of racing the joinable() check on it.
    if (producer_launch_thread.joinable()) producer_launch_thread.join();

    // Wake the writer threads so they notice running==false and exit --
    // they drain any lines still queued (WriteFile them) and close their
    // own stdin_write handle (graceful EOF for the child) before returning;
    // see WriterLoop's tail.
    multiclass_det.write_cv.notify_all();

    // Grace period: if the detector notices EOF on stdin (or was already
    // caught up) it should exit cleanly (close Mongo, etc.) within this
    // window. This does NOT wait for the writer thread itself --
    // see the (R27/O7) note below for why that must come later.
    if (multiclass_det.pi.hProcess) WaitForSingleObject(multiclass_det.pi.hProcess, 2000);

    // (R27/O7 fix) TerminateJobObject MUST happen before joining the writer
    // threads below, not after (the old order). If a detector stops reading
    // its stdin (e.g. a hung per-packet inference call that never returns),
    // WriterLoop's WriteFile blocks on a full OS pipe buffer and never
    // notices running==false -- joining that thread first, before anything
    // could ever unblock it, hung the whole app on close indefinitely (the
    // user had to kill it from Task Manager). Terminating the job here
    // kills every process in the tree, which breaks every pipe -- a broken
    // pipe reliably unblocks a pending WriteFile with ERROR_BROKEN_PIPE --
    // so by the time we join below, even a previously-wedged writer thread
    // is guaranteed to finish (and close its own stdin_write) almost
    // immediately, regardless of what the child was doing.
    if (job) TerminateJobObject(job, 0);
    // (B11) The producer lives in its own job now (see Impl::producer_job), so
    // the line above no longer reaches it -- terminate it explicitly, or a
    // live tshark would outlive the app.
    if (producer_job) TerminateJobObject(producer_job, 0);

    if (multiclass_det.writer_thread.joinable()) multiclass_det.writer_thread.join();

    if (fanout_thread.joinable()) fanout_thread.join();
    if (multiclass_reader_thread.joinable()) multiclass_reader_thread.join();
    if (ticker_thread.joinable()) ticker_thread.join();

    auto closeAll = [](Child& c) {
        if (c.stdin_write) CloseHandle(c.stdin_write);  // usually already closed by WriterLoop; nullptr-guarded
        if (c.stdout_read) CloseHandle(c.stdout_read);
        if (c.pi.hProcess) CloseHandle(c.pi.hProcess);
        if (c.pi.hThread) CloseHandle(c.pi.hThread);
    };
    closeAll(producer);
    closeAll(multiclass_det);
}

// ── PipelineOrchestrator ────────────────────────────────────────────────

PipelineOrchestrator::PipelineOrchestrator() : impl_(new Impl()) {}

PipelineOrchestrator::~PipelineOrchestrator() {
    impl_->StopInternal();
    if (impl_->job) CloseHandle(impl_->job);
    if (impl_->producer_job) CloseHandle(impl_->producer_job); // (B11)
    delete impl_;
}

bool PipelineOrchestrator::start(const std::wstring& repo_root, const std::wstring& interface) {
    impl_->start_time = NowEpoch();
    // (B3) Mirrors RING_DIR in live_wireshark_producer.py.
    impl_->ring_dir = repo_root + L"\\console\\capture_ring";

    // Job object: guarantees the entire spawned tree (producer's own tshark
    // child included) dies with this app, even on a crash -- Windows does
    // not otherwise kill descendants of a terminated process.
    impl_->job = CreateJobObjectW(nullptr, nullptr);
    if (impl_->job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION info{};
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(impl_->job, JobObjectExtendedLimitInformation, &info, sizeof(info));
    }

    // Shared by all three children -- harmless for the producer (it's
    // switched to local-IPC mode via --sink stdout on argv, not env), and
    // required by both detectors to opt out of their Kafka/Mongo-only
    // defaults (see process_pcap.py / process_pcap_multiclass.py).
    _wputenv_s(L"INPUT_MODE", L"stdin");
    _wputenv_s(L"OUTPUT_MODE", L"stdout");
    _wputenv_s(L"PYTHONIOENCODING", L"utf-8");
    _wputenv_s(L"PYTHONUNBUFFERED", L"1");
    // (R17) Everything this app captures IS real live capture, so tag the
    // Mongo documents accordingly. Without this the detectors fall back to
    // SOURCE_MODE="unknown" and live rows become indistinguishable from
    // CICIDS file-replay rows sharing the same collection -- exactly the
    // mix-up that once inflated a measured live FAR ~3.5x. Kafka is NOT
    // affected here: under INPUT_MODE=stdin, _packet_source() returns before
    // KafkaConsumer is ever constructed, so the SOURCE_MODE-derived GROUP_ID
    // is computed but never used (verified in process_pcap.py and
    // process_pcap_multiclass.py).
    _wputenv_s(L"SOURCE_MODE", L"live");

    const std::wstring python_exe = L"python";
    const std::wstring pipeline_dir = repo_root + L"\\pipeline";
    const std::wstring multiclass_dir = repo_root + L"\\multiclass_training";
    const std::wstring log_dir = repo_root + L"\\console\\logs";
    CreateDirectoryW(log_dir.c_str(), nullptr);

    // (B7/B10) The detector spawns now; the producer (tshark) is deliberately
    // deferred until it reports model_ready -- see ProducerLaunchWatcherLoop's
    // comment for why. Only the multiclass detector runs live (see this
    // file's top comment for why the binary one, process_pcap.py, was
    // dropped from this app).
    bool ok = true;
    ok = impl_->SpawnDetector(impl_->multiclass_det, python_exe, multiclass_dir + L"\\process_pcap_multiclass.py",
                               multiclass_dir, log_dir + L"\\multiclass_stderr.log") && ok;

    {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->state.reachable = ok;
        if (!ok) {
            impl_->state.last_error =
                "Failed to launch one or more subprocesses -- check logs\\*.log under "
                "console/. Is 'python' on PATH?";
        }
    }
    if (!ok) return false;

    impl_->pending_producer_python_exe = python_exe;
    impl_->pending_producer_script = pipeline_dir + L"\\live_wireshark_producer.py";
    impl_->pending_producer_cwd = pipeline_dir;
    impl_->pending_producer_interface = interface;
    impl_->pending_producer_log = log_dir + L"\\producer_stderr.log";

    impl_->running.store(true);
    impl_->multiclass_det.writer_thread = std::thread(&Impl::WriterLoop, impl_, std::ref(impl_->multiclass_det));
    impl_->multiclass_reader_thread = std::thread(&Impl::ReaderLoop, impl_, std::ref(impl_->multiclass_det));
    impl_->ticker_thread = std::thread(&Impl::TickLoop, impl_);
    impl_->producer_launch_thread = std::thread(&Impl::ProducerLaunchWatcherLoop, impl_);
    return true;
}

void PipelineOrchestrator::stop() {
    impl_->StopInternal();
}

// (B11) See the header for why this kills tshark instead of just muting the
// fanout: the capture_ring is a fixed-size overwriting buffer, and freezing
// it is the whole reason the user reached for a stop button.
void PipelineOrchestrator::PauseCapture() {
    std::lock_guard<std::mutex> ctl(impl_->capture_ctl_mtx);
    if (impl_->capture_paused.load()) return;
    if (!impl_->running.load()) return; // app is shutting down; StopInternal owns the teardown

    impl_->StopProducerSubtree();
    impl_->capture_paused.store(true);

    std::lock_guard<std::mutex> lock(impl_->mtx);
    impl_->state.capture_paused = true;
}

void PipelineOrchestrator::ResumeCapture() {
    std::lock_guard<std::mutex> ctl(impl_->capture_ctl_mtx);
    if (!impl_->capture_paused.load()) return;
    if (!impl_->running.load()) return;

    // A resume that lands before the detector finished loading its models
    // would recreate exactly the burst B7 removed (500 queued packets
    // draining at once the moment the model comes up), so wait it out the
    // same way ProducerLaunchWatcherLoop does -- as a flag check, not a
    // sleep, since this runs on the render thread.
    if (!impl_->multiclass_det.model_ready.load()) {
        std::lock_guard<std::mutex> lock(impl_->mtx);
        impl_->state.last_error = "Model henuz yuklenmedi -- yakalama birazdan tekrar denenebilir.";
        return;
    }

    bool ok = impl_->SpawnProducer(impl_->pending_producer_python_exe, impl_->pending_producer_script,
                                    impl_->pending_producer_cwd, impl_->pending_producer_interface,
                                    impl_->pending_producer_log);
    std::lock_guard<std::mutex> lock(impl_->mtx);
    if (!ok) {
        impl_->state.last_error =
            "Paket yakalama (tshark) yeniden baslatilamadi -- logs\\producer_stderr.log kontrol edin.";
        return;
    }
    // (B8) New capture generation -> new reference point for a side-by-side
    // Wireshark packet-count comparison.
    impl_->state.capture_start_wallclock = FormatHms(NowEpoch());
    impl_->state.last_error.clear();
    impl_->state.capture_paused = false;
    impl_->capture_paused.store(false);
    impl_->fanout_thread = std::thread(&Impl::FanoutLoop, impl_);
}

bool PipelineOrchestrator::IsCapturePaused() const {
    return impl_->capture_paused.load();
}

DashboardState PipelineOrchestrator::snapshot() {
    std::lock_guard<std::mutex> lock(impl_->mtx);
    return impl_->state;
}

PipelineOrchestrator::PacketLookupResult PipelineOrchestrator::LookupPacket(
        const std::string& frame_number, double capture_ts,
        const std::string& src_ip, const std::string& dst_ip) {
    PacketLookupResult result;
    if (frame_number.empty()) return result; // older alert, predates B2 plumbing

    auto all = ListRingFiles(impl_->ring_dir);
    auto candidates = CandidateRingFiles(all, capture_ts);
    std::wstring filter = WidenAscii(BuildDisplayFilter(frame_number, src_ip, dst_ip));

    for (auto& c : candidates) {
        std::wstring cmd = L"\"" + kTsharkPath + L"\" -r \"" + c.path + L"\" -Y \"" +
                            filter + L"\" -V -x";
        std::string out = RunProcessCaptureStdout(cmd);
        // tshark's -V output for a real match starts with "Frame N: ..."; an
        // empty/near-empty string means the filter matched nothing in this file.
        if (out.find("Frame ") != std::string::npos) {
            result.found = true;
            result.detail_text = out;
            result.source_file = c.path;
            return result;
        }
    }
    return result;
}

bool PipelineOrchestrator::ExtractPacketToFile(const std::string& frame_number, double capture_ts,
                                                const std::string& src_ip, const std::string& dst_ip,
                                                const std::wstring& out_path) {
    PacketLookupResult found = LookupPacket(frame_number, capture_ts, src_ip, dst_ip);
    if (!found.found) return false;

    std::wstring filter = WidenAscii(BuildDisplayFilter(frame_number, src_ip, dst_ip));
    std::wstring cmd = L"\"" + kTsharkPath + L"\" -r \"" + found.source_file + L"\" -Y \"" +
                        filter + L"\" -w \"" + out_path + L"\"";
    RunProcessCaptureStdout(cmd); // -w produces no useful stdout; the file itself is the result

    WIN32_FILE_ATTRIBUTE_DATA fad{};
    return GetFileAttributesExW(out_path.c_str(), GetFileExInfoStandard, &fad) &&
           (fad.nFileSizeHigh > 0 || fad.nFileSizeLow > 0);
}

bool FileHasContent(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    return GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &fad) &&
           (fad.nFileSizeHigh > 0 || fad.nFileSizeLow > 0);
}

// (B5) Extracts alerts one at a time into throwaway temp files (same
// find-the-ring-file-then-filter approach as ExtractPacketToFile -- reused
// rather than batched into one big OR'd filter because frame.number is only
// unique WITHIN a ring file, so alerts spanning different files need separate
// tshark invocations anyway), then combines whatever was found into a single
// pcapng with mergecap. Best-effort: an alert whose packet already rotated
// out of the ring is simply skipped, not treated as a hard failure.
PipelineOrchestrator::BulkDownloadResult PipelineOrchestrator::ExtractAlertsToFile(
        const std::vector<Alert>& alerts, const std::wstring& out_path) {
    BulkDownloadResult result;

    wchar_t temp_dir_buf[MAX_PATH];
    DWORD tlen = GetTempPathW(MAX_PATH, temp_dir_buf);
    std::wstring temp_dir = (tlen > 0 && tlen < MAX_PATH) ? std::wstring(temp_dir_buf) : L".\\";
    std::wstring unique_prefix = temp_dir + L"ids_bulk_" + std::to_wstring(GetCurrentProcessId()) + L"_";

    // (B9) Listed ONCE for the whole batch, not once per alert (ExtractPacketToFile's
    // LookupPacket-then-extract path re-lists on every single call).
    auto all_rings = ListRingFiles(impl_->ring_dir);

    std::vector<std::wstring> temp_files;
    int idx = 0;
    for (const auto& a : alerts) {
        if (a.frame_number.empty()) continue; // predates B2 plumbing, no way to locate it
        result.total++;

        // (B9) Deliberately skips LookupPacket's separate -V -x dissection pass
        // (used by the single-packet "Download PCAP" button, where the text
        // dump IS the point) -- here we only need the -w extraction, so trying
        // candidates directly halves the tshark invocations for this batch and
        // drops the expensive verbose-dissection output entirely. This matters
        // because a slow/heavy ring file (tens of thousands of packets under
        // load) times kMaxQueue-many alerts is exactly what previously piled
        // up enough tshark launches to hang the app (see RunProcessCaptureStdout's
        // new watchdog comment for the other half of that fix).
        auto candidates = CandidateRingFiles(all_rings, a.capture_ts);
        std::wstring filter = WidenAscii(BuildDisplayFilter(a.frame_number, a.src_ip, a.dst_ip));
        std::wstring temp_path = unique_prefix + std::to_wstring(idx++) + L".pcapng";

        bool found_this = false;
        for (auto& c : candidates) {
            std::wstring cmd = L"\"" + kTsharkPath + L"\" -r \"" + c.path + L"\" -Y \"" +
                                filter + L"\" -w \"" + temp_path + L"\"";
            RunProcessCaptureStdout(cmd);
            if (FileHasContent(temp_path)) {
                found_this = true;
                break;
            }
        }
        if (found_this) {
            temp_files.push_back(temp_path);
            result.found++;
        }
    }

    if (temp_files.empty()) return result;

    if (temp_files.size() == 1) {
        CopyFileW(temp_files[0].c_str(), out_path.c_str(), FALSE);
    } else {
        std::wstring cmd = L"\"" + kMergecapPath + L"\" -w \"" + out_path + L"\"";
        for (auto& f : temp_files) cmd += L" \"" + f + L"\"";
        RunProcessCaptureStdout(cmd);
    }
    for (auto& f : temp_files) DeleteFileW(f.c_str());

    if (!FileHasContent(out_path)) result.found = 0; // merge/copy itself failed
    return result;
}

// (B11) Archives the WHOLE ring, not a per-alert selection -- the counterpart
// to ExtractAlertsToFile above. That one answers "give me the packets behind
// these rows"; this one answers "the ring is about to eat this session, get
// all of it off disk". Same mergecap invocation shape, minus the per-alert
// tshark filtering pass (nothing is being selected, so nothing needs
// dissecting -- the ring files are already pcapng and merge directly).
PipelineOrchestrator::RingSaveResult PipelineOrchestrator::SaveRingToFile(const std::wstring& out_path) {
    RingSaveResult result;

    auto all = ListRingFiles(impl_->ring_dir);
    if (all.empty()) {
        result.error = "capture_ring bos -- kaydedilecek yakalama dosyasi yok.";
        return result;
    }

    // Only THIS app run's files. capture_ring accumulates across sessions --
    // tshark's -b files:N ring bounds a single tshark process, but every new
    // process (app restart, and every PauseCapture/ResumeCapture cycle) starts
    // a fresh series and leaves the previous one on disk. Measured on this
    // machine: 43 files / 1.8GB present while the live ring itself is only
    // ~500MB. Merging all of them would hand the user gigabytes of unrelated
    // days-old traffic and take minutes, when what they asked for is the
    // attack they just watched. The 60s back-margin absorbs the filename's
    // whole-second timestamp granularity against start_time.
    std::vector<RingFile> files;
    for (const auto& f : all)
        if (f.start_ts >= impl_->start_time - 60.0) files.push_back(f);

    if (files.empty()) {
        result.error = "Bu oturuma ait ring dosyasi yok -- yakalama henuz baslamamis olabilir.";
        return result;
    }

    // ListRingFiles already returns them oldest-first (sorted on the timestamp
    // parsed out of the filename), which is the order mergecap should see so
    // the output reads chronologically. mergecap also sorts by frame
    // timestamp itself, but only across the inputs it is handed -- feeding
    // them in order keeps the two consistent even for files whose clocks
    // straddle a rotation boundary.
    std::wstring cmd = L"\"" + kMergecapPath + L"\" -w \"" + out_path + L"\"";
    for (const auto& f : files) cmd += L" \"" + f.path + L"\"";

    // A full ring is 10 paths of maybe 120 chars -- nowhere near the 32767
    // command-line limit, but bail out loudly rather than silently truncating
    // if RING_FILE_COUNT was raised a lot.
    if (cmd.size() > 30000) {
        result.error = "Cok fazla ring dosyasi -- mergecap komut satiri sinirini asiyor.";
        return result;
    }

    RunProcessCaptureStdout(cmd); // -w writes the file; stdout carries nothing useful

    if (!FileHasContent(out_path)) {
        result.error = "mergecap ciktiyi yazamadi -- Wireshark kurulu mu? (" +
                        std::string(kMergecapPath.begin(), kMergecapPath.end()) + ")";
        return result;
    }
    result.ok = true;
    result.merged_files = static_cast<int>(files.size());
    return result;
}
