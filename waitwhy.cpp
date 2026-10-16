// waitwhy.cpp - "My program is slow but the CPU is idle. What is it waiting for?"
//
// Watches one running Windows process for a few seconds and reports, for each of
// its threads, where it spent time blocked (lock, disk, network, sleep, ...),
// which line of your code it was in, and which thread woke it up again.
//
// How it works:
//   1. Starts the Windows kernel trace session (ETW, "NT Kernel Logger") with
//      context-switch events (a thread stops or starts running on a CPU),
//      ready-thread events (thread A wakes up thread B) and thread events.
//   2. Asks the kernel to record a call stack with every context switch.
//   3. For each thread of the target process, measures every gap between
//      "switched out while waiting" and "switched back in".
//   4. Turns the stack addresses into function names with DbgHelp and the
//      program's .pdb file, groups the waits, and prints a plain-English report.
//
// Build (x64 Developer PowerShell for VS):
//   cl /nologo /EHsc /O2 /Zi /std:c++17 waitwhy.cpp
// Run (Administrator PowerShell, because kernel tracing needs admin rights):
//   .\waitwhy.exe --pid 1234
//   .\waitwhy.exe --name slowapp.exe --seconds 10 --top 8
//   .\waitwhy.exe --name slowapp.exe --seconds 5 --dump-events dump.txt

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
// clang-format off
#include <evntrace.h>
#include <evntcons.h>
#include <tlhelp32.h>
#include <dbghelp.h>
// clang-format on

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "analysis.h"
#include "dump.h"
#include "report.h"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#endif

static_assert(sizeof(void*) == 8, "Build waitwhy as a 64-bit (x64) program.");

#ifndef EVENT_TRACE_FLAG_DISPATCHER
#define EVENT_TRACE_FLAG_DISPATCHER 0x00000800
#endif
#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif
#ifndef PROCESS_TRACE_MODE_RAW_TIMESTAMP
#define PROCESS_TRACE_MODE_RAW_TIMESTAMP 0x00001000
#endif

namespace {

using namespace waitwhy;

// ---------------------------------------------------------------------------
// Constants from the Windows kernel trace format
// ---------------------------------------------------------------------------

const wchar_t kLoggerName[] = L"NT Kernel Logger";

const GUID kSystemTraceControlGuid = {
    0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};
const GUID kThreadGuid = {
    0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
const GUID kStackWalkGuid = {
    0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};

// Event types (opcodes) inside the kernel's Thread event class.
constexpr UCHAR kOpThreadStart = 1;
constexpr UCHAR kOpThreadEnd = 2;
constexpr UCHAR kOpThreadDcStart = 3;  // "already running when the trace started"
constexpr UCHAR kOpCSwitch = 36;
constexpr UCHAR kOpReadyThread = 50;
constexpr UCHAR kOpStackWalk = 32;     // inside the StackWalk class

constexpr int kTraceStackTracingInfo = 3;  // TRACE_INFO_CLASS value

// Exit codes, so that scripts and CI can tell the failures apart.
constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;             // bad arguments, or the program cannot be found
constexpr int kExitTraceUnavailable = 2;  // the kernel trace session could not be started

#pragma pack(push, 1)
struct CSwitchPayload {
  uint32_t newThreadId;
  uint32_t oldThreadId;
  int8_t newThreadPriority;
  int8_t oldThreadPriority;
  uint8_t previousCState;
  int8_t spareByte;
  int8_t oldThreadWaitReason;
  int8_t oldThreadWaitMode;
  int8_t oldThreadState;
  int8_t oldThreadWaitIdealProcessor;
  uint32_t newThreadWaitTime;
  uint32_t reserved;
};
#pragma pack(pop)
static_assert(sizeof(CSwitchPayload) == 24, "CSwitch event layout");

struct ClassicEventId {  // same layout as CLASSIC_EVENT_ID
  GUID eventGuid;
  UCHAR type;
  UCHAR reserved[7];
};

struct SessionProps {
  EVENT_TRACE_PROPERTIES props;
  wchar_t loggerName[64];
};

// ---------------------------------------------------------------------------
// Decoding: kernel events -> typed events for the analysis core (analysis.h)
// ---------------------------------------------------------------------------

Analyzer g_analysis;
std::vector<uint32_t> g_cpuThread(256, kUnknownThread);  // thread currently on each CPU
std::atomic<bool> g_stopRequested{false};
// End of the observation window, set by the main thread when it stops watching; 0 until then
// (W20). Events stamped later are still delivered until the session stops; they are not counted.
std::atomic<uint64_t> g_windowEnd{0};

bool PastWindow(uint64_t ts) {
  const uint64_t end = g_windowEnd.load(std::memory_order_relaxed);
  return end != 0 && ts > end;
}
FILE* g_dump = nullptr;   // --dump-events output; null when not asked for
uint64_t g_dumpLines = 0;

void OnCSwitch(const EVENT_RECORD* ev, uint64_t ts) {
  if (ev->UserDataLength < sizeof(CSwitchPayload)) return;
  CSwitchPayload c;
  std::memcpy(&c, ev->UserData, sizeof c);

  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  if (cpu < g_cpuThread.size()) g_cpuThread[cpu] = c.newThreadId;
  // After the window a thread keeps the state it had at its end: a wait still open then is
  // reported as still waiting. Stacks are still taken, because they arrive late (W14).
  if (PastWindow(ts)) return;

  if (g_dump && (g_analysis.IsTarget(c.oldThreadId) || g_analysis.IsTarget(c.newThreadId))) {
    std::fprintf(g_dump, "CSWITCH ts=%llu cpu=%u old=%u new=%u oldState=%d oldReason=%d\n",
                 static_cast<unsigned long long>(ts), cpu, c.oldThreadId, c.newThreadId,
                 c.oldThreadState, c.oldThreadWaitReason);
    ++g_dumpLines;
  }

  SwitchEvent e;
  e.ts = ts;
  e.oldTid = c.oldThreadId;
  e.newTid = c.newThreadId;
  e.oldState = c.oldThreadState;
  e.oldWaitReason = c.oldThreadWaitReason;
  g_analysis.OnSwitch(e);
}

void OnReadyThread(const EVENT_RECORD* ev) {
  if (ev->UserDataLength < sizeof(uint32_t)) return;
  uint32_t readied;
  std::memcpy(&readied, ev->UserData, sizeof readied);
  if (!g_analysis.IsTarget(readied)) return;
  // Payload: uint32 TThreadId, int8 AdjustReason, int8 AdjustIncrement, int8 Flag, int8 spare.
  const uint8_t flag = ev->UserDataLength >= 7 ? static_cast<const uint8_t*>(ev->UserData)[6] : 0;
  const auto ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);
  if (PastWindow(ts)) return;
  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  ReadyEvent e;
  e.ts = ts;
  e.readiedTid = readied;
  e.byTid = ResolveWaker(flag, ev->EventHeader.ThreadId,
                         cpu < g_cpuThread.size() ? g_cpuThread[cpu] : kUnknownThread);
  if (g_dump) {
    std::fprintf(g_dump, "READY ts=%llu cpu=%u readied=%u headerThread=%u flag=0x%02x by=%u\n",
                 static_cast<unsigned long long>(ts), cpu, readied,
                 static_cast<unsigned>(ev->EventHeader.ThreadId), flag, e.byTid);
    ++g_dumpLines;
  }
  g_analysis.OnReady(e);
}

// Thread start, end and rundown events all begin with uint32 ProcessId, uint32 TThreadId.
void OnThreadEvent(const EVENT_RECORD* ev, ThreadEvent::Kind kind) {
  if (ev->UserDataLength < 2 * sizeof(uint32_t)) return;
  ThreadEvent e;
  e.ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);
  if (PastWindow(e.ts)) return;
  e.kind = kind;
  std::memcpy(&e.pid, ev->UserData, sizeof e.pid);
  std::memcpy(&e.tid, static_cast<const uint8_t*>(ev->UserData) + 4, sizeof e.tid);
  if (g_dump && e.pid == g_analysis.pid) {
    std::fprintf(g_dump, "THREAD ts=%llu kind=%d pid=%u tid=%u\n",
                 static_cast<unsigned long long>(e.ts), static_cast<int>(kind), e.pid, e.tid);
    ++g_dumpLines;
  }
  g_analysis.OnThread(e);
}

void OnStackWalk(const EVENT_RECORD* ev) {
  // Layout: uint64 EventTimeStamp, uint32 StackProcess, uint32 StackThread, then addresses.
  if (ev->UserDataLength < 16) return;
  const auto* p = static_cast<const uint8_t*>(ev->UserData);
  StackEvent e;
  e.ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);
  std::memcpy(&e.eventTs, p, sizeof e.eventTs);
  std::memcpy(&e.tid, p + 12, sizeof e.tid);
  if (!g_analysis.IsTarget(e.tid)) return;
  const size_t ptrSize = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  const size_t frames = (ev->UserDataLength - 16) / ptrSize;

  unsigned long long kernelFrames = 0;
  for (size_t i = 0; i < frames; ++i) {
    uint64_t addr = 0;
    std::memcpy(&addr, p + 16 + i * ptrSize, ptrSize);
    if (addr >= kUserSpaceLimit) {
      ++kernelFrames;
    } else if (addr != 0) {
      e.userFrames.push_back(addr);
    }
  }

  if (g_dump) {
    std::fprintf(g_dump,
                 "STACK ts=%llu eventTs=%llu tid=%u kernelFrames=%llu userFrames=%llu "
                 "firstUser=0x%llx",
                 static_cast<unsigned long long>(e.ts), static_cast<unsigned long long>(e.eventTs),
                 e.tid, kernelFrames, static_cast<unsigned long long>(e.userFrames.size()),
                 static_cast<unsigned long long>(e.userFrames.empty() ? 0 : e.userFrames.front()));
    WriteFrames(g_dump, e.userFrames);
    std::fputc('\n', g_dump);
    ++g_dumpLines;
  }

  g_analysis.OnStack(e);
}

void WINAPI OnEvent(PEVENT_RECORD ev) {
  const EVENT_HEADER& h = ev->EventHeader;
  const UCHAR op = h.EventDescriptor.Opcode;
  if (IsEqualGUID(h.ProviderId, kThreadGuid)) {
    if (op == kOpCSwitch) {
      OnCSwitch(ev, static_cast<uint64_t>(h.TimeStamp.QuadPart));
    } else if (op == kOpReadyThread) {
      OnReadyThread(ev);
    } else if (op == kOpThreadStart) {
      OnThreadEvent(ev, ThreadEvent::Kind::Created);
    } else if (op == kOpThreadDcStart) {
      OnThreadEvent(ev, ThreadEvent::Kind::Existing);
    } else if (op == kOpThreadEnd) {
      OnThreadEvent(ev, ThreadEvent::Kind::Ended);
    }
  } else if (IsEqualGUID(h.ProviderId, kStackWalkGuid) && op == kOpStackWalk) {
    OnStackWalk(ev);
  }
}

// ---------------------------------------------------------------------------
// Kernel trace session
// ---------------------------------------------------------------------------

void FillProps(SessionProps& sp, bool forStart) {
  std::memset(&sp, 0, sizeof sp);
  sp.props.Wnode.BufferSize = sizeof sp;
  sp.props.LoggerNameOffset = offsetof(SessionProps, loggerName);
  if (!forStart) return;
  sp.props.Wnode.Guid = kSystemTraceControlGuid;
  sp.props.Wnode.ClientContext = 1;  // timestamps from QueryPerformanceCounter
  sp.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  sp.props.EnableFlags =
      EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER | EVENT_TRACE_FLAG_THREAD;
  sp.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  sp.props.BufferSize = 256;  // KB per buffer; context switches are very frequent
  sp.props.MinimumBuffers = 128;
  sp.props.MaximumBuffers = 512;
  sp.props.FlushTimer = 1;
}

ULONG StopKernelSession(SessionProps* out = nullptr) {
  SessionProps sp;
  FillProps(sp, false);
  ULONG rc = ControlTraceW(0, kLoggerName, &sp.props, EVENT_TRACE_CONTROL_STOP);
  if (out) *out = sp;
  return rc;
}

ULONG StartKernelSession(TRACEHANDLE* session) {
  SessionProps sp;
  FillProps(sp, true);
  ULONG rc = StartTraceW(session, kLoggerName, &sp.props);
  if (rc == ERROR_ALREADY_EXISTS) {
    std::printf("Note: another tool left the kernel trace session running; stopping it first.\n");
    StopKernelSession();
    FillProps(sp, true);
    rc = StartTraceW(session, kLoggerName, &sp.props);
  }
  return rc;
}

bool EnableContextSwitchStacks(TRACEHANDLE session) {
  using TraceSetInformationFn = ULONG(WINAPI*)(TRACEHANDLE, int, PVOID, ULONG);
  HMODULE advapi = GetModuleHandleW(L"advapi32.dll");
  if (!advapi) advapi = LoadLibraryW(L"advapi32.dll");
  auto fn = advapi ? reinterpret_cast<TraceSetInformationFn>(reinterpret_cast<void*>(
                         GetProcAddress(advapi, "TraceSetInformation")))
                   : nullptr;
  if (!fn) return false;
  ClassicEventId id{};
  id.eventGuid = kThreadGuid;
  id.type = kOpCSwitch;
  return fn(session, kTraceStackTracingInfo, &id, sizeof id) == ERROR_SUCCESS;
}

BOOL WINAPI OnCtrl(DWORD) {
  g_stopRequested = true;
  return TRUE;  // finish cleanly so the kernel session is always stopped
}

// ---------------------------------------------------------------------------
// Process, thread and symbol helpers
// ---------------------------------------------------------------------------

std::string Narrow(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                              nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr,
                      nullptr);
  return s;
}

bool FindProcessByName(const std::wstring& name, uint32_t* pid) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return false;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof pe;
  int matches = 0;
  for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
    if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) {
      if (matches++ == 0) *pid = pe.th32ProcessID;
    }
  }
  CloseHandle(snap);
  if (matches > 1)
    std::printf("Note: %d processes are named %s; watching PID %u. Use --pid to choose.\n",
                matches, Narrow(name).c_str(), *pid);
  return matches > 0;
}

void SnapshotThreads(uint32_t pid) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  THREADENTRY32 te{};
  te.dwSize = sizeof te;
  for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
    if (te.th32OwnerProcessID == pid) g_analysis.targetThreads.insert(te.th32ThreadID);
  }
  CloseHandle(snap);
}

std::string ThreadLabel(uint32_t tid) {
  static std::unordered_map<uint32_t, std::string> cache;
  auto it = cache.find(tid);
  if (it != cache.end()) return it->second;
  std::string label = "Thread " + std::to_string(tid);
  // Its ID may already belong to another thread, so do not look up a name for it.
  if (g_analysis.exitedThreads.count(tid)) return cache[tid] = label + " (exited)";
  using GetDescFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);
  static GetDescFn getDesc = reinterpret_cast<GetDescFn>(reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription")));
  if (getDesc) {
    HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (th) {
      PWSTR desc = nullptr;
      if (SUCCEEDED(getDesc(th, &desc)) && desc) {
        if (desc[0]) label += " (" + Narrow(desc) + ")";
        LocalFree(desc);
      }
      CloseHandle(th);
    }
  }
  cache[tid] = label;
  return label;
}

// Reads the user-mode call stack of a thread that is blocked right now, innermost first, by
// suspending it for the moment the walk takes. `proc` must have DbgHelp initialised.
// Returns false when the thread cannot be opened (it has exited).
bool SnapshotStack(HANDLE proc, uint32_t tid, std::vector<uint64_t>* frames) {
  HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
  if (!th) return false;
  if (SuspendThread(th) != static_cast<DWORD>(-1)) {
    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (GetThreadContext(th, &ctx)) {  // user-mode registers, even while blocked in the kernel
      STACKFRAME64 f{};
      f.AddrPC.Offset = ctx.Rip;
      f.AddrPC.Mode = AddrModeFlat;
      f.AddrStack.Offset = ctx.Rsp;
      f.AddrStack.Mode = AddrModeFlat;
      f.AddrFrame.Offset = ctx.Rbp;
      f.AddrFrame.Mode = AddrModeFlat;
      for (int i = 0; i < 128; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_AMD64, proc, th, &f, &ctx, nullptr,
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr) ||
            f.AddrPC.Offset == 0)
          break;
        frames->push_back(f.AddrPC.Offset);
      }
    }
    ResumeThread(th);
  }
  CloseHandle(th);
  return true;
}

// Threads still blocked when the trace ends, or blocked for the whole window, get one stack
// snapshot each (W7); the analysis decides which ones need it.
void SnapshotThreadsStillBlocked() {
  HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, g_analysis.pid);
  if (!proc) return;
  SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
  if (!SymInitializeW(proc, nullptr, TRUE)) {
    CloseHandle(proc);
    return;
  }
  for (uint32_t tid : g_analysis.targetThreads) {
    if (!g_analysis.NeedsSnapshot(tid)) continue;
    std::vector<uint64_t> frames;
    if (!SnapshotStack(proc, tid, &frames)) continue;  // gone; leave it as never seen
    if (g_dump) {
      std::fprintf(g_dump, "SNAPSHOT tid=%u", tid);
      WriteFrames(g_dump, frames);
      std::fputc('\n', g_dump);
    }
    g_analysis.ApplySnapshot(tid, std::move(frames));
  }
  SymCleanup(proc);
  CloseHandle(proc);
}

class Symbolizer : public SymbolSource {
 public:
  bool Init(uint32_t pid) {
    proc_ = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!proc_) return false;
    wchar_t path[MAX_PATH];
    DWORD len = MAX_PATH;
    if (QueryFullProcessImageNameW(proc_, 0, path, &len)) {
      std::wstring p(path, len);
      size_t slash = p.find_last_of(L"\\/");
      std::wstring file = slash == std::wstring::npos ? p : p.substr(slash + 1);
      size_t dot = file.find_last_of(L'.');
      exeModule_ = Lower(Narrow(dot == std::wstring::npos ? file : file.substr(0, dot)));
      exeFile_ = Narrow(file);
    }
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_LOAD_LINES);
    ok_ = SymInitializeW(proc_, nullptr, TRUE) != FALSE;
    return ok_;
  }
  ~Symbolizer() {
    if (ok_) SymCleanup(proc_);
    if (proc_) CloseHandle(proc_);
  }

  // Returns "module!function", or "module!0x1234" when no name is available.
  const std::string& Name(uint64_t addr) override {
    auto it = names_.find(addr);
    if (it != names_.end()) return it->second;
    std::string module = "?";
    std::string result;
    if (ok_) {
      IMAGEHLP_MODULEW64 mi{};
      mi.SizeOfStruct = sizeof mi;
      if (SymGetModuleInfoW64(proc_, addr, &mi)) module = Narrow(mi.ModuleName);
      alignas(SYMBOL_INFOW) unsigned char buf[sizeof(SYMBOL_INFOW) + 512 * sizeof(wchar_t)] = {};
      auto* si = reinterpret_cast<SYMBOL_INFOW*>(buf);
      si->SizeOfStruct = sizeof(SYMBOL_INFOW);
      si->MaxNameLen = 512;
      DWORD64 disp = 0;
      if (SymFromAddrW(proc_, addr, &disp, si)) result = module + "!" + Narrow(si->Name);
    }
    if (result.empty()) {
      char hex[32];
      std::snprintf(hex, sizeof hex, "!0x%llx", static_cast<unsigned long long>(addr));
      result = module + hex;
    }
    return names_[addr] = result;
  }

  // Lower-case path of the source file the code at `addr` came from, with backslashes;
  // empty when the .pdb has no line information for it.
  const std::string& SourceFile(uint64_t addr) override {
    auto it = files_.find(addr);
    if (it != files_.end()) return it->second;
    std::string file;
    if (ok_) {
      IMAGEHLP_LINEW64 line{};
      line.SizeOfStruct = sizeof line;
      DWORD disp = 0;
      if (SymGetLineFromAddrW64(proc_, addr, &disp, &line) && line.FileName) {
        file = Lower(Narrow(line.FileName));
        std::replace(file.begin(), file.end(), '/', '\\');
      }
    }
    return files_[addr] = file;
  }

  bool IsExeFrame(const std::string& name) const override {
    size_t bang = name.find('!');
    return bang != std::string::npos && Lower(name.substr(0, bang)) == exeModule_;
  }
  const std::string& ExeFile() const { return exeFile_; }

 private:
  HANDLE proc_ = nullptr;
  bool ok_ = false;
  std::string exeModule_;
  std::string exeFile_;
  std::unordered_map<uint64_t, std::string> names_;
  std::unordered_map<uint64_t, std::string> files_;
};

// ---------------------------------------------------------------------------
// Turning stacks into plain English (the rules live in analysis.h)
// ---------------------------------------------------------------------------

// Ends a dump with every name the report uses (W18), so the report can be rebuilt from the
// dump alone: the program's file, each address in a wait's stack, and the thread labels.
void WriteDumpNames(FILE* out, Symbolizer& sym, bool symbolsOk) {
  const Analyzer& an = g_analysis;
  std::fprintf(out, "NAMES symbolsOk=%d\n", symbolsOk ? 1 : 0);
  if (!sym.ExeFile().empty()) std::fprintf(out, "EXE name=%s\n", sym.ExeFile().c_str());
  std::map<uint64_t, bool> addrs;  // sorted, so dumps of the same run compare equal
  for (const auto& [key, b] : an.buckets)
    for (uint64_t a : b.stack) addrs[a] = true;
  for (const auto& [addr, unused] : addrs) {
    (void)unused;
    std::fprintf(out, "SYMBOL addr=0x%llx name=%s\n", static_cast<unsigned long long>(addr),
                 sym.Name(addr).c_str());
    const std::string& file = sym.SourceFile(addr);
    if (!file.empty())
      std::fprintf(out, "SOURCE addr=0x%llx file=%s\n", static_cast<unsigned long long>(addr),
                   file.c_str());
  }
  std::map<uint32_t, bool> tids;
  for (const auto& [tid, st] : an.threads) tids[tid] = true;
  for (uint32_t tid : an.targetThreads) tids[tid] = true;
  for (uint32_t tid : an.exitedThreads) tids[tid] = true;
  for (const auto& [tid, unused] : tids) {
    (void)unused;
    std::fprintf(out, "THREADNAME tid=%u name=%s\n", tid, ThreadLabel(tid).c_str());
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

void PrintReport(double ticksPerSecond, int topN, double minMs, const SessionProps& stopped,
                 bool stacksOn, Symbolizer& sym, bool symbolsOk) {
  ReportOptions opt;
  opt.ticksPerSecond = ticksPerSecond;
  opt.topN = static_cast<size_t>(topN);
  opt.minMs = minMs;
  opt.eventsLost = stopped.props.EventsLost;
  opt.buffersLost = stopped.props.RealTimeBuffersLost;
  opt.stacksOn = stacksOn;
  opt.symbolsOk = symbolsOk;
  opt.exeFile = sym.ExeFile();
  const Report report = BuildReport(g_analysis, sym, opt, ThreadLabel);
  std::fputs(RenderText(report).c_str(), stdout);
}

// Rebuilds the report from a version 2 dump (W18, W19), with no kernel trace and without the
// program: everything it needs, including the names, is in the dump.
int ReportFromDump(const std::wstring& path, int topN, double minMs) {
  std::ifstream in(std::filesystem::path(path), std::ios::binary);
  const std::vector<DumpLine> lines = ReadDump(in);
  if (lines.empty()) {
    std::printf("Cannot read an event dump from %s.\n", Narrow(path).c_str());
    return kExitUsage;
  }
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  if (info.version < 2)
    std::printf("Note: %s is a version 1 dump, which holds no function or thread names.\n",
                Narrow(path).c_str());
  DumpSymbols sym(lines);
  ReportOptions opt;
  opt.ticksPerSecond = info.ticksPerSecond > 0 ? info.ticksPerSecond : 1e7;
  opt.topN = static_cast<size_t>(topN);
  opt.minMs = minMs;
  opt.eventsLost = info.eventsLost;
  opt.buffersLost = info.buffersLost;
  opt.stacksOn = info.stacksOn;
  opt.symbolsOk = info.symbolsOk;
  opt.exeFile = info.exeFile;
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  std::printf("Report rebuilt from %s.\n", Narrow(path).c_str());
  std::fputs(RenderText(BuildReport(an, sym, opt, name)).c_str(), stdout);
  return kExitOk;
}

void Usage() {
  std::printf(
      "usage: waitwhy (--pid N | --name program.exe) [--seconds N] [--top N]\n"
      "               [--min-ms N] [--dump-events FILE]\n"
      "       waitwhy --from-dump FILE [--top N] [--min-ms N]\n"
      "  Watches a running program and reports what its threads were waiting on.\n"
      "  --dump-events also writes every context-switch, ready-thread, thread and stack\n"
      "  event of the program's threads to FILE, one line each, in the order they\n"
      "  arrived, then the names the report uses. Must be run as Administrator.\n"
      "  --from-dump prints the report again from such a FILE, on any machine.\n"
      "  --top N shows the N biggest groups of waits (default 6); --min-ms N hides\n"
      "  groups smaller than N milliseconds (default 10).\n"
      "  Exit codes: 0 report printed, 1 bad arguments or program not found,\n"
      "  2 the kernel trace could not be started (not Administrator, or unavailable).\n");
}

}  // namespace

// tests/replay_events.cpp includes this file to drive the event handlers with recorded
// events, and brings its own main.
#ifndef WAITWHY_NO_MAIN
int wmain(int argc, wchar_t** argv) {
  SetConsoleOutputCP(CP_UTF8);
  uint32_t& pid = g_analysis.pid;
  std::wstring name;
  std::wstring dumpPath;
  std::wstring fromDump;
  int seconds = 10;
  int topN = 6;
  double minMs = 10.0;
  for (int i = 1; i < argc; ++i) {
    std::wstring a = argv[i];
    bool hasValue = i + 1 < argc;
    if (a == L"--pid" && hasValue) {
      pid = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
    } else if (a == L"--name" && hasValue) {
      name = argv[++i];
    } else if (a == L"--seconds" && hasValue) {
      seconds = (std::max)(1, _wtoi(argv[++i]));
    } else if (a == L"--top" && hasValue) {
      topN = (std::max)(1, _wtoi(argv[++i]));
    } else if (a == L"--min-ms" && hasValue) {
      minMs = (std::max)(0.0, std::wcstod(argv[++i], nullptr));
    } else if (a == L"--dump-events" && hasValue) {
      dumpPath = argv[++i];
    } else if (a == L"--from-dump" && hasValue) {
      fromDump = argv[++i];
    } else {
      Usage();
      return kExitUsage;
    }
  }
  if (!fromDump.empty()) {
    if (pid != 0 || !name.empty() || !dumpPath.empty()) {
      Usage();
      return kExitUsage;
    }
    return ReportFromDump(fromDump, topN, minMs);
  }
  if (!name.empty() && !FindProcessByName(name, &pid)) {
    std::printf("No running process named %s.\n", Narrow(name).c_str());
    return kExitUsage;
  }
  if (pid == 0) {
    Usage();
    return kExitUsage;
  }
  HANDLE target = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!target) {
    std::printf("Cannot open PID %u. Is it running, and are you running as Administrator?\n", pid);
    return kExitUsage;
  }
  SnapshotThreads(pid);

  LARGE_INTEGER freq;
  QueryPerformanceFrequency(&freq);

  if (!dumpPath.empty()) {
    if (_wfopen_s(&g_dump, dumpPath.c_str(), L"w") != 0) g_dump = nullptr;
    if (!g_dump) {
      std::printf("Cannot write the event dump to %s.\n", Narrow(dumpPath).c_str());
      CloseHandle(target);
      return kExitUsage;
    }
    std::setvbuf(g_dump, nullptr, _IOFBF, 1 << 20);
    std::fprintf(g_dump,
                 "# waitwhy raw event dump, version 2 (the format is described in dump.h)\n"
                 "# Timestamps are QueryPerformanceCounter ticks.\n"
                 "# One line per event for the program's threads, in the order delivered,\n"
                 "# then what the report needs: the stop, snapshots, symbols and thread names.\n"
                 "DUMP version=2 pid=%u ticksPerSecond=%lld\n",
                 pid, static_cast<long long>(freq.QuadPart));
    for (uint32_t tid : g_analysis.targetThreads) std::fprintf(g_dump, "TARGET tid=%u\n", tid);
  }

  TRACEHANDLE session = 0;
  ULONG rc = StartKernelSession(&session);
  if (rc == ERROR_ACCESS_DENIED) {
    std::printf("Access denied. Run waitwhy from an Administrator PowerShell window.\n");
    return kExitTraceUnavailable;
  }
  if (rc != ERROR_SUCCESS) {
    std::printf("Could not start the kernel trace session (error %lu).\n", rc);
    return kExitTraceUnavailable;
  }
  SetConsoleCtrlHandler(OnCtrl, TRUE);
  const bool stacksOn = EnableContextSwitchStacks(session);
  g_analysis.stacksOn = stacksOn;

  EVENT_TRACE_LOGFILEW logfile{};
  logfile.LoggerName = const_cast<LPWSTR>(kLoggerName);
  logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
                             PROCESS_TRACE_MODE_RAW_TIMESTAMP;
  logfile.EventRecordCallback = OnEvent;
  TRACEHANDLE consumer = OpenTraceW(&logfile);
  if (consumer == INVALID_PROCESSTRACE_HANDLE) {
    std::printf("Could not open the trace for reading (error %lu).\n", GetLastError());
    StopKernelSession();
    return kExitTraceUnavailable;
  }
  // The window starts now, before the first event is read, so the reader thread never sees it
  // change (W20). Events Windows logged since the session started still set each thread's
  // state; their time counts from here.
  LARGE_INTEGER windowStart;
  QueryPerformanceCounter(&windowStart);
  g_analysis.firstTs = static_cast<uint64_t>(windowStart.QuadPart);
  if (g_dump) {
    std::fprintf(g_dump, "WINDOW ts=%llu\n", static_cast<unsigned long long>(g_analysis.firstTs));
    ++g_dumpLines;
  }
  std::thread reader([&consumer] { ProcessTrace(&consumer, 1, nullptr, nullptr); });

  std::printf("Watching PID %u (%zu threads) for %d seconds", pid, g_analysis.targetThreads.size(),
              seconds);
  std::fflush(stdout);
  // Wait for a deadline on the same clock as the events, not for a number of sleeps: each sleep
  // rounds up to the system timer, which made an 8 s run last 8.4 s.
  const uint64_t deadline = g_analysis.firstTs + static_cast<uint64_t>(seconds) *
                                                     static_cast<uint64_t>(freq.QuadPart);
  uint64_t nextDot = g_analysis.firstTs + static_cast<uint64_t>(freq.QuadPart);
  for (;;) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const auto t = static_cast<uint64_t>(now.QuadPart);
    if (t >= deadline || g_stopRequested) break;
    if (t >= nextDot) {
      std::printf(".");
      std::fflush(stdout);
      nextDot += static_cast<uint64_t>(freq.QuadPart);
    }
    const uint64_t untilMs = (std::min)(deadline, nextDot) - t;
    const auto waitMs = static_cast<DWORD>((std::min)(
        uint64_t{100}, untilMs * 1000 / static_cast<uint64_t>(freq.QuadPart)));
    if (WaitForSingleObject(target, waitMs) == WAIT_OBJECT_0) {
      std::printf("\nThe program exited while being watched.");
      break;
    }
  }
  std::printf("\n");

  LARGE_INTEGER windowEnd;
  QueryPerformanceCounter(&windowEnd);
  g_windowEnd.store(static_cast<uint64_t>(windowEnd.QuadPart), std::memory_order_relaxed);
  SessionProps stopped;
  StopKernelSession(&stopped);  // ProcessTrace returns once the buffers are drained
  reader.join();
  g_analysis.lastTs = static_cast<uint64_t>(windowEnd.QuadPart);
  CloseTrace(consumer);
  CloseHandle(target);
  if (g_dump) {
    std::fprintf(g_dump, "END ts=%llu contextSwitches=%llu stacksOn=%d eventsLost=%lu buffersLost=%lu\n",
                 static_cast<unsigned long long>(g_analysis.lastTs),
                 static_cast<unsigned long long>(g_analysis.contextSwitches), stacksOn ? 1 : 0,
                 stopped.props.EventsLost, stopped.props.RealTimeBuffersLost);
  }

  SnapshotThreadsStillBlocked();
  g_analysis.FlushAtEnd();
  Symbolizer sym;
  const bool symbolsOk = sym.Init(pid);
  if (g_dump) {
    WriteDumpNames(g_dump, sym, symbolsOk);
    std::fclose(g_dump);
    g_dump = nullptr;
    std::printf("Wrote %llu events to %s.\n", static_cast<unsigned long long>(g_dumpLines),
                Narrow(dumpPath).c_str());
  }
  PrintReport(static_cast<double>(freq.QuadPart), topN, minMs, stopped, stacksOn, sym, symbolsOk);
  return kExitOk;
}
#endif  // WAITWHY_NO_MAIN
