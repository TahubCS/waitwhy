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
#include <map>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

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
constexpr UCHAR kOpThreadDcStart = 3;  // "already running when the trace started"
constexpr UCHAR kOpCSwitch = 36;
constexpr UCHAR kOpReadyThread = 50;
constexpr UCHAR kOpStackWalk = 32;     // inside the StackWalk class

constexpr int kTraceStackTracingInfo = 3;  // TRACE_INFO_CLASS value
constexpr int8_t kThreadStateWaiting = 5;  // KTHREAD_STATE: Waiting
constexpr uint32_t kUnknownThread = 0xFFFFFFFFu;
constexpr uint32_t kSystemWaker = 0;  // idle thread, or a DPC (timer, finished I/O)
constexpr uint8_t kReadyFlagFromDpc = 0x1;  // ReadyThread Flag: readied from a DPC
constexpr uint64_t kUserSpaceLimit = 0x0000800000000000ull;  // addresses above are kernel code

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
// Data collected while tracing (only touched by the trace thread until it ends)
// ---------------------------------------------------------------------------

// One period where a thread was switched off the CPU.
struct OffCpu {
  uint64_t start = 0;
  uint64_t end = 0;
  int8_t reason = 0;       // kernel wait reason code
  bool isWait = false;     // true = blocked; false = preempted (it wanted the CPU)
  uint32_t wokenBy = kUnknownThread;
  std::vector<uint64_t> stack;  // user-mode return addresses, innermost first
};

// Upper limit on finished waits per thread that are still waiting for their call stack.
// Beyond it the oldest one is recorded without a stack, so memory stays bounded.
constexpr size_t kMaxWaitsAwaitingStack = 64;

struct ThreadState {
  bool offCpu = false;  // `open` holds the period the thread is off the CPU right now
  OffCpu open;
  // Finished waits whose call stack has not arrived yet, keyed by the timestamp of the
  // context switch that put the thread back on a CPU. The kernel records the stack for that
  // switch, and the StackWalk event carries the same value as its EventTimeStamp.
  std::map<uint64_t, OffCpu> awaitingStack;
  bool running = false;
  uint64_t runStart = 0;
  uint64_t runTicks = 0;
  uint64_t waitTicks = 0;
  uint64_t readyTicks = 0;
  bool seen = false;
};

// All waits of one thread that share the same call stack and wait reason.
struct Bucket {
  uint32_t tid = 0;
  int8_t reason = 0;
  uint64_t ticks = 0;
  uint32_t count = 0;
  bool stillWaitingAtEnd = false;
  std::vector<uint64_t> stack;
  std::map<uint32_t, uint64_t> wakers;  // waking thread id -> wait time it ended
};

uint32_t g_pid = 0;
std::unordered_set<uint32_t> g_targetThreads;
std::unordered_map<uint32_t, ThreadState> g_threads;
std::map<std::pair<uint32_t, uint64_t>, Bucket> g_buckets;
std::vector<uint32_t> g_cpuThread(256, kUnknownThread);  // thread currently on each CPU
uint64_t g_firstTs = 0;
uint64_t g_lastTs = 0;
uint64_t g_contextSwitches = 0;
uint64_t g_stacksAttached = 0;
uint64_t g_waitsWithoutStack = 0;
uint64_t g_kernelOnlyFragments = 0;  // stack events for a wait that held no user-mode frame
bool g_stacksOn = false;  // set before the trace is read; no stacks means no point waiting
std::atomic<bool> g_stopRequested{false};
FILE* g_dump = nullptr;   // --dump-events output; null when not asked for
uint64_t g_dumpLines = 0;

uint64_t HashWait(int8_t reason, const std::vector<uint64_t>& stack) {
  uint64_t h = 1469598103934665603ull;  // FNV-1a
  auto mix = [&h](uint64_t v) {
    for (int i = 0; i < 8; ++i) {
      h ^= (v >> (i * 8)) & 0xff;
      h *= 1099511628211ull;
    }
  };
  mix(static_cast<uint8_t>(reason));
  for (uint64_t a : stack) mix(a);
  return h;
}

void Record(uint32_t tid, ThreadState& st, const OffCpu& w, bool stillWaiting) {
  const uint64_t d = w.end > w.start ? w.end - w.start : 0;
  if (!w.isWait) {
    st.readyTicks += d;
    return;
  }
  st.waitTicks += d;
  Bucket& b = g_buckets[{tid, HashWait(w.reason, w.stack)}];
  if (b.count == 0) {
    b.tid = tid;
    b.reason = w.reason;
    b.stack = w.stack;
  }
  b.ticks += d;
  b.count += 1;
  if (stillWaiting) b.stillWaitingAtEnd = true;
  if (w.wokenBy != kUnknownThread) b.wakers[w.wokenBy] += d;
}

// Records a finished wait whose call stack never arrived.
void RecordWithoutStack(uint32_t tid, ThreadState& st, const OffCpu& w) {
  ++g_waitsWithoutStack;
  Record(tid, st, w, false);
}

void OnCSwitch(const EVENT_RECORD* ev, uint64_t ts) {
  if (ev->UserDataLength < sizeof(CSwitchPayload)) return;
  CSwitchPayload c;
  std::memcpy(&c, ev->UserData, sizeof c);
  if (g_firstTs == 0) g_firstTs = ts;
  g_lastTs = ts;
  ++g_contextSwitches;

  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  if (cpu < g_cpuThread.size()) g_cpuThread[cpu] = c.newThreadId;

  if (g_dump && (g_targetThreads.count(c.oldThreadId) || g_targetThreads.count(c.newThreadId))) {
    std::fprintf(g_dump, "CSWITCH ts=%llu cpu=%u old=%u new=%u oldState=%d oldReason=%d\n",
                 static_cast<unsigned long long>(ts), cpu, c.oldThreadId, c.newThreadId,
                 c.oldThreadState, c.oldThreadWaitReason);
    ++g_dumpLines;
  }

  // A thread of the target process leaves the CPU.
  if (g_targetThreads.count(c.oldThreadId)) {
    ThreadState& st = g_threads[c.oldThreadId];
    st.seen = true;
    if (st.running) {
      st.runTicks += ts - st.runStart;
      st.running = false;
    }
    // Earlier waits still awaiting their stack stay in `awaitingStack`, separate from this one.
    st.open = OffCpu{};
    st.open.start = ts;
    st.open.reason = c.oldThreadWaitReason;
    st.open.isWait = (c.oldThreadState == kThreadStateWaiting);
    st.offCpu = true;
  }

  // A thread of the target process gets back on a CPU.
  if (g_targetThreads.count(c.newThreadId)) {
    ThreadState& st = g_threads[c.newThreadId];
    st.seen = true;
    if (st.offCpu) {
      st.open.end = ts;
      st.offCpu = false;
      if (!st.open.isWait || !g_stacksOn) {
        Record(c.newThreadId, st, st.open, false);  // no stack needed, or none will come
      } else {
        // The stack for this wait is the one recorded for this switch-in, so it is matched
        // by this timestamp. It is logged after this event, possibly much later.
        st.awaitingStack.emplace(ts, std::move(st.open));
        if (st.awaitingStack.size() > kMaxWaitsAwaitingStack) {
          auto oldest = st.awaitingStack.begin();
          RecordWithoutStack(c.newThreadId, st, oldest->second);
          st.awaitingStack.erase(oldest);
        }
      }
    }
    st.running = true;
    st.runStart = ts;
  }
}

void OnReadyThread(const EVENT_RECORD* ev) {
  if (ev->UserDataLength < sizeof(uint32_t)) return;
  uint32_t readied;
  std::memcpy(&readied, ev->UserData, sizeof readied);
  if (!g_targetThreads.count(readied)) return;
  // Payload: uint32 TThreadId, int8 AdjustReason, int8 AdjustIncrement, int8 Flag, int8 spare.
  const uint8_t flag = ev->UserDataLength >= 7 ? static_cast<const uint8_t*>(ev->UserData)[6] : 0;
  if (g_dump) {
    std::fprintf(g_dump, "READY ts=%llu cpu=%u readied=%u headerThread=%u flag=0x%02x\n",
                 static_cast<unsigned long long>(ev->EventHeader.TimeStamp.QuadPart),
                 static_cast<unsigned>(ev->BufferContext.ProcessorNumber), readied,
                 static_cast<unsigned>(ev->EventHeader.ThreadId), flag);
    ++g_dumpLines;
  }
  ThreadState& st = g_threads[readied];
  if (!st.offCpu) return;
  // A DPC (a timer firing, an I/O finishing) borrows whatever thread happens to be on the
  // CPU; that thread did not wake ours, the system did.
  if (flag & kReadyFlagFromDpc) {
    st.open.wokenBy = kSystemWaker;
    return;
  }
  // The thread running on this CPU is the one that woke our thread up.
  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  uint32_t by = cpu < g_cpuThread.size() ? g_cpuThread[cpu] : kUnknownThread;
  if (by == kUnknownThread) by = ev->EventHeader.ThreadId;
  st.open.wokenBy = by;
}

void OnThreadStart(const EVENT_RECORD* ev) {
  if (ev->UserDataLength < 2 * sizeof(uint32_t)) return;
  uint32_t pid, tid;
  std::memcpy(&pid, ev->UserData, sizeof pid);
  std::memcpy(&tid, static_cast<const uint8_t*>(ev->UserData) + 4, sizeof tid);
  if (pid == g_pid) g_targetThreads.insert(tid);
}

void OnStackWalk(const EVENT_RECORD* ev) {
  // Layout: uint64 EventTimeStamp, uint32 StackProcess, uint32 StackThread, then addresses.
  if (ev->UserDataLength < 16) return;
  const auto* p = static_cast<const uint8_t*>(ev->UserData);
  uint64_t eventTs;
  uint32_t stackTid;
  std::memcpy(&eventTs, p, sizeof eventTs);
  std::memcpy(&stackTid, p + 12, sizeof stackTid);
  if (!g_targetThreads.count(stackTid)) return;
  const size_t ptrSize = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  const size_t frames = (ev->UserDataLength - 16) / ptrSize;

  if (g_dump) {
    unsigned long long kernelFrames = 0, userFrames = 0, firstUser = 0;
    for (size_t i = 0; i < frames; ++i) {
      uint64_t addr = 0;
      std::memcpy(&addr, p + 16 + i * ptrSize, ptrSize);
      if (addr >= kUserSpaceLimit) {
        ++kernelFrames;
      } else if (addr != 0 && userFrames++ == 0) {
        firstUser = addr;
      }
    }
    std::fprintf(g_dump,
                 "STACK ts=%llu eventTs=%llu tid=%u kernelFrames=%llu userFrames=%llu "
                 "firstUser=0x%llx\n",
                 static_cast<unsigned long long>(ev->EventHeader.TimeStamp.QuadPart),
                 static_cast<unsigned long long>(eventTs), stackTid, kernelFrames, userFrames,
                 firstUser);
    ++g_dumpLines;
  }

  ThreadState& st = g_threads[stackTid];
  // Only the wait that ended at the switch this stack was recorded for gets it. Stacks for
  // other switches (after a preemption, or for a wait already recorded) are ignored.
  auto it = st.awaitingStack.find(eventTs);
  if (it == st.awaitingStack.end()) return;

  // One stack can arrive as two events with the same EventTimeStamp: the kernel part,
  // logged at the switch, and the user part, logged once the thread is back in user mode.
  // Only user-mode frames are kept, so a fragment without any is skipped and the wait keeps
  // waiting for the rest of its stack.
  OffCpu& w = it->second;
  const size_t framesBefore = w.stack.size();
  for (size_t i = 0; i < frames; ++i) {
    uint64_t addr = 0;
    std::memcpy(&addr, p + 16 + i * ptrSize, ptrSize);
    if (addr != 0 && addr < kUserSpaceLimit) w.stack.push_back(addr);
  }
  if (w.stack.size() == framesBefore) {
    ++g_kernelOnlyFragments;
    return;
  }
  ++g_stacksAttached;
  Record(stackTid, st, w, false);
  st.awaitingStack.erase(it);
}

void WINAPI OnEvent(PEVENT_RECORD ev) {
  const EVENT_HEADER& h = ev->EventHeader;
  const UCHAR op = h.EventDescriptor.Opcode;
  if (IsEqualGUID(h.ProviderId, kThreadGuid)) {
    if (op == kOpCSwitch) {
      OnCSwitch(ev, static_cast<uint64_t>(h.TimeStamp.QuadPart));
    } else if (op == kOpReadyThread) {
      OnReadyThread(ev);
    } else if (op == kOpThreadStart || op == kOpThreadDcStart) {
      OnThreadStart(ev);
    }
  } else if (IsEqualGUID(h.ProviderId, kStackWalkGuid) && op == kOpStackWalk) {
    OnStackWalk(ev);
  }
}

// Called after tracing stops: close out anything still in progress.
void FlushAtEnd() {
  for (auto& [tid, st] : g_threads) {
    if (st.running && g_lastTs > st.runStart) st.runTicks += g_lastTs - st.runStart;
    for (auto& entry : st.awaitingStack) RecordWithoutStack(tid, st, entry.second);
    st.awaitingStack.clear();
    if (st.offCpu && g_lastTs > st.open.start) {
      st.open.end = g_lastTs;  // still off the CPU when the trace ended
      Record(tid, st, st.open, true);
    }
    st.offCpu = false;
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

std::string Lower(std::string s) {
  for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
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
    if (te.th32OwnerProcessID == pid) g_targetThreads.insert(te.th32ThreadID);
  }
  CloseHandle(snap);
}

std::string ThreadLabel(uint32_t tid) {
  static std::unordered_map<uint32_t, std::string> cache;
  auto it = cache.find(tid);
  if (it != cache.end()) return it->second;
  std::string label = "Thread " + std::to_string(tid);
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

class Symbolizer {
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
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
    ok_ = SymInitializeW(proc_, nullptr, TRUE) != FALSE;
    return ok_;
  }
  ~Symbolizer() {
    if (ok_) SymCleanup(proc_);
    if (proc_) CloseHandle(proc_);
  }

  // Returns "module!function", or "module!0x1234" when no name is available.
  const std::string& Name(uint64_t addr) {
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

  bool IsExeFrame(const std::string& name) const {
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
};

// ---------------------------------------------------------------------------
// Turning stacks into plain English
// ---------------------------------------------------------------------------

enum class Category { Lock, Disk, Network, Sleep, OtherThread, PageFault, Other };

const char* CategoryLabel(Category c) {
  switch (c) {
    case Category::Lock: return "a lock held by another thread";
    case Category::Disk: return "the disk (file read/write/flush)";
    case Category::Network: return "the network";
    case Category::Sleep: return "an intentional sleep or timer";
    case Category::OtherThread: return "another thread or an event";
    case Category::PageFault: return "memory being loaded from disk";
    default: return "something else";
  }
}

const char* CategorySentence(Category c) {
  switch (c) {
    case Category::Lock: return "waiting for a lock that another thread was holding";
    case Category::Disk: return "waiting for the disk";
    case Category::Network: return "waiting for the network";
    case Category::Sleep: return "sleeping on purpose";
    case Category::OtherThread: return "waiting for another thread or an event to signal it";
    case Category::PageFault: return "waiting for memory to be loaded from disk";
    default: return "waiting";
  }
}

const char* WaitReasonName(int8_t r) {
  static const char* names[] = {
      "Executive", "FreePage", "PageIn", "PoolAllocation", "DelayExecution", "Suspended",
      "UserRequest", "WrExecutive", "WrFreePage", "WrPageIn", "WrPoolAllocation",
      "WrDelayExecution", "WrSuspended", "WrUserRequest", "WrSpare0", "WrQueue",
      "WrLpcReceive", "WrLpcReply", "WrVirtualMemory", "WrPageOut", "WrRendezvous",
      "WrKeyedEvent", "WrTerminated", "WrProcessInSwap", "WrCpuRateControl", "WrCalloutStack",
      "WrKernel", "WrResource", "WrPushLock", "WrMutex", "WrQuantumEnd", "WrDispatchInt",
      "WrPreempted", "WrYieldExecution", "WrFastMutex", "WrGuardedMutex", "WrRundown",
      "WrAlertByThreadId"};
  if (r >= 0 && r < static_cast<int8_t>(sizeof names / sizeof names[0])) return names[r];
  return "unknown";
}

bool HasAny(const std::string& text, std::initializer_list<const char*> words) {
  for (const char* w : words)
    if (text.find(w) != std::string::npos) return true;
  return false;
}

Category Classify(const Bucket& b, Symbolizer& sym) {
  std::string all;
  for (uint64_t a : b.stack) all += Lower(sym.Name(a)) + "\n";
  if (HasAny(all, {"!readfile", "!writefile", "!flushfilebuffers", "!ntreadfile",
                   "!ntwritefile", "!ntflushbuffersfile", "!createfile", "!ntcreatefile"}))
    return Category::Disk;
  if (HasAny(all, {"!recv", "!wsarecv", "!send\n", "!wsasend", "!select", "!connect",
                   "!accept", "!wsapoll", "!getaddrinfo", "!winhttp", "!internetread"}))
    return Category::Network;
  if (HasAny(all, {"!sleep\n", "!sleepex\n", "!ntdelayexecution"}) || b.reason == 4 ||
      b.reason == 11)
    return Category::Sleep;
  if (HasAny(all, {"sleepconditionvariable", "!waitforsingleobject", "!waitformultipleobjects",
                   "::join", "!getqueuedcompletionstatus", "_thrd_join"}))
    return Category::OtherThread;
  if (HasAny(all, {"srwlock", "criticalsection", "mtx_lock", "mutex"}) || b.reason == 21 ||
      b.reason == 37)
    return Category::Lock;
  if (b.reason == 2 || b.reason == 9) return Category::PageFault;
  if (b.reason == 6 || b.reason == 13) return Category::OtherThread;
  return Category::Other;
}

// First frame in the program's own code, skipping C++ library internals.
std::string YourCodeFrame(const Bucket& b, Symbolizer& sym) {
  std::string firstExe;
  for (uint64_t a : b.stack) {
    const std::string& n = sym.Name(a);
    if (!sym.IsExeFrame(n)) continue;
    if (firstExe.empty()) firstExe = n;
    std::string fn = n.substr(n.find('!') + 1);
    if (fn.rfind("std::", 0) == 0 || fn.rfind("_", 0) == 0) continue;
    return n;
  }
  return firstExe.empty() ? "(not in your program's code)" : firstExe;
}

// Innermost frame, skipping the raw system-call stubs (ntdll!Nt..., ntdll!Zw...).
std::string BlockedInFrame(const Bucket& b, Symbolizer& sym) {
  for (uint64_t a : b.stack) {
    const std::string& n = sym.Name(a);
    std::string lower = Lower(n);
    if (lower.rfind("ntdll!nt", 0) == 0 || lower.rfind("ntdll!zw", 0) == 0) continue;
    return n;
  }
  return b.stack.empty() ? "(no call stack recorded)" : sym.Name(b.stack.front());
}

uint32_t TopWaker(const Bucket& b) {
  uint32_t best = kUnknownThread;
  uint64_t bestTicks = 0;
  for (auto& [tid, t] : b.wakers)
    if (t > bestTicks) best = tid, bestTicks = t;
  return best;
}

std::string WakerLabel(uint32_t tid) {
  if (tid == kUnknownThread) return "unknown";
  if (g_targetThreads.count(tid)) return ThreadLabel(tid);
  if (tid == kSystemWaker) return "the system (a timer or finished I/O)";
  return "outside your program (thread " + std::to_string(tid) + ")";
}

std::string FormatDuration(double seconds) {
  char buf[32];
  if (seconds >= 1.0)
    std::snprintf(buf, sizeof buf, "%.2f s", seconds);
  else
    std::snprintf(buf, sizeof buf, "%.0f ms", seconds * 1000.0);
  return buf;
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

void PrintReport(double ticksPerSecond, int topN, const SessionProps& stopped, bool stacksOn) {
  const double window = g_lastTs > g_firstTs ? (g_lastTs - g_firstTs) / ticksPerSecond : 0.0;
  auto secs = [&](uint64_t ticks) { return ticks / ticksPerSecond; };
  auto pct = [&](uint64_t ticks) { return window > 0 ? 100.0 * secs(ticks) / window : 0.0; };

  Symbolizer sym;
  bool symbolsOk = sym.Init(g_pid);

  std::printf("\n==============================================================\n");
  std::printf(" waitwhy report: %s (PID %u), watched for %s\n",
              sym.ExeFile().empty() ? "process" : sym.ExeFile().c_str(), g_pid,
              FormatDuration(window).c_str());
  std::printf("==============================================================\n");
  if (stopped.props.EventsLost || stopped.props.RealTimeBuffersLost)
    std::printf("Warning: Windows dropped %lu events (%lu buffers). Numbers may be a bit low.\n",
                stopped.props.EventsLost, stopped.props.RealTimeBuffersLost);
  if (!stacksOn) std::printf("Warning: call stacks were not available, so code locations are missing.\n");
  if (!symbolsOk) std::printf("Warning: could not open the process to read function names (did it exit?).\n");

  // Per-thread summary.
  std::vector<uint32_t> tids;
  int unseen = 0;
  for (uint32_t tid : g_targetThreads) {
    auto it = g_threads.find(tid);
    if (it == g_threads.end() || !it->second.seen) {
      ++unseen;
      continue;
    }
    tids.push_back(tid);
  }
  std::sort(tids.begin(), tids.end(), [](uint32_t a, uint32_t b) {
    return g_threads[a].waitTicks > g_threads[b].waitTicks;
  });

  std::printf("\nWhere each thread's time went\n");
  std::printf("  %-30s %10s %10s %12s\n", "Thread", "Running", "Waiting", "Wanted CPU");
  for (uint32_t tid : tids) {
    const ThreadState& st = g_threads[tid];
    std::printf("  %-30.30s %9.0f%% %9.0f%% %11.0f%%\n", ThreadLabel(tid).c_str(),
                pct(st.runTicks), pct(st.waitTicks), pct(st.readyTicks));
  }
  if (unseen)
    std::printf("  (%d more thread(s) never ran during the window: blocked the whole time or idle)\n",
                unseen);

  // Biggest waits.
  std::vector<const Bucket*> buckets;
  for (auto& [key, b] : g_buckets) buckets.push_back(&b);
  std::sort(buckets.begin(), buckets.end(),
            [](const Bucket* a, const Bucket* b) { return a->ticks > b->ticks; });

  std::printf("\nBiggest waits\n");
  if (buckets.empty()) std::printf("  No waits recorded. Is the program doing anything?\n");
  std::unordered_map<const Bucket*, Category> category;
  for (const Bucket* b : buckets) category[b] = Classify(*b, sym);
  for (int i = 0; i < static_cast<int>(buckets.size()) && i < topN; ++i) {
    const Bucket& b = *buckets[i];
    std::printf("\n  #%d  %s  waited %s (%.0f%% of the time) over %u wait(s)%s\n", i + 1,
                ThreadLabel(b.tid).c_str(), FormatDuration(secs(b.ticks)).c_str(), pct(b.ticks),
                b.count, b.stillWaitingAtEnd ? ", still waiting at the end" : "");
    std::printf("      Waiting on : %s\n", CategoryLabel(category[&b]));
    std::printf("      Your code  : %s\n", YourCodeFrame(b, sym).c_str());
    std::printf("      Blocked in : %s\n", BlockedInFrame(b, sym).c_str());
    std::printf("      Woken by   : %s\n", WakerLabel(TopWaker(b)).c_str());
    std::printf("      Wait reason: %s (kernel code %d)\n", WaitReasonName(b.reason), b.reason);
  }

  // Plain-English findings.
  std::printf("\nWhat this means\n");
  bool anyFinding = false;
  for (uint32_t tid : tids) {
    std::vector<const Bucket*> mine;
    for (const Bucket* b : buckets)
      if (b->tid == tid) mine.push_back(b);
    bool printedForThread = false;
    for (const Bucket* b : mine) {
      Category c = category[b];
      if (c == Category::Sleep || pct(b->ticks) < 10.0) continue;
      anyFinding = printedForThread = true;
      std::printf("  * %s spent %.0f%% of the time %s, in %s.\n", ThreadLabel(tid).c_str(),
                  pct(b->ticks), CategorySentence(c), YourCodeFrame(*b, sym).c_str());
      uint32_t waker = TopWaker(*b);
      if (c == Category::Lock && g_targetThreads.count(waker) && waker != tid) {
        // What was the thread that released the lock busy with?
        for (const Bucket* wb : buckets) {
          if (wb->tid != waker) continue;
          Category wc = category[wb];
          if (wc == Category::Lock || wc == Category::Sleep) continue;
          std::printf("    The lock was released by %s, which spends its time %s, in %s.\n",
                      ThreadLabel(waker).c_str(), CategorySentence(wc),
                      YourCodeFrame(*wb, sym).c_str());
          std::printf("    It is most likely holding the lock during that slow work. Move the\n"
                      "    slow work outside the lock (copy the data first, then do the work).\n");
          break;
        }
      }
    }
    const ThreadState& st = g_threads[tid];
    if (pct(st.readyTicks) >= 20.0) {
      anyFinding = printedForThread = true;
      std::printf("  * %s spent %.0f%% of the time ready to run but waiting for a free CPU.\n"
                  "    The machine is busy; this is CPU competition, not a blocking problem.\n",
                  ThreadLabel(tid).c_str(), pct(st.readyTicks));
    }
    (void)printedForThread;
  }
  if (!anyFinding)
    std::printf("  No thread lost a significant share of its time to blocking (sleeps excluded).\n");

  std::printf("\n(%llu context switches seen, %llu call stacks matched,"
              " %llu waits without a call stack, %llu kernel-only stack parts)\n",
              static_cast<unsigned long long>(g_contextSwitches),
              static_cast<unsigned long long>(g_stacksAttached),
              static_cast<unsigned long long>(g_waitsWithoutStack),
              static_cast<unsigned long long>(g_kernelOnlyFragments));
}

void Usage() {
  std::printf(
      "usage: waitwhy (--pid N | --name program.exe) [--seconds N] [--top N]\n"
      "               [--dump-events FILE]\n"
      "  Watches a running program and reports what its threads were waiting on.\n"
      "  --dump-events also writes every context-switch, ready-thread and stack event\n"
      "  of the program's threads to FILE, one line each, in the order they arrived.\n"
      "  Must be run as Administrator.\n");
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  SetConsoleOutputCP(CP_UTF8);
  std::wstring name;
  std::wstring dumpPath;
  int seconds = 10;
  int topN = 6;
  for (int i = 1; i < argc; ++i) {
    std::wstring a = argv[i];
    bool hasValue = i + 1 < argc;
    if (a == L"--pid" && hasValue) {
      g_pid = static_cast<uint32_t>(std::wcstoul(argv[++i], nullptr, 10));
    } else if (a == L"--name" && hasValue) {
      name = argv[++i];
    } else if (a == L"--seconds" && hasValue) {
      seconds = (std::max)(1, _wtoi(argv[++i]));
    } else if (a == L"--top" && hasValue) {
      topN = (std::max)(1, _wtoi(argv[++i]));
    } else if (a == L"--dump-events" && hasValue) {
      dumpPath = argv[++i];
    } else {
      Usage();
      return 1;
    }
  }
  if (!name.empty() && !FindProcessByName(name, &g_pid)) {
    std::printf("No running process named %s.\n", Narrow(name).c_str());
    return 1;
  }
  if (g_pid == 0) {
    Usage();
    return 1;
  }
  HANDLE target = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, g_pid);
  if (!target) {
    std::printf("Cannot open PID %u. Is it running, and are you running as Administrator?\n", g_pid);
    return 1;
  }
  SnapshotThreads(g_pid);

  LARGE_INTEGER freq;
  QueryPerformanceFrequency(&freq);

  if (!dumpPath.empty()) {
    g_dump = _wfopen(dumpPath.c_str(), L"w");
    if (!g_dump) {
      std::printf("Cannot write the event dump to %s.\n", Narrow(dumpPath).c_str());
      CloseHandle(target);
      return 1;
    }
    std::setvbuf(g_dump, nullptr, _IOFBF, 1 << 20);
    std::fprintf(g_dump,
                 "# waitwhy raw event dump for PID %u\n"
                 "# Timestamps are QueryPerformanceCounter ticks, %lld per second.\n"
                 "# One line per event for the program's threads, in the order delivered.\n"
                 "# CSWITCH ts cpu old new oldState oldReason\n"
                 "# READY   ts cpu readied headerThread flag\n"
                 "# STACK   ts eventTs tid kernelFrames userFrames firstUser\n",
                 g_pid, static_cast<long long>(freq.QuadPart));
  }

  TRACEHANDLE session = 0;
  ULONG rc = StartKernelSession(&session);
  if (rc == ERROR_ACCESS_DENIED) {
    std::printf("Access denied. Run waitwhy from an Administrator PowerShell window.\n");
    return 1;
  }
  if (rc != ERROR_SUCCESS) {
    std::printf("Could not start the kernel trace session (error %lu).\n", rc);
    return 1;
  }
  SetConsoleCtrlHandler(OnCtrl, TRUE);
  const bool stacksOn = EnableContextSwitchStacks(session);
  g_stacksOn = stacksOn;

  EVENT_TRACE_LOGFILEW logfile{};
  logfile.LoggerName = const_cast<LPWSTR>(kLoggerName);
  logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
                             PROCESS_TRACE_MODE_RAW_TIMESTAMP;
  logfile.EventRecordCallback = OnEvent;
  TRACEHANDLE consumer = OpenTraceW(&logfile);
  if (consumer == INVALID_PROCESSTRACE_HANDLE) {
    std::printf("Could not open the trace for reading (error %lu).\n", GetLastError());
    StopKernelSession();
    return 1;
  }
  std::thread reader([&consumer] { ProcessTrace(&consumer, 1, nullptr, nullptr); });

  std::printf("Watching PID %u (%zu threads) for %d seconds", g_pid, g_targetThreads.size(),
              seconds);
  std::fflush(stdout);
  for (int tenth = 0; tenth < seconds * 10 && !g_stopRequested; ++tenth) {
    if (WaitForSingleObject(target, 100) == WAIT_OBJECT_0) {
      std::printf("\nThe program exited while being watched.");
      break;
    }
    if (tenth % 10 == 9) {
      std::printf(".");
      std::fflush(stdout);
    }
  }
  std::printf("\n");

  SessionProps stopped;
  StopKernelSession(&stopped);  // ProcessTrace returns once the buffers are drained
  reader.join();
  CloseTrace(consumer);
  CloseHandle(target);
  if (g_dump) {
    std::fclose(g_dump);
    g_dump = nullptr;
    std::printf("Wrote %llu events to %s.\n", static_cast<unsigned long long>(g_dumpLines),
                Narrow(dumpPath).c_str());
  }

  FlushAtEnd();
  PrintReport(static_cast<double>(freq.QuadPart), topN, stopped, stacksOn);
  return 0;
}
