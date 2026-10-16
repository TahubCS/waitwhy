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

#include "analysis.h"

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
FILE* g_dump = nullptr;   // --dump-events output; null when not asked for
uint64_t g_dumpLines = 0;

void OnCSwitch(const EVENT_RECORD* ev, uint64_t ts) {
  if (ev->UserDataLength < sizeof(CSwitchPayload)) return;
  CSwitchPayload c;
  std::memcpy(&c, ev->UserData, sizeof c);

  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  if (cpu < g_cpuThread.size()) g_cpuThread[cpu] = c.newThreadId;

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
  const unsigned cpu = ev->BufferContext.ProcessorNumber;
  if (g_dump) {
    std::fprintf(g_dump, "READY ts=%llu cpu=%u readied=%u headerThread=%u flag=0x%02x\n",
                 static_cast<unsigned long long>(ts), cpu, readied,
                 static_cast<unsigned>(ev->EventHeader.ThreadId), flag);
    ++g_dumpLines;
  }
  ReadyEvent e;
  e.ts = ts;
  e.readiedTid = readied;
  e.byTid = ResolveWaker(flag, ev->EventHeader.ThreadId,
                         cpu < g_cpuThread.size() ? g_cpuThread[cpu] : kUnknownThread);
  g_analysis.OnReady(e);
}

// Thread start, end and rundown events all begin with uint32 ProcessId, uint32 TThreadId.
void OnThreadEvent(const EVENT_RECORD* ev, ThreadEvent::Kind kind) {
  if (ev->UserDataLength < 2 * sizeof(uint32_t)) return;
  ThreadEvent e;
  e.ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);
  e.kind = kind;
  std::memcpy(&e.pid, ev->UserData, sizeof e.pid);
  std::memcpy(&e.tid, static_cast<const uint8_t*>(ev->UserData) + 4, sizeof e.tid);
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
                 "firstUser=0x%llx\n",
                 static_cast<unsigned long long>(e.ts), static_cast<unsigned long long>(e.eventTs),
                 e.tid, kernelFrames, static_cast<unsigned long long>(e.userFrames.size()),
                 static_cast<unsigned long long>(e.userFrames.empty() ? 0 : e.userFrames.front()));
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
    g_analysis.ApplySnapshot(tid, std::move(frames));
  }
  SymCleanup(proc);
  CloseHandle(proc);
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

  // Lower-case path of the source file the code at `addr` came from, with backslashes;
  // empty when the .pdb has no line information for it.
  const std::string& SourceFile(uint64_t addr) {
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
  std::unordered_map<uint64_t, std::string> files_;
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
  // The program's own calls into the C++ runtime and the lock APIs say more than the
  // innermost frames: ntdll often resolves only to its nearest exported name, so a blocked
  // AcquireSRWLockExclusive can show up as RtlSleepConditionVariableSRW. A condition variable
  // wait also names its mutex, so it is checked first.
  if (HasAny(all, {"condition_variable", "cnd_wait"})) return Category::OtherThread;
  if (HasAny(all, {"mutex::lock", "mtx_lock", "mtx_do_lock", "acquiresrwlockexclusive",
                   "acquiresrwlockshared", "entercriticalsection"}))
    return Category::Lock;
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

// True for C++ runtime and standard library code that the linker copied into the exe
// (std::mutex::lock, _Mtx_lock, mtx_do_lock, the CRT's thread and main startup code). The
// source path decides when the .pdb has line information; otherwise the name does.
bool IsRuntimeFrame(const std::string& function, const std::string& sourceFile) {
  for (const char* dir : {"\\vctools\\crt\\", "\\crts\\ucrt\\", "\\vc\\tools\\msvc\\",
                          "\\windows kits\\"})
    if (sourceFile.find(dir) != std::string::npos) return true;
  for (const char* prefix : {"std::", "_", "Concurrency::", "concurrency::", "mtx_do_lock",
                             "thread_start<", "invoke_main", "mainCRTStartup", "wmainCRTStartup",
                             "WinMainCRTStartup", "wWinMainCRTStartup"})
    if (function.rfind(prefix, 0) == 0) return true;
  return false;
}

// First frame in the program's own code, skipping the C++ runtime linked into it.
std::string YourCodeFrame(const Bucket& b, Symbolizer& sym) {
  for (uint64_t a : b.stack) {
    const std::string& n = sym.Name(a);
    if (!sym.IsExeFrame(n)) continue;
    if (IsRuntimeFrame(n.substr(n.find('!') + 1), sym.SourceFile(a))) continue;
    return n;
  }
  return "(not in your program's code)";
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
  if (g_analysis.IsProgramThread(tid)) return ThreadLabel(tid);
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
  const Analyzer& an = g_analysis;
  const double window = an.lastTs > an.firstTs ? (an.lastTs - an.firstTs) / ticksPerSecond : 0.0;
  auto secs = [&](uint64_t ticks) { return ticks / ticksPerSecond; };
  auto pct = [&](uint64_t ticks) { return window > 0 ? 100.0 * secs(ticks) / window : 0.0; };

  Symbolizer sym;
  bool symbolsOk = sym.Init(an.pid);

  std::printf("\n==============================================================\n");
  std::printf(" waitwhy report: %s (PID %u), watched for %s\n",
              sym.ExeFile().empty() ? "process" : sym.ExeFile().c_str(), an.pid,
              FormatDuration(window).c_str());
  std::printf("==============================================================\n");
  if (stopped.props.EventsLost || stopped.props.RealTimeBuffersLost)
    std::printf("Warning: Windows dropped %lu events (%lu buffers). Numbers may be a bit low.\n",
                stopped.props.EventsLost, stopped.props.RealTimeBuffersLost);
  if (!stacksOn) std::printf("Warning: call stacks were not available, so code locations are missing.\n");
  if (!symbolsOk) std::printf("Warning: could not open the process to read function names (did it exit?).\n");

  // Per-thread summary.
  std::vector<uint32_t> tids;  // includes threads that exited during the trace
  for (const auto& [tid, st] : an.threads)
    if (st.seen) tids.push_back(tid);
  int unseen = 0;
  for (uint32_t tid : an.targetThreads) {
    auto it = an.threads.find(tid);
    if (it == an.threads.end() || !it->second.seen) ++unseen;
  }
  std::sort(tids.begin(), tids.end(), [&an](uint32_t x, uint32_t y) {
    return an.threads.at(x).waitTicks > an.threads.at(y).waitTicks;
  });

  std::printf("\nWhere each thread's time went\n");
  std::printf("  %-30s %10s %10s %12s\n", "Thread", "Running", "Waiting", "Wanted CPU");
  for (uint32_t tid : tids) {
    const ThreadState& st = an.threads.at(tid);
    std::printf("  %-30.30s %9.0f%% %9.0f%% %11.0f%%\n", ThreadLabel(tid).c_str(),
                pct(st.runTicks), pct(st.waitTicks), pct(st.readyTicks));
  }
  if (unseen)
    std::printf("  (%d more thread(s) never ran during the window: blocked the whole time or idle)\n",
                unseen);

  // Biggest waits.
  std::vector<const Bucket*> buckets;
  for (auto& [key, b] : an.buckets) buckets.push_back(&b);
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
    if (b.reason == kReasonUnknown)
      std::printf("      Wait reason: not known (already blocked when the trace started)\n");
    else
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
      if (c == Category::Lock && g_analysis.IsProgramThread(waker) && waker != tid) {
        // What was the thread that released the lock busy with?
        for (const Bucket* wb : buckets) {
          if (wb->tid != waker) continue;
          Category wc = category[wb];
          if (wc == Category::Lock || wc == Category::Sleep) continue;
          if (wb->stack.empty()) continue;  // nothing to say about where its time went
          std::printf("    The lock was released by %s, which spends its time %s, in %s.\n",
                      ThreadLabel(waker).c_str(), CategorySentence(wc),
                      YourCodeFrame(*wb, sym).c_str());
          std::printf("    It is most likely holding the lock during that slow work. Move the\n"
                      "    slow work outside the lock (copy the data first, then do the work).\n");
          break;
        }
      }
    }
    const ThreadState& st = an.threads.at(tid);
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

  std::printf("\n(%llu context switches seen, %llu waits with a call stack,"
              " %llu waits without a call stack, %llu kernel-only stack parts)\n",
              static_cast<unsigned long long>(an.contextSwitches),
              static_cast<unsigned long long>(an.waitsWithStack),
              static_cast<unsigned long long>(an.waitsWithoutStack),
              static_cast<unsigned long long>(an.kernelOnlyFragments));
}

void Usage() {
  std::printf(
      "usage: waitwhy (--pid N | --name program.exe) [--seconds N] [--top N]\n"
      "               [--dump-events FILE]\n"
      "  Watches a running program and reports what its threads were waiting on.\n"
      "  --dump-events also writes every context-switch, ready-thread and stack event\n"
      "  of the program's threads to FILE, one line each, in the order they arrived.\n"
      "  Must be run as Administrator.\n"
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
  int seconds = 10;
  int topN = 6;
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
    } else if (a == L"--dump-events" && hasValue) {
      dumpPath = argv[++i];
    } else {
      Usage();
      return kExitUsage;
    }
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
    g_dump = _wfopen(dumpPath.c_str(), L"w");
    if (!g_dump) {
      std::printf("Cannot write the event dump to %s.\n", Narrow(dumpPath).c_str());
      CloseHandle(target);
      return kExitUsage;
    }
    std::setvbuf(g_dump, nullptr, _IOFBF, 1 << 20);
    std::fprintf(g_dump,
                 "# waitwhy raw event dump for PID %u\n"
                 "# Timestamps are QueryPerformanceCounter ticks, %lld per second.\n"
                 "# One line per event for the program's threads, in the order delivered.\n"
                 "# CSWITCH ts cpu old new oldState oldReason\n"
                 "# READY   ts cpu readied headerThread flag\n"
                 "# STACK   ts eventTs tid kernelFrames userFrames firstUser\n",
                 pid, static_cast<long long>(freq.QuadPart));
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
  std::thread reader([&consumer] { ProcessTrace(&consumer, 1, nullptr, nullptr); });

  std::printf("Watching PID %u (%zu threads) for %d seconds", pid, g_analysis.targetThreads.size(),
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

  if (g_analysis.firstTs != 0) SnapshotThreadsStillBlocked();
  g_analysis.FlushAtEnd();
  PrintReport(static_cast<double>(freq.QuadPart), topN, stopped, stacksOn);
  return kExitOk;
}
#endif  // WAITWHY_NO_MAIN
