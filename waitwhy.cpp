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
#include <io.h>
#include <dbghelp.h>
#include <tdh.h>
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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "analysis.h"
#include "dump.h"
#include "report.h"
#include "diff.h"
#include "export.h"
#include "html.h"

#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "tdh.lib")
#endif

static_assert(sizeof(void*) == 8, "Build waitwhy as a 64-bit (x64) program.");

#ifndef EVENT_TRACE_FLAG_DISPATCHER
#define EVENT_TRACE_FLAG_DISPATCHER 0x00000800
#endif
#ifndef INVALID_PROCESSTRACE_HANDLE
#define INVALID_PROCESSTRACE_HANDLE ((TRACEHANDLE)INVALID_HANDLE_VALUE)
#endif
#ifndef EVENT_TRACE_SYSTEM_LOGGER_MODE
#define EVENT_TRACE_SYSTEM_LOGGER_MODE 0x02000000
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
const wchar_t kPrivatePrefix[] = L"waitwhy-";  // private sessions are named waitwhy-<pid> (W31)

const GUID kSystemTraceControlGuid = {
    0x9e814aad, 0x3204, 0x11d2, {0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39}};
const GUID kThreadGuid = {
    0x3d6fa8d1, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
const GUID kStackWalkGuid = {
    0xdef2fe46, 0x7bd6, 0x4b80, {0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3}};
const GUID kImageGuid = {
    0x2cb15d1d, 0x5fc1, 0x11d2, {0xab, 0xe1, 0x00, 0xa0, 0xc9, 0x11, 0xf5, 0x18}};
const GUID kProcessGuid = {
    0x3d6fa8d0, 0xfe05, 0x11d0, {0x9d, 0xda, 0x00, 0xc0, 0x4f, 0xd7, 0xba, 0x7c}};
const GUID kFileIoGuid = {
    0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};

// Event types (opcodes) inside the kernel's Thread event class.
constexpr UCHAR kOpThreadStart = 1;
constexpr UCHAR kOpThreadEnd = 2;
constexpr UCHAR kOpThreadDcStart = 3;  // "already running when the trace started"
constexpr UCHAR kOpCSwitch = 36;
constexpr UCHAR kOpReadyThread = 50;
constexpr UCHAR kOpStackWalk = 32;     // inside the StackWalk class
constexpr UCHAR kOpThreadSetName = 72;  // a thread named itself (W38)
constexpr UCHAR kOpProcessStart = 1;   // inside the Process class (W33)
constexpr UCHAR kOpProcessDcStart = 3;  // inside the Process class: running when the trace started
constexpr UCHAR kOpImageDcStart = 3;   // inside the Image class: loaded when the trace started
constexpr UCHAR kOpImageLoad = 10;     // inside the Image class: loaded during the trace
// Inside the FileIo class (W28): names of file objects, and the requests on them.
constexpr UCHAR kOpFileName = 0;
constexpr UCHAR kOpFileCreateName = 32;
constexpr UCHAR kOpFileRundown = 36;
constexpr UCHAR kOpFileCreate = 64;    // 64-75 and 77: a request starts (create, read, write, ...)
constexpr UCHAR kOpFileOpEnd = 76;     // a request has finished

constexpr int kTraceStackTracingInfo = 3;  // TRACE_INFO_CLASS value

// Exit codes, so that scripts and CI can tell the failures apart.
constexpr int kExitOk = 0;
constexpr int kExitUsage = 1;             // bad arguments, or the program cannot be found
constexpr int kExitTraceUnavailable = 2;  // the kernel trace session could not be started
constexpr int kExitWorse = 3;             // waitwhy diff: worse than allowed (W35)

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
  wchar_t logFile[1024];  // waitwhy record (W38): the .etl file the session writes
};

// UTF-16 to UTF-8.
std::string Narrow(const std::wstring& w) {
  if (w.empty()) return {};
  int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), nullptr, 0,
                              nullptr, nullptr);
  std::string s(static_cast<size_t>(n), '\0');
  WideCharToMultiByte(CP_UTF8, 0, w.c_str(), static_cast<int>(w.size()), &s[0], n, nullptr,
                      nullptr);
  return s;
}

// "\Device\HarddiskVolume3\x\y.dll" -> "C:\x\y.dll", "\SystemRoot\..." -> "C:\Windows\...".
std::wstring DosPath(const std::wstring& path) {
  if (path.rfind(L"\\??\\", 0) == 0) return path.substr(4);
  if (path.rfind(L"\\SystemRoot\\", 0) == 0) {
    wchar_t windows[MAX_PATH];
    const UINT n = GetWindowsDirectoryW(windows, MAX_PATH);
    if (n > 0 && n < MAX_PATH) return std::wstring(windows, n) + path.substr(11);
  }
  for (wchar_t drive = L'A'; drive <= L'Z'; ++drive) {
    const wchar_t name[3] = {drive, L':', L'\0'};
    wchar_t device[MAX_PATH];
    if (!QueryDosDeviceW(name, device, MAX_PATH)) continue;
    const std::wstring prefix = std::wstring(device) + L"\\";
    if (path.size() > prefix.size() && _wcsnicmp(path.c_str(), prefix.c_str(), prefix.size()) == 0)
      return std::wstring(name) + path.substr(prefix.size() - 1);
  }
  return path;
}

// ---------------------------------------------------------------------------
// Decoding: kernel events -> typed events for the analysis core (analysis.h)
// ---------------------------------------------------------------------------

Analyzer g_analysis;
std::vector<uint32_t> g_cpuThread(256, kUnknownThread);  // thread currently on each CPU
// Reading a recorded .etl file (W38): nothing may be asked of the live system, whose processes
// and threads may be others with the same IDs.
bool g_fromTraceFile = false;
// --no-suspend (W45, D13): no stack snapshots, which pause the program's threads for a moment.
bool g_noSuspend = false;
// --redact (W47): no folder paths, user or machine names in the report, dump or exports.
bool g_redact = false;
Redactor g_redactor;
std::string Redacted(const std::string& path) { return g_redact ? g_redactor.Paths(path) : path; }
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

// A property of an event, found through TDH by its name whatever its place, as raw bytes;
// empty when the event has none (W38).
std::vector<BYTE> EventProperty(const EVENT_RECORD* ev, const wchar_t* name) {
  PROPERTY_DATA_DESCRIPTOR d{};
  d.PropertyName = reinterpret_cast<ULONGLONG>(name);
  d.ArrayIndex = ULONG_MAX;
  ULONG size = 0;
  auto* record = const_cast<PEVENT_RECORD>(ev);
  if (TdhGetPropertySize(record, 0, nullptr, 1, &d, &size) != ERROR_SUCCESS || size == 0) return {};
  std::vector<BYTE> bytes(size);
  if (TdhGetProperty(record, 0, nullptr, 1, &d, size, bytes.data()) != ERROR_SUCCESS) return {};
  return bytes;
}

// Names the program's threads gave themselves, from a recorded trace's thread events (W38).
std::map<uint32_t, std::string> g_traceThreadNames;

void RememberTraceThreadName(const EVENT_RECORD* ev, uint32_t tid) {
  const std::vector<BYTE> bytes = EventProperty(ev, L"ThreadName");
  std::wstring name;
  for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
    const auto ch = static_cast<wchar_t>(bytes[i] | (bytes[i + 1] << 8));
    if (ch == L'\0') break;
    name += ch;
  }
  if (!name.empty()) g_traceThreadNames[tid] = Narrow(name);
}

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
  if (g_fromTraceFile && kind != ThreadEvent::Kind::Ended && g_analysis.IsWatched(e.pid))
    RememberTraceThreadName(ev, e.tid);
  if (g_dump && g_analysis.IsWatched(e.pid)) {
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

// A module the program had loaded, from the kernel's image events (W26). With these, function
// names can still be found after the program has exited.
struct ImageInfo {
  uint64_t base = 0;
  uint64_t size = 0;
  std::wstring path;  // as the kernel names it, e.g. \Device\HarddiskVolume3\...\ntdll.dll
};
std::map<uint32_t, std::vector<ImageInfo>> g_images;  // by process
// What the first pass over a recorded trace found (W38), from start, end and rundown
// events alike, since a circular trace keeps only its last part: the processes in the order
// first seen (ID -> file name, parent), every thread's process, and every process's modules.
std::map<uint32_t, std::string> g_traceProcessNames;
std::vector<uint32_t> g_traceProcessOrder;
std::map<uint32_t, uint32_t> g_traceParents;
struct TraceThread {
  uint32_t pid = 0;
  uint64_t endedAt = 0;  // 0: still running at the end of the trace
};
std::map<uint32_t, TraceThread> g_traceThreads;
std::map<uint32_t, std::vector<ImageInfo>> g_traceImages;
uint64_t g_traceFirstTs = 0;  // the earliest event the file still holds
uint64_t g_traceStackWalks = 0;  // its StackWalk events: whether it has call stacks at all

// Image_Load (versions 2 and 3, also its rundowns): ImageBase, ImageSize (pointers), ProcessId,
// ImageCheckSum, TimeDateStamp, a 32-bit field, DefaultBase (pointer), four reserved 32-bit
// fields, then the file name as a null-terminated UTF-16 string. With `watchedOnly`, the name
// is only read for the program's processes.
bool ParseImage(const EVENT_RECORD* ev, bool watchedOnly, uint32_t* pid, ImageInfo* image) {
  const size_t ptr = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  const size_t nameAt = 3 * ptr + 32;
  if (ev->UserDataLength < nameAt + sizeof(wchar_t)) return false;
  const auto* p = static_cast<const uint8_t*>(ev->UserData);
  std::memcpy(pid, p + 2 * ptr, sizeof *pid);
  if (watchedOnly && !g_analysis.IsWatched(*pid)) return false;
  std::memcpy(&image->base, p, ptr);
  std::memcpy(&image->size, p + ptr, ptr);
  for (size_t at = nameAt; at + sizeof(wchar_t) <= ev->UserDataLength; at += sizeof(wchar_t)) {
    wchar_t ch;
    std::memcpy(&ch, p + at, sizeof ch);
    if (ch == L'\0') break;
    image->path += ch;
  }
  return true;
}

void OnImage(const EVENT_RECORD* ev) {
  uint32_t pid = 0;
  ImageInfo image;
  if (!ParseImage(ev, true, &pid, &image)) return;
  if (g_dump) {
    std::fprintf(g_dump, "IMAGE ts=%llu base=0x%llx size=0x%llx name=%s\n",
                 static_cast<unsigned long long>(ev->EventHeader.TimeStamp.QuadPart),
                 static_cast<unsigned long long>(image.base),
                 static_cast<unsigned long long>(image.size), Redacted(Narrow(image.path)).c_str());
    ++g_dumpLines;
  }
  g_images[pid].push_back(std::move(image));
}

// --children (W33, D9): processes the program starts are watched too. The event thread adds
// them; the main thread reads the list under this lock (for thread names while watching).
bool g_followChildren = false;
std::mutex g_childrenLock;
std::vector<uint32_t> g_children;

// Where the fields of one kind of kernel event sit, found through TDH by their names, because
// the layouts differ between event versions (W28, W33). Fields after the first string have no
// fixed place and are left out; a string's size is 0.
struct EventFields {
  bool ok = false;
  std::map<std::wstring, std::pair<int, size_t>> at;  // name -> offset, size
  int Offset(const wchar_t* name) const {
    auto it = at.find(name);
    return it == at.end() ? -1 : it->second.first;
  }
  size_t Size(const wchar_t* name) const {
    auto it = at.find(name);
    return it == at.end() ? 0 : it->second.second;
  }
};

EventFields FindEventFields(PEVENT_RECORD ev) {
  // TDH_IN_TYPE values (tdh.h); not every SDK header names them.
  enum : USHORT { kInUnicodeString = 1, kInInt8 = 3, kInUInt8 = 4, kInInt16 = 5, kInUInt16 = 6,
                  kInInt32 = 7, kInUInt32 = 8, kInInt64 = 9, kInUInt64 = 10, kInBoolean = 13,
                  kInPointer = 16, kInFiletime = 17, kInHexInt32 = 20, kInHexInt64 = 21 };
  EventFields fields;
  ULONG size = 0;
  if (TdhGetEventInformation(ev, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER) return fields;
  std::vector<unsigned char> buffer(size);
  auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
  if (TdhGetEventInformation(ev, 0, nullptr, info, &size) != ERROR_SUCCESS) return fields;
  const size_t ptr = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  size_t offset = 0;
  for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
    const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
    if ((p.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) || p.count > 1) break;
    size_t fieldSize = 0;
    switch (p.nonStructType.InType) {
      case kInInt8: case kInUInt8: fieldSize = 1; break;
      case kInInt16: case kInUInt16: fieldSize = 2; break;
      case kInInt32: case kInUInt32: case kInBoolean: case kInHexInt32: fieldSize = 4; break;
      case kInInt64: case kInUInt64: case kInFiletime: case kInHexInt64: fieldSize = 8; break;
      case kInPointer: fieldSize = ptr; break;
      case kInUnicodeString: fieldSize = 0; break;  // runs to its terminating null
      default: i = info->TopLevelPropertyCount; continue;  // anything else: stop here
    }
    fields.at[reinterpret_cast<const wchar_t*>(buffer.data() + p.NameOffset)] = {static_cast<int>(offset), fieldSize};
    if (fieldSize == 0) break;  // nothing after a string has a fixed place
    offset += fieldSize;
  }
  fields.ok = true;
  return fields;
}

const EventFields& EventFieldsOf(PEVENT_RECORD ev) {
  static std::map<std::tuple<uint64_t, uint64_t, UCHAR, UCHAR, bool>, EventFields> cache;
  uint64_t guid[2];
  std::memcpy(guid, &ev->EventHeader.ProviderId, sizeof guid);
  const auto key = std::make_tuple(guid[0], guid[1], ev->EventHeader.EventDescriptor.Opcode,
                                   ev->EventHeader.EventDescriptor.Version,
                                   (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0);
  auto it = cache.find(key);
  if (it == cache.end()) it = cache.emplace(key, FindEventFields(ev)).first;
  return it->second;
}

// Where the fields W28 needs sit in one kind of FileIo event. -1: the event has no such field.
struct FileIoLayout {
  bool ok = false;
  int irp = -1, fileObject = -1, ttid = -1, name = -1;
  size_t ttidSize = 4;
};

const FileIoLayout& FileIoLayoutOf(PEVENT_RECORD ev) {
  static std::map<std::tuple<UCHAR, UCHAR, bool>, FileIoLayout> layouts;
  const auto key = std::make_tuple(ev->EventHeader.EventDescriptor.Opcode,
                                   ev->EventHeader.EventDescriptor.Version,
                                   (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0);
  auto it = layouts.find(key);
  if (it != layouts.end()) return it->second;
  const EventFields& f = EventFieldsOf(ev);
  FileIoLayout layout;
  layout.ok = f.ok;
  layout.irp = f.Offset(L"IrpPtr");
  layout.fileObject = f.Offset(L"FileObject");
  layout.ttid = f.Offset(L"TTID");
  layout.ttidSize = f.Size(L"TTID");
  for (const wchar_t* name : {L"FileName", L"OpenPath"})
    if (f.Offset(name) >= 0 && f.Size(name) == 0) layout.name = f.Offset(name);
  return layouts.emplace(key, layout).first->second;
}

void DumpFileName(uint64_t fileObject, const Analyzer::FileName& f) {
  if (!g_dump) return;
  std::fprintf(g_dump, "FILENAME fileObject=0x%llx kind=%d name=%s\n",
               static_cast<unsigned long long>(fileObject), static_cast<int>(f.kind), Redacted(f.path).c_str());
  ++g_dumpLines;
}

// File I/O of the program's threads, and the names of the file objects it used (W28).
void OnFileIo(PEVENT_RECORD ev, UCHAR op) {
  const FileIoLayout& layout = FileIoLayoutOf(ev);
  if (!layout.ok) return;
  const auto* p = static_cast<const uint8_t*>(ev->UserData);
  const size_t length = ev->UserDataLength;
  const size_t ptr = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  auto read = [&](int at, size_t bytes) -> uint64_t {
    uint64_t v = 0;
    if (at >= 0 && static_cast<size_t>(at) + bytes <= length) std::memcpy(&v, p + at, bytes);
    return v;
  };
  auto readName = [&]() {
    std::wstring name;
    if (layout.name < 0) return name;
    for (size_t at = static_cast<size_t>(layout.name); at + sizeof(wchar_t) <= length; at += sizeof(wchar_t)) {
      wchar_t ch;
      std::memcpy(&ch, p + at, sizeof ch);
      if (ch == L'\0') break;
      name += ch;
    }
    return name;
  };
  auto nameEvent = [&](uint64_t fileObject, const std::wstring& ntPath) {
    FileIoEvent e;
    e.op = FileIoEvent::Op::Name;
    e.fileObject = fileObject;
    e.kind = KindOfPath(Narrow(ntPath));
    e.path = Narrow(DosPath(ntPath));
    return e;
  };
  const auto ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);

  if (op == kOpFileName || op == kOpFileCreateName || op == kOpFileRundown) {
    const uint64_t fileObject = read(layout.fileObject, ptr);
    const std::wstring ntPath = readName();
    if (!fileObject || ntPath.empty()) return;
    const FileIoEvent e = nameEvent(fileObject, ntPath);
    if (g_analysis.OnFileIo(e)) DumpFileName(fileObject, *g_analysis.FileOf(fileObject));
    return;
  }
  FileIoEvent e;
  e.ts = ts;
  e.irp = read(layout.irp, ptr);
  if (!e.irp) return;
  if (op == kOpFileOpEnd) {
    e.op = FileIoEvent::Op::End;
    if (g_analysis.OnFileIo(e) && g_dump) {
      std::fprintf(g_dump, "FILEIO ts=%llu op=1 irp=0x%llx\n", static_cast<unsigned long long>(ts),
                   static_cast<unsigned long long>(e.irp));
      ++g_dumpLines;
    }
    return;
  }
  e.op = FileIoEvent::Op::Begin;
  e.fileObject = read(layout.fileObject, ptr);
  e.tid = layout.ttid >= 0 ? static_cast<uint32_t>(read(layout.ttid, layout.ttidSize))
                           : static_cast<uint32_t>(ev->EventHeader.ThreadId);
  if (!e.fileObject || PastWindow(ts)) return;
  const bool knewName = g_analysis.FileOf(e.fileObject) && !g_analysis.FileOf(e.fileObject)->path.empty();
  if (!g_analysis.OnFileIo(e)) return;
  if (g_dump) {
    std::fprintf(g_dump, "FILEIO ts=%llu op=0 tid=%u irp=0x%llx fileObject=0x%llx\n",
                 static_cast<unsigned long long>(ts), e.tid, static_cast<unsigned long long>(e.irp),
                 static_cast<unsigned long long>(e.fileObject));
    ++g_dumpLines;
  }
  // A create names its file. A name seen before the program used the file (the rundown of
  // files already open) is taken over now; the dump gets it here so a replay matches.
  if (op == kOpFileCreate && layout.name >= 0) {
    const std::wstring ntPath = readName();
    if (!ntPath.empty() && g_analysis.OnFileIo(nameEvent(e.fileObject, ntPath)))
      DumpFileName(e.fileObject, *g_analysis.FileOf(e.fileObject));
  } else if (!knewName && g_analysis.FileOf(e.fileObject) && !g_analysis.FileOf(e.fileObject)->path.empty()) {
    DumpFileName(e.fileObject, *g_analysis.FileOf(e.fileObject));
  }
}

void OnProcessStart(PEVENT_RECORD ev) {
  if (!g_followChildren) return;
  const auto ts = static_cast<uint64_t>(ev->EventHeader.TimeStamp.QuadPart);
  if (PastWindow(ts)) return;
  const EventFields& f = EventFieldsOf(ev);
  const int childAt = f.Offset(L"ProcessId"), parentAt = f.Offset(L"ParentId");
  if (!f.ok || childAt < 0 || parentAt < 0 ||
      static_cast<size_t>((std::max)(childAt, parentAt)) + 4 > ev->UserDataLength)
    return;
  uint32_t child = 0, parent = 0;
  std::memcpy(&child, static_cast<const uint8_t*>(ev->UserData) + childAt, sizeof child);
  std::memcpy(&parent, static_cast<const uint8_t*>(ev->UserData) + parentAt, sizeof parent);
  if (!g_analysis.IsWatched(parent) || g_analysis.IsWatched(child)) return;
  g_analysis.otherPids.insert(child);
  {
    std::lock_guard<std::mutex> lock(g_childrenLock);
    g_children.push_back(child);
  }
  if (g_dump) {
    std::fprintf(g_dump, "CHILD ts=%llu pid=%u parent=%u\n", static_cast<unsigned long long>(ts), child, parent);
    ++g_dumpLines;
  }
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
    } else if (op == kOpThreadSetName && g_fromTraceFile && ev->UserDataLength >= 8) {
      uint32_t pid = 0, tid = 0;
      std::memcpy(&pid, ev->UserData, sizeof pid);
      std::memcpy(&tid, static_cast<const uint8_t*>(ev->UserData) + 4, sizeof tid);
      if (g_analysis.IsWatched(pid)) RememberTraceThreadName(ev, tid);
    }
  } else if (IsEqualGUID(h.ProviderId, kStackWalkGuid) && op == kOpStackWalk) {
    OnStackWalk(ev);
  } else if (IsEqualGUID(h.ProviderId, kImageGuid) && (op == kOpImageLoad || op == kOpImageDcStart)) {
    OnImage(ev);
  } else if (IsEqualGUID(h.ProviderId, kFileIoGuid)) {
    OnFileIo(ev, op);
  } else if (IsEqualGUID(h.ProviderId, kProcessGuid) && op == kOpProcessStart) {
    OnProcessStart(ev);
  }
}

// The first pass over a recorded trace (W38): its processes, threads and modules.
constexpr UCHAR kOpDcEnd = 4;  // Process, Thread and Image classes: still there when the trace ended

void WINAPI OnTraceListEvent(PEVENT_RECORD ev) {
  const EVENT_HEADER& h = ev->EventHeader;
  const UCHAR op = h.EventDescriptor.Opcode;
  const auto ts = static_cast<uint64_t>(h.TimeStamp.QuadPart);
  if (g_traceFirstTs == 0 || ts < g_traceFirstTs) g_traceFirstTs = ts;
  const auto* data = static_cast<const uint8_t*>(ev->UserData);
  if (IsEqualGUID(h.ProviderId, kStackWalkGuid) && op == kOpStackWalk) {
    ++g_traceStackWalks;
  } else if (IsEqualGUID(h.ProviderId, kThreadGuid)) {
    if ((op != kOpThreadStart && op != kOpThreadDcStart && op != kOpDcEnd && op != kOpThreadEnd) ||
        ev->UserDataLength < 8)
      return;
    uint32_t pid = 0, tid = 0;
    std::memcpy(&pid, data, sizeof pid);
    std::memcpy(&tid, data + 4, sizeof tid);
    TraceThread& t = g_traceThreads[tid];
    t.pid = pid;
    t.endedAt = op == kOpThreadEnd ? ts : 0;
  } else if (IsEqualGUID(h.ProviderId, kImageGuid)) {
    if (op != kOpImageLoad && op != kOpImageDcStart && op != kOpDcEnd) return;
    uint32_t pid = 0;
    ImageInfo image;
    if (!ParseImage(ev, false, &pid, &image)) return;
    std::vector<ImageInfo>& images = g_traceImages[pid];
    for (const ImageInfo& known : images)
      if (known.base == image.base && known.path == image.path) return;
    images.push_back(std::move(image));
  } else if (IsEqualGUID(h.ProviderId, kProcessGuid)) {
    if (op != kOpProcessStart && op != kOpProcessDcStart && op != kOpDcEnd) return;
    const EventFields& f = EventFieldsOf(ev);
    const int at = f.Offset(L"ProcessId"), parentAt = f.Offset(L"ParentId");
    if (!f.ok || at < 0 || static_cast<size_t>(at) + 4 > ev->UserDataLength) return;
    uint32_t pid = 0;
    std::memcpy(&pid, data + at, sizeof pid);
    if (g_traceProcessNames.count(pid)) return;  // an ID used again later keeps its first process
    if (parentAt >= 0 && static_cast<size_t>(parentAt) + 4 <= ev->UserDataLength) {
      uint32_t parent = 0;
      std::memcpy(&parent, data + parentAt, sizeof parent);
      g_traceParents[pid] = parent;
    }
    const std::vector<BYTE> name = EventProperty(ev, L"ImageFileName");  // an ANSI string
    size_t length = 0;
    while (length < name.size() && name[length] != 0) ++length;
    g_traceProcessNames[pid] = std::string(reinterpret_cast<const char*>(name.data()), length);
    g_traceProcessOrder.push_back(pid);
  }
}

// ---------------------------------------------------------------------------
// Kernel trace session
// ---------------------------------------------------------------------------

// The session being used: a private system-logger session (W31, D10), or the shared
// "NT Kernel Logger" where Windows cannot give one.
std::wstring g_sessionName = kLoggerName;
// waitwhy record --ring (W39): the size of the circular file, in MB; 0 for a file that grows.
ULONG g_ringMb = 0;

void FillProps(SessionProps& sp, bool forStart, bool privateSession = false, const std::wstring& logFile = L"") {
  std::memset(&sp, 0, sizeof sp);
  sp.props.Wnode.BufferSize = sizeof sp;
  sp.props.LoggerNameOffset = offsetof(SessionProps, loggerName);
  if (!forStart) return;
  if (!privateSession) sp.props.Wnode.Guid = kSystemTraceControlGuid;
  sp.props.Wnode.ClientContext = 1;  // timestamps from QueryPerformanceCounter
  sp.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  sp.props.EnableFlags =
      EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER | EVENT_TRACE_FLAG_THREAD |
      EVENT_TRACE_FLAG_PROCESS | EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO |
      EVENT_TRACE_FLAG_DISK_FILE_IO |
      EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT;
  sp.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
  if (!logFile.empty()) {  // waitwhy record (W38): into a file instead
    sp.props.LogFileMode = g_ringMb ? EVENT_TRACE_FILE_MODE_CIRCULAR : EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    sp.props.MaximumFileSize = g_ringMb;
    sp.props.LogFileNameOffset = offsetof(SessionProps, logFile);
    wcsncpy_s(sp.logFile, logFile.c_str(), _TRUNCATE);
  }
  // A system-logger session (Windows 8 and later) gets the kernel's events under a name of its
  // own, so tools using "NT Kernel Logger" keep running.
  if (privateSession) sp.props.LogFileMode |= EVENT_TRACE_SYSTEM_LOGGER_MODE;
  sp.props.BufferSize = 256;  // KB per buffer; context switches are very frequent
  sp.props.MinimumBuffers = 128;
  sp.props.MaximumBuffers = 512;
  sp.props.FlushTimer = 1;
}

ULONG StopSession(const std::wstring& name, SessionProps* out = nullptr) {
  SessionProps sp;
  FillProps(sp, false);
  ULONG rc = ControlTraceW(0, name.c_str(), &sp.props, EVENT_TRACE_CONTROL_STOP);
  if (out) *out = sp;
  return rc;
}

ULONG StopKernelSession(SessionProps* out = nullptr) { return StopSession(g_sessionName, out); }

// Private sessions of a waitwhy that was killed keep running and use up one of the few
// system-logger sessions Windows allows. Stops those whose process is gone (W31).
void StopLeftoverSessions() {
  struct Slot {
    EVENT_TRACE_PROPERTIES props;
    wchar_t logger[1024];
    wchar_t file[1024];
  };
  std::vector<Slot> slots(64);
  std::vector<EVENT_TRACE_PROPERTIES*> list;
  for (Slot& slot : slots) {
    std::memset(&slot, 0, sizeof slot);
    slot.props.Wnode.BufferSize = sizeof slot;
    slot.props.LoggerNameOffset = offsetof(Slot, logger);
    slot.props.LogFileNameOffset = offsetof(Slot, file);
    list.push_back(&slot.props);
  }
  ULONG count = 0;
  if (QueryAllTracesW(list.data(), static_cast<ULONG>(list.size()), &count) != ERROR_SUCCESS) return;
  const size_t prefix = std::wcslen(kPrivatePrefix);
  for (ULONG i = 0; i < count && i < slots.size(); ++i) {
    const std::wstring name = slots[i].logger;
    if (name.compare(0, prefix, kPrivatePrefix) != 0) continue;
    const auto owner = static_cast<DWORD>(std::wcstoul(name.c_str() + prefix, nullptr, 10));
    if (owner == GetCurrentProcessId()) continue;
    HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, owner);
    const bool alive = process && WaitForSingleObject(process, 0) == WAIT_TIMEOUT;
    if (process) CloseHandle(process);
    if (alive) continue;
    if (StopSession(name) == ERROR_SUCCESS)
      std::printf("Note: stopped the trace session %s, left behind by a waitwhy that ended.\n",
                  Narrow(name).c_str());
  }
}

ULONG StartKernelSession(TRACEHANDLE* session, const std::wstring& logFile = L"") {
  StopLeftoverSessions();
  SessionProps sp;
  const std::wstring privateName = kPrivatePrefix + std::to_wstring(GetCurrentProcessId());
  FillProps(sp, true, true, logFile);
  ULONG rc = StartTraceW(session, privateName.c_str(), &sp.props);
  if (rc == ERROR_SUCCESS) {
    g_sessionName = privateName;
    return rc;
  }
  if (rc == ERROR_ACCESS_DENIED) return rc;
  std::printf("Note: a private trace session is not available here (error %lu); using the shared\n"
              "      \"NT Kernel Logger\" session, which stops any other tool that uses it.\n",
              rc);
  g_sessionName = kLoggerName;
  FillProps(sp, true, false, logFile);
  rc = StartTraceW(session, kLoggerName, &sp.props);
  if (rc == ERROR_ALREADY_EXISTS) {
    std::printf("Note: another tool left the kernel trace session running; stopping it first.\n");
    StopKernelSession();
    FillProps(sp, true, false, logFile);
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

std::vector<uint32_t> FindProcessesByName(const std::wstring& name) {
  std::vector<uint32_t> pids;
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) return pids;
  PROCESSENTRY32W pe{};
  pe.dwSize = sizeof pe;
  for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe))
    if (_wcsicmp(pe.szExeFile, name.c_str()) == 0) pids.push_back(pe.th32ProcessID);
  CloseHandle(snap);
  return pids;
}

// The program's process and the others watched with it (W33).
std::vector<uint32_t> WatchedProcesses() {
  std::vector<uint32_t> pids{g_analysis.pid};
  for (uint32_t p : g_analysis.otherPids) pids.push_back(p);
  std::sort(pids.begin() + 1, pids.end());
  return pids;
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

// The description a thread gave itself (SetThreadDescription), or empty.
std::string ThreadDescription(uint32_t tid) {
  using GetDescFn = HRESULT(WINAPI*)(HANDLE, PWSTR*);
  static GetDescFn getDesc = reinterpret_cast<GetDescFn>(reinterpret_cast<void*>(
      GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetThreadDescription")));
  std::string name;
  if (!getDesc) return name;
  HANDLE th = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
  if (!th) return name;
  PWSTR desc = nullptr;
  if (SUCCEEDED(getDesc(th, &desc)) && desc) {
    name = Narrow(desc);
    LocalFree(desc);
  }
  CloseHandle(th);
  return name;
}

// Names of the program's threads, taken while they are alive, so a thread that ended during
// the trace keeps its name in the report (W32: a launched program has usually exited). Only
// the main thread uses it, through a snapshot of the process's own threads.
std::unordered_map<uint32_t, std::string> g_threadNames;

void RememberThreadNames(uint32_t pid) {
  HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) return;
  THREADENTRY32 te{};
  te.dwSize = sizeof te;
  for (BOOL ok = Thread32First(snap, &te); ok; ok = Thread32Next(snap, &te)) {
    if (te.th32OwnerProcessID != pid) continue;
    const std::string name = ThreadDescription(te.th32ThreadID);
    if (!name.empty()) g_threadNames[te.th32ThreadID] = name;
  }
  CloseHandle(snap);
}

std::string ThreadLabel(uint32_t tid) {
  static std::unordered_map<uint32_t, std::string> cache;
  auto it = cache.find(tid);
  if (it != cache.end()) return it->second;
  std::string label = "Thread " + std::to_string(tid);
  auto remembered = g_threadNames.find(tid);
  // An ended thread's ID may already belong to another thread, so only the name taken while it
  // was alive is used.
  if (g_analysis.exitedThreads.count(tid)) {
    if (remembered != g_threadNames.end()) return cache[tid] = label + " (" + remembered->second + ", exited)";
    return cache[tid] = label + " (exited)";
  }
  std::string name = g_fromTraceFile ? std::string() : ThreadDescription(tid);
  if (name.empty() && remembered != g_threadNames.end()) name = remembered->second;
  if (!name.empty()) label += " (" + name + ")";
  return cache[tid] = label;
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
  for (uint32_t process : WatchedProcesses()) {
    HANDLE proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, process);
    if (!proc) continue;
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS);
    if (!SymInitializeW(proc, nullptr, TRUE)) {
      CloseHandle(proc);
      continue;
    }
    for (uint32_t tid : g_analysis.targetThreads) {
      if (g_analysis.ProcessOf(tid) != process || !g_analysis.NeedsSnapshot(tid)) continue;
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
}

// --symbols: "ms" for Microsoft's public symbol server, or a DbgHelp symbol path (W27).
std::wstring g_symbolsOption;

// Where DbgHelp looks for .pdb files: the program's own folder first, then what --symbols or
// _NT_SYMBOL_PATH say. "ms" downloads Windows' symbols once and keeps them in a local cache.
std::wstring SymbolSearchPath(const std::wstring& exeDir) {
  std::wstring extra;
  if (_wcsicmp(g_symbolsOption.c_str(), L"ms") == 0) {
    wchar_t local[MAX_PATH];
    const DWORD n = GetEnvironmentVariableW(L"LOCALAPPDATA", local, MAX_PATH);
    const std::wstring cache =
        (n > 0 && n < MAX_PATH ? std::wstring(local, n) : std::wstring(L".")) + L"\\waitwhy\\symbols";
    extra = L"srv*" + cache + L"*https://msdl.microsoft.com/download/symbols";
  } else if (!g_symbolsOption.empty()) {
    extra = g_symbolsOption;
  } else {
    wchar_t env[4096];
    const DWORD n = GetEnvironmentVariableW(L"_NT_SYMBOL_PATH", env, 4096);
    if (n > 0 && n < 4096) extra.assign(env, n);
  }
  std::wstring path = exeDir;
  if (!extra.empty()) path += (path.empty() ? L"" : L";") + extra;
  return path;
}

// A symbol server path needs symsrv.dll beside the dbghelp.dll in use; Windows' own copy in
// System32 has none. Returns a note when the download cannot work, empty otherwise.
std::string SymbolServerNote(const std::wstring& path) {
  if (Lower(Narrow(path)).find("srv*") == std::string::npos) return {};
  wchar_t dbghelp[MAX_PATH] = L"";
  const HMODULE m = GetModuleHandleW(L"dbghelp.dll");
  if (!m || !GetModuleFileNameW(m, dbghelp, MAX_PATH)) return {};
  std::wstring folder = dbghelp;
  folder.resize(folder.find_last_of(L"\\") + 1);
  if (GetFileAttributesW((folder + L"symsrv.dll").c_str()) != INVALID_FILE_ATTRIBUTES) return {};
  return "Note: Windows symbols cannot be downloaded: " + Narrow(dbghelp) +
         " has no symsrv.dll beside it.\n      Put dbghelp.dll and symsrv.dll from the Windows SDK "
         "(Debuggers\\x64) next to waitwhy.exe.\n";
}

class Symbolizer : public SymbolSource {
 public:
  // When the program has exited: load the modules it had loaded, at the addresses they had,
  // from the kernel's image events (W26).
  bool InitFromImages(const std::vector<ImageInfo>& images, uint32_t pid) {
    if (images.empty()) return false;
    // Any value unique to this process's session; DbgHelp only uses it as a key.
    proc_ = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x57a170000ull + pid));
    ownsHandle_ = false;
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_LOAD_LINES);
    if (!SymInitializeW(proc_, nullptr, FALSE)) return false;
    ok_ = true;
    std::wstring exeDir;
    for (const ImageInfo& image : images) {
      const std::wstring dos = DosPath(image.path);
      const size_t slash = dos.find_last_of(L"\\/");
      const std::wstring file = slash == std::wstring::npos ? dos : dos.substr(slash + 1);
      if (file.size() > 4 && _wcsicmp(file.c_str() + file.size() - 4, L".exe") == 0 && exeFile_.empty()) {
        exeFile_ = Narrow(file);
        exePath_ = dos;
        exeModule_ = Lower(Narrow(file.substr(0, file.size() - 4)));
        if (slash != std::wstring::npos) exeDir = dos.substr(0, slash);
      }
    }
    searchPath_ = SymbolSearchPath(exeDir);
    if (!searchPath_.empty()) SymSetSearchPathW(proc_, searchPath_.c_str());
    for (const ImageInfo& image : images)
      SymLoadModuleExW(proc_, nullptr, DosPath(image.path).c_str(), nullptr, image.base,
                       static_cast<DWORD>(image.size), nullptr, 0);
    fromImages_ = true;
    return true;
  }
  bool FromImages() const { return fromImages_; }
  bool Ok() const { return ok_; }
  const std::wstring& SearchPath() const { return searchPath_; }

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
      exePath_ = p;
    }
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS |
                  SYMOPT_LOAD_LINES);
    const size_t slash = exePath_.find_last_of(L"\\/");
    searchPath_ = SymbolSearchPath(slash == std::wstring::npos ? L"" : exePath_.substr(0, slash));
    ok_ = SymInitializeW(proc_, searchPath_.empty() ? nullptr : searchPath_.c_str(), TRUE) != FALSE;
    if (!ok_) {
      CloseHandle(proc_);
      proc_ = nullptr;
    }
    return ok_;
  }

  // A .pdb with the program's name next to it, if there is one (W26): when the report finds
  // no full names for the program anyway, that .pdb does not match the .exe.
  std::string PdbNextToExe() const {
    const size_t dot = exePath_.find_last_of(L'.');
    if (exePath_.empty() || dot == std::wstring::npos) return {};
    const std::wstring pdb = exePath_.substr(0, dot) + L".pdb";
    const DWORD attributes = GetFileAttributesW(pdb.c_str());
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY)) return {};
    return Narrow(pdb);
  }
  ~Symbolizer() {
    if (ok_) SymCleanup(proc_);
    if (proc_ && ownsHandle_) CloseHandle(proc_);
  }

  // Returns "module!function", or "module!0x1234" when no name is available.
  const std::string& Name(uint64_t addr) override {
    auto it = names_.find(addr);
    if (it != names_.end()) return it->second;
    std::string module = "?";
    std::string result;
    if (ok_) {
      alignas(SYMBOL_INFOW) unsigned char buf[sizeof(SYMBOL_INFOW) + 512 * sizeof(wchar_t)] = {};
      auto* si = reinterpret_cast<SYMBOL_INFOW*>(buf);
      si->SizeOfStruct = sizeof(SYMBOL_INFOW);
      si->MaxNameLen = 512;
      DWORD64 disp = 0;
      const bool named = SymFromAddrW(proc_, addr, &disp, si) != FALSE;
      // Asked after SymFromAddrW, which loads deferred symbols, so SymType is final.
      IMAGEHLP_MODULEW64 mi{};
      mi.SizeOfStruct = sizeof mi;
      if (SymGetModuleInfoW64(proc_, addr, &mi)) {
        module = Narrow(mi.ModuleName);
        kinds_[module] = KindOf(mi.SymType);
      }
      if (named) result = module + "!" + Narrow(si->Name);
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

  SymbolKind ModuleSymbols(const std::string& module) const override {
    auto it = kinds_.find(module);
    return it == kinds_.end() ? SymbolKind::Unknown : it->second;
  }
  const std::map<std::string, SymbolKind>& ModuleKinds() const { return kinds_; }

  bool IsExeFrame(const std::string& name) const override {
    size_t bang = name.find('!');
    return bang != std::string::npos && Lower(name.substr(0, bang)) == exeModule_;
  }
  const std::string& ExeFile() const { return exeFile_; }

 private:
  HANDLE proc_ = nullptr;
  bool ownsHandle_ = true;
  std::wstring exePath_;
  std::wstring searchPath_;
  bool fromImages_ = false;
  bool ok_ = false;
  std::string exeModule_;
  std::string exeFile_;
  std::unordered_map<uint64_t, std::string> names_;
  std::unordered_map<uint64_t, std::string> files_;
  std::map<std::string, SymbolKind> kinds_;  // modules named so far

  static SymbolKind KindOf(SYM_TYPE type) {
    switch (type) {
      case SymPdb: case SymDia: case SymCv: case SymSym: case SymCoff: return SymbolKind::Full;
      case SymExport: return SymbolKind::ExportsOnly;
      default: return SymbolKind::None;
    }
  }
};

// ---------------------------------------------------------------------------
// Turning stacks into plain English (the rules live in analysis.h)
// ---------------------------------------------------------------------------

// Names the processes of the threads outside the program that woke it (W28), for the report.
void NameWakerProcesses() {
  Analyzer& an = g_analysis;
  for (const auto& [key, b] : an.buckets) {
    for (const auto& [waker, ticks] : b.wakers) {
      (void)ticks;
      auto it = an.threadProcess.find(waker);
      if (an.IsProgramThread(waker) || it == an.threadProcess.end()) continue;
      const uint32_t owner = it->second;
      if (an.processNames.count(owner)) continue;
      std::string label = owner == Analyzer::kSystemProcess ? "System" : "";
      if (g_fromTraceFile) {
        auto named = g_traceProcessNames.find(owner);
        if (named != g_traceProcessNames.end() && label.empty()) label = named->second;
      } else if (HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner)) {
        wchar_t path[MAX_PATH];
        DWORD len = MAX_PATH;
        if (QueryFullProcessImageNameW(process, 0, path, &len)) {
          const std::wstring full(path, len);
          const size_t slash = full.find_last_of(L"\\/");
          label = Narrow(slash == std::wstring::npos ? full : full.substr(slash + 1));
        }
        CloseHandle(process);
      }
      an.processNames[owner] = label;
    }
  }
}

// Ends a dump with every name the report uses (W18), so the report can be rebuilt from the
// dump alone: the program's file, each address in a wait's stack, and the thread labels.
using SymbolizerFor = std::function<Symbolizer&(uint32_t pid)>;

void WriteDumpNames(FILE* out, const SymbolizerFor& symbolsFor, bool symbolsOk, const ThreadNamer& namer) {
  const Analyzer& an = g_analysis;
  Symbolizer& primary = symbolsFor(an.pid);
  std::fprintf(out, "NAMES symbolsOk=%d fromTrace=%d\n", symbolsOk ? 1 : 0, primary.FromImages() ? 1 : 0);
  const std::string pdb = primary.PdbNextToExe();
  if (!pdb.empty()) std::fprintf(out, "PDB file=%s\n", Redacted(pdb).c_str());
  // With several processes every name says whose it is (W33).
  const bool several = !an.otherPids.empty();
  for (uint32_t process : WatchedProcesses()) {
    Symbolizer& sym = symbolsFor(process);
    char tag[32] = "";
    if (several) std::snprintf(tag, sizeof tag, "pid=%u ", process);
    if (!sym.ExeFile().empty()) std::fprintf(out, "EXE %sname=%s\n", tag, sym.ExeFile().c_str());
    std::map<uint64_t, bool> addrs;  // sorted, so dumps of the same run compare equal
    for (const auto& [key, b] : an.buckets)
      if (an.ProcessOf(b.tid) == process)
        for (uint64_t a : b.stack) addrs[a] = true;
    for (const auto& [addr, unused] : addrs) {
      (void)unused;
      std::fprintf(out, "SYMBOL %saddr=0x%llx name=%s\n", tag, static_cast<unsigned long long>(addr),
                   sym.Name(addr).c_str());
      const std::string& file = sym.SourceFile(addr);
      if (!file.empty())
        std::fprintf(out, "SOURCE %saddr=0x%llx file=%s\n", tag, static_cast<unsigned long long>(addr),
                     (g_redact ? g_redactor.Names(file) : file).c_str());
    }
    for (const auto& [module, kind] : sym.ModuleKinds())
      std::fprintf(out, "MODULE %ssymbols=%s name=%s\n", tag,
                   kind == SymbolKind::Full ? "full" : kind == SymbolKind::ExportsOnly ? "exports" : "none",
                   module.c_str());
  }
  std::map<uint32_t, uint32_t> wakerProcess;  // sorted, like the rest
  for (const auto& [key, b] : an.buckets)
    for (const auto& [waker, ticks] : b.wakers) {
      (void)ticks;
      auto it = an.threadProcess.find(waker);
      if (!an.IsProgramThread(waker) && it != an.threadProcess.end()) wakerProcess[waker] = it->second;
    }
  std::map<uint32_t, bool> processes;
  for (const auto& [waker, owner] : wakerProcess) {
    std::fprintf(out, "THREADPID tid=%u pid=%u\n", waker, owner);
    processes[owner] = true;
  }
  for (const auto& [owner, unused] : processes) {
    (void)unused;
    auto it = an.processNames.find(owner);
    std::fprintf(out, "PROCESS pid=%u name=%s\n", owner, it == an.processNames.end() ? "" : it->second.c_str());
  }
  std::map<uint32_t, bool> tids;
  for (const auto& [tid, st] : an.threads) tids[tid] = true;
  for (uint32_t tid : an.targetThreads) tids[tid] = true;
  for (uint32_t tid : an.exitedThreads) tids[tid] = true;
  for (const auto& [tid, unused] : tids) {
    (void)unused;
    std::fprintf(out, "THREADNAME tid=%u name=%s\n", tid, namer(tid).c_str());
  }
}

// ---------------------------------------------------------------------------
// Report
// ---------------------------------------------------------------------------

// The version (W42). A release build writes version.h with the tag's version; any other build
// is a development build of the next release.
#if __has_include("version.h")
#include "version.h"
#endif
#ifndef WAITWHY_VERSION
#define WAITWHY_VERSION "1.0.0-dev"
#endif
constexpr char kVersion[] = WAITWHY_VERSION;

// --format and --out (W34): the report as text, JSON or HTML (W36), on the console or into a file.
struct Output {
  bool json = false;
  bool html = false;
  std::wstring file;
  std::wstring chromeFile, speedscopeFile;  // --export-chrome, --export-speedscope (W37)
  FILE* console = nullptr;  // where JSON for the console goes; everything else goes to stderr
};
Output g_output;

// JSON (or HTML) on the console must be the only thing there, so a script can parse it: from
// here on every other line waitwhy prints goes to stderr.
void KeepConsoleForJson() {
  if ((!g_output.json && !g_output.html) || !g_output.file.empty()) return;
  std::fflush(stdout);
  const int copy = _dup(_fileno(stdout));
  if (copy < 0) return;
  g_output.console = _fdopen(copy, "w");
  _dup2(_fileno(stderr), _fileno(stdout));
}

int WriteReport(const Report& original, const Analyzer& an, const SymbolsFor& symbols, double ticksPerSecond) {
  Report report = original;
  if (g_redact) RedactReport(report, g_redactor);
  const std::string text = g_output.html   ? RenderHtml(report, an, symbols, ticksPerSecond, kVersion)
                           : g_output.json ? RenderJson(report)
                                           : RenderText(report);
  if (g_output.file.empty()) {
    FILE* out = g_output.console ? g_output.console : stdout;
    std::fputs(text.c_str(), out);
    std::fflush(out);
    return kExitOk;
  }
  FILE* f = nullptr;
  if (_wfopen_s(&f, g_output.file.c_str(), L"wb") != 0 || !f) {
    std::printf("Cannot write the report to %s.\n", Narrow(g_output.file).c_str());
    return kExitUsage;
  }
  std::fputs(text.c_str(), f);
  std::fclose(f);
  std::printf("Wrote the report to %s.\n", Narrow(g_output.file).c_str());
  return kExitOk;
}

bool WriteTextFile(const std::wstring& file, const std::string& text, const char* what) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, file.c_str(), L"wb") != 0 || !f) {
    std::printf("Cannot write %s to %s.\n", what, Narrow(file).c_str());
    return false;
  }
  std::fputs(text.c_str(), f);
  std::fclose(f);
  std::printf("Wrote %s to %s.\n", what, Narrow(file).c_str());
  return true;
}

// --export-chrome and --export-speedscope (W37): the threads' timelines for other viewers.
int WriteExports(const Analyzer& an, const SymbolsFor& symbolsFor, const ThreadNamer& name,
                 double ticksPerSecond, const std::string& program) {
  int code = kExitOk;
  if (!g_output.chromeFile.empty() &&
      !WriteTextFile(g_output.chromeFile, ExportChromeTrace(an, symbolsFor, name, ticksPerSecond, program),
                     "the Chrome trace"))
    code = kExitUsage;
  if (!g_output.speedscopeFile.empty() &&
      !WriteTextFile(g_output.speedscopeFile,
                     ExportSpeedscope(an, symbolsFor, name, ticksPerSecond, program, kVersion),
                     "the speedscope profile"))
    code = kExitUsage;
  return code;
}

// Thread labels; with several processes, threads of the others say which process (W33).
std::string ProgramThreadLabel(uint32_t tid) {
  std::string label = ThreadLabel(tid);
  const uint32_t process = g_analysis.ProcessOf(tid);
  if (!g_analysis.otherPids.empty() && process != g_analysis.pid) label += " [PID " + std::to_string(process) + "]";
  return label;
}

int PrintReport(double ticksPerSecond, ReportOptions opt, const SessionProps& stopped,
                bool stacksOn, const SymbolizerFor& symbolsFor, bool symbolsOk) {
  Symbolizer& sym = symbolsFor(g_analysis.pid);
  opt.ticksPerSecond = ticksPerSecond;
  opt.eventsLost = stopped.props.EventsLost;
  opt.buffersLost = stopped.props.RealTimeBuffersLost;
  opt.stacksOn = stacksOn;
  // Stack snapshots (W45, D13): watch takes them unless --no-suspend; a trace file has none.
  opt.snapshotsOn = !g_noSuspend && !g_fromTraceFile;
  opt.symbolsOk = symbolsOk;
  opt.exeFile = sym.ExeFile();
  // A recorded trace is always named from its modules (W38); that is no news there.
  opt.namesFromTrace = sym.FromImages() && !g_fromTraceFile;
  opt.pdbNextToExe = sym.PdbNextToExe();
  const SymbolsFor symbols([&symbolsFor](uint32_t pid) -> SymbolSource& { return symbolsFor(pid); });
  const Report report = BuildReport(g_analysis, symbols, opt, ProgramThreadLabel);
  const int code = WriteReport(report, g_analysis, symbols, ticksPerSecond);
  const int exported = WriteExports(g_analysis, symbols, ProgramThreadLabel, ticksPerSecond, report.program);
  return code != kExitOk ? code : exported;
}

// Rebuilds the report from a version 2 dump (W18, W19), with no kernel trace and without the
// program: everything it needs, including the names, is in the dump.
int ReportFromDump(const std::wstring& path, ReportOptions opt) {
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
  DumpSymbolsByProcess sym(lines);
  opt.ticksPerSecond = info.ticksPerSecond > 0 ? info.ticksPerSecond : 1e7;
  opt.eventsLost = info.eventsLost;
  opt.buffersLost = info.buffersLost;
  opt.stacksOn = info.stacksOn;
  opt.snapshotsOn = info.snapshotsOn;
  opt.symbolsOk = info.symbolsOk;
  opt.exeFile = info.exeFile;
  opt.namesFromTrace = info.namesFromTrace;
  opt.pdbNextToExe = info.pdbNextToExe;
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  if (!g_output.json && !g_output.html) std::printf("Report rebuilt from %s.\n", Narrow(path).c_str());
  const SymbolsFor symbols(std::ref(sym));
  const Report report = BuildReport(an, symbols, opt, name);
  const int code = WriteReport(report, an, symbols, opt.ticksPerSecond);
  const int exported = WriteExports(an, symbols, name, opt.ticksPerSecond, report.program);
  return code != kExitOk ? code : exported;
}

// ---------------------------------------------------------------------------
// Recorded traces (W38): waitwhy record writes an .etl file, waitwhy analyze reads it
// ---------------------------------------------------------------------------

bool IsTraceFile(const std::wstring& path) {
  return path.size() > 4 && _wcsicmp(path.c_str() + path.size() - 4, L".etl") == 0;
}

// What an .etl file cannot hold is kept beside it, in FILE.etl.waitwhy: the program it was
// recorded for, the window, and the names the program's threads gave themselves.
struct RecordInfo {
  bool found = false;
  uint32_t pid = 0;
  std::vector<uint32_t> others;
  bool children = false;
  uint64_t start = 0, end = 0;
  std::map<uint32_t, std::string> threadNames;
};

std::wstring RecordInfoPath(const std::wstring& etl) { return etl + L".waitwhy"; }

bool WriteRecordInfo(const std::wstring& etl, uint64_t start, uint64_t end) {
  FILE* f = nullptr;
  if (_wfopen_s(&f, RecordInfoPath(etl).c_str(), L"w") != 0 || !f) return false;
  std::fprintf(f, "# waitwhy record: what the trace beside this file was recorded for; waitwhy analyze reads it.\n");
  std::fprintf(f, "RECORD version=1 pid=%u start=%llu end=%llu children=%d\n", g_analysis.pid,
               static_cast<unsigned long long>(start), static_cast<unsigned long long>(end),
               g_followChildren ? 1 : 0);
  for (uint32_t other : g_analysis.otherPids) std::fprintf(f, "WATCH pid=%u\n", other);
  const std::map<uint32_t, std::string> names(g_threadNames.begin(), g_threadNames.end());
  for (const auto& [tid, name] : names) std::fprintf(f, "THREADNAME tid=%u name=%s\n", tid, name.c_str());
  return std::fclose(f) == 0;
}

RecordInfo ReadRecordInfo(const std::wstring& etl) {
  RecordInfo info;
  std::ifstream in(std::filesystem::path(RecordInfoPath(etl)));
  auto field = [](const std::string& line, const std::string& key) -> std::string {
    const std::string k = " " + key + "=";
    size_t at = line.find(k);
    if (at == std::string::npos) return {};
    at += k.size();
    return key == "name" ? line.substr(at) : line.substr(at, line.find(' ', at) - at);
  };
  auto number = [&field](const std::string& line, const char* key) {
    return std::strtoull(field(line, key).c_str(), nullptr, 10);
  };
  std::string line;
  while (std::getline(in, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.compare(0, 7, "RECORD ") == 0) {
      info.found = true;
      info.pid = static_cast<uint32_t>(number(line, "pid"));
      info.start = number(line, "start");
      info.end = number(line, "end");
      info.children = number(line, "children") != 0;
    } else if (line.compare(0, 6, "WATCH ") == 0) {
      info.others.push_back(static_cast<uint32_t>(number(line, "pid")));
    } else if (line.compare(0, 11, "THREADNAME ") == 0) {
      info.threadNames[static_cast<uint32_t>(number(line, "tid"))] = field(line, "name");
    }
  }
  return info;
}

// Reads one .etl file from its start to its end through `callback`.
bool ReadTraceFile(const std::wstring& path, PEVENT_RECORD_CALLBACK callback, TRACE_LOGFILE_HEADER* header,
                   ULONG* error) {
  std::wstring file = path;
  EVENT_TRACE_LOGFILEW logfile{};
  logfile.LogFileName = &file[0];
  logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
  logfile.EventRecordCallback = callback;
  TRACEHANDLE handle = OpenTraceW(&logfile);
  if (handle == INVALID_PROCESSTRACE_HANDLE) {
    *error = GetLastError();
    return false;
  }
  *header = logfile.LogfileHeader;
  *error = ProcessTrace(&handle, 1, nullptr, nullptr);
  CloseTrace(handle);
  return *error == ERROR_SUCCESS;
}

// Raw timestamps count in the clock the trace was recorded with (WNODE_HEADER.ClientContext).
double TraceTicksPerSecond(const TRACE_LOGFILE_HEADER& h) {
  if (h.ReservedFlags == 2) return 1e7;  // system time, in 100 ns
  if (h.ReservedFlags == 3 && h.CpuSpeedInMHz) return h.CpuSpeedInMHz * 1e6;  // CPU cycles
  return h.PerfFreq.QuadPart > 0 ? static_cast<double>(h.PerfFreq.QuadPart) : 1e7;  // QPC
}

// waitwhy analyze FILE.etl: a trace from waitwhy record, or a WPR or xperf trace with context
// switches (and their stacks), through the same decoding and analysis as a live watch.
int AnalyzeTraceFile(const std::wstring& path, ReportOptions opt, uint32_t pid, const std::wstring& name,
                     bool allInstances) {
  g_fromTraceFile = true;
  TRACE_LOGFILE_HEADER header{};
  ULONG error = 0;
  if (!ReadTraceFile(path, OnTraceListEvent, &header, &error)) {
    std::printf("Cannot read the trace %s (error %lu). Is it an .etl file?\n", Narrow(path).c_str(), error);
    return kExitUsage;
  }
  const RecordInfo record = ReadRecordInfo(path);
  std::vector<uint32_t> others;
  if (pid == 0 && name.empty()) {
    if (!record.found) {
      std::printf("%s does not say which program it was recorded for (there is no %s).\n"
                  "Give it with --pid N or --name program.exe.\n",
                  Narrow(path).c_str(), Narrow(RecordInfoPath(path)).c_str());
      return kExitUsage;
    }
    pid = record.pid;
    others = record.others;
    if (record.children) g_followChildren = true;
  } else if (!name.empty()) {
    std::vector<uint32_t> found;
    for (uint32_t p : g_traceProcessOrder)
      if (_stricmp(g_traceProcessNames[p].c_str(), Narrow(name).c_str()) == 0) found.push_back(p);
    if (found.empty()) {
      std::printf("No process named %s is in %s.\n", Narrow(name).c_str(), Narrow(path).c_str());
      return kExitUsage;
    }
    pid = found[0];
    if (allInstances)
      others.assign(found.begin() + 1, found.end());
    else if (found.size() > 1)
      std::printf("Note: %zu processes in the trace are named %s; reporting on PID %u. Use --all for all of\n"
                  "      them, or --pid to choose one.\n",
                  found.size(), Narrow(name).c_str(), pid);
  } else if (!g_traceProcessNames.count(pid)) {
    std::printf("No process with ID %u is in %s.\n", pid, Narrow(path).c_str());
    return kExitUsage;
  }
  g_analysis.pid = pid;
  g_analysis.otherPids.insert(others.begin(), others.end());
  const double ticksPerSecond = TraceTicksPerSecond(header);
  const bool sameProgram = record.found && record.pid == pid;
  if (sameProgram) {
    // The window waitwhy record watched; events before it set the threads' states. A circular
    // trace (WPR in memory mode, for one) may no longer hold its start.
    g_analysis.firstTs = (std::max)(record.start, g_traceFirstTs);
    if (record.end > g_analysis.firstTs && g_traceFirstTs > record.start + static_cast<uint64_t>(ticksPerSecond / 10))
      std::printf("Note: the trace holds only the last %s of the %s recorded (a circular trace keeps its end).\n",
                  FormatDuration(static_cast<double>(record.end - g_analysis.firstTs) / ticksPerSecond).c_str(),
                  FormatDuration(static_cast<double>(record.end - record.start) / ticksPerSecond).c_str());
    g_windowEnd.store(record.end, std::memory_order_relaxed);
    g_threadNames.insert(record.threadNames.begin(), record.threadNames.end());
  }
  // The program's processes and threads are known before the events are read, so the waits of
  // a thread whose start the file no longer holds count too.
  if (g_followChildren)
    for (bool grew = true; grew;) {
      grew = false;
      for (const auto& [child, parent] : g_traceParents)
        if (g_analysis.IsWatched(parent) && !g_analysis.IsWatched(child)) {
          g_analysis.otherPids.insert(child);
          grew = true;
        }
    }
  const uint64_t windowStart = g_analysis.firstTs ? g_analysis.firstTs : g_traceFirstTs;
  for (const auto& [tid, t] : g_traceThreads) {
    g_analysis.threadProcess.emplace(tid, t.pid);
    if (g_analysis.IsWatched(t.pid) && (t.endedAt == 0 || t.endedAt >= windowStart))
      g_analysis.targetThreads.insert(tid);
  }
  // The analysis must know before the first event whether stacks will follow the waits.
  g_analysis.stacksOn = g_traceStackWalks > 0;
  if (!g_analysis.stacksOn)
    std::printf("Note: %s has no call stacks; record with call stacks on context switches for the\n"
                "      functions waits were in (waitwhy record does).\n",
                Narrow(path).c_str());
  if (!ReadTraceFile(path, OnEvent, &header, &error)) {
    std::printf("Cannot read the trace %s (error %lu).\n", Narrow(path).c_str(), error);
    return kExitUsage;
  }
  if (sameProgram && record.end > record.start) g_analysis.lastTs = record.end;
  for (uint32_t process : WatchedProcesses()) g_images[process] = g_traceImages[process];
  for (const auto& [tid, threadName] : g_traceThreadNames) g_threadNames.emplace(tid, threadName);
  const bool stacksOn = g_analysis.stacksOn;
  g_analysis.FlushAtEnd();
  NameWakerProcesses();
  std::map<uint32_t, std::unique_ptr<Symbolizer>> symbolizers;
  auto symbolsFor = [&](uint32_t process) -> Symbolizer& {
    auto it = symbolizers.find(process);
    if (it != symbolizers.end()) return *it->second;
    auto sym = std::make_unique<Symbolizer>();
    sym->InitFromImages(g_images[process], process);
    return *symbolizers.emplace(process, std::move(sym)).first->second;
  };
  Symbolizer& sym = symbolsFor(pid);
  for (uint32_t process : WatchedProcesses()) symbolsFor(process);
  std::fputs(SymbolServerNote(sym.SearchPath()).c_str(), stdout);
  SessionProps lost{};
  lost.props.EventsLost = header.EventsLost;
  lost.props.RealTimeBuffersLost = header.BuffersLost;
  if (!g_output.json && !g_output.html) std::printf("Report from the trace %s.\n", Narrow(path).c_str());
  return PrintReport(ticksPerSecond, opt, lost, stacksOn, symbolsFor, sym.Ok());
}

void Usage() {
  std::printf(
      "waitwhy %s - what is a program waiting for when it is slow but the CPU is idle?\n"
      "\n"
      "Usage:\n"
      "  waitwhy [watch] (--pid N | --name program.exe [--all]) [options]\n"
      "      Watch a running program, then report what its threads were waiting on.\n"
      "      Needs an Administrator shell.\n"
      "  waitwhy [watch] [options] -- program.exe [its arguments]\n"
      "      Start the program and watch it from its first instruction, until it exits\n"
      "      (or for --seconds). Needs an Administrator shell.\n"
      "  waitwhy record --out FILE.etl [watch options] (--pid N | --name X | -- program)\n"
      "      Record the kernel trace into FILE.etl (and FILE.etl.waitwhy) to report on\n"
      "      later, here or on another machine. Needs an Administrator shell.\n"
      "  waitwhy analyze FILE [report options]\n"
      "      Report again from a FILE written by --dump-events, on any machine.\n"
      "      (--from-dump FILE does the same.)\n"
      "  waitwhy analyze FILE.etl [--pid N | --name X [--all]] [--symbols ...] [report options]\n"
      "      Report from a trace written by waitwhy record, or by WPR or xperf with\n"
      "      context switches and their call stacks. Needs no Administrator shell.\n"
      "  waitwhy diff BEFORE.json AFTER.json [--fail-if-worse N]\n"
      "      Compare two JSON reports by activity; with --fail-if-worse, exit with 3\n"
      "      when one got worse by more than N percentage points, or a finding is new.\n"
      "  waitwhy --help | --version\n"
      "\n"
      "Watch options:\n"
      "  --seconds N          how long to watch (default 10)\n"
      "  --children           also watch the processes the program starts\n"
      "  --all                with --name: watch every process of that name\n"
      "  --no-suspend         take no stack snapshot of threads blocked the whole window\n"
      "                       (each pauses that thread for a moment); record never does\n"
      "  --dump-events FILE   also write every event of the program to FILE, and the names\n"
      "                       the report uses; attach it to bug reports\n"
      "  --symbols ms|PATH    ms: download Windows' own symbols from Microsoft (cached in\n"
      "                       %%LOCALAPPDATA%%\\waitwhy\\symbols); PATH: a DbgHelp symbol\n"
      "                       path. Without it, _NT_SYMBOL_PATH is used when set.\n"
      "\n"
      "Record options (waitwhy record):\n"
      "  --out FILE.etl       the trace file to write\n"
      "  --ring N             flight recorder: keep only the last N seconds, and print the\n"
      "                       report on them when stopped by Ctrl+C, --trigger or the\n"
      "                       program's exit (then --seconds is the longest it runs)\n"
      "  --ring-mb N          size of the circular file (default 8 MB per second of --ring,\n"
      "                       at least 64)\n"
      "  --trigger NAME       stop when the named event NAME (e.g. Local\\waitwhy) is set,\n"
      "                       by the program itself or by a script\n"
      "\n"
      "Report options:\n"
      "  --format text|json|html\n"
      "                       the report as text (default), as JSON (its layout is\n"
      "                       docs/report-schema.json) or as one self-contained HTML page\n"
      "                       with a timeline, call stacks and a flame graph\n"
      "  --out FILE           write the report to FILE instead of the console\n"
      "  --export-chrome FILE\n"
      "                       also write each thread's timeline as a Chrome trace, for\n"
      "                       ui.perfetto.dev or chrome://tracing\n"
      "  --export-speedscope FILE\n"
      "                       also write it as a speedscope profile (speedscope.app)\n"
      "  --redact             leave folder paths and the user's and machine's names out of\n"
      "                       the report, the dump and the exports, so they can be shared\n"
      "  --top N              show the N biggest groups of waits (default 6)\n"
      "  --min-ms N           hide groups smaller than N milliseconds (default 10)\n"
      "  --stall-ms N         report any single lock, disk, network or page-fault wait of\n"
      "                       N ms or more (default 50)\n"
      "\n"
      "Exit codes: 0 report printed; 1 bad arguments, or the program or file was not\n"
      "found; 2 the kernel trace could not be started (not Administrator, or unavailable);\n"
      "3 waitwhy diff found it worse than allowed.\n",
      kVersion);
}

// One argument of a command line, quoted the way the C runtime reads it back.
std::wstring QuoteArgument(const std::wstring& arg) {
  if (!arg.empty() && arg.find_first_of(L" \t\"") == std::wstring::npos) return arg;
  std::wstring out = L"\"";
  size_t backslashes = 0;
  for (wchar_t ch : arg) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    out.append(ch == L'"' ? backslashes * 2 + 1 : backslashes, L'\\');
    backslashes = 0;
    out += ch;
  }
  out.append(backslashes * 2, L'\\');
  return out + L"\"";
}

// Every error says what to do next (W30).
int UsageError(const std::string& message) {
  std::printf("%s\nRun 'waitwhy --help' to see the options.\n", message.c_str());
  return kExitUsage;
}

// waitwhy diff BEFORE.json AFTER.json [--fail-if-worse N] (W35): compares two JSON reports by
// activity. With --fail-if-worse it exits with 3 when an activity's share of its thread's time
// grew by more than N points, or a finding is new.
int DiffCommand(int argc, wchar_t** argv) {
  std::vector<std::wstring> files;
  double threshold = -1;
  for (int i = 2; i < argc; ++i) {
    const std::wstring a = argv[i];
    if (a == L"--fail-if-worse") {
      if (i + 1 >= argc) return UsageError("--fail-if-worse needs a number of percentage points, such as 10.");
      wchar_t* end = nullptr;
      threshold = std::wcstod(argv[++i], &end);
      if (end == argv[i] || (*end != L'\0' && std::wcscmp(end, L"%") != 0) || threshold < 0)
        return UsageError("--fail-if-worse needs a number of percentage points, such as 10.");
    } else if (!a.empty() && a[0] == L'-') {
      return UsageError("Unknown option '" + Narrow(a) + "' for waitwhy diff.");
    } else {
      files.push_back(a);
    }
  }
  if (files.size() != 2)
    return UsageError("waitwhy diff needs two JSON reports: the one before and the one after a change.");
  JsonValue reports[2];
  for (size_t k = 0; k < 2; ++k) {
    std::ifstream in(std::filesystem::path(files[k]), std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::string error;
    if (text.empty() || !JsonReader(text).Read(&reports[k], &error) || reports[k].Str("schema") != kReportSchema) {
      std::printf("%s is not a waitwhy JSON report (%s). Make one with --format json --out FILE.\n",
                  Narrow(files[k]).c_str(), text.empty() ? "cannot read it" : error.empty() ? "no schema" : error.c_str());
      return kExitUsage;
    }
  }
  const ReportDiff d = DiffReports(reports[0], reports[1], threshold);
  std::fputs(RenderDiff(d, threshold).c_str(), stdout);
  return d.worse ? kExitWorse : kExitOk;
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
  bool secondsGiven = false;
  bool allInstances = false;  // --all (W33)
  std::vector<std::wstring> launch;  // W32: the program to start, after "--"
  bool recording = false;  // waitwhy record (W38)
  double ringSeconds = 0;  // record --ring (W39): report on the last this many seconds
  double ringMb = 0;       // record --ring-mb: the circular file's size
  std::wstring triggerName;  // record --trigger: a named event that ends the recording
  ReportOptions shown;  // what the report shows: --top, --min-ms, --stall-ms
  // Command line v1 (W30): an optional command first; without one it means watch.
  int first = 1;
  std::wstring command = argc > 1 ? argv[1] : L"";
  if (command == L"--help" || command == L"-h" || command == L"/?" || command == L"help") {
    Usage();
    return kExitOk;
  }
  if (command == L"--version" || command == L"version") {
    std::printf("waitwhy %s\n", kVersion);
    return kExitOk;
  }
  if (command == L"watch") {
    first = 2;
  } else if (command == L"analyze") {
    if (argc < 3 || argv[2][0] == L'-') return UsageError("waitwhy analyze needs the dump FILE to read.");
    fromDump = argv[2];
    first = 3;
  } else if (command == L"diff") {
    return DiffCommand(argc, argv);
  } else if (command == L"record") {
    recording = true;
    first = 2;
  }
  auto number = [](const wchar_t* text, double* value) {
    wchar_t* end = nullptr;
    *value = std::wcstod(text, &end);
    return end != text && *end == L'\0' && *value >= 0;
  };
  for (int i = first; i < argc; ++i) {
    const std::wstring a = argv[i];
    if (a == L"--") {
      launch.assign(argv + i + 1, argv + argc);
      if (launch.empty()) return UsageError("Give the program to start after --.");
      break;
    }
    const bool takesValue = a == L"--pid" || a == L"--name" || a == L"--seconds" || a == L"--top" ||
                            a == L"--min-ms" || a == L"--stall-ms" || a == L"--dump-events" ||
                            a == L"--symbols" || a == L"--from-dump" || a == L"--format" ||
                            a == L"--out" || a == L"--export-chrome" || a == L"--export-speedscope" ||
                            a == L"--ring" || a == L"--ring-mb" || a == L"--trigger";
    if (!takesValue) {
      if (a == L"--help" || a == L"-h") {
        Usage();
        return kExitOk;
      }
      if (a == L"--children") {
        g_followChildren = true;
        continue;
      }
      if (a == L"--no-suspend") {
        g_noSuspend = true;
        continue;
      }
      if (a == L"--redact") {
        g_redact = true;
        for (const wchar_t* variable : {L"USERNAME", L"COMPUTERNAME", L"USERDOMAIN"}) {
          wchar_t value[256];
          const DWORD n = GetEnvironmentVariableW(variable, value, 256);
          if (n > 0 && n < 256) g_redactor.names.push_back(Narrow(std::wstring(value, n)));
        }
        continue;
      }
      if (a == L"--all") {
        allInstances = true;
        continue;
      }
      return UsageError("Unknown option '" + Narrow(a) + "'.");
    }
    if (i + 1 >= argc) return UsageError("Option " + Narrow(a) + " needs a value.");
    const wchar_t* value = argv[++i];
    double n = 0;
    const bool isNumber = number(value, &n);
    if (a == L"--pid") {
      if (!isNumber || n < 1 || n > 4294967295.0 || n != static_cast<double>(static_cast<uint32_t>(n)))
        return UsageError("--pid needs a process ID, a whole number such as 1234.");
      pid = static_cast<uint32_t>(n);
    } else if (a == L"--name") {
      name = value;
    } else if (a == L"--seconds") {
      if (!isNumber || n < 1) return UsageError("--seconds needs a whole number of seconds, 1 or more.");
      seconds = static_cast<int>((std::min)(n, 86400.0));
      secondsGiven = true;
    } else if (a == L"--top") {
      if (!isNumber || n < 1) return UsageError("--top needs a number, 1 or more.");
      shown.topN = static_cast<size_t>(n);
    } else if (a == L"--min-ms") {
      if (!isNumber) return UsageError("--min-ms needs a number of milliseconds, 0 or more.");
      shown.minMs = n;
    } else if (a == L"--stall-ms") {
      if (!isNumber) return UsageError("--stall-ms needs a number of milliseconds, 0 or more.");
      shown.stallMs = n;
    } else if (a == L"--dump-events") {
      dumpPath = value;
    } else if (a == L"--symbols") {
      g_symbolsOption = value;
    } else if (a == L"--from-dump") {
      fromDump = value;
    } else if (a == L"--format") {
      const std::wstring format = value;
      if (format != L"text" && format != L"json" && format != L"html")
        return UsageError("--format is text, json or html.");
      g_output.json = format == L"json";
      g_output.html = format == L"html";
    } else if (a == L"--out") {
      g_output.file = value;
    } else if (a == L"--export-chrome") {
      g_output.chromeFile = value;
    } else if (a == L"--export-speedscope") {
      g_output.speedscopeFile = value;
    } else if (a == L"--ring") {
      if (!isNumber || n < 1) return UsageError("--ring needs a number of seconds, 1 or more.");
      ringSeconds = (std::min)(n, 86400.0);
    } else if (a == L"--ring-mb") {
      if (!isNumber || n < 16) return UsageError("--ring-mb needs a size in MB, 16 or more.");
      ringMb = (std::min)(n, 65536.0);
    } else if (a == L"--trigger") {
      triggerName = value;
    }
  }
  // waitwhy record (W38): the trace goes into the --out file; the report comes from analyze.
  std::wstring recordFile;
  const bool ring = ringSeconds > 0;
  if (!recording && (ring || ringMb > 0 || !triggerName.empty()))
    return UsageError("--ring, --ring-mb and --trigger are for: waitwhy record --ring SECONDS --out FILE.etl");
  if (!ring && (ringMb > 0 || !triggerName.empty()))
    return UsageError("--ring-mb and --trigger need --ring SECONDS.");
  if (recording) {
    if (g_output.file.empty()) return UsageError("waitwhy record needs --out FILE.etl, the file to record into.");
    // A flight recording (W39) ends with its report, so it takes the report options; a plain
    // recording is reported on later.
    if (!ring && (g_output.json || g_output.html || !g_output.chromeFile.empty() || !g_output.speedscopeFile.empty()))
      return UsageError("waitwhy record only records. Give report options to: waitwhy analyze FILE.etl");
    if (g_output.html) return UsageError("A flight recording prints its report; for HTML, run: waitwhy analyze FILE.etl --format html --out FILE.html");
    if (!dumpPath.empty() || !fromDump.empty())
      return UsageError("waitwhy record takes no --dump-events or --from-dump.");
    std::error_code ec;
    recordFile = std::filesystem::absolute(std::filesystem::path(g_output.file), ec).wstring();
    if (ec || !IsTraceFile(recordFile)) return UsageError("waitwhy record --out needs a file name ending in .etl.");
    g_output.file.clear();
    // About 8 MB per second of a busy machine's context switches with their stacks.
    if (ring) g_ringMb = static_cast<ULONG>(ringMb > 0 ? ringMb : (std::max)(64.0, (std::min)(4096.0, ringSeconds * 8)));
  }
  KeepConsoleForJson();
  if (!fromDump.empty() && IsTraceFile(fromDump)) {
    if (!dumpPath.empty() || !launch.empty())
      return UsageError("A report from an .etl file takes no --dump-events or -- program.");
    if (pid != 0 && !name.empty()) return UsageError("Give only one of --pid and --name.");
    if (allInstances && name.empty()) return UsageError("--all needs --name: it reports on every process of that name.");
    return AnalyzeTraceFile(fromDump, shown, pid, name, allInstances);
  }
  if (!fromDump.empty()) {
    if (pid != 0 || !name.empty() || !dumpPath.empty())
      return UsageError("A report from a dump takes no --pid, --name or --dump-events.");
    return ReportFromDump(fromDump, shown);
  }
  if (static_cast<int>(pid != 0) + static_cast<int>(!name.empty()) + static_cast<int>(!launch.empty()) > 1)
    return UsageError("Give only one of --pid, --name and -- program.");
  if (pid == 0 && name.empty() && launch.empty())
    return UsageError("Which program? Give its process ID with --pid N, its file name with --name,\n"
                      "or start it with: waitwhy [options] -- program.exe [its arguments]");
  if (allInstances && name.empty()) return UsageError("--all needs --name: it watches every process of that name.");
  if (!name.empty()) {
    const std::vector<uint32_t> found = FindProcessesByName(name);
    if (found.empty()) {
      std::printf("No running process is named %s. Check the name on the Details tab of Task Manager,\n"
                  "or give the process ID with --pid.\n",
                  Narrow(name).c_str());
      return kExitUsage;
    }
    pid = found[0];
    if (allInstances) {
      g_analysis.otherPids.insert(found.begin() + 1, found.end());
    } else if (found.size() > 1) {
      std::printf("Note: %zu processes are named %s; watching PID %u. Use --all to watch them all,\n"
                  "      or --pid to choose one.\n",
                  found.size(), Narrow(name).c_str(), pid);
    }
  }
  // Launch mode (W32, D9): the program is created suspended and only resumed once the trace is
  // running, so its start-up is watched too. Without --seconds it is watched until it exits.
  PROCESS_INFORMATION launched{};
  if (!launch.empty()) {
    std::wstring commandLine;
    for (const std::wstring& arg : launch) commandLine += (commandLine.empty() ? L"" : L" ") + QuoteArgument(arg);
    STARTUPINFOW startup{};
    startup.cb = sizeof startup;
    if (!CreateProcessW(nullptr, &commandLine[0], nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr,
                        nullptr, &startup, &launched)) {
      std::printf("Cannot start %s (error %lu). Check the program's path, or give its full path.\n",
                  Narrow(launch[0]).c_str(), GetLastError());
      return kExitUsage;
    }
    pid = launched.dwProcessId;
    if (!secondsGiven) seconds = 86400;
  }
  // A flight recording runs until it is stopped: Ctrl+C, the trigger, or the program's exit.
  if (ring && !secondsGiven) seconds = 86400 * 7;
  HANDLE trigger = nullptr;
  if (!triggerName.empty()) {
    trigger = CreateEventW(nullptr, TRUE, FALSE, triggerName.c_str());
    if (!trigger) {
      std::printf("Cannot create the event %s (error %lu). Use a name such as Local\\waitwhy.\n",
                  Narrow(triggerName).c_str(), GetLastError());
      return kExitUsage;
    }
  }
  // A launched program that never ran is ended again when watching cannot start.
  auto abandonLaunch = [&launched] {
    if (!launched.hProcess) return;
    TerminateProcess(launched.hProcess, 1);
    CloseHandle(launched.hThread);
    launched.hThread = nullptr;
  };
  HANDLE target = launched.hProcess
                      ? launched.hProcess
                      : OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!target) {
    if (GetLastError() == ERROR_ACCESS_DENIED)
      std::printf("Access to PID %u was denied. Run waitwhy from an Administrator PowerShell window\n"
                  "(right-click PowerShell > Run as administrator).\n",
                  pid);
    else
      std::printf("No process with ID %u is running. Check the ID on the Details tab of Task Manager.\n", pid);
    return kExitUsage;
  }
  for (uint32_t process : WatchedProcesses()) SnapshotThreads(process);
  // The processes --all gave, for thread names; children come from the event thread (W33).
  const std::vector<uint32_t> watchedAtStart = WatchedProcesses();
  auto rememberThreadNames = [&watchedAtStart] {
    std::vector<uint32_t> pids = watchedAtStart;
    {
      std::lock_guard<std::mutex> lock(g_childrenLock);
      pids.insert(pids.end(), g_children.begin(), g_children.end());
    }
    for (uint32_t process : pids) RememberThreadNames(process);
  };

  LARGE_INTEGER freq;
  QueryPerformanceFrequency(&freq);

  if (!dumpPath.empty()) {
    if (_wfopen_s(&g_dump, dumpPath.c_str(), L"w") != 0) g_dump = nullptr;
    if (!g_dump) {
      std::printf("Cannot write the event dump to %s.\n", Narrow(dumpPath).c_str());
      abandonLaunch();
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
    for (uint32_t other : g_analysis.otherPids) std::fprintf(g_dump, "WATCH pid=%u\n", other);
    for (uint32_t tid : g_analysis.targetThreads) std::fprintf(g_dump, "TARGET tid=%u\n", tid);
  }

  TRACEHANDLE session = 0;
  ULONG rc = StartKernelSession(&session, recordFile);
  if (rc != ERROR_SUCCESS) abandonLaunch();
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

  // Watching reads the events as they come; recording leaves them to the file.
  TRACEHANDLE consumer = INVALID_PROCESSTRACE_HANDLE;
  if (!recording) {
    EVENT_TRACE_LOGFILEW logfile{};
    logfile.LoggerName = const_cast<LPWSTR>(g_sessionName.c_str());
    logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD |
                               PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    logfile.EventRecordCallback = OnEvent;
    consumer = OpenTraceW(&logfile);
    if (consumer == INVALID_PROCESSTRACE_HANDLE) {
      std::printf("Could not open the trace for reading (error %lu).\n", GetLastError());
      abandonLaunch();
      StopKernelSession();
      return kExitTraceUnavailable;
    }
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
  std::thread reader;
  if (!recording) reader = std::thread([&consumer] { ProcessTrace(&consumer, 1, nullptr, nullptr); });
  const char* const verb = recording ? "recording" : "watching";

  if (launched.hThread) {
    ResumeThread(launched.hThread);
    CloseHandle(launched.hThread);
    launched.hThread = nullptr;
    if (secondsGiven)
      std::printf("Started %s (PID %u); %s it for %d seconds", Narrow(launch[0]).c_str(), pid, verb, seconds);
    else
      std::printf("Started %s (PID %u); %s it until it exits (Ctrl+C stops)", Narrow(launch[0]).c_str(), pid, verb);
  } else if (ring) {
    std::printf("Recording PID %u (%zu threads), keeping the last %s, until Ctrl+C%s%s%s", pid,
                g_analysis.targetThreads.size(), FormatDuration(ringSeconds).c_str(),
                trigger ? ", the event " : "", trigger ? Narrow(triggerName).c_str() : "",
                " or the program's exit");
  } else {
    std::printf("%s PID %u (%zu threads) for %d seconds", recording ? "Recording" : "Watching", pid,
                g_analysis.targetThreads.size(), seconds);
  }
  std::fflush(stdout);
  // Wait for a deadline on the same clock as the events, not for a number of sleeps: each sleep
  // rounds up to the system timer, which made an 8 s run last 8.4 s.
  const uint64_t deadline = g_analysis.firstTs + static_cast<uint64_t>(seconds) *
                                                     static_cast<uint64_t>(freq.QuadPart);
  uint64_t nextDot = g_analysis.firstTs + static_cast<uint64_t>(freq.QuadPart);
  bool programExited = false;
  for (;;) {
    LARGE_INTEGER now;
    QueryPerformanceCounter(&now);
    const auto t = static_cast<uint64_t>(now.QuadPart);
    if (t >= deadline || g_stopRequested) break;
    if (t >= nextDot) {
      if (!ring) std::printf(".");
      std::fflush(stdout);
      nextDot += static_cast<uint64_t>(freq.QuadPart);
      rememberThreadNames();
    }
    const uint64_t untilMs = (std::min)(deadline, nextDot) - t;
    const auto waitMs = static_cast<DWORD>((std::min)(
        uint64_t{100}, untilMs * 1000 / static_cast<uint64_t>(freq.QuadPart)));
    const HANDLE handles[2] = {target, trigger};
    const DWORD signalled = WaitForMultipleObjects(trigger ? 2 : 1, handles, FALSE, waitMs);
    if (signalled == WAIT_OBJECT_0) {
      std::printf("\nThe program exited while being watched.");
      programExited = true;
      break;
    }
    if (signalled == WAIT_OBJECT_0 + 1) {
      std::printf("\n%s was set.", Narrow(triggerName).c_str());
      break;
    }
  }
  std::printf("\n");

  LARGE_INTEGER windowEnd;
  QueryPerformanceCounter(&windowEnd);
  rememberThreadNames();
  g_windowEnd.store(static_cast<uint64_t>(windowEnd.QuadPart), std::memory_order_relaxed);
  SessionProps stopped;
  StopKernelSession(&stopped);  // ProcessTrace returns once the buffers are drained
  if (reader.joinable()) reader.join();
  g_analysis.lastTs = static_cast<uint64_t>(windowEnd.QuadPart);
  if (consumer != INVALID_PROCESSTRACE_HANDLE) CloseTrace(consumer);
  if (launched.hProcess && !programExited)
    std::printf("Note: %s is still running; waitwhy leaves it running.\n", Narrow(launch[0]).c_str());
  CloseHandle(target);
  if (trigger) CloseHandle(trigger);
  if (ring) {
    // The flight recorder's report covers its last --ring seconds (W39).
    const uint64_t keep = static_cast<uint64_t>(ringSeconds * static_cast<double>(freq.QuadPart));
    const uint64_t from = g_analysis.lastTs - g_analysis.firstTs > keep ? g_analysis.lastTs - keep : g_analysis.firstTs;
    if (!WriteRecordInfo(recordFile, from, g_analysis.lastTs)) {
      std::printf("Cannot write %s.\n", Narrow(RecordInfoPath(recordFile)).c_str());
      return kExitUsage;
    }
    std::printf("Recorded to %s (%lu events lost); the report covers the last %s.\n", Narrow(recordFile).c_str(),
                stopped.props.EventsLost,
                FormatDuration(static_cast<double>(g_analysis.lastTs - from) / static_cast<double>(freq.QuadPart)).c_str());
    std::printf("For the same report as HTML: waitwhy analyze %s --format html --out report.html\n",
                Narrow(recordFile).c_str());
    return AnalyzeTraceFile(recordFile, shown, 0, L"", false);
  }
  if (recording) {
    const bool infoWritten = WriteRecordInfo(recordFile, g_analysis.firstTs, g_analysis.lastTs);
    std::error_code ec;
    const auto bytes = std::filesystem::file_size(std::filesystem::path(recordFile), ec);
    std::printf("Recorded %s of kernel events to %s (%.0f MB; %lu events and %lu buffers lost).\n",
                FormatDuration(static_cast<double>(g_analysis.lastTs - g_analysis.firstTs) /
                               static_cast<double>(freq.QuadPart)).c_str(),
                Narrow(recordFile).c_str(), ec ? 0.0 : static_cast<double>(bytes) / 1e6,
                stopped.props.EventsLost, stopped.props.LogBuffersLost);
    if (!infoWritten)
      std::printf("Note: could not write %s; give --pid %u to waitwhy analyze.\n",
                  Narrow(RecordInfoPath(recordFile)).c_str(), pid);
    std::printf("Make the report, here or on another machine (keep %s beside it):\n"
                "  waitwhy analyze %s\n",
                Narrow(RecordInfoPath(recordFile)).c_str(), Narrow(recordFile).c_str());
    return kExitOk;
  }
  if (g_dump) {
    std::fprintf(g_dump, "END ts=%llu contextSwitches=%llu stacksOn=%d eventsLost=%lu buffersLost=%lu%s\n",
                 static_cast<unsigned long long>(g_analysis.lastTs),
                 static_cast<unsigned long long>(g_analysis.contextSwitches), stacksOn ? 1 : 0,
                 stopped.props.EventsLost, stopped.props.RealTimeBuffersLost, g_noSuspend ? " snapshots=0" : "");
  }

  if (!g_noSuspend) SnapshotThreadsStillBlocked();
  g_analysis.FlushAtEnd();
  // A program that exited can no longer be asked for its modules; the trace recorded them.
  NameWakerProcesses();
  // One DbgHelp session per watched process (W33); a process that has exited is named from
  // the modules the trace recorded for it (W26).
  std::map<uint32_t, std::unique_ptr<Symbolizer>> symbolizers;
  auto symbolsFor = [&](uint32_t process) -> Symbolizer& {
    auto it = symbolizers.find(process);
    if (it != symbolizers.end()) return *it->second;
    auto sym = std::make_unique<Symbolizer>();
    const bool exited = process == pid && programExited;
    if (exited || !sym->Init(process)) sym->InitFromImages(g_images[process], process);
    return *symbolizers.emplace(process, std::move(sym)).first->second;
  };
  Symbolizer& sym = symbolsFor(pid);
  const bool symbolsOk = sym.Ok();
  for (uint32_t process : WatchedProcesses()) symbolsFor(process);
  std::fputs(SymbolServerNote(sym.SearchPath()).c_str(), stdout);
  if (g_dump) {
    WriteDumpNames(g_dump, symbolsFor, symbolsOk, ProgramThreadLabel);
    std::fclose(g_dump);
    g_dump = nullptr;
    std::printf("Wrote %llu events to %s.\n", static_cast<unsigned long long>(g_dumpLines),
                Narrow(dumpPath).c_str());
  }
  return PrintReport(static_cast<double>(freq.QuadPart), shown, stopped, stacksOn, symbolsFor, symbolsOk);
}
#endif  // WAITWHY_NO_MAIN
