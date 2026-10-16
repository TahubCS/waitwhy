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
const GUID kFileIoGuid = {
    0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};

// Event types (opcodes) inside the kernel's Thread event class.
constexpr UCHAR kOpThreadStart = 1;
constexpr UCHAR kOpThreadEnd = 2;
constexpr UCHAR kOpThreadDcStart = 3;  // "already running when the trace started"
constexpr UCHAR kOpCSwitch = 36;
constexpr UCHAR kOpReadyThread = 50;
constexpr UCHAR kOpStackWalk = 32;     // inside the StackWalk class
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

// A module the program had loaded, from the kernel's image events (W26). With these, function
// names can still be found after the program has exited.
struct ImageInfo {
  uint64_t base = 0;
  uint64_t size = 0;
  std::wstring path;  // as the kernel names it, e.g. \Device\HarddiskVolume3\...\ntdll.dll
};
std::vector<ImageInfo> g_images;

void OnImage(const EVENT_RECORD* ev) {
  // Image_Load (versions 2 and 3): ImageBase, ImageSize (pointers), ProcessId, ImageCheckSum,
  // TimeDateStamp, a 32-bit field, DefaultBase (pointer), four reserved 32-bit fields, then the
  // file name as a null-terminated UTF-16 string.
  const size_t ptr = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  const size_t nameAt = 3 * ptr + 32;
  if (ev->UserDataLength < nameAt + sizeof(wchar_t)) return;
  const auto* p = static_cast<const uint8_t*>(ev->UserData);
  uint32_t pid = 0;
  std::memcpy(&pid, p + 2 * ptr, sizeof pid);
  if (pid != g_analysis.pid) return;
  ImageInfo image;
  std::memcpy(&image.base, p, ptr);
  std::memcpy(&image.size, p + ptr, ptr);
  for (size_t at = nameAt; at + sizeof(wchar_t) <= ev->UserDataLength; at += sizeof(wchar_t)) {
    wchar_t ch;
    std::memcpy(&ch, p + at, sizeof ch);
    if (ch == L'\0') break;
    image.path += ch;
  }
  if (g_dump) {
    std::fprintf(g_dump, "IMAGE ts=%llu base=0x%llx size=0x%llx name=%s\n",
                 static_cast<unsigned long long>(ev->EventHeader.TimeStamp.QuadPart),
                 static_cast<unsigned long long>(image.base),
                 static_cast<unsigned long long>(image.size), Narrow(image.path).c_str());
    ++g_dumpLines;
  }
  g_images.push_back(std::move(image));
}

// Where the fields W28 needs sit in one kind of FileIo event, found once through TDH by their
// names, because the layouts differ between event versions. -1: the event has no such field.
struct FileIoLayout {
  bool ok = false;
  int irp = -1, fileObject = -1, ttid = -1, name = -1;
  size_t ttidSize = 4;
};

FileIoLayout FindFileIoLayout(PEVENT_RECORD ev) {
  // TDH_IN_TYPE values (tdh.h); not every SDK header names them.
  enum : USHORT { kInUnicodeString = 1, kInInt8 = 3, kInUInt8 = 4, kInInt16 = 5, kInUInt16 = 6,
                  kInInt32 = 7, kInUInt32 = 8, kInInt64 = 9, kInUInt64 = 10, kInBoolean = 13,
                  kInPointer = 16, kInFiletime = 17, kInHexInt32 = 20, kInHexInt64 = 21 };
  FileIoLayout layout;
  ULONG size = 0;
  if (TdhGetEventInformation(ev, 0, nullptr, nullptr, &size) != ERROR_INSUFFICIENT_BUFFER) return layout;
  std::vector<unsigned char> buffer(size);
  auto* info = reinterpret_cast<TRACE_EVENT_INFO*>(buffer.data());
  if (TdhGetEventInformation(ev, 0, nullptr, info, &size) != ERROR_SUCCESS) return layout;
  const size_t ptr = (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) ? 8 : 4;
  size_t offset = 0;
  for (ULONG i = 0; i < info->TopLevelPropertyCount; ++i) {
    const EVENT_PROPERTY_INFO& p = info->EventPropertyInfoArray[i];
    if ((p.Flags & (PropertyStruct | PropertyParamLength | PropertyParamCount)) || p.count > 1) break;
    const auto* name = reinterpret_cast<const wchar_t*>(buffer.data() + p.NameOffset);
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
    const int at = static_cast<int>(offset);
    if (wcscmp(name, L"IrpPtr") == 0) layout.irp = at;
    else if (wcscmp(name, L"FileObject") == 0) layout.fileObject = at;
    else if (wcscmp(name, L"TTID") == 0) layout.ttid = at, layout.ttidSize = fieldSize;
    else if (p.nonStructType.InType == kInUnicodeString &&
             (wcscmp(name, L"FileName") == 0 || wcscmp(name, L"OpenPath") == 0)) layout.name = at;
    if (fieldSize == 0) break;  // nothing after a string has a fixed place
    offset += fieldSize;
  }
  layout.ok = true;
  return layout;
}

const FileIoLayout& FileIoLayoutOf(PEVENT_RECORD ev) {
  static std::map<std::tuple<UCHAR, UCHAR, bool>, FileIoLayout> layouts;
  const auto key = std::make_tuple(ev->EventHeader.EventDescriptor.Opcode,
                                   ev->EventHeader.EventDescriptor.Version,
                                   (ev->EventHeader.Flags & EVENT_HEADER_FLAG_64_BIT_HEADER) != 0);
  auto it = layouts.find(key);
  if (it == layouts.end()) it = layouts.emplace(key, FindFileIoLayout(ev)).first;
  return it->second;
}

void DumpFileName(uint64_t fileObject, const Analyzer::FileName& f) {
  if (!g_dump) return;
  std::fprintf(g_dump, "FILENAME fileObject=0x%llx kind=%d name=%s\n",
               static_cast<unsigned long long>(fileObject), static_cast<int>(f.kind), f.path.c_str());
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
  } else if (IsEqualGUID(h.ProviderId, kImageGuid) && (op == kOpImageLoad || op == kOpImageDcStart)) {
    OnImage(ev);
  } else if (IsEqualGUID(h.ProviderId, kFileIoGuid)) {
    OnFileIo(ev, op);
  }
}

// ---------------------------------------------------------------------------
// Kernel trace session
// ---------------------------------------------------------------------------

// The session being used: a private system-logger session (W31, D10), or the shared
// "NT Kernel Logger" where Windows cannot give one.
std::wstring g_sessionName = kLoggerName;

void FillProps(SessionProps& sp, bool forStart, bool privateSession = false) {
  std::memset(&sp, 0, sizeof sp);
  sp.props.Wnode.BufferSize = sizeof sp;
  sp.props.LoggerNameOffset = offsetof(SessionProps, loggerName);
  if (!forStart) return;
  if (!privateSession) sp.props.Wnode.Guid = kSystemTraceControlGuid;
  sp.props.Wnode.ClientContext = 1;  // timestamps from QueryPerformanceCounter
  sp.props.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
  sp.props.EnableFlags =
      EVENT_TRACE_FLAG_CSWITCH | EVENT_TRACE_FLAG_DISPATCHER | EVENT_TRACE_FLAG_THREAD |
      EVENT_TRACE_FLAG_IMAGE_LOAD | EVENT_TRACE_FLAG_DISK_IO | EVENT_TRACE_FLAG_DISK_FILE_IO |
      EVENT_TRACE_FLAG_FILE_IO | EVENT_TRACE_FLAG_FILE_IO_INIT;
  sp.props.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
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

ULONG StartKernelSession(TRACEHANDLE* session) {
  StopLeftoverSessions();
  SessionProps sp;
  const std::wstring privateName = kPrivatePrefix + std::to_wstring(GetCurrentProcessId());
  FillProps(sp, true, true);
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
  FillProps(sp, true);
  rc = StartTraceW(session, kLoggerName, &sp.props);
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
  bool InitFromImages(const std::vector<ImageInfo>& images) {
    if (images.empty()) return false;
    proc_ = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0x57a17));  // any unique value
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

// Ends a dump with every name the report uses (W18), so the report can be rebuilt from the
// dump alone: the program's file, each address in a wait's stack, and the thread labels.
void WriteDumpNames(FILE* out, Symbolizer& sym, bool symbolsOk) {
  const Analyzer& an = g_analysis;
  std::fprintf(out, "NAMES symbolsOk=%d fromTrace=%d\n", symbolsOk ? 1 : 0, sym.FromImages() ? 1 : 0);
  const std::string pdb = sym.PdbNextToExe();
  if (!pdb.empty()) std::fprintf(out, "PDB file=%s\n", pdb.c_str());
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
  for (const auto& [module, kind] : sym.ModuleKinds())
    std::fprintf(out, "MODULE symbols=%s name=%s\n",
                 kind == SymbolKind::Full ? "full" : kind == SymbolKind::ExportsOnly ? "exports" : "none",
                 module.c_str());
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

void PrintReport(double ticksPerSecond, ReportOptions opt, const SessionProps& stopped,
                 bool stacksOn, Symbolizer& sym, bool symbolsOk) {
  opt.ticksPerSecond = ticksPerSecond;
  opt.eventsLost = stopped.props.EventsLost;
  opt.buffersLost = stopped.props.RealTimeBuffersLost;
  opt.stacksOn = stacksOn;
  opt.symbolsOk = symbolsOk;
  opt.exeFile = sym.ExeFile();
  opt.namesFromTrace = sym.FromImages();
  opt.pdbNextToExe = sym.PdbNextToExe();
  const Report report = BuildReport(g_analysis, sym, opt, ThreadLabel);
  std::fputs(RenderText(report).c_str(), stdout);
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
  DumpSymbols sym(lines);
  opt.ticksPerSecond = info.ticksPerSecond > 0 ? info.ticksPerSecond : 1e7;
  opt.eventsLost = info.eventsLost;
  opt.buffersLost = info.buffersLost;
  opt.stacksOn = info.stacksOn;
  opt.symbolsOk = info.symbolsOk;
  opt.exeFile = info.exeFile;
  opt.namesFromTrace = info.namesFromTrace;
  opt.pdbNextToExe = info.pdbNextToExe;
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  std::printf("Report rebuilt from %s.\n", Narrow(path).c_str());
  std::fputs(RenderText(BuildReport(an, sym, opt, name)).c_str(), stdout);
  return kExitOk;
}

constexpr char kVersion[] = "0.9.0";

void Usage() {
  std::printf(
      "waitwhy %s - what is a program waiting for when it is slow but the CPU is idle?\n"
      "\n"
      "Usage:\n"
      "  waitwhy [watch] (--pid N | --name program.exe) [options]\n"
      "      Watch a running program, then report what its threads were waiting on.\n"
      "      Needs an Administrator shell.\n"
      "  waitwhy analyze FILE [report options]\n"
      "      Report again from a FILE written by --dump-events, on any machine.\n"
      "      (--from-dump FILE does the same.)\n"
      "  waitwhy --help | --version\n"
      "\n"
      "Watch options:\n"
      "  --seconds N          how long to watch (default 10)\n"
      "  --dump-events FILE   also write every event of the program to FILE, and the names\n"
      "                       the report uses; attach it to bug reports\n"
      "  --symbols ms|PATH    ms: download Windows' own symbols from Microsoft (cached in\n"
      "                       %%LOCALAPPDATA%%\\waitwhy\\symbols); PATH: a DbgHelp symbol\n"
      "                       path. Without it, _NT_SYMBOL_PATH is used when set.\n"
      "\n"
      "Report options:\n"
      "  --top N              show the N biggest groups of waits (default 6)\n"
      "  --min-ms N           hide groups smaller than N milliseconds (default 10)\n"
      "  --stall-ms N         report any single lock, disk, network or page-fault wait of\n"
      "                       N ms or more (default 50)\n"
      "\n"
      "Exit codes: 0 report printed; 1 bad arguments, or the program or file was not\n"
      "found; 2 the kernel trace could not be started (not Administrator, or unavailable).\n",
      kVersion);
}

// Every error says what to do next (W30).
int UsageError(const std::string& message) {
  std::printf("%s\nRun 'waitwhy --help' to see the options.\n", message.c_str());
  return kExitUsage;
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
  } else if (command == L"record" || command == L"diff") {
    return UsageError("'waitwhy " + Narrow(command) + "' is not available in this version.");
  }
  auto number = [](const wchar_t* text, double* value) {
    wchar_t* end = nullptr;
    *value = std::wcstod(text, &end);
    return end != text && *end == L'\0' && *value >= 0;
  };
  for (int i = first; i < argc; ++i) {
    const std::wstring a = argv[i];
    const bool takesValue = a == L"--pid" || a == L"--name" || a == L"--seconds" || a == L"--top" ||
                            a == L"--min-ms" || a == L"--stall-ms" || a == L"--dump-events" ||
                            a == L"--symbols" || a == L"--from-dump";
    if (!takesValue) {
      if (a == L"--help" || a == L"-h") {
        Usage();
        return kExitOk;
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
    }
  }
  if (!fromDump.empty()) {
    if (pid != 0 || !name.empty() || !dumpPath.empty())
      return UsageError("A report from a dump takes no --pid, --name or --dump-events.");
    return ReportFromDump(fromDump, shown);
  }
  if (pid != 0 && !name.empty()) return UsageError("Give either --pid or --name, not both.");
  if (pid == 0 && name.empty())
    return UsageError("Which program? Give its process ID with --pid N or its file name with --name.");
  if (!name.empty() && !FindProcessByName(name, &pid)) {
    std::printf("No running process is named %s. Check the name on the Details tab of Task Manager,\n"
                "or give the process ID with --pid.\n",
                Narrow(name).c_str());
    return kExitUsage;
  }
  HANDLE target = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
  if (!target) {
    if (GetLastError() == ERROR_ACCESS_DENIED)
      std::printf("Access to PID %u was denied. Run waitwhy from an Administrator PowerShell window\n"
                  "(right-click PowerShell > Run as administrator).\n",
                  pid);
    else
      std::printf("No process with ID %u is running. Check the ID on the Details tab of Task Manager.\n", pid);
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
  logfile.LoggerName = const_cast<LPWSTR>(g_sessionName.c_str());
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
  bool programExited = false;
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
      programExited = true;
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
  // A program that exited can no longer be asked for its modules; the trace recorded them.
  Symbolizer sym;
  const bool symbolsOk = (!programExited && sym.Init(pid)) || sym.InitFromImages(g_images);
  std::fputs(SymbolServerNote(sym.SearchPath()).c_str(), stdout);
  if (g_dump) {
    WriteDumpNames(g_dump, sym, symbolsOk);
    std::fclose(g_dump);
    g_dump = nullptr;
    std::printf("Wrote %llu events to %s.\n", static_cast<unsigned long long>(g_dumpLines),
                Narrow(dumpPath).c_str());
  }
  PrintReport(static_cast<double>(freq.QuadPart), shown, stopped, stacksOn, sym, symbolsOk);
  return kExitOk;
}
#endif  // WAITWHY_NO_MAIN
