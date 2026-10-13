// replay_events.cpp - replays a waitwhy --dump-events file through waitwhy's own event
// handlers and checks the stack-matching results. No kernel trace and no Administrator
// rights are needed, so it runs on any Windows machine and in CI.
//
// Build (x64 Developer PowerShell for VS, from the repository root):
//   cl /nologo /EHsc /O2 /std:c++17 /DWAITWHY_NO_MAIN tests\replay_events.cpp /Fe:replay_events.exe
// Run:
//   .\replay_events.exe docs\traces\buggy-64mb-events.txt
//
// A dump has one line per event and no full stacks: a STACK line gives the number of kernel
// and user frames and the first user address. The replay rebuilds each stack from that, so
// stacks with the same first user address and depth look identical. Function names are
// therefore not checked here, only which waits get a stack.

#include "../waitwhy.cpp"

#include <fstream>
#include <sstream>

namespace {

struct DumpLine {
  int number = 0;  // line number in the file, for messages
  std::string kind;
  std::map<std::string, uint64_t> field;
};

std::vector<DumpLine> ReadDump(const char* path) {
  std::vector<DumpLine> lines;
  std::ifstream in(path);
  std::string text;
  for (int number = 1; std::getline(in, text); ++number) {
    if (!text.empty() && text.back() == '\r') text.pop_back();  // dumps are written as CRLF
    if (text.empty() || text[0] == '#') continue;
    std::istringstream words(text);
    DumpLine line;
    line.number = number;
    words >> line.kind;
    for (std::string word; words >> word;) {
      const size_t eq = word.find('=');
      if (eq == std::string::npos) continue;
      line.field[word.substr(0, eq)] = std::stoull(word.substr(eq + 1), nullptr, 0);
    }
    lines.push_back(std::move(line));
  }
  return lines;
}

// Clears everything the handlers accumulate, so several replays can run in one process.
void ResetState() {
  g_targetThreads.clear();
  g_exitedThreads.clear();
  g_threads.clear();
  g_buckets.clear();
  std::fill(g_cpuThread.begin(), g_cpuThread.end(), kUnknownThread);
  g_firstTs = g_lastTs = 0;
  g_contextSwitches = g_waitsWithStack = g_waitsWithoutStack = g_kernelOnlyFragments = 0;
  g_stacksOn = true;
  g_pid = 1;
}

// The program's threads are the ones that were readied or had stacks recorded.
void AddTargetThreads(const std::vector<DumpLine>& lines) {
  for (const DumpLine& l : lines) {
    if (l.kind == "READY") g_targetThreads.insert(static_cast<uint32_t>(l.field.at("readied")));
    if (l.kind == "STACK") g_targetThreads.insert(static_cast<uint32_t>(l.field.at("tid")));
  }
}

template <typename T>
void Append(std::vector<uint8_t>& data, T value) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
  data.insert(data.end(), bytes, bytes + sizeof value);
}

// Turns one dump line back into the EVENT_RECORD the kernel delivered and hands it to OnEvent.
void Feed(const DumpLine& l) {
  EVENT_RECORD ev{};
  std::vector<uint8_t> data;
  ev.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
  ev.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>(l.field.at("ts"));
  ev.EventHeader.ThreadId = kUnknownThread;
  if (l.kind == "CSWITCH") {
    ev.EventHeader.ProviderId = kThreadGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpCSwitch;
    ev.BufferContext.ProcessorNumber = static_cast<UCHAR>(l.field.at("cpu"));
    CSwitchPayload c{};
    c.newThreadId = static_cast<uint32_t>(l.field.at("new"));
    c.oldThreadId = static_cast<uint32_t>(l.field.at("old"));
    c.oldThreadState = static_cast<int8_t>(l.field.at("oldState"));
    c.oldThreadWaitReason = static_cast<int8_t>(l.field.at("oldReason"));
    Append(data, c);
  } else if (l.kind == "READY") {
    ev.EventHeader.ProviderId = kThreadGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpReadyThread;
    ev.BufferContext.ProcessorNumber = static_cast<UCHAR>(l.field.at("cpu"));
    ev.EventHeader.ThreadId = static_cast<ULONG>(l.field.at("headerThread"));
    Append(data, static_cast<uint32_t>(l.field.at("readied")));
    Append(data, static_cast<uint8_t>(0));  // AdjustReason
    Append(data, static_cast<uint8_t>(0));  // AdjustIncrement
    Append(data, static_cast<uint8_t>(l.field.at("flag")));
    Append(data, static_cast<uint8_t>(0));
  } else if (l.kind == "STACK") {
    ev.EventHeader.ProviderId = kStackWalkGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpStackWalk;
    Append(data, l.field.at("eventTs"));
    Append(data, g_pid);
    Append(data, static_cast<uint32_t>(l.field.at("tid")));
    for (uint64_t i = 0; i < l.field.at("kernelFrames"); ++i)
      Append(data, 0xFFFFF80000001000ull + i * 16);
    for (uint64_t i = 0; i < l.field.at("userFrames"); ++i)
      Append(data, i == 0 ? l.field.at("firstUser") : 0x00007FF600001000ull + i * 16);
  } else {
    return;
  }
  ev.UserData = data.data();
  ev.UserDataLength = static_cast<USHORT>(data.size());
  OnEvent(&ev);
}

int g_failures = 0;

void Expect(bool ok, const char* what, unsigned long long got, unsigned long long want) {
  std::printf("  %s %-46s got %llu, expected %llu\n", ok ? "ok  " : "FAIL", what, got, want);
  if (!ok) ++g_failures;
}

void ExpectEq(const char* what, unsigned long long got, unsigned long long want) {
  Expect(got == want, what, got, want);
}

// Waits of `tid` recorded with a stack whose innermost user frame is `firstUser`.
unsigned long long WaitsWithFirstFrame(uint32_t tid, uint64_t firstUser) {
  unsigned long long n = 0;
  for (const auto& [key, b] : g_buckets)
    if (b.tid == tid && !b.stack.empty() && b.stack.front() == firstUser) n += b.count;
  return n;
}

// docs/TRACE-FINDINGS.md, lines 108-135 of buggy-64mb-events.txt: saver blocks six times
// inside one WriteFile and one user-mode fragment, stamped with the first switch-in and
// delivered at line 135, covers all six. A preemption at line 132 sits in between.
void CheckSixWaitsShareOneStack(const std::vector<DumpLine>& all) {
  std::printf("Lines 108-135: one user stack for six waits of one system call\n");
  ResetState();
  std::vector<DumpLine> part;
  for (const DumpLine& l : all)
    if (l.number >= 108 && l.number <= 135) part.push_back(l);
  AddTargetThreads(all);
  for (const DumpLine& l : part) Feed(l);
  const uint32_t saver = 29716;
  ExpectEq("waits with a stack", g_waitsWithStack, 6);
  ExpectEq("waits still awaiting a stack", g_threads[saver].awaitingStack.size(), 0);
  ExpectEq("waits without a stack", g_waitsWithoutStack, 0);
  ExpectEq("kernel-only stack parts", g_kernelOnlyFragments, 6);
  ExpectEq("saver waits under the line-135 stack", WaitsWithFirstFrame(saver, 0x7ffc466a0ec4), 6);
}

// The whole capture. Before W14 the report said 845 waits matched, 711 without a stack.
void CheckWholeTrace(const std::vector<DumpLine>& all) {
  std::printf("Whole trace\n");
  ResetState();
  AddTargetThreads(all);
  for (const DumpLine& l : all) Feed(l);
  FlushAtEnd();
  ExpectEq("context switches", g_contextSwitches, 3891);
  ExpectEq("waits with a stack", g_waitsWithStack, 1552);
  ExpectEq("waits without a stack", g_waitsWithoutStack, 4);
  ExpectEq("kernel-only stack parts", g_kernelOnlyFragments, 1552);
}

}  // namespace

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : "docs\\traces\\buggy-64mb-events.txt";
  const std::vector<DumpLine> lines = ReadDump(path);
  if (lines.empty()) {
    std::printf("No events read from %s.\n", path);
    return 1;
  }
  std::printf("Replaying %zu events from %s\n", lines.size(), path);
  CheckSixWaitsShareOneStack(lines);
  CheckWholeTrace(lines);
  std::printf(g_failures ? "%d check(s) failed.\n" : "All checks passed.\n", g_failures);
  return g_failures ? 1 : 0;
}
