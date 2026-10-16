// replay_events.cpp - replays a waitwhy --dump-events file through the analysis core
// (analysis.h) and checks the stack-matching results. It makes no Windows calls, so it builds
// and runs on any machine with a C++17 compiler, in CI on Windows and Linux.
//
// Build and run (x64 Developer PowerShell for VS, from the repository root):
//   cl /nologo /EHsc /O2 /std:c++17 tests\replay_events.cpp /Fe:replay_events.exe
//   .\replay_events.exe docs\traces\buggy-64mb-events.txt
// or with GCC/Clang:
//   g++ -std=c++17 -O2 -Wall -Wextra tests/replay_events.cpp -o replay_events
//   ./replay_events docs/traces/buggy-64mb-events.txt
//
// A dump has one line per event and no full stacks: a STACK line gives the number of kernel
// and user frames and the first user address. The replay rebuilds each user stack from that,
// so stacks with the same first user address and depth look identical. Function names are
// therefore not checked here, only which waits get a stack. tests/decode_tests.cpp replays the
// same dump through waitwhy's ETW decoding as well.

#include "../analysis.h"
#include "dump_reader.h"

using namespace waitwhy;

namespace {

// The program's threads are the ones that were readied or had stacks recorded.
void AddTargetThreads(Analyzer& an, const std::vector<DumpLine>& lines) {
  for (const DumpLine& l : lines) {
    if (l.kind == "READY") an.targetThreads.insert(static_cast<uint32_t>(l.field.at("readied")));
    if (l.kind == "STACK") an.targetThreads.insert(static_cast<uint32_t>(l.field.at("tid")));
  }
}

// Decodes one dump line the way waitwhy.cpp decodes the kernel event behind it.
class Replayer {
 public:
  explicit Replayer(Analyzer& an) : an_(an), cpuThread_(256, kUnknownThread) {}

  void Feed(const DumpLine& l) {
    if (l.kind == "CSWITCH") {
      SwitchEvent e;
      e.ts = l.field.at("ts");
      e.oldTid = static_cast<uint32_t>(l.field.at("old"));
      e.newTid = static_cast<uint32_t>(l.field.at("new"));
      e.oldState = static_cast<int8_t>(l.field.at("oldState"));
      e.oldWaitReason = static_cast<int8_t>(l.field.at("oldReason"));
      const size_t cpu = l.field.at("cpu");
      if (cpu < cpuThread_.size()) cpuThread_[cpu] = e.newTid;
      an_.OnSwitch(e);
    } else if (l.kind == "READY") {
      ReadyEvent e;
      e.ts = l.field.at("ts");
      e.readiedTid = static_cast<uint32_t>(l.field.at("readied"));
      const size_t cpu = l.field.at("cpu");
      e.byTid = ResolveWaker(static_cast<uint8_t>(l.field.at("flag")),
                             static_cast<uint32_t>(l.field.at("headerThread")),
                             cpu < cpuThread_.size() ? cpuThread_[cpu] : kUnknownThread);
      an_.OnReady(e);
    } else if (l.kind == "STACK") {
      StackEvent e;
      e.ts = l.field.at("ts");
      e.eventTs = l.field.at("eventTs");
      e.tid = static_cast<uint32_t>(l.field.at("tid"));
      for (uint64_t i = 0; i < l.field.at("userFrames"); ++i)
        e.userFrames.push_back(i == 0 ? l.field.at("firstUser") : 0x00007FF600001000ull + i * 16);
      an_.OnStack(e);
    }
  }

 private:
  Analyzer& an_;
  std::vector<uint32_t> cpuThread_;
};

// Waits of `tid` recorded with a stack whose innermost user frame is `firstUser`.
unsigned long long WaitsWithFirstFrame(const Analyzer& an, uint32_t tid, uint64_t firstUser) {
  unsigned long long n = 0;
  for (const auto& [key, b] : an.buckets)
    if (b.tid == tid && !b.stack.empty() && b.stack.front() == firstUser) n += b.count;
  return n;
}

// docs/TRACE-FINDINGS.md, lines 108-135 of buggy-64mb-events.txt: saver blocks six times
// inside one WriteFile and one user-mode fragment, stamped with the first switch-in and
// delivered at line 135, covers all six. A preemption at line 132 sits in between.
void CheckSixWaitsShareOneStack(const std::vector<DumpLine>& all) {
  std::printf("Lines 108-135: one user stack for six waits of one system call\n");
  Analyzer an;
  an.pid = 1;
  an.stacksOn = true;
  AddTargetThreads(an, all);
  Replayer replay(an);
  for (const DumpLine& l : all)
    if (l.number >= 108 && l.number <= 135) replay.Feed(l);
  const uint32_t saver = 29716;
  ExpectEq("waits with a stack", an.waitsWithStack, 6);
  ExpectEq("waits still awaiting a stack", an.threads[saver].awaitingStack.size(), 0);
  ExpectEq("waits without a stack", an.waitsWithoutStack, 0);
  ExpectEq("kernel-only stack parts", an.kernelOnlyFragments, 6);
  ExpectEq("saver waits under the line-135 stack", WaitsWithFirstFrame(an, saver, 0x7ffc466a0ec4), 6);
}

// The whole capture. Before W14 the report said 845 waits matched, 711 without a stack.
void CheckWholeTrace(const std::vector<DumpLine>& all) {
  std::printf("Whole trace\n");
  Analyzer an;
  an.pid = 1;
  an.stacksOn = true;
  AddTargetThreads(an, all);
  Replayer replay(an);
  for (const DumpLine& l : all) replay.Feed(l);
  an.FlushAtEnd();
  ExpectEq("context switches", an.contextSwitches, 3891);
  ExpectEq("waits with a stack", an.waitsWithStack, 1552);
  ExpectEq("waits without a stack", an.waitsWithoutStack, 4);
  ExpectEq("kernel-only stack parts", an.kernelOnlyFragments, 1552);
}

}  // namespace

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : "docs/traces/buggy-64mb-events.txt";
  const std::vector<DumpLine> lines = ReadDump(path);
  if (lines.empty()) {
    std::printf("No events read from %s.\n", path);
    return 1;
  }
  std::printf("Replaying %zu events from %s\n", lines.size(), path);
  CheckSixWaitsShareOneStack(lines);
  CheckWholeTrace(lines);
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
