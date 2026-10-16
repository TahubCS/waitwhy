// replay_events.cpp - replays waitwhy --dump-events files through the analysis core
// (analysis.h, dump.h) and checks the stack-matching results. It makes no Windows calls, so it
// builds and runs on any machine with a C++17 compiler, in CI on Windows and Linux.
//
// Build and run (x64 Developer PowerShell for VS, from the repository root):
//   cl /nologo /W4 /WX /EHsc /O2 /std:c++17 tests\replay_events.cpp /Fe:replay_events.exe
//   .\replay_events.exe docs\traces\buggy-64mb-events.txt
// or with GCC/Clang:
//   g++ -std=c++17 -O2 -Wall -Wextra tests/replay_events.cpp -o replay_events
//   ./replay_events docs/traces/buggy-64mb-events.txt
//
// The recorded trace is a version 1 dump: a STACK line gives the number of kernel and user
// frames and only the first user address, so function names are not checked against it, only
// which waits get a stack. tests/decode_tests.cpp replays the same dump through waitwhy's ETW
// decoding as well. A small hand-written version 2 dump checks the lines W18 added.

#include <sstream>

#include "../dump.h"
#include "check.h"

using namespace waitwhy;

namespace {

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
  DumpReplay replay(an);
  replay.Prepare(all);
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
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(all);
  ExpectEq("read as version 1", info.version, 1);
  ExpectEq("context switches", an.contextSwitches, 3891);
  ExpectEq("waits with a stack", an.waitsWithStack, 1552);
  ExpectEq("waits without a stack", an.waitsWithoutStack, 4);
  ExpectEq("kernel-only stack parts", an.kernelOnlyFragments, 1552);
}

// A version 2 dump (W18): main (1) blocks on a lock that saver (2) releases; the user stack
// arrives in two parts; a thread is created in the program and one in another process; main
// is still asleep when tracing stops and gets a snapshot.
const char kVersion2[] = R"(# waitwhy event dump, version 2
DUMP version=2 pid=42 ticksPerSecond=1000
TARGET tid=1
TARGET tid=2
WINDOW ts=100
CSWITCH ts=100 cpu=0 old=0 new=1 oldState=0 oldReason=0
CSWITCH ts=110 cpu=0 old=1 new=2 oldState=5 oldReason=37
READY ts=150 cpu=0 readied=1 headerThread=2 flag=0x00 by=2
CSWITCH ts=160 cpu=0 old=2 new=1 oldState=5 oldReason=0
STACK ts=161 eventTs=160 tid=1 kernelFrames=3 userFrames=0 firstUser=0x0
STACK ts=170 eventTs=160 tid=1 kernelFrames=0 userFrames=2 firstUser=0x7ff600000010 frames=0x7ff600000010,0x7ff600000020
THREAD ts=180 kind=0 pid=42 tid=3
THREAD ts=185 kind=0 pid=99 tid=4
CSWITCH ts=190 cpu=0 old=1 new=0 oldState=5 oldReason=4
END ts=300 contextSwitches=50 stacksOn=1 eventsLost=0 buffersLost=0
SNAPSHOT tid=1 frames=0x7ff600000030
EXE name=slowapp.exe
SYMBOL addr=0x7ff600000010 name=ntdll!RtlSleepConditionVariableSRW
SYMBOL addr=0x7ff600000020 name=slowapp!`anonymous namespace'::update_frame
SOURCE addr=0x7ff600000020 file=c:\src\slowapp.cpp
THREADNAME tid=1 name=Thread 1 (main)
)";

void CheckVersion2() {
  std::printf("Version 2 dump\n");
  std::vector<DumpLine> lines;
  std::istringstream in(kVersion2);
  int number = 0;
  for (std::string text; std::getline(in, text);) {
    ++number;
    if (!text.empty() && text[0] != '#') lines.push_back(ParseDumpLine(text, number));
  }

  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  ExpectEq("version", info.version, 2);
  ExpectEq("pid", an.pid, 42);
  ExpectEq("ticks per second", static_cast<unsigned long long>(info.ticksPerSecond), 1000);
  ExpectStr("program file", info.exeFile, "slowapp.exe");
  ExpectStr("thread name", info.threadNames.count(1) ? info.threadNames.at(1) : "", "Thread 1 (main)");
  ExpectEq("threads of the program (created one added)", an.targetThreads.size(), 3);
  ExpectEq("window end from END", an.lastTs, 300);
  ExpectEq("context switches from END", an.contextSwitches, 50);
  ExpectEq("waits with a stack", an.waitsWithStack, 1);
  ExpectEq("waits without a stack (window-start waits)", an.waitsWithoutStack, 2);
  ExpectEq("kernel-only stack parts", an.kernelOnlyFragments, 1);
  const ThreadState& mainThread = an.threads.at(1);
  ExpectEq("main waiting (40 lock + 110 asleep at the end)", mainThread.waitTicks, 150);
  ExpectEq("main running", mainThread.runTicks, 40);
  ExpectEq("main ready", mainThread.readyTicks, 10);

  DumpSymbols sym(lines);
  for (const auto& [key, b] : an.buckets) {
    if (b.tid == 1 && b.reason == 37) {
      ExpectEq("lock wait ticks", b.ticks, 40);
      ExpectEq("lock released by saver", TopWaker(b), 2);
      ExpectStr("your code, named from the dump", YourCodeFrame(b, sym),
                "slowapp!`anonymous namespace'::update_frame");
      ExpectStr("blocked in", BlockedInFrame(b, sym), "ntdll!RtlSleepConditionVariableSRW");
    }
    if (b.tid == 1 && b.reason == 4) {
      ExpectEq("sleep still waiting at the end", b.stillWaitingAtEnd, 1);
      ExpectEq("sleep stack from the snapshot", b.stack.size() == 1 ? b.stack[0] : 0, 0x7ff600000030);
    }
  }
  ExpectStr("source file", sym.SourceFile(0x7ff600000020), "c:\\src\\slowapp.cpp");
  ExpectStr("address without a name", sym.Name(0x1234), "?!0x1234");
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
  CheckVersion2();
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
