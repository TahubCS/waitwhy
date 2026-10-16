// analysis_tests.cpp - unit tests for the analysis core (analysis.h): wait classification,
// the choice of "your code" and "blocked in" frames, and small hand-written event sequences.
// Frame names are the ones real reports showed for slowapp. No Windows calls; runs in CI on
// Windows and Linux.
//
// Build and run:
//   cl /nologo /EHsc /O2 /std:c++17 tests\analysis_tests.cpp /Fe:analysis_tests.exe
//   g++ -std=c++17 -Wall -Wextra tests/analysis_tests.cpp -o analysis_tests

#include "../analysis.h"
#include "check.h"

#include <string>

using namespace waitwhy;

namespace {

// Symbols for a made-up slowapp.exe: frame i of a stack is address 0x1000 + i, named in order.
class FakeSymbols : public SymbolSource {
 public:
  // `frames` are "module!function" or "module!function @ source-file".
  std::vector<uint64_t> Stack(std::initializer_list<const char*> frames) {
    std::vector<uint64_t> stack;
    for (const char* f : frames) {
      std::string text = f;
      std::string file;
      const size_t at = text.find(" @ ");
      if (at != std::string::npos) {
        file = text.substr(at + 3);
        text = text.substr(0, at);
      }
      const uint64_t addr = 0x1000 + names_.size();
      names_[addr] = text;
      files_[addr] = file;
      stack.push_back(addr);
    }
    return stack;
  }
  const std::string& Name(uint64_t addr) override { return names_[addr]; }
  const std::string& SourceFile(uint64_t addr) override { return files_[addr]; }
  bool IsExeFrame(const std::string& name) const override { return name.rfind("slowapp!", 0) == 0; }

 private:
  std::map<uint64_t, std::string> names_;
  std::map<uint64_t, std::string> files_;
};

void ExpectCategory(const char* what, Category got, Category want) {
  ExpectStr(what, CategoryLabel(got), CategoryLabel(want));
}

Bucket MakeBucket(std::vector<uint64_t> stack, int8_t reason) {
  Bucket b;
  b.stack = std::move(stack);
  b.reason = reason;
  return b;
}

// main in buggy slowapp, CI run #59: blocked in std::mutex::lock inside update_frame. ntdll
// only resolves to its nearest export, RtlSleepConditionVariableSRW (W13).
void CheckLockWait() {
  std::printf("Lock wait in update_frame (W9, W13)\n");
  FakeSymbols sym;
  const Bucket b = MakeBucket(
      sym.Stack({"ntdll!NtWaitForAlertByThreadId", "ntdll!RtlSleepConditionVariableSRW",
                 "slowapp!mtx_do_lock @ d:\\a\\_work\\1\\s\\src\\vctools\\crt\\github\\stl\\src\\mutex.cpp",
                 "slowapp!_Mtx_lock", "slowapp!std::mutex::lock",
                 "slowapp!`anonymous namespace'::update_frame @ c:\\src\\waitwhy\\slowapp.cpp",
                 "slowapp!main @ c:\\src\\waitwhy\\slowapp.cpp", "slowapp!invoke_main",
                 "kernel32!BaseThreadInitThunk"}),
      37);
  ExpectCategory("category", Classify(b, sym), Category::Lock);
  ExpectStr("your code", YourCodeFrame(b, sym), "slowapp!`anonymous namespace'::update_frame");
  ExpectStr("blocked in", BlockedInFrame(b, sym), "ntdll!RtlSleepConditionVariableSRW");
}

void CheckConditionVariable() {
  std::printf("Condition variable wait names its mutex too (W13)\n");
  FakeSymbols sym;
  const Bucket b = MakeBucket(
      sym.Stack({"ntdll!NtWaitForAlertByThreadId", "ntdll!RtlSleepConditionVariableSRW",
                 "slowapp!_Cnd_wait", "slowapp!std::condition_variable::wait",
                 "slowapp!worker"}),
      37);
  ExpectCategory("category", Classify(b, sym), Category::OtherThread);
  ExpectStr("your code", YourCodeFrame(b, sym), "slowapp!worker");
}

void CheckDiskWait() {
  std::printf("Disk wait in write_settings_to_disk\n");
  FakeSymbols sym;
  const Bucket b = MakeBucket(
      sym.Stack({"ntdll!NtWriteFile", "KERNELBASE!WriteFile",
                 "slowapp!`anonymous namespace'::write_settings_to_disk",
                 "slowapp!`anonymous namespace'::save_settings"}),
      0);
  ExpectCategory("category", Classify(b, sym), Category::Disk);
  ExpectStr("your code", YourCodeFrame(b, sym),
            "slowapp!`anonymous namespace'::write_settings_to_disk");
  ExpectStr("blocked in (skips the Nt stub)", BlockedInFrame(b, sym), "KERNELBASE!WriteFile");
}

void CheckSleep() {
  std::printf("Sleeps, by name and by wait reason\n");
  FakeSymbols sym;
  const Bucket named = MakeBucket(
      sym.Stack({"ntdll!NtDelayExecution", "KERNELBASE!SleepEx",
                 "slowapp!`anonymous namespace'::ticker_thread"}),
      0);
  ExpectCategory("NtDelayExecution", Classify(named, sym), Category::Sleep);
  ExpectCategory("DelayExecution reason, no stack", Classify(MakeBucket({}, 4), sym),
                 Category::Sleep);
  ExpectCategory("WrDelayExecution reason, no stack", Classify(MakeBucket({}, 11), sym),
                 Category::Sleep);
}

void CheckNetworkAndThreads() {
  std::printf("Network, other threads, page faults\n");
  FakeSymbols sym;
  ExpectCategory("recv", Classify(MakeBucket(sym.Stack({"mswsock!WSPRecv", "ws2_32!recv", "slowapp!serve"}), 6), sym),
                 Category::Network);
  ExpectCategory("WaitForSingleObject",
                 Classify(MakeBucket(sym.Stack({"ntdll!NtWaitForSingleObject",
                                                "KERNELBASE!WaitForSingleObject", "slowapp!run"}),
                                     6),
                          sym),
                 Category::OtherThread);
  ExpectCategory("std::thread::join",
                 Classify(MakeBucket(sym.Stack({"KERNELBASE!WaitForSingleObjectEx", "slowapp!_Thrd_join",
                                                "slowapp!std::thread::join", "slowapp!main"}),
                                     6),
                          sym),
                 Category::OtherThread);
  ExpectCategory("PageIn reason, no stack", Classify(MakeBucket({}, 2), sym), Category::PageFault);
  ExpectCategory("UserRequest reason, no stack", Classify(MakeBucket({}, 6), sym),
                 Category::OtherThread);
  ExpectCategory("Executive reason, no stack", Classify(MakeBucket({}, 0), sym), Category::Other);
}

void CheckFrameChoice() {
  std::printf("Frame choice without program code or stack\n");
  FakeSymbols sym;
  const Bucket idle = MakeBucket(
      sym.Stack({"ntdll!NtWaitForWorkViaWorkerFactory", "ntdll!TpCallbackMayRunLong",
                 "kernel32!BaseThreadInitThunk"}),
      kReasonUnknown);
  ExpectStr("your code", YourCodeFrame(idle, sym), "(not in your program's code)");
  ExpectStr("blocked in", BlockedInFrame(idle, sym), "ntdll!TpCallbackMayRunLong");
  ExpectStr("no stack", BlockedInFrame(MakeBucket({}, 0), sym), "(no call stack recorded)");
  ExpectCategory("idle worker is something else", Classify(idle, sym), Category::Other);
  ExpectEq("idle worker waits for work (W21)", IsWaitForWork(idle, sym), 1);
  ExpectEq("WrQueue reason waits for work", IsWaitForWork(MakeBucket({}, 15), sym), 1);
  const Bucket sleeping = MakeBucket(
      sym.Stack({"ntdll!NtDelayExecution", "KERNELBASE!SleepEx", "kernel32!BaseThreadInitThunk"}), 4);
  ExpectEq("a sleep is not a wait for work", IsWaitForWork(sleeping, sym), 0);
}

void CheckRuntimeFrames() {
  std::printf("Runtime frames are not your code (W9)\n");
  ExpectEq("CRT source path", IsRuntimeFrame("helper", "d:\\a\\_work\\1\\s\\src\\vctools\\crt\\x.cpp"), 1);
  ExpectEq("std:: name", IsRuntimeFrame("std::mutex::lock", ""), 1);
  ExpectEq("invoke_main", IsRuntimeFrame("invoke_main", ""), 1);
  ExpectEq("program function", IsRuntimeFrame("`anonymous namespace'::update_frame", "c:\\src\\slowapp.cpp"), 0);
}

void CheckTopWakerAndDuration() {
  std::printf("Top waker and durations\n");
  Bucket b;
  b.wakers = {{10, 5}, {20, 50}, {30, 7}};
  ExpectEq("thread that ended the most wait time", TopWaker(b), 20);
  ExpectEq("no wakers", TopWaker(Bucket{}), kUnknownThread);
  ExpectStr("seconds", FormatDuration(1.5), "1.50 s");
  ExpectStr("milliseconds", FormatDuration(0.0123), "12 ms");
}

// A wait readied by another thread: the time until the readying counts as waiting, the time
// from readying to switch-in as wanting a CPU (W5); the waker is recorded (W4).
void CheckReadySplitsWaitTime() {
  std::printf("Ready time is not wait time (W5)\n");
  Analyzer an;
  an.pid = 1;
  an.targetThreads = {100, 200};
  auto sw = [&](uint64_t ts, uint32_t oldTid, uint32_t newTid, int8_t state, int8_t reason) {
    SwitchEvent e;
    e.ts = ts;
    e.oldTid = oldTid;
    e.newTid = newTid;
    e.oldState = state;
    e.oldWaitReason = reason;
    an.OnSwitch(e);
  };
  sw(1000, 0, 100, 0, 0);           // 100 starts running
  sw(1100, 100, 200, 5, 37);        // 100 blocks on a lock, 200 runs
  ReadyEvent r;
  r.ts = 1400;
  r.readiedTid = 100;
  r.byTid = 200;
  an.OnReady(r);                    // 200 releases the lock
  sw(1500, 200, 100, 2, 0);         // 200 preempted (state Ready), 100 back on the CPU
  sw(1600, 100, 0, 5, 4);           // 100 sleeps until the end
  an.FlushAtEnd();
  const ThreadState& t = an.threads.at(100);
  ExpectEq("waiting ticks (300 lock + 0 sleep at end)", t.waitTicks, 300);
  ExpectEq("ready ticks", t.readyTicks, 100);
  ExpectEq("running ticks", t.runTicks, 200);
  uint64_t lockTicks = 0;
  uint32_t waker = kUnknownThread;
  for (const auto& [key, b] : an.buckets)
    if (b.tid == 100 && b.reason == 37) lockTicks = b.ticks, waker = TopWaker(b);
  ExpectEq("lock bucket ticks", lockTicks, 300);
  ExpectEq("lock released by", waker, 200);
  // W25: running 1000-1100, waiting 1100-1400 (ended by 200), ready 1400-1500, running 1500-1600.
  ExpectEq("intervals kept for wait chains", t.intervals.size(), 4);
  unsigned long long waitedFor200 = 0;
  for (const Interval& i : t.intervals)
    if (i.kind == Interval::Waiting && i.wokenBy == 200) waitedFor200 += i.end - i.start;
  ExpectEq("time waiting for thread 200", waitedFor200, 300);
}

// W20: the window starts when tracing starts. An event logged earlier still sets the thread's
// state, but no time before the window counts; a thread created or ended inside the window is
// measured against its own lifetime.
void CheckWindowAndLifetime() {
  std::printf("Exact window and thread lifetimes (W20)\n");
  Analyzer an;
  an.pid = 1;
  an.firstTs = 1000;
  an.targetThreads = {5};
  SwitchEvent e;
  e.ts = 900;  // before the window: thread 5 goes to sleep
  e.oldTid = 5;
  e.newTid = 0;
  e.oldState = kThreadStateWaiting;
  e.oldWaitReason = 4;
  an.OnSwitch(e);
  e = SwitchEvent{};
  e.ts = 1500;  // and wakes up
  e.oldTid = 0;
  e.newTid = 5;
  an.OnSwitch(e);
  ThreadEvent t;
  t.ts = 1200;
  t.pid = 1;
  t.tid = 6;
  t.kind = ThreadEvent::Kind::Created;
  an.OnThread(t);
  t.ts = 1700;
  t.tid = 5;
  t.kind = ThreadEvent::Kind::Ended;
  an.OnThread(t);
  an.lastTs = 2000;
  an.FlushAtEnd();
  ExpectEq("window start kept", an.firstTs, 1000);
  ExpectEq("sleep counted from the window start", an.threads.at(5).waitTicks, 500);
  ExpectEq("running until it ended", an.threads.at(5).runTicks, 200);
  ExpectEq("lifetime of the thread that ended", an.Lifetime(5), 700);
  ExpectEq("lifetime of the thread created during the trace", an.Lifetime(6), 800);
  ExpectEq("lifetime of a thread never seen is the window", an.Lifetime(99), 1000);
}

// W23: wait durations on a log scale with four steps per doubling.
void CheckDurationHistogram() {
  std::printf("Wait duration histogram (W23)\n");
  ExpectEq("step of 0", DurationStep(0), 0);
  ExpectEq("step of 1", DurationStep(1), 1);
  ExpectEq("largest value in the step of 3", DurationStepMax(DurationStep(3)), 3);
  ExpectEq("step of 100 (96..111)", DurationStep(100), 27);
  ExpectEq("largest value in step 27", DurationStepMax(27), 111);
  DurationHistogram h;
  for (uint64_t d = 1; d <= 100; ++d) h.Add(d);
  ExpectEq("count", h.count, 100);
  ExpectEq("longest", h.longest, 100);
  ExpectEq("95% at most (step 80..95)", h.Quantile(0.95), 95);
  ExpectEq("100% is the longest", h.Quantile(1.0), 100);
  DurationHistogram merged;
  merged.Add(h);
  merged.Add(5000);
  ExpectEq("merged longest", merged.longest, 5000);
  ExpectEq("merged count", merged.count, 101);
}

}  // namespace

int main() {
  CheckLockWait();
  CheckConditionVariable();
  CheckDiskWait();
  CheckSleep();
  CheckNetworkAndThreads();
  CheckFrameChoice();
  CheckRuntimeFrames();
  CheckTopWakerAndDuration();
  CheckReadySplitsWaitTime();
  CheckWindowAndLifetime();
  CheckDurationHistogram();
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
