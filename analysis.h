// analysis.h - waitwhy's analysis core (D7): turns typed kernel events into per-thread time
// splits and buckets of waits with their call stacks and wakers, and classifies the waits from
// the names of their stack frames.
//
// It makes no Windows calls, so tests can drive it with recorded or hand-written events on
// any machine, without a kernel trace or Administrator rights. waitwhy.cpp decodes the ETW
// events into the typed events below and hands them to an Analyzer.

#ifndef WAITWHY_ANALYSIS_H
#define WAITWHY_ANALYSIS_H

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace waitwhy {

constexpr int8_t kThreadStateTerminated = 4;  // KTHREAD_STATE: Terminated
constexpr int8_t kThreadStateWaiting = 5;     // KTHREAD_STATE: Waiting
constexpr int8_t kReasonUnknown = -1;         // our marker: blocked since before the trace began
constexpr uint32_t kUnknownThread = 0xFFFFFFFFu;
constexpr uint32_t kSystemWaker = 0;          // idle thread, or a DPC (timer, finished I/O)
constexpr uint8_t kReadyFlagFromDpc = 0x1;    // ReadyThread Flag: readied from a DPC
constexpr uint64_t kUserSpaceLimit = 0x0000800000000000ull;  // addresses above are kernel code

// Upper limit on finished waits per thread that are still waiting for their call stack.
// Beyond it the oldest one is recorded without a stack, so memory stays bounded.
constexpr size_t kMaxWaitsAwaitingStack = 64;

// ---------------------------------------------------------------------------
// Typed events (DESIGN.md 4.1). Timestamps are QueryPerformanceCounter ticks.
// ---------------------------------------------------------------------------

// A context switch: `oldTid` leaves a CPU, `newTid` gets it.
struct SwitchEvent {
  uint64_t ts = 0;
  uint32_t oldTid = kUnknownThread;
  uint32_t newTid = kUnknownThread;
  int8_t oldState = 0;       // KTHREAD_STATE of the thread leaving
  int8_t oldWaitReason = 0;  // KWAIT_REASON of the thread leaving
};

// A thread was readied (made able to run again). `byTid` is the thread that readied it,
// kSystemWaker for a DPC, as resolved by ResolveWaker.
struct ReadyEvent {
  uint64_t ts = 0;
  uint32_t readiedTid = kUnknownThread;
  uint32_t byTid = kUnknownThread;
};

// A call stack, or a part of one. `eventTs` is the timestamp of the context switch it was
// captured for; `ts` is when it was delivered. Only user-mode frames are passed in,
// innermost first; an empty list is a kernel-only part.
struct StackEvent {
  uint64_t ts = 0;
  uint64_t eventTs = 0;
  uint32_t tid = kUnknownThread;
  std::vector<uint64_t> userFrames;
};

struct ThreadEvent {
  enum class Kind { Created, Existing, Ended };  // Existing: rundown at trace start
  uint64_t ts = 0;
  uint32_t pid = 0;
  uint32_t tid = kUnknownThread;
  Kind kind = Kind::Created;
};

// Who readied a thread (W3, W4). A DPC (a timer firing, an I/O finishing) borrows whatever
// thread happens to be on the CPU; that thread did not wake ours, the system did. Otherwise
// the event is logged by the readying thread, so its header names the waker; the thread last
// switched in on that CPU is the fallback when the header has no thread.
inline uint32_t ResolveWaker(uint8_t readyFlag, uint32_t headerThread, uint32_t threadOnCpu) {
  if (readyFlag & kReadyFlagFromDpc) return kSystemWaker;
  return headerThread != kUnknownThread ? headerThread : threadOnCpu;
}

// ---------------------------------------------------------------------------
// What the analysis accumulates
// ---------------------------------------------------------------------------

// One period where a thread was switched off the CPU.
struct OffCpu {
  uint64_t start = 0;
  uint64_t end = 0;
  uint64_t readyAt = 0;    // when another thread or the system readied it; 0 = not yet
  int8_t reason = 0;       // kernel wait reason code
  bool isWait = false;     // true = blocked; false = preempted (it wanted the CPU)
  uint32_t wokenBy = kUnknownThread;
  std::vector<uint64_t> stack;  // user-mode return addresses, innermost first
};

// One stretch of a thread's time, kept for wait chains (W25): what a thread was doing while
// another one waited for it.
struct Interval {
  enum Kind : uint8_t { Running, Ready, Waiting };
  uint64_t start = 0;
  uint64_t end = 0;
  uint64_t bucket = 0;  // Waiting: HashWait of its bucket, so (tid, bucket) finds it
  uint32_t wokenBy = kUnknownThread;  // Waiting: the thread that ended it
  Kind kind = Running;
};

// Upper limit on intervals kept for all threads together (about 32 MB). Beyond it no more are
// kept and the report says its wait chains are incomplete.
constexpr size_t kMaxIntervals = size_t{1} << 20;

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
  // The part of the window the thread existed in (W20): from its creation, if that was during
  // the trace, to its end, if it ended. 0 means the window's own start or end.
  uint64_t bornAt = 0;
  uint64_t endedAt = 0;
  std::vector<Interval> intervals;  // in the order they were recorded, not sorted
};

// Wait durations on a log scale with four steps per doubling (W23), so a percentile is known to
// within about 20% while memory stays small: one entry per step that occurs.
inline uint16_t DurationStep(uint64_t ticks) {
  if (ticks == 0) return 0;
  int e = 63;
  while (!(ticks >> e)) --e;
  const unsigned sub = e >= 2 ? static_cast<unsigned>((ticks >> (e - 2)) & 3) : 0;
  return static_cast<uint16_t>(1 + e * 4 + static_cast<int>(sub));
}

// The longest duration that falls into `step`.
inline uint64_t DurationStepMax(uint16_t step) {
  if (step == 0) return 0;
  const int e = (step - 1) / 4;
  const uint64_t sub = static_cast<uint64_t>((step - 1) % 4);
  if (e < 2) return (uint64_t{2} << e) - 1;
  return ((5 + sub) << (e - 2)) - 1;
}

struct DurationHistogram {
  std::map<uint16_t, uint32_t> steps;
  uint64_t longest = 0;
  uint64_t count = 0;

  void Add(uint64_t ticks) {
    ++steps[DurationStep(ticks)];
    longest = (std::max)(longest, ticks);
    ++count;
  }
  void Add(const DurationHistogram& other) {
    for (const auto& [step, n] : other.steps) steps[step] += n;
    longest = (std::max)(longest, other.longest);
    count += other.count;
  }
  // At most this long for a share `q` of the waits (e.g. 0.95), rounded up to its step.
  uint64_t Quantile(double q) const {
    const auto rank = static_cast<uint64_t>(std::ceil(q * static_cast<double>(count)));
    uint64_t seen = 0;
    for (const auto& [step, n] : steps) {
      seen += n;
      if (seen >= rank) return (std::min)(DurationStepMax(step), longest);
    }
    return longest;
  }
};

// All waits of one thread that share the same call stack and wait reason.
struct Bucket {
  uint32_t tid = 0;
  int8_t reason = 0;
  uint64_t ticks = 0;
  uint32_t count = 0;
  DurationHistogram durations;  // each wait's own length (W23)
  bool stillWaitingAtEnd = false;
  std::vector<uint64_t> stack;
  std::map<uint32_t, uint64_t> wakers;  // waking thread id -> wait time it ended
};

inline uint64_t HashWait(int8_t reason, const std::vector<uint64_t>& stack) {
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

// ---------------------------------------------------------------------------
// The analysis: thread state machine (DESIGN.md 4.2) and stack matcher (4.3)
// ---------------------------------------------------------------------------

class Analyzer {
 public:
  // The process being watched, and whether stacks were switched on for context switches.
  // Without stacks no wait waits for one.
  uint32_t pid = 0;
  bool stacksOn = false;

  std::unordered_set<uint32_t> targetThreads;
  std::unordered_set<uint32_t> exitedThreads;  // the program's threads that ended while traced
  std::unordered_map<uint32_t, ThreadState> threads;
  std::map<std::pair<uint32_t, uint64_t>, Bucket> buckets;
  // The observation window. waitwhy.cpp sets firstTs to the moment tracing starts, before any
  // event arrives, and lastTs to the moment it stops (W20). Without that (old dumps, tests)
  // they are the first and last context switch.
  uint64_t firstTs = 0;
  uint64_t lastTs = 0;

  uint64_t contextSwitches = 0;
  uint64_t waitsWithStack = 0;
  uint64_t waitsWithoutStack = 0;
  uint64_t kernelOnlyFragments = 0;  // stack events for a wait that held no user-mode frame
  uint64_t endedWaitTicks = 0;        // wait time in waits that ended inside the window
  uint64_t unknownWakerTicks = 0;     // ... of which no waker was seen (W24)
  size_t intervalCount = 0;           // intervals kept, for all threads (W25)
  bool intervalsTruncated = false;    // kMaxIntervals was reached

  bool IsTarget(uint32_t tid) const { return targetThreads.count(tid) != 0; }
  bool IsProgramThread(uint32_t tid) const {
    return targetThreads.count(tid) != 0 || exitedThreads.count(tid) != 0;
  }

  // An event logged before the window started still says what state a thread is in, but its
  // time counts from the start of the window.
  uint64_t InWindow(uint64_t ts) const { return (std::max)(ts, firstTs); }

  // The time thread `tid` existed inside the window, in ticks.
  uint64_t Lifetime(uint32_t tid) const {
    auto it = threads.find(tid);
    const uint64_t from = it != threads.end() && it->second.bornAt ? it->second.bornAt : firstTs;
    const uint64_t to = it != threads.end() && it->second.endedAt ? it->second.endedAt : lastTs;
    return to > from ? to - from : 0;
  }

  void OnSwitch(const SwitchEvent& e) {
    if (firstTs == 0) firstTs = e.ts;
    lastTs = e.ts;
    ++contextSwitches;
    const uint64_t ts = InWindow(e.ts);

    // A thread of the target process leaves the CPU.
    if (IsTarget(e.oldTid)) {
      ThreadState& st = threads[e.oldTid];
      if (!st.seen && !st.offCpu) {  // it was already running when the trace started
        st.running = true;
        st.runStart = firstTs;
      }
      st.seen = true;
      if (st.running) {
        st.runTicks += ts - st.runStart;
        Keep(st, Interval::Running, st.runStart, ts);
        st.running = false;
      }
      // An exited thread never comes back, so there is no off-CPU period to open.
      if (e.oldState != kThreadStateTerminated) {
        // Earlier waits still awaiting their stack stay in `awaitingStack`, separate from this.
        st.open = OffCpu{};
        st.open.start = ts;
        st.open.reason = e.oldWaitReason;
        st.open.isWait = (e.oldState == kThreadStateWaiting);
        st.offCpu = true;
      }
    }

    // A thread of the target process gets back on a CPU.
    if (IsTarget(e.newTid)) {
      ThreadState& st = threads[e.newTid];
      OpenPeriodFromWindowStart(st, ts);
      st.seen = true;
      if (st.offCpu) {
        st.open.end = ts;
        st.offCpu = false;
        if (!st.open.isWait || !stacksOn) {
          Record(e.newTid, st, st.open, false);  // no stack needed, or none will come
        } else {
          // Its user-mode stack is logged after this event, possibly much later: either for
          // this switch-in, or for an earlier one when the thread has not been back in user
          // mode since (W14). OnStack finds it by the event's own timestamp either way.
          st.awaitingStack.emplace(e.ts, std::move(st.open));
          if (st.awaitingStack.size() > kMaxWaitsAwaitingStack) {
            auto oldest = st.awaitingStack.begin();
            RecordWithoutStack(e.newTid, st, oldest->second);
            st.awaitingStack.erase(oldest);
          }
        }
      }
      st.running = true;
      st.runStart = ts;
    }
  }

  void OnReady(const ReadyEvent& e) {
    if (!IsTarget(e.readiedTid)) return;
    ThreadState& st = threads[e.readiedTid];
    const uint64_t ts = InWindow(e.ts);
    OpenPeriodFromWindowStart(st, ts);
    if (!st.offCpu) return;
    if (st.open.readyAt == 0) st.open.readyAt = ts;
    st.open.wokenBy = e.byTid;
  }

  void OnThread(const ThreadEvent& e) {
    if (e.pid != pid) return;
    if (e.kind == ThreadEvent::Kind::Ended) {
      OnThreadEnd(e);
      return;
    }
    targetThreads.insert(e.tid);
    exitedThreads.erase(e.tid);
    // A new thread was not blocked or running before the trace, so the window-start periods
    // (W6) do not apply to it. A reused thread ID keeps adding to the same totals.
    if (e.kind == ThreadEvent::Kind::Created) {
      ThreadState& st = threads[e.tid];
      st.seen = true;
      st.bornAt = InWindow(e.ts);
      st.endedAt = 0;
    }
  }

  void OnStack(const StackEvent& e) {
    if (!IsTarget(e.tid)) return;
    ThreadState& st = threads[e.tid];

    // One stack can arrive as two events with the same EventTimeStamp: the kernel part,
    // logged at the switch, and the user part, logged once the thread is back in user mode.
    // Only user-mode frames are kept, so the kernel part is skipped and the wait keeps
    // waiting for its user part (W1).
    if (e.userFrames.empty()) {
      if (st.awaitingStack.count(e.eventTs)) ++kernelOnlyFragments;
      return;
    }

    // The user part is stamped with the switch-in it was captured for, and the thread can
    // block several more times before it gets back to user mode and the part is logged. Every
    // wait that ended in between happened inside the same call into the kernel, so they all
    // share this stack (W14). The stamped switch-in itself may have ended a preemption, not a
    // wait. Waits that ended before it belong to an earlier user-mode stack and are left alone.
    auto it = st.awaitingStack.lower_bound(e.eventTs);
    const auto last = st.awaitingStack.upper_bound((std::max)(e.ts, e.eventTs));
    while (it != last) {
      it->second.stack = e.userFrames;
      ++waitsWithStack;
      Record(e.tid, st, it->second, false);
      it = st.awaitingStack.erase(it);
    }
  }

  // A thread that is off the CPU when the trace ends never gets the stack that is logged at
  // its next switch-in, and a thread blocked for the whole window has no events at all. Both
  // get one stack snapshot instead (W7), taken by the caller.
  bool NeedsSnapshot(uint32_t tid) const {
    auto it = threads.find(tid);
    if (it == threads.end()) return true;  // never seen: blocked the whole window
    const ThreadState& st = it->second;
    const bool blockedWholeWindow = !st.seen && !st.offCpu;
    return blockedWholeWindow || (st.offCpu && st.open.isWait);
  }

  // A whole-window thread becomes one wait from the window start; FlushAtEnd records both
  // kinds as still waiting at the end.
  void ApplySnapshot(uint32_t tid, std::vector<uint64_t> frames) {
    ThreadState& st = threads[tid];
    if (!st.seen && !st.offCpu) {
      st.open = OffCpu{};
      st.open.start = firstTs;
      st.open.reason = kReasonUnknown;
      st.open.isWait = true;
      st.offCpu = true;
      st.seen = true;
    }
    st.open.stack = std::move(frames);
  }

  // Called after tracing stops: close out anything still in progress.
  void FlushAtEnd() {
    for (auto& [tid, st] : threads) {
      if (st.running && lastTs > st.runStart) {
        st.runTicks += lastTs - st.runStart;
        Keep(st, Interval::Running, st.runStart, lastTs);
      }
      for (auto& entry : st.awaitingStack) RecordWithoutStack(tid, st, entry.second);
      st.awaitingStack.clear();
      if (st.offCpu && lastTs > st.open.start) {
        st.open.end = lastTs;  // still off the CPU when the trace ended
        Record(tid, st, st.open, true);
      }
      st.offCpu = false;
    }
  }

 private:
  void Record(uint32_t tid, ThreadState& st, const OffCpu& w, bool stillWaiting) {
    if (!w.isWait) {
      st.readyTicks += w.end > w.start ? w.end - w.start : 0;  // preempted: wanted the CPU
      Keep(st, Interval::Ready, w.start, w.end);
      return;
    }
    // A wait ends when the thread is readied; from then until it is back on a CPU it only
    // wanted a CPU, so that part counts as ready time, not as waiting (W5).
    const uint64_t waitEnd = (w.readyAt > w.start && w.readyAt < w.end) ? w.readyAt : w.end;
    const uint64_t d = waitEnd > w.start ? waitEnd - w.start : 0;
    st.readyTicks += w.end > waitEnd ? w.end - waitEnd : 0;
    st.waitTicks += d;
    const uint64_t hash = HashWait(w.reason, w.stack);
    Keep(st, Interval::Waiting, w.start, waitEnd, hash, w.wokenBy);
    Keep(st, Interval::Ready, waitEnd, w.end);
    Bucket& b = buckets[{tid, hash}];
    if (b.count == 0) {
      b.tid = tid;
      b.reason = w.reason;
      b.stack = w.stack;
    }
    b.ticks += d;
    b.count += 1;
    b.durations.Add(d);
    if (stillWaiting) b.stillWaitingAtEnd = true;
    if (!stillWaiting) {
      endedWaitTicks += d;
      if (w.wokenBy == kUnknownThread) unknownWakerTicks += d;
    }
    if (w.wokenBy != kUnknownThread) b.wakers[w.wokenBy] += d;
  }

  // Keeps one interval of a thread's time for wait chains, while there is room.
  void Keep(ThreadState& st, Interval::Kind kind, uint64_t start, uint64_t end, uint64_t bucket = 0,
            uint32_t wokenBy = kUnknownThread) {
    if (end <= start) return;
    if (intervalCount >= kMaxIntervals) {
      intervalsTruncated = true;
      return;
    }
    Interval i;
    i.start = start;
    i.end = end;
    i.bucket = bucket;
    i.wokenBy = wokenBy;
    i.kind = kind;
    st.intervals.push_back(i);
    ++intervalCount;
  }

  // Records a finished wait whose call stack never arrived.
  void RecordWithoutStack(uint32_t tid, ThreadState& st, const OffCpu& w) {
    ++waitsWithoutStack;
    Record(tid, st, w, false);
  }

  // A thread whose first event is being readied or switched in was already off the CPU when
  // the trace started. Opens that period from the start of the window. Its wait reason is
  // not known, so it is classified from the stack that arrives at its switch-in (W6).
  void OpenPeriodFromWindowStart(ThreadState& st, uint64_t ts) {
    if (st.seen || st.offCpu) return;
    st.open = OffCpu{};
    st.open.start = firstTs != 0 ? firstTs : ts;
    st.open.reason = kReasonUnknown;
    st.open.isWait = true;
    st.offCpu = true;
  }

  // The thread ID can be reused by a new thread, possibly in another process, so it stops
  // being tracked here (W8). What it did so far stays in the report.
  void OnThreadEnd(const ThreadEvent& e) {
    if (!IsTarget(e.tid)) return;
    ThreadState& st = threads[e.tid];
    const uint64_t ts = InWindow(e.ts);
    if (st.running && ts > st.runStart) {
      st.runTicks += ts - st.runStart;
      Keep(st, Interval::Running, st.runStart, ts);
    }
    st.running = false;
    st.endedAt = ts;
    for (auto& entry : st.awaitingStack) RecordWithoutStack(e.tid, st, entry.second);
    st.awaitingStack.clear();
    st.offCpu = false;
    st.seen = true;
    targetThreads.erase(e.tid);
    exitedThreads.insert(e.tid);
  }
};

// ---------------------------------------------------------------------------
// Symbols: what the classification rules need to know about an address
// ---------------------------------------------------------------------------

// How a module's function names were found (W24).
enum class SymbolKind {
  Unknown,      // not recorded (old dumps, tests)
  Full,         // from the module's .pdb: every function has its own name
  ExportsOnly,  // only exported functions: others get the nearest export's name
  None,         // no names at all
};

// Names code addresses. waitwhy.cpp implements it with DbgHelp; tests use a fixed table.
class SymbolSource {
 public:
  virtual ~SymbolSource() = default;
  // "module!function", or "module!0x1234" when no name is available.
  virtual const std::string& Name(uint64_t addr) = 0;
  // Lower-case path of the source file the code at `addr` came from, with backslashes; empty
  // when there is no line information for it.
  virtual const std::string& SourceFile(uint64_t addr) = 0;
  // True when `name` (as returned by Name) is in the program's own executable.
  virtual bool IsExeFrame(const std::string& name) const = 0;
  // How names in `module` (the part of a name before '!') were found.
  virtual SymbolKind ModuleSymbols(const std::string& module) const {
    (void)module;
    return SymbolKind::Unknown;
  }
};

inline std::string Lower(std::string s) {
  for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  return s;
}

// ---------------------------------------------------------------------------
// Turning stacks into plain English
// ---------------------------------------------------------------------------

enum class Category { Lock, Disk, Network, Sleep, OtherThread, PageFault, Other };

inline const char* CategoryLabel(Category c) {
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

inline const char* CategorySentence(Category c) {
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

inline const char* WaitReasonName(int8_t r) {
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

inline bool HasAny(const std::string& text, std::initializer_list<const char*> words) {
  for (const char* w : words)
    if (text.find(w) != std::string::npos) return true;
  return false;
}

inline Category Classify(const Bucket& b, SymbolSource& sym) {
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
inline bool IsRuntimeFrame(const std::string& function, const std::string& sourceFile) {
  for (const char* dir : {"\\vctools\\crt\\", "\\crts\\ucrt\\", "\\vc\\tools\\msvc\\",
                          "\\windows kits\\"})
    if (sourceFile.find(dir) != std::string::npos) return true;
  for (const char* prefix : {"std::", "_", "Concurrency::", "concurrency::", "mtx_do_lock",
                             "thread_start<", "invoke_main", "mainCRTStartup", "wmainCRTStartup",
                             "WinMainCRTStartup", "wWinMainCRTStartup"})
    if (function.rfind(prefix, 0) == 0) return true;
  return false;
}

constexpr const char kNotYourCode[] = "(not in your program's code)";

// First frame in the program's own code, skipping the C++ runtime linked into it.
inline std::string YourCodeFrame(const Bucket& b, SymbolSource& sym) {
  for (uint64_t a : b.stack) {
    const std::string& n = sym.Name(a);
    if (!sym.IsExeFrame(n)) continue;
    if (IsRuntimeFrame(n.substr(n.find('!') + 1), sym.SourceFile(a))) continue;
    return n;
  }
  return kNotYourCode;
}

// A wait for work to arrive, as idle thread-pool workers do (W21): in the thread pool's
// worker-factory wait, or in a kernel queue (WrQueue, also I/O completion ports).
inline bool IsWaitForWork(const Bucket& b, SymbolSource& sym) {
  if (b.reason == 15) return true;  // WrQueue
  for (uint64_t a : b.stack)
    if (HasAny(Lower(sym.Name(a)), {"workerfactory", "tppworkerthread", "tppwaiterpthread"}))
      return true;
  return false;
}

// Innermost frame, skipping the raw system-call stubs (ntdll!Nt..., ntdll!Zw...).
inline std::string BlockedInFrame(const Bucket& b, SymbolSource& sym) {
  for (uint64_t a : b.stack) {
    const std::string& n = sym.Name(a);
    std::string lower = Lower(n);
    if (lower.rfind("ntdll!nt", 0) == 0 || lower.rfind("ntdll!zw", 0) == 0) continue;
    return n;
  }
  return b.stack.empty() ? "(no call stack recorded)" : sym.Name(b.stack.front());
}

inline uint32_t TopWaker(const Bucket& b) {
  uint32_t best = kUnknownThread;
  uint64_t bestTicks = 0;
  for (auto& [tid, t] : b.wakers)
    if (t > bestTicks) best = tid, bestTicks = t;
  return best;
}


inline std::string FormatDuration(double seconds) {
  char buf[32];
  if (seconds >= 1.0)
    std::snprintf(buf, sizeof buf, "%.2f s", seconds);
  else
    std::snprintf(buf, sizeof buf, "%.0f ms", seconds * 1000.0);
  return buf;
}

}  // namespace waitwhy

#endif  // WAITWHY_ANALYSIS_H
