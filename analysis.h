// analysis.h - waitwhy's analysis core (D7): turns typed kernel events into per-thread time
// splits and buckets of waits with their call stacks and wakers.
//
// It makes no Windows calls, so tests can drive it with recorded or hand-written events on
// any machine, without a kernel trace or Administrator rights. waitwhy.cpp decodes the ETW
// events into the typed events below and hands them to an Analyzer.

#ifndef WAITWHY_ANALYSIS_H
#define WAITWHY_ANALYSIS_H

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <map>
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
  uint64_t firstTs = 0;
  uint64_t lastTs = 0;

  uint64_t contextSwitches = 0;
  uint64_t waitsWithStack = 0;
  uint64_t waitsWithoutStack = 0;
  uint64_t kernelOnlyFragments = 0;  // stack events for a wait that held no user-mode frame

  bool IsTarget(uint32_t tid) const { return targetThreads.count(tid) != 0; }
  bool IsProgramThread(uint32_t tid) const {
    return targetThreads.count(tid) != 0 || exitedThreads.count(tid) != 0;
  }

  void OnSwitch(const SwitchEvent& e) {
    if (firstTs == 0) firstTs = e.ts;
    lastTs = e.ts;
    ++contextSwitches;

    // A thread of the target process leaves the CPU.
    if (IsTarget(e.oldTid)) {
      ThreadState& st = threads[e.oldTid];
      if (!st.seen && !st.offCpu) {  // it was already running when the trace started
        st.running = true;
        st.runStart = firstTs;
      }
      st.seen = true;
      if (st.running) {
        st.runTicks += e.ts - st.runStart;
        st.running = false;
      }
      // An exited thread never comes back, so there is no off-CPU period to open.
      if (e.oldState != kThreadStateTerminated) {
        // Earlier waits still awaiting their stack stay in `awaitingStack`, separate from this.
        st.open = OffCpu{};
        st.open.start = e.ts;
        st.open.reason = e.oldWaitReason;
        st.open.isWait = (e.oldState == kThreadStateWaiting);
        st.offCpu = true;
      }
    }

    // A thread of the target process gets back on a CPU.
    if (IsTarget(e.newTid)) {
      ThreadState& st = threads[e.newTid];
      OpenPeriodFromWindowStart(st, e.ts);
      st.seen = true;
      if (st.offCpu) {
        st.open.end = e.ts;
        st.offCpu = false;
        if (!st.open.isWait || !stacksOn) {
          Record(e.newTid, st, st.open, false);  // no stack needed, or none will come
        } else {
          // Its user-mode stack is logged after this event, possibly much later: either for
          // this switch-in, or for an earlier one when the thread has not been back in user
          // mode since (W14). OnStack finds it by timestamp either way.
          st.awaitingStack.emplace(e.ts, std::move(st.open));
          if (st.awaitingStack.size() > kMaxWaitsAwaitingStack) {
            auto oldest = st.awaitingStack.begin();
            RecordWithoutStack(e.newTid, st, oldest->second);
            st.awaitingStack.erase(oldest);
          }
        }
      }
      st.running = true;
      st.runStart = e.ts;
    }
  }

  void OnReady(const ReadyEvent& e) {
    if (!IsTarget(e.readiedTid)) return;
    ThreadState& st = threads[e.readiedTid];
    OpenPeriodFromWindowStart(st, e.ts);
    if (!st.offCpu) return;
    if (st.open.readyAt == 0) st.open.readyAt = e.ts;
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
    if (e.kind == ThreadEvent::Kind::Created) threads[e.tid].seen = true;
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
      if (st.running && lastTs > st.runStart) st.runTicks += lastTs - st.runStart;
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
      return;
    }
    // A wait ends when the thread is readied; from then until it is back on a CPU it only
    // wanted a CPU, so that part counts as ready time, not as waiting (W5).
    const uint64_t waitEnd = (w.readyAt > w.start && w.readyAt < w.end) ? w.readyAt : w.end;
    const uint64_t d = waitEnd > w.start ? waitEnd - w.start : 0;
    st.readyTicks += w.end > waitEnd ? w.end - waitEnd : 0;
    st.waitTicks += d;
    Bucket& b = buckets[{tid, HashWait(w.reason, w.stack)}];
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
    if (st.running && e.ts > st.runStart) st.runTicks += e.ts - st.runStart;
    st.running = false;
    for (auto& entry : st.awaitingStack) RecordWithoutStack(e.tid, st, entry.second);
    st.awaitingStack.clear();
    st.offCpu = false;
    st.seen = true;
    targetThreads.erase(e.tid);
    exitedThreads.insert(e.tid);
  }
};

}  // namespace waitwhy

#endif  // WAITWHY_ANALYSIS_H
