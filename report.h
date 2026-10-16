// report.h - builds waitwhy's report as plain data from the analysis (W19), and prints it.
//
// The live run and a report rebuilt from a dump (--from-dump) go through the same code, so the
// two must print the same text. It makes no Windows calls (D7).

#ifndef WAITWHY_REPORT_H
#define WAITWHY_REPORT_H

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <tuple>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis.h"

namespace waitwhy {

struct ReportOptions {
  double ticksPerSecond = 1.0;
  size_t topN = 6;
  double minMs = 10.0;  // smaller groups of waits are counted, not shown (W22)
  double stallMs = 50.0;  // a single wait this long is a finding on its own (W23)
  uint64_t eventsLost = 0;
  uint64_t buffersLost = 0;
  bool stacksOn = true;
  bool symbolsOk = true;  // the program could be opened to read function names
  std::string exeFile;    // the program's file name; empty when unknown
  bool namesFromTrace = false;  // the program had exited; names from its recorded modules (W26)
  std::string pdbNextToExe;     // a .pdb with the program's name beside it, if any (W26)
};

// The label of one of the program's threads, e.g. "Thread 37808 (main)".
using ThreadNamer = std::function<std::string(uint32_t)>;

struct ThreadRow {
  uint32_t tid = 0;
  std::string label;
  double runningPct = 0;
  double waitingPct = 0;
  double readyPct = 0;
};

struct WaitRow {
  uint32_t tid = 0;
  std::string thread;
  double seconds = 0;
  double pct = 0;
  uint32_t count = 0;
  bool stillWaitingAtEnd = false;
  double longestSeconds = 0;  // the longest single wait (W23)
  double p95Seconds = -1;     // 95% of the waits took at most this; -1 below 20 waits
  Category category = Category::Other;
  std::string yourCode;
  // The system functions it was blocked in, with their share of the row's wait time, largest
  // first (W22).
  std::vector<std::pair<std::string, double>> blockedIn;
  std::string wokenBy;
  int8_t reason = 0;  // the known kernel wait reason with the most time; kReasonUnknown if none
  // The objects its file I/O was on (W28), with their share of the row, largest first.
  std::vector<std::pair<std::string, double>> objects;
};

// What the thread that ended a group of waits was doing during them (W25).
struct ChainPart {
  enum class Kind { Running, Ready, Waiting, NotSeen };
  Kind kind = Kind::Waiting;
  Category category = Category::Other;  // Kind::Waiting
  std::string yourCode;                 // Kind::Waiting
  double seconds = 0;
  double pct = 0;  // of the waits' time
};

// One line of "What this means", with what explains it.
struct Finding {
  enum class Kind { Wait, CpuCompetition };
  Kind kind = Kind::Wait;
  uint32_t tid = 0;
  std::string thread;
  double pct = 0;
  Category category = Category::Other;  // Kind::Wait
  std::string yourCode;                 // Kind::Wait
  double longestSeconds = 0;            // Kind::Wait: the longest single wait
  bool longWait = false;                // Kind::Wait: the longest reached stallMs (W23)
  bool onlyLongWait = false;            // Kind::Wait: a finding only because of it
  // For a lock wait: the program thread that released the lock and what it spends its time on.
  bool hasReleaser = false;
  std::string releaser;
  Category releaserCategory = Category::Other;
  std::string releaserCode;
  // Measured wait chain (W25): the thread that ended these waits and what it did meanwhile,
  // largest part first. Empty when nothing was measured.
  std::string waker;
  double chainSeconds = 0;  // the waits it ended
  std::vector<ChainPart> chain;
};

// How far the report can be trusted (W24).
struct DataQuality {
  enum class Level { High, Medium, Low };
  Level confidence = Level::High;
  std::vector<std::string> reasons;  // why it is not high
  uint64_t eventsLost = 0;
  uint64_t buffersLost = 0;
  double stackPct = 100;     // share of all wait time with a user-mode call stack
  double wakerKnownPct = -1;  // share of the time in finished waits whose waker is known; -1: none
  std::vector<std::string> fullModules, exportModules, unnamedModules;
  bool modulesKnown = false;  // the symbol status was recorded
  bool programNamed = true;   // the program's own module has a .pdb (or it is not known)
  std::string pdbNextToExe;   // set when a .pdb lies beside the program but was not used
};

inline const char* LevelName(DataQuality::Level l) {
  return l == DataQuality::Level::High ? "high" : l == DataQuality::Level::Medium ? "medium" : "low";
}

struct Report {
  std::string program;  // file name, or "process"
  uint32_t pid = 0;
  double windowSeconds = 0;
  std::vector<std::string> warnings;
  std::vector<ThreadRow> threads;
  int unseenThreads = 0;  // never ran during the window
  std::vector<uint32_t> idleThreads;  // only waited for work outside the program (W21)
  bool anyWaits = false;
  std::vector<WaitRow> waits;  // the biggest, at most topN, none under minMs
  size_t hiddenWaitRows = 0;   // rows left out by minMs or topN
  double hiddenWaitSeconds = 0;
  std::vector<Finding> findings;
  DataQuality quality;
  uint64_t contextSwitches = 0;
  uint64_t waitsWithStack = 0;
  uint64_t waitsWithoutStack = 0;
  uint64_t kernelOnlyFragments = 0;
};

inline std::string WakerLabel(const Analyzer& an, uint32_t tid, const ThreadNamer& name) {
  if (tid == kUnknownThread) return "unknown";
  if (an.IsProgramThread(tid)) return name(tid);
  if (tid == kSystemWaker) return "the system (a timer or finished I/O)";
  auto process = an.threadProcess.find(tid);
  if (process != an.threadProcess.end()) {
    if (process->second == Analyzer::kSystemProcess)
      return "the system (kernel thread " + std::to_string(tid) + ")";
    auto pname = an.processNames.find(process->second);
    if (pname != an.processNames.end() && !pname->second.empty())
      return "outside your program (thread " + std::to_string(tid) + " of " + pname->second + ")";
    return "outside your program (thread " + std::to_string(tid) + ", process " +
           std::to_string(process->second) + ")";
  }
  return "outside your program (thread " + std::to_string(tid) + ")";
}

// All waits of one thread on one kind of thing at one place in the program's code (W22): one
// activity, however many call stacks and wait reasons it took.
struct WaitGroup {
  uint32_t tid = 0;
  Category category = Category::Other;
  std::string yourCode;
  uint64_t ticks = 0;
  uint32_t count = 0;
  bool stillWaitingAtEnd = false;
  bool anyStack = false;
  DurationHistogram durations;
  std::map<uint32_t, uint64_t> wakers;
  std::map<int8_t, uint64_t> reasons;
  std::map<std::string, uint64_t> blockedIn;
  std::map<std::string, uint64_t> objects;  // W28
};

inline uint32_t TopWaker(const WaitGroup& g) {
  uint32_t best = kUnknownThread;
  uint64_t bestTicks = 0;
  for (const auto& [tid, t] : g.wakers)
    if (t > bestTicks) best = tid, bestTicks = t;
  return best;
}

inline Report BuildReport(const Analyzer& an, SymbolSource& sym, const ReportOptions& opt,
                          const ThreadNamer& name) {
  Report r;
  const double window = an.lastTs > an.firstTs
                            ? static_cast<double>(an.lastTs - an.firstTs) / opt.ticksPerSecond
                            : 0.0;
  auto secs = [&](uint64_t ticks) { return static_cast<double>(ticks) / opt.ticksPerSecond; };
  // Shares are of the thread's own time in the window (W20): a thread that started or ended
  // during the trace is not measured against time it did not exist.
  auto pct = [&](uint32_t tid, uint64_t ticks) {
    const uint64_t life = an.Lifetime(tid);
    return life > 0 ? 100.0 * static_cast<double>(ticks) / static_cast<double>(life) : 0.0;
  };

  r.program = opt.exeFile.empty() ? "process" : opt.exeFile;
  r.pid = an.pid;
  r.windowSeconds = window;
  char line[160];
  if (opt.eventsLost || opt.buffersLost) {
    std::snprintf(line, sizeof line,
                  "Windows dropped %llu events (%llu buffers). Numbers may be a bit low.",
                  static_cast<unsigned long long>(opt.eventsLost),
                  static_cast<unsigned long long>(opt.buffersLost));
    r.warnings.push_back(line);
  }
  if (!opt.stacksOn)
    r.warnings.push_back("call stacks were not available, so code locations are missing.");
  if (!opt.symbolsOk)
    r.warnings.push_back("could not open the process to read function names (did it exit?).");
  if (opt.namesFromTrace)
    r.warnings.push_back("the program exited during the trace; function names come from the modules it had loaded.");

  // Per-thread summary, most waiting first. Ties go by thread ID, so the order never depends
  // on how a hash map happens to be laid out.
  std::vector<uint32_t> tids;  // includes threads that exited during the trace
  for (const auto& [tid, st] : an.threads)
    if (st.seen) tids.push_back(tid);
  for (uint32_t tid : an.targetThreads) {
    auto it = an.threads.find(tid);
    if (it == an.threads.end() || !it->second.seen) ++r.unseenThreads;
  }
  std::sort(tids.begin(), tids.end(), [&an](uint32_t x, uint32_t y) {
    const uint64_t wx = an.threads.at(x).waitTicks, wy = an.threads.at(y).waitTicks;
    return wx != wy ? wx > wy : x < y;
  });

  // Idle threads (W21): they hardly ran (at most 5% of their lifetime), none of their waits was
  // in the program's code, and at least 90% of their wait time was a wait for work, so a new
  // worker's short start-up wait does not count against it. They are counted, not reported.
  std::unordered_map<uint32_t, std::vector<const Bucket*>> byThread;
  for (const auto& [key, b] : an.buckets) byThread[b.tid].push_back(&b);
  auto isIdle = [&](uint32_t tid) {
    const uint64_t life = an.Lifetime(tid);
    if (life == 0 || an.threads.at(tid).runTicks * 20 > life) return false;
    auto it = byThread.find(tid);
    if (it == byThread.end()) return false;
    uint64_t total = 0, forWork = 0;
    for (const Bucket* b : it->second) {
      if (YourCodeFrame(*b, sym) != kNotYourCode) return false;
      total += b->ticks;
      if (IsWaitForWork(*b, sym)) forWork += b->ticks;
    }
    return total > 0 && forWork * 10 >= total * 9;
  };
  std::vector<uint32_t> shown;
  for (uint32_t tid : tids) (isIdle(tid) ? r.idleThreads : shown).push_back(tid);
  tids = shown;
  std::sort(r.idleThreads.begin(), r.idleThreads.end());
  auto idle = [&r](uint32_t tid) {
    return std::find(r.idleThreads.begin(), r.idleThreads.end(), tid) != r.idleThreads.end();
  };

  for (uint32_t tid : tids) {
    const ThreadState& st = an.threads.at(tid);
    ThreadRow row;
    row.tid = tid;
    row.label = name(tid);
    row.runningPct = pct(tid, st.runTicks);
    row.waitingPct = pct(tid, st.waitTicks);
    row.readyPct = pct(tid, st.readyTicks);
    r.threads.push_back(row);
  }

  // Group the waits by activity (W22). The map keeps groups in a fixed order, and the sort keeps
  // ties in that order.
  std::map<std::tuple<uint32_t, int, std::string>, WaitGroup> groupMap;
  // The object of a bucket's file I/O, once its name is known (W28).
  auto objectKind = [&an](const Bucket& b) {
    const Analyzer::FileName* f = an.FileOf(b.fileObject);
    return f ? f->kind : ObjectKind::None;
  };
  // By name a ReadFile or WriteFile is the disk. When no file request says what it was on, and
  // a thread rather than the system ended the wait (the other end of a pipe, the console host),
  // the wait was for that thread (W28).
  auto categoryOf = [&](const Bucket& b) {
    const ObjectKind object = objectKind(b);
    const Category c = Classify(b, sym, object);
    if (c == Category::Disk && object == ObjectKind::None && an.WokenByAThread(TopWaker(b), b.tid))
      return Category::OtherThread;
    return c;
  };
  for (const auto& [key, b] : an.buckets) {
    if (idle(b.tid)) continue;
    const Category c = categoryOf(b);
    const std::string code = YourCodeFrame(b, sym);
    WaitGroup& g = groupMap[{b.tid, static_cast<int>(c), code}];
    g.tid = b.tid;
    g.category = c;
    g.yourCode = code;
    g.ticks += b.ticks;
    g.count += b.count;
    g.stillWaitingAtEnd = g.stillWaitingAtEnd || b.stillWaitingAtEnd;
    g.anyStack = g.anyStack || !b.stack.empty();
    g.durations.Add(b.durations);
    for (const auto& [waker, t] : b.wakers) g.wakers[waker] += t;
    g.reasons[b.reason] += b.ticks;
    g.blockedIn[BlockedInFrame(b, sym)] += b.ticks;
    if (const Analyzer::FileName* f = an.FileOf(b.fileObject))
      g.objects[DescribeObject(f->kind == ObjectKind::None ? ObjectKind::Device : f->kind, f->path)] += b.ticks;
  }
  std::vector<const WaitGroup*> groups;
  for (const auto& [key, g] : groupMap) groups.push_back(&g);
  // Which group each bucket went into, for wait chains (W25).
  std::map<std::pair<uint32_t, uint64_t>, const WaitGroup*> groupOfBucket;
  for (const auto& [key, b] : an.buckets) {
    if (idle(b.tid)) continue;
    groupOfBucket[key] =
        &groupMap.at({b.tid, static_cast<int>(categoryOf(b)), YourCodeFrame(b, sym)});
  }

  // What thread `waker` did during the waits of `waiter` in `g` that it ended (W25).
  auto measureChain = [&](uint32_t waiter, const WaitGroup* g, uint32_t waker, Finding& f) {
    auto wt = an.threads.find(waiter);
    auto kt = an.threads.find(waker);
    if (wt == an.threads.end() || kt == an.threads.end()) return;
    std::vector<Interval> theirs = kt->second.intervals;
    std::sort(theirs.begin(), theirs.end(),
              [](const Interval& x, const Interval& y) { return x.start < y.start; });
    uint64_t total = 0, running = 0, ready = 0;
    std::map<const WaitGroup*, uint64_t> waiting;
    for (const Interval& w : wt->second.intervals) {
      if (w.kind != Interval::Waiting || w.wokenBy != waker) continue;
      auto gi = groupOfBucket.find({waiter, w.bucket});
      if (gi == groupOfBucket.end() || gi->second != g) continue;
      total += w.end - w.start;
      // Intervals of one thread do not overlap, so the first one that may overlap is found
      // by its start, one step back.
      auto it = std::lower_bound(theirs.begin(), theirs.end(), w.start,
                                 [](const Interval& x, uint64_t t) { return x.start < t; });
      if (it != theirs.begin()) --it;
      for (; it != theirs.end() && it->start < w.end; ++it) {
        const uint64_t a = (std::max)(it->start, w.start), b = (std::min)(it->end, w.end);
        if (b <= a) continue;
        if (it->kind == Interval::Running) running += b - a;
        else if (it->kind == Interval::Ready) ready += b - a;
        else {
          auto ki = groupOfBucket.find({waker, it->bucket});
          if (ki != groupOfBucket.end()) waiting[ki->second] += b - a;
        }
      }
    }
    if (total == 0) return;
    auto part = [&](ChainPart::Kind kind, uint64_t ticks, const WaitGroup* wg) {
      ChainPart p;
      p.kind = kind;
      p.seconds = secs(ticks);
      p.pct = 100.0 * static_cast<double>(ticks) / static_cast<double>(total);
      if (wg) {
        p.category = wg->category;
        p.yourCode = wg->yourCode;
      }
      if (p.pct >= 1.0) f.chain.push_back(p);
    };
    uint64_t covered = running + ready;
    for (const auto& [wg, ticks] : waiting) {
      part(ChainPart::Kind::Waiting, ticks, wg);
      covered += ticks;
    }
    part(ChainPart::Kind::Running, running, nullptr);
    part(ChainPart::Kind::Ready, ready, nullptr);
    if (covered < total) part(ChainPart::Kind::NotSeen, total - covered, nullptr);
    std::stable_sort(f.chain.begin(), f.chain.end(),
                     [](const ChainPart& x, const ChainPart& y) { return x.seconds > y.seconds; });
    f.waker = name(waker);
    f.chainSeconds = secs(total);
  };
  std::stable_sort(groups.begin(), groups.end(),
                   [](const WaitGroup* x, const WaitGroup* y) { return x->ticks > y->ticks; });
  r.anyWaits = !groups.empty();

  const double minTicks = opt.minMs / 1000.0 * opt.ticksPerSecond;
  for (const WaitGroup* g : groups) {
    if (r.waits.size() >= opt.topN || static_cast<double>(g->ticks) < minTicks) {
      ++r.hiddenWaitRows;
      r.hiddenWaitSeconds += secs(g->ticks);
      continue;
    }
    WaitRow w;
    w.tid = g->tid;
    w.thread = name(g->tid);
    w.seconds = secs(g->ticks);
    w.pct = pct(g->tid, g->ticks);
    w.count = g->count;
    w.stillWaitingAtEnd = g->stillWaitingAtEnd;
    w.longestSeconds = secs(g->durations.longest);
    if (g->durations.count >= 20) w.p95Seconds = secs(g->durations.Quantile(0.95));
    w.category = g->category;
    w.yourCode = g->yourCode;
    for (const auto& [fn, t] : g->blockedIn)
      w.blockedIn.emplace_back(fn, g->ticks ? 100.0 * static_cast<double>(t) / static_cast<double>(g->ticks) : 0.0);
    std::stable_sort(w.blockedIn.begin(), w.blockedIn.end(),
                     [](const auto& x, const auto& y) { return x.second > y.second; });
    w.wokenBy = WakerLabel(an, TopWaker(*g), name);
    for (const auto& [object, t] : g->objects)
      w.objects.emplace_back(object, g->ticks ? 100.0 * static_cast<double>(t) / static_cast<double>(g->ticks) : 0.0);
    std::stable_sort(w.objects.begin(), w.objects.end(),
                     [](const auto& x, const auto& y) { return x.second > y.second; });
    w.reason = kReasonUnknown;
    uint64_t best = 0;
    for (const auto& [reason, t] : g->reasons)
      if (reason != kReasonUnknown && (w.reason == kReasonUnknown || t > best)) w.reason = reason, best = t;
    r.waits.push_back(w);
  }

  // Plain-English findings.
  for (uint32_t tid : tids) {
    for (const WaitGroup* g : groups) {
      if (g->tid != tid) continue;
      const Category c = g->category;
      if (c == Category::Sleep) continue;
      // A single long wait freezes the thread even when its share of the time is small, e.g. a
      // UI thread that misses frames (W23). Waits for another thread are left out of this:
      // workers waiting for jobs do that by design.
      const bool longWait = secs(g->durations.longest) * 1000.0 >= opt.stallMs &&
                            c != Category::Other && c != Category::OtherThread;
      const bool bigShare = pct(tid, g->ticks) >= 10.0;
      if (!bigShare && !longWait) continue;
      Finding f;
      f.tid = tid;
      f.thread = name(tid);
      f.pct = pct(tid, g->ticks);
      f.category = c;
      f.yourCode = g->yourCode;
      f.longestSeconds = secs(g->durations.longest);
      f.longWait = longWait;
      f.onlyLongWait = !bigShare;
      const uint32_t waker = TopWaker(*g);
      if ((c == Category::Lock || c == Category::OtherThread) && an.IsProgramThread(waker) &&
          waker != tid)
        measureChain(tid, g, waker, f);
      if (c == Category::Lock && an.IsProgramThread(waker) && waker != tid) {
        // What was the thread that released the lock busy with?
        for (const WaitGroup* wg : groups) {
          if (wg->tid != waker) continue;
          if (wg->category == Category::Lock || wg->category == Category::Sleep) continue;
          if (!wg->anyStack) continue;  // nothing to say about where its time went
          f.hasReleaser = true;
          f.releaser = name(waker);
          f.releaserCategory = wg->category;
          f.releaserCode = wg->yourCode;
          break;
        }
      }
      r.findings.push_back(f);
    }
    const ThreadState& st = an.threads.at(tid);
    if (pct(tid, st.readyTicks) >= 20.0) {
      Finding f;
      f.kind = Finding::Kind::CpuCompetition;
      f.tid = tid;
      f.thread = name(tid);
      f.pct = pct(tid, st.readyTicks);
      r.findings.push_back(f);
    }
  }

  r.contextSwitches = an.contextSwitches;
  r.waitsWithStack = an.waitsWithStack;
  r.waitsWithoutStack = an.waitsWithoutStack;
  r.kernelOnlyFragments = an.kernelOnlyFragments;

  // Data quality (W24). Rules, from worst: low when there are no stacks, when under half of the
  // wait time has a stack, when more than 1% of events were lost, or when the program's own
  // code has no .pdb; medium when under 95% of the wait time has a stack, when any event was
  // lost, or when the waker of over 10% of the finished wait time is unknown.
  DataQuality& q = r.quality;
  q.eventsLost = opt.eventsLost;
  q.buffersLost = opt.buffersLost;
  uint64_t waitTicks = 0, stackTicks = 0;
  std::map<std::string, SymbolKind> modules;
  for (const auto& [key, b] : an.buckets) {
    waitTicks += b.ticks;
    if (!b.stack.empty()) stackTicks += b.ticks;
    for (uint64_t a : b.stack) {
      const std::string& n = sym.Name(a);
      const size_t bang = n.find('!');
      if (bang == std::string::npos || n.compare(0, bang, "?") == 0) continue;
      const std::string module = n.substr(0, bang);
      modules[module] = sym.ModuleSymbols(module);
      if (sym.IsExeFrame(n) && modules[module] != SymbolKind::Full &&
          modules[module] != SymbolKind::Unknown)
        q.programNamed = false;
    }
  }
  q.stackPct = waitTicks ? 100.0 * static_cast<double>(stackTicks) / static_cast<double>(waitTicks) : 100.0;
  if (an.endedWaitTicks)
    q.wakerKnownPct = 100.0 * static_cast<double>(an.endedWaitTicks - an.unknownWakerTicks) /
                      static_cast<double>(an.endedWaitTicks);
  for (const auto& [module, kind] : modules) {
    if (kind != SymbolKind::Unknown) q.modulesKnown = true;
    if (kind == SymbolKind::Full) q.fullModules.push_back(module);
    if (kind == SymbolKind::ExportsOnly) q.exportModules.push_back(module);
    if (kind == SymbolKind::None) q.unnamedModules.push_back(module);
  }
  const double events = static_cast<double>(an.contextSwitches + opt.eventsLost);
  const double lostPct = events > 0 ? 100.0 * static_cast<double>(opt.eventsLost) / events : 0.0;
  auto lower = [&q](DataQuality::Level l, std::string why) {
    if (static_cast<int>(l) > static_cast<int>(q.confidence)) q.confidence = l;
    q.reasons.push_back(std::move(why));
  };
  if (!opt.stacksOn) lower(DataQuality::Level::Low, "no call stacks");
  else if (q.stackPct < 50) lower(DataQuality::Level::Low, "most wait time has no call stack");
  else if (q.stackPct < 95) lower(DataQuality::Level::Medium, "some wait time has no call stack");
  if (lostPct > 1) lower(DataQuality::Level::Low, "many events lost");
  else if (opt.eventsLost) lower(DataQuality::Level::Medium, "some events lost");
  if (!q.programNamed)
    lower(DataQuality::Level::Low,
          opt.pdbNextToExe.empty() ? "no .pdb for the program" : "the program's .pdb does not match it");
  q.pdbNextToExe = q.programNamed ? std::string() : opt.pdbNextToExe;
  if (q.wakerKnownPct >= 0 && q.wakerKnownPct < 90)
    lower(DataQuality::Level::Medium, "many wakers unknown");
  if (an.intervalsTruncated) lower(DataQuality::Level::Medium, "wait chains incomplete");
  return r;
}

// printf into a std::string.
inline void Appendf(std::string& out, const char* format, ...) {
  char buf[1024];
  va_list args;
  va_start(args, format);
  const int n = std::vsnprintf(buf, sizeof buf, format, args);
  va_end(args);
  if (n < 0) return;
  if (static_cast<size_t>(n) < sizeof buf) {
    out += buf;
    return;
  }
  std::string big(static_cast<size_t>(n) + 1, '\0');
  va_start(args, format);
  std::vsnprintf(&big[0], big.size(), format, args);
  va_end(args);
  big.resize(static_cast<size_t>(n));
  out += big;
}

// The report as text. CI and scripts match some of these lines; keep them stable (README,
// "Report lines scripts can rely on").
inline std::string RenderText(const Report& r) {
  std::string out;
  Appendf(out, "\n==============================================================\n");
  Appendf(out, " waitwhy report: %s (PID %u), watched for %s\n", r.program.c_str(), r.pid,
          FormatDuration(r.windowSeconds).c_str());
  Appendf(out, "==============================================================\n");
  for (const std::string& w : r.warnings) Appendf(out, "Warning: %s\n", w.c_str());

  Appendf(out, "\nWhere each thread's time went\n");
  Appendf(out, "  %-30s %10s %10s %12s\n", "Thread", "Running", "Waiting", "Wanted CPU");
  for (const ThreadRow& t : r.threads)
    Appendf(out, "  %-30.30s %9.0f%% %9.0f%% %11.0f%%\n", t.label.c_str(), t.runningPct,
            t.waitingPct, t.readyPct);
  if (!r.idleThreads.empty())
    Appendf(out, "  (%zu idle thread-pool thread(s) not shown: they only waited for work, outside your code)\n",
            r.idleThreads.size());
  if (r.unseenThreads)
    Appendf(out, "  (%d more thread(s) never ran during the window: blocked the whole time or idle)\n",
            r.unseenThreads);

  Appendf(out, "\nBiggest waits\n");
  if (!r.anyWaits) Appendf(out, "  No waits recorded. Is the program doing anything?\n");
  for (size_t i = 0; i < r.waits.size(); ++i) {
    const WaitRow& w = r.waits[i];
    Appendf(out, "\n  #%zu  %s  waited %s (%.0f%% of the time) over %u wait(s)%s\n", i + 1,
            w.thread.c_str(), FormatDuration(w.seconds).c_str(), w.pct, w.count,
            w.stillWaitingAtEnd ? ", still waiting at the end" : "");
    Appendf(out, "      Waiting on : %s\n", CategoryLabel(w.category));
    if (!w.objects.empty()) {
      Appendf(out, "      Object     : %s", w.objects[0].first.c_str());
      if (w.objects.size() > 1) Appendf(out, " (%.0f%%), and %zu more", w.objects[0].second, w.objects.size() - 1);
      Appendf(out, "\n");
    }
    if (w.p95Seconds >= 0)
      Appendf(out, "      Longest    : %s (95%% of the waits took at most %s)\n",
              FormatDuration(w.longestSeconds).c_str(), FormatDuration(w.p95Seconds).c_str());
    else
      Appendf(out, "      Longest    : %s\n", FormatDuration(w.longestSeconds).c_str());
    Appendf(out, "      Your code  : %s\n", w.yourCode.c_str());
    // One system function, or the main ones with their shares.
    // Functions under 1% of the row are only counted.
    std::string blocked;
    size_t listed = 0;
    for (size_t k = 0; k < w.blockedIn.size() && listed < 3; ++k) {
      if (k > 0 && w.blockedIn[k].second < 1.0) break;
      if (listed++) blocked += ", ";
      blocked += w.blockedIn[k].first;
      if (w.blockedIn.size() > 1) Appendf(blocked, " (%.0f%%)", w.blockedIn[k].second);
    }
    if (w.blockedIn.size() > listed) Appendf(blocked, ", %zu more", w.blockedIn.size() - listed);
    Appendf(out, "      Blocked in : %s\n", blocked.c_str());
    Appendf(out, "      Woken by   : %s\n", w.wokenBy.c_str());
    if (w.reason == kReasonUnknown)
      Appendf(out, "      Wait reason: not known (already blocked when the trace started)\n");
    else
      Appendf(out, "      Wait reason: %s (kernel code %d)\n", WaitReasonName(w.reason), w.reason);
  }

  if (r.hiddenWaitRows)
    Appendf(out, "\n  (%zu smaller group(s) of waits not shown, %s in total; --top and --min-ms choose what is shown)\n",
            r.hiddenWaitRows, FormatDuration(r.hiddenWaitSeconds).c_str());

  Appendf(out, "\nWhat this means\n");
  for (const Finding& f : r.findings) {
    if (f.kind == Finding::Kind::CpuCompetition) {
      Appendf(out,
              "  * %s spent %.0f%% of the time ready to run but waiting for a free CPU.\n"
              "    The machine is busy; this is CPU competition, not a blocking problem.\n",
              f.thread.c_str(), f.pct);
      continue;
    }
    if (f.onlyLongWait) {
      Appendf(out, "  * %s was stuck for up to %s at a time %s, in %s (%.0f%% of the time in all).\n",
              f.thread.c_str(), FormatDuration(f.longestSeconds).c_str(),
              CategorySentence(f.category), f.yourCode.c_str(), f.pct);
    } else {
      Appendf(out, "  * %s spent %.0f%% of the time %s, in %s.\n", f.thread.c_str(), f.pct,
              CategorySentence(f.category), f.yourCode.c_str());
      if (f.longWait)
        Appendf(out, "    Its longest single wait was %s.\n", FormatDuration(f.longestSeconds).c_str());
    }
    if (!f.chain.empty()) {
      // Measured (W25): what the waker did while this thread waited for it.
      if (f.category == Category::Lock)
        Appendf(out, "    The lock was released by %s. While %s waited (%s), %s was\n",
                f.waker.c_str(), f.thread.c_str(), FormatDuration(f.chainSeconds).c_str(),
                f.waker.c_str());
      else
        Appendf(out, "    It was woken by %s. While %s waited (%s), %s was\n", f.waker.c_str(),
                f.thread.c_str(), FormatDuration(f.chainSeconds).c_str(), f.waker.c_str());
      for (size_t k = 0; k < f.chain.size() && k < 3; ++k) {
        const ChainPart& p = f.chain[k];
        std::string what = p.kind == ChainPart::Kind::Running   ? "running"
                           : p.kind == ChainPart::Kind::Ready   ? "waiting for a free CPU"
                           : p.kind == ChainPart::Kind::NotSeen ? "not seen (outside the trace)"
                                                                : std::string(CategorySentence(p.category)) + ", in " + p.yourCode;
        Appendf(out, "      %s: %s (%.0f%%)\n", what.c_str(), FormatDuration(p.seconds).c_str(), p.pct);
      }
      const ChainPart& top = f.chain.front();
      if (f.category == Category::Lock) {
        if (top.kind == ChainPart::Kind::Running)
          Appendf(out, "    So it holds the lock while it is running. Do less work while holding the lock.\n");
        else if (top.kind == ChainPart::Kind::Ready)
          Appendf(out, "    So it holds the lock while it is waiting for a free CPU. The machine is overloaded.\n");
        else if (top.kind == ChainPart::Kind::Waiting && top.category == Category::Sleep)
          Appendf(out, "    So it holds the lock while it is sleeping on purpose. Release the lock before sleeping.\n");
        else if (top.kind == ChainPart::Kind::Waiting && top.category == Category::Lock)
          Appendf(out, "    So it holds the lock while it is waiting for another lock: one lock waits on the next.\n");
        else if (top.kind == ChainPart::Kind::Waiting)
          Appendf(out,
                  "    So it holds the lock while it is %s. Move that work outside the lock\n"
                  "    (copy the data first, then do the work).\n",
                  CategorySentence(top.category));
      }
    } else if (f.hasReleaser) {
      Appendf(out, "    The lock was released by %s, which spends its time %s, in %s.\n",
              f.releaser.c_str(), CategorySentence(f.releaserCategory), f.releaserCode.c_str());
      Appendf(out,
              "    It is most likely holding the lock during that slow work. Move the\n"
              "    slow work outside the lock (copy the data first, then do the work).\n");
    }
  }
  if (r.findings.empty())
    Appendf(out, "  No thread lost a significant share of its time to blocking (sleeps excluded).\n");

  const DataQuality& q = r.quality;
  Appendf(out, "\nData quality: %s", LevelName(q.confidence));
  for (size_t i = 0; i < q.reasons.size(); ++i)
    Appendf(out, "%s%s", i ? ", " : " (", q.reasons[i].c_str());
  Appendf(out, "%s\n", q.reasons.empty() ? "" : ")");
  if (q.eventsLost || q.buffersLost)
    Appendf(out, "  Events lost      : %llu events, %llu buffers\n",
            static_cast<unsigned long long>(q.eventsLost), static_cast<unsigned long long>(q.buffersLost));
  else
    Appendf(out, "  Events lost      : none\n");
  Appendf(out, "  Call stacks      : %.0f%% of wait time (%llu waits with a call stack, %llu without; %llu kernel-only stack parts)\n",
          q.stackPct, static_cast<unsigned long long>(r.waitsWithStack),
          static_cast<unsigned long long>(r.waitsWithoutStack),
          static_cast<unsigned long long>(r.kernelOnlyFragments));
  if (q.wakerKnownPct >= 0)
    Appendf(out, "  Wakers known     : %.0f%% of the time in waits that ended\n", q.wakerKnownPct);
  auto join = [](const std::vector<std::string>& names) {
    std::string text;
    for (size_t i = 0; i < names.size(); ++i) text += (i ? ", " : "") + names[i];
    return text;
  };
  if (!q.modulesKnown) {
    Appendf(out, "  Function names   : not recorded\n");
  } else {
    std::string names;
    if (!q.fullModules.empty()) names += "full names in " + join(q.fullModules);
    if (!q.exportModules.empty())
      names += (names.empty() ? "" : "; ") + std::string("only exported names in ") + join(q.exportModules);
    if (!q.unnamedModules.empty())
      names += (names.empty() ? "" : "; ") + std::string("no names in ") + join(q.unnamedModules);
    Appendf(out, "  Function names   : %s\n", names.c_str());
    if (!q.exportModules.empty())
      Appendf(out, "                     (exported names only: a function that is not exported shows\n"
                   "                     as the nearest exported one, so those names can be wrong;\n"
                   "                     --symbols ms downloads Windows' own symbols)\n");
  }
  if (!q.pdbNextToExe.empty())
    Appendf(out, "  Note             : %s does not match the program; build both together (/Zi)\n",
            q.pdbNextToExe.c_str());
  Appendf(out, "  Context switches : %llu seen\n", static_cast<unsigned long long>(r.contextSwitches));
  return out;
}

}  // namespace waitwhy

#endif  // WAITWHY_REPORT_H
