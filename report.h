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
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis.h"

namespace waitwhy {

struct ReportOptions {
  double ticksPerSecond = 1.0;
  size_t topN = 6;
  uint64_t eventsLost = 0;
  uint64_t buffersLost = 0;
  bool stacksOn = true;
  bool symbolsOk = true;  // the program could be opened to read function names
  std::string exeFile;    // the program's file name; empty when unknown
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
  Category category = Category::Other;
  std::string yourCode;
  std::string blockedIn;
  std::string wokenBy;
  int8_t reason = 0;
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
  // For a lock wait: the program thread that released the lock and what it spends its time on.
  bool hasReleaser = false;
  std::string releaser;
  Category releaserCategory = Category::Other;
  std::string releaserCode;
};

struct Report {
  std::string program;  // file name, or "process"
  uint32_t pid = 0;
  double windowSeconds = 0;
  std::vector<std::string> warnings;
  std::vector<ThreadRow> threads;
  int unseenThreads = 0;  // never ran during the window
  bool anyWaits = false;
  std::vector<WaitRow> waits;  // the biggest, at most topN
  std::vector<Finding> findings;
  uint64_t contextSwitches = 0;
  uint64_t waitsWithStack = 0;
  uint64_t waitsWithoutStack = 0;
  uint64_t kernelOnlyFragments = 0;
};

inline std::string WakerLabel(const Analyzer& an, uint32_t tid, const ThreadNamer& name) {
  if (tid == kUnknownThread) return "unknown";
  if (an.IsProgramThread(tid)) return name(tid);
  if (tid == kSystemWaker) return "the system (a timer or finished I/O)";
  return "outside your program (thread " + std::to_string(tid) + ")";
}

inline Report BuildReport(const Analyzer& an, SymbolSource& sym, const ReportOptions& opt,
                          const ThreadNamer& name) {
  Report r;
  const double window = an.lastTs > an.firstTs
                            ? static_cast<double>(an.lastTs - an.firstTs) / opt.ticksPerSecond
                            : 0.0;
  auto secs = [&](uint64_t ticks) { return static_cast<double>(ticks) / opt.ticksPerSecond; };
  auto pct = [&](uint64_t ticks) { return window > 0 ? 100.0 * secs(ticks) / window : 0.0; };

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
  for (uint32_t tid : tids) {
    const ThreadState& st = an.threads.at(tid);
    ThreadRow row;
    row.tid = tid;
    row.label = name(tid);
    row.runningPct = pct(st.runTicks);
    row.waitingPct = pct(st.waitTicks);
    row.readyPct = pct(st.readyTicks);
    r.threads.push_back(row);
  }

  // Biggest waits. Buckets are in key order, and the sort keeps ties in that order.
  std::vector<const Bucket*> buckets;
  for (const auto& [key, b] : an.buckets) buckets.push_back(&b);
  std::stable_sort(buckets.begin(), buckets.end(),
                   [](const Bucket* x, const Bucket* y) { return x->ticks > y->ticks; });
  r.anyWaits = !buckets.empty();
  std::unordered_map<const Bucket*, Category> category;
  for (const Bucket* b : buckets) category[b] = Classify(*b, sym);
  for (size_t i = 0; i < buckets.size() && i < opt.topN; ++i) {
    const Bucket& b = *buckets[i];
    WaitRow w;
    w.tid = b.tid;
    w.thread = name(b.tid);
    w.seconds = secs(b.ticks);
    w.pct = pct(b.ticks);
    w.count = b.count;
    w.stillWaitingAtEnd = b.stillWaitingAtEnd;
    w.category = category[&b];
    w.yourCode = YourCodeFrame(b, sym);
    w.blockedIn = BlockedInFrame(b, sym);
    w.wokenBy = WakerLabel(an, TopWaker(b), name);
    w.reason = b.reason;
    r.waits.push_back(w);
  }

  // Plain-English findings.
  for (uint32_t tid : tids) {
    for (const Bucket* b : buckets) {
      if (b->tid != tid) continue;
      const Category c = category[b];
      if (c == Category::Sleep || pct(b->ticks) < 10.0) continue;
      Finding f;
      f.tid = tid;
      f.thread = name(tid);
      f.pct = pct(b->ticks);
      f.category = c;
      f.yourCode = YourCodeFrame(*b, sym);
      const uint32_t waker = TopWaker(*b);
      if (c == Category::Lock && an.IsProgramThread(waker) && waker != tid) {
        // What was the thread that released the lock busy with?
        for (const Bucket* wb : buckets) {
          if (wb->tid != waker) continue;
          const Category wc = category[wb];
          if (wc == Category::Lock || wc == Category::Sleep) continue;
          if (wb->stack.empty()) continue;  // nothing to say about where its time went
          f.hasReleaser = true;
          f.releaser = name(waker);
          f.releaserCategory = wc;
          f.releaserCode = YourCodeFrame(*wb, sym);
          break;
        }
      }
      r.findings.push_back(f);
    }
    const ThreadState& st = an.threads.at(tid);
    if (pct(st.readyTicks) >= 20.0) {
      Finding f;
      f.kind = Finding::Kind::CpuCompetition;
      f.tid = tid;
      f.thread = name(tid);
      f.pct = pct(st.readyTicks);
      r.findings.push_back(f);
    }
  }

  r.contextSwitches = an.contextSwitches;
  r.waitsWithStack = an.waitsWithStack;
  r.waitsWithoutStack = an.waitsWithoutStack;
  r.kernelOnlyFragments = an.kernelOnlyFragments;
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
    Appendf(out, "      Your code  : %s\n", w.yourCode.c_str());
    Appendf(out, "      Blocked in : %s\n", w.blockedIn.c_str());
    Appendf(out, "      Woken by   : %s\n", w.wokenBy.c_str());
    if (w.reason == kReasonUnknown)
      Appendf(out, "      Wait reason: not known (already blocked when the trace started)\n");
    else
      Appendf(out, "      Wait reason: %s (kernel code %d)\n", WaitReasonName(w.reason), w.reason);
  }

  Appendf(out, "\nWhat this means\n");
  for (const Finding& f : r.findings) {
    if (f.kind == Finding::Kind::CpuCompetition) {
      Appendf(out,
              "  * %s spent %.0f%% of the time ready to run but waiting for a free CPU.\n"
              "    The machine is busy; this is CPU competition, not a blocking problem.\n",
              f.thread.c_str(), f.pct);
      continue;
    }
    Appendf(out, "  * %s spent %.0f%% of the time %s, in %s.\n", f.thread.c_str(), f.pct,
            CategorySentence(f.category), f.yourCode.c_str());
    if (f.hasReleaser) {
      Appendf(out, "    The lock was released by %s, which spends its time %s, in %s.\n",
              f.releaser.c_str(), CategorySentence(f.releaserCategory), f.releaserCode.c_str());
      Appendf(out,
              "    It is most likely holding the lock during that slow work. Move the\n"
              "    slow work outside the lock (copy the data first, then do the work).\n");
    }
  }
  if (r.findings.empty())
    Appendf(out, "  No thread lost a significant share of its time to blocking (sleeps excluded).\n");

  Appendf(out,
          "\n(%llu context switches seen, %llu waits with a call stack,"
          " %llu waits without a call stack, %llu kernel-only stack parts)\n",
          static_cast<unsigned long long>(r.contextSwitches),
          static_cast<unsigned long long>(r.waitsWithStack),
          static_cast<unsigned long long>(r.waitsWithoutStack),
          static_cast<unsigned long long>(r.kernelOnlyFragments));
  return out;
}

}  // namespace waitwhy

#endif  // WAITWHY_REPORT_H
