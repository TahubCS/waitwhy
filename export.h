// export.h - the program's threads as timelines for other viewers (W37): Chrome / Perfetto
// trace JSON (chrome://tracing, ui.perfetto.dev) and speedscope (speedscope.app). Both are
// made from the intervals the analysis keeps for wait chains (W25). No Windows calls (D7).

#ifndef WAITWHY_EXPORT_H
#define WAITWHY_EXPORT_H

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "analysis.h"
#include "report.h"

namespace waitwhy {

// The intervals of one thread in time order, with what each wait was on.
struct TimelineSlice {
  uint64_t start = 0, end = 0;
  Interval::Kind kind = Interval::Running;
  const Bucket* bucket = nullptr;  // Waiting
};

inline std::vector<TimelineSlice> ThreadTimeline(const Analyzer& an, uint32_t tid) {
  std::vector<TimelineSlice> slices;
  auto it = an.threads.find(tid);
  if (it == an.threads.end()) return slices;
  for (const Interval& i : it->second.intervals) {
    TimelineSlice s;
    s.start = i.start;
    s.end = i.end;
    s.kind = i.kind;
    if (i.kind == Interval::Waiting) {
      auto b = an.buckets.find({tid, i.bucket});
      if (b != an.buckets.end()) s.bucket = &b->second;
    }
    slices.push_back(s);
  }
  std::sort(slices.begin(), slices.end(),
            [](const TimelineSlice& x, const TimelineSlice& y) { return x.start < y.start; });
  return slices;
}

// The program's threads with a timeline, by thread ID.
inline std::vector<uint32_t> TimelineThreads(const Analyzer& an) {
  std::vector<uint32_t> tids;
  for (const auto& [tid, st] : an.threads)
    if (!st.intervals.empty()) tids.push_back(tid);
  std::sort(tids.begin(), tids.end());
  return tids;
}

// "lock in slowapp!update_frame", "sleep in slowapp!main", "running", ...
inline std::string SliceName(const Analyzer& an, const TimelineSlice& s, SymbolSource& sym) {
  if (s.kind == Interval::Running) return "running";
  if (s.kind == Interval::Ready) return "wanted a CPU";
  if (!s.bucket) return "waiting";
  return std::string(CategoryKey(CategoryOfBucket(an, *s.bucket, sym))) + " in " + YourCodeFrame(*s.bucket, sym);
}

// Chrome's Trace Event Format: one complete event ("ph":"X") per slice, times in microseconds
// from the start of the window, and the thread names as metadata.
inline std::string ExportChromeTrace(const Analyzer& an, const SymbolsFor& symbolsFor,
                                     const ThreadNamer& name, double ticksPerSecond,
                                     const std::string& program) {
  auto us = [&](uint64_t ticks) {
    return static_cast<double>(ticks > an.firstTs ? ticks - an.firstTs : 0) * 1e6 / ticksPerSecond;
  };
  std::string out = "{\"displayTimeUnit\": \"ms\", \"traceEvents\": [\n";
  bool first = true;
  auto event = [&](const std::string& json) {
    out += first ? "  " : ",\n  ";
    out += json;
    first = false;
  };
  std::map<uint32_t, bool> processes;
  for (uint32_t tid : TimelineThreads(an)) processes[an.ProcessOf(tid)] = true;
  for (const auto& [pid, unused] : processes) {
    (void)unused;
    std::string e;
    Appendf(e, "{\"name\": \"process_name\", \"ph\": \"M\", \"pid\": %u, \"args\": {\"name\": %s}}", pid,
            JsonString(pid == an.pid ? program : "process " + std::to_string(pid)).c_str());
    event(e);
  }
  for (uint32_t tid : TimelineThreads(an)) {
    const uint32_t pid = an.ProcessOf(tid);
    SymbolSource& sym = symbolsFor(pid);
    std::string e;
    Appendf(e, "{\"name\": \"thread_name\", \"ph\": \"M\", \"pid\": %u, \"tid\": %u, \"args\": {\"name\": %s}}",
            pid, tid, JsonString(name(tid)).c_str());
    event(e);
    for (const TimelineSlice& s : ThreadTimeline(an, tid)) {
      std::string slice;
      const char* cat = s.kind == Interval::Running ? "running" : s.kind == Interval::Ready ? "ready" : "waiting";
      Appendf(slice, "{\"name\": %s, \"cat\": \"%s\", \"ph\": \"X\", \"ts\": %.3f, \"dur\": %.3f, \"pid\": %u, \"tid\": %u",
              JsonString(SliceName(an, s, sym)).c_str(), cat, us(s.start), us(s.end) - us(s.start), pid, tid);
      if (s.bucket) {
        Appendf(slice, ", \"args\": {\"blockedIn\": %s}", JsonString(BlockedInFrame(*s.bucket, sym)).c_str());
      }
      slice += "}";
      event(slice);
    }
  }
  out += "\n]}\n";
  return out;
}

// speedscope's evented profiles, one per thread: each wait opens its call stack (outermost
// frame first) with the wait as the innermost frame, so the flame chart shows where each
// thread waited and for how long. Times in milliseconds from the start of the window.
inline std::string ExportSpeedscope(const Analyzer& an, const SymbolsFor& symbolsFor,
                                    const ThreadNamer& name, double ticksPerSecond,
                                    const std::string& program, const char* version) {
  auto ms = [&](uint64_t ticks) {
    return static_cast<double>(ticks > an.firstTs ? ticks - an.firstTs : 0) * 1e3 / ticksPerSecond;
  };
  std::map<std::string, size_t> frameIndex;
  std::vector<std::string> frames;
  auto frame = [&](const std::string& n) {
    auto it = frameIndex.find(n);
    if (it != frameIndex.end()) return it->second;
    frames.push_back(n);
    return frameIndex[n] = frames.size() - 1;
  };
  std::string profiles;
  const double end = ms(an.lastTs);
  for (uint32_t tid : TimelineThreads(an)) {
    SymbolSource& sym = symbolsFor(an.ProcessOf(tid));
    std::string events;
    auto add = [&events](char type, size_t f, double at) {
      Appendf(events, "%s{\"type\": \"%c\", \"frame\": %zu, \"at\": %.3f}", events.empty() ? "" : ", ", type, f, at);
    };
    double last = 0;
    for (const TimelineSlice& s : ThreadTimeline(an, tid)) {
      std::vector<size_t> stack;  // outermost first
      if (s.bucket)
        for (auto a = s.bucket->stack.rbegin(); a != s.bucket->stack.rend(); ++a) stack.push_back(frame(sym.Name(*a)));
      stack.push_back(frame("[" + SliceName(an, s, sym) + "]"));
      const double from = (std::max)(ms(s.start), last), to = (std::max)(ms(s.end), from);
      for (size_t f : stack) add('O', f, from);
      for (auto f = stack.rbegin(); f != stack.rend(); ++f) add('C', *f, to);
      last = to;
    }
    Appendf(profiles, "%s\n    {\"type\": \"evented\", \"name\": %s, \"unit\": \"milliseconds\", \"startValue\": 0, \"endValue\": %.3f, \"events\": [%s]}",
            profiles.empty() ? "" : ",", JsonString(name(tid)).c_str(), (std::max)(end, last), events.c_str());
  }
  std::string out;
  Appendf(out, "{\"$schema\": \"https://www.speedscope.app/file-format-schema.json\", \"name\": %s, \"exporter\": %s,\n",
          JsonString("waitwhy: " + program).c_str(), JsonString(std::string("waitwhy ") + version).c_str());
  out += "  \"shared\": {\"frames\": [";
  for (size_t i = 0; i < frames.size(); ++i) Appendf(out, "%s{\"name\": %s}", i ? ", " : "", JsonString(frames[i]).c_str());
  out += "]},\n  \"profiles\": [" + profiles + "\n  ]\n}\n";
  return out;
}

}  // namespace waitwhy

#endif  // WAITWHY_EXPORT_H
