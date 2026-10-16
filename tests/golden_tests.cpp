// golden_tests.cpp - rebuilds reports from version 2 dumps and compares them, byte for byte,
// with the expected reports next to them (W19). Each pair in tests/golden is
// NAME.events.txt and NAME.report.txt. A change to the report's wording or layout shows up
// here as a reviewed change to the expected file. No Windows calls; runs in CI on Windows and
// Linux.
//
// Build and run, from the repository root:
//   cl /nologo /W4 /WX /EHsc /O2 /std:c++17 tests\golden_tests.cpp /Fe:golden_tests.exe
//   .\golden_tests.exe tests\golden
//   g++ -std=c++17 -Wall -Wextra tests/golden_tests.cpp -o golden_tests && ./golden_tests tests/golden

#include <fstream>
#include <sstream>

#include "../diff.h"
#include "../dump.h"
#include "../export.h"
#include "../html.h"
#include "../report.h"
#include "check.h"

using namespace waitwhy;

namespace {

const char* const kGoldenCases[] = {"slowapp-lock"};

std::string ReadFile(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  std::ostringstream text;
  text << in.rdbuf();
  std::string s = text.str();
  s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());  // the same with CRLF checkouts
  return s;
}

Report ReportFromDump(const std::vector<DumpLine>& lines) {
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  DumpSymbolsByProcess sym(lines);
  ReportOptions opt;
  opt.ticksPerSecond = info.ticksPerSecond;
  opt.eventsLost = info.eventsLost;
  opt.buffersLost = info.buffersLost;
  opt.stacksOn = info.stacksOn;
  opt.snapshotsOn = info.snapshotsOn;
  opt.symbolsOk = info.symbolsOk;
  opt.exeFile = info.exeFile;
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  return BuildReport(an, SymbolsFor(std::ref(sym)), opt, name);
}

// W37: the exports of the same dump are valid JSON, in the layout each viewer reads, and show
// main's lock wait where the report does.
void CheckExports(const std::vector<DumpLine>& lines) {
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  DumpSymbolsByProcess sym(lines);
  const SymbolsFor symbols(std::ref(sym));
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  auto expect = [](const char* what, bool ok) {
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++Failures();
  };
  const std::string lockWait = "lock in slowapp!`anonymous namespace'::update_frame";
  const double windowUs = static_cast<double>(an.lastTs - an.firstTs) * 1e6 / info.ticksPerSecond;

  JsonValue chrome;
  std::string error;
  expect("Chrome trace is JSON", JsonReader(ExportChromeTrace(an, symbols, name, info.ticksPerSecond, "slowapp.exe"))
                                     .Read(&chrome, &error));
  const JsonValue* events = chrome.Get("traceEvents");
  bool mainNamed = false, lockFound = false, slicesInWindow = true;
  std::map<double, double> busyUs;  // tid -> sum of its slices
  if (events)
    for (const JsonValue& e : events->items) {
      const std::string ph = e.Str("ph");
      if (ph == "M" && e.Str("name") == "thread_name" && e.Get("args") && e.Get("args")->Str("name") == "Thread 1 (main)")
        mainNamed = true;
      if (ph != "X") continue;
      const double ts = e.Num("ts"), dur = e.Num("dur");
      if (ts < 0 || dur < 0 || ts + dur > windowUs + 1) slicesInWindow = false;
      busyUs[e.Num("tid")] += dur;
      if (e.Num("tid") == 1 && e.Str("name") == lockWait && std::fabs(dur - 3.01e6) < 1e4) lockFound = true;
    }
  expect("Chrome trace names main's thread", mainNamed);
  expect("Chrome trace shows main's 3.01 s lock wait", lockFound);
  expect("Chrome slices lie in the window", slicesInWindow);
  bool noThreadOverfull = !busyUs.empty();
  for (const auto& [tid, us] : busyUs) noThreadOverfull = noThreadOverfull && us <= windowUs + 1;
  expect("no thread has more slices than the window", noThreadOverfull);

  JsonValue speedscope;
  expect("speedscope profile is JSON",
         JsonReader(ExportSpeedscope(an, symbols, name, info.ticksPerSecond, "slowapp.exe", "test")).Read(&speedscope, &error));
  const JsonValue* shared = speedscope.Get("shared");
  const JsonValue* frames = shared ? shared->Get("frames") : nullptr;
  const JsonValue* profiles = speedscope.Get("profiles");
  bool lockFrame = false;
  if (frames)
    for (const JsonValue& f : frames->items) lockFrame = lockFrame || f.Str("name") == "[" + lockWait + "]";
  expect("speedscope has main's lock wait as a frame", lockFrame);
  bool balanced = profiles && !profiles->items.empty();
  if (profiles)
    for (const JsonValue& p : profiles->items) {
      const JsonValue* list = p.Get("events");
      if (!list || p.Str("type") != "evented") {
        balanced = false;
        continue;
      }
      std::vector<double> open;
      double at = 0;
      for (const JsonValue& e : list->items) {
        if (e.Num("at") < at) balanced = false;
        at = e.Num("at");
        if (e.Str("type") == "O") {
          open.push_back(e.Num("frame"));
        } else if (open.empty() || open.back() != e.Num("frame")) {
          balanced = false;
        } else {
          open.pop_back();
        }
        if (frames && e.Num("frame") >= static_cast<double>(frames->items.size())) balanced = false;
      }
      if (!open.empty() || at > p.Num("endValue")) balanced = false;
    }
  expect("speedscope events nest, in time order, within each profile", balanced);
}

// W36: the HTML page holds the report's findings and charts, and nothing it would have to
// load from elsewhere.
void CheckHtml(const std::vector<DumpLine>& lines, const Report& report) {
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  DumpSymbolsByProcess sym(lines);
  const std::string html = RenderHtml(report, an, SymbolsFor(std::ref(sym)), info.ticksPerSecond, "test");
  auto count = [&html](const std::string& what) {
    size_t n = 0;
    for (size_t at = html.find(what); at != std::string::npos; at = html.find(what, at + what.size())) ++n;
    return n;
  };
  auto expect = [](const char* what, bool ok) {
    std::printf("  %s %s\n", ok ? "ok  " : "FAIL", what);
    if (!ok) ++Failures();
  };
  expect("HTML starts with a doctype", html.compare(0, 15, "<!doctype html>") == 0);
  expect("HTML loads nothing", count("<script") == 0 && count("src=") == 0 && count("href=") == 0 &&
                                   count("url(") == 0 && count("@import") == 0);
  expect("HTML has main's lock finding, escaped",
         count("Thread 1 (main) spent 30% of the time waiting for a lock that another thread was holding, in "
               "slowapp!`anonymous namespace&#39;::update_frame.") == 1);
  expect("HTML has the measured chain as a bar", count("<svg class=\"bar\"") == 1);
  expect("HTML has a timeline and a flame graph", count("<svg class=\"chart\"") == 2);
  expect("every svg and details is closed", count("<svg") == count("</svg>") && count("<details>") == count("</details>") &&
                                                count("<g>") == count("</g>"));
  expect("HTML timeline stays small", count("<rect") < 2000);
  expect("flame graph shows the lock wait", count("[a lock held by another thread]") >= 1);
  expect("flame graph leaves out sleeps", count("[an intentional sleep or timer]") == 0);
  expect("HTML has a stack per biggest wait", count("<details>") == report.waits.size());
  expect("HTML has the data quality", count("Data quality: high") == 1);
}

// Prints the first line where the two texts differ.
void ShowFirstDifference(const std::string& got, const std::string& want) {
  std::istringstream g(got), w(want);
  std::string gl, wl;
  for (int line = 1;; ++line) {
    const bool hasG = static_cast<bool>(std::getline(g, gl));
    const bool hasW = static_cast<bool>(std::getline(w, wl));
    if (!hasG && !hasW) return;
    if (!hasG || !hasW || gl != wl) {
      std::printf("    line %d\n      got:      %s\n      expected: %s\n", line,
                  hasG ? gl.c_str() : "(end of report)", hasW ? wl.c_str() : "(end of report)");
      return;
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::string dir = argc > 1 ? argv[1] : "tests/golden";
  for (const char* name : kGoldenCases) {
    std::printf("Golden report %s\n", name);
    const std::string base = dir + "/" + name;
    std::istringstream events(ReadFile(base + ".events.txt"));
    const std::vector<DumpLine> lines = ReadDump(events);
    const std::string want = ReadFile(base + ".report.txt");
    if (lines.empty() || want.empty()) {
      std::printf("  FAIL cannot read %s.events.txt and %s.report.txt\n", base.c_str(), base.c_str());
      ++Failures();
      continue;
    }
    const Report report = ReportFromDump(lines);
    const std::string got = RenderText(report);
    const bool same = got == want;
    std::printf("  %s report matches %s.report.txt\n", same ? "ok  " : "FAIL", name);
    if (!same) {
      ++Failures();
      ShowFirstDifference(got, want);
      std::printf("---- report as built ----\n%s---- end ----\n", got.c_str());
    }
    // W34: the same report as JSON.
    const std::string wantJson = ReadFile(base + ".report.json");
    if (!wantJson.empty()) {
      const std::string gotJson = RenderJson(report);
      const bool sameJson = gotJson == wantJson;
      std::printf("  %s JSON matches %s.report.json\n", sameJson ? "ok  " : "FAIL", name);
      if (!sameJson) {
        ++Failures();
        ShowFirstDifference(gotJson, wantJson);
      }
    }
    CheckExports(lines);
    CheckHtml(lines, report);
  }
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
