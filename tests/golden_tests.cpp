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

#include "../dump.h"
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

std::string ReportFromDump(const std::vector<DumpLine>& lines) {
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  DumpSymbolsByProcess sym(lines);
  ReportOptions opt;
  opt.ticksPerSecond = info.ticksPerSecond;
  opt.eventsLost = info.eventsLost;
  opt.buffersLost = info.buffersLost;
  opt.stacksOn = info.stacksOn;
  opt.symbolsOk = info.symbolsOk;
  opt.exeFile = info.exeFile;
  auto name = [&info](uint32_t tid) {
    auto it = info.threadNames.find(tid);
    return it != info.threadNames.end() ? it->second : "Thread " + std::to_string(tid);
  };
  return RenderText(BuildReport(an, SymbolsFor(std::ref(sym)), opt, name));
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
    const std::string got = ReportFromDump(lines);
    const bool same = got == want;
    std::printf("  %s report matches %s.report.txt\n", same ? "ok  " : "FAIL", name);
    if (!same) {
      ++Failures();
      ShowFirstDifference(got, want);
      std::printf("---- report as built ----\n%s---- end ----\n", got.c_str());
    }
  }
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
