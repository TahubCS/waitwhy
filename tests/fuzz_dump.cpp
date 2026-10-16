// fuzz_dump.cpp - libFuzzer target (W46, D12): any bytes as a --dump-events file, through
// everything that reads one: ReadDump, the replay into the analysis core, the report and all
// its renderings. Dumps come from other people's machines, so none of this may crash, hang or
// read out of bounds. Built and run in CI only:
//   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined tests/fuzz_dump.cpp -o fuzz_dump
//   ./fuzz_dump -max_total_time=60 corpus tests/golden

#include <cstddef>
#include <cstdint>
#include <sstream>
#include <string>

#include "../dump.h"
#include "../export.h"
#include "../html.h"
#include "../report.h"

using namespace waitwhy;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  std::istringstream in(std::string(reinterpret_cast<const char*>(data), size));
  const std::vector<DumpLine> lines = ReadDump(in);
  Analyzer an;
  DumpReplay replay(an);
  const DumpInfo info = replay.Run(lines);
  DumpSymbolsByProcess sym(lines);
  ReportOptions opt;
  opt.ticksPerSecond = info.ticksPerSecond > 0 ? info.ticksPerSecond : 1e7;
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
  const SymbolsFor symbols(std::ref(sym));
  Report report = BuildReport(an, symbols, opt, name);
  RenderText(report);
  RenderJson(report);
  RenderHtml(report, an, symbols, opt.ticksPerSecond, "fuzz");
  ExportChromeTrace(an, symbols, name, opt.ticksPerSecond, report.program);
  ExportSpeedscope(an, symbols, name, opt.ticksPerSecond, report.program, "fuzz");
  Redactor red;
  red.names = {"user"};
  RedactReport(report, red);
  RenderText(report);
  return 0;
}
