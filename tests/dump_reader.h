// dump_reader.h - reads a waitwhy --dump-events file: one event per line, "KIND key=value ...".
// Shared by the replay tests.

#ifndef WAITWHY_TESTS_DUMP_READER_H
#define WAITWHY_TESTS_DUMP_READER_H

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

struct DumpLine {
  int number = 0;  // line number in the file, for messages
  std::string kind;
  std::map<std::string, uint64_t> field;
};

inline std::vector<DumpLine> ReadDump(const char* path) {
  std::vector<DumpLine> lines;
  std::ifstream in(path);
  std::string text;
  for (int number = 1; std::getline(in, text); ++number) {
    if (!text.empty() && text.back() == '\r') text.pop_back();  // dumps are written as CRLF
    if (text.empty() || text[0] == '#') continue;
    std::istringstream words(text);
    DumpLine line;
    line.number = number;
    words >> line.kind;
    for (std::string word; words >> word;) {
      const size_t eq = word.find('=');
      if (eq == std::string::npos) continue;
      line.field[word.substr(0, eq)] = std::stoull(word.substr(eq + 1), nullptr, 0);
    }
    lines.push_back(std::move(line));
  }
  return lines;
}

// Test bookkeeping: prints one line per check and counts failures.
inline int& Failures() {
  static int failures = 0;
  return failures;
}

inline void ExpectEq(const char* what, unsigned long long got, unsigned long long want) {
  const bool ok = got == want;
  std::printf("  %s %-46s got %llu, expected %llu\n", ok ? "ok  " : "FAIL", what, got, want);
  if (!ok) ++Failures();
}

#endif  // WAITWHY_TESTS_DUMP_READER_H
