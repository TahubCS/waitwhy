// dump.h - reads waitwhy --dump-events files and replays them through the analysis core.
//
// A dump has one line per item: a kind, then `key=value` fields. Numbers are decimal or
// 0x-hex. A few kinds end with a text field (`name=` or `file=`) that runs to the end of the
// line, because names and paths can contain spaces.
//
// Version 1 (W12) holds the target's CSWITCH, READY and STACK events, with only the first
// user address of each stack. Version 2 (W18) adds what is needed to rebuild the live report
// exactly, without Windows:
//
//   DUMP       version pid ticksPerSecond          first line
//   TARGET     tid                                 threads of the program when tracing starts
//   WINDOW     ts                                  first context switch of the trace (any thread)
//   CSWITCH    ts cpu old new oldState oldReason
//   READY      ts cpu readied headerThread flag by  `by`: the waker as waitwhy resolved it
//   STACK      ts eventTs tid kernelFrames userFrames firstUser frames=0x..,0x..
//   THREAD     ts kind pid tid                     kind: 0 created, 1 existing, 2 ended
//   END        ts contextSwitches stacksOn eventsLost buffersLost   tracing stopped
//   SNAPSHOT   tid frames=0x..,0x..                stack of a thread still blocked (W7)
//   EXE        name=<file name of the program>
//   SYMBOL     addr name=<module!function>         every address in the report's stacks
//   SOURCE     addr file=<source file, lower case>
//   THREADNAME tid name=<label as the report prints it>
//
// It makes no Windows calls (D7).

#ifndef WAITWHY_DUMP_H
#define WAITWHY_DUMP_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "analysis.h"

namespace waitwhy {

struct DumpLine {
  int number = 0;  // line number in the file, for messages
  std::string kind;
  std::map<std::string, uint64_t> field;     // fields with a numeric value
  std::map<std::string, std::string> text;   // every field, as written

  bool Has(const char* key) const { return text.count(key) != 0; }
  uint64_t Get(const char* key, uint64_t fallback = 0) const {
    auto it = field.find(key);
    return it == field.end() ? fallback : it->second;
  }
};

// Parses "0x1,0x2,..." into addresses.
inline std::vector<uint64_t> ParseFrames(const std::string& list) {
  std::vector<uint64_t> frames;
  std::istringstream in(list);
  for (std::string item; std::getline(in, item, ',');)
    if (!item.empty()) frames.push_back(std::stoull(item, nullptr, 0));
  return frames;
}

inline DumpLine ParseDumpLine(const std::string& line, int number) {
  DumpLine l;
  l.number = number;
  std::string fields = line;
  // A text field at the end runs to the end of the line.
  for (const char* key : {" name=", " file="}) {
    const size_t at = fields.find(key);
    if (at == std::string::npos) continue;
    const std::string k(key + 1, std::strlen(key) - 2);
    l.text[k] = fields.substr(at + std::strlen(key));
    fields.resize(at);
    break;
  }
  std::istringstream words(fields);
  words >> l.kind;
  for (std::string word; words >> word;) {
    const size_t eq = word.find('=');
    if (eq == std::string::npos) continue;
    const std::string key = word.substr(0, eq);
    const std::string value = word.substr(eq + 1);
    l.text[key] = value;
    if (!value.empty() && value[0] >= '0' && value[0] <= '9')
      l.field[key] = std::stoull(value, nullptr, 0);
  }
  return l;
}

inline std::vector<DumpLine> ReadDump(const char* path) {
  std::vector<DumpLine> lines;
  std::ifstream in(path);
  std::string text;
  for (int number = 1; std::getline(in, text); ++number) {
    if (!text.empty() && text.back() == '\r') text.pop_back();  // dumps are written as CRLF
    if (text.empty() || text[0] == '#') continue;
    lines.push_back(ParseDumpLine(text, number));
  }
  return lines;
}

// What a dump says about the run, beyond its events.
struct DumpInfo {
  int version = 1;
  uint32_t pid = 0;
  double ticksPerSecond = 0;
  bool ended = false;  // an END line was read
  bool stacksOn = true;
  uint64_t eventsLost = 0;
  uint64_t buffersLost = 0;
  std::string exeFile;
  std::unordered_map<uint32_t, std::string> threadNames;
};

// Names addresses from a dump's SYMBOL, SOURCE and EXE lines, the way the live run named them.
class DumpSymbols : public SymbolSource {
 public:
  explicit DumpSymbols(const std::vector<DumpLine>& lines) {
    for (const DumpLine& l : lines) {
      if (l.kind == "SYMBOL" && l.Has("name")) names_[l.Get("addr")] = l.text.at("name");
      if (l.kind == "SOURCE" && l.Has("file")) files_[l.Get("addr")] = l.text.at("file");
      if (l.kind == "EXE" && l.Has("name")) {
        const std::string& file = l.text.at("name");
        exeModule_ = Lower(file.substr(0, file.find_last_of('.')));
      }
    }
  }
  const std::string& Name(uint64_t addr) override {
    auto it = names_.find(addr);
    if (it != names_.end()) return it->second;
    char hex[32];
    std::snprintf(hex, sizeof hex, "?!0x%llx", static_cast<unsigned long long>(addr));
    return names_[addr] = hex;
  }
  const std::string& SourceFile(uint64_t addr) override { return files_[addr]; }
  bool IsExeFrame(const std::string& name) const override {
    const size_t bang = name.find('!');
    return bang != std::string::npos && Lower(name.substr(0, bang)) == exeModule_;
  }

 private:
  std::unordered_map<uint64_t, std::string> names_;
  std::unordered_map<uint64_t, std::string> files_;
  std::string exeModule_;
};

// Feeds dump lines to an Analyzer as waitwhy.cpp fed it the kernel events behind them.
class DumpReplay {
 public:
  explicit DumpReplay(Analyzer& an) : an_(an), cpuThread_(256, kUnknownThread) {}

  // Reads the run's description and the program's threads at the start. A version 1 dump has
  // no TARGET lines, so the threads that were readied or had stacks recorded stand in.
  DumpInfo Prepare(const std::vector<DumpLine>& lines) {
    DumpInfo info;
    for (const DumpLine& l : lines) {
      if (l.kind == "DUMP") {
        info.version = static_cast<int>(l.Get("version", 1));
        info.pid = static_cast<uint32_t>(l.Get("pid"));
        info.ticksPerSecond = static_cast<double>(l.Get("ticksPerSecond"));
      } else if (l.kind == "TARGET") {
        an_.targetThreads.insert(static_cast<uint32_t>(l.Get("tid")));
      } else if (l.kind == "END") {
        info.ended = true;
        info.stacksOn = l.Get("stacksOn", 1) != 0;
        info.eventsLost = l.Get("eventsLost");
        info.buffersLost = l.Get("buffersLost");
      } else if (l.kind == "EXE" && l.Has("name")) {
        info.exeFile = l.text.at("name");
      } else if (l.kind == "THREADNAME" && l.Has("name")) {
        info.threadNames[static_cast<uint32_t>(l.Get("tid"))] = l.text.at("name");
      } else if (info.version == 1 && l.kind == "READY") {
        an_.targetThreads.insert(static_cast<uint32_t>(l.Get("readied")));
      } else if (info.version == 1 && l.kind == "STACK") {
        an_.targetThreads.insert(static_cast<uint32_t>(l.Get("tid")));
      }
    }
    an_.pid = info.version == 1 ? 1 : info.pid;
    an_.stacksOn = info.stacksOn;
    return info;
  }

  void Feed(const DumpLine& l) {
    if (l.kind == "WINDOW") {
      if (an_.firstTs == 0) an_.firstTs = l.Get("ts");
    } else if (l.kind == "CSWITCH") {
      SwitchEvent e;
      e.ts = l.Get("ts");
      e.oldTid = static_cast<uint32_t>(l.Get("old"));
      e.newTid = static_cast<uint32_t>(l.Get("new"));
      e.oldState = static_cast<int8_t>(l.Get("oldState"));
      e.oldWaitReason = static_cast<int8_t>(l.Get("oldReason"));
      const size_t cpu = l.Get("cpu");
      if (cpu < cpuThread_.size()) cpuThread_[cpu] = e.newTid;
      an_.OnSwitch(e);
    } else if (l.kind == "READY") {
      ReadyEvent e;
      e.ts = l.Get("ts");
      e.readiedTid = static_cast<uint32_t>(l.Get("readied"));
      const size_t cpu = l.Get("cpu");
      e.byTid = l.Has("by") ? static_cast<uint32_t>(l.Get("by"))
                            : ResolveWaker(static_cast<uint8_t>(l.Get("flag")),
                                           static_cast<uint32_t>(l.Get("headerThread")),
                                           cpu < cpuThread_.size() ? cpuThread_[cpu] : kUnknownThread);
      an_.OnReady(e);
    } else if (l.kind == "STACK") {
      StackEvent e;
      e.ts = l.Get("ts");
      e.eventTs = l.Get("eventTs");
      e.tid = static_cast<uint32_t>(l.Get("tid"));
      if (l.Has("frames")) {
        e.userFrames = ParseFrames(l.text.at("frames"));
      } else {
        // Version 1 kept only the first user address; stand-ins fill the rest of the depth,
        // so stacks with the same first address and depth look identical.
        for (uint64_t i = 0; i < l.Get("userFrames"); ++i)
          e.userFrames.push_back(i == 0 ? l.Get("firstUser") : 0x00007FF600001000ull + i * 16);
      }
      an_.OnStack(e);
    } else if (l.kind == "THREAD") {
      ThreadEvent e;
      e.ts = l.Get("ts");
      e.pid = static_cast<uint32_t>(l.Get("pid"));
      e.tid = static_cast<uint32_t>(l.Get("tid"));
      const uint64_t kind = l.Get("kind");
      e.kind = kind == 0 ? ThreadEvent::Kind::Created
                         : kind == 1 ? ThreadEvent::Kind::Existing : ThreadEvent::Kind::Ended;
      an_.OnThread(e);
    } else if (l.kind == "END") {
      // The live run saw every context switch on the machine, the dump only the program's.
      an_.lastTs = l.Get("ts");
      an_.contextSwitches = l.Get("contextSwitches");
    } else if (l.kind == "SNAPSHOT") {
      an_.ApplySnapshot(static_cast<uint32_t>(l.Get("tid")),
                        l.Has("frames") ? ParseFrames(l.text.at("frames")) : std::vector<uint64_t>{});
    }
  }

  // The whole dump, then what waitwhy does after tracing stops.
  DumpInfo Run(const std::vector<DumpLine>& lines) {
    DumpInfo info = Prepare(lines);
    for (const DumpLine& l : lines) Feed(l);
    an_.FlushAtEnd();
    return info;
  }

 private:
  Analyzer& an_;
  std::vector<uint32_t> cpuThread_;
};

// Writes "frames=0x..,0x.." (nothing for an empty list).
inline void WriteFrames(FILE* out, const std::vector<uint64_t>& frames) {
  if (frames.empty()) return;
  std::fputs(" frames=", out);
  for (size_t i = 0; i < frames.size(); ++i)
    std::fprintf(out, i ? ",0x%llx" : "0x%llx", static_cast<unsigned long long>(frames[i]));
}

}  // namespace waitwhy

#endif  // WAITWHY_DUMP_H
