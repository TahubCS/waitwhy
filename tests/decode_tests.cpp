// decode_tests.cpp - replays a waitwhy --dump-events file through waitwhy's own ETW decoding:
// each dump line becomes the EVENT_RECORD the kernel delivered and goes through OnEvent, then
// into the analysis core. The counts must equal those of tests/replay_events.cpp, which feeds
// the analysis core directly. Windows only (it includes waitwhy.cpp); no kernel trace and no
// Administrator rights are needed.
//
// Build and run (x64 Developer PowerShell for VS, from the repository root):
//   cl /nologo /EHsc /O2 /std:c++17 /DWAITWHY_NO_MAIN tests\decode_tests.cpp /Fe:decode_tests.exe
//   .\decode_tests.exe docs\traces\buggy-64mb-events.txt

#ifdef _MSC_VER
#pragma warning(disable : 4505)  // waitwhy.cpp functions that only its own main uses
#endif
#include "../waitwhy.cpp"

#include "dump_reader.h"

namespace {

template <typename T>
void Append(std::vector<uint8_t>& data, T value) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
  data.insert(data.end(), bytes, bytes + sizeof value);
}

// Turns one dump line back into the EVENT_RECORD the kernel delivered and hands it to OnEvent.
void Feed(const DumpLine& l) {
  EVENT_RECORD ev{};
  std::vector<uint8_t> data;
  ev.EventHeader.Flags = EVENT_HEADER_FLAG_64_BIT_HEADER;
  ev.EventHeader.TimeStamp.QuadPart = static_cast<LONGLONG>(l.field.at("ts"));
  ev.EventHeader.ThreadId = kUnknownThread;
  if (l.kind == "CSWITCH") {
    ev.EventHeader.ProviderId = kThreadGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpCSwitch;
    ev.BufferContext.ProcessorNumber = static_cast<UCHAR>(l.field.at("cpu"));
    CSwitchPayload c{};
    c.newThreadId = static_cast<uint32_t>(l.field.at("new"));
    c.oldThreadId = static_cast<uint32_t>(l.field.at("old"));
    c.oldThreadState = static_cast<int8_t>(l.field.at("oldState"));
    c.oldThreadWaitReason = static_cast<int8_t>(l.field.at("oldReason"));
    Append(data, c);
  } else if (l.kind == "READY") {
    ev.EventHeader.ProviderId = kThreadGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpReadyThread;
    ev.BufferContext.ProcessorNumber = static_cast<UCHAR>(l.field.at("cpu"));
    ev.EventHeader.ThreadId = static_cast<ULONG>(l.field.at("headerThread"));
    Append(data, static_cast<uint32_t>(l.field.at("readied")));
    Append(data, static_cast<uint8_t>(0));  // AdjustReason
    Append(data, static_cast<uint8_t>(0));  // AdjustIncrement
    Append(data, static_cast<uint8_t>(l.field.at("flag")));
    Append(data, static_cast<uint8_t>(0));
  } else if (l.kind == "STACK") {
    ev.EventHeader.ProviderId = kStackWalkGuid;
    ev.EventHeader.EventDescriptor.Opcode = kOpStackWalk;
    Append(data, l.field.at("eventTs"));
    Append(data, g_analysis.pid);
    Append(data, static_cast<uint32_t>(l.field.at("tid")));
    for (uint64_t i = 0; i < l.field.at("kernelFrames"); ++i)
      Append(data, 0xFFFFF80000001000ull + i * 16);
    for (uint64_t i = 0; i < l.field.at("userFrames"); ++i)
      Append(data, i == 0 ? l.field.at("firstUser") : 0x00007FF600001000ull + i * 16);
  } else {
    return;
  }
  ev.UserData = data.data();
  ev.UserDataLength = static_cast<USHORT>(data.size());
  OnEvent(&ev);
}

void CheckWholeTrace(const std::vector<DumpLine>& all) {
  std::printf("Whole trace through OnEvent\n");
  g_analysis = Analyzer{};
  g_analysis.pid = 1;
  g_analysis.stacksOn = true;
  std::fill(g_cpuThread.begin(), g_cpuThread.end(), kUnknownThread);
  for (const DumpLine& l : all) {
    if (l.kind == "READY") g_analysis.targetThreads.insert(static_cast<uint32_t>(l.field.at("readied")));
    if (l.kind == "STACK") g_analysis.targetThreads.insert(static_cast<uint32_t>(l.field.at("tid")));
  }
  for (const DumpLine& l : all) Feed(l);
  g_analysis.FlushAtEnd();
  ExpectEq("context switches", g_analysis.contextSwitches, 3891);
  ExpectEq("waits with a stack", g_analysis.waitsWithStack, 1552);
  ExpectEq("waits without a stack", g_analysis.waitsWithoutStack, 4);
  ExpectEq("kernel-only stack parts", g_analysis.kernelOnlyFragments, 1552);
}

// W3: a thread readied from a DPC was woken by the system, not by the thread the DPC
// interrupted. W4: otherwise the event header names the waker.
void CheckWakerDecoding() {
  std::printf("ReadyThread waker decoding\n");
  g_analysis = Analyzer{};
  g_analysis.pid = 1;
  g_analysis.targetThreads.insert(100);
  auto feed = [](const char* kind, std::map<std::string, uint64_t> f) {
    DumpLine l;
    l.kind = kind;
    l.field = std::move(f);
    Feed(l);
  };
  auto sw = [&](uint64_t ts, uint64_t oldTid, uint64_t newTid) {
    feed("CSWITCH", {{"ts", ts}, {"cpu", 0}, {"old", oldTid}, {"new", newTid},
                     {"oldState", 5}, {"oldReason", 6}});
  };
  sw(10, 100, 7);  // thread 100 blocks
  feed("READY", {{"ts", 20}, {"cpu", 0}, {"readied", 100}, {"headerThread", 7}, {"flag", 1}});
  ExpectEq("DPC wake-up names the system", g_analysis.threads[100].open.wokenBy, kSystemWaker);
  sw(30, 7, 100);
  sw(40, 100, 7);
  feed("READY", {{"ts", 50}, {"cpu", 0}, {"readied", 100}, {"headerThread", 7}, {"flag", 0}});
  ExpectEq("header thread is the waker", g_analysis.threads[100].open.wokenBy, 7);
}

}  // namespace

int main(int argc, char** argv) {
  const char* path = argc > 1 ? argv[1] : "docs\\traces\\buggy-64mb-events.txt";
  const std::vector<DumpLine> lines = ReadDump(path);
  if (lines.empty()) {
    std::printf("No events read from %s.\n", path);
    return 1;
  }
  std::printf("Replaying %zu events from %s\n", lines.size(), path);
  CheckWholeTrace(lines);
  CheckWakerDecoding();
  std::printf(Failures() ? "%d check(s) failed.\n" : "All checks passed.\n", Failures());
  return Failures() ? 1 : 0;
}
