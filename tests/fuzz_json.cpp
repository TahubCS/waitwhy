// fuzz_json.cpp - libFuzzer target (W46, D12): any bytes as a JSON report, through the JSON
// reader and waitwhy diff. Reports to compare may come from anywhere. Built and run in CI only:
//   clang++ -std=c++17 -g -O1 -fsanitize=fuzzer,address,undefined tests/fuzz_json.cpp -o fuzz_json
//   ./fuzz_json -max_total_time=60 corpus tests/golden

#include <cstddef>
#include <cstdint>
#include <string>

#include "../diff.h"

using namespace waitwhy;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  const std::string text(reinterpret_cast<const char*>(data), size);
  JsonValue value;
  std::string error;
  if (!JsonReader(text).Read(&value, &error)) return 0;
  // The report against itself and against an empty one, both ways.
  const JsonValue empty;
  for (double threshold : {-1.0, 0.0, 10.0}) {
    RenderDiff(DiffReports(value, value, threshold), threshold);
    RenderDiff(DiffReports(value, empty, threshold), threshold);
    RenderDiff(DiffReports(empty, value, threshold), threshold);
  }
  return 0;
}
