// check.h - the tests' check helpers: one printed line per check, failures counted.

#ifndef WAITWHY_TESTS_CHECK_H
#define WAITWHY_TESTS_CHECK_H

#include <cstdio>
#include <string>

inline int& Failures() {
  static int failures = 0;
  return failures;
}

inline void ExpectEq(const char* what, unsigned long long got, unsigned long long want) {
  const bool ok = got == want;
  std::printf("  %s %-46s got %llu, expected %llu\n", ok ? "ok  " : "FAIL", what, got, want);
  if (!ok) ++Failures();
}

inline void ExpectStr(const char* what, const std::string& got, const std::string& want) {
  const bool ok = got == want;
  std::printf("  %s %-46s got \"%s\"%s%s%s\n", ok ? "ok  " : "FAIL", what, got.c_str(),
              ok ? "" : ", expected \"", ok ? "" : want.c_str(), ok ? "" : "\"");
  if (!ok) ++Failures();
}

#endif  // WAITWHY_TESTS_CHECK_H
