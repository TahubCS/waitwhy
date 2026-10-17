// slowapp.cpp - a small program with a classic performance bug, used to test waitwhy.
//
// The bug: the "saver" thread holds a lock while it writes to disk. The main
// thread needs that same lock for every frame, so it keeps getting stuck until
// the disk write finishes. The CPU stays mostly idle, so Task Manager shows
// nothing wrong, but the program stutters.
//
// Build (x64 Developer PowerShell for VS):
//   cl /nologo /EHsc /Od /Zi /std:c++17 slowapp.cpp
//   (/Od keeps every function separate so waitwhy can show its name;
//    /Zi creates slowapp.pdb, which is where the function names come from)
//
// Run:
//   .\slowapp.exe                 buggy version (disk write inside the lock)
//   .\slowapp.exe --fixed         fixed version (copy under the lock, write outside it)
//   .\slowapp.exe --mb 64         write 64 MB per save (default 32) if your disk is very fast
//   .\slowapp.exe --calibrate     find the save size for this disk and print it as "mb=N" (W51):
//                                 doubled from 32 MB until one save takes 150 ms, at most 256 MB
//   .\slowapp.exe --seconds 20    exit by itself after 20 seconds

#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

namespace {

std::mutex g_settingsLock;                  // protects g_settings
std::vector<char> g_settings(8 * 1024 * 1024, 'x');  // 8 MB of pretend "settings"
std::atomic<bool> g_quit{false};
bool g_fixed = false;
int g_megabytesPerSave = 32;
std::wstring g_tempFile;

// Gives the current thread a name that waitwhy (and debuggers) can display.
// SetThreadDescription exists on Windows 10 1607 and later, so it is looked up at run time.
void NameThisThread(const wchar_t* name) {
  using SetDescFn = HRESULT(WINAPI*)(HANDLE, PCWSTR);
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  auto fn = k32 ? reinterpret_cast<SetDescFn>(
                      reinterpret_cast<void*>(GetProcAddress(k32, "SetThreadDescription")))
                : nullptr;
  if (fn) fn(GetCurrentThread(), name);
}

double NowMs() {
  static LARGE_INTEGER freq = [] { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f; }();
  LARGE_INTEGER t;
  QueryPerformanceCounter(&t);
  return 1000.0 * static_cast<double>(t.QuadPart) / static_cast<double>(freq.QuadPart);
}

// The slow part: writes the data to a file several times and forces it onto the disk.
NOINLINE void write_settings_to_disk(const std::vector<char>& data) {
  HANDLE f = CreateFileW(g_tempFile.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
  if (f == INVALID_HANDLE_VALUE) return;
  const int copies = (g_megabytesPerSave + 7) / 8;
  for (int i = 0; i < copies && !g_quit; ++i) {
    DWORD written = 0;
    WriteFile(f, data.data(), static_cast<DWORD>(data.size()), &written, nullptr);
  }
  FlushFileBuffers(f);  // wait until the data is really on the disk
  CloseHandle(f);
}

NOINLINE void save_settings() {
  if (!g_fixed) {
    // BUG: the lock stays held for the entire slow disk write.
    std::lock_guard<std::mutex> lock(g_settingsLock);
    write_settings_to_disk(g_settings);
  } else {
    // FIX: copy the data while holding the lock (fast), then write the copy without the lock.
    std::vector<char> copy;
    {
      std::lock_guard<std::mutex> lock(g_settingsLock);
      copy = g_settings;
    }
    write_settings_to_disk(copy);
  }
}

// W51: the smallest save size from 32 MB up (doubling, at most 256 MB) whose save takes at
// least 150 ms here, so the bug shows on a fast disk too. Each size is timed twice and the
// faster time counts: the first write of a new size also fills the file system's caches.
int CalibrateMegabytes() {
  for (g_megabytesPerSave = 32;; g_megabytesPerSave *= 2) {
    double best = 1e9;
    for (int i = 0; i < 2; ++i) {
      const double t0 = NowMs();
      write_settings_to_disk(g_settings);
      best = (std::min)(best, NowMs() - t0);
    }
    std::printf("A save of %d MB takes %.0f ms on this disk.\n", g_megabytesPerSave, best);
    if (best >= 150.0 || g_megabytesPerSave >= 256) return g_megabytesPerSave;
  }
}

NOINLINE void saver_thread() {
  NameThisThread(L"saver");
  while (!g_quit) {
    save_settings();
    Sleep(200);  // save about 5 times a second
  }
}

// A thread that only sleeps, so the report also shows what an intentional sleep looks like.
NOINLINE void ticker_thread() {
  NameThisThread(L"ticker");
  while (!g_quit) Sleep(250);
}

// One "frame" of work on the main thread. It needs the lock, just like a UI update would.
NOINLINE void update_frame(int frame) {
  std::lock_guard<std::mutex> lock(g_settingsLock);
  g_settings[static_cast<size_t>(frame) % g_settings.size()] = static_cast<char>('a' + frame % 26);
}

BOOL WINAPI OnCtrl(DWORD) {
  g_quit = true;
  return TRUE;  // let main() shut down cleanly
}

}  // namespace

int main(int argc, char** argv) {
  int runSeconds = 0;  // 0 = run until Ctrl+C
  bool calibrate = false;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--fixed") == 0) {
      g_fixed = true;
    } else if (std::strcmp(argv[i], "--mb") == 0 && i + 1 < argc) {
      g_megabytesPerSave = (std::max)(8, std::atoi(argv[++i]));
    } else if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
      runSeconds = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--calibrate") == 0) {
      calibrate = true;
    } else {
      std::printf("usage: slowapp [--fixed] [--mb N] [--seconds N] | slowapp --calibrate\n");
      return 1;
    }
  }

  wchar_t tempDir[MAX_PATH];
  GetTempPathW(MAX_PATH, tempDir);
  g_tempFile = std::wstring(tempDir) + L"slowapp_settings.tmp";
  if (calibrate) {
    const int mb = CalibrateMegabytes();
    DeleteFileW(g_tempFile.c_str());
    std::printf("mb=%d\n", mb);
    return 0;
  }

  NameThisThread(L"main");
  SetConsoleCtrlHandler(OnCtrl, TRUE);
  std::printf("slowapp is running the %s version. PID = %lu\n", g_fixed ? "FIXED" : "BUGGY",
              GetCurrentProcessId());
  std::printf("Every second it prints how long the main thread waited to update a frame.\n\n");

  std::thread saver(saver_thread);
  std::thread ticker(ticker_thread);

  const double startMs = NowMs();
  int frame = 0;
  while (!g_quit) {
    double secondStart = NowMs();
    double worst = 0;
    int frames = 0, stuck = 0;
    while (!g_quit && NowMs() - secondStart < 1000.0) {
      double t0 = NowMs();
      update_frame(frame++);
      double took = NowMs() - t0;
      if (took > worst) worst = took;
      if (took > 30.0) ++stuck;
      ++frames;
      Sleep(10);  // pretend the rest of the frame is idle time
    }
    std::printf("[%s] frames: %3d | slowest frame update: %7.1f ms | updates stuck > 30 ms: %d\n",
                g_fixed ? "fixed" : "buggy", frames, worst, stuck);
    if (runSeconds > 0 && NowMs() - startMs >= runSeconds * 1000.0) g_quit = true;
  }

  saver.join();
  ticker.join();
  DeleteFileW(g_tempFile.c_str());
  return 0;
}
