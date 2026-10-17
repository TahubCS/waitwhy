// scenarios.cpp - known-answer programs for waitwhy (W29). Each mode makes the program wait in
// one well-known way; CI watches each mode with waitwhy and checks the expected top finding.
// slowapp.cpp stays the reference for C8; these cover the other kinds of waiting.
//
// Build (x64 Developer PowerShell for VS):
//   cl /nologo /W4 /WX /EHsc /Od /Zi /std:c++17 scenarios.cpp /Fe:scenarios.exe
// Run:
//   .\scenarios.exe --mode NAME [--seconds N]
//
// Modes and what waitwhy should say:
//   condvar     main waits on a condition variable for a producer thread: another thread
//   coldread    main reads a file without the file cache: the disk
//   console     main writes many lines to the console: the console window
//   pipe        client waits for replies over a named pipe: another thread (a pipe)
//   socket      client waits for replies over a loopback TCP socket: the network
//   cpu         more busy threads than CPUs: ready to run but waiting for a free CPU
//   child       main waits for a child process to exit: another thread or an event
//   lockcpu     main waits for a lock that a worker holds while computing
//   locksleep   main waits for a lock that a worker holds while sleeping
//   lockdisk    main waits for a lock that a worker holds while writing to disk
//   sleep       everything only sleeps: no finding
//   stuckpipe   (W49) writer is blocked writing to a pipe nobody reads, from before tracing
//               starts until after it ends: another thread (a pipe), not the disk
//   sleeper     (used by child) sleeps and exits
//   bench       (W43, for measuring waitwhy's overhead) pairs of threads hand a token back and
//               forth as fast as they can, about the worst case for waitwhy: every hand-over
//               is two context switches, each with a call stack. Prints hand-overs per second.
//               --work-us N: each side computes N microseconds before it hands over, like a
//               program that does some work between its waits.

#ifndef UNICODE
#define UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#ifdef _MSC_VER
#pragma comment(lib, "ws2_32.lib")
#define NOINLINE __declspec(noinline)
#else
#define NOINLINE __attribute__((noinline))
#endif

namespace {

std::atomic<bool> g_quit{false};

void NameThisThread(const wchar_t* name) {
  using SetDescFn = HRESULT(WINAPI*)(HANDLE, PCWSTR);
  HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
  auto fn = k32 ? reinterpret_cast<SetDescFn>(
                      reinterpret_cast<void*>(GetProcAddress(k32, "SetThreadDescription")))
                : nullptr;
  if (fn) fn(GetCurrentThread(), name);
}

std::wstring TempPath(const wchar_t* file) {
  wchar_t dir[MAX_PATH];
  GetTempPathW(MAX_PATH, dir);
  return std::wstring(dir) + file;
}

// ---- condvar ------------------------------------------------------------------------------

std::mutex g_resultLock;
std::condition_variable g_resultReady;
int g_result = 0;

NOINLINE void produce_results() {
  NameThisThread(L"producer");
  while (!g_quit) {
    Sleep(200);
    {
      std::lock_guard<std::mutex> lock(g_resultLock);
      ++g_result;
    }
    g_resultReady.notify_one();
  }
}

NOINLINE void wait_for_result(int seen) {
  std::unique_lock<std::mutex> lock(g_resultLock);
  g_resultReady.wait_for(lock, std::chrono::seconds(1), [seen] { return g_result != seen || g_quit; });
}

void RunCondvar() {
  std::thread producer(produce_results);
  int seen = 0;
  while (!g_quit) {
    wait_for_result(seen);
    std::lock_guard<std::mutex> lock(g_resultLock);
    seen = g_result;
  }
  g_resultReady.notify_all();
  producer.join();
}

// ---- coldread -----------------------------------------------------------------------------

constexpr DWORD kChunk = 1 << 20;

NOINLINE void read_cold_file(HANDLE file, void* buffer, LONGLONG blocks) {
  LARGE_INTEGER at;
  at.QuadPart = (std::rand() % blocks) * static_cast<LONGLONG>(kChunk);
  SetFilePointerEx(file, at, nullptr, FILE_BEGIN);
  DWORD got = 0;
  ReadFile(file, buffer, kChunk, &got, nullptr);
}

void RunColdRead() {
  const std::wstring path = TempPath(L"waitwhy_scenarios_cold.bin");
  const LONGLONG blocks = 128;  // 128 MB
  {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    std::vector<char> data(kChunk, 'c');
    DWORD wrote = 0;
    for (LONGLONG i = 0; i < blocks; ++i) WriteFile(f, data.data(), kChunk, &wrote, nullptr);
    FlushFileBuffers(f);
    CloseHandle(f);
  }
  // Without the file cache every read goes to the disk. The buffer must be sector-aligned.
  HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                         FILE_FLAG_NO_BUFFERING, nullptr);
  void* buffer = VirtualAlloc(nullptr, kChunk, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  while (!g_quit) read_cold_file(f, buffer, blocks);
  VirtualFree(buffer, 0, MEM_RELEASE);
  CloseHandle(f);
  DeleteFileW(path.c_str());
}

// ---- console ------------------------------------------------------------------------------

NOINLINE void print_lines(int round) {
  for (int i = 0; i < 200; ++i)
    std::printf("round %6d line %3d: some text so the console window has something to draw\n", round, i);
  std::fflush(stdout);
}

void RunConsole() {
  for (int round = 0; !g_quit; ++round) {
    print_lines(round);
    Sleep(5);
  }
}

// ---- pipe ---------------------------------------------------------------------------------

const wchar_t kPipeName[] = L"\\\\.\\pipe\\waitwhy_scenarios";

NOINLINE void pipe_server() {
  NameThisThread(L"server");
  HANDLE pipe = CreateNamedPipeW(kPipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 1,
                                 4096, 4096, 0, nullptr);
  ConnectNamedPipe(pipe, nullptr);
  char byte = 0;
  DWORD n = 0;
  while (!g_quit && ReadFile(pipe, &byte, 1, &n, nullptr) && n == 1) {
    Sleep(100);  // a slow reply
    WriteFile(pipe, &byte, 1, &n, nullptr);
  }
  CloseHandle(pipe);
}

NOINLINE void pipe_round_trip(HANDLE pipe) {
  char byte = 'p';
  DWORD n = 0;
  WriteFile(pipe, &byte, 1, &n, nullptr);
  ReadFile(pipe, &byte, 1, &n, nullptr);
}

NOINLINE void pipe_client() {
  NameThisThread(L"client");
  HANDLE pipe = INVALID_HANDLE_VALUE;
  while (!g_quit && pipe == INVALID_HANDLE_VALUE) {
    pipe = CreateFileW(kPipeName, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (pipe == INVALID_HANDLE_VALUE) Sleep(10);
  }
  while (!g_quit) pipe_round_trip(pipe);
  CloseHandle(pipe);
}

void RunPipe() {
  std::thread server(pipe_server);
  std::thread client(pipe_client);
  while (!g_quit) Sleep(50);
  client.join();
  server.join();
}

// ---- stuck pipe (W49) ---------------------------------------------------------------------

const wchar_t kStuckPipeName[] = L"\\\\.\\pipe\\waitwhy_stuck";

// Writes until the pipe is full; the next write blocks until main closes its end.
NOINLINE void fill_pipe() {
  NameThisThread(L"writer");
  HANDLE pipe = CreateFileW(kStuckPipeName, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return;
  static char block[65536];
  DWORD n = 0;
  while (!g_quit && WriteFile(pipe, block, sizeof block, &n, nullptr)) {
  }
  CloseHandle(pipe);
}

void RunStuckPipe() {
  HANDLE pipe = CreateNamedPipeW(kStuckPipeName, PIPE_ACCESS_INBOUND, PIPE_TYPE_BYTE | PIPE_WAIT, 1, 4096, 4096,
                                 0, nullptr);
  if (pipe == INVALID_HANDLE_VALUE) return;
  std::thread writer(fill_pipe);
  ConnectNamedPipe(pipe, nullptr);  // the writer may already be connected
  while (!g_quit) Sleep(50);        // never reads
  DisconnectNamedPipe(pipe);        // ends the blocked write
  CloseHandle(pipe);
  writer.join();
}

// ---- socket -------------------------------------------------------------------------------

std::atomic<unsigned short> g_port{0};

NOINLINE void socket_server() {
  NameThisThread(L"server");
  SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  bind(listener, reinterpret_cast<sockaddr*>(&addr), static_cast<int>(sizeof addr));
  int len = static_cast<int>(sizeof addr);
  getsockname(listener, reinterpret_cast<sockaddr*>(&addr), &len);
  listen(listener, 1);
  g_port = ntohs(addr.sin_port);
  SOCKET peer = accept(listener, nullptr, nullptr);
  char byte = 0;
  while (!g_quit && recv(peer, &byte, 1, 0) == 1) {
    Sleep(100);  // a slow reply
    send(peer, &byte, 1, 0);
  }
  closesocket(peer);
  closesocket(listener);
}

NOINLINE void socket_round_trip(SOCKET s) {
  char byte = 's';
  send(s, &byte, 1, 0);
  recv(s, &byte, 1, 0);
}

NOINLINE void socket_client() {
  NameThisThread(L"client");
  while (!g_quit && g_port == 0) Sleep(10);
  SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = htons(g_port);
  connect(s, reinterpret_cast<sockaddr*>(&addr), static_cast<int>(sizeof addr));
  while (!g_quit) socket_round_trip(s);
  closesocket(s);
}

void RunSocket() {
  WSADATA wsa;
  WSAStartup(MAKEWORD(2, 2), &wsa);
  std::thread server(socket_server);
  std::thread client(socket_client);
  while (!g_quit) Sleep(50);
  client.join();
  server.join();
  WSACleanup();
}

// ---- cpu ----------------------------------------------------------------------------------

NOINLINE void spin() {
  NameThisThread(L"spinner");
  volatile unsigned long long n = 0;
  while (!g_quit) n = n + 1;
}

void RunCpu() {
  // Twice as many busy threads as CPUs: each one waits for a CPU about half the time.
  const unsigned count = 2 * (std::max)(1u, std::thread::hardware_concurrency()) + 1;
  std::vector<std::thread> threads;
  for (unsigned i = 0; i < count; ++i) threads.emplace_back(spin);
  for (std::thread& t : threads) t.join();
}

// ---- child --------------------------------------------------------------------------------

NOINLINE void wait_for_child(HANDLE process) { WaitForSingleObject(process, INFINITE); }

void RunChild() {
  wchar_t self[MAX_PATH];
  GetModuleFileNameW(nullptr, self, MAX_PATH);
  while (!g_quit) {
    std::wstring command = L"\"" + std::wstring(self) + L"\" --mode sleeper";
    STARTUPINFOW si{};
    si.cb = sizeof si;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, &command[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr,
                        nullptr, &si, &pi)) {
      Sleep(100);
      continue;
    }
    wait_for_child(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
  }
}

// ---- lockcpu, locksleep, lockdisk -----------------------------------------------------------

std::mutex g_sharedLock;

NOINLINE void compute_under_lock() {
  std::lock_guard<std::mutex> lock(g_sharedLock);
  const auto until = std::chrono::steady_clock::now() + std::chrono::milliseconds(50);
  volatile unsigned long long n = 0;
  while (std::chrono::steady_clock::now() < until) n = n + 1;
}

NOINLINE void sleep_under_lock() {
  std::lock_guard<std::mutex> lock(g_sharedLock);
  Sleep(50);
}

NOINLINE void write_under_lock(const std::wstring& path, const std::vector<char>& data) {
  std::lock_guard<std::mutex> lock(g_sharedLock);
  HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                         FILE_FLAG_WRITE_THROUGH, nullptr);
  DWORD wrote = 0;
  WriteFile(f, data.data(), static_cast<DWORD>(data.size()), &wrote, nullptr);
  FlushFileBuffers(f);
  CloseHandle(f);
}

NOINLINE void use_shared_data() {
  std::lock_guard<std::mutex> lock(g_sharedLock);
}

void RunLock(const std::string& mode) {
  std::thread holder([&mode] {
    NameThisThread(L"holder");
    const std::wstring path = TempPath(L"waitwhy_scenarios_lock.bin");
    const std::vector<char> data(16 << 20, 'd');
    while (!g_quit) {
      if (mode == "lockcpu") compute_under_lock();
      else if (mode == "locksleep") sleep_under_lock();
      else write_under_lock(path, data);
      Sleep(1);
    }
    DeleteFileW(path.c_str());
  });
  while (!g_quit) {
    use_shared_data();
    Sleep(1);
  }
  holder.join();
}

// ---- sleep --------------------------------------------------------------------------------

NOINLINE void nap() { Sleep(50); }

void RunSleep() {
  std::thread other([] {
    NameThisThread(L"napper");
    while (!g_quit) nap();
  });
  while (!g_quit) nap();
  other.join();
}

// ---- bench --------------------------------------------------------------------------------

struct PingPong {
  std::mutex lock;
  std::condition_variable changed;
  bool ping = true;
  unsigned long long handovers = 0;
};

NOINLINE void do_work(int microseconds) {
  if (microseconds <= 0) return;
  const auto until = std::chrono::steady_clock::now() + std::chrono::microseconds(microseconds);
  volatile unsigned long long n = 0;
  while (std::chrono::steady_clock::now() < until) n = n + 1;
}

NOINLINE void pass_token(PingPong& p, bool mine, int workUs) {
  do_work(workUs);
  std::unique_lock<std::mutex> hold(p.lock);
  p.changed.wait(hold, [&] { return p.ping == mine || g_quit; });
  p.ping = !mine;
  ++p.handovers;
  hold.unlock();
  p.changed.notify_one();
}

void RunBench(int seconds, int workUs) {
  const unsigned pairs = (std::max)(1u, std::thread::hardware_concurrency() / 2);
  std::vector<PingPong> games(pairs);
  std::vector<std::thread> threads;
  const auto start = std::chrono::steady_clock::now();
  for (PingPong& p : games)
    for (bool side : {true, false})
      threads.emplace_back([&p, side, workUs] {
        NameThisThread(side ? L"ping" : L"pong");
        while (!g_quit) pass_token(p, side, workUs);
        p.changed.notify_all();
      });
  for (std::thread& t : threads) t.join();
  const double elapsed = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
  unsigned long long total = 0;
  for (const PingPong& p : games) total += p.handovers;
  std::printf("bench: %u pairs, %d us of work, %d s, %.0f hand-overs per second\n", pairs, workUs, seconds,
              static_cast<double>(total) / (elapsed > 0 ? elapsed : 1));
}

}  // namespace

int main(int argc, char** argv) {
  std::string mode;
  int seconds = 15;
  int workUs = 0;  // bench only
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--mode") == 0 && i + 1 < argc) {
      mode = argv[++i];
    } else if (std::strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
      seconds = std::atoi(argv[++i]);
    } else if (std::strcmp(argv[i], "--work-us") == 0 && i + 1 < argc) {
      workUs = std::atoi(argv[++i]);
    } else {
      mode.clear();
      break;
    }
  }
  if (mode == "sleeper") {
    Sleep(300);
    return 0;
  }
  NameThisThread(L"main");
  std::thread timer([seconds] {
    Sleep(static_cast<DWORD>(seconds) * 1000);
    g_quit = true;
  });
  timer.detach();

  if (mode == "condvar") RunCondvar();
  else if (mode == "coldread") RunColdRead();
  else if (mode == "console") RunConsole();
  else if (mode == "pipe") RunPipe();
  else if (mode == "socket") RunSocket();
  else if (mode == "cpu") RunCpu();
  else if (mode == "child") RunChild();
  else if (mode == "lockcpu" || mode == "locksleep" || mode == "lockdisk") RunLock(mode);
  else if (mode == "sleep") RunSleep();
  else if (mode == "stuckpipe") RunStuckPipe();
  else if (mode == "bench") RunBench(seconds, workUs);
  else {
    std::printf("usage: scenarios --mode condvar|coldread|console|pipe|socket|cpu|child|\n"
                "                        lockcpu|locksleep|lockdisk|sleep|stuckpipe|bench [--seconds N]\n"
                "                        [--work-us N, bench only]\n");
    return 1;
  }
  return 0;
}
