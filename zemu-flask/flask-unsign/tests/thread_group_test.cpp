#include "../src/thread_group.h"
#include "../src/crack_cpu.h"
#include <iostream>

static void require(bool ok, const char* message) {
  if (!ok) throw std::runtime_error(message);
}
static bool throwsUnknown(const uint8_t*, size_t, void*) { throw 42; }
static bool matches(const uint8_t*, size_t, void*) { return true; }

int main() {
  // Simulate an exception on the caller/GPU side while a worker is active.
  std::atomic<bool> stop{false}, entered{false}, exited{false};
  try {
    ThreadGroup group(stop);
    group.launch([&] {
      entered.store(true);
      while (!stop.load()) std::this_thread::yield();
      exited.store(true);
    });
    while (!entered.load()) std::this_thread::yield();
    throw std::runtime_error("caller failed");
  } catch (const std::runtime_error&) {}
  require(stop.load() && exited.load(), "caller exception did not stop and join worker");

  // Exceptions thrown inside verification must not escape the worker entry point.
  std::vector<std::string> words(10000, "word");
  auto failed = crackCpuWords(words, 2, throwsUnknown, nullptr);
  require(!failed.found && !failed.error.empty(), "worker exception lost");
  require(!g_crackAbort.load(), "failure leaked into persistent cancellation state");
  auto recovered = crackCpuWords(words, 2, matches, nullptr);
  require(recovered.found && recovered.error.empty(), "next CPU task did not recover");

  HybridCtl ctl;
  ctl.tail.store(words.size());
  failed = crackCpuWordsRange(words, 2, throwsUnknown, nullptr, ctl);
  require(!failed.found && !failed.error.empty() && ctl.stop.load(),
          "CPU exception did not stop peer GPU");
  std::cout << "PASS thread unwinding, worker exceptions, peer stop, task recovery\n";
}
