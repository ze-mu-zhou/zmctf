#pragma once

#include <atomic>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#ifdef ZK_THREAD_TESTING
#include <cstdlib>
#include <system_error>
#endif

// Own every started thread until it is joined. Stop flags are task-local;
// failures must not set the persistent g_crackAbort flag used by serve.
// Default construction owns its stop flag: stopping means a recorded failure
// (finish() joins then throws), or destruction during unwinding (the caller
// abandons partial output). Packing workers may therefore return without
// completing output when stopped; consumers must run only after finish().
// With an external stop flag, normal cancellation or a peer's successful hit
// may also stop workers. stopped() does NOT generally imply finish() throws.
// finish() propagates only exceptions recorded by this group.
class ThreadGroup {
  std::atomic<bool> ownStop_{false};
  std::atomic<bool>& stop_;
  std::atomic<bool>* peer_;
  std::mutex mutex_;
  std::exception_ptr failure_;
  const char* phase_ = nullptr;
  std::vector<std::thread> threads_;

  void stop() noexcept {
    stop_.store(true, std::memory_order_relaxed);
    if (peer_) peer_->store(true, std::memory_order_relaxed);
  }
  void fail(const char* phase) {
    stop();
    std::lock_guard<std::mutex> lock(mutex_);
    if (!failure_) {
      failure_ = std::current_exception();
      phase_ = phase;
    }
  }
  void join() {
    for (auto& thread : threads_)
      if (thread.joinable()) thread.join();
  }

public:
  ThreadGroup() : stop_(ownStop_), peer_(nullptr) {}
  explicit ThreadGroup(std::atomic<bool>& stop, std::atomic<bool>* peer = nullptr)
      : stop_(stop), peer_(peer) {}
  ThreadGroup(const ThreadGroup&) = delete;
  ThreadGroup& operator=(const ThreadGroup&) = delete;
  ~ThreadGroup() {
    // During stack unwinding, stop before joining; after finish(), no work remains.
    for (auto& thread : threads_)
      if (thread.joinable()) { stop(); break; }
    join();
  }
  bool stopped() const { return stop_.load(std::memory_order_relaxed); }

  template<class Worker>
  void launch(Worker worker) {
    try {
#ifdef ZK_THREAD_TESTING
      // Fault injection exists only in the dedicated test executable.
      const int attempt = ++testAttempts;
      const char* createAt = std::getenv("ZK_TEST_THREAD_CREATE_AT");
      if (createAt && attempt == std::atoi(createAt))
        throw std::system_error(std::make_error_code(std::errc::resource_unavailable_try_again));
#endif
      threads_.emplace_back([this, worker = std::move(worker)
#ifdef ZK_THREAD_TESTING
                            , attempt
#endif
                            ]() mutable {
        try {
#ifdef ZK_THREAD_TESTING
          const char* workerAt = std::getenv("ZK_TEST_THREAD_WORKER_AT");
          if (workerAt && attempt == std::atoi(workerAt))
            throw std::runtime_error("injected worker failure");
#endif
          worker();
        } catch (...) { fail("工作线程执行失败"); }
      });
    } catch (...) {
      fail("线程创建失败");
      finish();
    }
  }
  void finish() {
    join();
    if (!failure_) return;
    try { std::rethrow_exception(failure_); }
    catch (const std::exception& e) { throw std::runtime_error(std::string(phase_) + ": " + e.what()); }
    catch (...) { throw std::runtime_error(std::string(phase_) + ": 未知异常"); }
  }
#ifdef ZK_THREAD_TESTING
  inline static std::atomic<int> testAttempts{0};
#endif
};
