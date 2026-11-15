// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <condition_variable>
#include <cstddef>
#include <deque>
#include <exception>
#include <functional>
#include <future>
#include <mutex>
#include <thread>
#include <vector>

namespace raye::archive::detail {

// Fixed set of workers. Tasks must not wait on other tasks of the same pool.
class ThreadPool {
public:
    explicit ThreadPool(unsigned threads); // 0 = hardware_concurrency
    ~ThreadPool();
    ThreadPool(const ThreadPool &) = delete;
    ThreadPool &operator=(const ThreadPool &) = delete;

    unsigned size() const { return static_cast<unsigned>(workers_.size()); }

    template <class F> auto submit(F &&f) -> std::future<decltype(f())> {
        using R = decltype(f());
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        auto fut = task->get_future();
        push([task] { (*task)(); });
        return fut;
    }

    // Runs body(i) for i in [0, n) on the pool and waits; rethrows the first
    // exception after every started task has returned.
    void parallel_for(std::size_t n, const std::function<void(std::size_t)> &body);

private:
    void push(std::function<void()> job);
    void run();

    std::vector<std::thread> workers_;
    std::deque<std::function<void()>> jobs_;
    std::mutex m_;
    std::condition_variable cv_;
    bool stop_ = false;
};

unsigned default_threads(int requested); // 0 or negative = cores

} // namespace raye::archive::detail
