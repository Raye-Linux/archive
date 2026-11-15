// SPDX-License-Identifier: GPL-3.0-or-later
#include "threadpool.h"

#include <atomic>

namespace raye::archive::detail {

unsigned default_threads(int requested)
{
    if (requested > 0) return unsigned(requested);
    unsigned n = std::thread::hardware_concurrency();
    return n ? n : 1;
}

ThreadPool::ThreadPool(unsigned threads)
{
    threads = default_threads(int(threads));
    workers_.reserve(threads);
    for (unsigned i = 0; i < threads; ++i) workers_.emplace_back([this] { run(); });
}

ThreadPool::~ThreadPool()
{
    {
        std::lock_guard l(m_);
        stop_ = true;
    }
    cv_.notify_all();
    for (auto &t : workers_) t.join();
}

void ThreadPool::push(std::function<void()> job)
{
    {
        std::lock_guard l(m_);
        jobs_.push_back(std::move(job));
    }
    cv_.notify_one();
}

void ThreadPool::run()
{
    for (;;) {
        std::function<void()> job;
        {
            std::unique_lock l(m_);
            cv_.wait(l, [this] { return stop_ || !jobs_.empty(); });
            if (jobs_.empty()) return;
            job = std::move(jobs_.front());
            jobs_.pop_front();
        }
        job();
    }
}

void ThreadPool::parallel_for(std::size_t n, const std::function<void(std::size_t)> &body)
{
    if (n == 0) return;
    if (n == 1 || size() == 1) {
        for (std::size_t i = 0; i < n; ++i) body(i);
        return;
    }
    std::atomic<std::size_t> next{0};
    std::atomic<bool> failed{false};
    std::exception_ptr first;
    std::mutex em;
    auto worker = [&] {
        for (;;) {
            if (failed.load()) return;
            std::size_t i = next.fetch_add(1);
            if (i >= n) return;
            try {
                body(i);
            } catch (...) {
                std::lock_guard l(em);
                if (!first) first = std::current_exception();
                failed = true;
            }
        }
    };
    const std::size_t lanes = std::min<std::size_t>(n, size());
    std::vector<std::future<void>> futs;
    for (std::size_t i = 1; i < lanes; ++i) futs.push_back(submit(worker));
    worker(); // the caller works too, so a pool of 1 never deadlocks
    for (auto &f : futs) f.get();
    if (first) std::rethrow_exception(first);
}

} // namespace raye::archive::detail
