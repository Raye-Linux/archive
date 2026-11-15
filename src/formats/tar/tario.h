// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "../../core/driver.h"

#include <functional>
#include <memory>

namespace raye::archive::detail {

struct TarItem;

// A handler that must see entries one by one, in archive order.
class OrderedHandler : public EntryHandler {};

class TarReader final : public ReaderImpl {
public:
    TarReader(std::shared_ptr<Source> src, std::uint64_t start, Format outer);
    ~TarReader() override;
    ArchiveInfo info() const override;
    std::vector<Entry> list(Context &ctx) override;
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx) override;
    const TarItem *item(std::size_t i) const;

private:
    void one(const TarItem &it, EntryHandler &h, Context &ctx, const std::function<void(void *, std::size_t)> &read);
    void extract_stream(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx);

    std::shared_ptr<Source> src_;
    std::uint64_t start_;
    Format outer_;
    std::vector<TarItem> items_;
    std::shared_ptr<Source> cache_; // the decoded tar, when it was small enough to keep
};

// One compressed file that is not a tar (notes.txt.gz).
class StreamReader final : public ReaderImpl {
public:
    StreamReader(std::shared_ptr<Source> src, std::uint64_t start, Format f, const std::string &archive_name);
    ArchiveInfo info() const override;
    std::vector<Entry> list(Context &ctx) override;
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx) override;

private:
    std::shared_ptr<Source> src_;
    std::uint64_t start_;
    Format f_;
    Entry e_;
};

std::unique_ptr<ReaderImpl> open_tar_family(const OpenRequest &req, Format f, Context &ctx);

class TarWriter final : public WriterImpl {
public:
    explicit TarWriter(Format f) : f_(f) {}
    void write(const std::vector<PlanItem> &plan, ReaderImpl *existing, Sink &out, const WriteOptions &opts,
               Context &ctx) override;

private:
    Format f_;
};

} // namespace raye::archive::detail
