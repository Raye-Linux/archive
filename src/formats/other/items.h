// SPDX-License-Identifier: GPL-3.0-or-later
// Base for archives whose file data sits uncompressed at known places
// (ar, cpio, ISO): extraction reads them straight from the file, several
// files at once.
#pragma once

#include "../../core/context.h"
#include "../../core/driver.h"

#include <functional>
#include <memory>
#include <set>
#include <utility>
#include <vector>

namespace raye::archive::detail {

struct Item {
    Entry entry;
    // Where the bytes are, in order: (offset, length). Usually one piece.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> pieces;
    bool zisofs = false; // ISO transparent compression: zlib blocks
};

class ItemReader : public ReaderImpl {
public:
    explicit ItemReader(std::shared_ptr<Source> src) : src_(std::move(src)) {}
    ArchiveInfo info() const override { return info_; }
    std::vector<Entry> list(Context &) override
    {
        std::vector<Entry> v;
        v.reserve(items_.size());
        for (std::size_t i = 0; i < items_.size(); ++i) {
            items_[i].entry.index = i;
            v.push_back(items_[i].entry);
        }
        return v;
    }
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &h, Context &ctx) override;

protected:
    std::shared_ptr<Source> src_;
    std::vector<Item> items_;
    ArchiveInfo info_;
};

// Calls one(i) for every index: folders first, files in parallel, links
// last; in plain order when a path repeats or ordered is set.
void for_each_entry(const std::vector<Entry> &all, const std::vector<std::size_t> &indexes, Context &ctx, bool ordered,
                    const std::function<void(std::size_t)> &one);

// begin/end/failed around writing one entry's data with write(sink).
void run_entry(const Entry &e, EntryHandler &h, Context &ctx, const std::function<void(Sink &)> &write);

std::string latin1_to_utf8(std::string_view s);
// Names from DOS-era formats (CAB, LZH, ARJ) with no charset given: kept if
// already UTF-8, else read as Shift-JIS when that decodes cleanly, else CP437.
std::string legacy_name_to_utf8(std::string_view s);

} // namespace raye::archive::detail
