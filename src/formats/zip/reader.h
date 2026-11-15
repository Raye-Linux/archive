// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "zip.h"

namespace raye::archive::detail::zip {

class ZipReader final : public ReaderImpl {
public:
    ZipReader(const OpenRequest &req, Context &ctx);

    ArchiveInfo info() const override { return info_; }
    std::vector<Entry> list(Context &ctx) override;
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx) override;
    bool copy_raw(std::size_t index, Sink &out, Context &ctx) override;

    // For the writer: keep entries as they are stored.
    const std::vector<Record> &records() const { return recs_; }
    struct RawSpan {
        std::uint64_t start = 0, length = 0; // local header through data descriptor
        bool local_zip64 = false;
    };
    RawSpan raw_span(std::size_t index) const;
    const Source &source() const { return *src_; }
    const std::string &raw_comment() const { return raw_comment_; }

private:
    void read_central(const OpenRequest &req);
    void scan_local_headers();
    void make_entries();
    std::uint64_t resolve(std::uint32_t disk, std::uint64_t offset) const;
    std::uint64_t data_start(const Record &r) const;
    // Decodes entry i into sink (nullptr: decode and drop). Verifies the CRC
    // and the AES authentication code.
    void decode(std::size_t i, Sink *sink, Context &ctx);
    void extract_one(std::size_t i, EntryHandler &handler, Context &ctx);

    std::shared_ptr<Source> src_;
    std::uint64_t size_ = 0;
    std::vector<Record> recs_;
    std::vector<Entry> entries_;
    std::vector<std::uint64_t> disk_start_; // set when the archive spans disks
    std::int64_t delta_ = 0;                // bytes before the archive (self-extracting stubs)
    std::string raw_comment_;
    ArchiveInfo info_;
    bool links_read_ = false;
};

} // namespace raye::archive::detail::zip
