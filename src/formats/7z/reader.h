// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "streams.h"

#include "../../core/driver.h"

#include <mutex>

namespace raye::archive::detail::sevenz {

class Reader final : public ReaderImpl {
public:
    Reader(const OpenRequest &req, Context &ctx);
    ArchiveInfo info() const override { return info_; }
    std::vector<Entry> list(Context &ctx) override;
    void extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx) override;

    // For the writer: keep whole folders without decoding them again.
    const Database &db() const { return db_; }
    const Source &source() const { return *src_; }
    std::uint64_t data_start() const { return base_ + kStartHeaderSize + db_.streams.pack_pos; }
    // Entry index -> file index in db().files, and where its data is.
    struct Where {
        std::size_t file;
        std::size_t folder = SIZE_MAX;  // SIZE_MAX: no data
        std::size_t sub = 0;            // index into streams.sub_sizes
        std::uint64_t offset = 0;       // inside the folder output
    };
    const std::vector<Where> &where() const { return where_; }
    std::uint64_t folder_data_start(std::size_t folder) const;
    // Opens a folder's output with a password that works (asks for one if needed).
    std::unique_ptr<Pull> open_folder_checked(std::size_t folder, Context &ctx, const std::string &for_entry);

private:
    void read_headers(Context &ctx);
    std::vector<std::uint8_t> decode_header_folder(const StreamsInfo &si, const std::string *pw);
    void extract_folder(std::size_t folder, const std::vector<std::size_t> &entries, EntryHandler &handler,
                        Context &ctx);
    std::string password_for(std::size_t folder, Context &ctx, const std::string &entry);

    std::shared_ptr<Source> src_;
    std::uint64_t base_ = 0;
    std::string name_;
    Database db_;
    ArchiveInfo info_;
    std::vector<Entry> entries_;
    std::vector<Where> where_;
    std::vector<std::vector<std::size_t>> folder_entries_; // entry indexes with data, in folder order
    std::shared_ptr<KeyCache> keys_ = make_key_cache();
    unsigned folder_threads_ = 1;
    std::mutex pw_m_;
    std::optional<std::string> good_pw_;
};

std::string folder_label(const Folder &f);

} // namespace raye::archive::detail::sevenz
