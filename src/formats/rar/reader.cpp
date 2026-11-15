// SPDX-License-Identifier: GPL-3.0-or-later
// RAR reader: walks the items, groups solid runs, decodes independent
// files in parallel and checks every CRC32 / BLAKE2sp.
#include "rar.h"

#include "../../core/driver.h"

#include <atomic>
#include <map>
#include <mutex>
#include <set>

namespace raye::archive::detail::rar {

namespace {

// Bytes held in memory (old comments stored inside a header).
class MemIn final : public ByteIn {
public:
    explicit MemIn(std::span<const std::uint8_t> d) : d_(d) {}
    std::size_t read(std::uint8_t *out, std::size_t n) override
    {
        n = std::min(n, d_.size() - pos_);
        std::memcpy(out, d_.data() + pos_, n);
        pos_ += n;
        return n;
    }

private:
    std::span<const std::uint8_t> d_;
    std::size_t pos_ = 0;
};

std::unique_ptr<Decoder> new_decoder(const Item &it, std::uint64_t window)
{
    switch (it.version) {
    case 50: return make_rar5_decoder(window, false);
    case 70: return make_rar5_decoder(window, true);
    case 29: return make_rar3_decoder(window);
    case 20: return make_rar2_decoder(window);
    case 15: return make_rar1_decoder(window);
    default: fail(ErrorCode::UnsupportedMethod, "this RAR compression version is not known", it.entry.path);
    }
}

bool has_data(const Item &it)
{
    return it.entry.type == EntryType::File || (it.entry.type == EntryType::Symlink && it.entry.link_target.empty());
}

// One unit of work: a lone file, or a solid run decoded in order.
struct Job {
    std::vector<std::size_t> items;
    std::uint64_t window = 0;
};

class RarReader final : public ReaderImpl {
public:
    RarReader(Volumes vols, Parsed p, std::string name) : vols_(std::move(vols)), p_(std::move(p)), name_(std::move(name)) {}

    void init(Context &ctx)
    {
        info_.solid = p_.solid;
        info_.encrypted_headers = p_.encrypted_headers;
        info_.volume_count = vols_.src.size();
        int maxver = 0;
        for (auto &it : p_.items) {
            if (it.entry.encrypted) info_.has_encrypted_entries = true;
            if (!it.stored) maxver = std::max(maxver, it.version);
            if (it.entry.solid) info_.solid = true;
        }
        std::string d = p_.version == 5 ? "RAR 5.0" : maxver == 15 ? "RAR 1.5" : maxver == 20 ? "RAR 2.0" : "RAR 2.9-4.x";
        if (maxver == 70) d = "RAR 7.0";
        if (info_.solid) d += ", solid";
        if (p_.encrypted_headers) d += ", encrypted headers";
        if (p_.locked) d += ", locked";
        if (p_.recovery) d += ", recovery record";
        if (vols_.src.size() > 1) d += ", " + std::to_string(vols_.src.size()) + " volumes";
        if (!p_.damage.empty()) d += ", damaged: " + p_.damage;
        info_.detail = d;
        read_comment(ctx);
    }

    ArchiveInfo info() const override { return info_; }

    std::vector<Entry> list(Context &) override
    {
        std::vector<Entry> v;
        v.reserve(p_.items.size());
        for (std::size_t i = 0; i < p_.items.size(); ++i) {
            v.push_back(p_.items[i].entry);
            v.back().index = i;
        }
        return v;
    }

    void extract(const std::vector<std::size_t> &indexes, EntryHandler &handler, Context &ctx) override
    {
        std::set<std::size_t> want(indexes.begin(), indexes.end());
        std::vector<Job> jobs, links;
        // Solid runs: a compressed item marked solid continues the last one.
        std::vector<std::size_t> run;
        auto close_run = [&] {
            if (run.empty()) return;
            std::size_t last = run.size();
            while (last > 0 && !want.count(run[last - 1])) --last;
            if (last) {
                Job j;
                j.items.assign(run.begin(), run.begin() + std::ptrdiff_t(last));
                j.window = run_window(j.items);
                jobs.push_back(std::move(j));
            }
            run.clear();
        };
        for (std::size_t i = 0; i < p_.items.size(); ++i) {
            const Item &it = p_.items[i];
            if (!has_data(it) || it.stored) {
                if (want.count(i)) (it.entry.type == EntryType::Hardlink ? links : jobs).push_back(Job{{i}, 0});
                continue;
            }
            if (!it.solid || run.empty() || p_.items[run.front()].version != it.version) close_run();
            run.push_back(i);
        }
        close_run();

        // Parallel lanes, but never more dictionaries than about 1 GiB.
        std::uint64_t biggest = 1;
        for (auto &j : jobs) biggest = std::max(biggest, j.window);
        std::size_t lanes = std::size_t(std::max<std::uint64_t>(1, (std::uint64_t(1) << 30) / biggest));
        lanes = std::min<std::size_t>({lanes, std::size_t(std::max(1, ctx.threads())), jobs.size()});
        std::atomic<std::size_t> next{0};
        ctx.pool().parallel_for(lanes, [&](std::size_t) {
            for (;;) {
                const std::size_t k = next.fetch_add(1);
                if (k >= jobs.size()) return;
                run_job(jobs[k], want, handler, ctx);
            }
        });
        // Hard links last: their target has to be on disk already.
        for (auto &j : links) run_job(j, want, handler, ctx);
    }

private:
    std::uint64_t run_window(const std::vector<std::size_t> &items) const
    {
        std::uint64_t dict = 0, total = 0;
        bool known = true;
        for (auto i : items) {
            const Item &it = p_.items[i];
            dict = std::max(dict, it.dict);
            total += it.entry.size;
            known = known && it.size_known;
        }
        return window_size(dict, total, known);
    }

    void run_job(const Job &job, const std::set<std::size_t> &want, EntryHandler &handler, Context &ctx)
    {
        std::unique_ptr<Decoder> dec;
        bool broken = false;
        for (std::size_t n = 0; n < job.items.size(); ++n) {
            const std::size_t i = job.items[n];
            const Item &it = p_.items[i];
            const bool wanted = want.count(i) != 0;
            ctx.checkpoint();
            if (!has_data(it)) {
                Entry e = it.entry;
                e.index = i;
                Sink *s = handler.begin(e);
                handler.end(e, s);
                continue;
            }
            if (!it.stored && !dec) dec = new_decoder(it, job.window);
            Entry e = it.entry;
            e.index = i;
            const bool link = it.entry.type == EntryType::Symlink;
            MemorySink target;
            Sink *s = nullptr;
            if (wanted && !link) {
                ctx.file_started(e.path);
                s = handler.begin(e);
            }
            try {
                if (broken) fail(ErrorCode::Corrupt, "an earlier file of this solid set is damaged", e.path);
                decode_one(it, link ? &target : s, dec.get(), n > 0, ctx);
                if (link) {
                    if (!wanted) continue;
                    e.link_target.assign(target.bytes().begin(), target.bytes().end());
                    s = handler.begin(e);
                }
                if (wanted) {
                    handler.end(e, s);
                    ctx.file_done();
                }
            } catch (const Error &err) {
                if (err.code() == ErrorCode::Cancelled) throw;
                if (!it.stored) broken = true;
                if (wanted) handler.failed(e, s, err);
            }
        }
    }

    const Keys *keys_for(const Item &it, Context &ctx, std::unique_ptr<Keys> &own)
    {
        if (it.crypt.kind == Crypt::None) return nullptr;
        if (it.crypt.kind == Crypt::Rar20 || it.crypt.kind == Crypt::Rar15)
            fail(ErrorCode::UnsupportedMethod, "RAR 1.5 and 2.0 encryption is not supported", it.entry.path);
        std::lock_guard l(key_m_);
        const std::string salt(reinterpret_cast<const char *>(it.crypt.salt.data()), 16);
        for (int attempt = 1;; ++attempt) {
            const std::string pw = ctx.password(it.entry.path, attempt);
            const std::string id = salt + char(it.crypt.kdf_log2) + char(it.crypt.kind) + char(it.crypt.has_salt) + pw;
            auto f = key_cache_.find(id);
            if (f == key_cache_.end()) {
                auto k = std::make_unique<Keys>();
                if (it.crypt.kind == Crypt::Rar3) rar3_keys(pw, it.crypt.has_salt ? it.crypt.salt.data() : nullptr, *k);
                else rar5_keys(pw, it.crypt, *k);
                f = key_cache_.emplace(id, std::move(k)).first;
            }
            if (it.crypt.kind == Crypt::Rar5 && it.crypt.has_check && f->second->check != it.crypt.check)
                continue; // check value says no: ask again
            ctx.password_ok(pw);
            own = std::make_unique<Keys>(*f->second);
            if (it.crypt.kind == Crypt::Rar5) std::memcpy(own->iv.data(), it.crypt.iv.data(), 16);
            return own.get();
        }
    }

    void decode_one(const Item &it, Sink *sink, Decoder *dec, bool solid, Context &ctx)
    {
        std::unique_ptr<Keys> keys;
        const Keys *k = keys_for(it, ctx, keys);
        PackedStream in(vols_, it, k);
        Output out(sink, it, ctx);
        try {
            if (it.stored) {
                std::vector<std::uint8_t> buf(1 << 16);
                for (;;) {
                    const std::size_t got = in.read(buf.data(), buf.size());
                    if (!got) break;
                    out.put(buf.data(), got);
                    if (out.full()) break;
                }
            } else if (in.total() > 0) {
                dec->decode(in, out, it, solid && it.solid);
            }
        } catch (const Error &e) {
            if (k && (e.code() == ErrorCode::Corrupt || e.code() == ErrorCode::Truncated) && !it.crypt.has_check)
                fail(ErrorCode::WrongPassword, "the password is wrong or the data is damaged", it.entry.path);
            if (it.truncated) fail(ErrorCode::Truncated, "this file is cut short (damaged archive or missing volume)", it.entry.path);
            throw;
        }
        if (it.truncated) fail(ErrorCode::Truncated, "this file is cut short (damaged archive or missing volume)", it.entry.path);
        if (it.size_known && out.written() < it.entry.size)
            fail(k && !it.crypt.has_check ? ErrorCode::WrongPassword : ErrorCode::Truncated,
                 "decoded data is shorter than the file", it.entry.path);
        const bool mix = k && it.crypt.kind == Crypt::Rar5 && it.crypt.hmac_sums;
        bool bad = false;
        if (it.has_blake) {
            auto h = out.blake();
            if (mix) h = rar5_mix_hash(h, k->hash_key);
            bad = h != it.blake;
        } else if (it.has_crc) {
            std::uint32_t c = out.crc();
            if (mix) c = rar5_mix_crc(c, k->hash_key);
            bad = c != it.crc;
        }
        if (bad) {
            if (k && !it.crypt.has_check) fail(ErrorCode::WrongPassword, "the password is wrong or the data is damaged", it.entry.path);
            fail(ErrorCode::Checksum, "checksum does not match: the data is damaged", it.entry.path);
        }
    }

    void read_comment(Context &ctx)
    {
        if (!p_.comment_item) return;
        try {
            const Item &it = *p_.comment_item;
            if (it.entry.size > (1 << 20)) return;
            MemorySink ms;
            Output out(&ms, it, ctx);
            if (!p_.comment_bytes.empty()) {
                MemIn in(p_.comment_bytes);
                if (it.stored) out.put(p_.comment_bytes.data(), p_.comment_bytes.size());
                else new_decoder(it, 0x40000)->decode(in, out, it, false);
            } else {
                PackedStream in(vols_, it, nullptr);
                if (it.stored) {
                    std::vector<std::uint8_t> b(std::size_t(it.entry.size));
                    const std::size_t got = in.read(b.data(), b.size());
                    out.put(b.data(), got);
                } else {
                    new_decoder(it, window_size(it.dict, it.entry.size, true))->decode(in, out, it, false);
                }
            }
            std::string s(ms.bytes().begin(), ms.bytes().end());
            while (!s.empty() && s.back() == '\0') s.pop_back();
            info_.comment = legacy_name(s);
        } catch (const Error &) {
            // A broken comment does not stop the archive from opening.
        }
    }

    Volumes vols_;
    Parsed p_;
    std::string name_;
    ArchiveInfo info_;
    std::mutex key_m_;
    std::map<std::string, std::unique_ptr<Keys>> key_cache_;
};

} // namespace

std::unique_ptr<ReaderImpl> open_rar(const OpenRequest &req, Context &ctx, bool rar5)
{
    Volumes vols;
    vols.base0 = req.detection.offset;
    if (req.volumes.size() > 1) {
        vols.src.push_back(req.source);
        for (std::size_t i = 1; i < req.volumes.size(); ++i) {
            try {
                vols.src.push_back(open_file_source(req.volumes[i]));
            } catch (const Error &) {
                vols.src.push_back(nullptr);
            }
        }
    } else {
        vols.src.push_back(req.source);
    }
    Parsed p = rar5 ? parse_rar5(vols, ctx) : parse_rar4(vols, ctx);
    auto r = std::make_unique<RarReader>(std::move(vols), std::move(p), req.name);
    r->init(ctx);
    return r;
}

} // namespace raye::archive::detail::rar
