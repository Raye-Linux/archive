// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 5.0 archive layout, from RARLAB's public technote.
#include "rar.h"

#include "../../core/bytes.h"

namespace raye::archive::detail::rar {

namespace {

constexpr std::uint8_t kSig5[8] = {'R', 'a', 'r', '!', 0x1a, 7, 1, 0};

enum : std::uint64_t {
    kMain = 1, kFile = 2, kService = 3, kCrypt = 4, kEnd = 5,
    kHasExtra = 1, kHasData = 2, kSplitBefore = 8, kSplitAfter = 16,
};

struct Header {
    std::vector<std::uint8_t> raw; // from the type field on
    std::uint64_t type = 0, flags = 0, extra = 0, data = 0;
    std::uint64_t data_pos = 0;    // file offset of the data area
    std::size_t body = 0;          // offset in raw after the common fields
};

class Walker {
public:
    Walker(const Volumes &vols, Context &ctx, Parsed &out) : vols_(vols), ctx_(ctx), out_(out) {}

    void run()
    {
        for (std::uint32_t v = 0; v < vols_.src.size(); ++v) {
            if (!vols_.src[v]) {
                if (!out_.items.empty() && out_.items.back().split_after) out_.items.back().truncated = true;
                note_damage("volume " + std::to_string(v + 1) + " is missing");
                return;
            }
            bool more = false;
            try {
                more = volume(v);
            } catch (const Error &e) {
                if (e.code() == ErrorCode::WrongPassword || e.code() == ErrorCode::PasswordRequired ||
                    e.code() == ErrorCode::Cancelled || e.code() == ErrorCode::UnsupportedMethod)
                    throw;
                if (v == 0 && out_.items.empty() && !main_seen_) throw;
                note_damage(e.message());
                return;
            }
            if (!more) return;
        }
        if (!out_.items.empty() && out_.items.back().split_after) {
            out_.items.back().truncated = true;
            note_damage("the last volume is missing");
        }
    }

private:
    void note_damage(const std::string &why)
    {
        if (out_.damage.empty()) out_.damage = why;
    }

    // Returns true when the end header says another volume follows.
    bool volume(std::uint32_t v)
    {
        const Source &src = *vols_.src[v];
        std::uint64_t pos = v == 0 ? vols_.base0 : 0;
        std::uint8_t sig[8];
        src.read_exact(pos, sig, 8);
        if (std::memcmp(sig, kSig5, 8) != 0) fail(ErrorCode::Corrupt, "volume " + std::to_string(v + 1) + " is not a RAR 5 volume");
        pos += 8;
        key_.reset(); // each volume repeats its encryption header
        while (pos < src.size()) {
            Header h = read_header(src, pos);
            if (h.data_pos + h.data > src.size() && h.type != kFile && h.type != kService)
                fail(ErrorCode::Truncated, "a header points past the end of the volume");
            switch (h.type) {
            case kMain: main(h); break;
            case kCrypt: crypt(h); break;
            case kFile: file(h, v, src.size(), false); break;
            case kService: file(h, v, src.size(), true); break;
            case kEnd: {
                ByteReader r(h.raw);
                r.seek(h.body);
                const std::uint64_t f = r.eof() ? 0 : r.vint();
                return (f & 1) != 0;
            }
            default: break; // unknown header: skip it
            }
            pos = h.data_pos + h.data;
        }
        return false;
    }

    Header read_header(const Source &src, std::uint64_t pos)
    {
        Header h;
        std::vector<std::uint8_t> buf;
        std::size_t total = 0;
        if (key_) {
            std::uint8_t iv[16];
            src.read_exact(pos, iv, 16);
            pos += 16;
            Aes aes(key_->key, Aes::Mode::Cbc, false, std::span<const std::uint8_t>(iv, 16));
            buf.resize(16);
            src.read_exact(pos, buf.data(), 16);
            aes.process(buf.data(), buf.data(), 16);
            total = header_total(buf);
            const std::size_t padded = (total + 15) & ~std::size_t(15);
            if (pos + padded > src.size()) fail(ErrorCode::Truncated, "archive ends inside a header");
            buf.resize(padded);
            src.read_exact(pos + 16, buf.data() + 16, padded - 16);
            aes.process(buf.data() + 16, buf.data() + 16, padded - 16);
            h.data_pos = pos + padded;
        } else {
            buf.resize(16);
            const std::size_t got = src.read_at(pos, buf.data(), 16);
            if (got < 7) fail(ErrorCode::Truncated, "archive ends inside a header");
            buf.resize(got);
            total = header_total(buf);
            if (pos + total > src.size()) fail(ErrorCode::Truncated, "archive ends inside a header");
            buf.resize(total);
            src.read_exact(pos, buf.data(), total);
            h.data_pos = pos + total;
        }
        if (crc32(0, buf.data() + 4, total - 4) != le32(buf.data())) {
            if (key_ && !key_checked_) fail(ErrorCode::WrongPassword, "the password is wrong");
            fail(ErrorCode::Corrupt, "header checksum does not match");
        }
        ByteReader r(std::span<const std::uint8_t>(buf.data() + 4, total - 4));
        r.vint(); // size
        h.raw.assign(buf.begin() + std::ptrdiff_t(4 + r.pos()), buf.begin() + std::ptrdiff_t(total));
        ByteReader b(h.raw);
        h.type = b.vint();
        h.flags = b.vint();
        if (h.flags & kHasExtra) h.extra = b.vint();
        if (h.flags & kHasData) h.data = b.vint();
        h.body = b.pos();
        if (h.extra > h.raw.size() - h.body) fail(ErrorCode::Corrupt, "extra area is larger than its header");
        return h;
    }

    static std::size_t header_total(const std::vector<std::uint8_t> &b)
    {
        ByteReader r(std::span<const std::uint8_t>(b.data() + 4, b.size() - 4));
        const std::uint64_t size = r.vint();
        if (size == 0 || size > (2u << 20)) fail(ErrorCode::Corrupt, "header size is not possible");
        return 4 + r.pos() + std::size_t(size);
    }

    void main(const Header &h)
    {
        main_seen_ = true;
        ByteReader r(h.raw);
        r.seek(h.body);
        const std::uint64_t f = r.vint();
        out_.solid = (f & 4) != 0;
        out_.recovery = out_.recovery || (f & 8) != 0;
        out_.locked = (f & 16) != 0;
    }

    void crypt(const Header &h)
    {
        ByteReader r(h.raw);
        r.seek(h.body);
        if (r.vint() != 0) fail(ErrorCode::UnsupportedMethod, "unknown RAR5 header encryption");
        CryptInfo ci;
        ci.kind = Crypt::Rar5;
        const std::uint64_t f = r.vint();
        ci.kdf_log2 = r.u8();
        auto salt = r.bytes(16);
        std::copy(salt.begin(), salt.end(), ci.salt.begin());
        if (f & 1) read_check(r, ci);
        out_.encrypted_headers = true;
        key_ = std::make_unique<Keys>();
        for (int attempt = 1;; ++attempt) {
            const std::string pw = ctx_.password({}, attempt);
            Keys k;
            if (rar5_keys(pw, ci, k)) {
                key_->key = k.key;
                key_checked_ = ci.has_check;
                ctx_.password_ok(pw);
                break;
            }
        }
    }

    static void read_check(ByteReader &r, CryptInfo &ci)
    {
        auto c = r.bytes(8);
        auto sum = r.bytes(4);
        std::uint8_t d[32];
        sha256(c.data(), 8, d);
        if (std::memcmp(d, sum.data(), 4) == 0) {
            ci.has_check = true;
            std::copy(c.begin(), c.end(), ci.check.begin());
        }
    }

    void file(const Header &h, std::uint32_t v, std::uint64_t vol_size, bool service)
    {
        ByteReader r(h.raw);
        r.seek(h.body);
        Item it;
        const std::uint64_t ff = r.vint();
        const std::uint64_t unp = r.vint();
        const std::uint64_t attr = r.vint();
        if (ff & 2) it.entry.mtime = Timestamp{std::int64_t(r.u32()), 0};
        if (ff & 4) { it.has_crc = true; it.crc = r.u32(); }
        const std::uint64_t comp = r.vint();
        const std::uint64_t host = r.vint();
        const std::uint64_t nlen = r.vint();
        if (nlen > r.left()) fail(ErrorCode::Corrupt, "name is longer than its header");
        it.entry.path = r.str(std::size_t(nlen));
        it.entry.size = unp;
        it.size_known = (ff & 8) == 0;
        it.entry.size_known = it.size_known;
        it.entry.packed_size = h.data;
        const unsigned ver = unsigned(comp & 0x3f);
        it.solid = (comp & 0x40) != 0;
        const unsigned method = unsigned(comp >> 7) & 7;
        const unsigned n = unsigned(comp >> 10) & 0x1f;
        it.stored = method == 0;
        it.version = ver == 0 ? 50 : ver == 1 ? 70 : 0;
        if (ver == 0 && n > 15) it.version = 0;
        if (it.version) {
            it.dict = 0x20000ull << n;
            if (ver == 1) it.dict += (it.dict / 32) * ((comp >> 15) & 0x1f);
        }
        it.entry.method = it.stored ? "Store" : it.version == 70 ? "RAR7" : "RAR5";
        if (!it.stored && it.version == 0) it.entry.method = "RAR5 v" + std::to_string(ver);
        it.entry.solid = it.solid && !it.stored;
        if (ff & 1) {
            it.entry.type = EntryType::Directory;
            it.entry.size = 0;
        }
        if (host == 0) {
            it.entry.windows_attributes = std::uint32_t(attr);
            if (attr & 0x10) it.entry.type = EntryType::Directory;
        } else if (host == 1) {
            it.entry.mode = std::uint32_t(attr & 07777);
            const std::uint64_t kind = attr & 0170000;
            if (kind == 0040000) it.entry.type = EntryType::Directory;
            else if (kind == 0120000) it.entry.type = EntryType::Symlink;
        }
        old_version_ = false;
        if (h.extra) extras(h, it);
        if (old_version_ && !(h.flags & kSplitBefore)) {
            skip_split_ = (h.flags & kSplitAfter) != 0;
            return;
        }
        if (skip_split_ && (h.flags & kSplitBefore)) {
            skip_split_ = (h.flags & kSplitAfter) != 0;
            return;
        }
        skip_split_ = false;
        if (it.entry.type == EntryType::Symlink && it.entry.link_target.empty()) it.entry.type = EntryType::File;
        it.split_after = (h.flags & kSplitAfter) != 0;
        if (h.flags & kHasData) {
            const std::uint64_t avail = h.data_pos < vol_size ? vol_size - h.data_pos : 0;
            Part p{v, h.data_pos, std::min(h.data, avail)};
            if (h.data > avail) {
                it.truncated = true;
                note_damage("data of " + it.entry.path + " is cut short");
            }
            it.parts.push_back(p);
        }
        if (service) {
            if (it.entry.path == "CMT" && it.crypt.kind == Crypt::None && !comment_) comment_ = it;
            return;
        }
        if (h.flags & kSplitBefore) {
            if (!out_.items.empty() && out_.items.back().split_after && out_.items.back().entry.path == it.entry.path) {
                Item &prev = out_.items.back();
                prev.parts.insert(prev.parts.end(), it.parts.begin(), it.parts.end());
                prev.split_after = it.split_after;
                prev.truncated = prev.truncated || it.truncated;
                prev.entry.packed_size += it.entry.packed_size;
                if (!it.split_after) {
                    prev.has_crc = it.has_crc;
                    prev.crc = it.crc;
                    prev.has_blake = it.has_blake;
                    prev.blake = it.blake;
                }
                return;
            }
            it.truncated = true; // its start is in a volume we do not have
            note_damage(it.entry.path + " starts in an earlier volume");
        }
        if (it.split_after) it.has_crc = false; // that CRC covers this part only
        it.entry.index = out_.items.size();
        it.entry.volume = v;
        it.entry.crc32 = it.has_crc ? std::optional<std::uint32_t>(it.crc) : std::nullopt;
        out_.items.push_back(std::move(it));
    }

    void extras(const Header &h, Item &it)
    {
        ByteReader r(std::span<const std::uint8_t>(h.raw.data() + (h.raw.size() - h.extra), std::size_t(h.extra)));
        while (!r.eof()) {
            const std::uint64_t size = r.vint();
            if (size == 0 || size > r.left()) fail(ErrorCode::Corrupt, "bad extra record in header");
            ByteReader e(r.bytes(std::size_t(size)));
            const std::uint64_t type = e.vint();
            switch (type) {
            case 1: { // encryption
                if (e.vint() != 0) fail(ErrorCode::UnsupportedMethod, "unknown RAR5 encryption", it.entry.path);
                const std::uint64_t f = e.vint();
                it.crypt.kind = Crypt::Rar5;
                it.crypt.kdf_log2 = e.u8();
                auto s = e.bytes(16);
                std::copy(s.begin(), s.end(), it.crypt.salt.begin());
                auto iv = e.bytes(16);
                std::copy(iv.begin(), iv.end(), it.crypt.iv.begin());
                if (f & 1) read_check(e, it.crypt);
                it.crypt.hmac_sums = (f & 2) != 0;
                it.entry.encrypted = true;
                break;
            }
            case 2: // hash
                if (e.vint() == 0) {
                    auto d = e.bytes(32);
                    std::copy(d.begin(), d.end(), it.blake.begin());
                    it.has_blake = true;
                }
                break;
            case 3: { // times
                const std::uint64_t f = e.vint();
                const bool unix_time = f & 1;
                std::optional<Timestamp> *slots[3] = {&it.entry.mtime, &it.entry.ctime, &it.entry.atime};
                bool present[3] = {(f & 2) != 0, (f & 4) != 0, (f & 8) != 0};
                for (int i = 0; i < 3; ++i) {
                    if (!present[i]) continue;
                    if (unix_time) *slots[i] = Timestamp{std::int64_t(e.u32()), 0};
                    else *slots[i] = file_time(e.u64());
                }
                if (unix_time && (f & 0x10))
                    for (int i = 0; i < 3; ++i)
                        if (present[i]) (*slots[i])->nanoseconds = e.u32() % 1000000000u;
                break;
            }
            case 5: { // redirection
                const std::uint64_t kind = e.vint();
                e.vint(); // flags
                const std::uint64_t len = e.vint();
                if (len > e.left()) fail(ErrorCode::Corrupt, "bad link target in header");
                std::string target = e.str(std::size_t(len));
                if (kind == 1 || kind == 2 || kind == 3) {
                    it.entry.type = EntryType::Symlink;
                    if (kind != 1) for (char &c : target) if (c == '\\') c = '/';
                } else if (kind == 4 || kind == 5) {
                    it.entry.type = EntryType::Hardlink;
                }
                it.entry.link_target = target;
                break;
            }
            case 4: // older version of a file: hidden, as RAR does without -ver
                e.vint();
                if (e.vint()) old_version_ = true;
                break;
            default: break; // owner, service data
            }
        }
    }

    const Volumes &vols_;
    Context &ctx_;
    Parsed &out_;
    std::unique_ptr<Keys> key_;
    bool key_checked_ = false;
    bool main_seen_ = false;
    bool old_version_ = false, skip_split_ = false;

public:
    std::optional<Item> comment_;
};

} // namespace

Parsed parse_rar5(const Volumes &vols, Context &ctx)
{
    Parsed p;
    p.version = 5;
    Walker w(vols, ctx, p);
    w.run();
    p.comment_item = w.comment_;
    return p;
}

} // namespace raye::archive::detail::rar
