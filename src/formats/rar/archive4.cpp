// SPDX-License-Identifier: GPL-3.0-or-later
// RAR 1.5 to 4.x archive layout: 7-byte block headers with a 16-bit CRC.
#include "rar.h"

#include "../../core/bytes.h"

#include <map>

namespace raye::archive::detail::rar {

namespace {

constexpr std::uint8_t kSig4[7] = {'R', 'a', 'r', '!', 0x1a, 7, 0};

enum : std::uint16_t {
    kLongBlock = 0x8000,
    // main header
    kMhdVolume = 0x01, kMhdComment = 0x02, kMhdLock = 0x04, kMhdSolid = 0x08, kMhdProtect = 0x40,
    kMhdPassword = 0x80,
    // file header
    kSplitBefore = 0x01, kSplitAfter = 0x02, kPassword = 0x04, kOldComment = 0x08, kSolid = 0x10, kLarge = 0x100,
    kUnicode = 0x200, kSalt = 0x400, kVersion = 0x800, kExtTime = 0x1000,
};

// The Unicode name trick of RAR 3.x: the 8-bit name, then a packed list
// of high bytes and runs that turn it into UTF-16.
std::vector<std::uint16_t> decode_unicode(std::span<const std::uint8_t> ascii, std::span<const std::uint8_t> enc)
{
    std::vector<std::uint16_t> out;
    std::size_t e = 0;
    if (enc.empty()) return out;
    const std::uint8_t high = enc[e++];
    std::uint8_t flags = 0;
    unsigned bits = 0;
    constexpr std::size_t kMax = 4096;
    while (e < enc.size() && out.size() < kMax) {
        if (bits == 0) {
            flags = enc[e++];
            bits = 8;
        }
        switch (flags >> 6) {
        case 0:
            if (e >= enc.size()) return out;
            out.push_back(enc[e++]);
            break;
        case 1:
            if (e >= enc.size()) return out;
            out.push_back(std::uint16_t(enc[e++] + (high << 8)));
            break;
        case 2:
            if (e + 1 >= enc.size()) return out;
            out.push_back(std::uint16_t(enc[e] | enc[e + 1] << 8));
            e += 2;
            break;
        default: {
            if (e >= enc.size()) return out;
            unsigned len = enc[e++];
            if (len & 0x80) {
                if (e >= enc.size()) return out;
                const std::uint8_t corr = enc[e++];
                for (len = (len & 0x7f) + 2; len > 0 && out.size() < kMax; --len) {
                    const std::uint8_t a = out.size() < ascii.size() ? ascii[out.size()] : 0;
                    out.push_back(std::uint16_t(((a + corr) & 0xff) + (high << 8)));
                }
            } else {
                for (len += 2; len > 0 && out.size() < kMax; --len)
                    out.push_back(out.size() < ascii.size() ? ascii[out.size()] : 0);
            }
            break;
        }
        }
        flags = std::uint8_t(flags << 2);
        bits -= 2;
    }
    return out;
}

class Walker4 {
public:
    Walker4(const Volumes &vols, Context &ctx, Parsed &out) : vols_(vols), ctx_(ctx), out_(out) {}

    void run()
    {
        for (std::uint32_t v = 0; v < vols_.src.size(); ++v) {
            if (!vols_.src[v]) {
                if (!out_.items.empty() && out_.items.back().split_after) out_.items.back().truncated = true;
                note("volume " + std::to_string(v + 1) + " is missing");
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
                note(e.message());
                return;
            }
            if (!more && v + 1 >= vols_.src.size()) break;
            if (!more && !volume_flag_) break;
        }
        if (!out_.items.empty() && out_.items.back().split_after) {
            out_.items.back().truncated = true;
            note("the last volume is missing");
        }
    }

private:
    void note(const std::string &why)
    {
        if (out_.damage.empty()) out_.damage = why;
    }

    const Keys &header_keys(const std::uint8_t salt[8], int attempt)
    {
        std::string s(reinterpret_cast<const char *>(salt), 8);
        if (attempt == attempt_) {
            auto it = cache_.find(s);
            if (it != cache_.end()) return *it->second;
        } else {
            cache_.clear();
            attempt_ = attempt;
        }
        pw_ = ctx_.password({}, attempt);
        auto k = std::make_unique<Keys>();
        rar3_keys(pw_, salt, *k);
        return *(cache_[s] = std::move(k));
    }

    bool volume(std::uint32_t v)
    {
        const Source &src = *vols_.src[v];
        std::uint64_t pos = v == 0 ? vols_.base0 : 0;
        std::uint8_t sig[7];
        src.read_exact(pos, sig, 7);
        if (std::memcmp(sig, kSig4, 7) != 0) fail(ErrorCode::Corrupt, "volume " + std::to_string(v + 1) + " is not a RAR volume");
        pos += 7;
        encrypted_ = false;
        while (pos + 7 <= src.size()) {
            std::vector<std::uint8_t> h;
            std::uint64_t data_pos = 0;
            bool crc_ok = false;
            if (encrypted_) {
                std::uint8_t salt[8];
                src.read_exact(pos, salt, 8);
                for (int attempt = attempt_ < 1 ? 1 : attempt_;; ++attempt) {
                    const Keys &k = header_keys(salt, attempt);
                    h = read_encrypted(src, pos + 8, k, data_pos);
                    crc_ok = (crc32(0, h.data() + 2, h.size() - 2) & 0xffff) == le16(h.data());
                    if (crc_ok || pw_confirmed_) break;
                    // Wrong password: the first header never checks out.
                    if (!ctx_.callbacks().password)
                        fail(ErrorCode::WrongPassword, "the password is wrong");
                }
                if (crc_ok && !pw_confirmed_) {
                    pw_confirmed_ = true;
                    ctx_.password_ok(pw_);
                }
            } else {
                std::uint8_t base[7];
                src.read_exact(pos, base, 7);
                const std::uint16_t size = le16(base + 5);
                if (size < 7) fail(ErrorCode::Corrupt, "block header is too short");
                if (pos + size > src.size()) fail(ErrorCode::Truncated, "archive ends inside a header");
                h.resize(size);
                src.read_exact(pos, h.data(), size);
                data_pos = pos + size;
                crc_ok = (crc32(0, h.data() + 2, h.size() - 2) & 0xffff) == le16(h.data());
            }
            const std::uint8_t type = h[2];
            const std::uint16_t flags = le16(h.data() + 3);
            std::uint64_t data = 0;
            if ((flags & kLongBlock) && h.size() >= 11) data = le32(h.data() + 7);
            if (type == 0x74 || type == 0x7a) {
                // RAR 1.5-2.x file comments sit inside the header and are not in its CRC.
                if (!crc_ok && !(flags & kOldComment)) note("a file header is damaged");
                if (h.size() >= 36 && (flags & kLarge)) data |= std::uint64_t(le32(h.data() + 32)) << 32;
                file(h, v, data_pos, src.size(), type == 0x7a);
            } else if (type == 0x73) {
                main_seen_ = true;
                volume_flag_ = (flags & kMhdVolume) != 0;
                out_.solid = (flags & kMhdSolid) != 0;
                out_.locked = (flags & kMhdLock) != 0;
                out_.recovery = out_.recovery || (flags & kMhdProtect) != 0;
                if ((flags & kMhdComment) && h.size() > 13) old_comment(std::span<const std::uint8_t>(h).subspan(13));
                if (flags & kMhdPassword) {
                    encrypted_ = true;
                    out_.encrypted_headers = true;
                }
            } else if (type == 0x7b) {
                return (flags & 1) != 0;
            } else {
                if (!crc_ok && type != 0x75) {
                    // An unknown block with a bad CRC: we cannot trust its size.
                    fail(ErrorCode::Corrupt, "block header checksum does not match");
                }
                if (type == 0x77 && h.size() >= 11) data = le32(h.data() + 7);
            }
            pos = data_pos + data;
        }
        return volume_flag_;
    }

    std::vector<std::uint8_t> read_encrypted(const Source &src, std::uint64_t pos, const Keys &k, std::uint64_t &data_pos)
    {
        Aes aes(k.key, Aes::Mode::Cbc, false, k.iv);
        std::vector<std::uint8_t> b(16);
        src.read_exact(pos, b.data(), 16);
        aes.process(b.data(), b.data(), 16);
        const std::size_t size = le16(b.data() + 5);
        if (size < 7) return b; // CRC will fail: wrong password or damage
        const std::size_t padded = (size + 15) & ~std::size_t(15);
        if (pos + padded > src.size()) {
            if (!pw_confirmed_) return b; // most likely a wrong password: let the CRC say so
            fail(ErrorCode::Truncated, "archive ends inside a header");
        }
        b.resize(padded);
        src.read_exact(pos + 16, b.data() + 16, padded - 16);
        aes.process(b.data() + 16, b.data() + 16, padded - 16);
        b.resize(size);
        data_pos = pos + padded;
        return b;
    }

    // RAR 1.5-2.x comment block inside the main header.
    void old_comment(std::span<const std::uint8_t> c)
    {
        if (c.size() < 13 || c[2] != 0x75) return;
        const std::uint16_t unp = le16(c.data() + 7);
        const std::uint8_t ver = c[9], method = c[10];
        Item it;
        it.entry.path = "CMT";
        it.entry.size = unp;
        it.stored = method == 0x30;
        it.version = ver <= 15 ? 15 : ver <= 26 ? 20 : 29;
        it.dict = 0x10000;
        out_.comment_item = it;
        out_.comment_bytes.assign(c.begin() + 13, c.end());
    }

    void file(const std::vector<std::uint8_t> &h, std::uint32_t v, std::uint64_t data_pos, std::uint64_t vol_size, bool sub)
    {
        if (h.size() < 32) fail(ErrorCode::Corrupt, "file header is too short");
        ByteReader r(h);
        r.seek(3);
        const std::uint16_t flags = r.u16();
        r.u16();
        std::uint64_t pack = r.u32();
        std::uint64_t unp = r.u32();
        const std::uint8_t host = r.u8();
        const std::uint32_t crc = r.u32();
        const std::uint32_t ftime = r.u32();
        const std::uint8_t ver = r.u8();
        const std::uint8_t method = r.u8();
        const std::uint16_t nsize = r.u16();
        const std::uint32_t attr = r.u32();
        bool unknown = false;
        if (flags & kLarge) {
            pack |= std::uint64_t(r.u32()) << 32;
            const std::uint32_t hi = r.u32();
            unknown = unp == 0xffffffff && hi == 0xffffffff;
            unp |= std::uint64_t(hi) << 32;
        } else {
            unknown = unp == 0xffffffff;
        }
        auto name = r.bytes(nsize);
        Item it;
        if (flags & kSalt) {
            auto s = r.bytes(8);
            std::copy(s.begin(), s.end(), it.crypt.salt.begin());
            it.crypt.has_salt = true;
        }
        it.entry.mtime = dos_time(ftime);
        if ((flags & kExtTime) && r.left() >= 2) ext_time(r, it);

        // Name: UTF-8 when the Unicode flag is set without a NUL, the
        // packed UTF-16 form after the NUL otherwise.
        std::string path;
        if (flags & kUnicode) {
            std::size_t z = 0;
            while (z < name.size() && name[z]) ++z;
            if (z == name.size()) path.assign(reinterpret_cast<const char *>(name.data()), name.size());
            else path = utf16_to_utf8(decode_unicode(name.first(z), name.subspan(z + 1)));
        } else {
            path = legacy_name(std::string_view(reinterpret_cast<const char *>(name.data()), name.size()));
        }
        if (host <= 2)
            for (char &c : path)
                if (c == '\\') c = '/';
        it.entry.path = path;
        it.entry.size = unp;
        it.size_known = !unknown;
        it.entry.size_known = !unknown;
        it.entry.packed_size = pack;
        it.stored = method == 0x30;
        it.version = ver < 15 ? 15 : ver <= 15 ? 15 : ver <= 26 ? 20 : ver <= 36 ? 29 : 0;
        if (ver < 13 && !it.stored) it.version = 0;
        const unsigned dbits = (flags >> 5) & 7;
        it.dict = 0x10000ull << (dbits == 7 ? 0 : dbits);
        it.solid = (flags & kSolid) != 0;
        it.entry.solid = it.solid && !it.stored;
        it.entry.method = it.stored ? "Store" : it.version == 29 ? "RAR3" : it.version == 20 ? "RAR2" : it.version == 15 ? "RAR1.5" : "RAR v" + std::to_string(ver);
        it.has_crc = true;
        it.crc = crc;
        if (flags & kPassword) {
            it.entry.encrypted = true;
            it.crypt.kind = ver >= 29 ? Crypt::Rar3 : ver >= 20 ? Crypt::Rar20 : Crypt::Rar15;
        }
        if (dbits == 7) it.entry.type = EntryType::Directory;
        if (host == 3) {
            it.entry.mode = attr & 07777;
            const std::uint32_t kind = attr & 0170000;
            if (kind == 0040000) it.entry.type = EntryType::Directory;
            else if (kind == 0120000) it.entry.type = EntryType::Symlink;
        } else {
            it.entry.windows_attributes = attr;
            if (attr & 0x10) it.entry.type = EntryType::Directory;
        }
        if (it.entry.type == EntryType::Directory) it.entry.size = 0;
        it.split_after = (flags & kSplitAfter) != 0;
        const std::uint64_t avail = data_pos < vol_size ? vol_size - data_pos : 0;
        if (pack || it.entry.type != EntryType::Directory) it.parts.push_back(Part{v, data_pos, std::min(pack, avail)});
        if (pack > avail) {
            it.truncated = true;
            note("data of " + path + " is cut short");
        }
        if ((flags & kVersion) && !sub) return; // older version: hidden, as RAR does without -ver
        if (sub) {
            if (path == "CMT" && it.crypt.kind == Crypt::None && !out_.comment_item) out_.comment_item = it;
            return;
        }
        if (flags & kSplitBefore) {
            if (!out_.items.empty() && out_.items.back().split_after && out_.items.back().entry.path == path) {
                Item &prev = out_.items.back();
                prev.parts.insert(prev.parts.end(), it.parts.begin(), it.parts.end());
                prev.split_after = it.split_after;
                prev.truncated = prev.truncated || it.truncated;
                prev.entry.packed_size += pack;
                prev.crc = it.crc;
                prev.has_crc = !it.split_after;
                prev.entry.crc32 = prev.has_crc ? std::optional<std::uint32_t>(prev.crc) : std::nullopt;
                return;
            }
            it.truncated = true;
            note(path + " starts in an earlier volume");
        }
        if (it.split_after) it.has_crc = false;
        it.entry.index = out_.items.size();
        it.entry.volume = v;
        if (it.has_crc) it.entry.crc32 = it.crc;
        out_.items.push_back(std::move(it));
    }

    static void ext_time(ByteReader &r, Item &it)
    {
        const std::uint16_t f = r.u16();
        std::optional<Timestamp> *slots[4] = {&it.entry.mtime, &it.entry.ctime, &it.entry.atime, nullptr};
        for (int i = 0; i < 4; ++i) {
            const unsigned mode = f >> ((3 - i) * 4);
            if (!(mode & 8)) continue;
            Timestamp t = it.entry.mtime.value_or(Timestamp{});
            if (i != 0) t = dos_time(r.u32());
            if (mode & 4) ++t.seconds;
            const unsigned count = mode & 3;
            std::uint32_t rem = 0;
            for (unsigned j = 0; j < count; ++j) rem |= std::uint32_t(r.u8()) << ((j + 3 - count) * 8);
            t.nanoseconds = (rem % 10000000u) * 100;
            if (slots[i]) *slots[i] = t;
        }
    }

    const Volumes &vols_;
    Context &ctx_;
    Parsed &out_;
    bool encrypted_ = false, main_seen_ = false, volume_flag_ = false, pw_confirmed_ = false;
    int attempt_ = 0;
    std::string pw_;
    std::map<std::string, std::unique_ptr<Keys>> cache_;
};

} // namespace

Parsed parse_rar4(const Volumes &vols, Context &ctx)
{
    Parsed p;
    p.version = 4;
    Walker4 w(vols, ctx, p);
    w.run();
    return p;
}

} // namespace raye::archive::detail::rar
