// SPDX-License-Identifier: GPL-3.0-or-later
#include "codec.h"

#include "bytes.h"
#include "context.h"

#include <raye/archive/error.h>

#include <algorithm>
#include <brotli/decode.h>
#include <brotli/encode.h>
#include <bzlib.h>
#include <lz4frame.h>
#include <lzma.h>
#include <zlib.h>
#include <zstd.h>

namespace raye::archive::detail {

namespace {

[[noreturn]] void bad(const char *what) { fail(ErrorCode::Corrupt, std::string("compressed data is damaged (") + what + ")"); }

int clamp_level(int l, int lo, int hi) { return std::clamp(l, lo, hi); }

// ---- zlib family
class ZlibCoder final : public Coder {
public:
    ZlibCoder(Codec c, bool enc, const CodecParams &p) : enc_(enc), gzip_(c == Codec::Gzip)
    {
        const int bits = c == Codec::Deflate ? -15 : c == Codec::Gzip ? 15 + 16 : 15;
        const int r = enc ? deflateInit2(&z_, clamp_level(p.level, 0, 9), Z_DEFLATED, bits, 9, Z_DEFAULT_STRATEGY)
                          : inflateInit2(&z_, bits);
        if (r != Z_OK) fail(ErrorCode::Internal, "zlib init failed");
    }
    ~ZlibCoder() override { enc_ ? deflateEnd(&z_) : inflateEnd(&z_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        CodeStep s;
        if (done_) return {0, 0, true};
        z_.next_in = const_cast<Bytef *>(in.data());
        z_.avail_in = uInt(std::min<std::size_t>(in.size(), 1u << 30));
        z_.next_out = out.data();
        z_.avail_out = uInt(std::min<std::size_t>(out.size(), 1u << 30));
        const uInt ai = z_.avail_in, ao = z_.avail_out;
        int r = enc_ ? deflate(&z_, finish ? Z_FINISH : Z_NO_FLUSH) : inflate(&z_, Z_NO_FLUSH);
        s.consumed = ai - z_.avail_in;
        s.produced = ao - z_.avail_out;
        if (r == Z_STREAM_END) {
            // gzip files may hold several members back to back.
            if (!enc_ && gzip_ && s.consumed < in.size()) {
                inflateReset(&z_);
                return s;
            }
            done_ = true;
            s.done = true;
        } else if (r == Z_BUF_ERROR) {
            if (!enc_ && finish && s.consumed == 0 && s.produced == 0 && in.size() == z_.avail_in && out.size())
                fail(ErrorCode::Truncated, "compressed data ends early");
        } else if (r != Z_OK) {
            bad("deflate");
        }
        return s;
    }

private:
    z_stream z_{};
    bool enc_, gzip_, done_ = false;
};

// ---- bzip2
class Bz2Coder final : public Coder {
public:
    Bz2Coder(bool enc, const CodecParams &p) : enc_(enc)
    {
        const int r = enc ? BZ2_bzCompressInit(&b_, clamp_level(p.level, 1, 9), 0, 0) : BZ2_bzDecompressInit(&b_, 0, 0);
        if (r != BZ_OK) fail(ErrorCode::Internal, "bzip2 init failed");
    }
    ~Bz2Coder() override { enc_ ? BZ2_bzCompressEnd(&b_) : BZ2_bzDecompressEnd(&b_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        if (done_) return {0, 0, true};
        b_.next_in = reinterpret_cast<char *>(const_cast<std::uint8_t *>(in.data()));
        b_.avail_in = unsigned(std::min<std::size_t>(in.size(), 1u << 30));
        b_.next_out = reinterpret_cast<char *>(out.data());
        b_.avail_out = unsigned(std::min<std::size_t>(out.size(), 1u << 30));
        const unsigned ai = b_.avail_in, ao = b_.avail_out;
        int r = enc_ ? BZ2_bzCompress(&b_, finish ? BZ_FINISH : BZ_RUN) : BZ2_bzDecompress(&b_);
        CodeStep s{ai - b_.avail_in, ao - b_.avail_out, false};
        if (r == BZ_STREAM_END) {
            if (!enc_ && s.consumed < in.size()) { // concatenated streams (pbzip2)
                BZ2_bzDecompressEnd(&b_);
                b_ = {};
                BZ2_bzDecompressInit(&b_, 0, 0);
                return s;
            }
            done_ = s.done = true;
        } else if (r < 0) {
            bad("bzip2");
        }
        return s;
    }

private:
    bz_stream b_{};
    bool enc_, done_ = false;
};

// ---- liblzma
std::uint32_t lzma_preset(int level) { return std::uint32_t(clamp_level(level, 0, 9)); }

class LzmaCoder final : public Coder {
public:
    LzmaCoder(Codec c, bool enc, CodecParams &p)
    {
        lzma_ret r = LZMA_OK;
        if (c == Codec::Xz || c == Codec::LzmaAlone) {
            if (!enc) {
                r = c == Codec::Xz ? lzma_stream_decoder(&s_, UINT64_MAX, LZMA_CONCATENATED)
                                   : lzma_alone_decoder(&s_, UINT64_MAX);
            } else if (c == Codec::Xz && p.threads > 1) {
                lzma_mt mt{};
                mt.threads = std::uint32_t(p.threads);
                mt.preset = lzma_preset(p.level);
                mt.check = LZMA_CHECK_CRC64;
                if (p.dictionary) {
                    lzma_lzma_preset(&opt_, mt.preset);
                    opt_.dict_size = std::uint32_t(p.dictionary);
                    filters_[0] = {LZMA_FILTER_LZMA2, &opt_};
                    filters_[1] = {LZMA_VLI_UNKNOWN, nullptr};
                    mt.filters = filters_;
                }
                r = lzma_stream_encoder_mt(&s_, &mt);
            } else {
                setup_opts(p);
                filters_[0] = {c == Codec::Xz ? LZMA_FILTER_LZMA2 : LZMA_FILTER_LZMA1, &opt_};
                filters_[1] = {LZMA_VLI_UNKNOWN, nullptr};
                r = c == Codec::Xz ? lzma_stream_encoder(&s_, filters_, LZMA_CHECK_CRC64) : lzma_alone_encoder(&s_, &opt_);
            }
        } else { // raw
            const lzma_vli id = c == Codec::Lzma1Raw ? LZMA_FILTER_LZMA1 : LZMA_FILTER_LZMA2;
            filters_[0].id = id;
            filters_[1] = {LZMA_VLI_UNKNOWN, nullptr};
            if (!enc) {
                if (lzma_properties_decode(&filters_[0], nullptr, p.props.data(), p.props.size()) != LZMA_OK)
                    fail(ErrorCode::Corrupt, "bad LZMA properties");
                props_owned_ = filters_[0].options;
                r = lzma_raw_decoder(&s_, filters_);
            } else {
                setup_opts(p);
                filters_[0].options = &opt_;
                std::uint32_t sz = 0;
                lzma_properties_size(&sz, &filters_[0]);
                p.props.resize(sz);
                lzma_properties_encode(&filters_[0], p.props.data());
                r = lzma_raw_encoder(&s_, filters_);
            }
        }
        if (r == LZMA_MEM_ERROR) fail(ErrorCode::Internal, "not enough memory for LZMA");
        if (r == LZMA_OPTIONS_ERROR) fail(ErrorCode::UnsupportedMethod, "unsupported LZMA settings");
        if (r != LZMA_OK) fail(ErrorCode::Internal, "liblzma init failed");
    }
    ~LzmaCoder() override
    {
        lzma_end(&s_);
        free(props_owned_);
    }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        if (done_) return {0, 0, true};
        s_.next_in = in.data();
        s_.avail_in = in.size();
        s_.next_out = out.data();
        s_.avail_out = out.size();
        lzma_ret r = lzma_code(&s_, finish ? LZMA_FINISH : LZMA_RUN);
        CodeStep st{in.size() - s_.avail_in, out.size() - s_.avail_out, false};
        if (r == LZMA_STREAM_END) done_ = st.done = true;
        else if (r == LZMA_BUF_ERROR) fail(ErrorCode::Truncated, "compressed data ends early");
        else if (r == LZMA_MEMLIMIT_ERROR || r == LZMA_MEM_ERROR) fail(ErrorCode::Internal, "not enough memory for LZMA");
        else if (r == LZMA_OPTIONS_ERROR) fail(ErrorCode::UnsupportedMethod, "unsupported LZMA settings");
        else if (r != LZMA_OK) bad("lzma");
        return st;
    }

private:
    void setup_opts(const CodecParams &p)
    {
        lzma_lzma_preset(&opt_, lzma_preset(p.level));
        if (p.dictionary) opt_.dict_size = std::uint32_t(std::min<std::uint64_t>(p.dictionary, 1536u << 20));
        if (p.word_size) opt_.nice_len = std::uint32_t(std::clamp(p.word_size, 8, 273));
    }
    lzma_stream s_ = LZMA_STREAM_INIT;
    lzma_options_lzma opt_{};
    lzma_filter filters_[2]{};
    void *props_owned_ = nullptr;
    bool done_ = false;
};

// ---- zstd
class ZstdDec final : public Coder {
public:
    ZstdDec() : d_(ZSTD_createDStream())
    {
        if (!d_) fail(ErrorCode::Internal, "zstd init failed");
        ZSTD_DCtx_setParameter(d_, ZSTD_d_windowLogMax, 31);
    }
    ~ZstdDec() override { ZSTD_freeDStream(d_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        ZSTD_inBuffer ib{in.data(), in.size(), 0};
        ZSTD_outBuffer ob{out.data(), out.size(), 0};
        size_t r = ZSTD_decompressStream(d_, &ob, &ib);
        if (ZSTD_isError(r)) bad("zstd");
        CodeStep s{ib.pos, ob.pos, false};
        // r == 0: a frame ended. More frames may follow; done only at input end.
        if (r == 0 && finish && ib.pos == in.size()) s.done = true;
        if (r != 0 && finish && ib.pos == in.size() && ob.pos < out.size() && s.produced == 0)
            fail(ErrorCode::Truncated, "compressed data ends early");
        return s;
    }

private:
    ZSTD_DStream *d_;
};

class ZstdEnc final : public Coder {
public:
    explicit ZstdEnc(const CodecParams &p) : c_(ZSTD_createCCtx())
    {
        if (!c_) fail(ErrorCode::Internal, "zstd init failed");
        // 0..9 maps onto 1..19; 22 is only reachable with an explicit dictionary/word size.
        static const int map[] = {1, 1, 2, 3, 5, 8, 11, 14, 17, 19};
        ZSTD_CCtx_setParameter(c_, ZSTD_c_compressionLevel, map[clamp_level(p.level, 0, 9)]);
        if (p.threads > 1) ZSTD_CCtx_setParameter(c_, ZSTD_c_nbWorkers, p.threads);
        if (p.dictionary) {
            int log = 10;
            while (log < 31 && (1ull << log) < p.dictionary) ++log;
            ZSTD_CCtx_setParameter(c_, ZSTD_c_windowLog, log);
            ZSTD_CCtx_setParameter(c_, ZSTD_c_enableLongDistanceMatching, log > 27);
        }
        ZSTD_CCtx_setParameter(c_, ZSTD_c_checksumFlag, 1);
        if (p.expected_size) ZSTD_CCtx_setPledgedSrcSize(c_, p.expected_size);
    }
    ~ZstdEnc() override { ZSTD_freeCCtx(c_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        ZSTD_inBuffer ib{in.data(), in.size(), 0};
        ZSTD_outBuffer ob{out.data(), out.size(), 0};
        size_t r = ZSTD_compressStream2(c_, &ob, &ib, finish ? ZSTD_e_end : ZSTD_e_continue);
        if (ZSTD_isError(r)) fail(ErrorCode::Internal, ZSTD_getErrorName(r));
        return {ib.pos, ob.pos, finish && r == 0};
    }

private:
    ZSTD_CCtx *c_;
};

// ---- lz4 frame
class Lz4Dec final : public Coder {
public:
    Lz4Dec()
    {
        if (LZ4F_isError(LZ4F_createDecompressionContext(&d_, LZ4F_VERSION))) fail(ErrorCode::Internal, "lz4 init failed");
    }
    ~Lz4Dec() override { LZ4F_freeDecompressionContext(d_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        size_t ol = out.size(), il = in.size();
        size_t r = LZ4F_decompress(d_, out.data(), &ol, in.data(), &il, nullptr);
        if (LZ4F_isError(r)) bad("lz4");
        CodeStep s{il, ol, false};
        if (r == 0 && finish && il == in.size()) s.done = true;
        return s;
    }

private:
    LZ4F_dctx *d_ = nullptr;
};

class Lz4Enc final : public Coder {
public:
    explicit Lz4Enc(const CodecParams &p)
    {
        if (LZ4F_isError(LZ4F_createCompressionContext(&c_, LZ4F_VERSION))) fail(ErrorCode::Internal, "lz4 init failed");
        prefs_.compressionLevel = p.level <= 2 ? 0 : p.level * 12 / 9;
        prefs_.frameInfo.contentChecksumFlag = LZ4F_contentChecksumEnabled;
        prefs_.frameInfo.blockSizeID = LZ4F_max4MB;
    }
    ~Lz4Enc() override { LZ4F_freeCompressionContext(c_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        // LZ4F writes whole blocks: stage them in hdr_ and drain into out.
        CodeStep s;
        if (!started_) {
            hdr_.resize(LZ4F_HEADER_SIZE_MAX);
            size_t n = LZ4F_compressBegin(c_, hdr_.data(), hdr_.size(), &prefs_);
            if (LZ4F_isError(n)) fail(ErrorCode::Internal, "lz4 begin");
            hdr_.resize(n);
            started_ = true;
        }
        if (!hdr_.empty()) return drain(out, s);
        std::size_t chunk = std::min<std::size_t>(in.size(), 1 << 20);
        if (chunk) {
            hdr_.resize(LZ4F_compressBound(chunk, &prefs_));
            size_t n = LZ4F_compressUpdate(c_, hdr_.data(), hdr_.size(), in.data(), chunk, nullptr);
            if (LZ4F_isError(n)) fail(ErrorCode::Internal, "lz4 update");
            hdr_.resize(n);
            s.consumed = chunk;
            return drain(out, s);
        }
        if (finish && !ended_) {
            hdr_.resize(LZ4F_compressBound(0, &prefs_));
            size_t n = LZ4F_compressEnd(c_, hdr_.data(), hdr_.size(), nullptr);
            if (LZ4F_isError(n)) fail(ErrorCode::Internal, "lz4 end");
            hdr_.resize(n);
            ended_ = true;
            return drain(out, s);
        }
        s.done = ended_ && hdr_.empty();
        return s;
    }

private:
    CodeStep drain(std::span<std::uint8_t> out, CodeStep s)
    {
        std::size_t n = std::min(out.size(), hdr_.size() - hdr_off_);
        std::copy_n(hdr_.data() + hdr_off_, n, out.data());
        hdr_off_ += n;
        s.produced = n;
        if (hdr_off_ == hdr_.size()) { hdr_.clear(); hdr_off_ = 0; s.done = ended_; }
        return s;
    }
    LZ4F_cctx *c_ = nullptr;
    LZ4F_preferences_t prefs_{};
    std::vector<std::uint8_t> hdr_;
    std::size_t hdr_off_ = 0;
    bool started_ = false, ended_ = false;
};

// ---- brotli
class BrotliDec final : public Coder {
public:
    BrotliDec() : d_(BrotliDecoderCreateInstance(nullptr, nullptr, nullptr))
    {
        if (!d_) fail(ErrorCode::Internal, "brotli init failed");
        BrotliDecoderSetParameter(d_, BROTLI_DECODER_PARAM_LARGE_WINDOW, 1);
    }
    ~BrotliDec() override { BrotliDecoderDestroyInstance(d_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        size_t ai = in.size(), ao = out.size();
        const std::uint8_t *ni = in.data();
        std::uint8_t *no = out.data();
        auto r = BrotliDecoderDecompressStream(d_, &ai, &ni, &ao, &no, nullptr);
        CodeStep s{in.size() - ai, out.size() - ao, r == BROTLI_DECODER_RESULT_SUCCESS};
        if (r == BROTLI_DECODER_RESULT_ERROR) bad("brotli");
        if (r == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT && finish && ai == 0 && s.produced == 0)
            fail(ErrorCode::Truncated, "compressed data ends early");
        return s;
    }

private:
    BrotliDecoderState *d_;
};

class BrotliEnc final : public Coder {
public:
    explicit BrotliEnc(const CodecParams &p) : e_(BrotliEncoderCreateInstance(nullptr, nullptr, nullptr))
    {
        if (!e_) fail(ErrorCode::Internal, "brotli init failed");
        BrotliEncoderSetParameter(e_, BROTLI_PARAM_QUALITY, std::uint32_t(clamp_level(p.level, 0, 9) * 11 / 9));
        if (p.dictionary) {
            int log = 10;
            while (log < 24 && (1ull << log) < p.dictionary) ++log;
            BrotliEncoderSetParameter(e_, BROTLI_PARAM_LGWIN, std::uint32_t(log));
        }
    }
    ~BrotliEnc() override { BrotliEncoderDestroyInstance(e_); }
    CodeStep step(std::span<const std::uint8_t> in, std::span<std::uint8_t> out, bool finish) override
    {
        size_t ai = in.size(), ao = out.size();
        const std::uint8_t *ni = in.data();
        std::uint8_t *no = out.data();
        if (!BrotliEncoderCompressStream(e_, finish ? BROTLI_OPERATION_FINISH : BROTLI_OPERATION_PROCESS, &ai, &ni, &ao,
                                         &no, nullptr))
            fail(ErrorCode::Internal, "brotli encode");
        return {in.size() - ai, out.size() - ao, bool(BrotliEncoderIsFinished(e_))};
    }

private:
    BrotliEncoderState *e_;
};

} // namespace

std::unique_ptr<Coder> make_decoder(Codec c, const CodecParams &p)
{
    CodecParams copy = p;
    switch (c) {
    case Codec::Deflate:
    case Codec::Zlib:
    case Codec::Gzip: return std::make_unique<ZlibCoder>(c, false, p);
    case Codec::Bzip2: return std::make_unique<Bz2Coder>(false, p);
    case Codec::Xz:
    case Codec::LzmaAlone:
    case Codec::Lzma1Raw:
    case Codec::Lzma2Raw: return std::make_unique<LzmaCoder>(c, false, copy);
    case Codec::Zstd: return std::make_unique<ZstdDec>();
    case Codec::Lz4Frame: return std::make_unique<Lz4Dec>();
    case Codec::Brotli: return std::make_unique<BrotliDec>();
    }
    fail(ErrorCode::UnsupportedMethod, "unknown codec");
}

std::unique_ptr<Coder> make_encoder(Codec c, CodecParams &p)
{
    switch (c) {
    case Codec::Deflate:
    case Codec::Zlib:
    case Codec::Gzip: return std::make_unique<ZlibCoder>(c, true, p);
    case Codec::Bzip2: return std::make_unique<Bz2Coder>(true, p);
    case Codec::Xz:
    case Codec::LzmaAlone:
    case Codec::Lzma1Raw:
    case Codec::Lzma2Raw: return std::make_unique<LzmaCoder>(c, true, p);
    case Codec::Zstd: return std::make_unique<ZstdEnc>(p);
    case Codec::Lz4Frame: return std::make_unique<Lz4Enc>(p);
    case Codec::Brotli: return std::make_unique<BrotliEnc>(p);
    }
    fail(ErrorCode::UnsupportedMethod, "unknown codec");
}

std::uint64_t decode_all(Coder &dec, SourceReader &in, std::uint64_t packed, Sink &out, Context *ctx, std::uint64_t max_out)
{
    std::vector<std::uint8_t> obuf(1 << 18);
    std::uint64_t left = packed, written = 0;
    for (;;) {
        if (ctx) ctx->checkpoint();
        auto view = in.peek();
        std::size_t avail = std::size_t(std::min<std::uint64_t>(view.size(), left));
        const bool finish = avail == left;
        auto s = dec.step(view.first(avail), obuf, finish);
        in.consume(s.consumed);
        left -= s.consumed;
        if (s.produced) {
            written += s.produced;
            if (written > max_out) fail(ErrorCode::Corrupt, "entry is bigger than its header says");
            out.write(obuf.data(), s.produced);
            if (ctx) ctx->add_bytes(s.produced);
        }
        if (s.done) return written;
        if (s.consumed == 0 && s.produced == 0) {
            if (finish) fail(ErrorCode::Truncated, "compressed data ends early");
            if (view.empty()) fail(ErrorCode::Truncated, "unexpected end of archive");
        }
    }
}

std::vector<std::uint8_t> decode_buffer(Codec c, std::span<const std::uint8_t> in, std::size_t max_out, const CodecParams &p)
{
    auto dec = make_decoder(c, p);
    std::vector<std::uint8_t> out;
    std::vector<std::uint8_t> buf(1 << 16);
    std::size_t pos = 0;
    for (;;) {
        auto s = dec->step(in.subspan(pos), buf, true);
        pos += s.consumed;
        out.insert(out.end(), buf.data(), buf.data() + s.produced);
        if (out.size() > max_out) fail(ErrorCode::Bomb, "decoded data is bigger than allowed");
        if (s.done) return out;
        if (s.consumed == 0 && s.produced == 0) fail(ErrorCode::Truncated, "compressed data ends early");
    }
}

std::vector<std::uint8_t> encode_buffer(Codec c, std::span<const std::uint8_t> in, CodecParams &p)
{
    auto enc = make_encoder(c, p);
    std::vector<std::uint8_t> out, buf(1 << 16);
    std::size_t pos = 0;
    for (;;) {
        auto s = enc->step(in.subspan(pos), buf, true);
        pos += s.consumed;
        out.insert(out.end(), buf.data(), buf.data() + s.produced);
        if (s.done) return out;
    }
}

} // namespace raye::archive::detail
