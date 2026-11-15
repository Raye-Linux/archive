// SPDX-License-Identifier: GPL-3.0-or-later
// Branch converters (BCJ and friends) and the delta filter. They turn
// relative jump targets into absolute ones before compression, which makes
// executables compress better. The same code runs both ways.
// ZIP and RAR may include this file.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace raye::archive::detail::filters {

enum class Kind { X86, Arm, Armt, Arm64, Ppc, Sparc, Ia64, RiscV, Delta };

class Filter {
public:
    virtual ~Filter() = default;
    // Converts buf in place and returns how many bytes are final. The rest
    // must be given again with more data after it, or, at the end of the
    // stream, left as it is.
    virtual std::size_t run(std::uint8_t *buf, std::size_t n) = 0;
};

// start: address of the first byte (7z: 0, or the 4-byte property).
// delta_distance: 1..256, only for Kind::Delta.
std::unique_ptr<Filter> make_filter(Kind k, bool encode, std::uint32_t start = 0, unsigned delta_distance = 1);

// x86 BCJ2: splits calls and jumps into separate streams (encoder) and puts
// them back (decoder). 7z uses it with four streams.
class Bcj2Decoder {
public:
    // Supplies the next bytes of stream i (0 main, 1 call, 2 jump, 3 range
    // coder); returns 0 at the end.
    using Pull = std::size_t (*)(void *ctx, int stream, std::uint8_t *buf, std::size_t n);
    Bcj2Decoder(Pull pull, void *ctx, std::uint64_t out_size);
    // Fills up to n bytes, returns 0 when out_size is reached.
    std::size_t read(std::uint8_t *out, std::size_t n);

private:
    int byte(int stream);
    bool bit(std::uint16_t &prob);
    Pull pull_;
    void *ctx_;
    std::uint64_t left_, pos_ = 0;
    std::uint8_t buf_[4][1 << 14];
    std::size_t have_[4] = {}, at_[4] = {};
    std::uint32_t range_ = 0xFFFFFFFF, code_ = 0;
    bool rc_started_ = false;
    std::uint16_t probs_[258];
    std::uint8_t prev_ = 0;
    std::uint8_t pending_[4];
    int npending_ = 0, ipending_ = 0;
};

class Bcj2Encoder {
public:
    // size: total input size; calls whose target lands inside it are split out.
    explicit Bcj2Encoder(std::uint64_t size);
    // Feed the whole input in order; end with finish().
    void write(const std::uint8_t *data, std::size_t n);
    void finish();
    std::vector<std::uint8_t> main, call, jump, rc;

private:
    void encode_bit(std::uint16_t &prob, int bit);
    void shift_low();
    void process(bool last);
    std::uint64_t size_;
    std::vector<std::uint8_t> pend_;
    std::uint64_t pos_ = 0; // stream position of pend_[0]
    std::uint8_t prev_ = 0;
    std::uint16_t probs_[258];
    std::uint64_t low_ = 0;
    std::uint32_t range_ = 0xFFFFFFFF;
    std::uint8_t cache_ = 0;
    std::uint64_t cache_size_ = 1;
};

} // namespace raye::archive::detail::filters
