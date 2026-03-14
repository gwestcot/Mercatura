#include <pow/scratchpad_pow.h>

#include <crypto/common.h>
#include <crypto/sha3.h>
#include <hash.h>
#include <primitives/block.h>
#include <primitives/blockhash.h>
#include <serialize.h>
#include <span.h>
#include <streams.h>
#include <uint256.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

namespace MCA::PoW {
namespace {

using Line = std::array<uint8_t, LINE_SIZE>;

static_assert(SCRATCHPAD_BYTES == 536870912ull, "Scratchpad must be 512 MiB");
static_assert(LINE_SIZE == 64, "Line size must be 64 bytes");
static_assert(NUM_LINES == 8388608ull, "Unexpected line count");
static_assert(NUM_STEPS == 8388608ull, "Unexpected step count");

std::array<uint8_t, 32> SerializeHeaderForPoW(const CBlockHeader &header) {
    DataStream ss{};
    ss << header;
    std::array<uint8_t, 32> out{};

    const uint8_t *ptr =
        reinterpret_cast<const uint8_t *>(ss.data());

    SHA3_256{}
        .Write(Span<const uint8_t>(ptr, ss.size()))
        .Finalize(Span<uint8_t>(out.data(), out.size()));

    return out;
}

std::array<uint8_t, 32> SHA3_256_Once(const uint8_t *data, size_t len) {
    std::array<uint8_t, 32> out{};
    SHA3_256{}
        .Write(Span<const uint8_t>(data, len))
        .Finalize(Span<uint8_t>(out.data(), out.size()));
    return out;
}

Line ExpandLine(const std::array<uint8_t, 32> &seed, uint32_t index) {
    uint8_t buf[36];
    std::memcpy(buf, seed.data(), 32);
    buf[32] = uint8_t(index);
    buf[33] = uint8_t(index >> 8);
    buf[34] = uint8_t(index >> 16);
    buf[35] = uint8_t(index >> 24);

    const auto h0 = SHA3_256_Once(buf, sizeof(buf));

    buf[32] ^= 0xA5;
    buf[33] ^= 0x5A;
    buf[34] ^= 0x3C;
    buf[35] ^= 0xC3;

    const auto h1 = SHA3_256_Once(buf, sizeof(buf));

    Line line{};
    std::memcpy(line.data(), h0.data(), 32);
    std::memcpy(line.data() + 32, h1.data(), 32);
    return line;
}

uint32_t SelectLine(const Line &line, uint64_t state) {
    const uint64_t lane0 = ReadLE64(&line[0]);
    const uint64_t lane1 = ReadLE64(&line[8]);
    const uint64_t lane2 = ReadLE64(&line[16]);
    const uint64_t lane3 = ReadLE64(&line[24]);
    const uint64_t mixed = lane0 ^ lane1 ^ lane2 ^ lane3 ^ state;
    return uint32_t(mixed & (NUM_LINES - 1));
}

void MixLine(Line &state_line, const Line &scratch_line, uint64_t step) {
    for (size_t i = 0; i < LINE_SIZE; i += 8) {
        const uint64_t a = ReadLE64(state_line.data() + i);
        const uint64_t b = ReadLE64(scratch_line.data() + i);
        const uint64_t mixed = (a ^ b) + (step + i);
        WriteLE64(state_line.data() + i,
                  (mixed << 17) | (mixed >> (64 - 17)));
    }
}

std::array<uint8_t, 32> FinalizeState(const std::array<uint8_t, 32> &header_hash,
                                      const Line &state_line) {
    uint8_t buf[32 + LINE_SIZE];
    std::memcpy(buf, header_hash.data(), 32);
    std::memcpy(buf + 32, state_line.data(), LINE_SIZE);

    const auto h1 = SHA3_256_Once(buf, sizeof(buf));
    return SHA3_256_Once(h1.data(), h1.size());
}

} // namespace

Q64x64 MulQ64x64(uint64_t a, uint64_t b) {
#if defined(__SIZEOF_INT128__)
    __uint128_t product = (__uint128_t)a * (__uint128_t)b;
    return Q64x64{
        .hi = uint64_t(product >> 64),
        .lo = uint64_t(product),
    };
#else
    const uint64_t a_lo = uint32_t(a);
    const uint64_t a_hi = a >> 32;
    const uint64_t b_lo = uint32_t(b);
    const uint64_t b_hi = b >> 32;

    const uint64_t p0 = a_lo * b_lo;
    const uint64_t p1 = a_lo * b_hi;
    const uint64_t p2 = a_hi * b_lo;
    const uint64_t p3 = a_hi * b_hi;

    uint64_t mid = (p0 >> 32) + uint32_t(p1) + uint32_t(p2);
    uint64_t hi = p3 + (p1 >> 32) + (p2 >> 32) + (mid >> 32);
    uint64_t lo = (mid << 32) | uint32_t(p0);

    return Q64x64{.hi = hi, .lo = lo};
#endif
}

uint64_t IsqrtU256(uint64_t x3, uint64_t x2, uint64_t x1, uint64_t x0) {
#if defined(__SIZEOF_INT128__)
    (void)x3;
    (void)x2;
    __uint128_t value = ((__uint128_t)x1 << 64) | x0;
    uint64_t bit = uint64_t(1) << 62;
    uint64_t result = 0;
    uint64_t n = uint64_t(value > UINT64_MAX ? UINT64_MAX : value);

    while (bit > n) {
        bit >>= 2;
    }

    while (bit != 0) {
        if (n >= result + bit) {
            n -= result + bit;
            result = (result >> 1) + bit;
        } else {
            result >>= 1;
        }
        bit >>= 2;
    }

    return result;
#else
    (void)x3;
    (void)x2;
    (void)x1;
    return static_cast<uint64_t>(std::sqrt(static_cast<long double>(x0)));
#endif
}

} // namespace MCA::PoW

BlockHash ComputeScratchpadPoWHash(const CBlockHeader &header) {
    using namespace MCA::PoW;

    const auto header_hash = SerializeHeaderForPoW(header);

    std::vector<Line> scratchpad;
    scratchpad.reserve(NUM_LINES);
    for (uint32_t i = 0; i < NUM_LINES; ++i) {
        scratchpad.push_back(ExpandLine(header_hash, i));
    }

    Line state_line = ExpandLine(header_hash, 0);
    uint64_t selector = ReadLE64(state_line.data());

    for (uint64_t step = 0; step < NUM_STEPS; ++step) {
        const uint32_t index = SelectLine(state_line, selector ^ step);
        MixLine(state_line, scratchpad[index], step);
        selector = ReadLE64(state_line.data() + ((step % 8) * 8));
    }

    const auto final_hash = FinalizeState(header_hash, state_line);
    uint256 result;
    std::memcpy(result.begin(), final_hash.data(), final_hash.size());
    return BlockHash{result};
}
