#include <crypto/mercahash.h>

#include <hash.h>
#include <primitives/block.h>
#include <streams.h>

static inline uint64_t RotL64(uint64_t x, int r)
{
    return (x << r) | (x >> (64 - r));
}

MercaHashState::MercaHashState()
    : scratchpad(MERCAHASH_SCRATCHPAD_BYTES, 0)
{
}

uint256 MercaHashFromHeader(const CBlockHeader& header)
{
    DataStream ss;
    ss << header;

    const auto* ptr = reinterpret_cast<const unsigned char*>(ss.data());
    return MercaHashFromBytes(ptr, ss.size());
}

uint256 MercaHashFromBytes(const unsigned char* data, size_t len)
{
    MercaHashState state;
    MercaHashInitialize(state, data, len);
    MercaHashFillScratchpad(state);
    MercaHashRandomWalk(state);
    return MercaHashFinalize(state);
}

void MercaHashInitialize(MercaHashState& state, const unsigned char* data, size_t len)
{
    static constexpr uint64_t K0 = 0x243f6a8885a308d3ULL;
    static constexpr uint64_t K1 = 0x13198a2e03707344ULL;
    static constexpr uint64_t K2 = 0xa4093822299f31d0ULL;
    static constexpr uint64_t K3 = 0x082efa98ec4e6c89ULL;

    for (size_t i = 0; i < state.rolling.size(); ++i) {
        uint64_t v = K0 ^ (K1 * static_cast<uint64_t>(i + 1));
        v ^= RotL64(K2 + static_cast<uint64_t>(i * 0x9e37), static_cast<int>((i % 31) + 1));
        v += K3 ^ static_cast<uint64_t>(i * 0x100000001b3ULL);
        state.rolling[i] = v;
    }

    for (size_t i = 0; i < len; ++i) {
        const uint64_t b = static_cast<uint64_t>(data[i]);
        const size_t idx0 = i % state.rolling.size();
        const size_t idx1 = (i * 7 + 13) % state.rolling.size();

        state.rolling[idx0] ^= b << ((i & 7) * 8);
        state.rolling[idx0] = RotL64(state.rolling[idx0] + K0 + static_cast<uint64_t>(i), 11);

        state.rolling[idx1] ^= RotL64(b + K1 + static_cast<uint64_t>(i), 17);
        state.rolling[idx1] += (state.rolling[idx0] ^ K2);
        state.rolling[idx1] = RotL64(state.rolling[idx1], 23);
    }

    for (size_t round = 0; round < 4; ++round) {
        for (size_t i = 0; i < state.rolling.size(); ++i) {
            const size_t j = (i + 1) % state.rolling.size();
            const size_t k = (i + 17) % state.rolling.size();

            state.rolling[i] ^= RotL64(state.rolling[j], 9);
            state.rolling[i] += state.rolling[k] ^ (K3 + static_cast<uint64_t>(round + i));
            state.rolling[i] = RotL64(state.rolling[i], static_cast<int>((i + round) % 29 + 3));
        }
    }

    state.cursor = (state.rolling[0] ^ state.rolling[17] ^ state.rolling[113]) % MERCAHASH_NUM_LINES;
}

void MercaHashFillScratchpad(MercaHashState& state)
{
    for (uint64_t line = 0; line < MERCAHASH_NUM_LINES; ++line) {
        const uint64_t offset = line * MERCAHASH_LINE_SIZE;

        uint64_t lane0 = state.rolling[(line + 0) % state.rolling.size()] ^ line;
        uint64_t lane1 = state.rolling[(line + 7) % state.rolling.size()] + (line << 1);
        uint64_t lane2 = state.rolling[(line + 13) % state.rolling.size()] ^ (line << 7);
        uint64_t lane3 = state.rolling[(line + 29) % state.rolling.size()] + 0x9e3779b97f4a7c15ULL;

        for (uint32_t chunk = 0; chunk < 8; ++chunk) {
            lane0 = RotL64(lane0 + (lane3 ^ 0x243f6a8885a308d3ULL), 13);
            lane1 = RotL64(lane1 ^ (lane0 + 0x13198a2e03707344ULL), 17);
            lane2 = RotL64(lane2 + (lane1 ^ 0xa4093822299f31d0ULL), 19);
            lane3 = RotL64(lane3 ^ (lane2 + 0x082efa98ec4e6c89ULL), 23);

            const uint64_t mixed = lane0 ^ lane1 ^ lane2 ^ lane3 ^ (line * (chunk + 1));

            for (int b = 0; b < 8; ++b) {
                state.scratchpad[offset + (chunk * 8) + b] =
                    static_cast<uint8_t>((mixed >> (8 * b)) & 0xff);
            }
        }

        state.rolling[line % state.rolling.size()] ^=
            lane0 + lane1 + lane2 + lane3 + line;
    }
}

void MercaHashRandomWalk(MercaHashState& state)
{
    for (uint32_t step = 0; step < MERCAHASH_STEPS; ++step) {
        const uint64_t idx = state.cursor % MERCAHASH_NUM_LINES;
        const uint64_t offset = idx * MERCAHASH_LINE_SIZE;

        uint64_t lane[8];
        for (int chunk = 0; chunk < 8; ++chunk) {
            uint64_t v = 0;
            for (int b = 0; b < 8; ++b) {
                v |= static_cast<uint64_t>(state.scratchpad[offset + (chunk * 8) + b]) << (8 * b);
            }
            lane[chunk] = v;
        }

        const size_t r0 = step % state.rolling.size();
        const size_t r1 = (step * 5 + 1) % state.rolling.size();
        const size_t r2 = (step * 7 + 3) % state.rolling.size();
        const size_t r3 = (step * 11 + 9) % state.rolling.size();

        uint64_t a = state.rolling[r0] ^ lane[0] ^ lane[4];
        uint64_t b = state.rolling[r1] + lane[1] + lane[5];
        uint64_t c = state.rolling[r2] ^ lane[2] ^ lane[6];
        uint64_t d = state.rolling[r3] + lane[3] + lane[7];

        if ((a ^ c) & 1ULL) {
            a = RotL64(a + (b ^ 0x243f6a8885a308d3ULL), 13);
            c = RotL64(c ^ (d + 0x13198a2e03707344ULL), 17);
        } else {
            a = RotL64(a ^ (d + 0xa4093822299f31d0ULL), 19);
            c = RotL64(c + (b ^ 0x082efa98ec4e6c89ULL), 23);
        }

        if ((b ^ d) & 1ULL) {
            b = RotL64(b + (c ^ 0x9e3779b97f4a7c15ULL), 11);
            d = RotL64(d ^ (a + 0xbf58476d1ce4e5b9ULL), 29);
        } else {
            b = RotL64(b ^ (a + 0x94d049bb133111ebULL), 7);
            d = RotL64(d + (c ^ 0x2545f4914f6cdd1dULL), 31);
        }

        state.rolling[r0] ^= a + lane[7];
        state.rolling[r1] += b ^ lane[6];
        state.rolling[r2] ^= c + lane[5];
        state.rolling[r3] += d ^ lane[4];

        for (int chunk = 0; chunk < 8; ++chunk) {
            const uint64_t mixed =
                lane[chunk]
                ^ state.rolling[(r0 + chunk) % state.rolling.size()]
                ^ RotL64(a + b + c + d + static_cast<uint64_t>(chunk), (chunk + 5));

            for (int bidx = 0; bidx < 8; ++bidx) {
                state.scratchpad[offset + (chunk * 8) + bidx] =
                    static_cast<uint8_t>((mixed >> (8 * bidx)) & 0xff);
            }
        }

        state.cursor =
            (a ^ b ^ c ^ d ^ lane[0] ^ lane[3] ^ lane[7] ^ static_cast<uint64_t>(step))
            % MERCAHASH_NUM_LINES;
    }
}\

uint256 MercaHashFinalize(const MercaHashState& state)
{
    uint64_t a = 0x243f6a8885a308d3ULL ^ state.cursor;
    uint64_t b = 0x13198a2e03707344ULL + state.rolling[17];
    uint64_t c = 0xa4093822299f31d0ULL ^ state.rolling[113];
    uint64_t d = 0x082efa98ec4e6c89ULL + state.rolling[251];

    for (size_t i = 0; i < state.rolling.size(); ++i) {
        const uint64_t x = state.rolling[i];

        a = RotL64(a ^ x, 13) + 0x9e3779b97f4a7c15ULL;
        b = RotL64(b + x, 17) ^ 0xbf58476d1ce4e5b9ULL;
        c = RotL64(c ^ (x + a), 19) + 0x94d049bb133111ebULL;
        d = RotL64(d + (x ^ b), 23) ^ 0x2545f4914f6cdd1dULL;
    }

    for (size_t i = 0; i < 4; ++i) {
        a = RotL64(a + (b ^ c), 11);
        b = RotL64(b ^ (c + d), 29);
        c = RotL64(c + (d ^ a), 7);
        d = RotL64(d ^ (a + b), 31);
    }

    HashWriter hasher;
    hasher << (a ^ c);
    hasher << (b ^ d);
    hasher << ((a + b) ^ state.rolling[0]);
    hasher << ((c + d) ^ state.rolling[state.rolling.size() - 1]);
    hasher << state.cursor;

    return hasher.GetHash();
}
