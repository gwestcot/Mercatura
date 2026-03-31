#ifndef MERCATURA_CRYPTO_MERCAHASH_H
#define MERCATURA_CRYPTO_MERCAHASH_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <uint256.h>

class CBlockHeader;

// Locked roadmap constants
static constexpr uint64_t MERCAHASH_SCRATCHPAD_BYTES = 1ULL << 30;   // 1 GiB
static constexpr uint32_t MERCAHASH_LINE_SIZE = 64;
static constexpr uint32_t MERCAHASH_NUM_LINES = 16777216;
static constexpr uint32_t MERCAHASH_STEPS = 1048576;

// Keep rolling state in the roadmap's 1-4 KB range.
// 256 * 8 bytes = 2048 bytes
static constexpr uint32_t MERCAHASH_ROLLING_WORDS = 256;

struct MercaHashState
{
    std::vector<uint8_t> scratchpad;
    std::array<uint64_t, MERCAHASH_ROLLING_WORDS> rolling{};
    uint64_t cursor = 0;

    MercaHashState();
};

// Public API used by validation/mining/tests
uint256 MercaHashFromHeader(const CBlockHeader& header);
uint256 MercaHashFromBytes(const unsigned char* data, size_t len);

// Internal phase-3 building blocks
void MercaHashInitialize(MercaHashState& state, const unsigned char* data, size_t len);
void MercaHashFillScratchpad(MercaHashState& state);
void MercaHashRandomWalk(MercaHashState& state);
uint256 MercaHashFinalize(const MercaHashState& state);

#endif // MERCATURA_CRYPTO_MERCAHASH_H
