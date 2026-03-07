#ifndef BITCOIN_POW_SCRATCHPAD_POW_H
#define BITCOIN_POW_SCRATCHPAD_POW_H

#include <array>
#include <cstddef>
#include <cstdint>

struct BlockHash;
class CBlockHeader;

namespace MCA::PoW {

constexpr size_t SCRATCHPAD_BYTES = 128ull * 1024ull * 1024ull;
constexpr size_t LINE_SIZE = 64;
constexpr size_t NUM_LINES = SCRATCHPAD_BYTES / LINE_SIZE;      // 2,097,152
constexpr size_t NUM_STEPS = NUM_LINES;                         // 2,097,152

struct Q64x64 {
    uint64_t hi;
    uint64_t lo;
};

Q64x64 MulQ64x64(uint64_t a, uint64_t b);
uint64_t IsqrtU256(uint64_t x3, uint64_t x2, uint64_t x1, uint64_t x0);

} // namespace MCA::PoW

BlockHash ComputeScratchpadPoWHash(const CBlockHeader &header);

#endif // BITCOIN_POW_SCRATCHPAD_POW_H
