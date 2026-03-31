// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdint>
#include <cstdlib>

/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 120; // MCA

/** Mercatura initial consensus block weight limit.
 * This matches 1,000,000 bytes of charged capacity under a 4 wu/byte model.
 */
static const uint64_t MCA_INITIAL_MAX_BLOCK_WEIGHT = 4000000;

/** Mercatura block capacity doubles every 2,628,000 blocks. */
static const int MCA_BLOCK_WEIGHT_DOUBLING_INTERVAL = 2628000;

/** Mercatura consensus block weight cap.
 * 1024 MiB * 4 weight-units-per-byte.
 */
static const uint64_t MCA_MAX_BLOCK_WEIGHT_CAP = 1024ULL * 1024ULL * 1024ULL * 4ULL;

static inline uint64_t GetMaxBlockWeight(int nHeight)
{
    if (nHeight < 0) nHeight = 0;

    uint64_t limit = MCA_INITIAL_MAX_BLOCK_WEIGHT;
    const int doublings = nHeight / MCA_BLOCK_WEIGHT_DOUBLING_INTERVAL;

    for (int i = 0; i < doublings; ++i) {
        if (limit >= MCA_MAX_BLOCK_WEIGHT_CAP / 2) {
            return MCA_MAX_BLOCK_WEIGHT_CAP;
        }
        limit *= 2;
    }

    return limit > MCA_MAX_BLOCK_WEIGHT_CAP ? MCA_MAX_BLOCK_WEIGHT_CAP : limit;
}

static const int WITNESS_SCALE_FACTOR = 4;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 60;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
