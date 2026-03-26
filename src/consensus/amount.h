// Copyright (c) 2009-2020 The Bitcoin Core developers
// Copyright (c) 2026-Present The Mercatura developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_AMOUNT_H
#define BITCOIN_CONSENSUS_AMOUNT_H

#include <stdint.h>

typedef int64_t CAmount;

// Mercatura consensus divisibility is locked at 2 decimal places.
// Base unit: 0.01 MCA
// 1 MCA = 100 base units
static constexpr CAmount COIN = 100;

// Temporary broad sanity bound carried forward during the port.
// This is not the subsidy design; it is only the existing MoneyRange guard.
static constexpr CAmount MAX_MONEY = 105000000 * COIN;

inline bool MoneyRange(const CAmount& nValue)
{
    return (nValue >= 0 && nValue <= MAX_MONEY);
}

#endif // BITCOIN_CONSENSUS_AMOUNT_H
