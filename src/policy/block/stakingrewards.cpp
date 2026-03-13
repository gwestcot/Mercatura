// Copyright (c) 2023 The Bitcoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <policy/block/stakingrewards.h>

#include <avalanche/avalanche.h>
#include <avalanche/processor.h>
#include <blockindex.h>
#include <common/args.h>
#include <consensus/activation.h>
#include <consensus/amount.h>
#include <logging.h>
#include <primitives/block.h>

#include <vector>

/**
 * Percentage of the block reward to be sent to staking rewards.
 */
static constexpr int STAKING_REWARD_RATIO = 10;

static bool IsMcaAvalancheActivated(const Consensus::Params &params,
                                    const CBlockIndex *pprev) {
    if (pprev == nullptr) {
        return false;
    }

    return (pprev->nHeight + 1) >= params.nMcaAvalancheActivationHeight;
}

bool StakingRewardsPolicy::operator()(BlockPolicyValidationState &state) {
    if (!m_blockIndex.pprev ||
        !IsMcaAvalancheActivated(m_consensusParams, m_blockIndex.pprev)) {
        return true;
    }

    assert(m_block.vtx.size());

    const BlockHash blockhash = m_blockIndex.GetBlockHash();

    std::vector<CScript> winners;
    if (!IsStakingRewardsActivated(m_consensusParams, m_blockIndex.pprev) ||
        !m_avalanche.getStakingRewardWinners(m_blockIndex.pprev->GetBlockHash(),
                                             winners)) {
        LogPrint(BCLog::AVALANCHE,
                 "Staking rewards for block %s: not ready yet\n",
                 blockhash.ToString());
        return true;
    }

    const Amount required = GetStakingRewardsAmount(m_blockReward);
    for (const auto &o : m_block.vtx[0]->vout) {
        if (o.nValue != required) {
            continue;
        }

        auto it = std::find(winners.begin(), winners.end(), o.scriptPubKey);
        if (it != winners.end()) {
            if (it != winners.begin()) {
                LogPrint(BCLog::AVALANCHE,
                         "Staking rewards for block %s: selected winner is "
                         "flaky, accepting an alternative one\n",
                         blockhash.ToString());
            }

            return true;
        }
    }

    LogPrint(BCLog::AVALANCHE,
             "Staking rewards for block %s: payout script mismatch!\n",
             blockhash.ToString());

    return state.Invalid(BlockPolicyValidationResult::POLICY_VIOLATION,
                         "policy-bad-staking-reward",
                         strprintf("Block %s violates staking reward policy",
                                   m_blockIndex.GetBlockHash().ToString()));
}

Amount GetStakingRewardsAmount(const Amount &coinbaseValue) {
    return STAKING_REWARD_RATIO * coinbaseValue / 100;
}

bool IsStakingRewardsActivated(const Consensus::Params &params,
                               const CBlockIndex *pprev) {
    return IsMcaAvalancheActivated(params, pprev) &&
           gArgs.GetBoolArg("-avalanchestakingrewards",
                            params.enableStakingRewards);
}
