// Copyright (c) 2026 The Mercatura developers
// Distributed under the MIT software license.

#include <policy/block/stakingrewards.h>

#include <blockindex.h>
#include <chainparams.h>
#include <uint256.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(mercatura_phase5_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mca_avalanche_activation_height) {
    const CChainParams &chainparams = Params();
    const Consensus::Params &consensusParams = chainparams.GetConsensus();

    CBlockIndex beforeActivation;
    CBlockIndex activationBlock;

    BlockHash h1 = BlockHash(uint256(1));
    BlockHash h2 = BlockHash(uint256(2));

    beforeActivation.phashBlock = &h1;
    activationBlock.phashBlock = &h2;

    beforeActivation.nHeight =
        consensusParams.nMcaAvalancheActivationHeight - 1;
    activationBlock.nHeight =
        consensusParams.nMcaAvalancheActivationHeight;

    activationBlock.pprev = &beforeActivation;

    BOOST_CHECK(!IsStakingRewardsActivated(consensusParams,
                                           beforeActivation.pprev));
    BOOST_CHECK(IsStakingRewardsActivated(consensusParams, &beforeActivation));
}

BOOST_AUTO_TEST_SUITE_END()
