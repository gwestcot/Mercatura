#include <boost/test/unit_test.hpp>

#include <crypto/mercahash.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/strencodings.h>

BOOST_AUTO_TEST_SUITE(mercahash_tests)

BOOST_AUTO_TEST_CASE(mercahash_deterministic_same_header)
{
    CBlockHeader hdr;
    hdr.nVersion = 1;
    hdr.hashPrevBlock = uint256{};
    hdr.hashMerkleRoot = uint256{};
    hdr.nTime = 1700000000;
    hdr.nBits = 0x1f00ffff;
    hdr.nNonce = 1;

    const uint256 h1 = MercaHashFromHeader(hdr);
    const uint256 h2 = MercaHashFromHeader(hdr);

    BOOST_CHECK(h1 == h2);
}

BOOST_AUTO_TEST_CASE(mercahash_changes_when_nonce_changes)
{
    CBlockHeader hdr1;
    hdr1.nVersion = 1;
    hdr1.hashPrevBlock = uint256{};
    hdr1.hashMerkleRoot = uint256{};
    hdr1.nTime = 1700000000;
    hdr1.nBits = 0x1f00ffff;
    hdr1.nNonce = 1;

    CBlockHeader hdr2 = hdr1;
    hdr2.nNonce = 2;

    BOOST_CHECK(MercaHashFromHeader(hdr1) != MercaHashFromHeader(hdr2));
}

BOOST_AUTO_TEST_CASE(block_header_gethash_matches_mercahash)
{
    CBlockHeader hdr;
    hdr.nVersion = 1;
    hdr.hashPrevBlock = uint256{};
    hdr.hashMerkleRoot = uint256{};
    hdr.nTime = 1700000000;
    hdr.nBits = 0x1f00ffff;
    hdr.nNonce = 42;

    BOOST_CHECK(hdr.GetHash() == MercaHashFromHeader(hdr));
}

BOOST_AUTO_TEST_CASE(mercahash_fixed_test_vector)
{
    CBlockHeader hdr;
    hdr.nVersion = 1;
    hdr.hashPrevBlock = uint256{};
    hdr.hashMerkleRoot = uint256{};
    hdr.nTime = 1700000000;
    hdr.nBits = 0x1f00ffff;
    hdr.nNonce = 42;

    const uint256 h = MercaHashFromHeader(hdr);
    const uint256 expected = uint256::FromHex("0ac4cb8e41c161ba2a732e86716a0c58766e6873cdf4a5133eeeb582eccb24c4").value();

    BOOST_CHECK(h == expected);
}

BOOST_AUTO_TEST_CASE(mercahash_second_fixed_test_vector)
{
    CBlockHeader hdr;
    hdr.nVersion = 2;
    hdr.hashPrevBlock = uint256{};
    hdr.hashMerkleRoot = uint256{};
    hdr.nTime = 1700001234;
    hdr.nBits = 0x1e0ffff0;
    hdr.nNonce = 99;

    const uint256 h = MercaHashFromHeader(hdr);
    const uint256 expected = uint256::FromHex("af7393c4224bb7eb1cca9a70a81a8e6cd45d4bb861cd8ceca4ee17489a71b41f").value();

    BOOST_CHECK(h == expected);
}

BOOST_AUTO_TEST_SUITE_END()
