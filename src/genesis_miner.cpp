#include <arith_uint256.h>
#include <consensus/merkle.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>

static CBlock CreateGenesisBlock(const char *pszTimestamp,
                                 const CScript &genesisOutputScript,
                                 uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<uint8_t>((const uint8_t *)pszTimestamp,
                                          (const uint8_t *)pszTimestamp +
                                              strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime = nTime;
    genesis.nBits = nBits;
    genesis.nNonce = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce,
                                 uint32_t nBits, int32_t nVersion,
                                 const Amount genesisReward) {
    const char *pszTimestamp =
        "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    const CScript genesisOutputScript =
        CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909"
                              "a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112"
                              "de5c384df7ba0b8d578a4c702b6bf11d5f")
                  << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce,
                              nBits, nVersion, genesisReward);
}

static void PrintHash(const char *label, const uint256 &hash) {
    std::printf("%s %s\n", label, hash.ToString().c_str());
}

static void MineGenesis(const char *name, uint32_t nTime, uint32_t nBits) {
    CBlock genesis = CreateGenesisBlock(nTime, 0, nBits, 1, 50 * COIN);

    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 target;
    target.SetCompact(nBits, &fNegative, &fOverflow);

    if (fNegative || fOverflow || target == 0) {
        std::fprintf(stderr, "%s: invalid compact target\n", name);
        return;
    }

    const auto start_time = std::chrono::steady_clock::now();

    std::atomic<bool> found{false};
    std::atomic<uint32_t> found_nonce{0};
    std::atomic<uint64_t> total_hashes{0};

    uint256 found_block_hash;
    uint256 found_pow_hash;

    const unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> workers;
    workers.reserve(threads);

    // fingerprint with nonce = 0
    {
        CBlock probe = genesis;
        probe.nNonce = 0;
        std::fprintf(stderr, "%s nonce=0 BLOCK_HASH = %s\n",
                     name, probe.GetHash().ToString().c_str());
        std::fprintf(stderr, "%s nonce=0 POW_HASH   = %s\n",
                     name, probe.GetPoWHash().ToString().c_str());
    }

    auto worker = [&](uint32_t start_nonce) {
        CBlock local = genesis;

        for (uint32_t nonce = start_nonce;
             !found.load(std::memory_order_relaxed);
             nonce += threads) {
            local.nNonce = nonce;

            const auto pow_hash = local.GetPoWHash();
            total_hashes.fetch_add(1, std::memory_order_relaxed);

            if (start_nonce == 0 && (nonce % 10000u) == 0) {
                const auto now = std::chrono::steady_clock::now();
                const double secs =
                    std::chrono::duration<double>(now - start_time).count();
                if (secs > 0.0) {
                    const double hps =
                        double(total_hashes.load(std::memory_order_relaxed)) /
                        secs;
                    std::fprintf(stderr,
                                 "%s elapsed=%.1fs total=%.3fK rate=%.2f H/s\r",
                                 name,
                                 secs,
                                 total_hashes.load(std::memory_order_relaxed) /
                                     1e3,
                                 hps);
                    std::fflush(stderr);
                }
            }

            if (UintToArith256(pow_hash) <= target) {
                if (!found.exchange(true)) {
                    found_nonce.store(nonce, std::memory_order_relaxed);
                    found_block_hash = local.GetHash();
                    found_pow_hash = pow_hash;
                }
                return;
            }
        }
    };

    for (uint32_t i = 0; i < threads; ++i) {
        workers.emplace_back(worker, i);
    }

    for (auto &t : workers) {
        t.join();
    }

    genesis.nNonce = found_nonce.load(std::memory_order_relaxed);

    std::printf("\n%s_NONCE %u\n", name, genesis.nNonce);
    PrintHash("BLOCK_HASH ", genesis.GetHash());
    PrintHash("POW_HASH   ", genesis.GetPoWHash());
    PrintHash("MERKLE     ", genesis.hashMerkleRoot);
}

int main() {
    // Regtest first: easiest validation path
    MineGenesis("REGTEST", 1296688602, 0x207fffff);

    // Existing MCA testnet/mainnet params currently in chainparams.cpp
    MineGenesis("TESTNET", 1296688602, 0x207fffff);
    MineGenesis("MAINNET", 1231006505, 0x207fffff);

    return 0;
}
