#include <arith_uint256.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>
#include <sstream>

using Clock = std::chrono::steady_clock;

struct GenesisProfile
{
    std::string network_label;
    std::string pszTimestamp;
    std::string pubkey_hex;
    uint32_t nTime;
    uint32_t nNonce;
    uint32_t nBits;
    int32_t nVersion;
    CAmount genesisReward;
};

static CBlock CreateGenesisBlock(const char* pszTimestamp,
                                 const CScript& genesisOutputScript,
                                 uint32_t nTime,
                                 uint32_t nNonce,
                                 uint32_t nBits,
                                 int32_t nVersion,
                                 const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.version = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig =
        CScript() << 486604799 << CScriptNum(4)
                  << std::vector<unsigned char>(
                         (const unsigned char*)pszTimestamp,
                         (const unsigned char*)pszTimestamp + std::strlen(pszTimestamp));
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

static GenesisProfile GetProfile(const std::string& network)
{
    // Placeholder presets for now.
    // Mainnet matches the currently inherited genesis inputs so you can verify behavior.
    if (network == "mainnet") {
        return GenesisProfile{
            "mainnet",
            "Pressure must be put on Vladimir Putin over Crimea",
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
            1395342829,
            0,
            0x1e0fffff,
            112,
            0
        };
    }

    if (network == "testnet") {
        return GenesisProfile{
            "testnet",
            "Pressure must be put on Vladimir Putin over Crimea",
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
            1440000002,
            0,
            0x1e00ffff,
            3,
            0
        };
    }

    if (network == "regtest") {
        return GenesisProfile{
            "regtest",
            "Pressure must be put on Vladimir Putin over Crimea",
            "04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f",
            1440000002,
            0,
            0x1e00ffff,
            3,
            0
        };
    }

    throw std::runtime_error("Unknown network. Use --network=mainnet, --network=testnet, or --network=regtest");
}

static std::string GetArgValue(const std::string& arg, const std::string& prefix)
{
    if (arg.rfind(prefix, 0) == 0) {
        return arg.substr(prefix.size());
    }
    return "";
}

static uint32_t ParseUint32HexOrDec(const std::string& value)
{
    unsigned long result = 0;
    if (value.rfind("0x", 0) == 0 || value.rfind("0X", 0) == 0) {
        result = std::stoul(value, nullptr, 16);
    } else {
        result = std::stoul(value, nullptr, 10);
    }
    return static_cast<uint32_t>(result);
}

int main(int argc, char* argv[])
{
    std::string network = "mainnet";

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const std::string value = GetArgValue(arg, "--network=");
        if (!value.empty()) {
            network = value;
        }
    }

    GenesisProfile profile = GetProfile(network);

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        const std::string bits_value = GetArgValue(arg, "--bits=");
        if (!bits_value.empty()) {
            profile.nBits = ParseUint32HexOrDec(bits_value);
        }
    }

    const CScript genesisOutputScript =
        CScript() << ParseHex(profile.pubkey_hex) << OP_CHECKSIG;

    CBlock genesis = CreateGenesisBlock(
        profile.pszTimestamp.c_str(),
        genesisOutputScript,
        profile.nTime,
        profile.nNonce,
        profile.nBits,
        profile.nVersion,
        profile.genesisReward
    );

    bool fNegative = false;
    bool fOverflow = false;
    arith_uint256 target;
    target.SetCompact(genesis.nBits, &fNegative, &fOverflow);

    std::cout << "=== Mercatura Genesis Miner ===\n";
    std::cout << "network      : " << profile.network_label << "\n";
    std::cout << "pszTimestamp : " << profile.pszTimestamp << "\n";
    std::cout << "nTime        : " << genesis.nTime << "\n";
    std::cout << "nBits        : 0x" << std::hex << genesis.nBits << std::dec << "\n";
    std::cout << "nVersion     : " << genesis.nVersion << "\n";
    std::cout << "Merkle Root  : " << genesis.hashMerkleRoot.ToString() << "\n";
    std::cout << "Target       : " << target.GetHex() << "\n\n";

    const auto start = Clock::now();
    auto last_status = start;

    uint64_t hashes_done = 0;
    uint256 best_pow = genesis.GetPoWHash();

    while (genesis.nNonce < std::numeric_limits<uint32_t>::max()) {
        const uint256 pow_hash = genesis.GetPoWHash();
        ++hashes_done;

        if (UintToArith256(pow_hash) < UintToArith256(best_pow)) {
            best_pow = pow_hash;
        }

        if (UintToArith256(pow_hash) <= target) {
            const auto end = Clock::now();
            const double seconds = std::chrono::duration<double>(end - start).count();
            const double rate = seconds > 0.0 ? (static_cast<double>(hashes_done) / seconds) : 0.0;

            std::cout << "\n=== SOLVED ===\n";
            std::cout << "network      : " << profile.network_label << "\n";
            std::cout << "Nonce        : " << genesis.nNonce << "\n";
            std::cout << "Merkle Root  : " << genesis.hashMerkleRoot.ToString() << "\n";
            std::cout << "Genesis Hash : " << genesis.GetHash().ToString() << "\n";
            std::cout << "PoW Hash     : " << genesis.GetPoWHash().ToString() << "\n";
            std::cout << "Elapsed (s)  : " << std::fixed << std::setprecision(2) << seconds << "\n";
            std::cout << "Hashrate     : " << std::fixed << std::setprecision(2) << rate << " H/s\n";
            return 0;
        }

        const auto now = Clock::now();
	if (std::chrono::duration_cast<std::chrono::seconds>(now - last_status).count() >= 1) {
    	    const double seconds = std::chrono::duration<double>(now - start).count();
    	    const double rate = seconds > 0.0 ? (static_cast<double>(hashes_done) / seconds) : 0.0;

    	    std::cout << "network=" << profile.network_label
              	      << " elapsed=" << std::fixed << std::setprecision(1) << seconds
                      << "s nonce=" << genesis.nNonce
                      << " hashes=" << hashes_done
                      << " rate=" << std::fixed << std::setprecision(3) << rate << " H/s"
                      << " best_pow=" << best_pow.ToString()
                      << "\r" << std::flush;

    	    last_status = now;
	}

        ++genesis.nNonce;
    }

    std::cerr << "\nExhausted nonce range without solution.\n";
    return 1;
}
