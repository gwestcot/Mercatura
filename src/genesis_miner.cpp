#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>

// Bitcoin ABC / Core style SHA256d (fast)
#include "hash.h"   // provides CSHA256 / CHash256 in many forks
#include "span.h"

static inline void u32le(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void sha256d_fast(const uint8_t* data, size_t len, uint8_t out[32]) {
    // CHash256 is double-SHA256
CHash256().Write(Span<const uint8_t>(data, len)).Finalize(Span<uint8_t>(out, 32));
}

// Convert compact bits to full target (big-endian bytes)
static std::array<uint8_t,32> bits_to_target_be(uint32_t bits) {
    const uint32_t exp = bits >> 24;
    const uint32_t mant = bits & 0x007fffff;

    std::array<uint8_t,32> t{};
    if (exp <= 3) {
        uint32_t v = mant >> (8 * (3 - exp));
        t[31] = (uint8_t)(v);
        t[30] = (uint8_t)(v >> 8);
        t[29] = (uint8_t)(v >> 16);
        t[28] = (uint8_t)(v >> 24);
    } else {
        int idx = (int)(32 - exp);
        if (idx < 0) idx = 0;
        if (idx + 3 <= 32) {
            t[idx + 0] = (uint8_t)(mant >> 16);
            t[idx + 1] = (uint8_t)(mant >> 8);
            t[idx + 2] = (uint8_t)(mant);
        }
    }
    return t;
}

// LE hash <= LE target compare
static inline bool leq_le(const uint8_t h_le[32], const std::array<uint8_t,32>& t_le) {
    for (int i = 31; i >= 0; --i) {
        if (h_le[i] < t_le[i]) return true;
        if (h_le[i] > t_le[i]) return false;
    }
    return true;
}

static std::array<uint8_t,32> merkle_hex_to_le(const char* hex) {
    std::array<uint8_t,32> be{};
    for (int i = 0; i < 32; i++) {
        unsigned int x;
        std::sscanf(hex + (i*2), "%2x", &x);
        be[i] = (uint8_t)x;
    }
    std::array<uint8_t,32> le{};
    for (int i = 0; i < 32; i++) le[i] = be[31 - i];
    return le;
}

struct Result { uint32_t nonce; std::array<uint8_t,32> hash_be; };

static Result mine(uint32_t time, uint32_t bits, const std::array<uint8_t,32>& merkle_le) {
    const auto target_be = bits_to_target_be(bits);
    std::array<uint8_t,32> target_le{};
    for (int i = 0; i < 32; ++i) target_le[i] = target_be[31 - i];

    uint8_t hdr[80];
    std::memset(hdr, 0, sizeof(hdr));
    u32le(hdr + 0, 1); // version
    std::memcpy(hdr + 36, merkle_le.data(), 32);
    u32le(hdr + 68, time);
    u32le(hdr + 72, bits);

    // print nonce=0 fingerprint
    {
        uint8_t tmp_hdr[80];
        std::memcpy(tmp_hdr, hdr, 80);
        u32le(tmp_hdr + 76, 0);
        uint8_t h_le[32], h_be[32];
        sha256d_fast(tmp_hdr, 80, h_le);
        for (int i = 0; i < 32; i++) h_be[i] = h_le[31 - i];
        std::fprintf(stderr, "C++ FAST hash(nonce=0) = ");
        for (int i = 0; i < 32; i++) std::fprintf(stderr, "%02x", h_be[i]);
        std::fprintf(stderr, "\n");
    }

    std::atomic<bool> found{false};
    std::atomic<uint32_t> found_nonce{0};
    std::array<uint8_t,32> found_hash_be{};
    std::atomic<uint64_t> total_hashes{0};
    auto start_time = std::chrono::steady_clock::now();

    const unsigned threads = std::max(1u, std::thread::hardware_concurrency());
    std::vector<std::thread> ts;
    ts.reserve(threads);

    auto worker = [&](uint32_t start) {
        uint8_t h_le[32];
        uint8_t local_hdr[80];
        std::memcpy(local_hdr, hdr, 80);

        for (uint32_t nonce = start; !found.load(std::memory_order_relaxed); nonce += threads) {
            u32le(local_hdr + 76, nonce);
            sha256d_fast(local_hdr, 80, h_le);
            total_hashes.fetch_add(1, std::memory_order_relaxed);

// progress output (only thread 0 prints, about once per ~2,000,000 nonces)
    if (start == 0 && (nonce % 2000000u) == 0) {
        auto now = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(now - start_time).count();
        if (secs > 0.0) {
            double hps = double(total_hashes.load(std::memory_order_relaxed)) / secs;
            std::fprintf(stderr,
                         "elapsed=%.1fs  total=%.3fM  rate=%.2f MH/s\r",
                         secs,
                         total_hashes.load(std::memory_order_relaxed) / 1e6,
                         hps / 1e6);
            std::fflush(stderr);
        }
    }

            if (leq_le(h_le, target_le)) {
                if (!found.exchange(true)) {
                    found_nonce.store(nonce);
                    for (int i = 0; i < 32; i++) found_hash_be[i] = h_le[31 - i];
                }
                return;
            }
        }
    };

    for (uint32_t i = 0; i < threads; i++) ts.emplace_back(worker, i);
    for (auto& t : ts) t.join();

    return {found_nonce.load(), found_hash_be};
}

static void print_hash(const char* label, const std::array<uint8_t,32>& hbe) {
    std::printf("%s ", label);
    for (int i = 0; i < 32; i++) std::printf("%02x", hbe[i]);
    std::printf("\n");
}

int main() {
    const char* merkle_hex = "0ab47e77458e949f2f881f9fbb6b9a49cedc25fcf42edecfc0c7fdf3e50d350e";
    auto merkle_le = merkle_hex_to_le(merkle_hex);

    auto r1 = mine(1231006505, 0x1d00ffff, merkle_le);
    std::printf("MAIN_NONCE %u\n", r1.nonce);
    print_hash("MAIN_HASH ", r1.hash_be);

    auto r2 = mine(1296688602, 0x1d00ffff, merkle_le);
    std::printf("TEST_NONCE %u\n", r2.nonce);
    print_hash("TEST_HASH ", r2.hash_be);

    return 0;
}
