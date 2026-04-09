#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include "../../utils/crypto_helpers.hpp"

/**
 * @file chacha20.hpp
 * @brief High-performance implementation of the ChaCha20 stream cipher using SIMD vector extensions.
 * 
 * @author Leonardo de Farias Abreu
 * @date 2026
 * @copyright MIT License
 */


#if defined(__clang__)
    typedef uint32_t v512u __attribute__((ext_vector_type(16)));
    #define PRAGMA_UNROLL_16 _Pragma("clang loop unroll_count(16)")
    #define PRAGMA_UNROLL_10 _Pragma("clang loop unroll_count(10)")
#elif defined(__GNUC__)
    typedef uint32_t v512u __attribute__((vector_size(64)));
    #define PRAGMA_UNROLL_16 _Pragma("GCC unroll 16")
    #define PRAGMA_UNROLL_10 _Pragma("GCC unroll 16")
#else
    #error "Compiler not supported, use GCC or Clang"
#endif

/**
 * @struct ChaCha20
 * @brief Main struct
 * 
 * This struct uses 512-bit wide vector registers to process 16 blocks of 512 bits (64 bytes)
 * Complies with the ChaCha20 specification as defined in RFC 8439, ensuring security and correctness.
 * 
 * @note Requires Clang or GCC with support for 512-bit vector extensions (AVX-512).
 * @warning Do not reuse the key-nonce pair for different messages (Nonce Reuse Attack).
 */

struct ChaCha20 {
public:
    ChaCha20(const uint32_t key[8], const uint32_t nonce[3]);

    void set_counter(uint32_t counter);
    void process(const uint8_t* input, uint8_t* output, size_t length);

    ~ChaCha20() {
        CryptoHelper::secure_zero_memory(&state, sizeof(state));
        CryptoHelper::unlock_memory(this, sizeof(ChaCha20));
    }

    ChaCha20(const ChaCha20&) = delete;
    ChaCha20& operator=(const ChaCha20&) = delete;

    ChaCha20(ChaCha20&&) noexcept = default;
    ChaCha20& operator=(ChaCha20&&) = delete;
private:
    alignas(64) v512u state[16];

    inline v512u _rotl_512(v512u v, uint8_t amount) {
        return (v << amount) | (v >> (32 - amount));
    }

    inline v512u _rotr_512(v512u v, uint8_t amount) {
        return (v >> amount) | (v << (32 - amount));
    }

    /**
     * @brief Transposes a 16x16 matrix of 512-bit vectors for optimal access patterns during the ChaCha20 block function.
     * @param out The matrix to transpose.
     */
    
    inline void transpose16x16(v512u out[16]) {
        v512u temp[16];
        
        PRAGMA_UNROLL_16
        for (int i = 0; i < 16; ++i) {
            PRAGMA_UNROLL_16
            for (int j = 0; j < 16; ++j) {
                temp[i][j] = out[j][i];
            }
        }
        
        PRAGMA_UNROLL_16
        for (int i = 0; i < 16; ++i) {
            out[i] = temp[i];
        }
    }


    void quarter_round(v512u& a, v512u& b, v512u& c, v512u& d);
    void blockFunction(v512u output[16]);
};

inline ChaCha20::ChaCha20(const uint32_t key[8], const uint32_t nonce[3]) {
    CryptoHelper::lock_memory(this, sizeof(ChaCha20));

    state[0] = (v512u)0x61707865;
    state[1] = (v512u)0x3320646e;
    state[2] = (v512u)0x79622d32;
    state[3] = (v512u)0x6b206574;

    for (size_t i = 0; i < 8; ++i) {
        state[4 + i] = (v512u)key[i];
    }

    state[12] = (v512u)0;
    state[12] += (v512u){0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};

    for (size_t i = 0; i < 3; ++i) {
        state[13 + i] = (v512u)nonce[i];
    }
}

inline void ChaCha20::quarter_round(v512u& a, v512u& b, v512u& c, v512u& d) {
    a += b; d ^= a; d = _rotl_512(d, 16);
    c += d; b ^= c; b = _rotl_512(b, 12);
    a += b; d ^= a; d = _rotl_512(d, 8);
    c += d; b ^= c; b = _rotl_512(b, 7);
}

inline void ChaCha20::set_counter(uint32_t counter) {
    state[12] = (v512u)counter;
    state[12] += (v512u){0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
}

inline void ChaCha20::blockFunction(v512u output[16]) {
    v512u w[16];
    for(int i=0; i<16; i++) w[i] = state[i];

    PRAGMA_UNROLL_10
    for (int i = 0; i < 10; ++i) {
        quarter_round(w[0], w[4], w[8], w[12]);
        quarter_round(w[1], w[5], w[9], w[13]);
        quarter_round(w[2], w[6], w[10], w[14]);
        quarter_round(w[3], w[7], w[11], w[15]);
        quarter_round(w[0], w[5], w[10], w[15]);
        quarter_round(w[1], w[6], w[11], w[12]);
        quarter_round(w[2], w[7], w[8], w[13]);
        quarter_round(w[3], w[4], w[9], w[14]);
    }

    for(int i=0; i<16; i++) {
        output[i] = w[i] + state[i];
    }

    state[12] += (v512u)16;
}

inline void ChaCha20::process(const uint8_t* input, uint8_t* output, size_t length) {
    size_t full_chunks = length / 1024;
    size_t processed = 0;
    uint32_t initial_counter = (uint32_t)(state[12][0] & 0xFFFFFFFF);

    for (size_t i = 0; i < full_chunks; ++i) {
        v512u ks[16];
        blockFunction(ks);
        transpose16x16(ks);
        
        for (int j = 0; j < 16; ++j) {
            size_t offset = (i * 1024) + (j * 64);
            v512u in_vec, out_vec;
            std::memcpy(&in_vec, input + offset, 64);
            out_vec = in_vec ^ ks[j];
            std::memcpy(output + offset, &out_vec, 64);
        }
        processed += 1024;
    }

    if (processed < length) {
        v512u ks[16];
        blockFunction(ks);
        transpose16x16(ks);

        size_t remaining = length - processed;
        
        for (size_t j = 0; j < 16 && (j * 64) < remaining; ++j) {
            size_t current_offset = processed + (j * 64);
            size_t chunk_size = std::min((size_t)64, remaining - (j * 64));
            
            v512u in_vec = {0};
            v512u out_vec;
            
            std::memcpy(&in_vec, input + current_offset, chunk_size);
            
            out_vec = in_vec ^ ks[j];
            
            std::memcpy(output + current_offset, &out_vec, chunk_size);
        }
    }

    set_counter(initial_counter + (uint32_t)((length + 63) >> 6));
}