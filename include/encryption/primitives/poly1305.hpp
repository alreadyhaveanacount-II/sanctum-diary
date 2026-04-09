#pragma once

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include "../../utils/crypto_helpers.hpp"

/**
 * @file poly1305.hpp
 * 
 * @author Leonardo de Farias Abreu
 * @date 2026
 * @copyright MIT License
 */

#if defined(__clang__)
    typedef uint64_t __poly130 __attribute__((ext_vector_type(5)));
    #define PRAGMA_UNROLL_2 _Pragma("clang loop unroll_count(2)")
#elif defined(__GNUC__)
    typedef uint64_t __poly130 __attribute__((vector_size(40)));
    #define PRAGMA_UNROLL_2 _Pragma("GCC unroll 2")
#else
    #error "Compiler not supported, use GCC or Clang"
#endif

struct Poly1305 {
private:
    __poly130 ser_r;
    __poly130 ser_r2 = (__poly130)0;
    __poly130 ser_r3 = (__poly130)0;
    __poly130 ser_r4 = (__poly130)0;

    __poly130 ser_s;
    __poly130 acc = (__poly130)0; // Accumulator

    size_t leftover_buff_size = 0;
    std::array<uint8_t, 16> leftover_buffer;

    inline void serialize(__poly130& out, const uint8_t* bytes, bool pad, uint8_t block_length=0) {
        out[0] = (uint32_t)bytes[0]         | (uint32_t)bytes[1] << 8  | (uint32_t)bytes[2] << 16 | ((uint32_t)bytes[3] & 0x03) << 24;
        out[1] = (uint32_t)bytes[3] >> 2    | (uint32_t)bytes[4] << 6  | (uint32_t)bytes[5] << 14 | ((uint32_t)bytes[6] & 0x0F) << 22;
        out[2] = (uint32_t)bytes[6] >> 4    | (uint32_t)bytes[7] << 4  | (uint32_t)bytes[8] << 12 | ((uint32_t)bytes[9] & 0x3F) << 20;
        out[3] = (uint32_t)bytes[9] >> 6    | (uint32_t)bytes[10] << 2 | (uint32_t)bytes[11] << 10 | (uint32_t)bytes[12] << 18;
        out[4] = (uint32_t)bytes[13]        | (uint32_t)bytes[14] << 8 | (uint32_t)bytes[15] << 16;

        if (pad) {
            uint32_t total_bits = block_length << 3;
            out[total_bits / 26] |= (1UL << (total_bits % 26));
        }
        
        for(int i=0; i<5; i++) out[i] &= 0x3FFFFFF;
    }

    inline std::array<uint8_t, 16> deserialize(const __poly130& in) {
        std::array<uint8_t, 16> bytes;

        bytes[0]  =  in[0] & 0xFF;
        bytes[1]  = (in[0] >> 8) & 0xFF;
        bytes[2]  = (in[0] >> 16) & 0xFF;
        bytes[3]  = (in[0] >> 24) | ((in[1] << 2) & 0xFF);
        
        bytes[4]  = (in[1] >> 6) & 0xFF;
        bytes[5]  = (in[1] >> 14) & 0xFF;
        bytes[6]  = (in[1] >> 22) | ((in[2] << 4) & 0xFF);
        
        bytes[7]  = (in[2] >> 4) & 0xFF;
        bytes[8]  = (in[2] >> 12) & 0xFF;
        bytes[9]  = (in[2] >> 20) | ((in[3] << 6) & 0xFF);
        
        bytes[10] = (in[3] >> 2) & 0xFF;
        bytes[11] = (in[3] >> 10) & 0xFF;
        bytes[12] = (in[3] >> 18) & 0xFF;
        
        bytes[13] =  in[4] & 0xFF;
        bytes[14] = (in[4] >> 8) & 0xFF;
        bytes[15] = (in[4] >> 16) & 0xFF;

        return bytes;
    }


    inline void carry_el(__poly130& el) {
        PRAGMA_UNROLL_2
        for(size_t i=0; i < 2; i++) {
            static constexpr uint64_t mask26 = 0x3FFFFFF;

            __poly130 carries = el >> 26;

            el &= mask26;

            el += __poly130 {
                carries[4] * 5,
                carries[0],
                carries[1],
                carries[2],
                carries[3]
            };
        }
    }

    inline void mult(__poly130& out, const __poly130 by) {
        uint64_t m0 = (out[0] * by[0]) + (out[1] * by[4] * 5) + (out[2] * by[3] * 5) + (out[3] * by[2] * 5) + (out[4] * by[1] * 5);
        uint64_t m1 = (out[0] * by[1]) + (out[1] * by[0]) + (out[2] * by[4] * 5) + (out[3] * by[3] * 5) + (out[4] * by[2] * 5);
        uint64_t m2 = (out[0] * by[2]) + (out[1] * by[1]) + (out[2] * by[0]) + (out[3] * by[4] * 5) + (out[4] * by[3] * 5);
        uint64_t m3 = (out[0] * by[3]) + (out[1] * by[2]) + (out[2] * by[1]) + (out[3] * by[0]) + (out[4] * by[4] * 5);
        uint64_t m4 = (out[0] * by[4]) + (out[1] * by[3]) + (out[2] * by[2]) + (out[3] * by[1]) + (out[4] * by[0]);

        out = __poly130 { m0, m1, m2, m3, m4 };

        carry_el(out);
    }

    inline void process_block(const std::array<uint8_t, 16>& block, uint8_t len = 16) {
        __poly130 serialized;
        serialize(serialized, block.data(), true, len);
        acc += serialized;
        mult(acc, ser_r);
    }

    inline void process_four_blocks(const std::array<uint8_t, 64>& block) {
        __poly130 serialized0;
        __poly130 serialized1;
        __poly130 serialized2;
        __poly130 serialized3;

        serialize(serialized0, block.data(), true, 16);
        serialize(serialized1, block.data()+16, true, 16);
        serialize(serialized2, block.data()+32, true, 16);
        serialize(serialized3, block.data()+48, true, 16);

        __poly130 term_1 = acc + serialized0;
        __poly130 term_2 = serialized1;
        __poly130 term_3 = serialized2;
        __poly130 term_4 = serialized3;
        
        mult(term_1, ser_r4);
        mult(term_2, ser_r3);
        mult(term_3, ser_r2);
        mult(term_4, ser_r);

        acc = term_1 + term_2 + term_3 + term_4;
        carry_el(acc);
    }
public:
    Poly1305(const Poly1305&) = delete;
    Poly1305& operator=(const Poly1305&) = delete;

    Poly1305(Poly1305&&) noexcept = default;
    Poly1305& operator=(Poly1305&&) = delete;

    ~Poly1305() {
        CryptoHelper::secure_zero_memory(this, sizeof(*this));
        CryptoHelper::unlock_memory(this, sizeof(*this));
    }

    Poly1305(const uint8_t poly_key[32]) {
        CryptoHelper::lock_memory(this, sizeof(*this));
        std::array<uint8_t, 16> r;
        std::array<uint8_t, 16> s;

        std::memcpy(r.data(), poly_key, 16);
        std::memcpy(s.data(), poly_key, 16);

        // Serializing r
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;
        r[4] &= 252;
        r[8] &= 252;
        r[12] &= 252;

        serialize(ser_r, r.data(), false);
        serialize(ser_s, s.data(), false);

        // r^2
        ser_r2 = ser_r;
        mult(ser_r2, ser_r);

        // r^3
        ser_r3 = ser_r2;
        mult(ser_r3, ser_r);

        // r^4
        ser_r4 = ser_r3;
        mult(ser_r4, ser_r);
    }

    inline void reset() {
        acc = (__poly130)0;
        leftover_buff_size = 0;
    }

    inline void pad16(size_t data_len) {
        size_t remainder = data_len % 16;
        if (remainder != 0) {
            static const uint8_t zeros[15] = {};
            update(zeros, 16 - remainder);
        }
    }

    inline void update(const uint8_t* chunk, size_t chunk_size) {
        size_t i = 0;

        if (leftover_buff_size > 0) {
            size_t can_copy = std::min(chunk_size, 16 - leftover_buff_size);
            std::memcpy(leftover_buffer.data() + leftover_buff_size, chunk, can_copy);
            
            leftover_buff_size += can_copy;
            i += can_copy;

            if (leftover_buff_size == 16) {
                process_block(leftover_buffer);
                leftover_buff_size = 0;
            } else {
                return;
            }
        }

        size_t remaining = chunk_size - i;

        size_t fast_limit = i + (remaining & ~63); 
        for (; i < fast_limit; i += 64) {
            std::array<uint8_t, 64> four_blocks;
            std::memcpy(four_blocks.data(), chunk + i, 64);
            process_four_blocks(four_blocks); 
        }

        remaining = chunk_size - i;
        size_t slow_limit = i + (remaining & ~15);
        for (; i < slow_limit; i += 16) {
            std::array<uint8_t, 16> block;
            std::memcpy(block.data(), chunk + i, 16);
            process_block(block);
        }

        size_t leftover = chunk_size - i;
        if (leftover > 0) {
            std::memcpy(leftover_buffer.data(), chunk + i, leftover);
            leftover_buff_size = leftover;
        }
    }

    inline std::array<uint8_t, 16> finalize() {
        if(leftover_buff_size != 0) {
            std::fill(leftover_buffer.data()+leftover_buff_size, leftover_buffer.data()+16, 0);
            process_block(leftover_buffer, leftover_buff_size);
        }

        acc += ser_s;
        carry_el(acc);
        return deserialize(acc);
    }
};