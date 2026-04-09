#pragma once
#include <array>
#include <iostream>
#include <span>
#include "../primitives/chacha20.hpp"
#include "../primitives/poly1305.hpp"

namespace CHACHA20_POLY1305 {
    #if defined(__clang__)
        typedef uint8_t v128u __attribute__((ext_vector_type(16)));
    #elif defined(__GNUC__)
        typedef uint8_t v128u __attribute__((vector_size(16)));
    #else
        #error "Compiler not supported, use GCC or Clang"
    #endif

    inline void encrypt(
        const uint32_t key[8], const uint32_t nonce[3],
        const uint8_t* plaintext, size_t plain_size,
        const uint8_t* aad, size_t aad_size,
        uint8_t* output, uint8_t tag[16]
    ) {
        ChaCha20 chacha(key, nonce);

        uint8_t poly_key[32] { 0 };
        chacha.process(poly_key, poly_key, 32);

        Poly1305 poly(poly_key);

        if(aad_size > 0) {
            poly.update(aad, aad_size);
            poly.pad16(aad_size);
        }

        if(plain_size > 0) {
            chacha.process(plaintext, output, plain_size);
            poly.update(output, plain_size);
            poly.pad16(plain_size);
        }

        uint64_t aad_len = aad_size;
        uint64_t ct_len  = plain_size;
        poly.update((uint8_t*)&aad_len, 8);
        poly.update((uint8_t*)&ct_len, 8);

        std::memcpy(tag, poly.finalize().data(), 16);
    }

    inline void decrypt(
        const uint32_t key[8], const uint32_t nonce[3],
        const uint8_t* ciphertext, size_t ciphertext_size,
        const uint8_t* aad, size_t aad_size,
        const uint8_t tag[16], uint8_t* output
    ) {
        ChaCha20 chacha(key, nonce);

        uint8_t poly_key[32] { 0 };
        chacha.process(poly_key, poly_key, 32);

        Poly1305 poly(poly_key);

        if(aad_size > 0) {
            poly.update(aad, aad_size);
            poly.pad16(aad_size);
        }

        if(ciphertext_size > 0) {
            poly.update(ciphertext, ciphertext_size);
            poly.pad16(ciphertext_size);
        }

        uint64_t aad_len = aad_size;
        uint64_t ct_len  = ciphertext_size;
        poly.update((uint8_t*)&aad_len, 8);
        poly.update((uint8_t*)&ct_len, 8);

        std::array<uint8_t, 16> computed_tag = poly.finalize();

        v128u computed_vec, provided_vec;
        std::memcpy(&computed_vec, computed_tag.data(), 16);
        std::memcpy(&provided_vec, tag, 16);

        v128u diff = computed_vec ^ provided_vec;

        uint8_t tags_match = diff[0] | diff[1] | diff[2] | diff[3] | diff[4] | diff[5] | diff[6] | diff[7] |
                            diff[8] | diff[9] | diff[10] | diff[11] | diff[12] | diff[13] | diff[14] | diff[15];

        if (tags_match != 0) {
            throw std::runtime_error("Tag verification failed");
        }

        if(ciphertext_size > 0) chacha.process(ciphertext, output, ciphertext_size);
    }
}