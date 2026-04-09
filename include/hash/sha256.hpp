#pragma once
#include <cstdint>
#include <bit>
#include <vector>
#include "../utils/crypto_helpers.hpp"

namespace SHA256 {
    std::vector<uint8_t> hash(const uint8_t* data, const size_t data_size) {
        // Initialize hash values:
        // (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):

        uint32_t h0 = 0x6a09e667;
        uint32_t h1 = 0xbb67ae85;
        uint32_t h2 = 0x3c6ef372;
        uint32_t h3 = 0xa54ff53a;
        uint32_t h4 = 0x510e527f;
        uint32_t h5 = 0x9b05688c;
        uint32_t h6 = 0x1f83d9ab;
        uint32_t h7 = 0x5be0cd19;

        // Initialize array of round constants:
        // (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311):

        constexpr uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        };

        // Padding message

        size_t new_size = ((data_size + 9 + 63) >> 6) << 6; 
        uint8_t* padded_data = (uint8_t*)calloc(new_size, 1);
        CryptoHelper::lock_memory(padded_data, new_size);
        std::memcpy(padded_data, data, data_size);
        padded_data[data_size] = 0x80;

        uint64_t bit_size = (uint64_t)data_size * 8;

        #pragma clang loop unroll(full)
        for (int i = 0; i < 8; ++i) {
            padded_data[new_size - 8 + i] = (uint8_t)(bit_size >> (56 - i * 8));
        }

        // Main loop

        for(size_t i=0; i < new_size; i+=64) {
            uint32_t* _32chunks = (uint32_t*)(padded_data + i);
            uint32_t w[64];
            std::memcpy(w, _32chunks, 64); // 64 bytes - 512 bits

            // Inverting for little endian cpus
            if constexpr (std::endian::native == std::endian::little) {
                for(size_t j=0; j < 16; j++) {
                    w[j] = __builtin_bswap32(w[j]);
                }
            }

            #pragma clang loop unroll(full)
            for(size_t j=16; j < 64; j++) {
                uint32_t s0 = std::rotr(w[j-15], 7) ^ std::rotr(w[j-15], 18) ^ (w[j-15] >> 3);
                uint32_t s1 = std::rotr(w[j-2], 17) ^ std::rotr(w[j-2], 19) ^ (w[j-2] >> 10);

                w[j] = w[j-16] + s0 + w[j-7] + s1;
            }

            // Initialize working variables to current hash value

            uint32_t a = h0;
            uint32_t b = h1;
            uint32_t c = h2;
            uint32_t d = h3;
            uint32_t e = h4;
            uint32_t f = h5;
            uint32_t g = h6;
            uint32_t h = h7;
            
            // Compression function main loop
            
            #pragma clang loop unroll(full)
            for(size_t j=0; j < 64; j++) {
                uint32_t S1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
                uint32_t ch = (e & f) ^ ((~e) & g);
                uint32_t temp1 = h + S1 + ch + k[j] + w[j];
                uint32_t S0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;
        
                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;
            h5 += f;
            h6 += g;
            h7 += h;

            CryptoHelper::secure_zero_memory(w, sizeof(w));
        }

        CryptoHelper::secure_zero_memory(padded_data, new_size);
        CryptoHelper::unlock_memory(padded_data, new_size);
        free(padded_data);

        std::vector<uint8_t> digest(32);
        uint32_t final_h[8] = {h0, h1, h2, h3, h4, h5, h6, h7};

        for (int i = 0; i < 8; ++i) {
            // SHA-256 exige saída em Big-Endian
            uint32_t val = (std::endian::native == std::endian::little) 
                        ? __builtin_bswap32(final_h[i]) 
                        : final_h[i];
            std::memcpy(&digest[i * 4], &val, 4);
        }

        CryptoHelper::secure_zero_memory(final_h, sizeof(final_h));
        h0 = h1 = h2 = h3 = h4 = h5 = h6 = h7 = 0;

        return digest;
    }

    std::vector<uint8_t> hmac_sha256(const std::vector<uint8_t>& key, const std::vector<uint8_t>& message) {
        const size_t block_size = 64; // Tamanho do bloco do SHA-256
        std::vector<uint8_t> k = key;
        CryptoHelper::lock_memory(k.data(), k.size());

        // 1. Se a chave for maior que o block_size, resuma-a
        if (k.size() > block_size) {
            std::vector<uint8_t> hashed_key = hash(k.data(), k.size());
            k = hashed_key;
            CryptoHelper::lock_memory(k.data(), k.size());
        }

        // 2. Se for menor, preencha com zeros à direita
        if (k.size() < block_size) {
            k.resize(block_size, 0x00);
        }

        std::vector<uint8_t> ipad(block_size), opad(block_size);
        CryptoHelper::lock_memory(ipad.data(), block_size);
        CryptoHelper::lock_memory(opad.data(), block_size);

        for (size_t i = 0; i < block_size; ++i) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }

        // Inner Hash
        std::vector<uint8_t> inner_content = ipad;
        inner_content.insert(inner_content.end(), message.begin(), message.end());
        std::vector<uint8_t> inner_hash = hash(inner_content.data(), inner_content.size());
        CryptoHelper::lock_memory(inner_hash.data(), inner_hash.size());

        // Outer Hash
        std::vector<uint8_t> outer_content = opad;
        outer_content.insert(outer_content.end(), inner_hash.begin(), inner_hash.end());
        std::vector<uint8_t> result = hash(outer_content.data(), outer_content.size());

        // --- LIMPEZA CRÍTICA ---
        // Limpa chaves e pads
        CryptoHelper::secure_zero_memory(k.data(), k.size());
        CryptoHelper::secure_zero_memory(ipad.data(), block_size);
        CryptoHelper::secure_zero_memory(opad.data(), block_size);
        
        // Limpa conteúdos temporários (que contêm a senha XORed)
        CryptoHelper::secure_zero_memory(inner_content.data(), inner_content.size());
        CryptoHelper::secure_zero_memory(outer_content.data(), outer_content.size());
        CryptoHelper::secure_zero_memory(inner_hash.data(), inner_hash.size());

        // Unlock de tudo
        CryptoHelper::unlock_memory(k.data(), k.size());
        CryptoHelper::unlock_memory(ipad.data(), block_size);
        CryptoHelper::unlock_memory(opad.data(), block_size);
        CryptoHelper::unlock_memory(inner_hash.data(), inner_hash.size());

        return result;
    }

    std::vector<uint8_t> pbkdf2_hmac_sha256(
        const std::vector<uint8_t>& password, 
        const std::vector<uint8_t>& salt, 
        uint32_t iterations, 
        uint32_t dkLen
    ) {
        std::vector<uint8_t> result;
        result.reserve(dkLen); // Evita realocações frequentes
        uint32_t block_count = (dkLen + 31) / 32;

        for (uint32_t i = 1; i <= block_count; ++i) {
            // 1. Preparar Salt || INT(i)
            std::vector<uint8_t> salt_i = salt;
            salt_i.push_back((i >> 24) & 0xFF);
            salt_i.push_back((i >> 16) & 0xFF);
            salt_i.push_back((i >> 8) & 0xFF);
            salt_i.push_back(i & 0xFF);

            // 2. U1 = HMAC(Password, Salt || INT(i))
            std::vector<uint8_t> vi = hmac_sha256(password, salt_i);
            CryptoHelper::lock_memory(vi.data(), vi.size());
            
            std::vector<uint8_t> ux = vi;
            CryptoHelper::lock_memory(ux.data(), ux.size());

            // 3. Iterações subsequentes
            for (uint32_t j = 1; j < iterations; ++j) {
                std::vector<uint8_t> next_vi = hmac_sha256(password, vi);
                
                // Limpa o vi antigo antes de atualizar
                CryptoHelper::secure_zero_memory(vi.data(), vi.size());
                vi = next_vi;
                
                for (size_t k = 0; k < 32; ++k) {
                    ux[k] ^= vi[k];
                }
            }

            // Adiciona ao resultado final
            size_t remaining = dkLen - result.size();
            size_t to_copy = (remaining < 32) ? remaining : 32;
            result.insert(result.end(), ux.begin(), ux.begin() + to_copy);

            // --- LIMPEZA DO BLOCO ---
            CryptoHelper::secure_zero_memory(vi.data(), vi.size());
            CryptoHelper::secure_zero_memory(ux.data(), ux.size());
            CryptoHelper::unlock_memory(vi.data(), vi.size());
            CryptoHelper::unlock_memory(ux.data(), ux.size());
            // salt_i não contém segredos (apenas salt + contador), wipe opcional
        }

        return result;
    }
}