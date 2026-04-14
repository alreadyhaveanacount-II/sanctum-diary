#pragma once

#include <cstdint>
#include <vector>
#include <bit>
#include "../hash/sha256.hpp"
#include "../utils/crypto_helpers.hpp"

void salsa20_word_specification(uint32_t out[16],uint32_t in[16]) {
    uint32_t x[16];

    std::memcpy(x, in, 16*sizeof(uint32_t));

    #pragma clang loop unroll(full)
    for (size_t i = 8; i > 0;i -= 2) {
        x[ 4] ^= std::rotl(x[ 0]+x[12], 7);  x[ 8] ^= std::rotl(x[ 4]+x[ 0], 9);
        x[12] ^= std::rotl(x[ 8]+x[ 4],13);  x[ 0] ^= std::rotl(x[12]+x[ 8],18);
        x[ 9] ^= std::rotl(x[ 5]+x[ 1], 7);  x[13] ^= std::rotl(x[ 9]+x[ 5], 9);
        x[ 1] ^= std::rotl(x[13]+x[ 9],13);  x[ 5] ^= std::rotl(x[ 1]+x[13],18);
        x[14] ^= std::rotl(x[10]+x[ 6], 7);  x[ 2] ^= std::rotl(x[14]+x[10], 9);
        x[ 6] ^= std::rotl(x[ 2]+x[14],13);  x[10] ^= std::rotl(x[ 6]+x[ 2],18);
        x[ 3] ^= std::rotl(x[15]+x[11], 7);  x[ 7] ^= std::rotl(x[ 3]+x[15], 9);
        x[11] ^= std::rotl(x[ 7]+x[ 3],13);  x[15] ^= std::rotl(x[11]+x[ 7],18);
        x[ 1] ^= std::rotl(x[ 0]+x[ 3], 7);  x[ 2] ^= std::rotl(x[ 1]+x[ 0], 9);
        x[ 3] ^= std::rotl(x[ 2]+x[ 1],13);  x[ 0] ^= std::rotl(x[ 3]+x[ 2],18);
        x[ 6] ^= std::rotl(x[ 5]+x[ 4], 7);  x[ 7] ^= std::rotl(x[ 6]+x[ 5], 9);
        x[ 4] ^= std::rotl(x[ 7]+x[ 6],13);  x[ 5] ^= std::rotl(x[ 4]+x[ 7],18);
        x[11] ^= std::rotl(x[10]+x[ 9], 7);  x[ 8] ^= std::rotl(x[11]+x[10], 9);
        x[ 9] ^= std::rotl(x[ 8]+x[11],13);  x[10] ^= std::rotl(x[ 9]+x[ 8],18);
        x[12] ^= std::rotl(x[15]+x[14], 7);  x[13] ^= std::rotl(x[12]+x[15], 9);
        x[14] ^= std::rotl(x[13]+x[12],13);  x[15] ^= std::rotl(x[14]+x[13],18);
    }

    #pragma clang loop unroll(full)
    for (size_t i = 0;i < 16;++i) out[i] = x[i] + in[i];
}

struct Scrypt {
private:
    std::vector<uint8_t> data;
    std::vector<uint8_t> salt;
    uint64_t N; // cost
    uint32_t r; // block size
    uint32_t p; // parallelization
    uint32_t dkLen;

    void scryptBlockMix(uint32_t* b, uint32_t* y) {
        uint32_t X[16];
        // 1. X = B[2 * r - 1]
        std::memcpy(X, &b[(2 * r - 1) * 16], 64);

        // 2. for i = 0 to 2 * r - 1 do
        for (uint32_t i = 0; i < 2 * r; ++i) {
            uint32_t T[16];
            #pragma clang loop unroll(full)
            for (int j = 0; j < 16; ++j) {
                T[j] = X[j] ^ b[i * 16 + j];
            }

            salsa20_word_specification(X, T);
            
            std::memcpy(&y[i * 16], X, 64);

            // Limpa T imediatamente após o uso em cada iteração
            CryptoHelper::secure_zero_memory(T, sizeof(T));
        }

        // 3. Final rearranje: Evens first, odds after
        for (uint32_t i = 0; i < r; ++i) {
            std::memcpy(&b[i * 16], &y[(i * 2) * 16], 64);
            std::memcpy(&b[(i + r) * 16], &y[(i * 2 + 1) * 16], 64);
        }

        // Limpa X antes de sair da função
        CryptoHelper::secure_zero_memory(X, sizeof(X));
    }


    void scryptROMix(uint32_t* B) {
        const uint32_t chunk_size = 32 * r; 
        const size_t chunk_bytes = chunk_size * sizeof(uint32_t);
        const size_t v_total_bytes = (size_t)N * chunk_bytes;
        
        // 1. Alocação e Lock
        std::vector<uint32_t> V(N * chunk_size);
        std::vector<uint32_t> X(chunk_size);
        std::vector<uint32_t> Y(chunk_size);

        // Trava os buffers na RAM
        CryptoHelper::lock_memory(V.data(), v_total_bytes);
        CryptoHelper::lock_memory(X.data(), chunk_bytes);
        CryptoHelper::lock_memory(Y.data(), chunk_bytes);

        // X = B
        std::memcpy(X.data(), B, chunk_bytes);

        // 2. Loop de Escrita (Mistura sequencial)
        for (uint64_t i = 0; i < N; ++i) {
            std::memcpy(&V[i * chunk_size], X.data(), chunk_bytes);
            scryptBlockMix(X.data(), Y.data());
        }

        // 3. Loop de Acesso Aleatório (Aqui reside o custo de memória)
        for (uint64_t i = 0; i < N; ++i) {
            // Integerify: interpreta o início do último bloco de 64 bytes como uint64_t
            // Nota: interpretamos como Little-Endian explicitamente se necessário
            uint64_t j = *reinterpret_cast<uint64_t*>(&X[(2 * r - 1) * 16]) % N;
            
            // X = X xor V[j]
            for (uint32_t k = 0; k < chunk_size; ++k) {
                X[k] ^= V[j * chunk_size + k];
            }
            
            scryptBlockMix(X.data(), Y.data());
        }

        // 4. B' = X
        std::memcpy(B, X.data(), chunk_bytes);

        // --- LIMPEZA DE SEGURANÇA ---
        CryptoHelper::secure_zero_memory(V.data(), v_total_bytes);
        CryptoHelper::secure_zero_memory(X.data(), chunk_bytes);
        CryptoHelper::secure_zero_memory(Y.data(), chunk_bytes);

        CryptoHelper::unlock_memory(V.data(), v_total_bytes);
        CryptoHelper::unlock_memory(X.data(), chunk_bytes);
        CryptoHelper::unlock_memory(Y.data(), chunk_bytes);
    }


public:
    Scrypt(
        const std::vector<uint8_t> data, const std::vector<uint8_t> salt,
        uint64_t n, uint32_t r,
        uint32_t p, uint32_t dkLen
    ) : N(n), r(r), p(p), dkLen(dkLen), data(data), salt(salt)
    {
    }

    ~Scrypt() {
        CryptoHelper::secure_zero_memory(data.data(), data.size());
        CryptoHelper::secure_zero_memory(salt.data(), salt.size());
    }

    std::vector<uint8_t> kdf() {
        // 1. Initialize B: PBKDF2-HMAC-SHA256
        uint32_t buflen = p * 128 * r;
        std::vector<uint8_t> B_bytes = SHA256::pbkdf2_hmac_sha256(data, salt, 1, buflen);
        
        // Trava imediatamente após a criação
        CryptoHelper::lock_memory(B_bytes.data(), B_bytes.size());

        // Converter para uint32_t LE
        std::vector<uint32_t> B_u32(buflen / 4);
        CryptoHelper::lock_memory(B_u32.data(), B_u32.size() * sizeof(uint32_t));

        for (size_t i = 0; i < B_u32.size(); ++i) {
            B_u32[i] = (uint32_t)B_bytes[i * 4] |
                    ((uint32_t)B_bytes[i * 4 + 1] << 8) |
                    ((uint32_t)B_bytes[i * 4 + 2] << 16) |
                    ((uint32_t)B_bytes[i * 4 + 3] << 24);
        }

        // 2. ROMix paralelo (conceitualmente)
        uint32_t chunk_u32 = 32 * r;
        for (uint32_t i = 0; i < p; ++i) {
            scryptROMix(&B_u32[i * chunk_u32]);
        }

        // Converter de volta para bytes (Little-Endian)
        for (size_t i = 0; i < B_u32.size(); ++i) {
            B_bytes[i * 4]     = (B_u32[i] & 0xFF);
            B_bytes[i * 4 + 1] = (B_u32[i] >> 8) & 0xFF;
            B_bytes[i * 4 + 2] = (B_u32[i] >> 16) & 0xFF;
            B_bytes[i * 4 + 3] = (B_u32[i] >> 24) & 0xFF;
        }

        // 3. Gerar a chave final (DK) - Usando os bytes processados
        std::vector<uint8_t> dk = SHA256::pbkdf2_hmac_sha256(data, B_bytes, 1, dkLen);

        // --- LIMPEZA FINAL OBRIGATÓRIA ---
        CryptoHelper::secure_zero_memory(B_u32.data(), B_u32.size() * sizeof(uint32_t));
        CryptoHelper::secure_zero_memory(B_bytes.data(), B_bytes.size());

        CryptoHelper::unlock_memory(B_u32.data(), B_u32.size() * sizeof(uint32_t));
        CryptoHelper::unlock_memory(B_bytes.data(), B_bytes.size());

        return dk; // Retorna o Derived Key (DK)
    }

};

// How to use:

// std::string p_str = "";
// std::string s_str = "";

// std::vector<uint8_t> password(p_str.begin(), p_str.end());
// std::vector<uint8_t> salt(s_str.begin(), s_str.end());

// uint64_t N = 131072;
// uint32_t r = 8;
// uint32_t p = 1;
// uint32_t dkLen = 32;

// Scrypt scrypt_engine(password, salt, N, r, p, dkLen);
// std::vector<uint8_t> result = scrypt_engine.kdf();