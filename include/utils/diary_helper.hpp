#pragma once
#include "file_ops.hpp"
#include "crypto_helpers.hpp"
#include "encryption/aead/chacha20_poly1305.hpp"
#include <cstdint>
#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <chrono>
#include <optional>
#define DIARY_ENTRIES_START 32
#define DIARY_ENTRY_HEADER_SIZE 52
#define TRUE_ENTRIES_START 1160

namespace Diary {
    struct DiaryEntry {
        std::string title;
        std::string content;
        std::vector<uint8_t> serialized;
        size_t starts_at;
        uint64_t timestamp;

        ~DiaryEntry() {
            CryptoHelper::secure_zero_memory((char*)title.data(), title.size());
            CryptoHelper::secure_zero_memory((char*)content.data(), content.size());
        }
    };

    void to_bytes_le(uint64_t val, uint8_t* arr) {
        arr[0] = (uint8_t)(val & 0xFF);
        arr[1] = (uint8_t)((val >> 8) & 0xFF);
        arr[2] = (uint8_t)((val >> 16) & 0xFF);
        arr[3] = (uint8_t)((val >> 24) & 0xFF);
        arr[4] = (uint8_t)((val >> 32) & 0xFF);
        arr[5] = (uint8_t)((val >> 40) & 0xFF);
        arr[6] = (uint8_t)((val >> 48) & 0xFF);
        arr[7] = (uint8_t)((val >> 56) & 0xFF);
    }

    uint64_t from_bytes_le(uint8_t* arr) {
        return  (uint64_t)arr[0]       |
           ((uint64_t)arr[1] << 8)     |
           ((uint64_t)arr[2] << 16)    |
           ((uint64_t)arr[3] << 24)    |
           ((uint64_t)arr[4] << 32)    |
           ((uint64_t)arr[5] << 40)    |
           ((uint64_t)arr[6] << 48)    |
           ((uint64_t)arr[7] << 56);
    }

    void to_bytes_le_u32(uint32_t val, uint8_t* arr) {
        arr[0] = (uint8_t)(val & 0xFF);
        arr[1] = (uint8_t)((val >> 8) & 0xFF);
        arr[2] = (uint8_t)((uint32_t)val >> 16 & 0xFF);
        arr[3] = (uint8_t)((uint32_t)val >> 24 & 0xFF);
    }

    uint32_t from_bytes_le_u32(uint8_t* arr) {
        return  (uint32_t)arr[0]        |
            ((uint32_t)arr[1] << 8)  |
            ((uint32_t)arr[2] << 16) |
            ((uint32_t)arr[3] << 24);
    }

    DiaryEntry add_entry(const std::string& title, const std::string& content, const std::vector<uint8_t>& plain_key, uint64_t timestamp_=0) {
        DiaryEntry new_entry;
        new_entry.title = title;
        new_entry.content = content;
        uint32_t nonce[3];
        uint8_t tag[16];
        CryptoHelper::gen_secure_random_bytes((uint8_t*)nonce, 12);

        uint8_t timestamp[8];
        auto duration = std::chrono::system_clock::now().time_since_epoch();
        uint64_t millis = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(duration).count());
        new_entry.timestamp = (timestamp_ == 0) ? millis : timestamp_;

        to_bytes_le(new_entry.timestamp, timestamp);

        // 1. Prepara os dados para criptografia (Título + Conteúdo)'
        size_t total_payload = title.size() + content.size();
        std::vector<uint8_t> ciphertext(total_payload);
        std::memcpy(ciphertext.data(), title.data(), title.size());
        std::memcpy(ciphertext.data()+title.size(), content.data(), content.size());

        // 2. Criptografa in-place
        CHACHA20_POLY1305::encrypt(
            (uint32_t*) plain_key.data(), (uint32_t*) nonce,
            ciphertext.data(), ciphertext.size(),
            timestamp, 8,
            ciphertext.data(), tag
        );

        // 3. Monta o pacote final (Tag[16] + Nonce[12] + TitleLen[8] + ContentLen[8] + Ciphertext[N])
        std::vector<uint8_t> final_entry;
        final_entry.resize(DIARY_ENTRY_HEADER_SIZE + ciphertext.size());

        uint8_t* p = final_entry.data();
        std::memcpy(p,      tag, 16);
        std::memcpy(p + 16, nonce, 12);
        to_bytes_le((uint64_t)title.size(), p + 28);
        to_bytes_le((uint64_t)content.size(), p + 36);
        to_bytes_le(new_entry.timestamp, p + 44);
        std::memcpy(p + DIARY_ENTRY_HEADER_SIZE, ciphertext.data(), ciphertext.size());

        new_entry.serialized = std::move(final_entry);

        return new_entry;
    }

    DiaryEntry random_entry(const std::vector<uint8_t>& plain_key) {
        uint8_t random_title;
        CryptoHelper::gen_secure_random_bytes(&random_title, 1);

        uint8_t random_body[511];
        CryptoHelper::gen_secure_random_bytes(random_body, 511);

        return add_entry(std::string(reinterpret_cast<char*>(&random_title), 1), std::string(reinterpret_cast<char*>(random_body), 511), plain_key);
    }

    std::optional<DiaryEntry> read_next_entry(uint8_t*& ptr, size_t& at, const std::vector<uint8_t>& plain_key) {
        uint8_t tag[16];
        uint8_t nonce[12];
        uint8_t timestamp_bytes[8];
        uint64_t title_len = from_bytes_le(ptr+28);
        uint64_t content_len = from_bytes_le(ptr+36);
        uint64_t timestamp = from_bytes_le(ptr+44);

        to_bytes_le(timestamp, timestamp_bytes);

        std::memcpy(tag, ptr, 16);
        std::memcpy(nonce, ptr+16, 12);

        uint64_t total_cipher_len = title_len + content_len;
        std::vector<uint8_t> ciphertext(total_cipher_len);
        std::memcpy(ciphertext.data(), ptr+DIARY_ENTRY_HEADER_SIZE, total_cipher_len);

        try {
            CHACHA20_POLY1305::decrypt(
                (uint32_t*) plain_key.data(), (uint32_t*) nonce, 
                ciphertext.data(), ciphertext.size(),
                timestamp_bytes, 8,
                tag, ciphertext.data()
            );

            DiaryEntry new_entry;
            new_entry.title = std::string(ciphertext.begin(), ciphertext.begin() + title_len);
            new_entry.content = std::string(ciphertext.begin() + title_len, ciphertext.end());
            new_entry.timestamp = timestamp;

            new_entry.starts_at = at;
            
            size_t total_entry_len = DIARY_ENTRY_HEADER_SIZE + total_cipher_len;
            new_entry.serialized.assign(ptr, ptr + total_entry_len);

            ptr += total_entry_len;
            at += total_entry_len;

            return new_entry;
        } catch (...) {
            return std::nullopt;
        }
    }

    bool test_key(
        const fs::path& diary_path,
        const std::vector<uint8_t>& plain_key
    ) {
        std::vector<uint8_t> block = read_file_range(diary_path, DIARY_ENTRIES_START, DIARY_ENTRY_HEADER_SIZE + 512);
        
        if (block.size() < DIARY_ENTRY_HEADER_SIZE) return false;

        uint8_t* ptr = block.data();
        size_t at = 0;
        auto entry = read_next_entry(ptr, at, plain_key);

        if (entry) return true;

        return false;
    }

    void skip_entry(uint8_t*& ptr, size_t& at) {
        uint64_t title_len = from_bytes_le(ptr+28);
        uint64_t content_len = from_bytes_le(ptr+36);
        ptr += DIARY_ENTRY_HEADER_SIZE + title_len + content_len;
        at += DIARY_ENTRY_HEADER_SIZE + title_len + content_len;
    }

    std::optional<std::string> get_duress_path(const fs::path& diary_path, const std::vector<uint8_t>& plain_key) {
        std::vector<uint8_t> block = read_file_range(diary_path, 596, 564);
        
        if (block.size() < DIARY_ENTRY_HEADER_SIZE) return std::nullopt;

        uint8_t* ptr = block.data();
        size_t at = 0;
        auto entry = read_next_entry(ptr, at, plain_key);

        if (entry) return std::string(entry->content.c_str());

        return std::nullopt;
    }

    void map_all_entries(
        std::vector<DiaryEntry>& entries,
        const fs::path& diary_path,
        const std::vector<uint8_t>& plain_key
    ) {
        entries.clear();
        
        size_t file_size = get_file_size(diary_path);
        if (file_size <= 16) return;

        std::vector<uint8_t> data = read_file_range(diary_path, TRUE_ENTRIES_START, file_size - TRUE_ENTRIES_START);
        
        uint8_t* ptr = data.data();
        size_t at = 0;
        size_t total_buffer_size = data.size();

        while (at < total_buffer_size) {
            if (total_buffer_size - at < DIARY_ENTRY_HEADER_SIZE) break;

            auto entry = read_next_entry(ptr, at, plain_key);
            
            if (entry.has_value()) {
                entries.push_back(std::move(*entry));
            } else {
                std::cout << "Invalid Entry" << std::endl;
                break;
            }
        }
    }

    void save_diary_entries(const fs::path& diary_path, const std::vector<DiaryEntry>& entries) {
        if(entries.empty()) return;

        size_t total_entry_size = 0;
        for (const auto& entry : entries) {
            total_entry_size += entry.serialized.size();
        }

        std::vector<uint8_t> encrypted_data(total_entry_size);
        uint8_t* data_ptr = encrypted_data.data();

        for (const auto& entry : entries) {
            std::memcpy(data_ptr, entry.serialized.data(), entry.serialized.size());
            data_ptr += entry.serialized.size();
        }

        truncate_file(diary_path, TRUE_ENTRIES_START);
        rewrite_binary_section(diary_path, encrypted_data.data(), encrypted_data.size(), TRUE_ENTRIES_START);
    }
}