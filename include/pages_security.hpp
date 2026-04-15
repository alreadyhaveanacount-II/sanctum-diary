#pragma once

#include "imgui/imgui.h"
#include "app_state.hpp"
#include "utils/crypto_helpers.hpp"
#include "utils/file_ops.hpp"
#include "utils/diary_helper.hpp"
#include <cstdint>
#include <vector>

namespace Pages {
    void lock_sensitive_data() {
        if(!g_state.is_diary_decrypted) return;

        Diary::save_diary_entries(g_state.curr_diary, g_state.decrypted_entries);

        for (auto& entry : g_state.decrypted_entries) {
            CryptoHelper::secure_zero_memory(entry.title.data(), entry.title.size());
            CryptoHelper::secure_zero_memory(entry.content.data(), entry.content.size());
            CryptoHelper::secure_zero_memory(entry.serialized.data(), entry.serialized.size());
        }

        std::vector<uint8_t> enc_key = CryptoHelper::encrypt_with_hello(g_state.hello_keyname, g_state.keydata);

        CryptoHelper::secure_zero_memory(g_state.keydata.data(), g_state.keydata.size());
        CryptoHelper::unlock_memory(g_state.keydata.data(), g_state.keydata.size());

        if(!enc_key.empty()) g_state.keydata = std::move(enc_key);
        
        g_state.decrypted_entries.clear();
        g_state.is_diary_decrypted = false;
    }

    bool unlock_sensitive_data() {
        auto decrypted_opt = CryptoHelper::decrypt_with_hello(g_state.hello_keyname, g_state.keydata);
        
        if (!decrypted_opt.has_value() || decrypted_opt->empty()) {
            return false;
        }

        std::vector<uint8_t> temp = std::move(decrypted_opt.value());

        try {
            g_state.keydata = temp;
            CryptoHelper::lock_memory(g_state.keydata.data(), g_state.keydata.size());
            
            Diary::map_all_entries(g_state.decrypted_entries, g_state.curr_diary, g_state.keydata);
            CryptoHelper::lock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size());

            g_state.is_diary_decrypted = true;
        } catch (...) {
            CryptoHelper::secure_zero_memory(temp.data(), temp.size());
            throw;
        }

        CryptoHelper::secure_zero_memory(temp.data(), temp.size());
        return true;
    }

    void cleanup() {
        if(g_state.is_diary_decrypted) {
            Diary::save_diary_entries(g_state.curr_diary, g_state.decrypted_entries);
        }

        for (auto& entry : g_state.decrypted_entries) {
            CryptoHelper::secure_zero_memory((void*)entry.title.data(), entry.title.size());
            CryptoHelper::secure_zero_memory((void*)entry.content.data(), entry.content.size());
            CryptoHelper::secure_zero_memory(entry.serialized.data(), entry.serialized.size());
        }

        CryptoHelper::secure_zero_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size() * sizeof(Diary::DiaryEntry));
        CryptoHelper::secure_zero_memory(g_state.keydata.data(), g_state.keydata.size());

        CryptoHelper::unlock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size() * sizeof(Diary::DiaryEntry));
        CryptoHelper::unlock_memory(g_state.keydata.data(), g_state.keydata.size());
        
        CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
        CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));

        g_state.decrypted_entries.clear();
        g_state.decrypted_entries.shrink_to_fit();
    }

    void timeout_bridge() {
        lock_sensitive_data();
        g_state.currentPage = PageEnum::INACTIVE;
        CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
        CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
    }

    void handle_security_timeout() {
        if(g_state.currentPage == PageEnum::OPEN_DB || g_state.currentPage == PageEnum::TYPE_PWD) return;

        double current_time = ImGui::GetTime();
        
        LASTINPUTINFO lii = { sizeof(LASTINPUTINFO) };

        if (GetLastInputInfo(&lii)) {
            DWORD idleTime = GetTickCount64() - lii.dwTime;
            
            if (idleTime > 120000 && g_state.is_diary_decrypted) { // 2 minutes
                timeout_bridge();
            }
        }
    }

    void inactive_screen() {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        
        ImGui::Begin("LockScreen", nullptr, 
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);

        float window_width = ImGui::GetWindowSize().x;
        float window_height = ImGui::GetWindowSize().y;
        float button_width = 250.0f;
        float button_height = 60.0f;

        ImGui::SetCursorPos(ImVec2((window_width - button_width) * 0.5f, (window_height - button_height) * 0.5f));
        
        if (ImGui::Button("Desbloquear Diário", ImVec2(button_width, button_height))) {
            if(unlock_sensitive_data()) {
                g_state.currentPage = PageEnum::ENTRY_SELECT;
            }
        }
    }
}