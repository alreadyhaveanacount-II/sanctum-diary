#pragma once

#include "imgui/imgui.h"
#include "app_state.hpp"
#include "kdf/scrypt.hpp"
#include "utils/crypto_helpers.hpp"
#include "encryption/aead/chacha20_poly1305.hpp"
#include "utils/file_ops.hpp"
#include "utils/diary_helper.hpp"
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <vector>

namespace Pages {
    void entry_select() {
        ImGui::Begin("Selecione uma entrada", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

        if (ImGui::Button("+ Nova Entrada", ImVec2(-FLT_MIN, 45))) {
            g_state.currentPage = PageEnum::CREATE_ENTRY;
        }

        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::BeginChild("ScrollableList", ImVec2(0, 0), true)) {
            for (size_t i = 1; i < g_state.decrypted_entries.size(); ++i) {
                auto& entry = g_state.decrypted_entries[i];
                
                // Criamos um ID único combinando o índice e o título
                std::string id = entry.title + "##" + std::to_string(i);

                // Bloco vertical (Selectable com altura fixa)
                if (ImGui::Selectable(id.c_str(), g_state.selected_entry_index == i, 0, ImVec2(0, 60))) {
                    g_state.selected_entry_index = i;
                    g_state.currentPage = PageEnum::VIEW_ENTRY;
                    auto& entry = g_state.decrypted_entries[i];
    
                    std::memset(g_state.titleBuf, 0, sizeof(g_state.titleBuf));
                    std::strncpy(g_state.titleBuf, entry.title.c_str(), sizeof(g_state.titleBuf) - 1);
                    
                    std::memset(g_state.contentBuf, 0, sizeof(g_state.contentBuf));
                    std::strncpy(g_state.contentBuf, entry.content.c_str(), sizeof(g_state.contentBuf) - 1);
                }

                // Mostrar uma prévia do conteúdo (opcional)
                ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
                ImGui::SetCursorPosY(ImGui::GetCursorPosY() - 35); // Ajusta para escrever dentro do selectable
                ImGui::TextWrapped("  %.50s...", entry.content.c_str()); 
                ImGui::PopStyleColor();

                ImGui::Spacing();
                ImGui::Separator();
            }
        }
        
        ImGui::EndChild();
    }

    void view_entry() {
        const auto& entry = g_state.decrypted_entries[g_state.selected_entry_index];
        
        // O ID "###view" garante que a janela seja tratada como a mesma pelo ImGui
        std::string title = entry.title + "###view";

        if (ImGui::Begin(title.c_str())) {
            ImGui::Text("Título");
            ImGui::PushItemWidth(-FLT_MIN);
            ImGui::InputText("##title", g_state.titleBuf, sizeof(g_state.titleBuf));
            ImGui::PopItemWidth();
            
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Conteúdo:");

            float altura_disponivel = ImGui::GetContentRegionAvail().y - 120.0f;
            ImGui::InputTextMultiline("##content", g_state.contentBuf, sizeof(g_state.contentBuf), ImVec2(-FLT_MIN, altura_disponivel));

            // Botão para fechar a visualização
            if (ImGui::Button("Fechar Visualização", ImVec2(-FLT_MIN, 30))) {
                g_state.selected_entry_index = -1;
                g_state.currentPage = PageEnum::ENTRY_SELECT;
            }

            if (ImGui::Button("Apagar", ImVec2(-FLT_MIN, 30))) {
                g_state.decrypted_entries.erase(g_state.decrypted_entries.begin() + g_state.selected_entry_index);
                g_state.selected_entry_index = -1;
                g_state.currentPage = PageEnum::ENTRY_SELECT;
                CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
            }

            if (ImGui::Button("Salvar", ImVec2(-FLT_MIN, 30))) {
                if (strlen(g_state.titleBuf) > 0 && strlen(g_state.contentBuf) > 0) {
                    Diary::DiaryEntry new_entry = Diary::add_entry(
                        std::string(g_state.titleBuf), std::string(g_state.contentBuf),
                        g_state.keydata
                    );

                    g_state.decrypted_entries[g_state.selected_entry_index] = new_entry;

                    CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                    CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));

                    g_state.selected_entry_index = -1;
                    g_state.currentPage = PageEnum::ENTRY_SELECT;
                }
            }
        }
    }

    void create_entry() {
        ImGui::Begin("Nova Entrada", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

        ImGui::Text("Título"); // Rótulo no topo
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##title", g_state.titleBuf, sizeof(g_state.titleBuf));

        ImGui::Spacing();
        ImGui::Text("Conteúdo");
        ImGui::InputTextMultiline("##content", g_state.contentBuf, sizeof(g_state.contentBuf), ImVec2(-FLT_MIN, -50));

        ImGui::Spacing();
        if (ImGui::Button("Salvar Entrada", ImVec2(-FLT_MIN, 40))) {
            if (strlen(g_state.titleBuf) > 0 && strlen(g_state.contentBuf) > 0) {
                // 1. Gera a entrada criptografada
                Diary::DiaryEntry entry = Diary::add_entry(g_state.titleBuf, g_state.contentBuf, g_state.keydata);
                
                // 2. Atualiza o estado global
                g_state.decrypted_entries.push_back(entry);
                
                // 3. Salva no arquivo (Append)
                append_binary(g_state.curr_diary, entry.serialized.data(), entry.serialized.size());

                // 4. Limpa os buffers para a próxima
                CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
                
                // Fecha ou muda o estado da UI se necessário
                g_state.currentPage = PageEnum::ENTRY_SELECT;
            }
        }
    }

    void open_diary() {
        static char pathBuffer[256] = "";

        ImGui::Begin("Abrir banco", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

        // Rótulo e Input de Texto para o Caminho
        ImGui::Text("Caminho do Diario (sem extensao):");
        ImGui::InputText("##path", pathBuffer, IM_ARRAYSIZE(pathBuffer));

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // Botões Lado a Lado
        if (ImGui::Button("Abrir Existente")) {
            fs::path file_path(pathBuffer);
            if (file_path.extension() != ".sdde") file_path += ".sdde";

            if(!fs::exists(file_path)) {
                printf("Diario nao existente");
            } else {
                g_state.curr_diary = file_path;
                g_state.is_diary_new = false;
                g_state.currentPage = PageEnum::TYPE_PWD;
            }
        }

        ImGui::SameLine(); // Mantém o próximo item na mesma linha

        if (ImGui::Button("Criar Novo")) {
            fs::path file_path(pathBuffer);

            if (file_path.extension() != ".sdde") file_path += ".sdde";

            uint8_t initial_data[16];
            CryptoHelper::gen_secure_random_bytes(initial_data, 16);

            if(fs::exists(file_path)) {
                printf("Diario ja existe");
            } else {
                save_binary(file_path, initial_data, 16);
                g_state.curr_diary = file_path;
                g_state.is_diary_new = true;
                g_state.currentPage = PageEnum::TYPE_PWD;
            }
        }
    }

    void handle_password() {
        static uint32_t N_exponent = 20; // 2^20 
        static uint32_t r = 8, p = 1, dkLen = 32;

        ImGui::Begin("Senha do Diário", nullptr, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

        ImGui::Text("Digite sua senha:");
        ImGui::InputText("##pwd", g_state.pwdBuffer, IM_ARRAYSIZE(g_state.pwdBuffer), ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);

        ImGui::Separator();
        ImGui::Text("Scrypt Parameters(don't enter any if the file isn't new)");

        uint32_t min_v = 1;
        uint32_t max_v = 20;   

        ImGui::SliderScalar("N exponent(2^N)", ImGuiDataType_U32, &N_exponent, &min_v, &max_v, "%u");

        if(ImGui::InputScalar("r", ImGuiDataType_U32, &r)) {
            if ((uint64_t)r * (uint64_t)p > (1ULL << 30)) {
                r = (uint32_t)((1ULL << 30) / (uint64_t)p);
            }
        }

        if(ImGui::InputScalar("p", ImGuiDataType_U32, &p)) {
            if ((uint64_t)r * (uint64_t)p > (1ULL << 30)) {
                p = (uint32_t)((1ULL << 30) / (uint64_t)r);
            }
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if (ImGui::Button("Entrar")) {
            uint64_t N = 1 << N_exponent;

            // 2. Getting salt
            std::vector<uint8_t> salt = read_file_range(g_state.curr_diary, 0, 16);

            // Deriving key
            std::vector<uint8_t> password(g_state.pwdBuffer, g_state.pwdBuffer + strlen(g_state.pwdBuffer));

            if(!g_state.is_diary_new) {
                std::vector<uint8_t> nrp = read_file_range(g_state.curr_diary, 16, 16);
                N = Diary::from_bytes_le(nrp.data());
                r = Diary::from_bytes_le_u32(nrp.data()+8);
                p = Diary::from_bytes_le_u32(nrp.data()+12);
            }

            Scrypt scryptengine(password, salt, N, r, p, dkLen);
            std::vector<uint8_t> derivated = scryptengine.kdf();

            bool all_went_right = true;

            if(g_state.is_diary_new) {
                Diary::DiaryEntry test_entry = Diary::random_entry(derivated);

                uint8_t params[16];
                Diary::to_bytes_le(N, params);
                Diary::to_bytes_le_u32(r, params+8);
                Diary::to_bytes_le_u32(p, params+12);

                append_binary(g_state.curr_diary, params, 16);
                append_binary(g_state.curr_diary, test_entry.serialized.data(), test_entry.serialized.size());
            } else {
                if(!Diary::test_key(g_state.curr_diary, derivated)) {
                    all_went_right = false;
                    std::cout << "Incorrect key\n";
                }
            }

            if(all_went_right) {
                g_state.currentPage = PageEnum::ENTRY_SELECT;
                g_state.is_diary_decrypted = true;
                g_state.hello_keyname = std::wstring(L"sanctum_hellokey");
                CryptoHelper::create_windows_hello_key(g_state.hello_keyname);

                g_state.keydata = derivated;
                CryptoHelper::lock_memory(g_state.keydata.data(), g_state.keydata.size());
            
                g_state.decrypted_entries = Diary::map_all_entries(g_state.curr_diary, derivated);
                CryptoHelper::lock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size());
            }

            CryptoHelper::secure_zero_memory(derivated.data(), derivated.size());
            CryptoHelper::secure_zero_memory(g_state.pwdBuffer, 256);
        }
    }

    void lock_sensitive_data() {
        if(g_state.is_diary_decrypted) {
            g_state.decrypted_entries[0] = Diary::random_entry(g_state.keydata);
            Diary::save_diary_entries(g_state.curr_diary, g_state.decrypted_entries);
        }

        for (auto& entry : g_state.decrypted_entries) {
            std::fill(entry.title.begin(), entry.title.end(), 0);
            std::fill(entry.content.begin(), entry.content.end(), 0);
            std::fill(entry.serialized.begin(), entry.serialized.end(), 0);
        }

        g_state.decrypted_entries.clear();
        g_state.decrypted_entries.shrink_to_fit();

        g_state.keydata = CryptoHelper::encrypt_with_hello(g_state.hello_keyname, g_state.keydata);
        
        g_state.is_diary_decrypted = false;
    }

    bool unlock_sensitive_data() {
        try {
            g_state.keydata = CryptoHelper::decrypt_with_hello(g_state.hello_keyname, g_state.keydata).value();
            CryptoHelper::lock_memory(g_state.keydata.data(), g_state.keydata.size());
            g_state.decrypted_entries = Diary::map_all_entries(g_state.curr_diary, g_state.keydata);
            CryptoHelper::lock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size());
            g_state.is_diary_decrypted = true;

            return true;
        } catch (...) {
            return false;
        }
    }

    void cleanup() {
        if(g_state.is_diary_decrypted) {
            g_state.decrypted_entries[0] = Diary::random_entry(g_state.keydata);
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

        g_state.decrypted_entries.clear();
        g_state.decrypted_entries.shrink_to_fit();
    }

    void handle_security_timeout() {
        if(g_state.currentPage == PageEnum::OPEN_DB || g_state.currentPage == PageEnum::TYPE_PWD) return;

        double current_time = ImGui::GetTime();
        
        bool is_currently_focused = (GetForegroundWindow() == g_state.hwnd);

        if (!is_currently_focused) {
            if (g_state.was_focused) {
                g_state.last_focused_time = current_time;
                g_state.was_focused = false;
            }

            if (g_state.is_diary_decrypted) {
                double seconds_inactive = current_time - g_state.last_focused_time;
                
                if (seconds_inactive >= 60.0) {
                    lock_sensitive_data();
                    g_state.currentPage = PageEnum::INACTIVE;
                    g_state.was_focused = true; // Reseta para não travar em loop
                    CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                    CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
                }
            }
        } else {
            g_state.was_focused = true;
        }
    }

    void inactive_screen() {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        
        ImGui::Begin("LockScreen", nullptr, 
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove);

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
