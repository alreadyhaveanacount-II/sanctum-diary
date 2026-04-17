#pragma once

#include "imgui/imgui.h"
#include "app_state.hpp"
#include "kdf/scrypt.hpp"
#include "utils/crypto_helpers.hpp"
#include "utils/file_ops.hpp"
#include "utils/diary_helper.hpp"
#include <cstddef>
#include <cstring>
#include <cstdint>
#include <iostream>
#include <vector>

namespace Pages {
    void open_diary() {
        ImGui::Begin("Abrir banco", nullptr, 
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);

        // 2. Configurações de tamanho
        ImVec2 button_size = ImVec2(300, 50);
        float window_width = ImGui::GetWindowSize().x;
        float window_height = ImGui::GetWindowSize().y;
        
        // Calcula o bloco central (2 botões + espaçamento)
        float total_height = (button_size.y * 2) + ImGui::GetStyle().ItemSpacing.y;
        float start_x = (window_width - button_size.x) * 0.5f;
        float start_y = (window_height - total_height) * 0.5f;

        // 4. Botão: Abrir Existente
        ImGui::SetCursorPos(ImVec2(start_x, start_y));
        if (ImGui::Button("ABRIR EXISTENTE", button_size)) {
            std::string path = CryptoHelper::OpenFileDialog((HWND)g_state.hwnd);
            if (!path.empty()) {
                fs::path file_path(path);

                if (file_path.extension() != ".sdde") file_path += ".sdde";

                if (fs::exists(file_path)) {
                    g_state.curr_diary = file_path;
                    g_state.is_diary_new = false;
                    g_state.currentPage = PageEnum::TYPE_PWD;
                }
            }
        }

        // 5. Botão: Criar Novo
        ImGui::SetCursorPosX(start_x);
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.12f, 0.35f, 0.60f, 1.0f)); // Azul Sanctum
        if (ImGui::Button("CRIAR NOVO DIÁRIO", button_size)) {
            std::string path = CryptoHelper::SaveFileDialog((HWND)g_state.hwnd);
            if (!path.empty()) {
                fs::path file_path(path);
                if (file_path.extension() != ".sdde") file_path += ".sdde";

                uint8_t initial_data[16];
                CryptoHelper::gen_secure_random_bytes(initial_data, 16);
                
                save_binary(file_path, initial_data, 16);
                g_state.curr_diary = file_path;
                g_state.is_diary_new = true;
                g_state.currentPage = PageEnum::TYPE_PWD;
            }
        }
        ImGui::PopStyleColor();
    }

    void derivate_key(std::vector<uint8_t>& result, char* password, const std::vector<uint8_t>& salt, uint64_t N, uint32_t r, uint32_t p) {
        std::vector<uint8_t> temp_pwd(password, password+strlen(password));
        Scrypt scryptengine(temp_pwd, salt, N, r, p, 32);
        result = scryptengine.kdf();
        CryptoHelper::secure_zero_memory(temp_pwd.data(), temp_pwd.size());
    }

    void handle_password() {
        static uint32_t N_exponent = 20; 
        static uint32_t r = 8, p = 1, dkLen = 32;
        static char dummyPassword[256] = "";
        static std::string dummyPath;

        // Estilo mais "limpo"
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(20, 20));
        ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 6));

        ImGui::Begin("Senha do Diário", nullptr, 
            ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove);

        // Título e Subtítulo
        ImGui::TextDisabled("SISTEMA DE CRIPTOGRAFIA");
        ImGui::Text("Acesso ao Diário");
        ImGui::Separator();
        ImGui::Spacing();

        // 2. Campo de Senha em destaque
        ImGui::Text("Digite sua senha mestre:");
        ImGui::SetNextItemWidth(-1);
        bool enterPressed = ImGui::InputText("##pwd", g_state.pwdBuffer, IM_ARRAYSIZE(g_state.pwdBuffer), 
                                            ImGuiInputTextFlags_Password | ImGuiInputTextFlags_EnterReturnsTrue);

        ImGui::Spacing();

        // 3. Botão de Entrar (Estilizado)
        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.26f, 0.59f, 0.98f, 1.0f));
        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.35f, 0.65f, 1.0f, 1.0f));
        if (ImGui::Button("DESBLOQUEAR DIÁRIO", ImVec2(-1, 45)) || enterPressed) {
            uint64_t N = 1 << N_exponent;

            // 2. Getting salt
            std::vector<uint8_t> salt = read_file_range(g_state.curr_diary, 0, 16);

            if(!g_state.is_diary_new) {
                std::vector<uint8_t> nrp = read_file_range(g_state.curr_diary, 16, 16);
                N = Diary::from_bytes_le(nrp.data());
                r = Diary::from_bytes_le_u32(nrp.data()+8);
                p = Diary::from_bytes_le_u32(nrp.data()+12);
            }

            std::vector<uint8_t> derivated;
            derivate_key(derivated, g_state.pwdBuffer, salt, N, r, p);

            bool all_went_right = true;

            if(g_state.is_diary_new) {
                Diary::DiaryEntry test_entry = Diary::random_entry(derivated);

                uint8_t params[16];
                Diary::to_bytes_le(N, params);
                Diary::to_bytes_le_u32(r, params+8);
                Diary::to_bytes_le_u32(p, params+12);

                append_binary(g_state.curr_diary, params, 16);
                append_binary(g_state.curr_diary, test_entry.serialized.data(), test_entry.serialized.size());
                
                if(dummyPath.empty()) {
                    // Generating a random invalid entry
                    std::vector<uint8_t> random_key(32, 0);
                    CryptoHelper::gen_secure_random_bytes(random_key.data(), 32);
                    test_entry = Diary::random_entry(random_key);
                    append_binary(g_state.curr_diary, test_entry.serialized.data(), test_entry.serialized.size());
                    CryptoHelper::secure_zero_memory(random_key.data(), 32);
                } else {
                    uint8_t fake_data[1160];
                    CryptoHelper::gen_secure_random_bytes(fake_data, 1160);
                    append_binary(fs::path(dummyPath), fake_data, 1160);

                    // Generating the dummy entry
                    std::vector<uint8_t> fake_derivated;
                    derivate_key(fake_derivated, dummyPassword, salt, N, r, p);

                    uint8_t random_title_byte;
                    CryptoHelper::gen_secure_random_bytes(&random_title_byte, 1);

                    uint8_t random_body[511];

                    size_t path_size = dummyPath.size();
                    size_t copy_len = (path_size + 1 <= 511) ? path_size + 1 : 511;

                    std::memcpy(random_body, dummyPath.c_str(), copy_len);

                    if (copy_len < 511) {
                        CryptoHelper::gen_secure_random_bytes(random_body + copy_len, 511 - copy_len);
                    }

                    Diary::DiaryEntry dummy_entry = Diary::add_entry(
                        std::string(reinterpret_cast<const char*>(&random_title_byte), 1), 
                        std::string(reinterpret_cast<const char*>(random_body), 511), 
                        fake_derivated
                    );

                    append_binary(g_state.curr_diary, dummy_entry.serialized.data(), dummy_entry.serialized.size());
                }
            } else {
                if(!Diary::test_key(g_state.curr_diary, derivated)) {
                    all_went_right = false;
                    std::optional<std::string> duress_path = Diary::get_duress_path(g_state.curr_diary, derivated);
                    
                    if(duress_path) {
                        all_went_right = true;
                        g_state.curr_diary = fs::path(*duress_path);
                    } else {
                        std::cout << "Incorrect password";
                    }
                }
            }

            if(all_went_right) {
                g_state.currentPage = PageEnum::ENTRY_SELECT;
                g_state.is_diary_decrypted = true;
                g_state.hello_keyname = std::wstring(L"sanctum_hellokey");
                while(!CryptoHelper::create_windows_hello_key(g_state.hello_keyname)) {
                    continue;
                }

                g_state.keydata = derivated;
                CryptoHelper::lock_memory(g_state.keydata.data(), g_state.keydata.size());

                Diary::map_all_entries(g_state.decrypted_entries, g_state.curr_diary, derivated);
                CryptoHelper::lock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size());

                dummyPath.clear();
                CryptoHelper::secure_zero_memory(dummyPassword, sizeof(dummyPassword));
            }

            CryptoHelper::secure_zero_memory(derivated.data(), derivated.size());
            CryptoHelper::secure_zero_memory(g_state.pwdBuffer, 256);
        }
        ImGui::PopStyleColor(2);

        // 4. Configurações Avançadas (Recolhível)
        ImGui::Spacing();
        ImGui::Separator();
        if (ImGui::TreeNode("Parâmetros Scrypt (Avançado)")) {
            ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(4, 4));
            
            if (!g_state.is_diary_new) {
                ImGui::BeginDisabled();
                ImGui::TextWrapped("Nota: Parâmetros lidos do arquivo existente.");
            }

            uint32_t min_v = 1, max_v = 20;   
            ImGui::Text("N exponent (2^N):");
            ImGui::SetNextItemWidth(-1);
            ImGui::SliderScalar("##N", ImGuiDataType_U32, &N_exponent, &min_v, &max_v, "%u");

            ImGui::Columns(2, "params", false);
            ImGui::Text("Parâmetro r:");
            ImGui::SetNextItemWidth(-1);
            if(ImGui::InputScalar("##r", ImGuiDataType_U32, &r)) {
                if ((uint64_t)r * (uint64_t)p > (1ULL << 30)) r = (uint32_t)((1ULL << 30) / (uint64_t)p);
            }

            ImGui::NextColumn();
            ImGui::Text("Parâmetro p:");
            ImGui::SetNextItemWidth(-1);
            if(ImGui::InputScalar("##p", ImGuiDataType_U32, &p)) {
                if ((uint64_t)r * (uint64_t)p > (1ULL << 30)) p = (uint32_t)((1ULL << 30) / (uint64_t)r);
            }
            ImGui::Columns(1);

            if (!g_state.is_diary_new) ImGui::EndDisabled();

            ImGui::PopStyleVar();
            ImGui::TreePop();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        if(g_state.is_diary_new) {
            if (ImGui::TreeNode("Senha secundária")) {
                ImGui::Text("Digite uma senha secundária:");
                ImGui::SetNextItemWidth(-1);
                ImGui::InputText("##dummy_pwd", dummyPassword, IM_ARRAYSIZE(dummyPassword));

                ImGui::Spacing();

                ImGui::Text("Caminho do Diário falso:");
                ImGui::SetNextItemWidth(-1);

                ImGui::InputText("##dummy_path", (char*)dummyPath.c_str(), dummyPath.size() + 1, ImGuiInputTextFlags_ReadOnly);
                ImGui::Spacing();

                if (ImGui::Button("CRIAR DIÁRIO FALSO", ImVec2(-1, 30))) {
                    dummyPath = CryptoHelper::SaveFileDialog((HWND)g_state.hwnd, false);
                }

                ImGui::TreePop();
            }
        }

        ImGui::PopStyleVar(2);
    }
}