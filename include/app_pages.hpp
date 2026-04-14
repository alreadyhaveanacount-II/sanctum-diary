#pragma once

#include "imgui/imgui.h"
#include "app_state.hpp"
#include "kdf/scrypt.hpp"
#include "utils/crypto_helpers.hpp"
#include "encryption/aead/chacha20_poly1305.hpp"
#include "utils/file_ops.hpp"
#include "utils/diary_helper.hpp"
#include <cstddef>
#include <cstring>
#include <format>
#include <iomanip>
#include <cstdint>
#include <iostream>
#include <vector>

namespace Pages {
    void entry_select() {
        static char searchBuffer[100] = {};
        static std::vector<size_t> filtered_indices;
        static bool search_active = false;
        static int day = 0, month = 0, year = 0;

        ImGui::Begin("Selecione uma entrada", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);

        // Search input
        ImGui::Text("Pesquisar por texto em título");
        ImGui::InputText("##search", searchBuffer, sizeof(searchBuffer));

        // Date filter inputs
        ImGui::PushItemWidth(40);
        ImGui::InputInt("##day", &day, 0, 0);
        ImGui::SameLine();
        ImGui::Text("/");
        ImGui::SameLine();
        ImGui::InputInt("##month", &month, 0, 0);
        ImGui::SameLine();
        ImGui::Text("/");
        ImGui::SameLine();
        ImGui::PushItemWidth(60);
        ImGui::InputInt("##year", &year, 0, 0);
        ImGui::PopItemWidth();
        ImGui::SameLine();
        ImGui::Text("(DD/MM/YYYY)");

        // Search button
        if (ImGui::Button("Pesquisar", ImVec2(-FLT_MIN, 20))) {
            filtered_indices.clear();
            search_active = true;

            std::string searchStr = searchBuffer;
            std::transform(searchStr.begin(), searchStr.end(), searchStr.begin(), ::tolower);

            for (size_t i = 0; i < g_state.decrypted_entries.size(); ++i) {
                auto& entry = g_state.decrypted_entries[i];
                bool match = true;

                // Text search
                if (!searchStr.empty()) {
                    std::string titleLower = entry.title;
                    std::transform(titleLower.begin(), titleLower.end(), titleLower.begin(), ::tolower);
                    if (titleLower.find(searchStr) == std::string::npos)
                        match = false;
                }

                // Date filter
                if (match && (day != 0 || month != 0 || year != 0)) {
                    auto tp = std::chrono::system_clock::time_point{
                        std::chrono::milliseconds{entry.timestamp}
                    };
                    auto lt = std::chrono::current_zone()->to_local(tp);
                    auto days_floor = std::chrono::floor<std::chrono::days>(lt);
                    std::chrono::year_month_day ymd{days_floor};

                    if (day != 0 && (int)(unsigned)ymd.day() != day) match = false;
                    if (month != 0 && (int)(unsigned)ymd.month() != month) match = false;
                    if (year != 0 && (int)ymd.year() != year) match = false;
                }

                if (match)
                    filtered_indices.push_back(i);
            }
        }

        ImGui::Separator();
        ImGui::Spacing();

        // New entry button
        if (ImGui::Button("+ Nova Entrada", ImVec2(-FLT_MIN, 45))) {
            CryptoHelper::secure_zero_memory(searchBuffer, sizeof(searchBuffer));
            filtered_indices.clear();
            search_active = false;
            day = month = year = 0;
            g_state.currentPage = PageEnum::CREATE_ENTRY;
        }

        ImGui::Separator();
        ImGui::Spacing();

        // Scrollable list
        if (ImGui::BeginChild("ScrollableList", ImVec2(0, 0), true)) {
            if (g_state.decrypted_entries.empty()) {
                ImGui::TextDisabled("Nenhuma entrada encontrada. Crie uma nova entrada.");
            } else {
                size_t render_count = search_active ? filtered_indices.size() : g_state.decrypted_entries.size();

                for (size_t render_idx = 0; render_idx < render_count; ++render_idx) {
                    // Get the REAL index into decrypted_entries
                    size_t real_index = search_active ? filtered_indices[render_idx] : render_idx;
                    auto& entry = g_state.decrypted_entries[real_index];
                    bool isSelected = (g_state.selected_entry_index == real_index);

                    std::string selectableId = entry.title + "##" + std::to_string(real_index);

                    ImGui::BeginGroup();

                    // Selectable entry
                    if (ImGui::Selectable(
                            selectableId.c_str(),
                            isSelected,
                            ImGuiSelectableFlags_AllowOverlap,
                            ImVec2(0, 60)))
                    {
                        g_state.selected_entry_index = real_index;

                        // Copy title and content to buffers
                        CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                        std::strncpy(g_state.titleBuf, entry.title.c_str(), sizeof(g_state.titleBuf) - 1);
                        g_state.titleBuf[sizeof(g_state.titleBuf) - 1] = '\0';

                        CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
                        std::strncpy(g_state.contentBuf, entry.content.c_str(), sizeof(g_state.contentBuf) - 1);
                        g_state.contentBuf[sizeof(g_state.contentBuf) - 1] = '\0';

                        // Reset search state
                        CryptoHelper::secure_zero_memory(searchBuffer, sizeof(searchBuffer));
                        filtered_indices.clear();
                        search_active = false;
                        day = month = year = 0;

                        g_state.currentPage = PageEnum::VIEW_ENTRY;
                    }

                    // Timestamp display (top-right corner of entry)
                    {
                        auto tp_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(
                            std::chrono::system_clock::time_point{std::chrono::milliseconds{entry.timestamp}}
                        );
                        auto local_tp = std::chrono::current_zone()->to_local(tp_ms);
                        std::string full_date = std::format("{:%d/%m/%Y, %H:%M:%S}", local_tp);

                        float dateWidth = ImGui::CalcTextSize(full_date.c_str()).x;
                        float posX = ImGui::GetWindowWidth() - dateWidth - ImGui::GetStyle().ScrollbarSize - ImGui::GetStyle().WindowPadding.x;

                        ImVec2 savedCursor = ImGui::GetCursorPos();
                        ImGui::SetCursorPos(ImVec2(posX, savedCursor.y - 60));
                        ImGui::TextDisabled("%s", full_date.c_str());
                        ImGui::SetCursorPos(savedCursor);
                    }

                    // Content preview
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.7f, 0.7f, 0.7f, 1.0f));
                    ImGui::TextWrapped("  %.50s...", entry.content.c_str());
                    ImGui::PopStyleColor();

                    ImGui::EndGroup();

                    ImGui::Spacing();
                    ImGui::Separator();
                }
            }
        }
        ImGui::EndChild();
    }

    void view_entry() {
        const auto& entry = g_state.decrypted_entries[g_state.selected_entry_index];
        
        // O ID "###view" garante que a janela seja tratada como a mesma pelo ImGui
        std::string title = entry.title + "###view";

        if (ImGui::Begin(title.c_str())) {
            auto tp_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::time_point{std::chrono::milliseconds{entry.timestamp}}
            );

            auto local_tp = std::chrono::current_zone()->to_local(tp_ms);
            std::string full_date = std::format("{:%d/%m/%Y, %H:%M:%S}", local_tp);

            ImGui::Text("Data: %s", full_date.c_str());
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::Text("Título");
            ImGui::PushItemWidth(-FLT_MIN);
            ImGui::InputText("##title", g_state.titleBuf, sizeof(g_state.titleBuf));
            ImGui::PopItemWidth();
            ImGui::Separator();
            
            ImGui::Separator();
            ImGui::Spacing();

            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.4f, 1.0f), "Conteúdo:");

            float altura_disponivel = ImGui::GetContentRegionAvail().y - 120.0f;

            ImGui::InputTextMultiline("##content", g_state.contentBuf, sizeof(g_state.contentBuf), ImVec2(-FLT_MIN, altura_disponivel), ImGuiInputTextFlags_AllowTabInput);

            // Botão para fechar a visualização
            if (ImGui::Button("Fechar Visualização", ImVec2(-FLT_MIN, 30))) {
                g_state.selected_entry_index = -1;
                g_state.currentPage = PageEnum::ENTRY_SELECT;
                CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
                CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
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
                        g_state.keydata, g_state.decrypted_entries[g_state.selected_entry_index].timestamp
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
        ImGui::Begin("Nova Entrada", nullptr, ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoBringToFrontOnFocus);

        ImGui::Text("Título"); // Rótulo no topo
        ImGui::SetNextItemWidth(-FLT_MIN);
        ImGui::InputText("##title", g_state.titleBuf, sizeof(g_state.titleBuf));

        ImGui::Spacing();
        ImGui::Text("Conteúdo");
        
        ImGui::InputTextMultiline("##content", g_state.contentBuf, sizeof(g_state.contentBuf), ImVec2(-FLT_MIN, -85), ImGuiInputTextFlags_AllowTabInput); 

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

        if (ImGui::Button("Fechar Visualização", ImVec2(-FLT_MIN, 30))) {
            g_state.currentPage = PageEnum::ENTRY_SELECT;
            CryptoHelper::secure_zero_memory(g_state.titleBuf, sizeof(g_state.titleBuf));
            CryptoHelper::secure_zero_memory(g_state.contentBuf, sizeof(g_state.contentBuf));
        }
    }

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
                CryptoHelper::create_windows_hello_key(g_state.hello_keyname);

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

        ImGui::PopStyleVar(2);
    }

    void lock_sensitive_data() {
        if(g_state.is_diary_decrypted) {
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
            Diary::map_all_entries(g_state.decrypted_entries, g_state.curr_diary, g_state.keydata);
            CryptoHelper::lock_memory(g_state.decrypted_entries.data(), g_state.decrypted_entries.size());
            g_state.is_diary_decrypted = true;

            return true;
        } catch (...) {
            return false;
        }
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