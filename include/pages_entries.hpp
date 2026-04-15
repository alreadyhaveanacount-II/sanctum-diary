#pragma once

#include "imgui/imgui.h"
#include "app_state.hpp"
#include "utils/crypto_helpers.hpp"
#include "utils/file_ops.hpp"
#include "utils/diary_helper.hpp"
#include <cstddef>
#include <cstring>
#include <format>
#include <iomanip>
#include <cstdint>
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
}