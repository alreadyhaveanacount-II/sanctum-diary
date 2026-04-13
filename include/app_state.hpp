#pragma once
#include <filesystem>
#include <windows.h>
#include "imgui/imgui.h"
#include "utils/diary_helper.hpp"
namespace fs = std::filesystem;

enum class PageEnum { INACTIVE, OPEN_DB, TYPE_PWD, ENTRY_SELECT, CREATE_ENTRY, VIEW_ENTRY };

struct StateMachine {
    fs::path curr_diary;
    PageEnum currentPage = PageEnum::OPEN_DB;
    std::wstring hello_keyname;
    std::vector<uint8_t> keydata;
    HANDLE hwnd;
    bool dummy_mode;
    double last_focused_time;
    std::vector<Diary::DiaryEntry> decrypted_entries;
    char titleBuf[128];
    char contentBuf[4096];
    char pwdBuffer[256];
    int selected_entry_index;
    bool is_diary_decrypted;
    bool is_diary_new;
};

extern StateMachine g_state; // Declaração global
