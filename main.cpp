#define GLFW_DLL
#define GLFW_EXPOSE_NATIVE_WIN32
#pragma comment(lib, "wtsapi32.lib")
#include "include/utils/crypto_helpers.hpp"
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include "utils/file_ops.hpp"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#include "utils/crypto_helpers.hpp"
#include "app_state.hpp"
#include "pages_entries.hpp"
#include "pages_login.hpp"
#include "pages_security.hpp"
#include <wtsapi32.h>

StateMachine g_state;

WNDPROC g_GlfwWndProc;

LRESULT CALLBACK SessionGuardCallback(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg == WM_WTSSESSION_CHANGE) {
        if (wParam == WTS_SESSION_LOCK) {
            if (g_state.is_diary_decrypted) {
                Pages::timeout_bridge();
            }
        }
    }
    
    return CallWindowProc(g_GlfwWndProc, hWnd, msg, wParam, lParam);
}

int main(int argc, char* argv[]) {
    if (!glfwInit()) return -1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);
    GLFWwindow* window = glfwCreateWindow(800, 600, "Sanctum Private Diary", NULL, NULL);
    if (!window) { glfwTerminate(); return -1; }
    
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);
    ImGui::StyleColorsDark();

    g_state.currentPage = PageEnum::OPEN_DB;
    g_state.hwnd = glfwGetWin32Window(window);

    HWND win32_hwnd = (HWND)g_state.hwnd;

    g_GlfwWndProc = (WNDPROC)GetWindowLongPtr(win32_hwnd, GWLP_WNDPROC);
    SetWindowLongPtr(win32_hwnd, GWLP_WNDPROC, (LONG_PTR)SessionGuardCallback);

    WTSRegisterSessionNotification(win32_hwnd, NOTIFY_FOR_THIS_SESSION);

    HICON hIcon = LoadIcon(GetModuleHandle(NULL), MAKEINTRESOURCE(101)); 
    SetWindowDisplayAffinity(win32_hwnd, WDA_EXCLUDEFROMCAPTURE);

    if (hIcon) {
        SendMessage(win32_hwnd, WM_SETICON, ICON_BIG, (LPARAM)hIcon);
        SendMessage(win32_hwnd, WM_SETICON, ICON_SMALL, (LPARAM)hIcon);
    }

    if (argc > 1) {
        fs::path file_path(argv[1]);
        if (fs::exists(file_path) && file_path.extension() == ".sdde") {
            g_state.curr_diary = file_path;
            g_state.is_diary_new = false;
            g_state.currentPage = PageEnum::TYPE_PWD;
        }
    }

    ImGui::GetIO().IniFilename = NULL;

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->Pos);
        ImGui::SetNextWindowSize(viewport->Size);
        
        switch(g_state.currentPage) {
            case PageEnum::OPEN_DB:
                Pages::open_diary();
                break;
            case PageEnum::TYPE_PWD:
                Pages::handle_password();
                break;
            case PageEnum::ENTRY_SELECT:
                Pages::entry_select();
                break;
            case PageEnum::CREATE_ENTRY:
                Pages::create_entry();
                break;
            case PageEnum::VIEW_ENTRY:
                Pages::view_entry();
                break;
            case PageEnum::INACTIVE:
                Pages::inactive_screen();
                break;
        }

        ImGui::End();
        // ----------------------------

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.15f, 0.15f, 0.18f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);

        Pages::handle_security_timeout();
    }

    // Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    Pages::cleanup();
    bool key_deleted = CryptoHelper::delete_windows_hello_key(g_state.hello_keyname);

    if (key_deleted) {
        g_state.hello_keyname.clear();
        g_state.keydata.clear();
        std::cout << "Chave deletada com sucesso." << std::endl;
    } else {
        std::cerr << "Erro ao deletar a chave do Windows Hello." << std::endl;
    }

    return 0;
}