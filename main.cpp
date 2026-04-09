#include "include/app_pages.hpp"
#include "include/app_state.hpp"
#include "include/utils/crypto_helpers.hpp"
#define GLFW_DLL
#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>
#include "include/utils/file_ops.hpp"
#include "imgui/imgui.h"
#include "imgui/imgui_impl_glfw.h"
#include "imgui/imgui_impl_opengl3.h"
#include "app_pages.hpp"
#include "app_state.hpp"
#include "utils/crypto_helpers.hpp"

StateMachine g_state;

int main() {
    if (!glfwInit()) return -1;

    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);
    GLFWwindow* window = glfwCreateWindow(800, 600, "CryptoTool - SHA256 & Auth", NULL, NULL);
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

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        // --- Interface do Usuário ---
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        
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
