@echo off
clang++ main.cpp include/imgui/imgui.cpp include/imgui/imgui_draw.cpp include/imgui/imgui_widgets.cpp include/imgui/imgui_tables.cpp include/imgui/imgui_demo.cpp include/imgui/imgui_impl_glfw.cpp include/imgui/imgui_impl_opengl3.cpp -I./include -I./include/imgui -L./lib -std=c++20 -DNOMINMAX -DGLFW_DLL -O3 -march=native -lglfw3dll -lopengl32 -lgdi32 -luser32 -lshell32 -o main.exe
echo -- Built
main