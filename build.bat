@echo off
windres resource.rc -o resource.o
clang++ main.cpp -m64 -lcomdlg32 -target x86_64-pc-windows-msvc include/imgui/imgui.cpp include/imgui/imgui_draw.cpp include/imgui/imgui_widgets.cpp include/imgui/imgui_tables.cpp include/imgui/imgui_demo.cpp include/imgui/imgui_impl_glfw.cpp include/imgui/imgui_impl_opengl3.cpp -I./include -I./include/imgui -L./lib -std=c++20 -DNOMINMAX -DGLFW_DLL -O3 -march=native -lglfw3dll -lopengl32 -lncrypt -lgdi32 -luser32 -lshell32 resource.o -flto -fuse-ld=lld -o Sanctum.exe
echo -- Built
Sanctum