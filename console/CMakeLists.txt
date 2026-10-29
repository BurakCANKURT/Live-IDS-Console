cmake_minimum_required(VERSION 3.16)
project(ids_native_dashboard CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# MSYS2 MinGW-w64 prefix (GLFW static lib + headers). Override with
#   cmake -DMINGW_PREFIX=D:/msys64/mingw64 ...
set(MINGW_PREFIX "C:/msys64/mingw64" CACHE PATH "MSYS2 mingw64 prefix")

# ── Dear ImGui + ImPlot ─────────────────────────────────────────────────────
# Fetched at configure time at pinned tags, so the repo does not vendor them.
# To build offline, point IMGUI_DIR / IMPLOT_DIR at local checkouts instead.
include(FetchContent)
set(IMGUI_DIR  "" CACHE PATH "Local Dear ImGui checkout (empty = fetch v1.91.9)")
set(IMPLOT_DIR "" CACHE PATH "Local ImPlot checkout (empty = fetch v0.16)")

if(NOT IMGUI_DIR)
    FetchContent_Declare(imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG        v1.91.9
        GIT_SHALLOW    TRUE)
    FetchContent_GetProperties(imgui)
    if(NOT imgui_POPULATED)
        FetchContent_Populate(imgui)
    endif()
    set(IMGUI_DIR ${imgui_SOURCE_DIR})
endif()

if(NOT IMPLOT_DIR)
    FetchContent_Declare(implot
        GIT_REPOSITORY https://github.com/epezent/implot.git
        GIT_TAG        v0.16
        GIT_SHALLOW    TRUE)
    FetchContent_GetProperties(implot)
    if(NOT implot_POPULATED)
        FetchContent_Populate(implot)
    endif()
    set(IMPLOT_DIR ${implot_SOURCE_DIR})
endif()

find_package(nlohmann_json REQUIRED)
find_package(OpenGL REQUIRED)

# Link GLFW's static archive directly (not the find_package(glfw3) imported
# target, which resolves to the shared glfw3.dll import lib) so the result is
# a single self-contained .exe.
find_library(GLFW_STATIC_LIB NAMES libglfw3.a glfw3
    PATHS "${MINGW_PREFIX}/lib" NO_DEFAULT_PATH)
if(NOT GLFW_STATIC_LIB)
    message(FATAL_ERROR "libglfw3.a not found under ${MINGW_PREFIX}/lib -- "
                        "install it with: pacman -S mingw-w64-x86_64-glfw")
endif()

set(IDS_DASHBOARD_SOURCES
    src/main.cpp
    src/pipeline_orchestrator.cpp
    src/theme.cpp
    ${IMGUI_DIR}/imgui.cpp
    ${IMGUI_DIR}/imgui_draw.cpp
    ${IMGUI_DIR}/imgui_tables.cpp
    ${IMGUI_DIR}/imgui_widgets.cpp
    ${IMGUI_DIR}/imgui_demo.cpp
    ${IMGUI_DIR}/backends/imgui_impl_glfw.cpp
    ${IMGUI_DIR}/backends/imgui_impl_opengl3.cpp
    ${IMPLOT_DIR}/implot.cpp
    ${IMPLOT_DIR}/implot_items.cpp
)

# Shared settings for every dashboard target.
function(ids_configure_target tgt)
    target_include_directories(${tgt} PRIVATE
        ${IMGUI_DIR}
        ${IMGUI_DIR}/backends
        ${IMPLOT_DIR}
        "${MINGW_PREFIX}/include"   # GLFW headers (static lib has no CMake package)
        src)
    target_link_libraries(${tgt} PRIVATE
        ${GLFW_STATIC_LIB}
        OpenGL::GL
        nlohmann_json::nlohmann_json
        opengl32)
    if(WIN32)
        # gdi32/user32/shell32: needed directly by GLFW's static Win32 backend.
        # comdlg32: GetSaveFileNameW "Save As" dialog (packet download/export).
        target_link_libraries(${tgt} PRIVATE gdi32 user32 shell32 comdlg32)
        # Static MinGW runtime (libgcc/libstdc++/winpthread): no DLLs to ship.
        target_link_options(${tgt} PRIVATE -static)
    endif()
endfunction()

add_executable(ids_dashboard ${IDS_DASHBOARD_SOURCES})
ids_configure_target(ids_dashboard)

# Optional experimental variant: soft-vote committee (IDS_R26_PHASE2_SOFTVOTE
# passes MC_R26_SOFTVOTE=1 to the detector process, see main.cpp).
# EXCLUDE_FROM_ALL -- built only on request and never overwrites ids_dashboard.exe:
#   cmake --build build --target ids_dashboard_r26_phase2_softvote
add_executable(ids_dashboard_r26_phase2_softvote EXCLUDE_FROM_ALL ${IDS_DASHBOARD_SOURCES})
target_compile_definitions(ids_dashboard_r26_phase2_softvote PRIVATE IDS_R26_PHASE2_SOFTVOTE)
ids_configure_target(ids_dashboard_r26_phase2_softvote)
