#include "theme.h"

#include <cstring>
#include <cstdio>

namespace theme {

const ImVec4 kBg        = ImVec4(0.059f, 0.090f, 0.165f, 1.00f); // #0f172a
const ImVec4 kPanel      = ImVec4(0.118f, 0.161f, 0.231f, 1.00f); // #1e293b
const ImVec4 kPanelAlt   = ImVec4(0.153f, 0.204f, 0.286f, 1.00f); // #27374a
const ImVec4 kBorder     = ImVec4(0.220f, 0.278f, 0.365f, 1.00f); // #38475d
const ImVec4 kText       = ImVec4(0.886f, 0.910f, 0.941f, 1.00f); // #e2e8f0
const ImVec4 kTextDim    = ImVec4(0.580f, 0.639f, 0.722f, 1.00f);
const ImVec4 kAccent     = ImVec4(0.231f, 0.510f, 0.965f, 1.00f); // #3b82f6
const ImVec4 kDanger     = ImVec4(0.937f, 0.267f, 0.267f, 1.00f); // #ef4444
// CRITICAL sits one step deeper than kDanger on the same red hue, so the
// mechanism-based top tier (volumetric signature + high score) reads as
// "more than HIGH" without introducing a new colour family.
const ImVec4 kCritical   = ImVec4(0.749f, 0.106f, 0.161f, 1.00f); // #bf1b29
const ImVec4 kWarning    = ImVec4(0.961f, 0.620f, 0.043f, 1.00f); // #f59e0b
const ImVec4 kSuccess    = ImVec4(0.133f, 0.773f, 0.369f, 1.00f); // #22c55e
const ImVec4 kInfo       = ImVec4(0.545f, 0.361f, 0.965f, 1.00f); // #8b5cf6

ImVec4 SeverityColor(const char* severity) {
    if (!severity) return kTextDim;
    if (!std::strcmp(severity, "CRITICAL")) return kCritical;
    if (!std::strcmp(severity, "HIGH")) return kDanger;
    if (!std::strcmp(severity, "MEDIUM") || !std::strcmp(severity, "MED")) return kWarning;
    // R20: OOD gate verdict (mongo_logger._severity_from_score) -- not a
    // "good" LOW, it's "we don't know", keep it visually separate.
    if (!std::strcmp(severity, "INFO")) return kInfo;
    return kSuccess;
}

ImVec4 StatusColor(const char* status) {
    if (!status) return kTextDim;
    if (!std::strcmp(status, "ATTACK")) return kDanger;
    // R20: OOD gate verdict -- neither confirmed BENIGN nor ATTACK, don't
    // paint it green (that reads as "checked, safe" which it isn't).
    if (!std::strcmp(status, "UNKNOWN")) return kInfo;
    return kSuccess;
}

void Apply() {
    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowRounding = 8.0f;
    s.ChildRounding = 8.0f;
    s.FrameRounding = 5.0f;
    s.PopupRounding = 6.0f;
    s.ScrollbarRounding = 8.0f;
    s.GrabRounding = 6.0f;
    s.TabRounding = 6.0f;
    s.WindowBorderSize = 1.0f;
    s.ChildBorderSize = 1.0f;
    s.FrameBorderSize = 0.0f;
    s.WindowPadding = ImVec2(14, 12);
    s.FramePadding = ImVec2(10, 6);
    s.ItemSpacing = ImVec2(10, 8);
    s.ItemInnerSpacing = ImVec2(8, 6);
    s.IndentSpacing = 18.0f;
    s.ScrollbarSize = 14.0f;
    s.GrabMinSize = 10.0f;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                  = kText;
    c[ImGuiCol_TextDisabled]          = kTextDim;
    c[ImGuiCol_WindowBg]              = kBg;
    c[ImGuiCol_ChildBg]               = kPanel;
    c[ImGuiCol_PopupBg]               = kPanel;
    c[ImGuiCol_Border]                = kBorder;
    c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]               = kPanelAlt;
    c[ImGuiCol_FrameBgHovered]        = ImVec4(kPanelAlt.x + 0.04f, kPanelAlt.y + 0.04f, kPanelAlt.z + 0.04f, 1.0f);
    c[ImGuiCol_FrameBgActive]         = ImVec4(kPanelAlt.x + 0.07f, kPanelAlt.y + 0.07f, kPanelAlt.z + 0.07f, 1.0f);
    c[ImGuiCol_TitleBg]               = kPanel;
    c[ImGuiCol_TitleBgActive]         = kPanel;
    c[ImGuiCol_TitleBgCollapsed]      = kPanel;
    c[ImGuiCol_MenuBarBg]             = kPanel;
    c[ImGuiCol_ScrollbarBg]           = kBg;
    c[ImGuiCol_ScrollbarGrab]         = kBorder;
    c[ImGuiCol_ScrollbarGrabHovered]  = kAccent;
    c[ImGuiCol_ScrollbarGrabActive]   = kAccent;
    c[ImGuiCol_CheckMark]             = kAccent;
    c[ImGuiCol_SliderGrab]            = kAccent;
    c[ImGuiCol_SliderGrabActive]      = kAccent;
    c[ImGuiCol_Button]                = kPanelAlt;
    c[ImGuiCol_ButtonHovered]         = kAccent;
    c[ImGuiCol_ButtonActive]          = kAccent;
    c[ImGuiCol_Header]                = kPanelAlt;
    c[ImGuiCol_HeaderHovered]         = ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.5f);
    c[ImGuiCol_HeaderActive]          = kAccent;
    c[ImGuiCol_Separator]             = kBorder;
    c[ImGuiCol_SeparatorHovered]      = kAccent;
    c[ImGuiCol_SeparatorActive]       = kAccent;
    c[ImGuiCol_ResizeGrip]            = kBorder;
    c[ImGuiCol_ResizeGripHovered]     = kAccent;
    c[ImGuiCol_ResizeGripActive]      = kAccent;
    c[ImGuiCol_Tab]                   = kPanel;
    c[ImGuiCol_TabHovered]            = ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.6f);
    c[ImGuiCol_TabActive]             = kPanelAlt;
    c[ImGuiCol_TabUnfocused]          = kPanel;
    c[ImGuiCol_TabUnfocusedActive]    = kPanelAlt;
    c[ImGuiCol_PlotLines]             = kAccent;
    c[ImGuiCol_PlotLinesHovered]      = kWarning;
    c[ImGuiCol_PlotHistogram]         = kAccent;
    c[ImGuiCol_PlotHistogramHovered]  = kWarning;
    c[ImGuiCol_TableHeaderBg]         = kPanelAlt;
    c[ImGuiCol_TableBorderStrong]     = kBorder;
    c[ImGuiCol_TableBorderLight]      = ImVec4(kBorder.x, kBorder.y, kBorder.z, 0.5f);
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]         = ImVec4(1, 1, 1, 0.02f);
    c[ImGuiCol_TextSelectedBg]        = ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.35f);
    c[ImGuiCol_DragDropTarget]        = kWarning;
    c[ImGuiCol_NavHighlight]          = kAccent;
}

Fonts LoadFonts(ImGuiIO& io) {
    Fonts f;
    // Basic Latin + Latin-1 Supplement (ImGui's default range) is missing
    // Latin Extended-A -- model/UI labels use Turkish-specific letters
    // (i, s, g, I with breve/cedilla/dot, e.g. "Siniflandirilamadi") that
    // live at U+0100-U+017F, so without this range those glyphs render as
    // "?" in the alert table and distribution charts.
    static const ImWchar turkish_ranges[] = {
        0x0020, 0x00FF, // Basic Latin + Latin-1 Supplement
        0x0100, 0x017F, // Latin Extended-A (i-dotless, s-cedilla, g-breve, ...)
        0,
    };

    const char* candidates[] = {
        "C:\\Windows\\Fonts\\segoeui.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
    };
    const char* body_path = nullptr;
    for (const char* p : candidates) {
        FILE* fp = std::fopen(p, "rb");
        if (fp) { std::fclose(fp); body_path = p; break; }
    }

    if (body_path) {
        f.body = io.Fonts->AddFontFromFileTTF(body_path, 17.0f, nullptr, turkish_ranges);
        f.header = io.Fonts->AddFontFromFileTTF(body_path, 24.0f, nullptr, turkish_ranges);
    } else {
        // ImGui's bundled fallback (ProggyClean) is a fixed bitmap font with
        // no Latin Extended-A glyphs regardless of requested range -- Turkish
        // text will still show "?" here, but this path only triggers if
        // Windows' own font files are missing, which shouldn't happen.
        ImFontConfig cfg;
        cfg.SizePixels = 15.0f;
        f.body = io.Fonts->AddFontDefault(&cfg);
        ImFontConfig cfg2;
        cfg2.SizePixels = 20.0f;
        f.header = io.Fonts->AddFontDefault(&cfg2);
    }

    const char* mono_path = "C:\\Windows\\Fonts\\consola.ttf";
    FILE* fp = std::fopen(mono_path, "rb");
    if (fp) {
        std::fclose(fp);
        f.mono = io.Fonts->AddFontFromFileTTF(mono_path, 16.0f, nullptr, turkish_ranges);
    } else {
        f.mono = f.body;
    }

    return f;
}

} // namespace theme
