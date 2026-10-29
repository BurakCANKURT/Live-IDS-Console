// Dark "SOC console" visual theme -- slate/navy surfaces, off-white text,
// semantic status colors shared by every widget in main.cpp so severity
// coloring stays consistent across the alerts table, gauge, and charts.
#pragma once

#include "imgui.h"

struct Fonts {
    ImFont* body = nullptr;
    ImFont* header = nullptr;
    ImFont* mono = nullptr;
};

namespace theme {

void Apply();
Fonts LoadFonts(ImGuiIO& io);

extern const ImVec4 kBg;
extern const ImVec4 kPanel;
extern const ImVec4 kPanelAlt;
extern const ImVec4 kBorder;
extern const ImVec4 kText;
extern const ImVec4 kTextDim;
extern const ImVec4 kAccent;
extern const ImVec4 kDanger;
extern const ImVec4 kCritical;
extern const ImVec4 kWarning;
extern const ImVec4 kSuccess;
extern const ImVec4 kInfo;

ImVec4 SeverityColor(const char* severity);
ImVec4 StatusColor(const char* status);

} // namespace theme
