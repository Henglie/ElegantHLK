#define _CRT_SECURE_NO_WARNINGS 

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0501 // 保持 Windows XP 兼容
#endif

#pragma warning(disable: 28251)
#pragma warning(disable: 4244)

#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <commdlg.h>
#include <wincrypt.h> 
#include <stdio.h>
#include <process.h>
#include <string.h>
#include <gdiplus.h> // 原生实现高分辨率显示

#include <vector>
#include <map>
#include <string>
#include <regex>     // 引入正则用于高级过滤

// 解决基础版 XP SDK 隐藏 SHA256 宏的问题
#ifndef CALG_SHA_256
#define ALG_SID_SHA_256 12
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#ifndef ListView_GetCheckState
#define ListView_GetCheckState(hwndLV, i) ((((UINT)(SendMessageA((hwndLV), LVM_GETITEMSTATE, (WPARAM)(i), LVIS_STATEIMAGEMASK))) >> 12) - 1)
#endif

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "comdlg32.lib")

#pragma comment(linker, "/subsystem:windows")

#define ID_COMBO_DISK        1001
#define ID_EDIT_ADDRESS      1002
#define ID_COMBO_FILTER      1003
#define ID_LIST_FILE         1004
#define ID_LIST_HARDLINK     1005
#define ID_BTN_REFRESH       1006
#define ID_BTN_ANALYZE       1007
#define ID_BTN_CREATE_HLINK  1008
#define ID_BTN_RESTORE_SLINK 1009
#define ID_BTN_ABOUT         1011

// 高级过滤与新控件 ID
#define ID_EDIT_INC_REGEX    1012
#define ID_EDIT_EXC_REGEX    1013
#define ID_EDIT_MIN_SIZE     1014
#define ID_EDIT_MAX_SIZE     1015
#define ID_PROGRESS_BAR      1016

#define ID_BTN_SELALL_L      1017
#define ID_BTN_INVSEL_L      1018
#define ID_BTN_SELALL_R      1019
#define ID_BTN_INVSEL_R      1020
#define ID_BTN_EXPORT_R      1021

#define IDM_COPY_FILENAME    2001
#define IDM_COPY_PATH        2002
#define IDM_COPY_SHA256      2003
#define IDM_PASTE            2004
#define IDM_OPEN_EXPLORER    2005
#define IDM_CREATE_HLINK_CTX 2006
#define IDM_DELETE           2007

#define WM_USER_SCAN_DONE       (WM_USER + 100)
#define WM_USER_ANALYZE_DONE    (WM_USER + 101)
#define WM_USER_CREATE_DONE     (WM_USER + 102)
#define WM_USER_UPDATE_PROGRESS (WM_USER + 103)
#define WM_USER_UPDATE_SCANFILE (WM_USER + 104)

HINSTANCE g_hInst;
HWND g_hMainWnd, g_hComboDisk, g_hEditAddress, g_hComboFilter, g_hFileList, g_hHardlinkList;
HWND g_hBtnRefresh, g_hBtnAnalyze, g_hBtnCreate, g_hBtnRestore, g_hBtnAbout;
HWND g_hTxtTotalSaved, g_hProgressBar, g_hGroupFilter;
HWND g_hBtnSelAllL, g_hBtnInvSelL, g_hBtnSelAllR, g_hBtnInvSelR;
HWND g_hBtnExportR, g_hTxtScanInfo;
char g_szScanFile[2048] = "";
volatile int g_nScanCounter = 0;

// V1.1 统计与拖拽
size_t g_StatGroupCount = 0;   // 重复组数
size_t g_StatDupFileCount = 0; // 重复文件总数
DWORD  g_StatElapsedMs = 0;    // 分析耗时(毫秒)
std::map<std::string, int> g_GroupParity; // SHA256 -> 0/1 交替底色
CRITICAL_SECTION g_csParity;               // 保护 g_GroupParity 跨线程访问

// 静态文本和输入框 HWND
HWND g_hTxtDisk, g_hTxtAddr, g_hTxtFilter;
HWND g_hTxtInc, g_hEditInc, g_hTxtExc, g_hEditExc, g_hTxtSize, g_hEditSizeMin, g_hTxtSizeTo, g_hEditSizeMax;

char g_CurrentPath[2048] = "C:\\";
char g_CurrentFilter[1024] = "*.*";

// 高级过滤参数
char g_IncludeRegex[1024] = "";
char g_ExcludeRegex[1024] = "";
LONGLONG g_MinSize = 0;
LONGLONG g_MaxSize = 0;

BOOL g_bScanning = FALSE;
BOOL g_bExcludeRisky = FALSE;
LONGLONG g_llTotalSavedSpace = 0;

volatile BOOL g_bCancelAnalysis = FALSE;

int g_DPI = 96;
ULONG_PTR g_gdiplusToken;

struct FileNode {
    std::string fullPath;
    std::string fileName;
    LARGE_INTEGER size = { 0 };
    DWORD attr = 0;
};

// 排序状态变量
HWND g_CurrentSortList = NULL;
int g_CurrentSortColumn = 0;
BOOL g_CurrentSortAsc = TRUE;

int g_SortColLeft = 0; BOOL g_SortAscLeft = TRUE;
int g_SortColRight = 0; BOOL g_SortAscRight = TRUE;

// 目标扫描文件夹集合
std::vector<std::string> g_TargetDirs;

// --- 函数声明 ---
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND hwnd);
void SetDefaultFont(HWND hwnd);
void ShowFileContextMenu(HWND hwnd, POINT pt, BOOL isHardlinkList);
unsigned __stdcall ScanDirectoryThread(void* pArguments);
unsigned __stdcall AnalyzeDirectoryThread(void* pArguments);
unsigned __stdcall CreateHardlinksThread(void* pArguments);
void AddListItem(HWND hList, const char* col0, const char* col1, const char* col2, const char* col3, const char* col4, DWORD dwAttributes, const char* overridePath = NULL);
void CopyToClipboard(HWND hwnd, const char* text);
void ExportHardlinkList(HWND hwnd);
int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
BOOL BreakHardlink(const char* filepath);
void GetSafeFullPath(const char* dir, const char* file, char* outPath, size_t maxLen);
BOOL CalculateFileSHA256(const char* filename, std::string& outHash);
void FormatSize(LONGLONG bytes, char* buf, size_t maxLen);
LONGLONG ParseSize(const char* str);
void UpdateAdvancedFilters();
bool IsAdvancedFiltered(const char* filename, LONGLONG fileSize);
BOOL IsRiskyExt(const char* path);

int DPIScale(int value) { return MulDiv(value, g_DPI, 96); }

void EnableDPIAwareness() {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI* SETPROCESSDPIAWARE_T)(void);
        SETPROCESSDPIAWARE_T pSetDPIAware = (SETPROCESSDPIAWARE_T)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (pSetDPIAware) pSetDPIAware();
    }
}

void FormatSize(LONGLONG bytes, char* buf, size_t maxLen) {
    if (bytes == 0) { snprintf(buf, maxLen, "0.00 KB"); return; }
    double sizeKB = (double)bytes / 1024.0;
    if (sizeKB < 1024.0) snprintf(buf, maxLen, "%.2f KB", sizeKB);
    else if (sizeKB < 1024.0 * 1024.0) snprintf(buf, maxLen, "%.2f MB", sizeKB / 1024.0);
    else snprintf(buf, maxLen, "%.2f GB", sizeKB / (1024.0 * 1024.0));
}

LONGLONG ParseSize(const char* str) {
    double val = atof(str);
    if (strstr(str, "GB")) return (LONGLONG)(val * 1024.0 * 1024.0 * 1024.0);
    if (strstr(str, "MB")) return (LONGLONG)(val * 1024.0 * 1024.0);
    if (strstr(str, "KB")) return (LONGLONG)(val * 1024.0);
    return (LONGLONG)val;
}

void GetListViewSubItemTextA(HWND hList, int iItem, int iSubItem, char* buf, int maxLen) {
    LVITEMA lvi = { 0 }; lvi.iSubItem = iSubItem; lvi.pszText = buf; lvi.cchTextMax = maxLen;
    SendMessageA(hList, LVM_GETITEMTEXTA, iItem, (LPARAM)&lvi);
}

LPARAM GetListViewParamA(HWND hList, int iItem) {
    LVITEMA lvi = { 0 }; lvi.iItem = iItem; lvi.mask = LVIF_PARAM;
    SendMessageA(hList, LVM_GETITEMA, 0, (LPARAM)&lvi);
    return lvi.lParam;
}

void GetSafeFullPath(const char* dir, const char* file, char* outPath, size_t maxLen) {
    snprintf(outPath, maxLen, (dir[strlen(dir) - 1] == '\\') ? "%s%s" : "%s\\%s", dir, file);
}

BOOL CalculateFileSHA256(const char* filename, std::string& outHash) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HCRYPTPROV hProv = 0; HCRYPTHASH hHash = 0; BOOL bResult = FALSE;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
            BYTE buffer[1024 * 32]; DWORD bytesRead = 0;
            while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
                if (g_bCancelAnalysis) break;
                CryptHashData(hHash, buffer, bytesRead, 0);
            }
            if (!g_bCancelAnalysis) {
                DWORD hashLen = 0; DWORD hashLenSize = sizeof(DWORD);
                CryptGetHashParam(hHash, HP_HASHSIZE, (BYTE*)&hashLen, &hashLenSize, 0);
                if (hashLen > 0) {
                    BYTE* hashVal = new BYTE[hashLen];
                    if (CryptGetHashParam(hHash, HP_HASHVAL, hashVal, &hashLen, 0)) {
                        char hexStr[3]; outHash = "";
                        for (DWORD i = 0; i < hashLen; i++) {
                            sprintf(hexStr, "%02x", hashVal[i]); outHash += hexStr;
                        }
                        bResult = TRUE;
                    }
                    delete[] hashVal;
                }
            }
            CryptDestroyHash(hHash);
        }
        CryptReleaseContext(hProv, 0);
    }
    CloseHandle(hFile);
    return bResult;
}

int main() { return WinMain(GetModuleHandleA(NULL), NULL, GetCommandLineA(), SW_SHOWDEFAULT); }

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    InitializeCriticalSection(&g_csParity);
    EnableDPIAwareness();
    HDC hdc = GetDC(NULL); g_DPI = GetDeviceCaps(hdc, LOGPIXELSX); ReleaseDC(NULL, hdc);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);

    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA) };
    wc.lpfnWndProc = WndProc; wc.hInstance = hInstance; wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW); wc.lpszClassName = "ElegantHardlinkClass";
    RegisterClassExA(&wc);

    g_hMainWnd = CreateWindowExA(0, "ElegantHardlinkClass", "优雅硬链接 V1.1.1",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, DPIScale(1000), DPIScale(680), NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd) return 0;
    DragAcceptFiles(g_hMainWnd, TRUE);
    ShowWindow(g_hMainWnd, nCmdShow); UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    return (int)msg.wParam;
}

int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    HWND hList = g_CurrentSortList;
    if (!hList) return 0;

    char txt1[2048] = { 0 }, txt2[2048] = { 0 };
    GetListViewSubItemTextA(hList, lParam1, g_CurrentSortColumn, txt1, 2048);
    GetListViewSubItemTextA(hList, lParam2, g_CurrentSortColumn, txt2, 2048);

    LPARAM param1 = GetListViewParamA(hList, lParam1);
    LPARAM param2 = GetListViewParamA(hList, lParam2);

    BOOL isDir1 = (param1 & FILE_ATTRIBUTE_DIRECTORY) != 0;
    BOOL isDir2 = (param2 & FILE_ATTRIBUTE_DIRECTORY) != 0;

    // 无论按哪一列排序，文件夹优先逻辑
    char name1[2048] = { 0 }, name2[2048] = { 0 };
    GetListViewSubItemTextA(hList, lParam1, 0, name1, 2048);
    GetListViewSubItemTextA(hList, lParam2, 0, name2, 2048);

    if (strcmp(name1, "..") == 0) return -1;
    if (strcmp(name2, "..") == 0) return 1;
    if (isDir1 && !isDir2) return -1;
    if (!isDir1 && isDir2) return 1;

    int res = 0;
    bool isSizeCol = (hList == g_hFileList && g_CurrentSortColumn == 1) ||
        (hList == g_hHardlinkList && g_CurrentSortColumn == 2);

    if (isSizeCol) {
        LONGLONG s1 = ParseSize(txt1);
        LONGLONG s2 = ParseSize(txt2);
        if (s1 < s2) res = -1;
        else if (s1 > s2) res = 1;
    }
    else {
        res = _stricmp(txt1, txt2);
    }

    return g_CurrentSortAsc ? res : -res;
}

void UpdateAdvancedFilters() {
    GetWindowTextA(g_hEditInc, g_IncludeRegex, sizeof(g_IncludeRegex));
    GetWindowTextA(g_hEditExc, g_ExcludeRegex, sizeof(g_ExcludeRegex));

    char szMin[32] = { 0 }, szMax[32] = { 0 };
    GetWindowTextA(g_hEditSizeMin, szMin, sizeof(szMin));
    GetWindowTextA(g_hEditSizeMax, szMax, sizeof(szMax));

    g_MinSize = atoll(szMin) * 1024 * 1024;
    g_MaxSize = atoll(szMax) * 1024 * 1024;
}

bool IsAdvancedFiltered(const char* filename, LONGLONG fileSize) {
    if (g_MinSize > 0 && fileSize < g_MinSize) return true;
    if (g_MaxSize > 0 && fileSize > g_MaxSize) return true;

    std::string fname(filename);
    try {
        if (strlen(g_ExcludeRegex) > 0) {
            std::regex reExc(g_ExcludeRegex, std::regex_constants::icase);
            if (std::regex_search(fname, reExc)) return true;
        }
        if (strlen(g_IncludeRegex) > 0) {
            std::regex reInc(g_IncludeRegex, std::regex_constants::icase);
            if (!std::regex_search(fname, reInc)) return true;
        }
    }
    catch (const std::regex_error&) {}
    return false;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: CreateControls(hwnd); break;

    case WM_GETMINMAXINFO: {
        LPMINMAXINFO lpMMI = (LPMINMAXINFO)lParam;
        lpMMI->ptMinTrackSize.x = DPIScale(850);
        lpMMI->ptMinTrackSize.y = DPIScale(550);
        break;
    }

    case WM_SIZE: {
        if (wParam == SIZE_MINIMIZED) break;
        int cx = LOWORD(lParam);
        int cy = HIWORD(lParam);

        MoveWindow(g_hEditAddress, DPIScale(260), DPIScale(12), cx - DPIScale(640), DPIScale(24), TRUE);
        MoveWindow(g_hTxtFilter, cx - DPIScale(370), DPIScale(15), DPIScale(40), DPIScale(20), TRUE);
        MoveWindow(g_hComboFilter, cx - DPIScale(330), DPIScale(12), DPIScale(300), DPIScale(400), TRUE);

        MoveWindow(g_hGroupFilter, DPIScale(10), DPIScale(42), cx - DPIScale(20), DPIScale(60), TRUE);
        MoveWindow(g_hTxtInc, DPIScale(20), DPIScale(65), DPIScale(80), DPIScale(20), TRUE);
        MoveWindow(g_hEditInc, DPIScale(100), DPIScale(62), DPIScale(150), DPIScale(24), TRUE);
        MoveWindow(g_hTxtExc, DPIScale(270), DPIScale(65), DPIScale(80), DPIScale(20), TRUE);
        MoveWindow(g_hEditExc, DPIScale(350), DPIScale(62), DPIScale(150), DPIScale(24), TRUE);
        MoveWindow(g_hTxtSize, cx - DPIScale(350), DPIScale(65), DPIScale(60), DPIScale(20), TRUE);
        MoveWindow(g_hEditSizeMin, cx - DPIScale(280), DPIScale(62), DPIScale(60), DPIScale(24), TRUE);
        MoveWindow(g_hTxtSizeTo, cx - DPIScale(210), DPIScale(65), DPIScale(20), DPIScale(20), TRUE);
        MoveWindow(g_hEditSizeMax, cx - DPIScale(180), DPIScale(62), DPIScale(60), DPIScale(24), TRUE);

        // 选择按钮栏和列表区域计算
        int listW = (cx - DPIScale(30)) / 2;
        int listY = DPIScale(140);
        int listHeight = cy - listY - DPIScale(100);
        if (listHeight < DPIScale(100)) listHeight = DPIScale(100);

        MoveWindow(g_hBtnSelAllL, DPIScale(10), DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnInvSelL, DPIScale(80), DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnSelAllR, DPIScale(20) + listW, DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnInvSelR, DPIScale(90) + listW, DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnExportR, DPIScale(160) + listW, DPIScale(110), DPIScale(90), DPIScale(25), TRUE);

        MoveWindow(g_hFileList, DPIScale(10), listY, listW, listHeight, TRUE);
        MoveWindow(g_hHardlinkList, DPIScale(20) + listW, listY, listW, listHeight, TRUE);

        // 底部按钮栏
        int btnY = cy - DPIScale(85);
        MoveWindow(g_hBtnRefresh, DPIScale(10), btnY, DPIScale(120), DPIScale(35), TRUE);
        MoveWindow(g_hBtnAnalyze, DPIScale(140), btnY, DPIScale(130), DPIScale(35), TRUE);
        MoveWindow(g_hBtnCreate, DPIScale(280), btnY, DPIScale(140), DPIScale(35), TRUE);
        MoveWindow(g_hBtnRestore, DPIScale(430), btnY, DPIScale(130), DPIScale(35), TRUE);

        int btnY2 = cy - DPIScale(40);
        int progW = DPIScale(180);
        int progX = cx - DPIScale(120) - progW - DPIScale(10);
        int scanX = DPIScale(10);
        int scanW = progX - scanX - DPIScale(10);
        if (scanW < DPIScale(80)) scanW = DPIScale(80);
        MoveWindow(g_hTxtScanInfo, scanX, btnY2 + DPIScale(2), scanW, DPIScale(18), TRUE);
        MoveWindow(g_hProgressBar, progX, btnY2 + DPIScale(2), progW, DPIScale(16), TRUE);
        MoveWindow(g_hTxtTotalSaved, scanX, btnY2 + DPIScale(20), progX + progW - scanX, DPIScale(18), TRUE);
        MoveWindow(g_hBtnAbout, cx - DPIScale(110), btnY2, DPIScale(100), DPIScale(35), TRUE);
        break;
    }

    case WM_USER_UPDATE_PROGRESS:
        SendMessage(g_hProgressBar, PBM_SETRANGE32, 0, lParam);
        SendMessage(g_hProgressBar, PBM_SETPOS, wParam, 0);
        break;

    case WM_USER_UPDATE_SCANFILE:
        SetWindowTextA(g_hTxtScanInfo, g_szScanFile);
        break;

    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->idFrom == ID_LIST_FILE && lpnmh->code == NM_DBLCLK) {
            LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
            if (lpnmitem->iItem != -1) {
                char text[2048] = { 0 };
                GetListViewSubItemTextA(g_hFileList, lpnmitem->iItem, 0, text, 2048);
                LPARAM itemParam = GetListViewParamA(g_hFileList, lpnmitem->iItem);

                if (itemParam & FILE_ATTRIBUTE_DIRECTORY) {
                    if (strcmp(text, "..") == 0) {
                        PathRemoveFileSpecA(g_CurrentPath);
                        if (strlen(g_CurrentPath) <= 3) snprintf(g_CurrentPath, sizeof(g_CurrentPath), "%c:\\", g_CurrentPath[0]);
                    }
                    else {
                        if (g_CurrentPath[strlen(g_CurrentPath) - 1] != '\\') strcat(g_CurrentPath, "\\");
                        strcat(g_CurrentPath, text);
                    }
                    SetWindowTextA(g_hEditAddress, g_CurrentPath);
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
                }
            }
        }
        if ((lpnmh->idFrom == ID_LIST_FILE || lpnmh->idFrom == ID_LIST_HARDLINK) && lpnmh->code == LVN_COLUMNCLICK) {
            LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
            HWND hList = pnmv->hdr.hwndFrom;
            int col = pnmv->iSubItem;

            if (hList == g_hFileList) {
                if (g_SortColLeft == col) g_SortAscLeft = !g_SortAscLeft;
                else { g_SortColLeft = col; g_SortAscLeft = TRUE; }
                g_CurrentSortList = g_hFileList;
                g_CurrentSortColumn = g_SortColLeft;
                g_CurrentSortAsc = g_SortAscLeft;
            }
            else if (hList == g_hHardlinkList) {
                if (g_SortColRight == col) g_SortAscRight = !g_SortAscRight;
                else { g_SortColRight = col; g_SortAscRight = TRUE; }
                g_CurrentSortList = g_hHardlinkList;
                g_CurrentSortColumn = g_SortColRight;
                g_CurrentSortAsc = g_SortAscRight;
            }

            SendMessageA(hList, LVM_SORTITEMSEX, (WPARAM)hList, (LPARAM)CompareFuncEx);
        }
        if ((lpnmh->idFrom == ID_LIST_FILE || lpnmh->idFrom == ID_LIST_HARDLINK) && lpnmh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
            if (lplvcd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (lplvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                DWORD attr = (DWORD)lplvcd->nmcd.lItemlParam;
                BOOL bHidden = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
                BOOL bReadOnly = (attr & FILE_ATTRIBUTE_READONLY) != 0;
                if (bHidden && bReadOnly) lplvcd->clrText = RGB(128, 0, 128);
                else if (bHidden) lplvcd->clrText = RGB(255, 0, 0);
                else if (bReadOnly) lplvcd->clrText = RGB(0, 0, 255);
                else lplvcd->clrText = RGB(0, 0, 0);

                // 右侧重复列表：同一 SHA256 组用交替底色，方便区分"哪几行是一伙的"
                if (lpnmh->idFrom == ID_LIST_HARDLINK) {
                    char sha[128] = { 0 };
                    GetListViewSubItemTextA(g_hHardlinkList, (int)lplvcd->nmcd.dwItemSpec, 3, sha, sizeof(sha));
                    int parity = 0;
                    EnterCriticalSection(&g_csParity);
                    std::map<std::string, int>::iterator git = g_GroupParity.find(sha);
                    if (git != g_GroupParity.end()) parity = git->second;
                    LeaveCriticalSection(&g_csParity);
                    lplvcd->clrTextBk = parity ? RGB(226, 239, 252) : RGB(255, 255, 255);
                }
                return CDRF_NEWFONT;
            }
        }
        break;
    }

    case WM_COMMAND:
        if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == ID_COMBO_DISK) {
            int idx = (int)SendMessageA(g_hComboDisk, CB_GETCURSEL, 0, 0);
            char comboRaw[2048];
            SendMessageA(g_hComboDisk, CB_GETLBTEXT, idx, (LPARAM)comboRaw);
            comboRaw[3] = '\0';
            lstrcpyA(g_CurrentPath, comboRaw);
            SetWindowTextA(g_hEditAddress, g_CurrentPath);
            SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
        }
        if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == ID_COMBO_FILTER) {
            int idx = (int)SendMessageA(g_hComboFilter, CB_GETCURSEL, 0, 0);
            char tempFilter[2048];
            SendMessageA(g_hComboFilter, CB_GETLBTEXT, idx, (LPARAM)tempFilter);
            char* pStart = strchr(tempFilter, '(');
            char* pEnd = strchr(tempFilter, ')');
            if (pStart && pEnd) { *pEnd = '\0'; lstrcpyA(g_CurrentFilter, pStart + 1); }
            else { lstrcpyA(g_CurrentFilter, tempFilter); }
            SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
        }
        if (HIWORD(wParam) == BN_CLICKED) {
            switch (LOWORD(wParam)) {
            case ID_BTN_SELALL_L:
            case ID_BTN_INVSEL_L:
            case ID_BTN_SELALL_R:
            case ID_BTN_INVSEL_R: {
                HWND hList = (LOWORD(wParam) == ID_BTN_SELALL_L || LOWORD(wParam) == ID_BTN_INVSEL_L) ? g_hFileList : g_hHardlinkList;
                BOOL isInv = (LOWORD(wParam) == ID_BTN_INVSEL_L || LOWORD(wParam) == ID_BTN_INVSEL_R);
                int count = (int)SendMessageA(hList, LVM_GETITEMCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    BOOL cur = ListView_GetCheckState(hList, i);
                    BOOL next = isInv ? !cur : TRUE;
                    ListView_SetItemState(hList, i, INDEXTOSTATEIMAGEMASK(next ? 2 : 1), LVIS_STATEIMAGEMASK);
                }
                break;
            }

            case ID_BTN_REFRESH:
                if (g_bScanning) { g_bCancelAnalysis = TRUE; SetWindowTextA(g_hBtnRefresh, "正在停止..."); break; }
                GetWindowTextA(g_hEditAddress, g_CurrentPath, 2048);
                UpdateAdvancedFilters();
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                SetWindowTextA(g_hTxtTotalSaved, "总计可省: 等待分析...");
                SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
                SendMessageA(g_hFileList, LVM_DELETEALLITEMS, 0, 0);
                SendMessageA(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                SetWindowTextA(g_hBtnRefresh, "停止扫描");
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, ScanDirectoryThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;

            case ID_BTN_ANALYZE: {
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) {
                        g_bCancelAnalysis = TRUE;
                        SetWindowTextA(g_hBtnAnalyze, "正在终止...");
                    }
                    break;
                }

                g_TargetDirs.clear();
                int listCount = (int)SendMessageA(g_hFileList, LVM_GETITEMCOUNT, 0, 0);
                for (int i = 0; i < listCount; i++) {
                    if (ListView_GetCheckState(g_hFileList, i)) {
                        LPARAM param = GetListViewParamA(g_hFileList, i);
                        if (param & FILE_ATTRIBUTE_DIRECTORY) {
                            char text[2048] = { 0 };
                            GetListViewSubItemTextA(g_hFileList, i, 0, text, 2048);
                            if (strcmp(text, "..") != 0) {
                                char full[2048]; GetSafeFullPath(g_CurrentPath, text, full, 2048);
                                g_TargetDirs.push_back(full);
                            }
                        }
                    }
                }
                if (g_TargetDirs.empty()) g_TargetDirs.push_back(g_CurrentPath);

                GetWindowTextA(g_hEditAddress, g_CurrentPath, 2048);
                UpdateAdvancedFilters();
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                g_llTotalSavedSpace = 0;
                SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
                SendMessageA(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                SetWindowTextA(g_hBtnAnalyze, "终止分析");
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, AnalyzeDirectoryThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;
            }

            case ID_BTN_CREATE_HLINK: {
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) { g_bCancelAnalysis = TRUE; SetWindowTextA(g_hBtnCreate, "正在终止..."); }
                    break;
                }
                int itemCount = (int)SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
                if (itemCount == 0) {
                    MessageBoxA(hwnd, "请先执行【分析文件(查重)】，找出重复文件后再执行一键转换！", "提示", MB_OK | MB_ICONWARNING);
                    break;
                }

                // 判断是否有勾选项
                int checkedCount = 0;
                for (int i = 0; i < itemCount; i++) {
                    if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;
                }

                bool hasRiskyFiles = false;
                for (int i = 0; i < itemCount; i++) {
                    if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;

                    char path[2048] = { 0 };
                    GetListViewSubItemTextA(g_hHardlinkList, i, 0, path, 2048);
                    if (IsRiskyExt(path)) { hasRiskyFiles = true; break; }
                }

                g_bExcludeRisky = FALSE;
                if (hasRiskyFiles) {
                    int res = MessageBoxA(hwnd, "检测到易改变的办公文档或备份文件（如 .docx, .xlsx, .bak 等）。\n硬链接会导致一处修改处处被修改，不建议对需要独立编辑的文件使用。\n\n[是(Y)] 安全模式：自动排除这些高风险文件并转换其余文件\n[否(N)] 强制模式：无视警告，全部转换为硬链接\n[取消] 终止操作", "高危文件拦截警告", MB_YESNOCANCEL | MB_ICONWARNING);
                    if (res == IDCANCEL) break;
                    if (res == IDYES) g_bExcludeRisky = TRUE;
                }
                else {
                    if (checkedCount == 0) {
                        if (MessageBoxA(hwnd, "您没有在右侧勾选任何指定文件。\n确定要将右侧列表中【所有】重复的文件全部转换为硬链接吗？", "全部清理确认", MB_YESNO | MB_ICONWARNING) != IDYES) break;
                    }
                    else {
                        if (MessageBoxA(hwnd, "确定要将您【勾选】的重复的文件转换为硬链接吗？\n(未勾选的将自动忽略)", "选中文件清理确认", MB_YESNO | MB_ICONINFORMATION) != IDYES) break;
                    }
                }

                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                SetWindowTextA(g_hBtnCreate, "终止转换");
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, CreateHardlinksThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;
            }

            case ID_BTN_EXPORT_R: ExportHardlinkList(hwnd); break;
            case ID_BTN_RESTORE_SLINK: {
                int cnt = (int)SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
                if (cnt == 0) { MessageBoxA(hwnd, "右侧列表为空，请先「分析文件(查重)」找出已有硬链接。", "提示", MB_OK | MB_ICONWARNING); break; }
                int chk = 0; for (int i = 0; i < cnt; i++) if (ListView_GetCheckState(g_hHardlinkList, i)) chk++;
                std::vector<std::string> targets;
                for (int i = 0; i < cnt; i++) {
                    if (chk > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;
                    char hl[16] = { 0 }; GetListViewSubItemTextA(g_hHardlinkList, i, 4, hl, 16);
                    if (hl[0] != '1') continue;
                    char p[2048] = { 0 }; GetListViewSubItemTextA(g_hHardlinkList, i, 0, p, 2048);
                    if (strlen(p) > 0) targets.push_back(p);
                }
                if (targets.empty()) { MessageBoxA(hwnd, "没有可解绑的项（需要第 5 列「硬链接」为 1）。", "提示", MB_OK | MB_ICONINFORMATION); break; }
                char ask[256]; snprintf(ask, sizeof(ask), "将对 %zu 个文件执行解绑：先复制实数据到临时文件，再写回原路径，期间会临时占用同等空间。\n继续？", targets.size());
                if (MessageBoxA(hwnd, ask, "解绑硬链接确认", MB_YESNO | MB_ICONQUESTION) != IDYES) break;
                size_t okN = 0, failN = 0;
                for (size_t i = 0; i < targets.size(); i++) {
                    if (BreakHardlink(targets[i].c_str())) okN++; else failN++;
                }
                char done[256]; snprintf(done, sizeof(done), "解绑完成。\n\n成功：%zu\n失败：%zu", okN, failN);
                MessageBoxA(hwnd, done, "完成", MB_OK | MB_ICONINFORMATION);
                SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
                break;
            }
            case ID_BTN_ABOUT:
                MessageBoxA(hwnd, "作者：恒烈 EternalBlaze\ngithub项目地址：https://github.com/Henglie/ElegantHLK\n开源协议：MIT", "关于作者", MB_OK | MB_ICONINFORMATION);
                break;
            }
        }

        if (HIWORD(wParam) == 0) {
            HWND hFocus = GetFocus();
            BOOL isHardlinkList = (hFocus == g_hHardlinkList);
            HWND hActiveList = isHardlinkList ? g_hHardlinkList : g_hFileList;
            int selIdx = (int)SendMessageA(hActiveList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            char selText[2048] = { 0 };
            if (selIdx != -1) GetListViewSubItemTextA(hActiveList, selIdx, 0, selText, 2048);

            char full[2048];
            if (isHardlinkList && strchr(selText, '\\')) lstrcpyA(full, selText);
            else GetSafeFullPath(g_CurrentPath, selText, full, 2048);

            switch (LOWORD(wParam)) {
            case IDM_COPY_FILENAME: {
                const char* baseName = strrchr(selText, '\\');
                CopyToClipboard(hwnd, baseName ? baseName + 1 : selText);
                break;
            }
            case IDM_COPY_PATH: CopyToClipboard(hwnd, full); break;
            case IDM_COPY_SHA256: {
                if (isHardlinkList) {
                    char sha[128] = { 0 };
                    GetListViewSubItemTextA(hActiveList, selIdx, 3, sha, 128);
                    if (strlen(sha) > 0) CopyToClipboard(hwnd, sha);
                }
                break;
            }
            case IDM_OPEN_EXPLORER: {
                char param[2048 + 20]; snprintf(param, sizeof(param), "/select,\"%s\"", full);
                ShellExecuteA(NULL, "open", "explorer.exe", param, NULL, SW_SHOWNORMAL); break;
            }
            case IDM_DELETE: {
                if (selIdx == -1 || strlen(full) == 0) break;
                char prompt[2200]; snprintf(prompt, sizeof(prompt), "确定将此项送入回收站？\n\n%s", full);
                if (MessageBoxA(hwnd, prompt, "删除到回收站", MB_YESNO | MB_ICONWARNING) != IDYES) break;
                char dblNull[2052] = { 0 }; lstrcpynA(dblNull, full, 2050);
                SHFILEOPSTRUCTA op = { 0 };
                op.hwnd = hwnd; op.wFunc = FO_DELETE; op.pFrom = dblNull;
                op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;
                if (SHFileOperationA(&op) == 0 && !op.fAnyOperationsAborted) {
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
                }
                break;
            }
            case IDM_CREATE_HLINK_CTX: {
                DWORD attr = (DWORD)GetListViewParamA(hActiveList, selIdx);
                if (attr & FILE_ATTRIBUTE_DIRECTORY) MessageBoxA(hwnd, "硬链接不能作用于文件夹！", "错误", MB_OK | MB_ICONERROR);
                else MessageBoxA(hwnd, "请使用列表上方的『一键创建硬链接』按钮执行。", "提示", MB_OK);
                break;
            }
            }
        }
        break;

    case WM_USER_SCAN_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowTextA(g_hBtnRefresh, "刷新当前目录");
        SetWindowTextA(g_hBtnAnalyze, "分析文件(查重)");
        SetWindowTextA(g_hBtnCreate, "一键创建硬链接");
        char totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, sizeof(totalBuf));
        char finalStr[256]; snprintf(finalStr, sizeof(finalStr), "硬链接后总计可省空间: %s", totalBuf);
        SetWindowTextA(g_hTxtTotalSaved, finalStr);
        break;
    }

    case WM_USER_ANALYZE_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETRANGE32, 0, 100);
        SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
        SetWindowTextA(g_hTxtScanInfo, "");
        SetWindowTextA(g_hBtnRefresh, "刷新当前目录");
        SetWindowTextA(g_hBtnAnalyze, "分析文件(查重)");
        SetWindowTextA(g_hBtnCreate, "一键创建硬链接");

        char totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, sizeof(totalBuf));
        double dElapsed = g_StatElapsedMs / 1000.0;
        char finalStr[320];
        snprintf(finalStr, sizeof(finalStr), "可省空间: %s  |  重复组: %zu  |  重复文件: %zu  |  耗时: %.2fs",
                 totalBuf, g_StatGroupCount, g_StatDupFileCount, dElapsed);
        SetWindowTextA(g_hTxtTotalSaved, finalStr);

        BOOL bCancelled = (BOOL)lParam; size_t count = (size_t)wParam;
        if (bCancelled) MessageBoxA(hwnd, "分析已被用户终止！", "提示", MB_OK | MB_ICONINFORMATION);
        else {
            char msg[512];
            snprintf(msg, sizeof(msg),
                "分析成功！\n\n重复文件组数：%zu 组\n重复文件总数：%zu 个\n可创建的硬链接数：%zu 个\n预计可释放空间：%s\n本次分析耗时：%.2f 秒",
                g_StatGroupCount, g_StatDupFileCount, count, totalBuf, dElapsed);
            MessageBoxA(hwnd, msg, "查重分析完成", MB_OK | MB_ICONINFORMATION);
        }
        break;
    }

    case WM_USER_CREATE_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowTextA(g_hBtnRefresh, "刷新当前目录");
        SetWindowTextA(g_hBtnAnalyze, "分析文件(查重)");
        SetWindowTextA(g_hBtnCreate, "一键创建硬链接");

        size_t successCount = (size_t)wParam;
        size_t failCount = (size_t)lParam;

        char msg[256];
        snprintf(msg, sizeof(msg), "硬链接批量转换完成！\n\n成功替换并释放物理文件: %zu 个\n替换失败(或已排除): %zu 个\n\n(即将自动刷新目录)", successCount, failCount);
        MessageBoxA(hwnd, msg, "操作完成", MB_OK | MB_ICONINFORMATION);

        SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
        break;
    }

    case WM_CONTEXTMENU:
        if ((HWND)wParam == g_hFileList || ((HWND)wParam == g_hHardlinkList)) {
            POINT pt; pt.x = LOWORD(lParam); pt.y = HIWORD(lParam);
            ShowFileContextMenu(hwnd, pt, (HWND)wParam == g_hHardlinkList);
        }
        break;
    case WM_DROPFILES: {
        HDROP hDrop = (HDROP)wParam;
        char dropped[2048] = { 0 };
        if (DragQueryFileA(hDrop, 0, dropped, sizeof(dropped)) > 0) {
            DWORD da = GetFileAttributesA(dropped);
            if (da != INVALID_FILE_ATTRIBUTES) {
                if (da & FILE_ATTRIBUTE_DIRECTORY) {
                    lstrcpynA(g_CurrentPath, dropped, sizeof(g_CurrentPath));
                } else {
                    lstrcpynA(g_CurrentPath, dropped, sizeof(g_CurrentPath));
                    PathRemoveFileSpecA(g_CurrentPath);
                }
                SetWindowTextA(g_hEditAddress, g_CurrentPath);
                SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
            }
        }
        DragFinish(hDrop);
        break;
    }
    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProcA(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

unsigned __stdcall ScanDirectoryThread(void* pArguments) {
    char searchPath[2048]; GetSafeFullPath(g_CurrentPath, "*.*", searchPath, 2048);
    g_llTotalSavedSpace = 0;

    if (strlen(g_CurrentPath) > 3) AddListItem(g_hFileList, "..", "", "返回上一级", "", NULL, FILE_ATTRIBUTE_DIRECTORY);

    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (g_bCancelAnalysis) break;
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

            BOOL isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            LONGLONG fileSize = ((LONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

            if (!isDir) {
                if (!PathMatchSpecA(fd.cFileName, g_CurrentFilter)) continue;
                if (IsAdvancedFiltered(fd.cFileName, fileSize)) continue;
            }

            char sizeStr[64] = { 0 };
            if (!isDir) { FormatSize(fileSize, sizeStr, sizeof(sizeStr)); }

            if (isDir) { AddListItem(g_hFileList, fd.cFileName, "", "文件夹", "", NULL, fd.dwFileAttributes); continue; }

            char fullPath[2048]; GetSafeFullPath(g_CurrentPath, fd.cFileName, fullPath, 2048);
            HANDLE hFile = CreateFileA(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
            if (hFile != INVALID_HANDLE_VALUE) {
                BY_HANDLE_FILE_INFORMATION fileInfo;
                if (GetFileInformationByHandle(hFile, &fileInfo)) {
                    char infoStr[128]; snprintf(infoStr, sizeof(infoStr), "已绑定: %lu", fileInfo.nNumberOfLinks);
                    char hlFlag[8];
                    snprintf(hlFlag, sizeof(hlFlag), "%d", fileInfo.nNumberOfLinks > 1 ? 1 : 0);

                    if (fileInfo.nNumberOfLinks > 1) AddListItem(g_hHardlinkList, fd.cFileName, infoStr, sizeStr, "", hlFlag, fd.dwFileAttributes);
                    else AddListItem(g_hFileList, fd.cFileName, sizeStr, infoStr, hlFlag, NULL, fd.dwFileAttributes);
                }
                CloseHandle(hFile);
            }
            else AddListItem(g_hFileList, fd.cFileName, sizeStr, "无权限读取", "", NULL, fd.dwFileAttributes);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    g_CurrentSortList = g_hFileList;
    g_CurrentSortColumn = g_SortColLeft;
    g_CurrentSortAsc = g_SortAscLeft;
    SendMessageA(g_hFileList, LVM_SORTITEMSEX, (WPARAM)g_hFileList, (LPARAM)CompareFuncEx);
    PostMessage(g_hMainWnd, WM_USER_SCAN_DONE, 0, 0);
    return 0;
}

void CollectFilesRecursively(const std::string& folder, std::vector<FileNode>& fileList) {
    if (g_bCancelAnalysis) return;
    char searchPath[2048]; GetSafeFullPath(folder.c_str(), "*.*", searchPath, 2048);
    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (g_bCancelAnalysis) break;
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            char fullPath[2048]; GetSafeFullPath(folder.c_str(), fd.cFileName, fullPath, 2048);

            if ((++g_nScanCounter & 0x3F) == 0) {
                snprintf(g_szScanFile, sizeof(g_szScanFile), "正在扫描: %s", fullPath);
                PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                CollectFilesRecursively(fullPath, fileList);
            }
            else if (PathMatchSpecA(fd.cFileName, g_CurrentFilter)) {
                LONGLONG fileSize = ((LONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                if (!IsAdvancedFiltered(fd.cFileName, fileSize)) {
                    FileNode node; node.fullPath = fullPath; node.fileName = fd.cFileName;
                    node.size.LowPart = fd.nFileSizeLow; node.size.HighPart = fd.nFileSizeHigh;
                    node.attr = fd.dwFileAttributes; fileList.push_back(node);
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

unsigned __stdcall AnalyzeDirectoryThread(void* pArguments) {
    g_llTotalSavedSpace = 0;
    g_nScanCounter = 0;
    std::vector<FileNode> allFiles;

    g_StatGroupCount = 0;
    g_StatDupFileCount = 0;
    EnterCriticalSection(&g_csParity);
    g_GroupParity.clear();
    LeaveCriticalSection(&g_csParity);
    DWORD dwAnalyzeStart = GetTickCount();

    snprintf(g_szScanFile, sizeof(g_szScanFile), "正在递归收集文件列表...");
    PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);

    for (size_t i = 0; i < g_TargetDirs.size(); ++i) {
        CollectFilesRecursively(g_TargetDirs[i], allFiles);
    }

    size_t totalHardlinksToCreate = 0;

    if (!g_bCancelAnalysis) {
        std::map<LONGLONG, std::vector<FileNode>> sizeMap;
        for (size_t i = 0; i < allFiles.size(); ++i) {
            if (g_bCancelAnalysis) break;
            if (allFiles[i].size.QuadPart > 0) sizeMap[allFiles[i].size.QuadPart].push_back(allFiles[i]);
        }

        size_t totalHashTasks = 0;
        for (std::map<LONGLONG, std::vector<FileNode>>::iterator it = sizeMap.begin(); it != sizeMap.end(); ++it) {
            if (it->second.size() > 1) totalHashTasks += it->second.size();
        }

        size_t completedTasks = 0;

        for (std::map<LONGLONG, std::vector<FileNode>>::iterator it = sizeMap.begin(); it != sizeMap.end(); ++it) {
            if (g_bCancelAnalysis) break;
            if (it->second.size() > 1) {
                std::map<std::string, std::vector<FileNode>> hashMap;
                for (size_t i = 0; i < it->second.size(); ++i) {
                    if (g_bCancelAnalysis) break;
                    snprintf(g_szScanFile, sizeof(g_szScanFile), "正在校验: %s", it->second[i].fullPath.c_str());
                    PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);
                    std::string hashVal;
                    if (CalculateFileSHA256(it->second[i].fullPath.c_str(), hashVal)) {
                        hashMap[hashVal].push_back(it->second[i]);
                    }
                    completedTasks++;
                    if (completedTasks % 5 == 0 || completedTasks == totalHashTasks) {
                        PostMessage(g_hMainWnd, WM_USER_UPDATE_PROGRESS, completedTasks, totalHashTasks);
                    }
                }

                for (std::map<std::string, std::vector<FileNode>>::iterator hit = hashMap.begin(); hit != hashMap.end(); ++hit) {
                    if (g_bCancelAnalysis) break;
                    if (hit->second.size() > 1) {

                        std::map<ULONGLONG, int> physicalFiles;
                        for (size_t k = 0; k < hit->second.size(); ++k) {
                            HANDLE hFile = CreateFileA(hit->second[k].fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                BY_HANDLE_FILE_INFORMATION fi;
                                if (GetFileInformationByHandle(hFile, &fi)) {
                                    ULONGLONG fileId = ((ULONGLONG)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
                                    physicalFiles[fileId]++;
                                }
                                CloseHandle(hFile);
                            }
                        }

                        size_t uniquePhysicalCount = physicalFiles.size();
                        LONGLONG savedSpace = 0;
                        if (uniquePhysicalCount > 1) {
                            size_t createCount = uniquePhysicalCount - 1;
                            totalHardlinksToCreate += createCount;
                            savedSpace = createCount * it->first;
                            g_llTotalSavedSpace += savedSpace;
                        }

                        // 统计：本组算 1 个重复组，组内文件计入重复文件数；分配交替底色
                        EnterCriticalSection(&g_csParity);
                        g_GroupParity[hit->first] = (int)(g_StatGroupCount & 1);
                        LeaveCriticalSection(&g_csParity);
                        g_StatGroupCount++;
                        g_StatDupFileCount += hit->second.size();

                        char szSaved[64]; FormatSize(savedSpace, szSaved, sizeof(szSaved));

                        for (size_t k = 0; k < hit->second.size(); ++k) {
                            if (g_bCancelAnalysis) break;
                            char status[128]; snprintf(status, sizeof(status), "重复(%zu个)", hit->second.size());

                            char hlFlag[8] = "0";
                            HANDLE hFile = CreateFileA(hit->second[k].fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                BY_HANDLE_FILE_INFORMATION fi;
                                if (GetFileInformationByHandle(hFile, &fi)) {
                                    if (fi.nNumberOfLinks > 1) strcpy(hlFlag, "1");
                                }
                                CloseHandle(hFile);
                            }

                            AddListItem(g_hHardlinkList, hit->second[k].fullPath.c_str(), status, szSaved, hit->first.c_str(), hlFlag, hit->second[k].attr, hit->second[k].fullPath.c_str());
                        }
                    }
                }
            }
        }
    }

    g_StatElapsedMs = GetTickCount() - dwAnalyzeStart;

    g_CurrentSortList = g_hHardlinkList;
    g_CurrentSortColumn = g_SortColRight;
    g_CurrentSortAsc = g_SortAscRight;
    SendMessageA(g_hHardlinkList, LVM_SORTITEMSEX, (WPARAM)g_hHardlinkList, (LPARAM)CompareFuncEx);
    PostMessage(g_hMainWnd, WM_USER_ANALYZE_DONE, (WPARAM)totalHardlinksToCreate, (LPARAM)g_bCancelAnalysis);
    return 0;
}

unsigned __stdcall CreateHardlinksThread(void* pArguments) {
    int count = (int)SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    int checkedCount = 0;

    for (int i = 0; i < count; i++) {
        if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;
    }

    std::map<std::string, std::vector<std::string>> dupGroups;
    for (int i = 0; i < count; i++) {
        // 如果用户勾选了文件，只处理被勾选的文件；如果没有勾选，处理全部
        if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;

        char path[2048] = { 0 }; char sha[128] = { 0 };
        GetListViewSubItemTextA(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemTextA(g_hHardlinkList, i, 3, sha, 128);
        if (strlen(path) > 0 && strlen(sha) > 0) dupGroups[sha].push_back(path);
    }

    size_t successCount = 0; size_t failCount = 0;

    for (std::map<std::string, std::vector<std::string>>::iterator it = dupGroups.begin(); it != dupGroups.end(); ++it) {
        if (g_bCancelAnalysis) break;
        std::vector<std::string>& paths = it->second;

        if (paths.size() > 1) {
            std::string master = paths[0];

            for (size_t i = 1; i < paths.size(); ++i) {
                if (g_bCancelAnalysis) break;
                std::string target = paths[i];

                if (g_bExcludeRisky && IsRiskyExt(target.c_str())) {
                    failCount++;
                    continue;
                }

                std::string targetBak = target + ".hlbak";

                if (MoveFileA(target.c_str(), targetBak.c_str())) {
                    if (CreateHardLinkA(target.c_str(), master.c_str(), NULL)) {
                        DeleteFileA(targetBak.c_str());
                        successCount++;
                    }
                    else {
                        MoveFileA(targetBak.c_str(), target.c_str());
                        failCount++;
                    }
                }
                else failCount++;
            }
        }
    }
    PostMessage(g_hMainWnd, WM_USER_CREATE_DONE, (WPARAM)successCount, (LPARAM)failCount);
    return 0;
}

BOOL IsRiskyExt(const char* path) {
    const char* ext = PathFindExtensionA(path);
    if (!ext || ext[0] != '.') return FALSE;
    char extLower[32]; lstrcpynA(extLower, ext, 32); CharLowerA(extLower);
    static const char* RISKY[] = { ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".bak", ".tmp", ".wps", NULL };
    for (int i = 0; RISKY[i]; i++) if (lstrcmpA(extLower, RISKY[i]) == 0) return TRUE;
    return FALSE;
}

BOOL BreakHardlink(const char* filepath) {
    char tempPath[2048]; snprintf(tempPath, sizeof(tempPath), "%s.tmp_hl_bak", filepath);
    if (!CopyFileA(filepath, tempPath, FALSE)) return FALSE;
    if (!DeleteFileA(filepath)) { DeleteFileA(tempPath); return FALSE; }
    return MoveFileA(tempPath, filepath);
}

void CopyToClipboard(HWND hwnd, const char* text) {
    if (OpenClipboard(hwnd)) {
        EmptyClipboard(); HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(text) + 1);
        if (hg) { memcpy(GlobalLock(hg), text, strlen(text) + 1); GlobalUnlock(hg); SetClipboardData(CF_TEXT, hg); }
        CloseClipboard();
    }
}

void ExportHardlinkList(HWND hwnd) {
    int count = (int)SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    if (count == 0) {
        MessageBoxA(hwnd, "右侧列表为空，请先进行【分析文件(查重)】再导出。", "提示", MB_OK | MB_ICONWARNING);
        return;
    }

    int checkedCount = 0;
    for (int i = 0; i < count; i++) {
        if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;
    }

    char fileName[2048] = "重复文件列表.csv";
    OPENFILENAMEA ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = "CSV 文件 (*.csv)\0*.csv\0文本文件 (*.txt)\0*.txt\0所有的类型\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = sizeof(fileName);
    ofn.lpstrDefExt = "csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileNameA(&ofn)) return;

    FILE* fp = fopen(fileName, "wb");
    if (!fp) {
        MessageBoxA(hwnd, "无法写入文件，请检查文件是否被占用或权限不足。", "错误", MB_OK | MB_ICONERROR);
        return;
    }

    fprintf(fp, "路径,状态,大小/可省,SHA256,已硬链接\r\n");

    size_t exported = 0;
    for (int i = 0; i < count; i++) {
        if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;
        char path[2048] = { 0 }, status[256] = { 0 }, sizeStr[128] = { 0 }, sha[128] = { 0 }, hl[16] = { 0 };
        GetListViewSubItemTextA(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemTextA(g_hHardlinkList, i, 1, status, 256);
        GetListViewSubItemTextA(g_hHardlinkList, i, 2, sizeStr, 128);
        GetListViewSubItemTextA(g_hHardlinkList, i, 3, sha, 128);
        GetListViewSubItemTextA(g_hHardlinkList, i, 4, hl, 16);
        fprintf(fp, "\"%s\",\"%s\",\"%s\",%s,%s\r\n", path, status, sizeStr, sha, (hl[0] == '1' ? "是" : "否"));
        exported++;
    }
    fclose(fp);

    char msg[2560];
    snprintf(msg, sizeof(msg), "已导出 %zu 条记录到：\n%s\n\n是否在打开文件所在位置？\n(该CSV可被 Excel 直接打开)", exported, fileName);
    if (MessageBoxA(hwnd, msg, "导出成功", MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
        char param[2048 + 20]; snprintf(param, sizeof(param), "/select,\"%s\"", fileName);
        ShellExecuteA(NULL, "open", "explorer.exe", param, NULL, SW_SHOWNORMAL);
    }
}

void AddListItem(HWND hList, const char* col0, const char* col1, const char* col2, const char* col3, const char* col4, DWORD dwAttributes, const char* overridePath) {
    SHFILEINFOA sfi = { 0 }; char targetPath[2048];
    if (overridePath) lstrcpyA(targetPath, overridePath);
    else GetSafeFullPath(g_CurrentPath, col0, targetPath, 2048);

    SHGetFileInfoA((LPCSTR)targetPath, dwAttributes, &sfi, sizeof(SHFILEINFOA), SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);

    LVITEMA lvi = { 0 }; lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvi.iItem = (int)SendMessageA(hList, LVM_GETITEMCOUNT, 0, 0);
    lvi.pszText = overridePath ? (LPSTR)overridePath : (LPSTR)col0;
    lvi.iImage = sfi.iIcon;
    lvi.lParam = (LPARAM)dwAttributes;
    int idx = (int)SendMessageA(hList, LVM_INSERTITEMA, 0, (LPARAM)&lvi);

    if (col1) { LVITEMA lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 1; lviSub.pszText = (LPSTR)col1; SendMessageA(hList, LVM_SETITEMTEXTA, idx, (LPARAM)&lviSub); }
    if (col2) { LVITEMA lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 2; lviSub.pszText = (LPSTR)col2; SendMessageA(hList, LVM_SETITEMTEXTA, idx, (LPARAM)&lviSub); }
    if (col3) { LVITEMA lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 3; lviSub.pszText = (LPSTR)col3; SendMessageA(hList, LVM_SETITEMTEXTA, idx, (LPARAM)&lviSub); }
    if (col4) { LVITEMA lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 4; lviSub.pszText = (LPSTR)col4; SendMessageA(hList, LVM_SETITEMTEXTA, idx, (LPARAM)&lviSub); }
}

void SetDefaultFont(HWND hwnd) {
    static HFONT s_hFont = NULL;
    if (!s_hFont) s_hFont = CreateFontA(DPIScale(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Microsoft YaHei");
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)s_hFont, MAKELPARAM(TRUE, 0));
}

void ShowFileContextMenu(HWND hwnd, POINT pt, BOOL isHardlinkList) {
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, IDM_COPY_FILENAME, (LPCSTR)"复制文件名");
    AppendMenuA(hMenu, MF_STRING, IDM_COPY_PATH, (LPCSTR)"复制完整路径");
    if (isHardlinkList) AppendMenuA(hMenu, MF_STRING, IDM_COPY_SHA256, (LPCSTR)"复制 SHA256 (用于比对)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_OPEN_EXPLORER, (LPCSTR)"在资源管理器中定位");
    if (isHardlinkList) AppendMenuA(hMenu, MF_STRING, IDM_CREATE_HLINK_CTX, (LPCSTR)"对该文件创建硬链接");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_DELETE, (LPCSTR)"[危险] 删除文件");
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

void CreateControls(HWND hwnd) {
    g_hTxtDisk = CreateWindowExA(0, "STATIC", "磁盘:", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hComboDisk = CreateWindowExA(0, WC_COMBOBOXA, "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, DPIScale(50), DPIScale(12), DPIScale(160), DPIScale(200), hwnd, (HMENU)(INT_PTR)ID_COMBO_DISK, g_hInst, NULL);

    char drives[256]; GetLogicalDriveStringsA(256, drives); char* drive = drives;
    while (*drive) {
        char volName[MAX_PATH] = { 0 }; char dispStr[MAX_PATH];
        GetVolumeInformationA(drive, volName, MAX_PATH, NULL, NULL, NULL, NULL, 0);
        if (volName[0]) snprintf(dispStr, sizeof(dispStr), "%s [%s]", drive, volName); else snprintf(dispStr, sizeof(dispStr), "%s", drive);
        SendMessageA(g_hComboDisk, CB_ADDSTRING, 0, (LPARAM)dispStr); drive += strlen(drive) + 1;
    }
    SendMessageA(g_hComboDisk, CB_SETCURSEL, 0, 0);

    g_hTxtAddr = CreateWindowExA(0, "STATIC", "地址:", WS_VISIBLE | WS_CHILD, DPIScale(220), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditAddress = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_CurrentPath, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(260), DPIScale(12), DPIScale(360), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_ADDRESS, g_hInst, NULL);

    g_hTxtFilter = CreateWindowExA(0, "STATIC", "类型:", WS_VISIBLE | WS_CHILD, DPIScale(630), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hComboFilter = CreateWindowExA(0, WC_COMBOBOXA, "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, DPIScale(670), DPIScale(12), DPIScale(300), DPIScale(400), hwnd, (HMENU)(INT_PTR)ID_COMBO_FILTER, g_hInst, NULL);

    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"自定义类型 (*.*)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"常用视频 (*.mp4;*.mkv;*.avi;*.rmvb;*.wmv;*.flv;*.mov;*.ts)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"高清/蓝光 (*.m2ts;*.vob;*.iso;*.webm;*.mts)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"常用音频 (*.mp3;*.wav;*.flac;*.aac;*.ogg;*.ape;*.m4a;*.wma)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"图片素材 (*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.webp;*.tiff)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"执行文件 (*.exe;*.dll;*.sys)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"压缩包 (*.zip;*.rar;*.7z;*.tar;*.gz)");
    SendMessageA(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)"文档 (*.txt;*.doc;*.docx;*.pdf;*.md)");
    SendMessageA(g_hComboFilter, CB_SETCURSEL, 0, 0);

    g_hGroupFilter = CreateWindowExA(0, "BUTTON", "高级筛选 (正则黑白名单 & 大小限制)", WS_VISIBLE | WS_CHILD | BS_GROUPBOX, DPIScale(10), DPIScale(42), DPIScale(960), DPIScale(60), hwnd, NULL, g_hInst, NULL);
    g_hTxtInc = CreateWindowExA(0, "STATIC", "包含(正则):", WS_VISIBLE | WS_CHILD, DPIScale(20), DPIScale(65), DPIScale(80), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditInc = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(100), DPIScale(62), DPIScale(150), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_INC_REGEX, g_hInst, NULL);
    g_hTxtExc = CreateWindowExA(0, "STATIC", "排除(正则):", WS_VISIBLE | WS_CHILD, DPIScale(270), DPIScale(65), DPIScale(80), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditExc = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(350), DPIScale(62), DPIScale(150), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_EXC_REGEX, g_hInst, NULL);
    g_hTxtSize = CreateWindowExA(0, "STATIC", "大小(MB):", WS_VISIBLE | WS_CHILD, DPIScale(610), DPIScale(65), DPIScale(60), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditSizeMin = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_NUMBER, DPIScale(670), DPIScale(62), DPIScale(60), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_MIN_SIZE, g_hInst, NULL);
    g_hTxtSizeTo = CreateWindowExA(0, "STATIC", "-", WS_VISIBLE | WS_CHILD, DPIScale(740), DPIScale(65), DPIScale(20), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditSizeMax = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_NUMBER, DPIScale(760), DPIScale(62), DPIScale(60), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_MAX_SIZE, g_hInst, NULL);

    // 新增全选 / 反选按钮
    g_hBtnSelAllL = CreateWindowExA(0, "BUTTON", "全选", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_SELALL_L, g_hInst, NULL);
    g_hBtnInvSelL = CreateWindowExA(0, "BUTTON", "反选", WS_VISIBLE | WS_CHILD, DPIScale(80), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_INVSEL_L, g_hInst, NULL);
    g_hBtnSelAllR = CreateWindowExA(0, "BUTTON", "全选", WS_VISIBLE | WS_CHILD, DPIScale(440), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_SELALL_R, g_hInst, NULL);
    g_hBtnInvSelR = CreateWindowExA(0, "BUTTON", "反选", WS_VISIBLE | WS_CHILD, DPIScale(510), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_INVSEL_R, g_hInst, NULL);
    g_hBtnExportR = CreateWindowExA(0, "BUTTON", "导出列表", WS_VISIBLE | WS_CHILD, DPIScale(580), DPIScale(110), DPIScale(90), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_EXPORT_R, g_hInst, NULL);

    g_hFileList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, DPIScale(10), DPIScale(140), DPIScale(420), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_FILE, g_hInst, NULL);
    LVCOLUMNA lvc = { 0 }; lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = DPIScale(170); lvc.pszText = (LPSTR)"名称(可点击排序)"; SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPSTR)"大小";       SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(100); lvc.pszText = (LPSTR)"状态";       SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(60);  lvc.pszText = (LPSTR)"硬链接";     SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 3, (LPARAM)&lvc);
    SendMessageA(g_hFileList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

    g_hHardlinkList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, DPIScale(440), DPIScale(140), DPIScale(530), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_HARDLINK, g_hInst, NULL);
    lvc.cx = DPIScale(170); lvc.pszText = (LPSTR)"已绑定/潜在重复文件"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPSTR)"状态信息"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(90);  lvc.pszText = (LPSTR)"大小/可省"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(140); lvc.pszText = (LPSTR)"SHA256"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 3, (LPARAM)&lvc);
    lvc.cx = DPIScale(50);  lvc.pszText = (LPSTR)"硬链接"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 4, (LPARAM)&lvc);
    SendMessageA(g_hHardlinkList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

    SHFILEINFOA sfi; HIMAGELIST hSysImageList = (HIMAGELIST)SHGetFileInfoA((LPCSTR)"C:\\", 0, &sfi, sizeof(SHFILEINFOA), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    SendMessageA(g_hFileList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);
    SendMessageA(g_hHardlinkList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);

    int btnY = 580;
    g_hBtnRefresh = CreateWindowExA(0, "BUTTON", "刷新当前目录", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(btnY), DPIScale(120), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_REFRESH, g_hInst, NULL);
    g_hBtnAnalyze = CreateWindowExA(0, "BUTTON", "分析文件(查重)", WS_VISIBLE | WS_CHILD, DPIScale(140), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ANALYZE, g_hInst, NULL);
    g_hBtnCreate = CreateWindowExA(0, "BUTTON", "一键创建硬链接", WS_VISIBLE | WS_CHILD, DPIScale(280), DPIScale(btnY), DPIScale(140), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_CREATE_HLINK, g_hInst, NULL);
    g_hBtnRestore = CreateWindowExA(0, "BUTTON", "解绑硬链接", WS_VISIBLE | WS_CHILD, DPIScale(430), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_RESTORE_SLINK, g_hInst, NULL);

    int btnY2 = 625;
    g_hTxtScanInfo = CreateWindowExA(0, "STATIC", "", WS_VISIBLE | WS_CHILD | SS_LEFT | SS_PATHELLIPSIS | SS_NOPREFIX, DPIScale(180), DPIScale(btnY2 + 2), DPIScale(300), DPIScale(18), hwnd, NULL, g_hInst, NULL);
    g_hProgressBar = CreateWindowExA(0, PROGRESS_CLASSA, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH, DPIScale(500), DPIScale(btnY2 + 2), DPIScale(180), DPIScale(16), hwnd, (HMENU)(INT_PTR)ID_PROGRESS_BAR, g_hInst, NULL);

    g_hTxtTotalSaved = CreateWindowExA(0, "STATIC", "硬链接后总计可省空间: 0.00 KB", WS_VISIBLE | WS_CHILD | SS_RIGHT, DPIScale(390), DPIScale(btnY2 + 8), DPIScale(460), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hBtnAbout = CreateWindowExA(0, "BUTTON", "关于作者", WS_VISIBLE | WS_CHILD, DPIScale(870), DPIScale(btnY2), DPIScale(100), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ABOUT, g_hInst, NULL);

    SetDefaultFont(g_hGroupFilter);
    SetDefaultFont(g_hTxtDisk); SetDefaultFont(g_hTxtAddr); SetDefaultFont(g_hTxtFilter);
    SetDefaultFont(g_hTxtInc); SetDefaultFont(g_hEditInc); SetDefaultFont(g_hTxtExc); SetDefaultFont(g_hEditExc);
    SetDefaultFont(g_hTxtSize); SetDefaultFont(g_hEditSizeMin); SetDefaultFont(g_hTxtSizeTo); SetDefaultFont(g_hEditSizeMax);
    SetDefaultFont(g_hTxtTotalSaved); SetDefaultFont(g_hComboDisk); SetDefaultFont(g_hEditAddress); SetDefaultFont(g_hComboFilter);
    SetDefaultFont(g_hFileList); SetDefaultFont(g_hHardlinkList);
    SetDefaultFont(g_hBtnSelAllL); SetDefaultFont(g_hBtnInvSelL); SetDefaultFont(g_hBtnSelAllR); SetDefaultFont(g_hBtnInvSelR);
    SetDefaultFont(g_hBtnExportR); SetDefaultFont(g_hTxtScanInfo);
    SetDefaultFont(g_hBtnRefresh); SetDefaultFont(g_hBtnAnalyze); SetDefaultFont(g_hBtnCreate); SetDefaultFont(g_hBtnRestore);
    SetDefaultFont(g_hBtnAbout);
}