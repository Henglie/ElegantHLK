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
#include <wincrypt.h> 
#include <stdio.h>
#include <process.h>
#include <string.h>
#include <gdiplus.h> // 原生实现高分辨率显示

#include <vector>
#include <map>
#include <string>

// 解决基础版 XP SDK 隐藏 SHA256 宏的问题
#ifndef CALG_SHA_256
#define ALG_SID_SHA_256 12
#define CALG_SHA_256 (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shlwapi.lib")

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
#define ID_BTN_SET_HOTKEY    1010
#define ID_BTN_ABOUT         1011

#define IDM_COPY_FILENAME    2001
#define IDM_COPY_PATH        2002
#define IDM_COPY_SHA256      2003
#define IDM_PASTE            2004
#define IDM_OPEN_EXPLORER    2005
#define IDM_CREATE_HLINK_CTX 2006
#define IDM_DELETE           2007

#define WM_USER_SCAN_DONE    (WM_USER + 100)
#define WM_USER_ANALYZE_DONE (WM_USER + 101)
#define WM_USER_CREATE_DONE  (WM_USER + 102)

HINSTANCE g_hInst;
HWND g_hMainWnd, g_hComboDisk, g_hEditAddress, g_hComboFilter, g_hFileList, g_hHardlinkList;
HWND g_hBtnRefresh, g_hBtnAnalyze, g_hBtnCreate, g_hBtnRestore, g_hBtnHotkey, g_hBtnAbout;
HWND g_hTxtTotalSaved;

char g_CurrentPath[2048] = "C:\\";
char g_CurrentFilter[1024] = "*.*";
BOOL g_bScanning = FALSE;
BOOL g_bSortAsc = TRUE;
LONGLONG g_llTotalSavedSpace = 0;

volatile BOOL g_bCancelAnalysis = FALSE;

int g_DPI = 96;
ULONG_PTR g_gdiplusToken;

struct FileNode {
    std::string fullPath;
    std::string fileName;
    LARGE_INTEGER size;
    DWORD attr;
};

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
void GenerateAHKScript(HWND hwnd);
int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
BOOL BreakHardlink(const char* filepath);
void GetSafeFullPath(const char* dir, const char* file, char* outPath, size_t maxLen);
BOOL CalculateFileSHA256(const char* filename, std::string& outHash);
void FormatSize(LONGLONG bytes, char* buf, size_t maxLen);

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
    EnableDPIAwareness();
    HDC hdc = GetDC(NULL); g_DPI = GetDeviceCaps(hdc, LOGPIXELSX); ReleaseDC(NULL, hdc);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icex);

    WNDCLASSEXA wc = { sizeof(WNDCLASSEXA) };
    wc.lpfnWndProc = WndProc; wc.hInstance = hInstance; wc.hCursor = LoadCursorA(NULL, (LPCSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW); wc.lpszClassName = "ElegantHardlinkClass";
    RegisterClassExA(&wc);

    g_hMainWnd = CreateWindowExA(0, "ElegantHardlinkClass", "优雅硬链接 V0.23",
        WS_OVERLAPPEDWINDOW ^ WS_THICKFRAME ^ WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, DPIScale(1000), DPIScale(620), NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd) return 0;
    ShowWindow(g_hMainWnd, nCmdShow); UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessageA(&msg); }
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    return (int)msg.wParam;
}

int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    HWND hList = (HWND)lParamSort;
    char txt1[2048] = { 0 }, txt2[2048] = { 0 };
    GetListViewSubItemTextA(hList, lParam1, 0, txt1, 2048);
    GetListViewSubItemTextA(hList, lParam2, 0, txt2, 2048);
    LPARAM param1 = GetListViewParamA(hList, lParam1);
    LPARAM param2 = GetListViewParamA(hList, lParam2);

    BOOL isDir1 = (param1 & FILE_ATTRIBUTE_DIRECTORY) != 0;
    BOOL isDir2 = (param2 & FILE_ATTRIBUTE_DIRECTORY) != 0;

    if (strcmp(txt1, "..") == 0) return -1;
    if (strcmp(txt2, "..") == 0) return 1;

    if (isDir1 && !isDir2) return -1;
    if (!isDir1 && isDir2) return 1;

    int res = _stricmp(txt1, txt2);
    return g_bSortAsc ? res : -res;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: CreateControls(hwnd); break;

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
            g_bSortAsc = !g_bSortAsc;
            SendMessageA(lpnmh->hwndFrom, LVM_SORTITEMSEX, (WPARAM)lpnmh->hwndFrom, (LPARAM)CompareFuncEx);
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
            case ID_BTN_REFRESH:
                if (g_bScanning) { g_bCancelAnalysis = TRUE; break; }
                GetWindowTextA(g_hEditAddress, g_CurrentPath, 2048);
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                SetWindowTextA(g_hTxtTotalSaved, "总计可省: 等待分析...");
                SendMessageA(g_hFileList, LVM_DELETEALLITEMS, 0, 0);
                SendMessageA(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                SetWindowTextA(g_hBtnRefresh, "正在停止...");
                _beginthreadex(NULL, 0, ScanDirectoryThread, NULL, 0, NULL);
                break;

            case ID_BTN_ANALYZE:
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) {
                        g_bCancelAnalysis = TRUE;
                        SetWindowTextA(g_hBtnAnalyze, "正在终止...");
                    }
                    break;
                }
                GetWindowTextA(g_hEditAddress, g_CurrentPath, 2048);
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                g_llTotalSavedSpace = 0;
                SendMessageA(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                SetWindowTextA(g_hBtnAnalyze, "终止分析");
                _beginthreadex(NULL, 0, AnalyzeDirectoryThread, NULL, 0, NULL);
                break;

            case ID_BTN_CREATE_HLINK:
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) { g_bCancelAnalysis = TRUE; SetWindowTextA(g_hBtnCreate, "正在终止..."); }
                    break;
                }
                if (SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0) == 0) {
                    MessageBoxA(hwnd, "请先执行【分析文件(查重)】，找出重复文件后再执行一键转换！", "提示", MB_OK | MB_ICONWARNING);
                    break;
                }
                if (MessageBoxA(hwnd, "【高危操作确认】\n确定要将右侧列表中所有重复的文件转换为硬链接吗？\n\n警告：程序将自动保留组内的第1个文件作为源文件，并「永久删除」其余重复的物理文件以释放空间！", "物理文件清理确认", MB_YESNO | MB_ICONWARNING) == IDYES) {
                    g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                    SetWindowTextA(g_hBtnCreate, "终止转换");
                    _beginthreadex(NULL, 0, CreateHardlinksThread, NULL, 0, NULL);
                }
                break;

            case ID_BTN_SET_HOTKEY: GenerateAHKScript(hwnd); break;
            case ID_BTN_ABOUT:
                //这是我的信息，把开源地址留下吧，作者名也别改qwq
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
            case IDM_COPY_FILENAME: CopyToClipboard(hwnd, selText); break;
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
            case IDM_CREATE_HLINK_CTX: {
                DWORD attr = (DWORD)GetListViewParamA(hActiveList, selIdx);
                if (attr & FILE_ATTRIBUTE_DIRECTORY) MessageBoxA(hwnd, "硬链接不能作用于文件夹！", "错误", MB_OK | MB_ICONERROR);
                else MessageBoxA(hwnd, "请使用左侧列表上方的『一键创建硬链接』或者快捷键脚本执行。", "提示", MB_OK);
                break;
            }
            }
        }
        break;

    case WM_USER_SCAN_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
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
        SetWindowTextA(g_hBtnRefresh, "刷新当前目录");
        SetWindowTextA(g_hBtnAnalyze, "分析文件(查重)");
        SetWindowTextA(g_hBtnCreate, "一键创建硬链接");

        char totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, sizeof(totalBuf));
        char finalStr[256]; snprintf(finalStr, sizeof(finalStr), "硬链接后总计可省空间: %s", totalBuf);
        SetWindowTextA(g_hTxtTotalSaved, finalStr);

        BOOL bCancelled = (BOOL)lParam; size_t count = (size_t)wParam;
        if (bCancelled) MessageBoxA(hwnd, "分析已被用户终止！", "提示", MB_OK | MB_ICONINFORMATION);
        else {
            char msg[256]; snprintf(msg, sizeof(msg), "分析成功！\n\n共发现可以创建的硬链接数：%zu 个\n预计可释放空间：%s", count, totalBuf);
            MessageBoxA(hwnd, msg, "查重分析完成", MB_OK | MB_ICONINFORMATION);
        }
        break;
    }

    case WM_USER_CREATE_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SetWindowTextA(g_hBtnRefresh, "刷新当前目录");
        SetWindowTextA(g_hBtnAnalyze, "分析文件(查重)");
        SetWindowTextA(g_hBtnCreate, "一键创建硬链接");

        size_t successCount = (size_t)wParam;
        size_t failCount = (size_t)lParam;

        char msg[256];
        snprintf(msg, sizeof(msg), "硬链接批量转换完成！\n\n成功替换并释放物理文件: %zu 个\n替换失败: %zu 个\n\n(即将自动刷新目录)", successCount, failCount);
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
    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProcA(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

unsigned __stdcall ScanDirectoryThread(void* pArguments) {
    char searchPath[2048]; GetSafeFullPath(g_CurrentPath, "*.*", searchPath, 2048);
    g_llTotalSavedSpace = 0;

    // 文件夹行，硬链接状态直接留空
    if (strlen(g_CurrentPath) > 3) AddListItem(g_hFileList, "..", "", "返回上一级", "", NULL, FILE_ATTRIBUTE_DIRECTORY);

    WIN32_FIND_DATAA fd; HANDLE hFind = FindFirstFileA(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (g_bCancelAnalysis) break;
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;

            BOOL isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            if (!isDir && !PathMatchSpecA(fd.cFileName, g_CurrentFilter)) continue;

            char sizeStr[64] = { 0 };
            if (!isDir) {
                LONGLONG fileSize = ((LONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                FormatSize(fileSize, sizeStr, sizeof(sizeStr));
            }

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

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) CollectFilesRecursively(fullPath, fileList);
            else if (PathMatchSpecA(fd.cFileName, g_CurrentFilter)) {
                FileNode node; node.fullPath = fullPath; node.fileName = fd.cFileName;
                node.size.LowPart = fd.nFileSizeLow; node.size.HighPart = fd.nFileSizeHigh;
                node.attr = fd.dwFileAttributes; fileList.push_back(node);
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
}

unsigned __stdcall AnalyzeDirectoryThread(void* pArguments) {
    g_llTotalSavedSpace = 0;
    std::vector<FileNode> allFiles;
    CollectFilesRecursively(g_CurrentPath, allFiles);

    size_t totalHardlinksToCreate = 0;

    if (!g_bCancelAnalysis) {
        std::map<LONGLONG, std::vector<FileNode>> sizeMap;
        for (size_t i = 0; i < allFiles.size(); ++i) {
            if (g_bCancelAnalysis) break;
            if (allFiles[i].size.QuadPart > 0) sizeMap[allFiles[i].size.QuadPart].push_back(allFiles[i]);
        }

        for (std::map<LONGLONG, std::vector<FileNode>>::iterator it = sizeMap.begin(); it != sizeMap.end(); ++it) {
            if (g_bCancelAnalysis) break;
            if (it->second.size() > 1) {
                std::map<std::string, std::vector<FileNode>> hashMap;
                for (size_t i = 0; i < it->second.size(); ++i) {
                    if (g_bCancelAnalysis) break;
                    std::string hashVal;
                    if (CalculateFileSHA256(it->second[i].fullPath.c_str(), hashVal)) hashMap[hashVal].push_back(it->second[i]);
                }

                for (std::map<std::string, std::vector<FileNode>>::iterator hit = hashMap.begin(); hit != hashMap.end(); ++hit) {
                    if (g_bCancelAnalysis) break;
                    if (hit->second.size() > 1) {
                        size_t createCount = hit->second.size() - 1;
                        totalHardlinksToCreate += createCount;
                        LONGLONG savedSpace = createCount * it->first;
                        g_llTotalSavedSpace += savedSpace;

                        char szSaved[64]; FormatSize(savedSpace, szSaved, sizeof(szSaved));

                        for (size_t k = 0; k < hit->second.size(); ++k) {
                            if (g_bCancelAnalysis) break;
                            char status[128]; snprintf(status, sizeof(status), "重复(%zu个)", hit->second.size());

                            // 动态判定这组深层重复文件到底有没有被硬链接过
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
    PostMessage(g_hMainWnd, WM_USER_ANALYZE_DONE, (WPARAM)totalHardlinksToCreate, (LPARAM)g_bCancelAnalysis);
    return 0;
}

unsigned __stdcall CreateHardlinksThread(void* pArguments) {
    int count = (int)SendMessageA(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);

    std::map<std::string, std::vector<std::string>> dupGroups;
    for (int i = 0; i < count; i++) {
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

void GenerateAHKScript(HWND hwnd) {
    FILE* fp = fopen("ElegantHardlink_Hotkey.ahk", "w");
    if (fp) {
        fprintf(fp, "; 优雅硬链接 - 自动化热键脚本\n^h::\n    Send, ^c\n    Sleep, 150\n    Loop, Parse, Clipboard, `n, `r\n    {\n        if (A_LoopField = \"\")\n            continue\n        SplitPath, A_LoopField, outName\n        RunWait, cmd.exe /c mklink /H \"%%A_WorkingDir%%\\%%outName%%\" \"%%A_LoopField%%\", , Hide\n    }\n    MsgBox, 64, 硬链接工具, 外部硬链接创建指令已下发！\nreturn\n");
        fclose(fp); MessageBoxA(hwnd, "脚本 ElegantHardlink_Hotkey.ahk 已生成！", "成功", MB_OK);
    }
}

void AddListItem(HWND hList, const char* col0, const char* col1, const char* col2, const char* col3, const char* col4, DWORD dwAttributes, const char* overridePath) {
    SHFILEINFOA sfi; char targetPath[2048];
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
    HFONT hFont = CreateFontA(DPIScale(15), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, "Microsoft YaHei");
    SendMessageA(hwnd, WM_SETFONT, (WPARAM)hFont, MAKELPARAM(TRUE, 0));
}

void ShowFileContextMenu(HWND hwnd, POINT pt, BOOL isHardlinkList) {
    HMENU hMenu = CreatePopupMenu();
    AppendMenuA(hMenu, MF_STRING, IDM_COPY_FILENAME, (LPCSTR)"复制文件名");
    AppendMenuA(hMenu, MF_STRING, IDM_COPY_PATH, (LPCSTR)"复制完整路径");
    if (isHardlinkList) AppendMenuA(hMenu, MF_STRING, IDM_COPY_SHA256, (LPCSTR)"复制 SHA256 (用于比对)");
    AppendMenuA(hMenu, MF_STRING, IDM_PASTE, (LPCSTR)"粘贴至当前目录 (需借助脚本)");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_OPEN_EXPLORER, (LPCSTR)"在资源管理器中定位");
    if (isHardlinkList) AppendMenuA(hMenu, MF_STRING, IDM_CREATE_HLINK_CTX, (LPCSTR)"对该文件创建硬链接");
    AppendMenuA(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenuA(hMenu, MF_STRING, IDM_DELETE, (LPCSTR)"[危险] 删除文件");
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

void CreateControls(HWND hwnd) {
    HWND hTxt1 = CreateWindowExA(0, "STATIC", "磁盘:", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hComboDisk = CreateWindowExA(0, WC_COMBOBOXA, "", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, DPIScale(50), DPIScale(10), DPIScale(160), DPIScale(200), hwnd, (HMENU)(INT_PTR)ID_COMBO_DISK, g_hInst, NULL);

    char drives[256]; GetLogicalDriveStringsA(256, drives); char* drive = drives;
    while (*drive) {
        char volName[MAX_PATH] = { 0 }; char dispStr[MAX_PATH];
        GetVolumeInformationA(drive, volName, MAX_PATH, NULL, NULL, NULL, NULL, 0);
        if (volName[0]) snprintf(dispStr, sizeof(dispStr), "%s [%s]", drive, volName); else snprintf(dispStr, sizeof(dispStr), "%s", drive);
        SendMessageA(g_hComboDisk, CB_ADDSTRING, 0, (LPARAM)dispStr); drive += strlen(drive) + 1;
    }
    SendMessageA(g_hComboDisk, CB_SETCURSEL, 0, 0);

    HWND hTxtAddr = CreateWindowExA(0, "STATIC", "地址:", WS_VISIBLE | WS_CHILD, DPIScale(220), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditAddress = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", g_CurrentPath, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(260), DPIScale(12), DPIScale(360), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_ADDRESS, g_hInst, NULL);

    HWND hTxtFilter = CreateWindowExA(0, "STATIC", "类型:", WS_VISIBLE | WS_CHILD, DPIScale(630), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
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

    g_hFileList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, DPIScale(10), DPIScale(45), DPIScale(420), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_FILE, g_hInst, NULL);
    LVCOLUMNA lvc = { 0 }; lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = DPIScale(170); lvc.pszText = (LPSTR)"名称(可点击排序)"; SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPSTR)"大小";       SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(100); lvc.pszText = (LPSTR)"状态";       SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(60);  lvc.pszText = (LPSTR)"硬链接";     SendMessageA(g_hFileList, LVM_INSERTCOLUMNA, 3, (LPARAM)&lvc);
    SendMessageA(g_hFileList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    g_hHardlinkList = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS | LVS_SINGLESEL, DPIScale(440), DPIScale(45), DPIScale(530), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_HARDLINK, g_hInst, NULL);
    lvc.cx = DPIScale(170); lvc.pszText = (LPSTR)"已绑定/潜在重复文件"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPSTR)"状态信息"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(90);  lvc.pszText = (LPSTR)"大小/可省"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(140); lvc.pszText = (LPSTR)"SHA256"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 3, (LPARAM)&lvc);
    lvc.cx = DPIScale(50);  lvc.pszText = (LPSTR)"硬链接"; SendMessageA(g_hHardlinkList, LVM_INSERTCOLUMNA, 4, (LPARAM)&lvc);
    SendMessageA(g_hHardlinkList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    SHFILEINFOA sfi; HIMAGELIST hSysImageList = (HIMAGELIST)SHGetFileInfoA((LPCSTR)"C:\\", 0, &sfi, sizeof(SHFILEINFOA), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    SendMessageA(g_hFileList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);
    SendMessageA(g_hHardlinkList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);

    int btnY = 480;
    g_hBtnRefresh = CreateWindowExA(0, "BUTTON", "刷新当前目录", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(btnY), DPIScale(120), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_REFRESH, g_hInst, NULL);
    g_hBtnAnalyze = CreateWindowExA(0, "BUTTON", "分析文件(查重)", WS_VISIBLE | WS_CHILD, DPIScale(140), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ANALYZE, g_hInst, NULL);
    g_hBtnCreate = CreateWindowExA(0, "BUTTON", "一键创建硬链接", WS_VISIBLE | WS_CHILD, DPIScale(280), DPIScale(btnY), DPIScale(140), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_CREATE_HLINK, g_hInst, NULL);
    g_hBtnRestore = CreateWindowExA(0, "BUTTON", "解绑硬链接", WS_VISIBLE | WS_CHILD, DPIScale(430), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_RESTORE_SLINK, g_hInst, NULL);

    g_hBtnHotkey = CreateWindowExA(0, "BUTTON", "生成快捷键脚本", WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(btnY + 45), DPIScale(160), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_SET_HOTKEY, g_hInst, NULL);
    g_hTxtTotalSaved = CreateWindowExA(0, "STATIC", "硬链接后总计可省空间: 0.00 KB", WS_VISIBLE | WS_CHILD | SS_RIGHT, DPIScale(300), DPIScale(btnY + 50), DPIScale(550), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hBtnAbout = CreateWindowExA(0, "BUTTON", "关于作者", WS_VISIBLE | WS_CHILD, DPIScale(870), DPIScale(btnY + 45), DPIScale(100), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ABOUT, g_hInst, NULL);

    SetDefaultFont(hTxt1); SetDefaultFont(hTxtAddr); SetDefaultFont(hTxtFilter); SetDefaultFont(g_hTxtTotalSaved);
    SetDefaultFont(g_hComboDisk); SetDefaultFont(g_hEditAddress); SetDefaultFont(g_hComboFilter);
    SetDefaultFont(g_hFileList); SetDefaultFont(g_hHardlinkList);
    SetDefaultFont(g_hBtnRefresh); SetDefaultFont(g_hBtnAnalyze); SetDefaultFont(g_hBtnCreate); SetDefaultFont(g_hBtnRestore);
    SetDefaultFont(g_hBtnHotkey); SetDefaultFont(g_hBtnAbout);
}