#define _CRT_SECURE_NO_WARNINGS 

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

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
#include <uxtheme.h>  // v1.2 暗色主题（XP 起自带，无需新依赖） 
#include <aclapi.h>     // v1.3: GetNamedSecurityInfo / SetEntriesInAcl
#include <stdio.h>
#include <stdarg.h>
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
#define ListView_GetCheckState(hwndLV, i) ((((UINT)(SendMessage((hwndLV), LVM_GETITEMSTATE, (WPARAM)(i), LVIS_STATEIMAGEMASK))) >> 12) - 1)
#endif

// v1.3: symbolic link support
#ifndef SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
#define SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE 0x2
#endif
#ifndef IO_REPARSE_TAG_SYMLINK
#define IO_REPARSE_TAG_SYMLINK (0xA000000CL)
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
#pragma comment(lib, "uxtheme.lib")

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
#define ID_BTN_DELETE_DUPS   1022
#define ID_CHK_SLINK         1025
#define ID_BTN_SETTINGS      1027 // 设置按钮：语言/主题/字号统一入口

#define IDM_COPY_FILENAME    2001
#define IDM_COPY_PATH        2002
#define IDM_COPY_SHA256      2003
#define IDM_PASTE            2004
#define IDM_OPEN_EXPLORER    2005
#define IDM_CREATE_HLINK_CTX 2006
#define IDM_DELETE           2007
#define IDM_OPEN_GROUP       2008 // v1.5
#define IDM_LANG_AUTO        3001
#define IDM_LANG_ZH          3002
#define IDM_LANG_EN          3003
#define IDM_THEME_AUTO       3011
#define IDM_THEME_LIGHT      3012
#define IDM_THEME_DARK       3013
#define IDM_FONT_S           3021 // v1.5
#define IDM_FONT_M           3022
#define IDM_FONT_L           3023
#define IDM_FONT_XL          3024

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
HWND g_hBtnDelDup;            // v1.2 新增按钮
HWND g_hChkSlink;               // v1.3: 软连接模式复选框
BOOL g_bSlinkMode = FALSE;      // v1.3: TRUE = 一键转换时建软连接
int g_AnchorL = -1, g_AnchorR = -1; // v1.3: Shift 范围勾选的锚点行
volatile LONG g_nAclFixed = 0;  // v1.3: 本轮 ACL 权限接管成功次数
int g_FontPt = 11;             // v1.5: UI 字号（磅），注册表可存
int g_SplitX = 0;              // v1.5: 左右列表分栏线客户区 x（0=未初始化）
int g_SplitPermille = 500;     // v1.5: 分栏比例（千分比，按可用宽度）
BOOL g_bDragSplit = FALSE;     // v1.5: 正在拖拽分栏
HWND g_hBtnSettings;          // 设置按钮（语言/主题/字号统一入口）
wchar_t g_szScanFile[2048] = L"";
volatile int g_nScanCounter = 0;

// V1.1 统计与拖拽
size_t g_StatGroupCount = 0;   // 重复组数
size_t g_StatDupFileCount = 0; // 重复文件总数
DWORD  g_StatElapsedMs = 0;    // 分析耗时(毫秒)
std::map<std::wstring, int> g_GroupParity; // SHA256 -> 0/1 交替底色
CRITICAL_SECTION g_csParity;               // 保护 g_GroupParity 跨线程访问

// 静态文本和输入框 HWND
HWND g_hTxtDisk, g_hTxtAddr, g_hTxtFilter;
HWND g_hTxtInc, g_hEditInc, g_hTxtExc, g_hEditExc, g_hTxtSize, g_hEditSizeMin, g_hTxtSizeTo, g_hEditSizeMax;

wchar_t g_CurrentPath[2048] = L"C:\\";
wchar_t g_CurrentFilter[1024] = L"*.*";

// 高级过滤参数
wchar_t g_IncludeRegex[1024] = L"";
wchar_t g_ExcludeRegex[1024] = L"";
LONGLONG g_MinSize = 0;
LONGLONG g_MaxSize = 0;

BOOL g_bScanning = FALSE;
BOOL g_bExcludeRisky = FALSE;
LONGLONG g_llTotalSavedSpace = 0;

volatile BOOL g_bCancelAnalysis = FALSE;

int g_DPI = 96;
ULONG_PTR g_gdiplusToken;

struct FileNode {
    std::wstring fullPath;
    std::wstring fileName;
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
std::vector<std::wstring> g_TargetDirs;

// ===================== v1.2：i18n 字符串表 =====================
// zh 列为 GBK 字节、en 列为纯 ASCII，统一走 A 版 Win32 API；非中文系统只显示 ASCII，永远不乱码。
enum StrId {
    S_TITLE, S_DISK, S_ADDR, S_TYPE, S_GROUP_FILTER, S_INC_REGEX, S_EXC_REGEX, S_SIZE_MB,
    S_FLT_CUSTOM, S_FLT_VIDEO, S_FLT_HD, S_FLT_AUDIO, S_FLT_IMAGE, S_FLT_EXE, S_FLT_ZIP, S_FLT_DOC,
    S_BTN_SELALL, S_BTN_INVSEL, S_BTN_EXPORT, S_BTN_REFRESH, S_BTN_ANALYZE, S_BTN_CREATE,
    S_BTN_RESTORE, S_BTN_ABOUT, S_BTN_DELDUP, S_BTN_LANG, S_BTN_THEME,
    S_COL_NAME, S_COL_SIZE, S_COL_STATUS, S_COL_HL, S_COL_DUP, S_COL_STATUSINFO, S_COL_SIZESAVE,
    S_UP_LEVEL, S_FOLDER, S_LINKS_FMT, S_NO_PERM, S_SCANNING_FMT, S_COLLECTING, S_HASHING_FMT, S_DUP_FMT,
    S_STOPPING, S_STOP_SCAN, S_ABORTING, S_STOP_ANALYZE, S_STOP_CREATE, S_WAIT_ANALYZE,
    S_TOTAL_SAVED_FMT, S_TOTAL_SAVED_INIT, S_STATS_FMT,
    S_T_TIP, S_T_ERROR, S_T_DONE,
    S_MSG_NEED_ANALYZE, S_MSG_RISKY, S_T_RISKY, S_MSG_CONFIRM_ALL, S_T_CONFIRM_ALL, S_MSG_CONFIRM_SEL, S_T_CONFIRM_SEL,
    S_MSG_EMPTY_R_ANALYZE, S_MSG_NO_UNLINK, S_MSG_UNLINK_ASK, S_T_UNLINK, S_MSG_UNLINK_DONE,
    S_MSG_ABOUT, S_MSG_DIR_HLINK, S_MSG_USE_MAIN_BTN, S_MSG_DEL_ONE, S_T_DEL_RECYCLE,
    S_MSG_ANALYZE_CANCELLED, S_MSG_ANALYZE_DONE, S_T_ANALYZE_DONE, S_MSG_CREATE_DONE, S_T_OP_DONE,
    S_MSG_EMPTY_EXPORT, S_EXPORT_DEFAULT_NAME, S_EXPORT_FILTER, S_MSG_WRITE_FAIL,
    S_CSV_HEADER, S_YES, S_NO, S_MSG_EXPORT_DONE, S_T_EXPORT_DONE,
    S_CTX_NAME, S_CTX_PATH, S_CTX_SHA, S_CTX_EXPLORE, S_CTX_CREATEHL, S_CTX_DELETE,
    S_MSG_EMPTY_R_SIMPLE, S_MSG_DELDUP_ASK, S_T_DELDUP, S_MSG_DELDUP_DONE, S_MSG_DELDUP_NONE, S_SKIPPED_PROTECTED,
    S_TXT_TITLE, S_TXT_GROUP, S_TXT_KEEP, S_TXT_DUP, S_TXT_HINT,
    S_MENU_FOLLOW, S_MENU_LIGHT, S_MENU_DARK,
    S_CHK_SLINK, S_BTN_CREATE_SL, S_MSG_CONFIRM_ALL_SL, S_MSG_CONFIRM_SEL_SL,
    S_MSG_CREATE_DONE_SL, S_MSG_SL_FAIL_HINT, S_MSG_SL_NO_SUPPORT,     S_ACL_COUNT_FMT,
    S_BTN_FONT, S_FONT_S, S_FONT_M, S_FONT_L, S_FONT_XL, S_CTX_OPEN_GROUP, // v1.5
S_BTN_SETTINGS, // 设置
    S__COUNT
};

static const wchar_t* const STR_TBL[S__COUNT][2] = {
    { L"优雅硬链接 V1.6", L"ElegantHLK V1.6" },                                       // S_TITLE
    { L"磁盘:", L"Disk:" },                                                           // S_DISK
    { L"地址:", L"Path:" },                                                           // S_ADDR
    { L"类型:", L"Type:" },                                                           // S_TYPE
    { L"高级筛选 (正则黑白名单 & 大小限制)", L"Advanced Filters (regex white/blacklist & size)" }, // S_GROUP_FILTER
    { L"包含(正则):", L"Include(regex):" },                                           // S_INC_REGEX
    { L"排除(正则):", L"Exclude(regex):" },                                           // S_EXC_REGEX
    { L"大小(MB):", L"Size(MB):" },                                                   // S_SIZE_MB
    { L"自定义类型 (*.*)", L"Custom (*.*)" },                                         // S_FLT_CUSTOM
    { L"常用视频 (*.mp4;*.mkv;*.avi;*.rmvb;*.wmv;*.flv;*.mov;*.ts)", L"Videos (*.mp4;*.mkv;*.avi;*.rmvb;*.wmv;*.flv;*.mov;*.ts)" },
    { L"高清/蓝光 (*.m2ts;*.vob;*.iso;*.webm;*.mts)", L"HD/Blu-ray (*.m2ts;*.vob;*.iso;*.webm;*.mts)" },
    { L"常用音频 (*.mp3;*.wav;*.flac;*.aac;*.ogg;*.ape;*.m4a;*.wma)", L"Audio (*.mp3;*.wav;*.flac;*.aac;*.ogg;*.ape;*.m4a;*.wma)" },
    { L"图片素材 (*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.webp;*.tiff)", L"Images (*.jpg;*.jpeg;*.png;*.gif;*.bmp;*.webp;*.tiff)" },
    { L"执行文件 (*.exe;*.dll;*.sys)", L"Executables (*.exe;*.dll;*.sys)" },
    { L"压缩包 (*.zip;*.rar;*.7z;*.tar;*.gz)", L"Archives (*.zip;*.rar;*.7z;*.tar;*.gz)" },
    { L"文档 (*.txt;*.doc;*.docx;*.pdf;*.md)", L"Documents (*.txt;*.doc;*.docx;*.pdf;*.md)" },
    { L"全选", L"All" },                                                              // S_BTN_SELALL
    { L"反选", L"Invert" },                                                           // S_BTN_INVSEL
    { L"导出列表", L"Export" },                                                       // S_BTN_EXPORT
    { L"刷新当前目录", L"Refresh Dir" },                                              // S_BTN_REFRESH
    { L"分析文件(查重)", L"Analyze Dupes" },                                          // S_BTN_ANALYZE
    { L"一键创建硬链接", L"Create Hardlinks" },                                       // S_BTN_CREATE
    { L"解绑硬链接", L"Break Hardlink" },                                             // S_BTN_RESTORE
    { L"关于作者", L"About" },                                                        // S_BTN_ABOUT
    { L"删除重复文件", L"Delete Dupes" },                                             // S_BTN_DELDUP
    { L"语言", L"Language" },                                                         // S_BTN_LANG
    { L"主题", L"Theme" },                                                            // S_BTN_THEME
    { L"名称(可点击排序)", L"Name (click to sort)" },                                 // S_COL_NAME
    { L"大小", L"Size" },                                                             // S_COL_SIZE
    { L"状态", L"Status" },                                                           // S_COL_STATUS
    { L"硬链接", L"Hardlink" },                                                       // S_COL_HL
    { L"已绑定/潜在重复文件", L"Linked/Duplicate Files" },                            // S_COL_DUP
    { L"状态信息", L"Status Info" },                                                  // S_COL_STATUSINFO
    { L"大小/可省", L"Size/Savings" },                                                // S_COL_SIZESAVE
    { L"返回上一级", L"[Up one level]" },                                             // S_UP_LEVEL
    { L"文件夹", L"Folder" },                                                         // S_FOLDER
    { L"已绑定: %lu", L"Links: %lu" },                                                // S_LINKS_FMT
    { L"无权限读取", L"Access Denied" },                                              // S_NO_PERM
    { L"正在扫描: %s", L"Scanning: %s" },                                             // S_SCANNING_FMT
    { L"正在递归收集文件列表...", L"Collecting file list..." },                       // S_COLLECTING
    { L"正在校验: %s", L"Hashing: %s" },                                              // S_HASHING_FMT
    { L"重复(%zu个)", L"Dupes(%zu)" },                                                // S_DUP_FMT
    { L"正在停止...", L"Stopping..." },                                               // S_STOPPING
    { L"停止扫描", L"Stop Scan" },                                                    // S_STOP_SCAN
    { L"正在终止...", L"Terminating..." },                                            // S_ABORTING
    { L"终止分析", L"Stop Analysis" },                                                // S_STOP_ANALYZE
    { L"终止转换", L"Stop Convert" },                                                 // S_STOP_CREATE
    { L"总计可省: 等待分析...", L"Total savings: waiting..." },                       // S_WAIT_ANALYZE
    { L"硬链接后总计可省空间: %s", L"Total savings after hardlink: %s" },             // S_TOTAL_SAVED_FMT
    { L"硬链接后总计可省空间: 0.00 KB", L"Total savings after hardlink: 0.00 KB" },   // S_TOTAL_SAVED_INIT
    { L"可省空间: %s  |  重复组: %zu  |  重复文件: %zu  |  耗时: %.2fs", L"Savings: %s  |  Groups: %zu  |  Files: %zu  |  Time: %.2fs" }, // S_STATS_FMT
    { L"提示", L"Notice" },                                                           // S_T_TIP
    { L"错误", L"Error" },                                                            // S_T_ERROR
    { L"完成", L"Done" },                                                             // S_T_DONE
    { L"请先执行【分析文件(查重)】，找出重复文件后再执行一键转换！", L"Please run [Analyze Dupes] first to find duplicates before creating hardlinks!" }, // S_MSG_NEED_ANALYZE
    { L"检测到易改变的办公文档或备份文件（如 .docx, .xlsx, .bak 等）。\n硬链接会导致一处修改处处被修改，不建议对需要独立编辑的文件使用。\n\n[是(Y)] 安全模式：自动排除这些高风险文件并转换其余文件\n[否(N)] 强制模式：无视警告，全部转换为硬链接\n[取消] 终止操作",
      L"Detected frequently-changing office documents or backup files (e.g. .docx, .xlsx, .bak).\nHardlinks mean editing one edits all; not recommended for files you edit independently.\n\n[Yes] Safe mode: exclude these risky files and convert the rest\n[No] Force mode: ignore the warning and convert everything\n[Cancel] Abort" }, // S_MSG_RISKY
    { L"高危文件拦截警告", L"Risky Files Warning" },                                  // S_T_RISKY
    { L"您没有在右侧勾选任何指定文件。\n确定要将右侧列表中【所有】重复的文件全部转换为硬链接吗？",
      L"No files are checked on the right.\nConvert ALL duplicate files in the right list to hardlinks?" }, // S_MSG_CONFIRM_ALL
    { L"全部清理确认", L"Convert All Confirmation" },                                 // S_T_CONFIRM_ALL
    { L"确定要将您【勾选】的重复的文件转换为硬链接吗？\n(未勾选的将自动忽略)",
      L"Convert the CHECKED duplicate files to hardlinks?\n(Unchecked items will be ignored)" }, // S_MSG_CONFIRM_SEL
    { L"选中文件清理确认", L"Convert Checked Confirmation" },                         // S_T_CONFIRM_SEL
    { L"右侧列表为空，请先「分析文件(查重)」找出已有硬链接。", L"Right list is empty. Run [Analyze Dupes] first to find existing hardlinks." }, // S_MSG_EMPTY_R_ANALYZE
    { L"没有可解绑的项（需要第 5 列「硬链接」为 1）。", L"Nothing to break (column 5 'Hardlink' must be 1)." }, // S_MSG_NO_UNLINK
    { L"将对 %zu 个文件执行解绑：先复制实数据到临时文件，再写回原路径，期间会临时占用同等空间。\n继续？",
      L"Will break hardlinks for %zu files: copy the real data to a temp file, then write it back; equal disk space is used temporarily.\nContinue?" }, // S_MSG_UNLINK_ASK
    { L"解绑硬链接确认", L"Break Hardlink Confirmation" },                            // S_T_UNLINK
    { L"解绑完成。\n\n成功：%zu\n失败：%zu", L"Break done.\n\nSucceeded: %zu\nFailed: %zu" }, // S_MSG_UNLINK_DONE
    { L"作者：恒烈 EternalBlaze\ngithub项目地址：https://github.com/Henglie/ElegantHLK\n开源协议：MIT",
      L"Author: Henglie EternalBlaze\nGitHub: https://github.com/Henglie/ElegantHLK\nLicense: MIT" }, // S_MSG_ABOUT
    { L"硬链接不能作用于文件夹！", L"Hardlinks cannot be applied to folders!" },      // S_MSG_DIR_HLINK
    { L"请使用列表上方的『一键创建硬链接』按钮执行。", L"Please use the [Create Hardlinks] button below the list." }, // S_MSG_USE_MAIN_BTN
    { L"确定将此项送入回收站？\n\n%s", L"Send this item to the Recycle Bin?\n\n%s" }, // S_MSG_DEL_ONE
    { L"删除到回收站", L"Delete to Recycle Bin" },                                    // S_T_DEL_RECYCLE
    { L"分析已被用户终止！", L"Analysis cancelled by user!" },                        // S_MSG_ANALYZE_CANCELLED
    { L"分析成功！\n\n重复文件组数：%zu 组\n重复文件总数：%zu 个\n可创建的硬链接数：%zu 个\n预计可释放空间：%s\n本次分析耗时：%.2f 秒",
      L"Analysis complete!\n\nDuplicate groups: %zu\nDuplicate files: %zu\nHardlinks to create: %zu\nEstimated space to free: %s\nTime elapsed: %.2f s" }, // S_MSG_ANALYZE_DONE
    { L"查重分析完成", L"Analysis Complete" },                                        // S_T_ANALYZE_DONE
    { L"硬链接批量转换完成！\n\n成功替换并释放物理文件: %zu 个\n替换失败(或已排除): %zu 个\n\n(即将自动刷新目录)",
      L"Batch hardlink conversion done!\n\nConverted and freed: %zu\nFailed (or excluded): %zu\n\n(The directory will refresh automatically)" }, // S_MSG_CREATE_DONE
    { L"操作完成", L"Operation Complete" },                                           // S_T_OP_DONE
    { L"右侧列表为空，请先进行【分析文件(查重)】再导出。", L"Right list is empty. Run [Analyze Dupes] before exporting." }, // S_MSG_EMPTY_EXPORT
    { L"重复文件列表.csv", L"duplicate_list.csv" },                                   // S_EXPORT_DEFAULT_NAME
    { L"CSV 文件 (*.csv)\0*.csv\0文本文件 (*.txt)\0*.txt\0所有的类型\0*.*\0", L"CSV File (*.csv)\0*.csv\0Text File (*.txt)\0*.txt\0All Files\0*.*\0" }, // S_EXPORT_FILTER
    { L"无法写入文件，请检查文件是否被占用或权限不足。", L"Cannot write the file. Check whether it is locked or permission is denied." }, // S_MSG_WRITE_FAIL
    { L"路径,状态,大小/可省,SHA256,已硬链接\r\n", L"Path,Status,Size/Savings,SHA256,Hardlinked\r\n" }, // S_CSV_HEADER
    { L"是", L"Yes" },                                                                // S_YES
    { L"否", L"No" },                                                                 // S_NO
    { L"已导出 %zu 条记录到：\n%s\n\n是否打开文件所在位置？", L"Exported %zu records to:\n%s\n\nOpen the containing folder?" }, // S_MSG_EXPORT_DONE
    { L"导出成功", L"Export Complete" },                                              // S_T_EXPORT_DONE
    { L"复制文件名", L"Copy Filename" },                                              // S_CTX_NAME
    { L"复制完整路径", L"Copy Full Path" },                                           // S_CTX_PATH
    { L"复制 SHA256 (用于比对)", L"Copy SHA256 (for comparison)" },                   // S_CTX_SHA
    { L"在资源管理器中定位", L"Locate in Explorer" },                                 // S_CTX_EXPLORE
    { L"对该文件创建硬链接", L"Create Hardlink for This File" },                      // S_CTX_CREATEHL
    { L"[危险] 删除文件", L"[Danger] Delete File" },                                  // S_CTX_DELETE
    { L"右侧列表为空，请先执行【分析文件(查重)】。", L"Right list is empty. Run [Analyze Dupes] first." }, // S_MSG_EMPTY_R_SIMPLE
    { L"将保留每组第 1 个文件，其余 %zu 个重复副本【送入回收站】（不创建硬链接，可随时还原）。\n继续？",
      L"The 1st file of each group is kept; the other %zu duplicate copies go to the Recycle Bin (no hardlinks; restorable anytime).\nContinue?" }, // S_MSG_DELDUP_ASK
    { L"删除重复文件确认", L"Delete Duplicates Confirmation" },                       // S_T_DELDUP
    { L"删除完成。\n\n已送入回收站：%zu\n失败：%zu", L"Delete done.\n\nSent to Recycle Bin: %zu\nFailed: %zu" }, // S_MSG_DELDUP_DONE
    { L"没有可删除的重复文件（可能仅剩受保护路径项）。", L"No duplicate files can be deleted (only protected paths remain)." }, // S_MSG_DELDUP_NONE
    { L"已跳过受保护路径", L"Skipped protected paths" },                              // S_SKIPPED_PROTECTED
    { L"ElegantHLK 重复文件清单", L"ElegantHLK Duplicate File List" },                // S_TXT_TITLE
    { L"组 %zu（SHA256: %s）", L"Group %zu (SHA256: %s)" },                           // S_TXT_GROUP
    { L"  [保留] %s", L"  [Keep] %s" },                                               // S_TXT_KEEP
    { L"  [重复] %s", L"  [Dupe] %s" },                                               // S_TXT_DUP
    { L"提示：每组保留第 1 个，其余 [重复] 项可安全删除或转换为硬链接。", L"Hint: keep the 1st of each group; [Dupe] items can be safely deleted or converted to hardlinks." }, // S_TXT_HINT
    { L"跟随系统", L"Follow System" },                                                // S_MENU_FOLLOW
    { L"浅色", L"Light" },                                                            // S_MENU_LIGHT
    { L"深色", L"Dark" },                                                             // S_MENU_DARK
    { L"软连接模式", L"Symlink mode" },                                          // S_CHK_SLINK
    { L"一键创建软连接", L"Create Symlinks" },                                     // S_BTN_CREATE_SL
    { L"将为【所有】重复文件创建软连接，指向每组第 1 个文件（可跨盘符）。\n软连接只是链接，源文件被移动或删除后会失效。\n\n确定继续吗？", L"Will create symlinks for ALL duplicate files, each pointing to the 1st file of its group (works across volumes).\nA symlink breaks when the source file is moved or deleted.\n\nContinue?" }, // S_MSG_CONFIRM_ALL_SL
    { L"将为【勾选】的重复文件创建软连接，指向每组第 1 个文件（可跨盘符）。\n软连接只是链接，源文件被移动或删除后会失效。\n\n继续？", L"Will create symlinks for the CHECKED duplicate files, each pointing to the 1st file of its group (works across volumes).\nA symlink breaks when the source file is moved or deleted.\n\nContinue?" }, // S_MSG_CONFIRM_SEL_SL
    { L"软连接批量创建完成！\n\n成功创建: %zu 个\n失败: %zu 个\n\n(即将自动刷新目录)", L"Batch symlink creation done!\n\nCreated: %zu\nFailed: %zu\n\n(The directory will refresh automatically)" }, // S_MSG_CREATE_DONE_SL
    { L"部分软连接创建失败，常见原因：当前账户没有 SeCreateSymbolicLink 权限。\n解决办法：右键「以管理员身份运行」本程序；或在 Win10 创意者更新及以上系统开启「开发者模式」。", L"Some symlinks failed. Common cause: the current account lacks the SeCreateSymbolicLink privilege.\nFix: run this program as administrator, or enable Developer Mode on Windows 10 (1703+)." }, // S_MSG_SL_FAIL_HINT
    { L"当前系统不支持创建软连接（需要 Windows Vista 及以上）。", L"This system cannot create symbolic links (Windows Vista or later required)." }, // S_MSG_SL_NO_SUPPORT
    { L"(其中通过权限接管访问: %zu 个)", L"(accessed via ownership takeover: %zu)" }, // S_ACL_COUNT_FMT
    { L"字号", L"Size" },                                           // S_BTN_FONT
    { L"小（10 号字）", L"Small (10pt)" },                          // S_FONT_S
    { L"标准（11 号字）", L"Standard (11pt)" },                     // S_FONT_M
    { L"大（12 号字）", L"Large (12pt)" },                          // S_FONT_L
    { L"特大（14 号字）", L"Extra (14pt)" },                        // S_FONT_XL
    { L"打开本组所有文件位置", L"Open all locations in this group" }, // S_CTX_OPEN_GROUP
    { L"设置", L"Settings" },                                      // S_BTN_SETTINGS
};

int g_LangMode = 0; // 0=跟随系统 1=中文 2=English
int g_Lang = 0;     // 解析结果：0=zh 1=en
#define TR(id) (STR_TBL[id][g_Lang])

// ===================== v1.2：昼夜主题（纯 Win32 实现，无新增技术栈）=====================
int g_ThemeMode = 0;  // 0=跟随系统 1=浅色 2=深色
BOOL g_bDark = FALSE;
HBRUSH g_hbrBg = NULL, g_hbrEdit = NULL;
// --- 函数声明 ---
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void CreateControls(HWND hwnd);
void SetDefaultFont(HWND hwnd);
void ShowFileContextMenu(HWND hwnd, POINT pt, BOOL isHardlinkList);
unsigned __stdcall ScanDirectoryThread(void* pArguments);
unsigned __stdcall AnalyzeDirectoryThread(void* pArguments);
unsigned __stdcall CreateHardlinksThread(void* pArguments);
void AddListItem(HWND hList, const wchar_t* col0, const wchar_t* col1, const wchar_t* col2, const wchar_t* col3, const wchar_t* col4, DWORD dwAttributes, const wchar_t* overridePath = NULL);
void CopyToClipboard(HWND hwnd, const wchar_t* text);
void ExportHardlinkList(HWND hwnd);
int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);
BOOL BreakHardlink(const wchar_t* filepath);
void GetSafeFullPath(const wchar_t* dir, const wchar_t* file, wchar_t* outPath, size_t maxLen);
BOOL CalculateFileSHA256(const wchar_t* filename, std::wstring& outHash);
void FormatSize(LONGLONG bytes, wchar_t* buf, size_t maxLen);
LONGLONG ParseSize(const wchar_t* str);
void UpdateAdvancedFilters();
bool IsAdvancedFiltered(const wchar_t* filename, LONGLONG fileSize);
BOOL IsRiskyExt(const wchar_t* path);
BOOL IsProtectedPath(const wchar_t* path);
void LoadSettings();
void ApplyLanguage();
void ApplyLanguageToUI();
void ApplyTheme();
BOOL SystemDarkModeEnabled();
void AppendThemedItem(HMENU hMenu, UINT id, const wchar_t* text);
void AppendThemedSub(HMENU hParent, HMENU hSub, const wchar_t* text);
void DoDeleteDuplicates(HWND hwnd);
HFONT GetAppFont();
DWORD RegGetDword(const wchar_t* name, DWORD defVal);
void RegSetDword(const wchar_t* name, DWORD val);
void DrawThemedButton(LPDRAWITEMSTRUCT dis);
void DrawThemedMenuItem(LPDRAWITEMSTRUCT dis);
void ApplyFontToUI(); // v1.5
void OpenGroupLocations(HWND hwnd, int iItem); // v1.5
// v1.3: ACL 权限兜底（issue：即便提权，仍有属主/DACL 拒绝访问的文件）
typedef struct {
    wchar_t path[2048];
    BOOL active;
    PSECURITY_DESCRIPTOR sd;
    PSID owner, group;
    PACL dacl, sacl;
} AclRestore;
static void AclRestoreAccess(AclRestore* st);
static BOOL AclGrantAccess(const wchar_t* path, BOOL isDir, AclRestore* st);
static HANDLE OpenFileExAcl(const wchar_t* path, DWORD access, DWORD share, DWORD flags, AclRestore* st);
static BOOL CreateSymbolicLinkSmart(const wchar_t* linkPath, const wchar_t* targetPath);

int DPIScale(int value) { return MulDiv(value, g_DPI, 96); }

void EnableDPIAwareness() {
    HMODULE hUser32 = GetModuleHandle(L"user32.dll");
    if (hUser32) {
        typedef BOOL(WINAPI* SETPROCESSDPIAWARE_T)(void);
        SETPROCESSDPIAWARE_T pSetDPIAware = (SETPROCESSDPIAWARE_T)GetProcAddress(hUser32, "SetProcessDPIAware");
        if (pSetDPIAware) pSetDPIAware();
    }
}

void FormatSize(LONGLONG bytes, wchar_t* buf, size_t maxLen) {
    if (bytes == 0) { swprintf(buf, maxLen, L"0.00 KB"); return; }
    double sizeKB = (double)bytes / 1024.0;
    if (sizeKB < 1024.0) swprintf(buf, maxLen, L"%.2f KB", sizeKB);
    else if (sizeKB < 1024.0 * 1024.0) swprintf(buf, maxLen, L"%.2f MB", sizeKB / 1024.0);
    else swprintf(buf, maxLen, L"%.2f GB", sizeKB / (1024.0 * 1024.0));
}

LONGLONG ParseSize(const wchar_t* str) {
    double val = _wtof(str);
    if (wcsstr(str, L"GB")) return (LONGLONG)(val * 1024.0 * 1024.0 * 1024.0);
    if (wcsstr(str, L"MB")) return (LONGLONG)(val * 1024.0 * 1024.0);
    if (wcsstr(str, L"KB")) return (LONGLONG)(val * 1024.0);
    return (LONGLONG)val;
}

void GetListViewSubItemText(HWND hList, int iItem, int iSubItem, wchar_t* buf, int maxLen) {
    LVITEM lvi = { 0 }; lvi.iSubItem = iSubItem; lvi.pszText = buf; lvi.cchTextMax = maxLen;
    SendMessage(hList, LVM_GETITEMTEXT, iItem, (LPARAM)&lvi);
}

LPARAM GetListViewParam(HWND hList, int iItem) {
    LVITEM lvi = { 0 }; lvi.iItem = iItem; lvi.mask = LVIF_PARAM;
    SendMessage(hList, LVM_GETITEM, 0, (LPARAM)&lvi);
    return lvi.lParam;
}

void GetSafeFullPath(const wchar_t* dir, const wchar_t* file, wchar_t* outPath, size_t maxLen) {
    size_t dl = wcslen(dir); // v1.3: 空串防越界
    swprintf(outPath, maxLen, (dl > 0 && dir[dl - 1] == '\\') ? L"%s%s" : L"%s\\%s", dir, file);
}

BOOL CalculateFileSHA256(const wchar_t* filename, std::wstring& outHash) {
    AclRestore acl; // v1.3: ACL 兜底（无权限读时接管后重试）
    HANDLE hFile = OpenFileExAcl(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_FLAG_SEQUENTIAL_SCAN, &acl);
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
                        wchar_t hexStr[3]; outHash = L"";
                        for (DWORD i = 0; i < hashLen; i++) {
                            swprintf(hexStr, _countof(hexStr), L"%02x", hashVal[i]); outHash += hexStr;
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
    AclRestoreAccess(&acl); // v1.3: 只读打开，对象未变，立即还原
    return bResult;
}

int main() { return wWinMain(GetModuleHandleW(NULL), NULL, GetCommandLineW(), SW_SHOWDEFAULT); }

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR lpCmdLine, int nCmdShow) {
    g_hInst = hInstance;
    InitializeCriticalSection(&g_csParity);
    EnableDPIAwareness();
    LoadSettings(); ApplyLanguage(); ApplyTheme(); // v1.2：先读设置，再定语言/主题
    HDC hdc = GetDC(NULL); g_DPI = GetDeviceCaps(hdc, LOGPIXELSX); ReleaseDC(NULL, hdc);

    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    Gdiplus::GdiplusStartup(&g_gdiplusToken, &gdiplusStartupInput, NULL);

    INITCOMMONCONTROLSEX icex = { sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES | ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icex);

    WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
    wc.lpfnWndProc = WndProc; wc.hInstance = hInstance; wc.hCursor = LoadCursor(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = g_hbrBg; // v1.2 主题底色
    wc.lpszClassName = L"ElegantHardlinkClass";
    RegisterClassEx(&wc);

    g_hMainWnd = CreateWindowEx(0, L"ElegantHardlinkClass", TR(S_TITLE),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, DPIScale(1000), DPIScale(680), NULL, NULL, hInstance, NULL);

    if (!g_hMainWnd) return 0;
    DragAcceptFiles(g_hMainWnd, TRUE);
    ShowWindow(g_hMainWnd, nCmdShow); UpdateWindow(g_hMainWnd);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) { TranslateMessage(&msg); DispatchMessage(&msg); }
    Gdiplus::GdiplusShutdown(g_gdiplusToken);
    return (int)msg.wParam;
}

int CALLBACK CompareFuncEx(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort) {
    HWND hList = g_CurrentSortList;
    if (!hList) return 0;

    wchar_t txt1[2048] = { 0 }, txt2[2048] = { 0 };
    GetListViewSubItemText(hList, lParam1, g_CurrentSortColumn, txt1, 2048);
    GetListViewSubItemText(hList, lParam2, g_CurrentSortColumn, txt2, 2048);

    LPARAM param1 = GetListViewParam(hList, lParam1);
    LPARAM param2 = GetListViewParam(hList, lParam2);

    BOOL isDir1 = (param1 & FILE_ATTRIBUTE_DIRECTORY) != 0;
    BOOL isDir2 = (param2 & FILE_ATTRIBUTE_DIRECTORY) != 0;

    // 无论按哪一列排序，文件夹优先逻辑
    wchar_t name1[2048] = { 0 }, name2[2048] = { 0 };
    GetListViewSubItemText(hList, lParam1, 0, name1, 2048);
    GetListViewSubItemText(hList, lParam2, 0, name2, 2048);

    if (wcscmp(name1, L"..") == 0) return -1;
    if (wcscmp(name2, L"..") == 0) return 1;
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
        res = _wcsicmp(txt1, txt2);
    }

    return g_CurrentSortAsc ? res : -res;
}

void UpdateAdvancedFilters() {
    GetWindowText(g_hEditInc, g_IncludeRegex, _countof(g_IncludeRegex));
    GetWindowText(g_hEditExc, g_ExcludeRegex, _countof(g_ExcludeRegex));

    wchar_t szMin[32] = { 0 }, szMax[32] = { 0 };
    GetWindowText(g_hEditSizeMin, szMin, _countof(szMin));
    GetWindowText(g_hEditSizeMax, szMax, _countof(szMax));

    g_MinSize = _wtoll(szMin) * 1024 * 1024;
    g_MaxSize = _wtoll(szMax) * 1024 * 1024;
}

bool IsAdvancedFiltered(const wchar_t* filename, LONGLONG fileSize) {
    if (g_MinSize > 0 && fileSize < g_MinSize) return true;
    if (g_MaxSize > 0 && fileSize > g_MaxSize) return true;

    std::wstring fname(filename);
    try {
        if (wcslen(g_ExcludeRegex) > 0) {
            std::wregex reExc(g_ExcludeRegex, std::regex_constants::icase);
            if (std::regex_search(fname, reExc)) return true;
        }
        if (wcslen(g_IncludeRegex) > 0) {
            std::wregex reInc(g_IncludeRegex, std::regex_constants::icase);
            if (!std::regex_search(fname, reInc)) return true;
        }
    }
    catch (const std::regex_error&) {}
    return false;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: g_hMainWnd = hwnd; CreateControls(hwnd); break; // v1.2：ApplyTheme 需要尽早拿到句柄

    case WM_MEASUREITEM: { // v1.2 深色模式自绘菜单：测量
        LPMEASUREITEMSTRUCT mis = (LPMEASUREITEMSTRUCT)lParam;
        if (mis->CtlType != ODT_MENU) return DefWindowProc(hwnd, uMsg, wParam, lParam);
        if (!mis->itemData) { mis->itemWidth = DPIScale(180); mis->itemHeight = DPIScale(7); return TRUE; }
        const wchar_t* mt = (const wchar_t*)mis->itemData;
        HDC mdc = GetDC(hwnd);
        HFONT moldF = (HFONT)SelectObject(mdc, GetAppFont());
        SIZE msz = { 0 }; GetTextExtentPoint32(mdc, mt, (int)wcslen(mt), &msz);
        SelectObject(mdc, moldF); ReleaseDC(hwnd, mdc);
        mis->itemWidth = msz.cx + DPIScale(52);
        mis->itemHeight = msz.cy + DPIScale(10);
        return TRUE;
    }

    case WM_DRAWITEM: { // v1.2 自绘按钮 / 深色菜单
        LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
        if (dis->CtlType == ODT_BUTTON) { DrawThemedButton(dis); return TRUE; }
        if (dis->CtlType == ODT_MENU) { DrawThemedMenuItem(dis); return TRUE; }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }

    case WM_CTLCOLORSTATIC: // v1.2 深色：静态文本
        if (g_bDark) {
            HDC hdcCtl = (HDC)wParam;
            SetTextColor(hdcCtl, RGB(235, 235, 235));
            SetBkColor(hdcCtl, RGB(32, 32, 32));
            return (LRESULT)g_hbrBg;
        }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);

    case WM_CTLCOLOREDIT:   // v1.2 深色：输入框 / 下拉框
    case WM_CTLCOLORLISTBOX:
        if (g_bDark) {
            HDC hdcCtl = (HDC)wParam;
            SetTextColor(hdcCtl, RGB(235, 235, 235));
            SetBkColor(hdcCtl, RGB(45, 45, 45));
            return (LRESULT)g_hbrEdit;
        }
        return DefWindowProc(hwnd, uMsg, wParam, lParam);

    case WM_SETTINGCHANGE: // v1.2 跟随系统：系统主题切换时自动重着色
        if (g_ThemeMode == 0 && SystemDarkModeEnabled() != g_bDark) ApplyTheme();
        break;

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

        // v1.5: 选择按钮栏和列表区域计算（左右分栏可拖拽）
        if (g_SplitX <= 0)
            g_SplitX = DPIScale(10) + ((cx - DPIScale(30)) * g_SplitPermille) / 1000;
        int minSplit = DPIScale(212);
        int maxSplit = cx - DPIScale(322);
        if (maxSplit < minSplit) maxSplit = minSplit;
        if (g_SplitX < minSplit) g_SplitX = minSplit;
        if (g_SplitX > maxSplit) g_SplitX = maxSplit;
        int listW = g_SplitX - DPIScale(12);  // 左列表宽（x 从 10 起，分隔槽右侧留空）
        int rightX = g_SplitX + DPIScale(4);  // 右列表起点
        int rightW = cx - rightX - DPIScale(10);
        int listY = DPIScale(140);
        int listHeight = cy - listY - DPIScale(100);
        if (listHeight < DPIScale(100)) listHeight = DPIScale(100);

        MoveWindow(g_hBtnSelAllL, DPIScale(10), DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnInvSelL, DPIScale(80), DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnSelAllR, rightX, DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnInvSelR, rightX + DPIScale(70), DPIScale(110), DPIScale(60), DPIScale(25), TRUE);
        MoveWindow(g_hBtnExportR, rightX + DPIScale(140), DPIScale(110), DPIScale(90), DPIScale(25), TRUE);
        MoveWindow(g_hBtnSettings, rightX + DPIScale(232), DPIScale(110), DPIScale(76), DPIScale(25), TRUE);

        MoveWindow(g_hFileList, DPIScale(10), listY, listW, listHeight, TRUE);
        MoveWindow(g_hHardlinkList, rightX, listY, rightW, listHeight, TRUE);

        // 底部按钮栏
        int btnY = cy - DPIScale(85);
        MoveWindow(g_hBtnRefresh, DPIScale(10), btnY, DPIScale(120), DPIScale(35), TRUE);
        MoveWindow(g_hBtnAnalyze, DPIScale(140), btnY, DPIScale(130), DPIScale(35), TRUE);
        MoveWindow(g_hBtnCreate, DPIScale(280), btnY, DPIScale(140), DPIScale(35), TRUE);
        MoveWindow(g_hBtnRestore, DPIScale(430), btnY, DPIScale(130), DPIScale(35), TRUE);
        MoveWindow(g_hBtnDelDup, DPIScale(570), btnY, DPIScale(140), DPIScale(35), TRUE);
        MoveWindow(g_hChkSlink, DPIScale(720), btnY + DPIScale(3), DPIScale(130), DPIScale(28), TRUE); // v1.3

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
        SetWindowText(g_hTxtScanInfo, g_szScanFile);
        break;

    case WM_NOTIFY: {
        LPNMHDR lpnmh = (LPNMHDR)lParam;
        if (lpnmh->idFrom == ID_LIST_FILE && lpnmh->code == NM_DBLCLK) {
            LPNMITEMACTIVATE lpnmitem = (LPNMITEMACTIVATE)lParam;
            if (lpnmitem->iItem != -1) {
                wchar_t text[2048] = { 0 };
                GetListViewSubItemText(g_hFileList, lpnmitem->iItem, 0, text, 2048);
                LPARAM itemParam = GetListViewParam(g_hFileList, lpnmitem->iItem);

                if (itemParam & FILE_ATTRIBUTE_DIRECTORY) {
                    if (wcscmp(text, L"..") == 0) {
                        PathRemoveFileSpec(g_CurrentPath);
                        if (wcslen(g_CurrentPath) <= 3) swprintf(g_CurrentPath, _countof(g_CurrentPath), L"%c:\\", g_CurrentPath[0]);
                    }
                    else {
                        if (g_CurrentPath[wcslen(g_CurrentPath) - 1] != '\\') wcscat(g_CurrentPath, L"\\");
                        wcscat(g_CurrentPath, text);
                    }
                    SetWindowText(g_hEditAddress, g_CurrentPath);
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
                }
            }
        }
        // v1.5: 点击复选框的行保持/叠加选中高亮，勾过的行不再"点完就褪色"
        if ((lpnmh->idFrom == ID_LIST_FILE || lpnmh->idFrom == ID_LIST_HARDLINK) && lpnmh->code == NM_CLICK) {
            LPNMITEMACTIVATE pnma = (LPNMITEMACTIVATE)lParam;
            LVHITTESTINFO hti = { 0 };
            hti.pt = pnma->ptAction;
            if (pnma->iItem >= 0 && ListView_SubItemHitTest(pnma->hdr.hwndFrom, &hti) >= 0 && (hti.flags & LVHT_ONITEMSTATEICON))
                ListView_SetItemState(pnma->hdr.hwndFrom, pnma->iItem, LVIS_SELECTED, LVIS_SELECTED);
        }
        // v1.5: 右侧列表双击 = 打开该重复组所有文件所在位置
        if (lpnmh->idFrom == ID_LIST_HARDLINK && lpnmh->code == NM_DBLCLK) {
            LPNMITEMACTIVATE pnmd = (LPNMITEMACTIVATE)lParam;
            if (pnmd->iItem >= 0) OpenGroupLocations(hwnd, pnmd->iItem);
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

            SendMessage(hList, LVM_SORTITEMSEX, (WPARAM)hList, (LPARAM)CompareFuncEx);
        }
        // v1.2 深色模式：列表表头自绘兜底（新系统由 DarkMode_Explorer 主题处理）
        if (g_bDark && lpnmh->code == NM_CUSTOMDRAW &&
            (lpnmh->hwndFrom == ListView_GetHeader(g_hFileList) || lpnmh->hwndFrom == ListView_GetHeader(g_hHardlinkList))) {
            LPNMCUSTOMDRAW phdc = (LPNMCUSTOMDRAW)lParam;
            if (phdc->dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (phdc->dwDrawStage == CDDS_ITEMPREPAINT) {
                HWND hHdr = lpnmh->hwndFrom;
                HDC hdc = phdc->hdc; RECT rc = phdc->rc;
                HBRUSH hbr = CreateSolidBrush(RGB(45, 45, 45));
                FillRect(hdc, &rc, hbr); DeleteObject(hbr);
                HPEN hpen = CreatePen(PS_SOLID, 1, RGB(70, 70, 70));
                HPEN oldPen = (HPEN)SelectObject(hdc, hpen);
                MoveToEx(hdc, rc.right - 1, rc.top, NULL); LineTo(hdc, rc.right - 1, rc.bottom);
                MoveToEx(hdc, rc.left, rc.bottom - 1, NULL); LineTo(hdc, rc.right, rc.bottom - 1);
                SelectObject(hdc, oldPen); DeleteObject(hpen);
                wchar_t htxt[256] = { 0 };
                HDITEM hdi = { 0 }; hdi.mask = HDI_TEXT; hdi.pszText = htxt; hdi.cchTextMax = _countof(htxt);
                SendMessage(hHdr, HDM_GETITEM, (WPARAM)phdc->dwItemSpec, (LPARAM)&hdi);
                HFONT oldF = (HFONT)SelectObject(hdc, GetAppFont());
                SetBkMode(hdc, TRANSPARENT); SetTextColor(hdc, RGB(235, 235, 235));
                rc.left += DPIScale(6);
                DrawText(hdc, htxt, -1, &rc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
                SelectObject(hdc, oldF);
                return CDRF_SKIPDEFAULT;
            }
        }
        if ((lpnmh->idFrom == ID_LIST_FILE || lpnmh->idFrom == ID_LIST_HARDLINK) && lpnmh->code == NM_CUSTOMDRAW) {
            LPNMLVCUSTOMDRAW lplvcd = (LPNMLVCUSTOMDRAW)lParam;
            if (lplvcd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
            if (lplvcd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
                DWORD attr = (DWORD)lplvcd->nmcd.lItemlParam;
                BOOL bHidden = (attr & FILE_ATTRIBUTE_HIDDEN) != 0;
                BOOL bReadOnly = (attr & FILE_ATTRIBUTE_READONLY) != 0;
                if (bHidden && bReadOnly) lplvcd->clrText = g_bDark ? RGB(205, 130, 225) : RGB(128, 0, 128);
                else if (bHidden) lplvcd->clrText = g_bDark ? RGB(255, 110, 100) : RGB(255, 0, 0);
                else if (bReadOnly) lplvcd->clrText = g_bDark ? RGB(115, 170, 255) : RGB(0, 0, 255);
                else lplvcd->clrText = g_bDark ? RGB(235, 235, 235) : RGB(0, 0, 0);

                // 右侧重复列表：同一 SHA256 组用交替底色，方便区分L"哪几行是一伙的"
                if (lpnmh->idFrom == ID_LIST_HARDLINK) {
                    wchar_t sha[128] = { 0 };
                    GetListViewSubItemText(g_hHardlinkList, (int)lplvcd->nmcd.dwItemSpec, 3, sha, _countof(sha));
                    int parity = 0;
                    EnterCriticalSection(&g_csParity);
                    std::map<std::wstring, int>::iterator git = g_GroupParity.find(sha);
                    if (git != g_GroupParity.end()) parity = git->second;
                    LeaveCriticalSection(&g_csParity);
                                        if (g_bDark) lplvcd->clrTextBk = parity ? RGB(52, 61, 71) : RGB(38, 38, 38);
                    else lplvcd->clrTextBk = parity ? RGB(226, 239, 252) : RGB(255, 255, 255);
                }
                return CDRF_NEWFONT;
            }
        }
        // v1.3: 多选增强——Shift 点首尾把范围内全勾/全不勾（以锚点行勾选态为准），Ctrl 单个勾/取消
        if ((lpnmh->idFrom == ID_LIST_FILE || lpnmh->idFrom == ID_LIST_HARDLINK) && lpnmh->code == LVN_ITEMCHANGED) {
            LPNMLISTVIEW pnmv = (LPNMLISTVIEW)lParam;
            if ((pnmv->uChanged & LVIF_STATE) && (pnmv->uNewState & LVIS_SELECTED) && !(pnmv->uOldState & LVIS_SELECTED)) {
                static BOOL s_bRangeBusy = FALSE;
                if (!s_bRangeBusy) {
                    HWND hList = pnmv->hdr.hwndFrom;
                    int* pAnchor = (hList == g_hHardlinkList) ? &g_AnchorR : &g_AnchorL;
                    if (GetKeyState(VK_SHIFT) < 0) {
                        int anchor = (*pAnchor >= 0) ? *pAnchor : pnmv->iItem;
                        int lo = (anchor < pnmv->iItem) ? anchor : pnmv->iItem;
                        int hi = (anchor < pnmv->iItem) ? pnmv->iItem : anchor;
                        BOOL mark = ListView_GetCheckState(hList, anchor);
                        s_bRangeBusy = TRUE; // 批量勾选会触发嵌套通知，用标记短路
                        for (int i = lo; i <= hi; i++)
                            ListView_SetItemState(hList, i, INDEXTOSTATEIMAGEMASK(mark ? 2 : 1), LVIS_STATEIMAGEMASK);
                        s_bRangeBusy = FALSE;
                    }
                    else if (GetKeyState(VK_CONTROL) < 0) {
                        BOOL cur = ListView_GetCheckState(hList, pnmv->iItem);
                        ListView_SetItemState(hList, pnmv->iItem, INDEXTOSTATEIMAGEMASK(cur ? 1 : 2), LVIS_STATEIMAGEMASK);
                    }
                    else {
                        *pAnchor = pnmv->iItem;
                    }
                }
            }
        }
        break;
    }

    case WM_COMMAND:
        if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == ID_COMBO_DISK) {
            int idx = (int)SendMessage(g_hComboDisk, CB_GETCURSEL, 0, 0);
            wchar_t comboRaw[2048];
            SendMessage(g_hComboDisk, CB_GETLBTEXT, idx, (LPARAM)comboRaw);
            comboRaw[3] = '\0';
            lstrcpy(g_CurrentPath, comboRaw);
            SetWindowText(g_hEditAddress, g_CurrentPath);
            SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
        }
        if (HIWORD(wParam) == CBN_SELCHANGE && LOWORD(wParam) == ID_COMBO_FILTER) {
            int idx = (int)SendMessage(g_hComboFilter, CB_GETCURSEL, 0, 0);
            wchar_t tempFilter[2048];
            SendMessage(g_hComboFilter, CB_GETLBTEXT, idx, (LPARAM)tempFilter);
            wchar_t* pStart = wcschr(tempFilter, '(');
            wchar_t* pEnd = wcschr(tempFilter, ')');
            if (pStart && pEnd) { *pEnd = '\0'; lstrcpy(g_CurrentFilter, pStart + 1); }
            else { lstrcpy(g_CurrentFilter, tempFilter); }
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
                int count = (int)SendMessage(hList, LVM_GETITEMCOUNT, 0, 0);
                for (int i = 0; i < count; i++) {
                    BOOL cur = ListView_GetCheckState(hList, i);
                    BOOL next = isInv ? !cur : TRUE;
                    ListView_SetItemState(hList, i, INDEXTOSTATEIMAGEMASK(next ? 2 : 1), LVIS_STATEIMAGEMASK);
                }
                break;
            }

            case ID_BTN_REFRESH:
                if (g_bScanning) { g_bCancelAnalysis = TRUE; SetWindowText(g_hBtnRefresh, TR(S_STOPPING)); break; }
                GetWindowText(g_hEditAddress, g_CurrentPath, 2048);
                UpdateAdvancedFilters();
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                SetWindowText(g_hTxtTotalSaved, TR(S_WAIT_ANALYZE));
                SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
                SendMessage(g_hFileList, LVM_DELETEALLITEMS, 0, 0);
                SendMessage(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                g_AnchorL = g_AnchorR = -1; // v1.3: 列表清空后锚点复位
                SetWindowText(g_hBtnRefresh, TR(S_STOP_SCAN));
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, ScanDirectoryThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;

            case ID_BTN_ANALYZE: {
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) {
                        g_bCancelAnalysis = TRUE;
                        SetWindowText(g_hBtnAnalyze, TR(S_ABORTING));
                    }
                    break;
                }

                g_TargetDirs.clear();
                int listCount = (int)SendMessage(g_hFileList, LVM_GETITEMCOUNT, 0, 0);
                for (int i = 0; i < listCount; i++) {
                    if (ListView_GetCheckState(g_hFileList, i)) {
                        LPARAM param = GetListViewParam(g_hFileList, i);
                        if (param & FILE_ATTRIBUTE_DIRECTORY) {
                            wchar_t text[2048] = { 0 };
                            GetListViewSubItemText(g_hFileList, i, 0, text, 2048);
                            if (wcscmp(text, L"..") != 0) {
                                wchar_t full[2048]; GetSafeFullPath(g_CurrentPath, text, full, 2048);
                                g_TargetDirs.push_back(full);
                            }
                        }
                    }
                }
                if (g_TargetDirs.empty()) g_TargetDirs.push_back(g_CurrentPath);

                GetWindowText(g_hEditAddress, g_CurrentPath, 2048);
                UpdateAdvancedFilters();
                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                g_llTotalSavedSpace = 0;
                g_nAclFixed = 0; // v1.3

                SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
                SendMessage(g_hHardlinkList, LVM_DELETEALLITEMS, 0, 0);
                g_AnchorL = g_AnchorR = -1; // v1.3: 列表清空后锚点复位
                SetWindowText(g_hBtnAnalyze, TR(S_STOP_ANALYZE));
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, AnalyzeDirectoryThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;
            }

            case ID_BTN_CREATE_HLINK: {
                if (g_bScanning) {
                    if (!g_bCancelAnalysis) { g_bCancelAnalysis = TRUE; SetWindowText(g_hBtnCreate, TR(S_ABORTING)); }
                    break;
                }
                int itemCount = (int)SendMessage(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
                if (itemCount == 0) {
                    MessageBox(hwnd, TR(S_MSG_NEED_ANALYZE), TR(S_T_TIP), MB_OK | MB_ICONWARNING);
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

                    wchar_t path[2048] = { 0 };
                    GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
                    if (IsRiskyExt(path)) { hasRiskyFiles = true; break; }
                }

                g_bExcludeRisky = FALSE;
                if (hasRiskyFiles) {
                    int res = MessageBox(hwnd, TR(S_MSG_RISKY), TR(S_T_RISKY), MB_YESNOCANCEL | MB_ICONWARNING);
                    if (res == IDCANCEL) break;
                    if (res == IDYES) g_bExcludeRisky = TRUE;
                }
                else {
                    if (checkedCount == 0) {
                        // v1.3: 软连接模式用专门确认文案，说明软连接语义
                        if (MessageBox(hwnd, g_bSlinkMode ? TR(S_MSG_CONFIRM_ALL_SL) : TR(S_MSG_CONFIRM_ALL), TR(S_T_CONFIRM_ALL), MB_YESNO | MB_ICONWARNING) != IDYES) break;
                    }
                    else {
                        if (MessageBox(hwnd, g_bSlinkMode ? TR(S_MSG_CONFIRM_SEL_SL) : TR(S_MSG_CONFIRM_SEL), TR(S_T_CONFIRM_SEL), MB_YESNO | MB_ICONINFORMATION) != IDYES) break;
                    }
                }

                // v1.3: XP 等系统没有软连接 API，提前拦截
                if (g_bSlinkMode && !GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateSymbolicLinkW")) {
                    MessageBox(hwnd, TR(S_MSG_SL_NO_SUPPORT), TR(S_T_ERROR), MB_OK | MB_ICONERROR);
                    break;
                }

                g_bScanning = TRUE; g_bCancelAnalysis = FALSE;
                SetWindowText(g_hBtnCreate, TR(S_STOP_CREATE));
                { HANDLE hT = (HANDLE)_beginthreadex(NULL, 0, CreateHardlinksThread, NULL, 0, NULL); if (hT) CloseHandle(hT); }
                break;
            }

            case ID_BTN_EXPORT_R: ExportHardlinkList(hwnd); break;
            case ID_BTN_DELETE_DUPS: DoDeleteDuplicates(hwnd); break;
            case ID_BTN_SETTINGS: { // 设置：语言 / 主题 / 字号 级联菜单
                HMENU hLangMenu = CreatePopupMenu();
                AppendThemedItem(hLangMenu, IDM_LANG_AUTO, TR(S_MENU_FOLLOW));
                AppendThemedItem(hLangMenu, IDM_LANG_ZH, L"中文");
                AppendThemedItem(hLangMenu, IDM_LANG_EN, L"English");
                CheckMenuRadioItem(hLangMenu, IDM_LANG_AUTO, IDM_LANG_EN, IDM_LANG_AUTO + g_LangMode, MF_BYCOMMAND);
                HMENU hThemeMenu = CreatePopupMenu();
                AppendThemedItem(hThemeMenu, IDM_THEME_AUTO, TR(S_MENU_FOLLOW));
                AppendThemedItem(hThemeMenu, IDM_THEME_LIGHT, TR(S_MENU_LIGHT));
                AppendThemedItem(hThemeMenu, IDM_THEME_DARK, TR(S_MENU_DARK));
                CheckMenuRadioItem(hThemeMenu, IDM_THEME_AUTO, IDM_THEME_DARK, IDM_THEME_AUTO + g_ThemeMode, MF_BYCOMMAND);
                HMENU hFontMenu = CreatePopupMenu();
                AppendThemedItem(hFontMenu, IDM_FONT_S, TR(S_FONT_S));
                AppendThemedItem(hFontMenu, IDM_FONT_M, TR(S_FONT_M));
                AppendThemedItem(hFontMenu, IDM_FONT_L, TR(S_FONT_L));
                AppendThemedItem(hFontMenu, IDM_FONT_XL, TR(S_FONT_XL));
                static const int s_ptOpts[4] = { 10, 11, 12, 14 };
                int curIdx = 1;
                for (int i = 0; i < 4; i++) if (s_ptOpts[i] == g_FontPt) curIdx = i;
                CheckMenuRadioItem(hFontMenu, IDM_FONT_S, IDM_FONT_XL, IDM_FONT_S + curIdx, MF_BYCOMMAND);
                HMENU hSettings = CreatePopupMenu();
                AppendThemedSub(hSettings, hLangMenu, TR(S_BTN_LANG));
                AppendThemedSub(hSettings, hThemeMenu, TR(S_BTN_THEME));
                AppendThemedSub(hSettings, hFontMenu, TR(S_BTN_FONT));
                RECT brc; GetWindowRect(g_hBtnSettings, &brc);
                TrackPopupMenu(hSettings, TPM_LEFTALIGN | TPM_TOPALIGN, brc.left, brc.bottom, 0, hwnd, NULL);
                DestroyMenu(hSettings);
                break;
            }
            }
        }

        if (HIWORD(wParam) == 0) {
            HWND hFocus = GetFocus();
            BOOL isHardlinkList = (hFocus == g_hHardlinkList);
            HWND hActiveList = isHardlinkList ? g_hHardlinkList : g_hFileList;
            int selIdx = (int)SendMessage(hActiveList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            wchar_t selText[2048] = { 0 };
            if (selIdx != -1) GetListViewSubItemText(hActiveList, selIdx, 0, selText, 2048);

            wchar_t full[2048];
            if (isHardlinkList && wcschr(selText, '\\')) lstrcpy(full, selText);
            else GetSafeFullPath(g_CurrentPath, selText, full, 2048);

            switch (LOWORD(wParam)) {
            case IDM_LANG_AUTO: case IDM_LANG_ZH: case IDM_LANG_EN:
                g_LangMode = (int)(LOWORD(wParam)) - IDM_LANG_AUTO;
                RegSetDword(L"Language", (DWORD)g_LangMode);
                ApplyLanguage(); ApplyLanguageToUI();
                break;
            case IDM_THEME_AUTO: case IDM_THEME_LIGHT: case IDM_THEME_DARK:
                g_ThemeMode = (int)(LOWORD(wParam)) - IDM_THEME_AUTO;
                RegSetDword(L"Theme", (DWORD)g_ThemeMode);
                ApplyTheme();
                break;
            case IDM_OPEN_GROUP: // v1.5: 打开本组所有文件位置
                if (isHardlinkList && selIdx != -1) OpenGroupLocations(hwnd, selIdx);
                break;
            case IDM_FONT_S: case IDM_FONT_M: case IDM_FONT_L: case IDM_FONT_XL: { // v1.5: 字号
                static const int s_ptVals[4] = { 10, 11, 12, 14 };
                int fIdx = (int)(LOWORD(wParam)) - IDM_FONT_S;
                if (fIdx >= 0 && fIdx < 4) {
                    g_FontPt = s_ptVals[fIdx];
                    RegSetDword(L"FontSize", (DWORD)g_FontPt);
                    ApplyFontToUI();
                }
                break;
            }
            case IDM_COPY_FILENAME: {
                const wchar_t* baseName = wcsrchr(selText, '\\');
                CopyToClipboard(hwnd, baseName ? baseName + 1 : selText);
                break;
            }
            case IDM_COPY_PATH: CopyToClipboard(hwnd, full); break;
            case IDM_COPY_SHA256: {
                if (isHardlinkList) {
                    wchar_t sha[128] = { 0 };
                    GetListViewSubItemText(hActiveList, selIdx, 3, sha, 128);
                    if (wcslen(sha) > 0) CopyToClipboard(hwnd, sha);
                }
                break;
            }
            case IDM_OPEN_EXPLORER: {
                wchar_t param[2048 + 20]; swprintf(param, _countof(param), L"/select,\"%s\"", full);
                ShellExecute(NULL, L"open", L"explorer.exe", param, NULL, SW_SHOWNORMAL); break;
            }
            case IDM_DELETE: {
                if (selIdx == -1 || wcslen(full) == 0) break;
                wchar_t prompt[2200]; swprintf(prompt, _countof(prompt), TR(S_MSG_DEL_ONE), full);
                if (MessageBox(hwnd, prompt, TR(S_T_DEL_RECYCLE), MB_YESNO | MB_ICONWARNING) != IDYES) break;
                wchar_t dblNull[2052] = { 0 }; lstrcpyn(dblNull, full, 2050);
                SHFILEOPSTRUCT op = { 0 };
                op.hwnd = hwnd; op.wFunc = FO_DELETE; op.pFrom = dblNull;
                op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;
                if (SHFileOperation(&op) == 0 && !op.fAnyOperationsAborted) {
                    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
                }
                break;
            }
            case IDM_CREATE_HLINK_CTX: {
                DWORD attr = (DWORD)GetListViewParam(hActiveList, selIdx);
                if (attr & FILE_ATTRIBUTE_DIRECTORY) MessageBox(hwnd, TR(S_MSG_DIR_HLINK), TR(S_T_ERROR), MB_OK | MB_ICONERROR);
                else MessageBox(hwnd, TR(S_MSG_USE_MAIN_BTN), TR(S_T_TIP), MB_OK);
                break;
            }
            }
        }
        break;

    case WM_USER_SCAN_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowText(g_hBtnRefresh, TR(S_BTN_REFRESH));
        SetWindowText(g_hBtnAnalyze, TR(S_BTN_ANALYZE));
        SetWindowText(g_hBtnCreate, g_bSlinkMode ? TR(S_BTN_CREATE_SL) : TR(S_BTN_CREATE)); // v1.3
        wchar_t totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, _countof(totalBuf));
        wchar_t finalStr[256]; swprintf(finalStr, _countof(finalStr), TR(S_TOTAL_SAVED_FMT), totalBuf);
        SetWindowText(g_hTxtTotalSaved, finalStr);
        break;
    }

    case WM_USER_ANALYZE_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETRANGE32, 0, 100);
        SendMessage(g_hProgressBar, PBM_SETPOS, 100, 0);
        SetWindowText(g_hTxtScanInfo, L"");
        SetWindowText(g_hBtnRefresh, TR(S_BTN_REFRESH));
        SetWindowText(g_hBtnAnalyze, TR(S_BTN_ANALYZE));
        SetWindowText(g_hBtnCreate, g_bSlinkMode ? TR(S_BTN_CREATE_SL) : TR(S_BTN_CREATE)); // v1.3

        wchar_t totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, _countof(totalBuf));
        double dElapsed = g_StatElapsedMs / 1000.0;
        wchar_t finalStr[320];
        swprintf(finalStr, _countof(finalStr), TR(S_STATS_FMT),
                 totalBuf, g_StatGroupCount, g_StatDupFileCount, dElapsed);
        SetWindowText(g_hTxtTotalSaved, finalStr);

        BOOL bCancelled = (BOOL)lParam; size_t count = (size_t)wParam;
        if (bCancelled) MessageBox(hwnd, TR(S_MSG_ANALYZE_CANCELLED), TR(S_T_TIP), MB_OK | MB_ICONINFORMATION);
        else {
            wchar_t msg[800]; // v1.3: 可能拼接权限接管统计
            swprintf(msg, _countof(msg),
                TR(S_MSG_ANALYZE_DONE),
                g_StatGroupCount, g_StatDupFileCount, count, totalBuf, dElapsed);
            if (g_nAclFixed > 0) {
                wchar_t aclLine[224];
                swprintf(aclLine, _countof(aclLine), TR(S_ACL_COUNT_FMT), (size_t)g_nAclFixed);
                lstrcat(msg, L"\n");
                lstrcat(msg, aclLine);
            }
            MessageBox(hwnd, msg, TR(S_T_ANALYZE_DONE), MB_OK | MB_ICONINFORMATION);
        }
        break;
    }

    case WM_USER_CREATE_DONE: {
        g_bScanning = FALSE; g_bCancelAnalysis = FALSE;
        SendMessage(g_hProgressBar, PBM_SETPOS, 0, 0);
        SetWindowText(g_hBtnRefresh, TR(S_BTN_REFRESH));
        SetWindowText(g_hBtnAnalyze, TR(S_BTN_ANALYZE));
        SetWindowText(g_hBtnCreate, g_bSlinkMode ? TR(S_BTN_CREATE_SL) : TR(S_BTN_CREATE)); // v1.3

        size_t successCount = (size_t)wParam;
        size_t failCount = (size_t)lParam;

        wchar_t msg[1600]; // v1.3: 软连接模式可能拼接失败原因提示
        swprintf(msg, _countof(msg), g_bSlinkMode ? TR(S_MSG_CREATE_DONE_SL) : TR(S_MSG_CREATE_DONE), successCount, failCount);
        if (g_nAclFixed > 0) {
            wchar_t aclLine[224];
            swprintf(aclLine, _countof(aclLine), TR(S_ACL_COUNT_FMT), (size_t)g_nAclFixed);
            lstrcat(msg, L"\n");
            lstrcat(msg, aclLine);
        }
        if (g_bSlinkMode && failCount > 0) {
            lstrcat(msg, L"\n\n");
            lstrcat(msg, TR(S_MSG_SL_FAIL_HINT));
        }
        MessageBox(hwnd, msg, TR(S_T_OP_DONE), MB_OK | MB_ICONINFORMATION);

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
        wchar_t dropped[2048] = { 0 };
        if (DragQueryFile(hDrop, 0, dropped, _countof(dropped)) > 0) {
            DWORD da = GetFileAttributes(dropped);
            if (da != INVALID_FILE_ATTRIBUTES) {
                if (da & FILE_ATTRIBUTE_DIRECTORY) {
                    lstrcpyn(g_CurrentPath, dropped, _countof(g_CurrentPath));
                } else {
                    lstrcpyn(g_CurrentPath, dropped, _countof(g_CurrentPath));
                    PathRemoveFileSpec(g_CurrentPath);
                }
                SetWindowText(g_hEditAddress, g_CurrentPath);
                SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
            }
        }
        DragFinish(hDrop);
        break;
    }
    case WM_SETCURSOR: // 悬停分栏线变左右箭头（严格限定在左右列表的高度范围内，不影响上方编辑框等控件）
        if (LOWORD(lParam) == HTCLIENT && g_SplitX > 0) {
            POINT spt; GetCursorPos(&spt); ScreenToClient(hwnd, &spt);
            RECT crc; GetClientRect(hwnd, &crc);
            int zoneTop = DPIScale(140);
            int zoneBottom = crc.bottom - DPIScale(100);
            if (spt.y >= zoneTop && spt.y <= zoneBottom) {
                int d = spt.x - g_SplitX; if (d < 0) d = -d;
                if (d <= DPIScale(3)) { SetCursor(LoadCursorW(NULL, (LPCWSTR)IDC_SIZEWE)); return TRUE; }
            }
        }
        return DefWindowProcW(hwnd, uMsg, wParam, lParam);

    case WM_LBUTTONDOWN: // 命中分栏线开始拖拽（同样仅限列表区域高度内）
        if (g_SplitX > 0) {
            RECT crc; GetClientRect(hwnd, &crc);
            int y = (int)(short)HIWORD(lParam);
            if (y >= DPIScale(140) && y <= crc.bottom - DPIScale(100)) {
                int d = (int)(short)LOWORD(lParam) - g_SplitX; if (d < 0) d = -d;
                if (d <= DPIScale(3)) { g_bDragSplit = TRUE; SetCapture(hwnd); }
            }
        }
        break;

    case WM_MOUSEMOVE: // v1.5: 拖拽中实时重排
        if (g_bDragSplit && GetCapture() == hwnd) {
            RECT crc; GetClientRect(hwnd, &crc);
            g_SplitX = (int)(short)LOWORD(lParam);
            SendMessage(hwnd, WM_SIZE, SIZE_RESTORED, MAKELPARAM(crc.right, crc.bottom));
            InvalidateRect(hwnd, NULL, TRUE);
        }
        break;

    case WM_LBUTTONUP: // v1.5: 结束拖拽并记住分栏比例
        if (g_bDragSplit) {
            g_bDragSplit = FALSE;
            if (GetCapture() == hwnd) ReleaseCapture();
            RECT crc; GetClientRect(hwnd, &crc);
            int span = crc.right - DPIScale(30);
            if (span > 0) {
                g_SplitPermille = (int)(((g_SplitX - DPIScale(10)) * 1000LL) / span);
                if (g_SplitPermille < 200) g_SplitPermille = 200;
                if (g_SplitPermille > 800) g_SplitPermille = 800;
                RegSetDword(L"SplitPos", (DWORD)g_SplitPermille);
            }
        }
        break;

    case WM_PAINT: { // v1.5: 画分栏分隔槽
        PAINTSTRUCT ps; HDC hdc = BeginPaint(hwnd, &ps);
        if (g_SplitX > 0) { // 分隔槽同样只画到列表区域高度
            RECT grc = { g_SplitX - DPIScale(2), DPIScale(140), g_SplitX + DPIScale(2), ps.rcPaint.bottom - DPIScale(100) };
            HBRUSH hbr = CreateSolidBrush(g_bDark ? RGB(70, 70, 70) : RGB(204, 204, 204));
            FillRect(hdc, &grc, hbr); DeleteObject(hbr);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }

    case WM_DESTROY: PostQuitMessage(0); break;
    default: return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

unsigned __stdcall ScanDirectoryThread(void* pArguments) {
    wchar_t searchPath[2048]; GetSafeFullPath(g_CurrentPath, L"*.*", searchPath, 2048);
    g_llTotalSavedSpace = 0;

    if (wcslen(g_CurrentPath) > 3) AddListItem(g_hFileList, L"..", L"", TR(S_UP_LEVEL), L"", NULL, FILE_ATTRIBUTE_DIRECTORY);

    WIN32_FIND_DATA fd; HANDLE hFind = FindFirstFile(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (g_bCancelAnalysis) break;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;

            BOOL isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
            LONGLONG fileSize = ((LONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;

            if (!isDir) {
                if (!PathMatchSpec(fd.cFileName, g_CurrentFilter)) continue;
                if (IsAdvancedFiltered(fd.cFileName, fileSize)) continue;
            }

            wchar_t sizeStr[64] = { 0 };
            if (!isDir) { FormatSize(fileSize, sizeStr, _countof(sizeStr)); }

            if (isDir) { AddListItem(g_hFileList, fd.cFileName, L"", TR(S_FOLDER), L"", NULL, fd.dwFileAttributes); continue; }

            wchar_t fullPath[2048]; GetSafeFullPath(g_CurrentPath, fd.cFileName, fullPath, 2048);
            AclRestore acl; // v1.3: ACL 兜底
            HANDLE hFile = OpenFileExAcl(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, &acl);
            if (hFile != INVALID_HANDLE_VALUE) {
                BY_HANDLE_FILE_INFORMATION fileInfo;
                if (GetFileInformationByHandle(hFile, &fileInfo)) {
                    wchar_t infoStr[128]; swprintf(infoStr, _countof(infoStr), TR(S_LINKS_FMT), fileInfo.nNumberOfLinks);
                    wchar_t hlFlag[8];
                    swprintf(hlFlag, _countof(hlFlag), L"%d", fileInfo.nNumberOfLinks > 1 ? 1 : 0);

                    if (fileInfo.nNumberOfLinks > 1) AddListItem(g_hHardlinkList, fd.cFileName, infoStr, sizeStr, L"", hlFlag, fd.dwFileAttributes);
                    else AddListItem(g_hFileList, fd.cFileName, sizeStr, infoStr, hlFlag, NULL, fd.dwFileAttributes);
                }
                CloseHandle(hFile);
                AclRestoreAccess(&acl); // v1.3: 只读打开，立即还原
            }
            else AddListItem(g_hFileList, fd.cFileName, sizeStr, TR(S_NO_PERM), L"", NULL, fd.dwFileAttributes);
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }

    g_CurrentSortList = g_hFileList;
    g_CurrentSortColumn = g_SortColLeft;
    g_CurrentSortAsc = g_SortAscLeft;
    SendMessage(g_hFileList, LVM_SORTITEMSEX, (WPARAM)g_hFileList, (LPARAM)CompareFuncEx);
    PostMessage(g_hMainWnd, WM_USER_SCAN_DONE, 0, 0);
    return 0;
}

void CollectFilesRecursively(const std::wstring& folder, std::vector<FileNode>& fileList) {
    if (g_bCancelAnalysis) return;
    wchar_t searchPath[2048]; GetSafeFullPath(folder.c_str(), L"*.*", searchPath, 2048);
    WIN32_FIND_DATA fd; HANDLE hFind = FindFirstFile(searchPath, &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (g_bCancelAnalysis) break;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            // v1.3: 跳过软连接（链接不是重复数据本体，也避免跟着链接进死循环）
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && fd.dwReserved0 == IO_REPARSE_TAG_SYMLINK) continue;
            wchar_t fullPath[2048]; GetSafeFullPath(folder.c_str(), fd.cFileName, fullPath, 2048);

            if ((++g_nScanCounter & 0x3F) == 0) {
                swprintf(g_szScanFile, _countof(g_szScanFile), TR(S_SCANNING_FMT), fullPath);
                PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);
            }
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                CollectFilesRecursively(fullPath, fileList);
            }
            else if (PathMatchSpec(fd.cFileName, g_CurrentFilter)) {
                LONGLONG fileSize = ((LONGLONG)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                if (!IsAdvancedFiltered(fd.cFileName, fileSize)) {
                    FileNode node; node.fullPath = fullPath; node.fileName = fd.cFileName;
                    node.size.LowPart = fd.nFileSizeLow; node.size.HighPart = fd.nFileSizeHigh;
                    node.attr = fd.dwFileAttributes; fileList.push_back(node);
                }
            }
        } while (FindNextFile(hFind, &fd));
        FindClose(hFind);
    }
}

// v1.3: GetTickCount64 needs _WIN32_WINNT>=0x600 to declare; load dynamically for XP safety
static ULONGLONG NowTick64() {
    typedef ULONGLONG (WINAPI *GTC64_T)(void);
    static GTC64_T pGtc64 = NULL;
    static BOOL s_looked = FALSE;
    if (!s_looked) { s_looked = TRUE; pGtc64 = (GTC64_T)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetTickCount64"); }
    if (pGtc64) return pGtc64();
    return (ULONGLONG)GetTickCount(); // XP: 32-bit ms
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
    ULONGLONG dwAnalyzeStart = NowTick64(); // v1.3: 64-bit counter, no wraparound

    swprintf(g_szScanFile, _countof(g_szScanFile), TR(S_COLLECTING));
    PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);

    for (size_t i = 0; i < g_TargetDirs.size(); ++i) {
        CollectFilesRecursively(g_TargetDirs[i], allFiles);
    }

    size_t totalHardlinksToCreate = 0;

    if (!g_bCancelAnalysis) {
        std::map<LONGLONG, std::vector<size_t>> sizeMap; // v1.3: 存下标代替拷贝 FileNode，大目录更省内存
        for (size_t i = 0; i < allFiles.size(); ++i) {
            if (g_bCancelAnalysis) break;
            if (allFiles[i].size.QuadPart > 0) sizeMap[allFiles[i].size.QuadPart].push_back(i);
        }

        size_t totalHashTasks = 0;
        for (std::map<LONGLONG, std::vector<size_t>>::iterator it = sizeMap.begin(); it != sizeMap.end(); ++it) {
            if (it->second.size() > 1) totalHashTasks += it->second.size();
        }

        size_t completedTasks = 0;

        for (std::map<LONGLONG, std::vector<size_t>>::iterator it = sizeMap.begin(); it != sizeMap.end(); ++it) {
            if (g_bCancelAnalysis) break;
            if (it->second.size() > 1) {
                std::map<std::wstring, std::vector<size_t>> hashMap; // v1.3: 同样只存下标
                for (size_t i = 0; i < it->second.size(); ++i) {
                    if (g_bCancelAnalysis) break;
                    FileNode& fn = allFiles[it->second[i]];
                    swprintf(g_szScanFile, _countof(g_szScanFile), TR(S_HASHING_FMT), fn.fullPath.c_str());
                    PostMessage(g_hMainWnd, WM_USER_UPDATE_SCANFILE, 0, 0);
                    std::wstring hashVal;
                    if (CalculateFileSHA256(fn.fullPath.c_str(), hashVal)) {
                        hashMap[hashVal].push_back(it->second[i]);
                    }
                    completedTasks++;
                    if (completedTasks % 5 == 0 || completedTasks == totalHashTasks) {
                        PostMessage(g_hMainWnd, WM_USER_UPDATE_PROGRESS, completedTasks, totalHashTasks);
                    }
                }

                for (std::map<std::wstring, std::vector<size_t>>::iterator hit = hashMap.begin(); hit != hashMap.end(); ++hit) {
                    if (g_bCancelAnalysis) break;
                    if (hit->second.size() > 1) {

                        // v1.3: 打开一次同时拿文件 ID 与链接数，下面展示阶段不再逐个重开
                        std::map<ULONGLONG, int> physicalFiles;
                        std::vector<DWORD> linksOf(hit->second.size(), 0);
                        for (size_t k = 0; k < hit->second.size(); ++k) {
                            FileNode& fn = allFiles[hit->second[k]];
                            AclRestore acl; // v1.3: ACL 兜底
                            HANDLE hFile = OpenFileExAcl(fn.fullPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, &acl);
                            if (hFile != INVALID_HANDLE_VALUE) {
                                BY_HANDLE_FILE_INFORMATION fi;
                                if (GetFileInformationByHandle(hFile, &fi)) {
                                    ULONGLONG fileId = ((ULONGLONG)fi.nFileIndexHigh << 32) | fi.nFileIndexLow;
                                    physicalFiles[fileId]++;
                                    linksOf[k] = fi.nNumberOfLinks;
                                }
                                CloseHandle(hFile);
                                AclRestoreAccess(&acl);
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

                        wchar_t szSaved[64]; FormatSize(savedSpace, szSaved, _countof(szSaved));

                        for (size_t k = 0; k < hit->second.size(); ++k) {
                            if (g_bCancelAnalysis) break;
                            FileNode& fn = allFiles[hit->second[k]];
                            wchar_t status[128]; swprintf(status, _countof(status), TR(S_DUP_FMT), hit->second.size());

                            wchar_t hlFlag[8] = L"0";
                            if (linksOf[k] > 1) wcscpy(hlFlag, L"1"); // v1.3: 复用上面记录的链接数，不再重开文件

                            AddListItem(g_hHardlinkList, fn.fullPath.c_str(), status, szSaved, hit->first.c_str(), hlFlag, fn.attr, fn.fullPath.c_str());
                        }
                    }
                }
            }
        }
    }

    g_StatElapsedMs = (DWORD)(NowTick64() - dwAnalyzeStart);

    g_CurrentSortList = g_hHardlinkList;
    g_CurrentSortColumn = g_SortColRight;
    g_CurrentSortAsc = g_SortAscRight;
    SendMessage(g_hHardlinkList, LVM_SORTITEMSEX, (WPARAM)g_hHardlinkList, (LPARAM)CompareFuncEx);
    PostMessage(g_hMainWnd, WM_USER_ANALYZE_DONE, (WPARAM)totalHardlinksToCreate, (LPARAM)g_bCancelAnalysis);
    return 0;
}

// v1.3: 建软连接。Vista+ 才有此 API，动态加载保证 XP 上安全返回失败
static BOOL CreateSymbolicLinkSmart(const wchar_t* linkPath, const wchar_t* targetPath) {
    typedef BOOLEAN (WINAPI *CSL_T)(const wchar_t*, const wchar_t*, DWORD);
    static CSL_T pCsl = NULL;
    static BOOL s_looked = FALSE;
    if (!s_looked) {
        s_looked = TRUE;
        pCsl = (CSL_T)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateSymbolicLinkW");
    }
    if (!pCsl) return FALSE;
    if (pCsl(linkPath, targetPath, 0)) return TRUE;
    DWORD err = GetLastError();
    if (err == ERROR_INVALID_FUNCTION || err == ERROR_PRIVILEGE_NOT_HELD) {
        // Win10 1703+ 开发者模式可免提权创建
        if (pCsl(linkPath, targetPath, SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) return TRUE;
    }
    return FALSE;
}

unsigned __stdcall CreateHardlinksThread(void* pArguments) {
    g_nAclFixed = 0; // v1.3: 本轮转换的接管计数清零
    int count = (int)SendMessage(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    int checkedCount = 0;

    for (int i = 0; i < count; i++) {
        if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;
    }

    std::map<std::wstring, std::vector<std::wstring>> dupGroups;
    for (int i = 0; i < count; i++) {
        // 如果用户勾选了文件，只处理被勾选的文件；如果没有勾选，处理全部
        if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;

        wchar_t path[2048] = { 0 }; wchar_t sha[128] = { 0 };
        GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemText(g_hHardlinkList, i, 3, sha, 128);
        if (wcslen(path) > 0 && wcslen(sha) > 0) dupGroups[sha].push_back(path);
    }

    size_t successCount = 0; size_t failCount = 0;

    for (std::map<std::wstring, std::vector<std::wstring>>::iterator it = dupGroups.begin(); it != dupGroups.end(); ++it) {
        if (g_bCancelAnalysis) break;
        std::vector<std::wstring>& paths = it->second;

        if (paths.size() > 1) {
            std::wstring master = paths[0];

            for (size_t i = 1; i < paths.size(); ++i) {
                if (g_bCancelAnalysis) break;
                std::wstring target = paths[i];

                if (IsProtectedPath(target.c_str()) || IsProtectedPath(master.c_str())) {
                    failCount++;
                    continue;
                }
                if (g_bExcludeRisky && IsRiskyExt(target.c_str())) {
                    failCount++;
                    continue;
                }

                std::wstring targetBak = target + L".hlbak";
                BOOL moved = MoveFile(target.c_str(), targetBak.c_str());
                AclRestore stF, stD; // v1.3: ACL 兜底——文件本身不行再接管父目录
                BOOL grantedFile = FALSE, grantedDir = FALSE;
                if (!moved) {
                    wchar_t dir[2048]; lstrcpyn(dir, target.c_str(), (int)_countof(dir));
                    wchar_t* slash = wcsrchr(dir, '\\');
                    if (slash) {
                        grantedFile = AclGrantAccess(target.c_str(), FALSE, &stF);
                        if (grantedFile) moved = MoveFile(target.c_str(), targetBak.c_str());
                        if (!moved) {
                            if (slash == dir + 2) slash[1] = 0; else *slash = 0;
                            grantedDir = AclGrantAccess(dir, TRUE, &stD);
                            if (grantedDir) moved = MoveFile(target.c_str(), targetBak.c_str());
                        }
                    }
                }
                if (!moved) {
                    failCount++;
                    AclRestoreAccess(&stF);
                    AclRestoreAccess(&stD);
                    continue;
                }

                BOOL linked = FALSE;
                if (g_bSlinkMode) linked = CreateSymbolicLinkSmart(target.c_str(), master.c_str()); // v1.3: 软连接模式
                else linked = CreateHardLink(target.c_str(), master.c_str(), NULL);

                if (linked) {
                    DeleteFile(targetBak.c_str());
                    successCount++;
                    // 原文件对象已被删除，接管状态不还原（还原会错落在新建的链接上）
                }
                else {
                    MoveFile(targetBak.c_str(), target.c_str());
                    failCount++;
                    AclRestoreAccess(&stF); // 已移回，原对象还在，还原
                    AclRestoreAccess(&stD);
                }
            }
        }
    }
    PostMessage(g_hMainWnd, WM_USER_CREATE_DONE, (WPARAM)successCount, (LPARAM)failCount);
    return 0;
}

// ===================== v1.3：ACL 权限兜底（不同所有者/权限的文件也能处理）=====================
// 思路：开启 SeTakeOwnership/SeRestore/SeBackup 特权 → 临时把文件所有者接管为 Administrators
// 并补一条完全控制 ACE → 操作完成后按需还原原所有者与原 DACL。即时生效、用完即还。

static void EnableAclPrivileges() {
    static BOOL s_done = FALSE;
    if (s_done) return;
    s_done = TRUE;
    const wchar_t* privs[] = { SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME, SE_BACKUP_NAME, SE_SECURITY_NAME, NULL };
    for (int i = 0; privs[i]; i++) {
        HANDLE tok = NULL;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
            TOKEN_PRIVILEGES tp; LUID luid;
            if (LookupPrivilegeValue(NULL, privs[i], &luid)) {
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
            }
            CloseHandle(tok);
        }
    }
}

// 接管所有权并追加 Administrators 完全控制 ACE；原安全描述符备份进 st 供还原
static BOOL AclGrantAccess(const wchar_t* path, BOOL isDir, AclRestore* st) {
    memset(st, 0, sizeof(AclRestore));
    lstrcpyn(st->path, path, (int)sizeof(st->path));
    EnableAclPrivileges();
    DWORD r = GetNamedSecurityInfo(st->path, SE_FILE_OBJECT,
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
        &st->owner, &st->group, &st->dacl, &st->sacl, &st->sd);
    if (r != ERROR_SUCCESS) return FALSE;

    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    PSID adminSid = NULL;
    if (!AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
                                  0, 0, 0, 0, 0, 0, &adminSid))
        return FALSE;

    BOOL ok = (SetNamedSecurityInfo(st->path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
                                     adminSid, NULL, NULL, NULL) == ERROR_SUCCESS);
    if (ok) {
        EXPLICIT_ACCESS ea;
        memset(&ea, 0, sizeof(ea));
        ea.grfAccessPermissions = GENERIC_ALL;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = isDir ? SUB_CONTAINERS_AND_OBJECTS_INHERIT : NO_INHERITANCE;
        BuildTrusteeWithSid(&ea.Trustee, adminSid);
        PACL newDacl = NULL;
        if (SetEntriesInAcl(1, &ea, st->dacl, &newDacl) == ERROR_SUCCESS) {
            if (SetNamedSecurityInfo(st->path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                      NULL, NULL, newDacl, NULL) != ERROR_SUCCESS)
                ok = FALSE;
            LocalFree(newDacl);
        }
        else ok = FALSE;
    }
    FreeSid(adminSid);
    if (ok) {
        st->active = TRUE;
        InterlockedIncrement(&g_nAclFixed);
    }
    else if (st->sd) {
        LocalFree(st->sd);
        st->sd = NULL;
    }
    return ok;
}

// 还原原所有者/DACL。路径上的对象可能已被替换或删除（转换流程），只在还存在时还原
static void AclRestoreAccess(AclRestore* st) {
    if (!st->active) {
        if (st->sd) { LocalFree(st->sd); st->sd = NULL; }
        return;
    }
    st->active = FALSE;
    if (GetFileAttributes(st->path) != INVALID_FILE_ATTRIBUTES) {
        SetNamedSecurityInfo(st->path, SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            st->owner, st->group, st->dacl, st->sacl);
    }
    if (st->sd) { LocalFree(st->sd); st->sd = NULL; }
}

// 普通方式打开失败时走接管兜底；成功后调用方必须在 CloseHandle 后 AclRestoreAccess
static HANDLE OpenFileExAcl(const wchar_t* path, DWORD access, DWORD share, DWORD flags, AclRestore* st) {
    memset(st, 0, sizeof(AclRestore));
    HANDLE h = CreateFile(path, access, share, NULL, OPEN_EXISTING, flags, NULL);
    if (h != INVALID_HANDLE_VALUE) return h;
    DWORD attr = GetFileAttributes(path);
    if (attr == INVALID_FILE_ATTRIBUTES) return INVALID_HANDLE_VALUE;
    if (!AclGrantAccess(path, (attr & FILE_ATTRIBUTE_DIRECTORY) != 0, st)) return INVALID_HANDLE_VALUE;
    h = CreateFile(path, access, share, NULL, OPEN_EXISTING, flags, NULL);
    if (h == INVALID_HANDLE_VALUE) AclRestoreAccess(st);
    return h;
}

BOOL IsRiskyExt(const wchar_t* path) {
    const wchar_t* ext = PathFindExtension(path);
    if (!ext || ext[0] != '.') return FALSE;
    wchar_t extLower[32]; lstrcpyn(extLower, ext, 32); CharLower(extLower);
    static const wchar_t* RISKY[] = { L".doc", L".docx", L".xls", L".xlsx", L".ppt", L".pptx", L".bak", L".tmp", L".wps", NULL };
    for (int i = 0; RISKY[i]; i++) if (lstrcmp(extLower, RISKY[i]) == 0) return TRUE;
    return FALSE;
}

BOOL IsProtectedPath(const wchar_t* path) {
    wchar_t full[MAX_PATH * 2];
    if (!GetFullPathName(path, _countof(full), full, NULL)) {
        lstrcpyn(full, path, _countof(full));
    }
    wchar_t pathLower[MAX_PATH * 2];
    lstrcpyn(pathLower, full, _countof(pathLower));
    CharLower(pathLower);
    const wchar_t* envVars[] = { L"SystemRoot", L"ProgramFiles", L"ProgramFiles(x86)", L"ProgramData", L"windir", NULL };
    for (int i = 0; envVars[i]; i++) {
        wchar_t dir[MAX_PATH];
        DWORD n = GetEnvironmentVariable(envVars[i], dir, _countof(dir));
        if (n == 0 || n >= _countof(dir)) continue;
        CharLower(dir);
        size_t len = wcslen(dir);
        if (len > 0 && _wcsnicmp(pathLower, dir, len) == 0) {
            char nextCh = pathLower[len];
            if (nextCh == 92 || nextCh == 47 || nextCh == 0) return TRUE;
        }
    }
    return FALSE;
}

BOOL BreakHardlink(const wchar_t* filepath) {
    wchar_t tempPath[2048]; swprintf(tempPath, _countof(tempPath), L"%s.tmp_hl_bak", filepath);
    AclRestore st; // v1.3: ACL 兜底
    memset(&st, 0, sizeof(st));
    BOOL granted = FALSE;
    if (!CopyFile(filepath, tempPath, FALSE)) {
        granted = AclGrantAccess(filepath, FALSE, &st);
        if (!granted || !CopyFile(filepath, tempPath, FALSE)) {
            AclRestoreAccess(&st);
            return FALSE;
        }
    }
    if (!DeleteFile(filepath)) { // 原对象还在，可还原
        DeleteFile(tempPath);
        AclRestoreAccess(&st);
        return FALSE;
    }
    return MoveFile(tempPath, filepath); // 原对象已删，接管状态随对象消失，不还原
}

void CopyToClipboard(HWND hwnd, const wchar_t* text) {
    if (OpenClipboard(hwnd)) {
        EmptyClipboard(); HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, (wcslen(text) + 1) * sizeof(wchar_t));
        if (hg) { memcpy(GlobalLock(hg), text, (wcslen(text) + 1) * sizeof(wchar_t)); GlobalUnlock(hg); SetClipboardData(CF_UNICODETEXT, hg); }
        CloseClipboard();
    }
}

// v1.4: 导出文件统一写 UTF-8（带 BOM，Excel/记事本不乱码），内部字符串为宽字符
static void FputUtf8(FILE* fp, const wchar_t* s) {
    int cb = WideCharToMultiByte(CP_UTF8, 0, s, -1, NULL, 0, NULL, NULL);
    if (cb > 1) {
        char* tmp = (char*)malloc(cb);
        if (tmp && WideCharToMultiByte(CP_UTF8, 0, s, -1, tmp, cb, NULL, NULL) > 0)
            fwrite(tmp, 1, cb - 1, fp);
        free(tmp);
    }
}

static void FputUtf8f(FILE* fp, const wchar_t* fmt, ...) {
    wchar_t wbuf[4608];
    va_list ap; va_start(ap, fmt);
    _vsnwprintf(wbuf, _countof(wbuf) - 1, fmt, ap);
    wbuf[_countof(wbuf) - 1] = 0;
    va_end(ap);
    FputUtf8(fp, wbuf);
}

void ExportHardlinkList(HWND hwnd) {
    int count = (int)SendMessage(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, TR(S_MSG_EMPTY_EXPORT), TR(S_T_TIP), MB_OK | MB_ICONWARNING);
        return;
    }

    int checkedCount = 0;
    for (int i = 0; i < count; i++) {
        if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;
    }

    wchar_t fileName[2048] = { 0 };
    lstrcpyn(fileName, TR(S_EXPORT_DEFAULT_NAME), _countof(fileName));
    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = TR(S_EXPORT_FILTER);
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = _countof(fileName);
    ofn.lpstrDefExt = L"csv";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
    if (!GetSaveFileName(&ofn)) return;

    FILE* fp = _wfopen(fileName, L"wb");
    if (!fp) {
        MessageBox(hwnd, TR(S_MSG_WRITE_FAIL), TR(S_T_ERROR), MB_OK | MB_ICONERROR);
        return;
    }
    const unsigned char kUtf8Bom[3] = { 0xEF, 0xBB, 0xBF }; // v1.4: BOM
    fwrite(kUtf8Bom, 1, 3, fp);

    // v1.2：选 .txt 时导出可读分组清单（每组首个保留、其余可删），否则保持 CSV
    const wchar_t* dotExt = PathFindExtension(fileName);
    if (dotExt && lstrcmpi(dotExt, L".txt") == 0) {
        std::map<std::wstring, std::vector<std::wstring> > txtGroups;
        std::vector<std::wstring> txtOrder;
        for (int i = 0; i < count; i++) {
            if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;
            wchar_t path[2048] = { 0 }, sha[128] = { 0 };
            GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
            GetListViewSubItemText(g_hHardlinkList, i, 3, sha, 128);
            if (wcslen(path) == 0 || wcslen(sha) == 0) continue;
            if (txtGroups.find(sha) == txtGroups.end()) txtOrder.push_back(sha);
            txtGroups[sha].push_back(path);
        }
        FputUtf8f(fp, L"%s\r\n\r\n", TR(S_TXT_TITLE));
        size_t gi = 0, lines = 0;
        for (size_t o = 0; o < txtOrder.size(); o++) {
            std::vector<std::wstring>& v = txtGroups[txtOrder[o]];
            if (v.size() < 2) continue;
            FputUtf8f(fp, TR(S_TXT_GROUP), ++gi, txtOrder[o].c_str());
            FputUtf8f(fp, L"\r\n");
            for (size_t k = 0; k < v.size(); k++) {
                FputUtf8f(fp, k == 0 ? TR(S_TXT_KEEP) : TR(S_TXT_DUP), v[k].c_str());
                FputUtf8f(fp, L"\r\n");
                lines++;
            }
            FputUtf8f(fp, L"\r\n");
        }
        FputUtf8f(fp, L"%s\r\n", TR(S_TXT_HINT));
        fclose(fp);
        wchar_t msg[2560];
        swprintf(msg, _countof(msg), TR(S_MSG_EXPORT_DONE), lines, fileName);
        if (MessageBox(hwnd, msg, TR(S_T_EXPORT_DONE), MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
            wchar_t param[2048 + 20]; swprintf(param, _countof(param), L"/select,\"%s\"", fileName);
            ShellExecute(NULL, L"open", L"explorer.exe", param, NULL, SW_SHOWNORMAL);
        }
        return;
    }

    FputUtf8(fp, TR(S_CSV_HEADER));

    size_t exported = 0;
    for (int i = 0; i < count; i++) {
        if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;
        wchar_t path[2048] = { 0 }, status[256] = { 0 }, sizeStr[128] = { 0 }, sha[128] = { 0 }, hl[16] = { 0 };
        GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemText(g_hHardlinkList, i, 1, status, 256);
        GetListViewSubItemText(g_hHardlinkList, i, 2, sizeStr, 128);
        GetListViewSubItemText(g_hHardlinkList, i, 3, sha, 128);
        GetListViewSubItemText(g_hHardlinkList, i, 4, hl, 16);
        FputUtf8f(fp, L"\"%s\",\"%s\",\"%s\",%s,%s\r\n", path, status, sizeStr, sha, (hl[0] == '1' ? TR(S_YES) : TR(S_NO)));
        exported++;
    }
    fclose(fp);

    wchar_t msg[2560];
    swprintf(msg, _countof(msg), TR(S_MSG_EXPORT_DONE), exported, fileName);
    if (MessageBox(hwnd, msg, TR(S_T_EXPORT_DONE), MB_OKCANCEL | MB_ICONINFORMATION) == IDOK) {
        wchar_t param[2048 + 20]; swprintf(param, _countof(param), L"/select,\"%s\"", fileName);
        ShellExecute(NULL, L"open", L"explorer.exe", param, NULL, SW_SHOWNORMAL);
    }
}

void AddListItem(HWND hList, const wchar_t* col0, const wchar_t* col1, const wchar_t* col2, const wchar_t* col3, const wchar_t* col4, DWORD dwAttributes, const wchar_t* overridePath) {
    SHFILEINFO sfi = { 0 }; wchar_t targetPath[2048];
    if (overridePath) lstrcpy(targetPath, overridePath);
    else GetSafeFullPath(g_CurrentPath, col0, targetPath, 2048);

    SHGetFileInfo((LPCWSTR)targetPath, dwAttributes, &sfi, sizeof(SHFILEINFO), SHGFI_SYSICONINDEX | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);

    LVITEM lvi = { 0 }; lvi.mask = LVIF_TEXT | LVIF_IMAGE | LVIF_PARAM;
    lvi.iItem = (int)SendMessage(hList, LVM_GETITEMCOUNT, 0, 0);
    lvi.pszText = overridePath ? (LPWSTR)overridePath : (LPWSTR)col0;
    lvi.iImage = sfi.iIcon;
    lvi.lParam = (LPARAM)dwAttributes;
    int idx = (int)SendMessage(hList, LVM_INSERTITEM, 0, (LPARAM)&lvi);

    if (col1) { LVITEM lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 1; lviSub.pszText = (LPWSTR)col1; SendMessage(hList, LVM_SETITEMTEXT, idx, (LPARAM)&lviSub); }
    if (col2) { LVITEM lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 2; lviSub.pszText = (LPWSTR)col2; SendMessage(hList, LVM_SETITEMTEXT, idx, (LPARAM)&lviSub); }
    if (col3) { LVITEM lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 3; lviSub.pszText = (LPWSTR)col3; SendMessage(hList, LVM_SETITEMTEXT, idx, (LPARAM)&lviSub); }
    if (col4) { LVITEM lviSub = { 0 }; lviSub.mask = LVIF_TEXT; lviSub.iItem = idx; lviSub.iSubItem = 4; lviSub.pszText = (LPWSTR)col4; SendMessage(hList, LVM_SETITEMTEXT, idx, (LPARAM)&lviSub); }
}

HFONT GetAppFont() { // v1.2：字体单例；v1.5：字号可在设置中调整，变化时重建
    static HFONT s_hFont = NULL;
    static int s_pt = 0;
    if (!s_hFont || s_pt != g_FontPt) {
        if (s_hFont) DeleteObject(s_hFont);
        s_hFont = CreateFontW(-DPIScale(g_FontPt), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, VARIABLE_PITCH | FF_SWISS, L"Microsoft YaHei");
        s_pt = g_FontPt;
    }
    return s_hFont;
}

void SetDefaultFont(HWND hwnd) {
    SendMessage(hwnd, WM_SETFONT, (WPARAM)GetAppFont(), MAKELPARAM(TRUE, 0));
}

// v1.5: 打开该重复组（相同 SHA256）全部文件所在位置
void OpenGroupLocations(HWND hwnd, int iItem) {
    (void)hwnd;
    wchar_t sha[128] = { 0 };
    GetListViewSubItemText(g_hHardlinkList, iItem, 3, sha, 128);
    if (!sha[0]) return;
    int count = (int)SendMessage(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    for (int i = 0; i < count; i++) {
        wchar_t path[2048] = { 0 }, sha2[128] = { 0 };
        GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemText(g_hHardlinkList, i, 3, sha2, 128);
        if (!path[0] || wcscmp(sha2, sha) != 0) continue;
        wchar_t param[2048 + 20];
        swprintf(param, _countof(param), L"/select,\"%s\"", path);
        ShellExecuteW(NULL, L"open", L"explorer.exe", param, NULL, SW_SHOWNORMAL);
    }
}

// v1.5: 字号变更后刷新全部控件字体并重绘
void ApplyFontToUI() {
    GetAppFont(); // 触发按新字号重建
    HWND ctrls[] = {
        g_hGroupFilter, g_hTxtDisk, g_hTxtAddr, g_hTxtFilter, g_hTxtInc, g_hEditInc, g_hTxtExc, g_hEditExc,
        g_hTxtSize, g_hEditSizeMin, g_hTxtSizeTo, g_hEditSizeMax, g_hTxtTotalSaved, g_hComboDisk, g_hEditAddress,
        g_hComboFilter, g_hFileList, g_hHardlinkList, g_hBtnSelAllL, g_hBtnInvSelL, g_hBtnSelAllR, g_hBtnInvSelR,
        g_hBtnExportR, g_hTxtScanInfo, g_hBtnRefresh, g_hBtnAnalyze, g_hBtnCreate, g_hBtnRestore, g_hBtnAbout,
        g_hBtnDelDup, g_hBtnSettings, g_hChkSlink
    };
    for (int i = 0; i < (int)(sizeof(ctrls) / sizeof(ctrls[0])); i++)
        if (ctrls[i]) SendMessage(ctrls[i], WM_SETFONT, (WPARAM)GetAppFont(), MAKELPARAM(TRUE, 0));
    RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
}

void ShowFileContextMenu(HWND hwnd, POINT pt, BOOL isHardlinkList) {
    HMENU hMenu = CreatePopupMenu();
    AppendThemedItem(hMenu, IDM_COPY_FILENAME, (LPCWSTR)TR(S_CTX_NAME));
    AppendThemedItem(hMenu, IDM_COPY_PATH, (LPCWSTR)TR(S_CTX_PATH));
    if (isHardlinkList) AppendThemedItem(hMenu, IDM_COPY_SHA256, (LPCWSTR)TR(S_CTX_SHA));
    AppendThemedItem(hMenu, 0, NULL);
    AppendThemedItem(hMenu, IDM_OPEN_EXPLORER, (LPCWSTR)TR(S_CTX_EXPLORE));
    if (isHardlinkList) AppendThemedItem(hMenu, IDM_OPEN_GROUP, (LPCWSTR)TR(S_CTX_OPEN_GROUP)); // v1.5

    if (isHardlinkList) AppendThemedItem(hMenu, IDM_CREATE_HLINK_CTX, (LPCWSTR)TR(S_CTX_CREATEHL));
    AppendThemedItem(hMenu, 0, NULL);
    AppendThemedItem(hMenu, IDM_DELETE, (LPCWSTR)TR(S_CTX_DELETE));
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

// ===================== v1.2：设置持久化（HKCU\Software\ElegantHLK）=====================
DWORD RegGetDword(const wchar_t* name, DWORD defVal) {
    HKEY hKey; DWORD val = defVal;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\ElegantHLK", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD sz = sizeof(val), type = 0;
        if (RegQueryValueEx(hKey, name, NULL, &type, (LPBYTE)&val, &sz) != ERROR_SUCCESS || type != REG_DWORD) val = defVal;
        RegCloseKey(hKey);
    }
    return val;
}

void RegSetDword(const wchar_t* name, DWORD val) {
    HKEY hKey;
    if (RegCreateKeyEx(HKEY_CURRENT_USER, L"Software\\ElegantHLK", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueEx(hKey, name, 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
        RegCloseKey(hKey);
    }
}

void LoadSettings() {
    g_LangMode = (int)RegGetDword(L"Language", 0);
    g_ThemeMode = (int)RegGetDword(L"Theme", 0);
    if (g_LangMode < 0 || g_LangMode > 2) g_LangMode = 0;
    if (g_ThemeMode < 0 || g_ThemeMode > 2) g_ThemeMode = 0;
    // v1.5: 字号取合法档位最近值，分栏比例限 200~800
    g_FontPt = (int)RegGetDword(L"FontSize", 11);
    const int ptAllowed[4] = { 10, 11, 12, 14 };
    int bestIdx = 0, bestDist = 1 << 30;
    for (int i = 0; i < 4; i++) { int d = g_FontPt - ptAllowed[i]; if (d < 0) d = -d; if (d < bestDist) { bestDist = d; bestIdx = i; } }
    g_FontPt = ptAllowed[bestIdx];
    g_SplitPermille = (int)RegGetDword(L"SplitPos", 500);
    if (g_SplitPermille < 200) g_SplitPermille = 200;
    if (g_SplitPermille > 800) g_SplitPermille = 800;
}

// 解析当前生效语言：手动优先；自动模式下非中文系统一律英文
void ApplyLanguage() {
    if (g_LangMode == 1) { g_Lang = 0; return; }
    if (g_LangMode == 2) { g_Lang = 1; return; }
    LANGID lid = LANGIDFROMLCID(GetSystemDefaultLCID());
    typedef LANGID(WINAPI* GETUILANG)(void);
    GETUILANG pGetUILang = (GETUILANG)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetUserDefaultUILanguage");
    if (pGetUILang) lid = pGetUILang();
    g_Lang = (PRIMARYLANGID(lid) == LANG_CHINESE) ? 0 : 1;
}

// 语言切换后刷新全部 UI 文本（按钮/标签/列头/下拉项/标题）
void ApplyLanguageToUI() {
    if (!g_hMainWnd) return;
    SetWindowText(g_hMainWnd, TR(S_TITLE));
    SetWindowText(g_hTxtDisk, TR(S_DISK));
    SetWindowText(g_hTxtAddr, TR(S_ADDR));
    SetWindowText(g_hTxtFilter, TR(S_TYPE));
    SetWindowText(g_hGroupFilter, TR(S_GROUP_FILTER));
    SetWindowText(g_hTxtInc, TR(S_INC_REGEX));
    SetWindowText(g_hTxtExc, TR(S_EXC_REGEX));
    SetWindowText(g_hTxtSize, TR(S_SIZE_MB));
    SetWindowText(g_hBtnSelAllL, TR(S_BTN_SELALL));
    SetWindowText(g_hBtnSelAllR, TR(S_BTN_SELALL));
    SetWindowText(g_hBtnInvSelL, TR(S_BTN_INVSEL));
    SetWindowText(g_hBtnInvSelR, TR(S_BTN_INVSEL));
    SetWindowText(g_hBtnExportR, TR(S_BTN_EXPORT));
    SetWindowText(g_hBtnDelDup, TR(S_BTN_DELDUP));
    SetWindowText(g_hBtnSettings, TR(S_BTN_SETTINGS));
    SetWindowText(g_hBtnAbout, TR(S_BTN_ABOUT));
    if (!g_bScanning) { // 任务进行中保持「停止」语义，避免状态错乱
        SetWindowText(g_hBtnRefresh, TR(S_BTN_REFRESH));
        SetWindowText(g_hBtnAnalyze, TR(S_BTN_ANALYZE));
        SetWindowText(g_hBtnCreate, g_bSlinkMode ? TR(S_BTN_CREATE_SL) : TR(S_BTN_CREATE)); // v1.3
        SetWindowText(g_hBtnRestore, TR(S_BTN_RESTORE));
    }

    int sel = (int)SendMessage(g_hComboFilter, CB_GETCURSEL, 0, 0);
    SendMessage(g_hComboFilter, CB_RESETCONTENT, 0, 0);
    static const StrId s_fltIds[8] = { S_FLT_CUSTOM, S_FLT_VIDEO, S_FLT_HD, S_FLT_AUDIO, S_FLT_IMAGE, S_FLT_EXE, S_FLT_ZIP, S_FLT_DOC };
    for (int i = 0; i < 8; i++) SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(s_fltIds[i]));
    SendMessage(g_hComboFilter, CB_SETCURSEL, sel < 0 ? 0 : sel, 0);

    static const StrId s_leftCols[4] = { S_COL_NAME, S_COL_SIZE, S_COL_STATUS, S_COL_HL };
    for (int c = 0; c < 4; c++) {
        LVCOLUMN lvc = { 0 }; lvc.mask = LVCF_TEXT; lvc.pszText = (LPWSTR)TR(s_leftCols[c]);
        SendMessage(g_hFileList, LVM_SETCOLUMN, c, (LPARAM)&lvc);
    }
    static const int s_rightColIdx[4] = { 0, 1, 2, 4 };
    static const StrId s_rightCols[4] = { S_COL_DUP, S_COL_STATUSINFO, S_COL_SIZESAVE, S_COL_HL };
    for (int c = 0; c < 4; c++) {
        LVCOLUMN lvc = { 0 }; lvc.mask = LVCF_TEXT; lvc.pszText = (LPWSTR)TR(s_rightCols[c]);
        SendMessage(g_hHardlinkList, LVM_SETCOLUMN, s_rightColIdx[c], (LPARAM)&lvc);
    }

    wchar_t totalBuf[128]; FormatSize(g_llTotalSavedSpace, totalBuf, _countof(totalBuf));
    wchar_t finalStr[320]; swprintf(finalStr, _countof(finalStr), TR(S_TOTAL_SAVED_FMT), totalBuf);
    SetWindowText(g_hTxtTotalSaved, finalStr);

    RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_FRAME);
}

// 读系统暗色设置（HKCU\...\Personalize\AppsUseLightTheme，XP 无此键 => 浅色）
BOOL SystemDarkModeEnabled() {
    DWORD val = 1; HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD sz = sizeof(val), type = 0;
        if (RegQueryValueEx(hKey, L"AppsUseLightTheme", NULL, &type, (LPBYTE)&val, &sz) != ERROR_SUCCESS || type != REG_DWORD) val = 1;
        RegCloseKey(hKey);
    }
    return val == 0;
}

// uxtheme 自 XP 起自带；老系统不认识 DarkMode_* 主题名会自动忽略，安全
static void SetCtrlTheme(HWND h, const wchar_t* darkName) {
    if (!h) return;
    if (g_bDark) SetWindowTheme(h, darkName, NULL);
    else SetWindowTheme(h, NULL, NULL);
}

void ApplyTheme() {
    BOOL dark = (g_ThemeMode == 2) || (g_ThemeMode == 0 && SystemDarkModeEnabled());
    g_bDark = dark;
    if (g_hbrBg) { DeleteObject(g_hbrBg); g_hbrBg = NULL; }
    if (g_hbrEdit) { DeleteObject(g_hbrEdit); g_hbrEdit = NULL; }
    g_hbrBg = CreateSolidBrush(dark ? RGB(32, 32, 32) : RGB(255, 255, 255));
    g_hbrEdit = CreateSolidBrush(dark ? RGB(45, 45, 45) : RGB(255, 255, 255));
    if (!g_hMainWnd) return; // WinMain 早期调用只为建笔刷

    SetClassLongPtr(g_hMainWnd, GCLP_HBRBACKGROUND, (LONG_PTR)g_hbrBg);

    // Win10 1903+ 暗色标题栏（dwmapi 运行时探测，XP/老系统自动跳过）
    HMODULE hDwm = LoadLibraryW(L"dwmapi.dll");
    if (hDwm) {
        typedef HRESULT(WINAPI* DSWA)(HWND, DWORD, LPCVOID, DWORD);
        DSWA pDswa = (DSWA)GetProcAddress(hDwm, "DwmSetWindowAttribute");
        if (pDswa) { BOOL d = dark; pDswa(g_hMainWnd, 20 /*DWMWA_USE_IMMERSIVE_DARK_MODE*/, &d, sizeof(d)); }
        FreeLibrary(hDwm);
    }

    // 列表/表头/下拉框交给系统暗色主题（Win10 1809+ 生效）
    SetCtrlTheme(g_hFileList, L"DarkMode_Explorer");
    SetCtrlTheme(g_hHardlinkList, L"DarkMode_Explorer");
    SetCtrlTheme(ListView_GetHeader(g_hFileList), L"DarkMode_ItemsView");
    SetCtrlTheme(ListView_GetHeader(g_hHardlinkList), L"DarkMode_ItemsView");
    SetCtrlTheme(g_hComboDisk, L"DarkMode_CFD");
    SetCtrlTheme(g_hComboFilter, L"DarkMode_CFD");

    if (dark) {
        SetWindowTheme(g_hProgressBar, L"", L""); // 关主题后颜色消息才生效
        SendMessage(g_hProgressBar, PBM_SETBKCOLOR, 0, RGB(45, 45, 45));
        SendMessage(g_hProgressBar, PBM_SETBARCOLOR, 0, RGB(6, 176, 37));
    } else {
        SetWindowTheme(g_hProgressBar, NULL, NULL);
    }

    COLORREF lb = dark ? RGB(38, 38, 38) : RGB(255, 255, 255);
    COLORREF lt = dark ? RGB(235, 235, 235) : RGB(0, 0, 0);
    HWND lists[2] = { g_hFileList, g_hHardlinkList };
    for (int i = 0; i < 2; i++) {
        ListView_SetBkColor(lists[i], lb);
        ListView_SetTextBkColor(lists[i], lb);
        ListView_SetTextColor(lists[i], lt);
    }

    RedrawWindow(g_hMainWnd, NULL, NULL, RDW_INVALIDATE | RDW_ALLCHILDREN | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
}

// v1.2 自绘按钮（浅色仿原生、深色暗底），分组框同走此路
void DrawThemedButton(LPDRAWITEMSTRUCT dis) {
    HWND hBtn = dis->hwndItem;
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    wchar_t text[256] = { 0 };
    GetWindowText(hBtn, text, _countof(text));
    LONG_PTR style = GetWindowLongPtrA(hBtn, GWL_STYLE);
    BOOL pressed = (dis->itemState & ODS_SELECTED) != 0;
    BOOL disabled = (dis->itemState & ODS_DISABLED) != 0;
    COLORREF clrBg = g_bDark ? RGB(32, 32, 32) : RGB(255, 255, 255);
    COLORREF clrText = g_bDark ? RGB(235, 235, 235) : RGB(0, 0, 0);
    HFONT oldF = (HFONT)SelectObject(hdc, GetAppFont());

    if ((style & BS_TYPEMASK) == BS_GROUPBOX) {
        SIZE sz = { 0 }; GetTextExtentPoint32(hdc, text, (int)wcslen(text), &sz);
        int top = rc.top + sz.cy / 2;
        HPEN hpen = CreatePen(PS_SOLID, 1, g_bDark ? RGB(90, 90, 90) : RGB(208, 208, 208));
        HPEN oldP = (HPEN)SelectObject(hdc, hpen);
        HBRUSH oldB = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, rc.left + 1, top, rc.right - 1, rc.bottom - 1);
        SelectObject(hdc, oldB); SelectObject(hdc, oldP); DeleteObject(hpen);
        RECT trc; trc.left = rc.left + DPIScale(9); trc.top = rc.top;
        trc.right = trc.left + sz.cx + DPIScale(2); trc.bottom = rc.top + sz.cy;
        HBRUSH hbr = CreateSolidBrush(clrBg);
        FillRect(hdc, &trc, hbr); DeleteObject(hbr);
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, disabled ? RGB(128, 128, 128) : clrText);
        trc.left += DPIScale(1);
        DrawText(hdc, text, -1, &trc, DT_LEFT | DT_TOP | DT_SINGLELINE | DT_NOPREFIX);
        SelectObject(hdc, oldF);
        return;
    }

    COLORREF face = g_bDark ? (pressed ? RGB(85, 85, 85) : RGB(58, 58, 58))
                            : (pressed ? RGB(218, 228, 240) : RGB(245, 245, 245));
    COLORREF border = g_bDark ? RGB(110, 110, 110) : RGB(172, 172, 172);
    HBRUSH hbr = CreateSolidBrush(face);
    FillRect(hdc, &rc, hbr); DeleteObject(hbr);
    HPEN hpen = CreatePen(PS_SOLID, 1, border);
    HPEN oldP = (HPEN)SelectObject(hdc, hpen);
    HBRUSH oldB = (HBRUSH)SelectObject(hdc, GetStockObject(NULL_BRUSH));
    Rectangle(hdc, rc.left, rc.top, rc.right, rc.bottom);
    SelectObject(hdc, oldB); SelectObject(hdc, oldP); DeleteObject(hpen);
    if (dis->itemState & ODS_FOCUS) {
        RECT frc = rc; InflateRect(&frc, -DPIScale(3), -DPIScale(3));
        DrawFocusRect(hdc, &frc);
    }
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, disabled ? RGB(128, 128, 128) : clrText);
    DrawText(hdc, text, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

// v1.2 深色模式自绘菜单项（itemData=字符串指针；NULL=分隔线；选中态画圆点）
void DrawThemedMenuItem(LPDRAWITEMSTRUCT dis) {
    HDC hdc = dis->hDC;
    RECT rc = dis->rcItem;
    if (!dis->itemData) {
        HBRUSH hbr = CreateSolidBrush(RGB(43, 43, 43));
        FillRect(hdc, &rc, hbr); DeleteObject(hbr);
        HPEN hpen = CreatePen(PS_SOLID, 1, RGB(70, 70, 70));
        HPEN oldP = (HPEN)SelectObject(hdc, hpen);
        int y = (rc.top + rc.bottom) / 2;
        MoveToEx(hdc, rc.left + DPIScale(8), y, NULL); LineTo(hdc, rc.right - DPIScale(8), y);
        SelectObject(hdc, oldP); DeleteObject(hpen);
        return;
    }
    BOOL sel = (dis->itemState & ODS_SELECTED) != 0;
    BOOL disabled = (dis->itemState & (ODS_DISABLED | ODS_GRAYED)) != 0;
    HBRUSH hbr = CreateSolidBrush(sel ? RGB(68, 68, 68) : RGB(43, 43, 43));
    FillRect(hdc, &rc, hbr); DeleteObject(hbr);
    if (dis->itemState & ODS_CHECKED) {
        int d = DPIScale(8);
        int cx = rc.left + DPIScale(15), cy = (rc.top + rc.bottom) / 2;
        HBRUSH dot = CreateSolidBrush(RGB(120, 180, 255));
        HBRUSH oldB = (HBRUSH)SelectObject(hdc, dot);
        HPEN oldP = (HPEN)SelectObject(hdc, GetStockObject(NULL_PEN));
        Ellipse(hdc, cx - d / 2, cy - d / 2, cx + d / 2, cy + d / 2);
        SelectObject(hdc, oldB); SelectObject(hdc, oldP); DeleteObject(dot);
    }
    HFONT oldF = (HFONT)SelectObject(hdc, GetAppFont());
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, disabled ? RGB(125, 125, 125) : RGB(235, 235, 235));
    RECT trc = rc; trc.left += DPIScale(30);
    DrawText(hdc, (const wchar_t*)dis->itemData, -1, &trc, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX);
    SelectObject(hdc, oldF);
}

// 深色模式下菜单项改自绘（文字指针即 itemData），浅色保持系统绘制
void AppendThemedItem(HMENU hMenu, UINT id, const wchar_t* text) {
    if (g_bDark) {
        if (text) AppendMenu(hMenu, MF_OWNERDRAW, id, (LPCWSTR)text);
        else AppendMenu(hMenu, MF_OWNERDRAW | MF_SEPARATOR, 0, NULL);
    }
    else {
        if (text) AppendMenu(hMenu, MF_STRING, id, text);
        else AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    }
}

// v1.5: 级联子菜单挂载（深色下同样走自绘，父项文字指针作 itemData）
void AppendThemedSub(HMENU hParent, HMENU hSub, const wchar_t* text) {
    if (g_bDark) AppendMenuW(hParent, MF_OWNERDRAW | MF_POPUP, (UINT_PTR)hSub, text);
    else AppendMenuW(hParent, MF_POPUP, (UINT_PTR)hSub, text);
}

// v1.2：不建硬链接，直接把每组多余副本送入回收站（保留每组第 1 个）
void DoDeleteDuplicates(HWND hwnd) {
    int count = (int)SendMessage(g_hHardlinkList, LVM_GETITEMCOUNT, 0, 0);
    if (count == 0) {
        MessageBox(hwnd, TR(S_MSG_EMPTY_R_SIMPLE), TR(S_T_TIP), MB_OK | MB_ICONWARNING);
        return;
    }
    int checkedCount = 0;
    for (int i = 0; i < count; i++) if (ListView_GetCheckState(g_hHardlinkList, i)) checkedCount++;

    std::map<std::wstring, int> seenSha;
    std::wstring buf; // SHFileOperation 用的多路径串（逐个 \0 分隔）
    size_t delN = 0, skipN = 0;
    for (int i = 0; i < count; i++) {
        if (checkedCount > 0 && !ListView_GetCheckState(g_hHardlinkList, i)) continue;
        wchar_t path[2048] = { 0 }, sha[128] = { 0 };
        GetListViewSubItemText(g_hHardlinkList, i, 0, path, 2048);
        GetListViewSubItemText(g_hHardlinkList, i, 3, sha, 128);
        if (wcslen(path) == 0 || wcslen(sha) == 0) continue; // 只处理分析产生的行
        if (seenSha.find(sha) == seenSha.end()) { seenSha[sha] = 1; continue; } // 每组第 1 个保留
        if (IsProtectedPath(path)) { skipN++; continue; }
        buf.append(path, wcslen(path) + 1);
        delN++;
    }
    if (delN == 0) {
        MessageBox(hwnd, TR(S_MSG_DELDUP_NONE), TR(S_T_TIP), MB_OK | MB_ICONINFORMATION);
        return;
    }
    wchar_t ask[768];
    swprintf(ask, _countof(ask), TR(S_MSG_DELDUP_ASK), delN);
    if (skipN > 0) {
        wchar_t extra[128]; swprintf(extra, _countof(extra), L"\n\n(%s: %zu)", TR(S_SKIPPED_PROTECTED), skipN);
        lstrcat(ask, extra);
    }
    if (MessageBox(hwnd, ask, TR(S_T_DELDUP), MB_YESNO | MB_ICONWARNING) != IDYES) return;
    buf.append(L"\0", 1);
    SHFILEOPSTRUCT op = { 0 };
    op.hwnd = hwnd; op.wFunc = FO_DELETE; op.pFrom = buf.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION;
    int r = SHFileOperation(&op);
    size_t okN = (r == 0 && !op.fAnyOperationsAborted) ? delN : 0;
    wchar_t done[256];
    swprintf(done, _countof(done), TR(S_MSG_DELDUP_DONE), okN, delN - okN);
    MessageBox(hwnd, done, TR(S_T_DONE), MB_OK | MB_ICONINFORMATION);
    SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_BTN_REFRESH, BN_CLICKED), 0);
}

void CreateControls(HWND hwnd) {
    g_hTxtDisk = CreateWindowEx(0, L"STATIC", TR(S_DISK), WS_VISIBLE | WS_CHILD, DPIScale(10), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hComboDisk = CreateWindowEx(0, WC_COMBOBOX, L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, DPIScale(50), DPIScale(12), DPIScale(160), DPIScale(200), hwnd, (HMENU)(INT_PTR)ID_COMBO_DISK, g_hInst, NULL);

    wchar_t drives[256]; GetLogicalDriveStrings(256, drives); wchar_t* drive = drives;
    while (*drive) {
        wchar_t volName[MAX_PATH] = { 0 }; wchar_t dispStr[MAX_PATH];
        GetVolumeInformation(drive, volName, MAX_PATH, NULL, NULL, NULL, NULL, 0);
        if (volName[0]) swprintf(dispStr, _countof(dispStr), L"%s [%s]", drive, volName); else swprintf(dispStr, _countof(dispStr), L"%s", drive);
        SendMessage(g_hComboDisk, CB_ADDSTRING, 0, (LPARAM)dispStr); drive += wcslen(drive) + 1;
    }
    SendMessage(g_hComboDisk, CB_SETCURSEL, 0, 0);

    g_hTxtAddr = CreateWindowEx(0, L"STATIC", TR(S_ADDR), WS_VISIBLE | WS_CHILD, DPIScale(220), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditAddress = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", g_CurrentPath, WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(260), DPIScale(12), DPIScale(360), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_ADDRESS, g_hInst, NULL);

    g_hTxtFilter = CreateWindowEx(0, L"STATIC", TR(S_TYPE), WS_VISIBLE | WS_CHILD, DPIScale(630), DPIScale(15), DPIScale(40), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hComboFilter = CreateWindowEx(0, WC_COMBOBOX, L"", WS_VISIBLE | WS_CHILD | CBS_DROPDOWNLIST, DPIScale(670), DPIScale(12), DPIScale(300), DPIScale(400), hwnd, (HMENU)(INT_PTR)ID_COMBO_FILTER, g_hInst, NULL);

    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_CUSTOM));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_VIDEO));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_HD));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_AUDIO));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_IMAGE));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_EXE));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_ZIP));
    SendMessage(g_hComboFilter, CB_ADDSTRING, 0, (LPARAM)TR(S_FLT_DOC));
    SendMessage(g_hComboFilter, CB_SETCURSEL, 0, 0);

    g_hGroupFilter = CreateWindowEx(0, L"BUTTON", TR(S_GROUP_FILTER), WS_VISIBLE | WS_CHILD | BS_GROUPBOX | BS_OWNERDRAW, DPIScale(10), DPIScale(42), DPIScale(960), DPIScale(60), hwnd, NULL, g_hInst, NULL);
    g_hTxtInc = CreateWindowEx(0, L"STATIC", TR(S_INC_REGEX), WS_VISIBLE | WS_CHILD, DPIScale(20), DPIScale(65), DPIScale(80), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditInc = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(100), DPIScale(62), DPIScale(150), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_INC_REGEX, g_hInst, NULL);
    g_hTxtExc = CreateWindowEx(0, L"STATIC", TR(S_EXC_REGEX), WS_VISIBLE | WS_CHILD, DPIScale(270), DPIScale(65), DPIScale(80), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditExc = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL, DPIScale(350), DPIScale(62), DPIScale(150), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_EXC_REGEX, g_hInst, NULL);
    g_hTxtSize = CreateWindowEx(0, L"STATIC", TR(S_SIZE_MB), WS_VISIBLE | WS_CHILD, DPIScale(610), DPIScale(65), DPIScale(60), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditSizeMin = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_NUMBER, DPIScale(670), DPIScale(62), DPIScale(60), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_MIN_SIZE, g_hInst, NULL);
    g_hTxtSizeTo = CreateWindowEx(0, L"STATIC", L"-", WS_VISIBLE | WS_CHILD, DPIScale(740), DPIScale(65), DPIScale(20), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hEditSizeMax = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | ES_AUTOHSCROLL | ES_NUMBER, DPIScale(760), DPIScale(62), DPIScale(60), DPIScale(24), hwnd, (HMENU)(INT_PTR)ID_EDIT_MAX_SIZE, g_hInst, NULL);

    // 新增全选 / 反选按钮
    g_hBtnSelAllL = CreateWindowEx(0, L"BUTTON", TR(S_BTN_SELALL), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(10), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_SELALL_L, g_hInst, NULL);
    g_hBtnInvSelL = CreateWindowEx(0, L"BUTTON", TR(S_BTN_INVSEL), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(80), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_INVSEL_L, g_hInst, NULL);
    g_hBtnSelAllR = CreateWindowEx(0, L"BUTTON", TR(S_BTN_SELALL), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(440), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_SELALL_R, g_hInst, NULL);
    g_hBtnInvSelR = CreateWindowEx(0, L"BUTTON", TR(S_BTN_INVSEL), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(510), DPIScale(110), DPIScale(60), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_INVSEL_R, g_hInst, NULL);
    g_hBtnExportR = CreateWindowEx(0, L"BUTTON", TR(S_BTN_EXPORT), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(580), DPIScale(110), DPIScale(90), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_EXPORT_R, g_hInst, NULL);

    g_hFileList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, DPIScale(10), DPIScale(140), DPIScale(420), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_FILE, g_hInst, NULL);
    LVCOLUMN lvc = { 0 }; lvc.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;
    lvc.cx = DPIScale(170); lvc.pszText = (LPWSTR)TR(S_COL_NAME); SendMessage(g_hFileList, LVM_INSERTCOLUMN, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPWSTR)TR(S_COL_SIZE);       SendMessage(g_hFileList, LVM_INSERTCOLUMN, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(100); lvc.pszText = (LPWSTR)TR(S_COL_STATUS);       SendMessage(g_hFileList, LVM_INSERTCOLUMN, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(60);  lvc.pszText = (LPWSTR)TR(S_COL_HL);     SendMessage(g_hFileList, LVM_INSERTCOLUMN, 3, (LPARAM)&lvc);
    SendMessage(g_hFileList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

    g_hHardlinkList = CreateWindowEx(WS_EX_CLIENTEDGE, WC_LISTVIEW, L"", WS_VISIBLE | WS_CHILD | LVS_REPORT | LVS_SHOWSELALWAYS, DPIScale(440), DPIScale(140), DPIScale(530), DPIScale(420), hwnd, (HMENU)(INT_PTR)ID_LIST_HARDLINK, g_hInst, NULL);
    lvc.cx = DPIScale(170); lvc.pszText = (LPWSTR)TR(S_COL_DUP); SendMessage(g_hHardlinkList, LVM_INSERTCOLUMN, 0, (LPARAM)&lvc);
    lvc.cx = DPIScale(80);  lvc.pszText = (LPWSTR)TR(S_COL_STATUSINFO); SendMessage(g_hHardlinkList, LVM_INSERTCOLUMN, 1, (LPARAM)&lvc);
    lvc.cx = DPIScale(90);  lvc.pszText = (LPWSTR)TR(S_COL_SIZESAVE); SendMessage(g_hHardlinkList, LVM_INSERTCOLUMN, 2, (LPARAM)&lvc);
    lvc.cx = DPIScale(140); lvc.pszText = (LPWSTR)L"SHA256"; SendMessage(g_hHardlinkList, LVM_INSERTCOLUMN, 3, (LPARAM)&lvc);
    lvc.cx = DPIScale(50);  lvc.pszText = (LPWSTR)TR(S_COL_HL); SendMessage(g_hHardlinkList, LVM_INSERTCOLUMN, 4, (LPARAM)&lvc);
    SendMessage(g_hHardlinkList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_CHECKBOXES);

    SHFILEINFO sfi; HIMAGELIST hSysImageList = (HIMAGELIST)SHGetFileInfo((LPCWSTR)L"C:\\", 0, &sfi, sizeof(SHFILEINFO), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
    SendMessage(g_hFileList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);
    SendMessage(g_hHardlinkList, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hSysImageList);

    // v1.2：删除重复项（不建硬链接直接删）+ 语言 / 主题切换按钮
    g_hBtnSettings = CreateWindowExW(0, L"BUTTON", TR(S_BTN_SETTINGS), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(230), DPIScale(110), DPIScale(76), DPIScale(25), hwnd, (HMENU)(INT_PTR)ID_BTN_SETTINGS, g_hInst, NULL);

    // v1.3: 软连接模式开关（勾选后「一键创建」改为建软连接）
    g_hChkSlink = CreateWindowEx(0, L"BUTTON", TR(S_CHK_SLINK), WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX, DPIScale(720), DPIScale(583), DPIScale(130), DPIScale(30), hwnd, (HMENU)(INT_PTR)ID_CHK_SLINK, g_hInst, NULL);

    int btnY = 580;
    g_hBtnRefresh = CreateWindowEx(0, L"BUTTON", TR(S_BTN_REFRESH), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(10), DPIScale(btnY), DPIScale(120), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_REFRESH, g_hInst, NULL);
    g_hBtnAnalyze = CreateWindowEx(0, L"BUTTON", TR(S_BTN_ANALYZE), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(140), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ANALYZE, g_hInst, NULL);
    g_hBtnCreate = CreateWindowEx(0, L"BUTTON", TR(S_BTN_CREATE), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(280), DPIScale(btnY), DPIScale(140), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_CREATE_HLINK, g_hInst, NULL);
    g_hBtnRestore = CreateWindowEx(0, L"BUTTON", TR(S_BTN_RESTORE), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(430), DPIScale(btnY), DPIScale(130), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_RESTORE_SLINK, g_hInst, NULL);

    int btnY2 = 625;
    g_hTxtScanInfo = CreateWindowEx(0, L"STATIC", L"", WS_VISIBLE | WS_CHILD | SS_LEFT | SS_PATHELLIPSIS | SS_NOPREFIX, DPIScale(180), DPIScale(btnY2 + 2), DPIScale(300), DPIScale(18), hwnd, NULL, g_hInst, NULL);
    g_hProgressBar = CreateWindowEx(0, PROGRESS_CLASS, NULL, WS_VISIBLE | WS_CHILD | PBS_SMOOTH, DPIScale(500), DPIScale(btnY2 + 2), DPIScale(180), DPIScale(16), hwnd, (HMENU)(INT_PTR)ID_PROGRESS_BAR, g_hInst, NULL);

    g_hTxtTotalSaved = CreateWindowEx(0, L"STATIC", TR(S_TOTAL_SAVED_INIT), WS_VISIBLE | WS_CHILD | SS_RIGHT, DPIScale(390), DPIScale(btnY2 + 8), DPIScale(460), DPIScale(20), hwnd, NULL, g_hInst, NULL);
    g_hBtnAbout = CreateWindowEx(0, L"BUTTON", TR(S_BTN_ABOUT), WS_VISIBLE | WS_CHILD | BS_OWNERDRAW, DPIScale(870), DPIScale(btnY2), DPIScale(100), DPIScale(35), hwnd, (HMENU)(INT_PTR)ID_BTN_ABOUT, g_hInst, NULL);

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
    SetDefaultFont(g_hBtnDelDup); SetDefaultFont(g_hBtnSettings);
    SetDefaultFont(g_hChkSlink); // v1.3
    ApplyTheme(); // v1.2 初始主题
}