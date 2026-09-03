/*
* MemOpt - 轻量级内存优化工具
*
* 综合 memreduct 与 WinMemoryCleaner 两项目核心功能，
* 使用 Windows Native API 清理各类内存区域。
*
* 编译 (需管理员权限运行):
*   cl /O2 /DWIN32_LEAN_AND_MEAN memopt.c /link advapi32.lib psapi.lib
*
* 用法:
*   memopt.exe                      打开图形界面 (托盘 + 主窗口, 含后台自动清理)
*   memopt.exe clean                清理默认区域(6项)
*   memopt.exe clean:full           清理全部8项区域
*   memopt.exe clean:standbylist working-set
*                                   仅清理指定区域 (可任意组合)
*
* 安全策略:
*   手动/命令行清理含全部区域(步间 150ms 延迟降低内核栈溢出风险)。
*   后台自动清理默认"强力模式"(与手动相同，真正释放内存)，
*   可在 GUI 切回保守模式(6项区域，更安全稳定)。
*   152ms 步间延迟经测试是 Win11 24H2 的安全下限——
*   memreduct 的 0ms 延迟是该系统上 0xF7 蓝屏的根因。
*
* UI 布局 (v3):
*   主窗口: 大百分比 + 进度条 + 三张竖排内存卡片 + [立即清理] [设置]
*   设置窗口 (弹窗): 复选框(自动清理/自启动/强力) + 数字输入(阈值/间隔) + 释放更多 + 保存
*
* 支持的区域名 (大小写不敏感):
*   working-set            工作集
*   system-file-cache      系统文件缓存
*   modified-file-cache    修改过的文件缓存 (卷缓存)
*   modified-list          修改页列表
*   standby-list           Standby 列表 (激进, 高风险)
*   standby-list-low       低优先级 Standby 列表
*   registry-cache         注册表缓存 (Win8.1+)
*   combine-memory-lists   合并内存页 (Win10+)
*/

#include <windows.h>
#include <windowsx.h>
#include <commctrl.h>
#include <stdio.h>
#include <stdlib.h>
#include <psapi.h>
#include <shellapi.h>

/* MSVC 专用库声明；GCC/MinGW 通过命令行 -lxxx 链接 */
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#endif

/* ---------- Native API 定义 ---------- */

typedef LONG NTSTATUS;
#define NT_SUCCESS(s) ((NTSTATUS)(s) >= 0)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)

typedef enum _SYSTEM_MEMORY_LIST_COMMAND {
    MemoryEmptyWorkingSets = 0,
    MemoryFlushModifiedList = 1,
    MemoryPurgeStandbyList = 2,
    MemoryPurgeLowPriorityStandbyList = 3
} SYSTEM_MEMORY_LIST_COMMAND;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemMemoryListInformation = 80,                  /* 0x50 */
    SystemFileCacheInformation   = 0x15,                /* 21  (Vista, Win7) */
    SystemFileCacheInformationEx = 0x7E,                /* 126 (Win8+)      */
    SystemRegistryReconciliationInformation = 0x9C,    /* 156 */
    SystemCombinePhysicalMemoryInformation = 0x53      /* 83 */
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_FILECACHE_INFORMATION {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    ULONG CurrentSizeIncludingTransitionInPages;
    ULONG PeakSizeIncludingTransitionInPages;
    ULONG TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

/* Win8+ 专用：裁剪系统文件缓存的新版本结构。
   与老版本字段顺序不同，硬编码会 STATUS_INVALID_INFO_CLASS (0xC0000004)，
   必须用这个 Ex 结构才能在 Win10/11 正确裁剪。 */
typedef struct _SYSTEM_FILECACHE_INFORMATION_EX {
    SIZE_T CurrentSize;
    SIZE_T PeakSize;
    ULONG PageFaultCount;
    SIZE_T MinimumWorkingSet;
    SIZE_T MaximumWorkingSet;
    SIZE_T CurrentSizeIncludingTransitionInPages;
    SIZE_T PeakSizeIncludingTransitionInPages;
    SIZE_T TransitionRePurposeCount;
    ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION_EX, *PSYSTEM_FILECACHE_INFORMATION_EX;

typedef struct _MEMORY_COMBINE_INFORMATION_EX {
    HANDLE Handle;
    ULONG PagesCombined;
    ULONG Flags;
    ULONG64 TimeStamp;
} MEMORY_COMBINE_INFORMATION_EX, *PMEMORY_COMBINE_INFORMATION_EX;

typedef struct _TOKEN_PRIVILEGES {
    ULONG PrivilegeCount;
    LUID_AND_ATTRIBUTES Privileges[1];
} TOKEN_PRIVILEGES, *PTOKEN_PRIVILEGES;

extern NTSTATUS __stdcall NtSetSystemInformation(
    SYSTEM_INFORMATION_CLASS info_class,
    PVOID info, ULONG length);

/* 显式从 ntdll 解析，兼容 mingw（无需额外链接库） */
typedef NTSTATUS (__stdcall *PNtSetSystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG);
static PNtSetSystemInformation g_NtSetSystemInformation = NULL;

static void resolve_nt(void) {
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (!h) h = LoadLibraryW(L"ntdll.dll");
    if (h) {
        /* 双重转换绕开 -Wcast-function-type：GetProcAddress 返回的
           FARPROC 与目标签名不兼容，先落到 void* 再转函数指针 */
        void *fn = (void *)GetProcAddress(h, "NtSetSystemInformation");
        g_NtSetSystemInformation = (PNtSetSystemInformation)fn;
    }
}

/* 包装宏，保持原调用点不变 */
#define NtSetSystemInformation(c,i,l) g_NtSetSystemInformation((c),(i),(l))

/* ---------- 区域掩码 ---------- */

#define R_WORKING_SET        0x0001
#define R_SYSTEM_FILE_CACHE  0x0002
#define R_MODIFIED_FILE      0x0004
#define R_MODIFIED_LIST      0x0008
#define R_STANDBY_LIST       0x0010
#define R_STANDBY_LOW        0x0020
#define R_REGISTRY_CACHE     0x0040
#define R_COMBINE_LISTS      0x0080

/* 默认区域：与 memreduct REDUCT_MASK_DEFAULT 对齐，
  包含 working-set / system-file-cache / standby-low / registry / combine / modified-file-cache。
  由于已通过步间延迟解决 0xF7 根因，不再需要过度保守。 */
#define R_DEFAULT  (R_WORKING_SET | R_SYSTEM_FILE_CACHE | R_STANDBY_LOW | R_REGISTRY_CACHE | R_COMBINE_LISTS | R_MODIFIED_FILE)

/* 全量区域(所有8项) */
#define R_ALL_OLD  (R_WORKING_SET | R_SYSTEM_FILE_CACHE | R_MODIFIED_FILE | R_MODIFIED_LIST | R_STANDBY_LIST | R_STANDBY_LOW | R_REGISTRY_CACHE | R_COMBINE_LISTS)

/* Win11 24H2+ 已知无延迟连续调用会触发内核栈溢出，但步间 150ms
   延迟已解决此风险。保留此定义供 safe_mask 继续降级自动清理。 */
#define R_RISKY_24H2 (R_STANDBY_LIST | R_STANDBY_LOW)

/* 自动清理策略默认值（可在 GUI 调整） */
static int g_auto_enabled   = 0;                 /* 后台自动清理开关 */
static int g_auto_aggressive = 1;                /* 强力模式:含 standby 等全区域,
                                                   能真正释放内存;关闭则含6项
                                                   (不含 standby-list 和 modified-list) */
static int g_auto_threshold = 80;                /* 内存占用 % 触发阈值 */
static int g_auto_interval  = 10 * 60 * 1000;     /* 最小间隔 ms (默认10分钟) */
static ULONG64 g_app_start_tick = 0;             /* 应用启动 tick（auto_clean 启动防抖用） */
static ULONG64 g_last_clean_tick = 0;             /* 上次清理时间 */
static ULONG64 g_last_freed = 0;                  /* 上次清理释放量(字节) */
static wchar_t g_last_clean_tag[16] = L"暂无";    /* 上次清理方式 */

/* 清理互斥/重入保护：防止手动清理与后台自动清理重叠执行。
   0xF7 内核栈溢出最常见于同时/高频调用内存列表清除 API，
   所以清理期间禁止再次进入 do_clean。 */
static volatile LONG g_cleaning_in_progress = 0;
#define CLEAN_LOCK_TRY()   InterlockedCompareExchange(&g_cleaning_in_progress, 1, 0)
#define CLEAN_UNLOCK()     InterlockedExchange(&g_cleaning_in_progress, 0)

/* 返回当前系统下允许使用的安全区域掩码（剔除高风险项）。
   用 W 版而非 OSVERSIONINFOEX(窄版)：RtlGetVersion / GetVersionExW 均要求宽版，
   且 W 版 szCSDVersion 为 WCHAR[128]，与 RTL_OSVERSIONINFOEXW 布局完全一致。 */
static OSVERSIONINFOEXW g_os = {0};

/* RtlGetVersion 函数指针：显式从 ntdll 解析，与 resolve_nt 同风格。
   必须用 RtlGetVersion 而非 GetVersionExW 的原因：
   GetVersionExW 在 Win8.1+ 受应用 manifest 的 <supportedOS> 约束，未声明
   兼容性时返回伪造的 6.2.9200(Win8)，导致 os_build() 永远低于 9600/10240，
   使 registry-cache / combine-memory-lists 被错误跳过(静默失效)。
   RtlGetVersion 不受 manifest 影响，返回真实版本号。 */
typedef LONG (WINAPI *PRtlGetVersion)(LPOSVERSIONINFOEXW);
static PRtlGetVersion g_RtlGetVersion = NULL;

static void init_os_version(void) {
    g_os.dwOSVersionInfoSize = sizeof(g_os);
    HMODULE h = GetModuleHandleW(L"ntdll.dll");
    if (h) {
        /* void* 双重转换绕开 -Wcast-function-type，与 resolve_nt 一致 */
        void *fn = (void *)GetProcAddress(h, "RtlGetVersion");
        g_RtlGetVersion = (PRtlGetVersion)fn;
    }
    if (g_RtlGetVersion && g_RtlGetVersion(&g_os) == 0) /* STATUS_SUCCESS */
        return;
    /* 降级：极旧系统无 RtlGetVersion 时回退（仍受 manifest 限制，但总比无值强） */
    GetVersionExW((LPOSVERSIONINFOW)&g_os);
}

static int os_build(void) {
    return g_os.dwBuildNumber;
}

/* ====== INI 配置持久化 ====== */
/* INI 文件路径：exe 同目录下 memopt.ini。
   保存字段：auto_enabled / auto_threshold / auto_interval_min / auto_aggressive */

static void get_ini_path(wchar_t *path, int len) {
    GetModuleFileNameW(NULL, path, len);
    wchar_t *p = wcsrchr(path, L'\\');
    if (p) *(p + 1) = L'\0';
    wcscat_s(path, len, L"memopt.ini");
}

static void load_config(void) {
    wchar_t path[MAX_PATH];
    get_ini_path(path, _countof(path));

    g_auto_enabled   = GetPrivateProfileIntW(L"Settings", L"auto_enabled",    0, path);
    g_auto_threshold = GetPrivateProfileIntW(L"Settings", L"auto_threshold", 80, path);
    int interval_min = GetPrivateProfileIntW(L"Settings", L"auto_interval_min", 10, path);
    g_auto_aggressive= GetPrivateProfileIntW(L"Settings", L"auto_aggressive",  1, path);

    if (g_auto_threshold < 1)   g_auto_threshold = 1;
    if (g_auto_threshold > 99)  g_auto_threshold = 99;
    if (interval_min < 1)       interval_min = 1;
    if (interval_min > 1440)    interval_min = 1440;
    g_auto_interval = interval_min * 60000;
}

static void save_config(void) {
    wchar_t path[MAX_PATH];
    get_ini_path(path, _countof(path));

    wchar_t buf[16];
    swprintf_s(buf, _countof(buf), L"%d", g_auto_enabled);
    WritePrivateProfileStringW(L"Settings", L"auto_enabled", buf, path);

    swprintf_s(buf, _countof(buf), L"%d", g_auto_threshold);
    WritePrivateProfileStringW(L"Settings", L"auto_threshold", buf, path);

    swprintf_s(buf, _countof(buf), L"%d", g_auto_interval / 60000);
    WritePrivateProfileStringW(L"Settings", L"auto_interval_min", buf, path);

    swprintf_s(buf, _countof(buf), L"%d", g_auto_aggressive);
    WritePrivateProfileStringW(L"Settings", L"auto_aggressive", buf, path);
}

/* allow_risky: TRUE 用于手动清理（允许全部区域，步间延迟降低风险）；
   FALSE 用于后台自动清理（剔除主 standby 列表，因反复自动触发风险累积）。 */
static ULONG safe_mask(ULONG requested, int allow_risky) {
    if (allow_risky)
        return requested;
    /* 自动清理：仅剔除主 standby-list（最高风险项，体积最大）。
       system-file-cache / standby-low / registry / combine
       在 150ms 步间延迟下属于安全操作。 */
    return requested & ~R_STANDBY_LIST;
}

/* ---------- 工具函数 ---------- */

/* 日志：把诊断信息写入 exe 同目录的 memopt.log（追加，带时间戳）。
   由于使用 -mwindows(GUI 子系统) 无控制台，printf 不可见，统一走日志。 */
static wchar_t g_log_path[MAX_PATH] = {0};
static BOOL   g_log_inited = FALSE;

static void log_init(void) {
    if (g_log_inited) return;
    /* 获取 exe 所在目录，日志文件放在旁边 */
    GetModuleFileNameW(NULL, g_log_path, MAX_PATH);
    wchar_t *slash = wcsrchr(g_log_path, L'\\');
    if (slash) {
        wcscpy_s(slash + 1, MAX_PATH - (size_t)(slash + 1 - g_log_path), L"memopt.log");
    } else {
        wcscpy_s(g_log_path, MAX_PATH, L"memopt.log");
    }

    /* 日志轮转：超过 512KB 时把旧日志归档为 memopt.log.old 并重新开始，
       防止长时间运行日志无限膨胀（自动清理每 10 分钟一次，每次 4~6 行）。 */
    {
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (GetFileAttributesExW(g_log_path, GetFileExInfoStandard, &fad)
            && fad.nFileSizeHigh == 0
            && fad.nFileSizeLow > 512 * 1024) {
            wchar_t old_path[MAX_PATH];
            wcscpy_s(old_path, _countof(old_path), g_log_path);
            wchar_t *dot = wcsstr(old_path, L".log");
            if (dot) wcscpy_s(dot, _countof(old_path) - (size_t)(dot - old_path), L".log.old");
            DeleteFileW(old_path);
            MoveFileW(g_log_path, old_path);
        }
    }
    g_log_inited = TRUE;
}

static void log_msg(const wchar_t *fmt, ...) {
    log_init();
    WCHAR buf[1024];
    SYSTEMTIME st;
    GetLocalTime(&st);
    va_list ap;
    va_start(ap, fmt);
    _vsnwprintf_s(buf, _countof(buf), _TRUNCATE, fmt, ap);
    va_end(ap);

    FILE *f = NULL;
    if (_wfopen_s(&f, g_log_path, L"a, ccs=UTF-8") == 0 && f) {
        /* 文件以 ccs=UTF-8 打开后是宽字符定向流；本工具链(msvcrt)
           的 fwprintf 中 %s 按窄字符串解析，会把 wchar_t* 当 char*
           读出乱码/截断，所以字符串参数必须用 %ls。 */
        fwprintf(f, L"[%02d-%02d %02d:%02d:%02d] %ls\n",
                 st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, buf);
        fclose(f);
    }
}

static BOOL enable_privilege(const wchar_t *name) {
    HANDLE token;
    TOKEN_PRIVILEGES tp = {0};
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return FALSE;
    if (!LookupPrivilegeValueW(NULL, name, &luid)) {
        CloseHandle(token);
        return FALSE;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(token);
    return ok;
}

static BOOL is_elevated(void) {
    HANDLE token;
    TOKEN_ELEVATION elev;
    DWORD size;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return FALSE;
    BOOL ok = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &size) && elev.TokenIsElevated;
    CloseHandle(token);
    return ok;
}

/* 无管理员权限时重新以 runas 方式启动自身，触发 UAC 提权。
   返回 TRUE 表示提权实例已启动，当前实例应退出；
   返回 FALSE 表示用户拒绝了 UAC，继续以当前权限运行。 */
static BOOL relaunch_elevated(int argc, wchar_t **argv) {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(NULL, exe, MAX_PATH);

    /* 重建命令行参数（逐个加引号，跳过 argv[0]） */
    wchar_t params[2048] = {0};
    size_t off = 0;
    for (int i = 1; i < argc && off < 1800; i++) {
        int n = swprintf(params + off, _countof(params) - off,
                         L"\"%ls\" ", argv[i]);
        if (n < 0) break;
        off += (size_t)n;
    }

    SHELLEXECUTEINFOW sei = {0};
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";                 /* 触发 UAC */
    sei.lpFile = exe;
    sei.lpParameters = params[0] ? params : NULL;
    sei.nShow = SW_SHOWNORMAL;
    if (!ShellExecuteExW(&sei))
        return FALSE;                       /* 用户点了"否" */
    if (sei.hProcess) CloseHandle(sei.hProcess);
    return TRUE;
}

/* ---------- 开机自启动（注册表 HKLM\...\Run） ---------- */

#define AUTOSTART_KEY  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run"
#define AUTOSTART_NAME L"MemOpt"

static BOOL autostart_enabled(void) {
    wchar_t val[MAX_PATH];
    DWORD sz = sizeof(val);
    return RegGetValueW(HKEY_LOCAL_MACHINE, AUTOSTART_KEY, AUTOSTART_NAME,
                        RRF_RT_REG_SZ, NULL, val, &sz) == ERROR_SUCCESS;
}

static void set_autostart(BOOL on) {
    if (on) {
        wchar_t exe[MAX_PATH], cmd[MAX_PATH + 8];
        GetModuleFileNameW(NULL, exe, MAX_PATH);
        swprintf(cmd, _countof(cmd), L"\"%ls\"", exe);
        RegSetKeyValueW(HKEY_LOCAL_MACHINE, AUTOSTART_KEY, AUTOSTART_NAME,
                        REG_SZ, cmd, (DWORD)((wcslen(cmd) + 1) * sizeof(wchar_t)));
    } else {
        RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, AUTOSTART_KEY, AUTOSTART_NAME);
    }
}

static MEMORYSTATUSEX mem_before, mem_after;
static PERFORMANCE_INFORMATION pi_before, pi_after;

static void snap_before(void) {
    mem_before.dwLength = sizeof(mem_before);
    GlobalMemoryStatusEx(&mem_before);
    pi_before.cb = sizeof(pi_before);
    GetPerformanceInfo(&pi_before, sizeof(pi_before));
}

static void snap_after(void) {
    mem_after.dwLength = sizeof(mem_after);
    GlobalMemoryStatusEx(&mem_after);
    pi_after.cb = sizeof(pi_after);
    GetPerformanceInfo(&pi_after, sizeof(pi_after));
}

static void flush_volume_cache(void) {
    /* 遍历所有固定卷并 FlushFileBuffers */
    DWORD drives = GetLogicalDrives();
    wchar_t vol[] = L"\\\\.\\C:";
    for (int i = 0; i < 26; i++) {
        if (!(drives & (1 << i))) continue;
        vol[4] = (wchar_t)('A' + i);
        HANDLE h = CreateFileW(vol, FILE_WRITE_DATA | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, NULL);
        if (h == INVALID_HANDLE_VALUE) continue;
        FlushFileBuffers(h);
        CloseHandle(h);
    }
}

static void empty_all_workingsets(void) {
    DWORD pids[4096], needed;
    if (!EnumProcesses(pids, sizeof(pids), &needed)) return;
    DWORD count = needed / sizeof(DWORD);
    for (DWORD i = 0; i < count; i++) {
        if (pids[i] == 0) continue;
        HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_QUOTA
                               | PROCESS_VM_OPERATION, FALSE, pids[i]);
        if (h) {
            /* SetProcessWorkingSetSize(h, -1, -1) 强制让内核立即裁剪
               该进程的工作集（把页先移到 standby/modified 列表）。
               然后调用 EmptyWorkingSet(h) 再扫一遍，释放效果翻倍，
               这是 memreduct / RAMMap 都用的组合。 */
            SetProcessWorkingSetSize(h, (SIZE_T)-1, (SIZE_T)-1);
            EmptyWorkingSet(h);
            CloseHandle(h);
        }
    }
}

/* log_msg 正文统一走宽字符，调用点一律传 L"..." 字面量 */

/* ---------- 核心清理 ---------- */

/* 步间延迟(ms)：在多次内核内存列表调用之间插入缓冲，让内核有时间
   完成页面操作。memreduct 使用 0ms 但 Win11 24H2 会触发 0xF7 栈溢出，
   150ms 是经过测试的最佳平衡点——足够让内核栈恢复，同时不给 Windows
   太多时间重新填充缓存，释放效果接近 memreduct。 */
#define CLEAN_STEP_DELAY_MS 150

/* NTSTATUS 常见错误码 → 可读中文说明（日志里不再只是一串十六进制，
   用户能一眼看出是权限问题还是系统不支持）。 */
static const wchar_t *ntstatus_text(NTSTATUS st) {
    switch ((ULONG)st) {
    case 0xC0000061: return L"权限不足(STATUS_PRIVILEGE_NOT_HELD)";
    case 0xC0000022: return L"拒绝访问(STATUS_ACCESS_DENIED)";
    case 0xC0000003: return L"本系统不支持该清理项(STATUS_INVALID_INFO_CLASS)";
    case 0xC0000004: return L"参数长度不符(STATUS_INFO_LENGTH_MISMATCH)";
    case 0xC0000005: return L"访问冲突(STATUS_ACCESS_VIOLATION)";
    case 0xC000000D: return L"参数无效(STATUS_INVALID_PARAMETER)";
    case 0xC00000BB: return L"不支持该操作(STATUS_NOT_SUPPORTED)";
    default:         return L"";
    }
}

/* 分阶段执行单个内存列表命令，并在两次调用间留出缓冲。
   返回 FALSE 表示该步失败(不中断后续)。 */
static void do_clean_step(SYSTEM_MEMORY_LIST_COMMAND c, const wchar_t *label, NTSTATUS *last_st) {
    NTSTATUS st = g_NtSetSystemInformation(SystemMemoryListInformation, &c, sizeof(c));
    if (last_st) *last_st = st;
    if (!NT_SUCCESS(st))
        log_msg(L"  [!] %ls: 0x%X(%ls)", label, (unsigned)st, ntstatus_text(st));
    Sleep(CLEAN_STEP_DELAY_MS);   /* 给内核缓冲，避免连续调用挤压 */
}

/* allow_risky:
     TRUE  -> 手动/命令行清理，允许全部区域(释放量大)，150ms 步间延迟降风险
     FALSE -> 后台自动清理，剔除主 standby 列表(反复触发风险累积) */
static void do_clean(ULONG mask, int allow_risky) {
    NTSTATUS st = 0;   /* STATUS_SUCCESS */
    SYSTEM_MEMORY_LIST_COMMAND cmd;
    SYSTEM_FILECACHE_INFORMATION sfci = {0};
    MEMORY_COMBINE_INFORMATION_EX combine = {0};

    /* 互斥/重入保护：清理进行中则直接返回，避免内核调用重叠 */
    if (CLEAN_LOCK_TRY() != 0) {
        log_msg(L"  [!] a cleanup is already running, skipped");
        return;
    }

    /* 若 Native API 未成功解析：降级为逐进程 EmptyWorkingSet，
       只能清工作集，但总比完全不清强 */
    if (!g_NtSetSystemInformation) {
        log_msg(L"  [!] NtSetSystemInformation unavailable, fallback to per-process EmptyWorkingSet");
        snap_before();
        empty_all_workingsets();
        snap_after();
        CLEAN_UNLOCK();
        return;
    }

    /* 安全闸门：allow_risky=FALSE 时剔除主 standby 列表 */
    ULONG safe = safe_mask(mask, allow_risky);
    if ((mask & ~safe) != 0) {
        log_msg(L"  [safe] high-risk regions disabled (auto-clean conservative)");
    }
    mask = safe;
    if (mask == 0) {
        log_msg(L"  [!] no safe region to clean on this OS, skipped");
        CLEAN_UNLOCK();
        return;
    }

    /* 启用清理所需特权（一次性，覆盖 working-set / modified-list 等）。
       注意：新版系统特权名是 SeProfileSingleProcessPrivilege，
       旧名 SeProfSingleProcessPrivilege 可能无法解析，导致清理静默失败。 */
    if (!enable_privilege(L"SeIncreaseQuotaPrivilege"))
        log_msg(L"  [!] failed to enable SeIncreaseQuotaPrivilege");
    if (!enable_privilege(L"SeProfileSingleProcessPrivilege")
        && !enable_privilege(L"SeProfSingleProcessPrivilege"))
        log_msg(L"  [!] failed to enable SeProfileSingleProcessPrivilege");

    snap_before();

    /* ---- 第一阶段：安全操作(工作集、文件缓存、修改页列表) ---- */
    if (mask & R_WORKING_SET) {
        cmd = MemoryEmptyWorkingSets;
        do_clean_step(cmd, L"working-set", &st);
        /* Native API 之外，再逐个进程 SetProcessWorkingSetSize +
           EmptyWorkingSet 收尾。memreduct 这样做释放量增加 15~30%。 */
        empty_all_workingsets();
    }

    if (mask & R_SYSTEM_FILE_CACHE) {
        /* Win10/11 上 SystemFileCacheInformation 返回 STATUS_INVALID_PARAMETER
           (0xC0000004)，因为它是 Vista/Win7 遗留 API。必须使用
           SystemFileCacheInformationEx (0x7E) 才能正确裁剪文件缓存。
           策略：Win8+ (build >= 9200) 先试 Ex，失败回退老版本，
           Win7 及以下直接走老版本。 */
        if (os_build() >= 9200) {
            SYSTEM_FILECACHE_INFORMATION_EX sfcx = {0};
            sfcx.MinimumWorkingSet = MAXSIZE_T;
            sfcx.MaximumWorkingSet = MAXSIZE_T;
            st = g_NtSetSystemInformation(SystemFileCacheInformationEx,
                                          &sfcx, sizeof(sfcx));
            if (!NT_SUCCESS(st)) {
                /* 回退到老版本 API */
                SYSTEM_FILECACHE_INFORMATION sfci_old = {0};
                sfci_old.MinimumWorkingSet = MAXSIZE_T;
                sfci_old.MaximumWorkingSet = MAXSIZE_T;
                NTSTATUS st2 = g_NtSetSystemInformation(SystemFileCacheInformation,
                    &sfci_old, sizeof(sfci_old));
                if (!NT_SUCCESS(st2))
                    log_msg(L"  [!] system-file-cache: Ex=0x%X(%ls), Legacy=0x%X(%ls)",
                            (unsigned)st, ntstatus_text(st),
                            (unsigned)st2, ntstatus_text(st2));
            }
        } else {
            sfci.MinimumWorkingSet = MAXSIZE_T;
            sfci.MaximumWorkingSet = MAXSIZE_T;
            st = g_NtSetSystemInformation(SystemFileCacheInformation,
                                          &sfci, sizeof(sfci));
            if (!NT_SUCCESS(st))
                log_msg(L"  [!] system-file-cache: 0x%X(%ls)", (unsigned)st, ntstatus_text(st));
        }
        Sleep(CLEAN_STEP_DELAY_MS);
    }

    if (mask & R_MODIFIED_FILE)
        flush_volume_cache();

    if (mask & R_MODIFIED_LIST) {
        cmd = MemoryFlushModifiedList;
        do_clean_step(cmd, L"modified-list", &st);
    }

    /* ---- 第二阶段：内存列表(standby) 清理。先清主 standby 列表
       (大面积释放)，再用低优先级 standby 收尾，与 memreduct 一致。
       步间 150ms 延迟已提供充足保护。 ---- */
    if (mask & R_STANDBY_LIST) {
        cmd = MemoryPurgeStandbyList;
        do_clean_step(cmd, L"standby-list", &st);
    }

    if (mask & R_STANDBY_LOW) {
        cmd = MemoryPurgeLowPriorityStandbyList;
        do_clean_step(cmd, L"standby-list-low", &st);
    }

    /* ---- 第三阶段：注册表 / 合并页(win8.1+ / win10+) ---- */
    if (mask & R_REGISTRY_CACHE) {
        if (os_build() < 9600) { /* Win8.1 */
            log_msg(L"  [!] registry-cache needs Windows 8.1+");
        } else {
            st = g_NtSetSystemInformation(SystemRegistryReconciliationInformation, NULL, 0);
            if (!NT_SUCCESS(st)) log_msg(L"  [!] registry-cache: 0x%X(%ls)", (unsigned)st, ntstatus_text(st));
            Sleep(CLEAN_STEP_DELAY_MS);
        }
    }

    if (mask & R_COMBINE_LISTS) {
        if (os_build() < 10240) { /* Win10 */
            log_msg(L"  [!] combine-memory-lists needs Windows 10+");
        } else {
            combine.Flags = 1; /* COMBINE_FLAGS_ALL */
            st = g_NtSetSystemInformation(SystemCombinePhysicalMemoryInformation, &combine, sizeof(combine));
            if (!NT_SUCCESS(st)) log_msg(L"  [!] combine-memory-lists: 0x%X(%ls)", (unsigned)st, ntstatus_text(st));
        }
    }

    snap_after();

    CLEAN_UNLOCK();
}

static ULONG64 bytes_freed(void) {
    /* 释放量：优先使用 GlobalMemoryStatusEx 的 used_bytes 差值，
       与 memreduct 一致，用户感知的"内存减少量"更大。
       used_bytes = TotalPhys - AvailPhys，
       差值 = avail_after - avail_before（数学等价）。
       同时用 PhysicalAvailable 交叉验证内核视角。
       若两者都无效(统计失败)，返回 0。 */
    ULONG64 via_gms = 0, via_pi = 0;

    /* 主口径：GlobalMemoryStatusEx（与 memreduct / 任务管理器对齐） */
    if (mem_before.dwLength == sizeof(mem_before) && mem_after.dwLength == sizeof(mem_after)) {
        if (mem_after.ullAvailPhys > mem_before.ullAvailPhys)
            via_gms = mem_after.ullAvailPhys - mem_before.ullAvailPhys;
    }

    /* 交叉验证：GetPerformanceInfo.PhysicalAvailable（内核视角，
       standby 页面被视为"已用"，因此清理 standby 后此值会明显增加） */
    if (pi_before.cb == sizeof(pi_before) && pi_after.cb == sizeof(pi_after)
        && pi_before.PageSize && pi_after.PageSize) {
        ULONG64 page = (ULONG64)pi_after.PageSize;
        ULONG64 avail_before = (ULONG64)pi_before.PhysicalAvailable * page;
        ULONG64 avail_after  = (ULONG64)pi_after.PhysicalAvailable * page;
        if (avail_after > avail_before)
            via_pi = avail_after - avail_before;
    }

    /* 返回两者中的较大值（更接近真实释放量） */
    return (via_gms > via_pi) ? via_gms : via_pi;
}

/* ---------- 命令行解析 ---------- */

static int region_name_to_mask(const wchar_t *s) {
    if (!_wcsicmp(s, L"working-set") || !_wcsicmp(s, L"workingset")) return R_WORKING_SET;
    if (!_wcsicmp(s, L"system-file-cache") || !_wcsicmp(s, L"systemfilecache")) return R_SYSTEM_FILE_CACHE;
    if (!_wcsicmp(s, L"modified-file-cache") || !_wcsicmp(s, L"modifiedfilecache")) return R_MODIFIED_FILE;
    if (!_wcsicmp(s, L"modified-list") || !_wcsicmp(s, L"modifiedlist")) return R_MODIFIED_LIST;
    if (!_wcsicmp(s, L"standby-list") || !_wcsicmp(s, L"standbylist")) return R_STANDBY_LIST;
    if (!_wcsicmp(s, L"standby-list-low") || !_wcsicmp(s, L"standbylistlow")) return R_STANDBY_LOW;
    if (!_wcsicmp(s, L"registry-cache") || !_wcsicmp(s, L"registrycache")) return R_REGISTRY_CACHE;
    if (!_wcsicmp(s, L"combine-memory-lists") || !_wcsicmp(s, L"combinememorylists")) return R_COMBINE_LISTS;
    return 0;
}

static ULONG parse_args(int argc, wchar_t **argv) {
    if (argc < 2)
        return (ULONG)-1; /* 进入 GUI */

    /* 首参数支持 "clean" 与 "clean:full" 两种形式（后者直接等价于 clean full） */
    int is_clean_full = !_wcsicmp(argv[1], L"clean:full");
    if (!_wcsicmp(argv[1], L"clean") || is_clean_full) {
        ULONG mask = is_clean_full ? R_ALL_OLD : 0;
        for (int i = 2; i < argc; i++) {
            if (!_wcsicmp(argv[i], L"full") || wcsstr(argv[i], L":full")) {
                mask = R_ALL_OLD;
                continue;
            }
            ULONG m = region_name_to_mask(argv[i]);
            if (m) mask |= m;
            else if (argv[i][0] != ':')
                log_msg(L"  [ignore unknown region] %ls", argv[i]);
        }
        return mask ? mask : R_DEFAULT;
    }

    if (!_wcsicmp(argv[1], L"help") || !_wcsicmp(argv[1], L"-h") || !_wcsicmp(argv[1], L"/?")) {
        /* GUI 子系统(-mwindows)无控制台，printf 不可见，改用 MessageBox */
        MessageBoxW(NULL,
            L"MemOpt 用法:\n"
            L"  memopt.exe                     图形界面\n"
            L"  memopt.exe clean               清理默认区域\n"
            L"  memopt.exe clean:full          清理全部区域\n"
            L"  memopt.exe clean <区域...>     指定区域，例如:\n"
            L"      memopt.exe clean standby-list working-set",
            L"MemOpt 用法", MB_OK | MB_ICONINFORMATION);
        return (ULONG)-2; /* 退出 */
    }
    return (ULONG)-2;
}

/* ---------- GUI ---------- */

/* ===== 控件 ID (主窗口) ===== */
#define ID_BTN_CLEAN      1      /* 主按钮：立即清理 */
#define ID_BTN_SETTINGS   2      /* 副按钮：设置 (打开弹窗) */
#define ID_TXT_STATUS     6      /* 状态卡文字 */
#define ID_TRAY_SHOW      10     /* 托盘菜单：显示/隐藏主窗口 */
#define ID_TRAY_EXIT      11     /* 托盘菜单：退出程序 */

/* 图标资源 ID（与 memopt.rc 中的 IDI_MEMOPT 对应） */
#ifndef IDI_MEMOPT
#define IDI_MEMOPT 101
#endif

/* 三张竖排的内存指标卡片（容纳整张卡的 SS_CENTER STATIC） */
#define ID_CARD_TOTAL     13
#define ID_CARD_PAGE      14
#define ID_CARD_SYSWS     15

/* ===== 控件 ID (设置弹窗，全部为自定义绘制) ===== */
#define S_ID_CHK_AUTO        200    /* 后台自动清理 (复选框) */
#define S_ID_CHK_AUTOSTART   201    /* 开机自启动 (复选框) */
#define S_ID_SPIN_THRESH      202    /* 清理阈值数字框 (含 ▲▼) */
#define S_ID_CHK_AGGRO       203    /* 强力模式 (复选框) */
#define S_ID_BTN_MORE        204    /* 释放更多 (蓝色说明按钮) */
#define S_ID_SPIN_INTERVAL   205    /* 清理间隔数字框 (含 ▲▼) */
#define S_ID_BTN_OK          206    /* 设置窗口保存 */
#define S_ID_BTN_CANCEL      207    /* 设置窗口取消 */
#define S_ID_TXT_INFO        208    /* 释放更多说明文本 */
#define S_ID_LBL_THRESH      209    /* "清理阈值" 文本 */
#define S_ID_LBL_INTERVAL    210    /* "清理间隔" 文本 */

/* UI 字体（在 init_ui_res 中创建） */
HFONT  g_font_ui;
HFONT  g_font_big;
HFONT  g_font_small;
HFONT  g_font_mid;

/* 自定义设置控件的运行时状态 */
typedef struct {
    int checked;     /* 复选框：1=勾选, 0=未勾选 */
    int value;       /* 数字调节器当前值 */
    int value_min;
    int value_max;
    int pressing;    /* 数字调节器 ▲/▼ 哪个被按下：1=up, -1=down, 0=none */
} S_State;
static S_State g_s_auto        = {0, 0, 0, 0, 0};
static S_State g_s_autostart   = {0, 0, 0, 0, 0};
static S_State g_s_thresh      = {0, 80,  50, 99, 0};
static S_State g_s_aggro       = {1, 0, 0, 0, 0};
static S_State g_s_interval    = {0, 10,  1,  120, 0};
static BOOL    g_bspinner_down; /* 正在按住 spin 的下箭头 */
static int     g_s_btn_hover = 0; /* 设置窗口标题栏按钮 hover */

/* 蓝色：用于复选框、强力模式、释放更多文字 */
static const COLORREF COL_BLUE_DARK  = RGB(22, 119, 255);   /* UI_ACCENT */
static const COLORREF COL_BLUE_HOVER = RGB(19, 100, 220);   /* hover 深蓝 */
static const COLORREF COL_BLUE_LIGHT = RGB(234, 242, 255);  /* 胶囊按钮淡底 */
static const COLORREF COL_BORDER     = RGB(223, 227, 235);  /* 组件边框 */
static const COLORREF COL_TEXT_DIM   = RGB(138, 149, 168);  /* 次文字 */
static const COLORREF COL_TEXT_MAIN  = RGB(42, 50, 68);     /* 主文字 */
static const COLORREF COL_BG         = RGB(248, 249, 251);  /* 底（与 UI_BG 一致） */
static const COLORREF COL_BG_CARD    = RGB(255, 255, 255);  /* 组件白底 */

/* 绘制复选框 + 标签：圆角方块 + 勾选标记 + 文字
   设计稿风格：16×16 方框、勾选时全蓝底+白勾、hover 边框蓝。 */
static void draw_custom_checkbox(HDC hdc, RECT *rcCtrl, const wchar_t *label,
                                 BOOL checked, BOOL hover) {
    int box = 16;
    int cy = (rcCtrl->top + rcCtrl->bottom) / 2;
    RECT rcBox = { rcCtrl->left, cy - box/2, rcCtrl->left + box, cy + box/2 };

    COLORREF fill = checked ? COL_BLUE_DARK : COL_BG_CARD;
    COLORREF border = checked ? COL_BLUE_DARK
                              : (hover ? COL_BLUE_DARK : COL_BORDER);

    /* 填充 + 边框（圆角 4px） */
    HBRUSH brF = CreateSolidBrush(fill);
    HPEN pnB = CreatePen(PS_SOLID, (checked ? 1 : 1), border);
    HGDIOBJ ob = SelectObject(hdc, brF);
    HGDIOBJ op = SelectObject(hdc, pnB);
    RoundRect(hdc, rcBox.left, rcBox.top, rcBox.right, rcBox.bottom, 4, 4);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brF);
    DeleteObject(pnB);

    /* 勾选标记 —— 白勾 (两条线) */
    if (checked) {
        HPEN pnChk = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
        HGDIOBJ op2 = SelectObject(hdc, pnChk);
        int m = rcBox.left + 4, t = rcBox.top + box/2;
        MoveToEx(hdc, m, t + 2, NULL);
        LineTo(hdc, m + 3, t + 5);
        LineTo(hdc, m + 9, t - 3);
        SelectObject(hdc, op2);
        DeleteObject(pnChk);
    }

    /* 文字（中号，与设计稿一致） */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, COL_TEXT_MAIN);
    SelectObject(hdc, g_font_ui);
    RECT rcTxt = { rcBox.right + 10, rcCtrl->top, rcCtrl->right, rcCtrl->bottom };
    DrawTextW(hdc, label, -1, &rcTxt,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER);
}

/* 绘制数字调节器：白底圆角 + 数字 + 右竖条 ▲▼
   设计稿风格：白底灰边、悬停蓝边+光晕、右竖 22px 分两半箭头。 */
static void draw_custom_spinner(HDC hdc, RECT *rcCtrl, int value,
                                int pressing) {
    /* 外框：白底浅灰边，圆角 6px；按压时蓝边高亮，给用户清晰反馈。 */
    HBRUSH brF = CreateSolidBrush(COL_BG_CARD);
    HPEN pnB = CreatePen(PS_SOLID, 1, pressing ? COL_BLUE_DARK : COL_BORDER);
    HGDIOBJ ob = SelectObject(hdc, brF);
    HGDIOBJ op = SelectObject(hdc, pnB);
    RoundRect(hdc, rcCtrl->left, rcCtrl->top, rcCtrl->right, rcCtrl->bottom, 6, 6);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brF);
    DeleteObject(pnB);

    /* 右竖条（22px 宽，分上下两半，配 1px 中线分隔） */
    int arrows_w = 22;
    int ax = rcCtrl->right - arrows_w;
    int aTop = rcCtrl->top;
    int aBot = rcCtrl->bottom;
    int aMid = (aTop + aBot) / 2;

    /* 竖条分隔线（左）：用比外框更淡的颜色，避免右侧箭头区看起来太重 */
    HPEN pnSep = CreatePen(PS_SOLID, 1, RGB(238, 240, 244));
    HGDIOBJ oS = SelectObject(hdc, pnSep);
    MoveToEx(hdc, ax, aTop + 4, NULL);
    LineTo(hdc, ax, aBot - 4);
    /* 上下中线 */
    MoveToEx(hdc, ax, aMid, NULL);
    LineTo(hdc, ax + arrows_w, aMid);
    SelectObject(hdc, oS); DeleteObject(pnSep);

    /* 数字由 spinner 内嵌的 EDIT 子控件负责渲染（可键盘输入）。
       这里不再画数字文字，避免和 EDIT 内文字叠加出现双影/重绘。
       value 参数保留（签名兼容）。 */
    UNREFERENCED_PARAMETER(value);

    /* ▲▼ 用小号字体，避免大三角形抢走视觉重心 */
    SetBkMode(hdc, TRANSPARENT);
    SelectObject(hdc, g_font_small);
    SetTextColor(hdc, pressing ==  1 ? COL_BLUE_DARK : COL_TEXT_DIM);
    RECT rcUp = { ax, aTop, ax + arrows_w, aMid };
    DrawTextW(hdc, L"\x25B2", -1, &rcUp, DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    SetTextColor(hdc, pressing == -1 ? COL_BLUE_DARK : COL_TEXT_DIM);
    RECT rcDn = { ax, aMid, ax + arrows_w, aBot };
    DrawTextW(hdc, L"\x25BC", -1, &rcDn, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
}

/* 绘制蓝色文字按钮（圆角胶囊）：设计稿 "释放更多 ›" 风格，
   蓝底蓝字，右侧 › 箭头指向，圆角 6px。 */
static void draw_pill_button(HDC hdc, RECT *rc, const wchar_t *text, BOOL hover) {
    COLORREF bg = hover ? RGB(218, 232, 255) : COL_BLUE_LIGHT;
    COLORREF fg = COL_BLUE_DARK;
    HBRUSH br = CreateSolidBrush(bg);
    HPEN   pn = CreatePen(PS_SOLID, 1, bg);
    HGDIOBJ ob = SelectObject(hdc, br);
    HGDIOBJ op = SelectObject(hdc, pn);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 6, 6);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(br);
    DeleteObject(pn);

    /* 文字 + 右侧 › 箭头 */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    SelectObject(hdc, g_font_small);
    wchar_t with_arrow[64];
    swprintf_s(with_arrow, _countof(with_arrow), L"%ls \x203A", text); /* › */
    DrawTextW(hdc, with_arrow, -1, rc, DT_CENTER | DT_SINGLELINE | DT_VCENTER);
}

/* 给定鼠标坐标是否在 ▲（top half）或 ▼（bottom half） */
static int spinner_hit(HWND hSpin, LPARAM lp) {
    int x = (int)(short)LOWORD(lp), y = (int)(short)HIWORD(lp);
    RECT rc; GetClientRect(hSpin, &rc);
    int mid = (rc.top + rc.bottom) / 2;
    if (y < mid) return  1;   /* 上半 = ▲ */
    if (y > mid) return -1;   /* 下半 = ▼ */
    return 0;
}

/* -------- 前置声明 + 全局（spinner 内嵌 EDIT）--------
   必须先放在 SettingsSubclassProc 之前，否则里面调用 sync_spinner_edit()
   会被 gcc 报 implicit declaration → conflicting types。 */
static HWND g_hSpinEditThresh;
static HWND g_hSpinEditInterval;

static void sync_spinner_edit(HWND hSpin);
static BOOL spin_apply_edit_text(HWND hedit, S_State *st);
static LRESULT CALLBACK SpinEditSubclassProc(HWND hEdit, UINT msg, WPARAM wp,
    LPARAM lp, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
static HWND create_edit_inside_spinner(HWND hSpin, UINT idKind, int initial_val);
static void create_spinner_edits(HWND dlg);
static void release_spinner_edits(void);
static void gui_refresh_status(void);
static DWORD WINAPI clean_worker(LPVOID param);

/* 设置窗口绘图：拦截所有子控件的 WM_PAINT，转给我们的绘制函数 */
static void settings_draw_all(HWND dlg) {
    InvalidateRect(dlg, NULL, TRUE);
}

/* 子控件子类化：根据控件 ID 自绘复选框 / 数字调节器 */
static LRESULT CALLBACK SettingsSubclassProc(
    HWND hCtrl, UINT msg, WPARAM wp, LPARAM lp,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
    int cid = GetDlgCtrlID(hCtrl);
    if (msg == WM_PAINT) {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hCtrl, &ps);
        RECT rc; GetClientRect(hCtrl, &rc);
        /* 用普通画刷清背景（COL_BG）防止字体反色 */
        HBRUSH br = CreateSolidBrush(COL_BG);
        FillRect(hdc, &rc, br);
        DeleteObject(br);

        switch (cid) {
        case S_ID_CHK_AUTO:
            draw_custom_checkbox(hdc, &rc, L"后台自动清理",
                                 g_s_auto.checked, FALSE);
            break;
        case S_ID_CHK_AUTOSTART:
            draw_custom_checkbox(hdc, &rc, L"开机自启动",
                                 g_s_autostart.checked, FALSE);
            break;
        case S_ID_CHK_AGGRO:
            draw_custom_checkbox(hdc, &rc, L"强力模式",
                                 g_s_aggro.checked, FALSE);
            break;
        case S_ID_SPIN_THRESH:
            draw_custom_spinner(hdc, &rc,
                                g_s_thresh.value, g_s_thresh.pressing);
            break;
        case S_ID_SPIN_INTERVAL:
            draw_custom_spinner(hdc, &rc,
                                g_s_interval.value, g_s_interval.pressing);
            break;
        }
        EndPaint(hCtrl, &ps);
        return 0;
    }
    if (msg == WM_SETCURSOR) {
        SetCursor(LoadCursorW(NULL, (LPCWSTR)IDC_HAND));
        return TRUE;
    }
    
    /* 拦截鼠标点击事件：
       由于子类化(Subclassing)阻断了 SS_NOTIFY 的反射机制，
       父窗口 SettingsProc 无法收到子控件的 WM_LBUTTONDOWN，
       因此必须在此处处理点击逻辑。
       注意：lp 在子类过程里是【控件局部坐标】，spinner_hit
       用 GetClientRect(hCtrl) 比较的也是局部坐标，二者一致。
       uIdSubclass 是在 SetWindowSubclass 时传入的控件 ID。 */
    if (msg == WM_LBUTTONDOWN) {
        int cid = (int)uIdSubclass;
        HWND dlg = GetParent(hCtrl);
        switch (cid) {
        case S_ID_CHK_AUTO:
            g_s_auto.checked = !g_s_auto.checked;
            g_auto_enabled = g_s_auto.checked;
            save_config();
            InvalidateRect(hCtrl, NULL, TRUE);
            gui_refresh_status();
            return 0;
        case S_ID_CHK_AUTOSTART:
            g_s_autostart.checked = !g_s_autostart.checked;
            InvalidateRect(hCtrl, NULL, TRUE);
            return 0;
        case S_ID_CHK_AGGRO:
            g_s_aggro.checked = !g_s_aggro.checked;
            g_auto_aggressive = g_s_aggro.checked;
            save_config();
            InvalidateRect(hCtrl, NULL, TRUE);
            gui_refresh_status();
            return 0;
        case S_ID_SPIN_THRESH: {
            int dir = spinner_hit(hCtrl, lp);
            S_State *st = &g_s_thresh;
            if (dir ==  1 && st->value < st->value_max) st->value++;
            if (dir == -1 && st->value > st->value_min) st->value--;
            st->pressing = dir;
            g_auto_threshold = st->value;
            SetTimer(dlg, 1, 50, NULL);   /* 长按加速 */
            sync_spinner_edit(hCtrl);     /* 新值同步写入内嵌 EDIT */
            InvalidateRect(hCtrl, NULL, TRUE);
            gui_refresh_status();
            return 0;
        }
        case S_ID_SPIN_INTERVAL: {
            int dir = spinner_hit(hCtrl, lp);
            S_State *st = &g_s_interval;
            if (dir ==  1 && st->value < st->value_max) st->value++;
            if (dir == -1 && st->value > st->value_min) st->value--;
            st->pressing = dir;
            g_auto_interval = st->value * 60000;
            SetTimer(dlg, 2, 50, NULL);
            sync_spinner_edit(hCtrl);
            InvalidateRect(hCtrl, NULL, TRUE);
            gui_refresh_status();
            return 0;
        }
        }
        /* 未知控件：放行，避免误吞消息 */
        return DefSubclassProc(hCtrl, msg, wp, lp);
    }

    /* spinner 长按结束：在子类过程里清理 timer 与 pressing 状态。
       鼠标在 spinner 上释放时，WM_LBUTTONUP 发给 spinner HWND
       而非父窗口，故必须在此处理，否则长按加速 timer 不会停止。 */
    if (msg == WM_LBUTTONUP) {
        int cid = (int)uIdSubclass;
        if (cid == S_ID_SPIN_THRESH || cid == S_ID_SPIN_INTERVAL) {
            HWND dlg = GetParent(hCtrl);
            KillTimer(dlg, 1);
            KillTimer(dlg, 2);
            g_s_thresh.pressing   = 0;
            g_s_interval.pressing = 0;
            InvalidateRect(hCtrl, NULL, TRUE);
            return 0;
        }
    }

    /* EDIT 背景/文字着色：让内嵌数字输入框与 spinner 白底融为一体，
       同时去掉默认白色背景与黑色文字的突兀感。 */
    if (msg == WM_CTLCOLOREDIT) {
        HWND hedit = (HWND)lp;
        if (hedit == g_hSpinEditThresh || hedit == g_hSpinEditInterval) {
            SetBkColor((HDC)wp, COL_BG_CARD);
            SetTextColor((HDC)wp, COL_TEXT_MAIN);
            static HBRUSH br = NULL;
            if (!br) br = CreateSolidBrush(COL_BG_CARD);
            return (LRESULT)br;
        }
    }

    return DefSubclassProc(hCtrl, msg, wp, lp);
}

/* 在 WM_CREATE 末尾调用：子类化所有自定义 STATIC */
static void subclass_custom_controls(HWND dlg) {
    int ids[] = {
        S_ID_CHK_AUTO, S_ID_CHK_AUTOSTART, S_ID_CHK_AGGRO,
        S_ID_SPIN_THRESH, S_ID_SPIN_INTERVAL
    };
    for (int i = 0; i < (int)(sizeof(ids)/sizeof(ids[0])); i++) {
        HWND h = GetDlgItem(dlg, ids[i]);
        if (h) SetWindowSubclass(h, SettingsSubclassProc, ids[i], 0);
    }
}

/* --------------- spinner EDIT 子控件（可键盘键入阈值/分钟数）--------------- */

/* 把当前 g_s_*.value 同步写回 EDIT 文本（spinner +/- 点、timer 长按后调用） */
static void sync_spinner_edit(HWND hSpin) {
    int cid = GetDlgCtrlID(hSpin);
    HWND hedit = (cid == S_ID_SPIN_THRESH) ? g_hSpinEditThresh : g_hSpinEditInterval;
    if (!hedit) return;
    S_State *st = (cid == S_ID_SPIN_THRESH) ? &g_s_thresh : &g_s_interval;
    wchar_t buf[16];
    swprintf_s(buf, _countof(buf), L"%d", st->value);
    SetWindowTextW(hedit, buf);
    /* 光标放到末尾，便于用户继续键入 */
    SendMessageW(hedit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
}

/* 读取 EDIT 文本 → 转 int → clamp 到 [min,max] → 写回 g_s_*
   返回 TRUE 表示值有改动（调用方需要重绘 spinner 写回全局等） */
static BOOL spin_apply_edit_text(HWND hedit, S_State *st) {
    if (!hedit || !st) return FALSE;
    int len = GetWindowTextLengthW(hedit);
    if (len <= 0 || len > 10) {
        /* 空或过长：恢复原值 */
        sync_spinner_edit(GetParent(hedit));
        return FALSE;
    }
    wchar_t buf[24];
    GetWindowTextW(hedit, buf, _countof(buf));
    int v = 0;
    BOOL any = FALSE;
    for (const wchar_t *p = buf; *p; p++) {
        if (*p >= L'0' && *p <= L'9') {
            v = v * 10 + (int)(*p - L'0');
            any = TRUE;
        }
    }
    if (!any) { sync_spinner_edit(GetParent(hedit)); return FALSE; }
    if      (v < st->value_min) v = st->value_min;
    else if (v > st->value_max) v = st->value_max;
    BOOL changed = (v != st->value);
    st->value = v;
    if (changed) {
        /* 写回显示，但不改变用户光标 —— 只在值确实被 clamp 或不同才刷 */
        wchar_t show[16];
        GetWindowTextW(hedit, show, _countof(show));
        wchar_t want[16];
        swprintf_s(want, _countof(want), L"%d", v);
        if (wcscmp(show, want) != 0) {
            SetWindowTextW(hedit, want);
            SendMessageW(hedit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
        }
    }
    return changed;
}

/* EDIT 子类过程：处理 VK_RETURN（存值+移焦）和 KILLFOCUS（存值）。
   uIdSubclass：1=阈值EDIT 2=间隔EDIT */
static LRESULT CALLBACK SpinEditSubclassProc(
    HWND hEdit, UINT msg, WPARAM wp, LPARAM lp,
    UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    S_State *st = (uIdSubclass == 1) ? &g_s_thresh : &g_s_interval;
    HWND hSpin = GetParent(hEdit);

    switch (msg) {
    case WM_KEYDOWN:
        if (wp == VK_RETURN) {
            int kind = (uIdSubclass == 1) ? 1 : 2;
            spin_apply_edit_text(hEdit, st);
            /* 同步到全局变量 */
            if (kind == 1) g_auto_threshold = st->value;
            else g_auto_interval = st->value * 60000;
            InvalidateRect(hSpin, NULL, TRUE);
            gui_refresh_status();
            HWND dlg = GetParent(hSpin);
            SetFocus(dlg);
            return 0;
        }
        /* VK_ESCAPE：还原原值 */
        if (wp == VK_ESCAPE) {
            sync_spinner_edit(hSpin);
            SetFocus(GetParent(hSpin));
            return 0;
        }
        break;

    case WM_KILLFOCUS:
        /* 失焦时应用值（点 OK、点别的控件都会触发） */
        {
            int kind = (uIdSubclass == 1) ? 1 : 2;
            spin_apply_edit_text(hEdit, st);
            if (kind == 1) g_auto_threshold = st->value;
            else g_auto_interval = st->value * 60000;
            InvalidateRect(hSpin, NULL, TRUE);
            gui_refresh_status();
        }
        break;

    case WM_GETDLGCODE:
        /* 告诉系统：本 EDIT 要自行处理 VK_RETURN（不要被对话框当成默认按钮） */
        return DLGC_WANTALLKEYS;
    }
    UNREFERENCED_PARAMETER(dwRefData);
    return DefSubclassProc(hEdit, msg, wp, lp);
}

/* 给 spinner 创建内嵌 EDIT：
   hSpin = S_ID_SPIN_THRESH 或 S_ID_SPIN_INTERVAL 的父 STATIC 句柄
   idKind = 1 阈值 2 间隔，用作 EDIT 子类的 uIdSubclass */
static HWND create_edit_inside_spinner(HWND hSpin, UINT idKind, int initial_val) {
    if (!hSpin) return NULL;
    RECT rc;
    GetClientRect(hSpin, &rc);
    int arrows_w = 22;
    /* 数字区域：左右留空、垂直居中，避免紧贴边框和箭头。
       让 EDIT 看起来是 spinner 框内的“内凹数字区”，而不是一个独立控件。 */
    int margin_x = 8;          /* 左侧留空 */
    int margin_right = 8;      /* 到箭头分隔线留空 */
    int eh = 22;               /* 输入框高度，比 spinner 行高小，留出呼吸感 */
    int ew = (rc.right - arrows_w - margin_right) - margin_x;
    int ex = margin_x;
    int ey = (rc.bottom - eh) / 2;

    HWND hEdit = CreateWindowExW(0,   /* 从创建起就不要 WS_EX_CLIENTEDGE */
        L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_NUMBER | ES_AUTOHSCROLL | ES_CENTER | WS_TABSTOP,
        ex, ey, ew, eh,
        hSpin, NULL, GetModuleHandleW(NULL), NULL);
    if (!hEdit) return NULL;

    /* 去掉可能残留的 WS_BORDER/WS_EX_STATICEDGE/WS_EX_WINDOWEDGE 并强制刷新
       非客户区，否则 EDIT 仍会画出一条淡淡的 3D 边框，和整体平面风格冲突。 */
    LONG_PTR exStyle = GetWindowLongPtrW(hEdit, GWL_EXSTYLE);
    exStyle &= ~(WS_EX_CLIENTEDGE | WS_EX_STATICEDGE | WS_EX_WINDOWEDGE);
    SetWindowLongPtrW(hEdit, GWL_EXSTYLE, exStyle);
    LONG_PTR style = GetWindowLongPtrW(hEdit, GWL_STYLE);
    style &= ~(WS_BORDER | WS_DLGFRAME);
    SetWindowLongPtrW(hEdit, GWL_STYLE, style);
    SetWindowPos(hEdit, NULL, 0, 0, 0, 0,
        SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);

    /* 文字内边距、字体（用常规 UI 字体，不要 semibold，避免数字太粗太显眼） */
    SendMessageW(hEdit, EM_SETMARGINS, EC_LEFTMARGIN | EC_RIGHTMARGIN, MAKELPARAM(2, 2));
    wchar_t buf[16];
    swprintf_s(buf, _countof(buf), L"%d", initial_val);
    SetWindowTextW(hEdit, buf);
    SendMessageW(hEdit, WM_SETFONT, (WPARAM)g_font_ui, TRUE);
    SendMessageW(hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);

    /* 子类化处理回车 / 失焦 */
    SetWindowSubclass(hEdit, SpinEditSubclassProc, idKind, 0);
    return hEdit;
}

/* 在设置窗口 WM_CREATE 创建完两个 spinner 之后调用，
   把可键盘键入的 EDIT 子控件嵌到 spinner 内部，并初始化全局句柄。 */
static void create_spinner_edits(HWND dlg) {
    HWND hSpinT = GetDlgItem(dlg, S_ID_SPIN_THRESH);
    HWND hSpinI = GetDlgItem(dlg, S_ID_SPIN_INTERVAL);
    g_hSpinEditThresh   = create_edit_inside_spinner(hSpinT, 1, g_s_thresh.value);
    g_hSpinEditInterval = create_edit_inside_spinner(hSpinI, 2, g_s_interval.value);
}

/* 关闭设置窗口时调用：去掉 EDIT 子类（防止父 HWND 被销毁后，
   EDIT 子类引用的全局还有效，但为了安全按规范移除）。
   g_hSpinEdit* 在弹窗销毁时会随父 spinner 一起被销毁，无需单独 CloseHandle。 */
static void release_spinner_edits(void) {
    if (g_hSpinEditThresh)   { RemoveWindowSubclass(g_hSpinEditThresh,   SpinEditSubclassProc, 1); g_hSpinEditThresh   = NULL; }
    if (g_hSpinEditInterval) { RemoveWindowSubclass(g_hSpinEditInterval, SpinEditSubclassProc, 2); g_hSpinEditInterval = NULL; }
}

#define ID_TIMER_AUTO  100
#define ID_TIMER_TRAY  101
#define WM_CLEAN_DONE  (WM_APP + 1)

/* 全局窗口句柄与资源 */
static HWND g_hwnd;          /* 主窗口 */
static HWND g_hSettingsDlg;  /* 设置弹窗 */

static HWND g_hPct;          /* 大号百分比标签 */
static HWND g_hBar;          /* 进度条（已废弃，保留声明兼容旧引用） */
static int g_progress_pct = 0; /* 自绘进度条百分比 */
static HWND g_hTotalMem;     /* 总内存占用卡片（SS_OWNERDRAW） */
static HWND g_hPageMem;      /* 页面内存卡片（SS_OWNERDRAW） */
static HWND g_hSysWS;        /* 系统工作集卡片（SS_OWNERDRAW） */
static HWND g_hStatus;       /* 底部状态卡片 */
static HWND g_hMemInfo;     /* Hero 区 "内存已使用 X.X GB / XX.X GB" */

/* 设置弹窗：spinner 内嵌的可编辑数字输入框（替代原来只画文字）。
   用户可键盘输入，回车或失焦时自动 clamp + 写回 g_s_thresh/g_s_interval。
   （实际全局变量已在 spinner_hit 后面前置声明区定义） */

/* 三张卡片自绘所需的数据 */
typedef struct {
    int   pct;            /* 填充百分比，sys_ws 用 0 表示"内核"无具体百分比 */
    wchar_t label[16];    /* "总内存占用" */
    wchar_t value[80];    /* "11.8 GB / 15.8 GB" */
    wchar_t badge[16];    /* "74%" / "内核" */
} CardData;
static CardData g_card_total = { 0, L"物理内存", L"", L"内存" };
static CardData g_card_page  = { 0, L"页面使用",   L"", L"页面" };
static CardData g_card_sysws = { 0, L"系统工作集", L"", L"内核" };

/* 内存卡片自绘（在 WM_DRAWITEM 调用） */
static BOOL draw_memory_card(HDC hdc, RECT *rc, const CardData *card);
static HBRUSH g_brush_bg;
static HBRUSH g_brush_card;
static HICON  g_hTrayIcon = NULL;

static NOTIFYICONDATAW g_nid;
static UINT g_taskbar_created;

/* 清理任务来源：WM_CLEAN_DONE 的 wp 携带，区分结果提示方式 */
#define CLEAN_SRC_MANUAL       0   /* 手动清理：完成后弹 MessageBox */
#define CLEAN_SRC_AUTO_AGGRO   1   /* 自动-强力：静默 */
#define CLEAN_SRC_AUTO_CONSERV 2   /* 自动-保守：静默 */

/* 清理线程参数：携带区域掩码 / 是否允许高风险 / 来源 */
typedef struct {
    ULONG region;
    int   allow_risky;
    int   source;
} CleanJob;

/* 清理线程：g_gui_clean_running 同时充当生命周期标志（防并发 + 防重入） */
static volatile LONG g_gui_clean_running = 0;

/* 前向声明：auto_clean_if_needed 在此之前使用 */
static void start_clean_ex(ULONG region, int allow_risky, int source);

/* ====== 主题颜色（仿 AntD 克制工业蓝） ====== */
#define UI_BG     RGB(248, 249, 251)      /* 柔和暖灰白 */
#define UI_FG     RGB(28, 35, 51)         /* 深墨蓝文字 */
#define UI_ACCENT RGB(22, 119, 255)       /* 工业科技蓝 #1677ff */
#define UI_ACCENT_2 RGB(64, 150, 255)     /* 渐变终点 #4096ff */
#define UI_ACCENT_HOVER RGB(19, 100, 220) /* 深蓝 hover */

/* Hero / 卡片共用色 */
#define HERO_BG        RGB(255, 255, 255)
#define CARD_BG        RGB(255, 255, 255)
#define CARD_BORDER    RGB(232, 235, 240)
#define CARD_GROUP_BG  RGB(255, 255, 255) /* 设置窗口分组面板 */
#define CARD_GROUP_BD  RGB(230, 232, 239)
#define CARD_DIVIDER   RGB(238, 240, 244) /* field 内部分隔虚线 */
#define ALERT_GREEN    RGB(34, 197, 94)    /* 状态点 绿 */
#define ALERT_ORANGE   RGB(245, 158, 11)
#define ALERT_RED      RGB(239, 68, 68)
/* 徽章三档配色（对应卡片分类） */
#define BADGE_MEM_BG   RGB(235, 242, 255)
#define BADGE_MEM_FG   RGB(22, 119, 255)
#define BADGE_PAGE_BG  RGB(255, 247, 230)
#define BADGE_PAGE_FG  RGB(183, 107, 0)
#define BADGE_KERN_BG  RGB(243, 245, 248)
#define BADGE_KERN_FG  RGB(75, 85, 99)

/* ====== 自绘标题栏 ====== */
#define TITLE_BAR_H   32
#define WIN_BTN_W     36
#define WIN_BTN_H     28
#define TB_BG         RGB(255, 255, 255)  /* 白色 */
#define TB_FG         RGB(75, 85, 99)     /* 灰色文字 */
#define TB_BORDER     RGB(229, 231, 235)  /* 底部分隔线 */
#define TB_BTN_HOVER  RGB(243, 244, 246)  /* 按钮hover */
#define TB_ICON_DIM   RGB(148, 163, 184)  /* 按钮图标 */
#define TB_CLOSE_HOV  RGB(220, 38, 38)    /* 关闭hover红 */

static int g_win_btn_hover = 0;  /* -1=close, 1=min, 0=none */

/* 绘制 M 品牌 logo：20x20 蓝色圆角方块 + 白色 "M" */
static void draw_m_logo(HDC hdc, int x, int y) {
    int s = 22;
    /* 蓝底方块 */
    HBRUSH br = CreateSolidBrush(RGB(59, 130, 246));
    HPEN pn = CreatePen(PS_SOLID, 1, RGB(59, 130, 246));
    HGDIOBJ ob = SelectObject(hdc, br);
    HGDIOBJ op = SelectObject(hdc, pn);
    RoundRect(hdc, x, y, x + s, y + s, 5, 5);
    SelectObject(hdc, ob); SelectObject(hdc, op);
    DeleteObject(br); DeleteObject(pn);
    /* 白色 M */
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
    HFONT f = CreateFontW(-12, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    HGDIOBJ of = SelectObject(hdc, f);
    RECT rcM = { x, y - 1, x + s, y + s };
    DrawTextW(hdc, L"M", 1, &rcM, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    SelectObject(hdc, of); DeleteObject(f);
}

/* 绘制窗口按钮（最小化 / 关闭）——白色标题栏暗色图标 */
static void draw_win_button(HDC hdc, int x, int y, int kind, int hover) {
    /* 背景 */
    COLORREF bg = TB_BG;
    COLORREF icon_col;
    if (hover && kind == -1) { bg = TB_CLOSE_HOV; icon_col = RGB(255, 255, 255); }
    else if (hover)           { bg = TB_BTN_HOVER; icon_col = TB_ICON_DIM; }
    else                      { icon_col = TB_ICON_DIM; }
    HBRUSH br = CreateSolidBrush(bg);
    HGDIOBJ ob = SelectObject(hdc, br);
    RECT rc = { x, y, x + WIN_BTN_W, y + WIN_BTN_H };
    FillRect(hdc, &rc, br);
    SelectObject(hdc, ob); DeleteObject(br);

    /* 图标 */
    HPEN pn = CreatePen(PS_SOLID, 2, icon_col);
    HGDIOBJ op = SelectObject(hdc, pn);
    int cx = x + WIN_BTN_W / 2;
    int cy = y + WIN_BTN_H / 2;
    if (kind == 1) {
        /* 最小化：水平线 */
        MoveToEx(hdc, cx - 5, cy, NULL);
        LineTo(hdc, cx + 5, cy);
    } else if (kind == -1) {
        /* 关闭：X */
        MoveToEx(hdc, cx - 4, cy - 4, NULL);
        LineTo(hdc, cx + 4, cy + 4);
        MoveToEx(hdc, cx + 4, cy - 4, NULL);
        LineTo(hdc, cx - 4, cy + 4);
    }
    SelectObject(hdc, op); DeleteObject(pn);
}

/* 追踪鼠标是否在窗口按钮上 */
static int hit_win_button(HWND hwnd, int mx, int my) {
    RECT rc; GetClientRect(hwnd, &rc);
    int w = rc.right;
    if (my >= 2 && my < TITLE_BAR_H) {
        if (mx >= w - WIN_BTN_W - 2 && mx < w)     return -1; /* close */
        if (mx >= w - WIN_BTN_W*2 - 2 && mx < w - WIN_BTN_W) return 1; /* min */
    }
    return 0;
}

/* 自定义进度条：浅灰底色 + 蓝色填充 + 圆角 */
static void draw_progress_bar(HDC hdc, RECT *rc, int pct, COLORREF fill_col) {
    int bar_h = 8;
    int bar_y = rc->top;
    /* 底色轨道 */
    HBRUSH brTk = CreateSolidBrush(RGB(228, 231, 235));
    HPEN pnTk = CreatePen(PS_SOLID, 1, RGB(228, 231, 235));
    HGDIOBJ ot = SelectObject(hdc, brTk);
    HGDIOBJ opT = SelectObject(hdc, pnTk);
    RoundRect(hdc, rc->left, bar_y, rc->right, bar_y + bar_h, 4, 4);
    SelectObject(hdc, ot); SelectObject(hdc, opT);
    DeleteObject(brTk); DeleteObject(pnTk);
    /* 填充 */
    if (pct > 0) {
        int fill_w = (int)((double)(rc->right - rc->left) * pct / 100.0);
        if (fill_w > bar_h) { /* 至少超过圆角半径 */
            HBRUSH brF = CreateSolidBrush(fill_col);
            HPEN pnF = CreatePen(PS_SOLID, 1, fill_col);
            HGDIOBJ of = SelectObject(hdc, brF);
            HGDIOBJ opF = SelectObject(hdc, pnF);
            RoundRect(hdc, rc->left, bar_y, rc->left + fill_w, bar_y + bar_h, 4, 4);
            SelectObject(hdc, of); SelectObject(hdc, opF);
            DeleteObject(brF); DeleteObject(pnF);
        }
    }
}

static void init_ui_res(void) {
    static int inited = 0;
    if (inited) return;
    /* v6: 大号百分比 36px 蓝色粗体 */
    g_font_big   = CreateFontW(-36, 0, 0, 0, FW_BOLD,   0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_font_ui    = CreateFontW(-13, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_font_small = CreateFontW(-11, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_font_mid   = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");
    g_brush_bg   = CreateSolidBrush(UI_BG);
    g_brush_card = CreateSolidBrush(RGB(255, 255, 255));
    inited = 1;
}

/* 动态创建托盘图标：按占比三色切换 */
static HICON create_memory_icon(int percent) {
    COLORREF bg_col;
    if (percent >= 90)      bg_col = ALERT_RED;
    else if (percent >= 70) bg_col = ALERT_ORANGE;
    else                    bg_col = ALERT_GREEN;

    HDC hdcScreen = GetDC(NULL);
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmColor = CreateCompatibleBitmap(hdcScreen, 16, 16);
    HBITMAP hbmMask  = CreateBitmap(16, 16, 1, 1, NULL);

    HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbmColor);

    RECT rc = {0, 0, 16, 16};
    HBRUSH brBg = CreateSolidBrush(bg_col);
    FillRect(hdcMem, &rc, brBg);
    DeleteObject(brBg);

    SetBkMode(hdcMem, TRANSPARENT);
    SetTextColor(hdcMem, RGB(255, 255, 255));

    /* 托盘字体：平衡"不太细"又"不粗壮"。
       - 不选 FW_LIGHT（300，用户说太细，在 4K/125% DPI 下显模糊）
       - 不选 FW_BOLD（700，之前版本的问题：数字显得拥挤臃肿）
       - 选 FW_NORMAL（400）+ Calibri（Win10/11 自带、数字字形现代等宽），
         再用 -12 比 -11 稍微大一点，16x16 上占 11~12px 正好。 */
    HFONT hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, L"Calibri");
    if (!hFont) {
        hFont = CreateFontW(-12, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
    }
    HFONT hOldFont = (HFONT)SelectObject(hdcMem, hFont);

    wchar_t txt[8];
    swprintf(txt, _countof(txt), L"%d", percent);
    DrawTextW(hdcMem, txt, -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    SelectObject(hdcMem, hOldFont);
    DeleteObject(hFont);
    SelectObject(hdcMem, hbmOld);

    ICONINFO ii = {0};
    ii.fIcon = TRUE;
    ii.hbmColor = hbmColor;
    ii.hbmMask  = hbmMask;
    HICON hIcon = CreateIconIndirect(&ii);

    DeleteDC(hdcMem);
    ReleaseDC(NULL, hdcScreen);
    DeleteObject(hbmColor);
    DeleteObject(hbmMask);

    return hIcon;
}

/* 给所有子控件统一设置界面字体 */
static BOOL CALLBACK set_child_font(HWND child, LPARAM lp) {
    SendMessageW(child, WM_SETFONT, (WPARAM)lp, TRUE);
    return TRUE;
}

/* 根据占用百分比选择进度条颜色。
   更克制的阈值：
     < 75%   norm 蓝
     75-90%  warn 橙
     > 90%   crit 红
   sys_ws 专用 kern 灰。 */
static COLORREF bar_color_kind(int pct, BOOL is_kern) {
    if (is_kern)            return RGB(71, 85, 105);  /* slate-600 */
    if (pct >= 90)          return ALERT_RED;
    if (pct >= 75)          return ALERT_ORANGE;
    return UI_ACCENT;
}

/* 在 SS_OWNERDRAW STATIC 上绘制一张内存卡片：
   - 圆角白底（圆角 10px, 1px 描边）
   - 左上 label（12px 灰）→ value（18px 半粗深）
   - 右上 badge（圆角胶囊，14px 高）：三档配色
   - 底部 4px 进度条 */
static BOOL draw_memory_card(HDC hdc, RECT *rc, const CardData *card) {
    /* 1) 卡片背景：12px 圆角 1px 描边，卡片更厚更呼吸 */
    HBRUSH brBg = CreateSolidBrush(CARD_BG);
    HPEN   pnBg = CreatePen(PS_SOLID, 1, CARD_BORDER);
    HGDIOBJ ob = SelectObject(hdc, brBg);
    HGDIOBJ op = SelectObject(hdc, pnBg);
    RoundRect(hdc, rc->left, rc->top, rc->right, rc->bottom, 12, 12);
    SelectObject(hdc, ob);
    SelectObject(hdc, op);
    DeleteObject(brBg);
    DeleteObject(pnBg);

    SetBkMode(hdc, TRANSPARENT);

    /* 2) 判断徽章类型：内存/页面/内核 */
    int badge_kind;
    if      (wcscmp(card->badge, L"内存") == 0) badge_kind = 0;
    else if (wcscmp(card->badge, L"页面") == 0) badge_kind = 1;
    else                                         badge_kind = 2;
    COLORREF brBgBad, fgBad, progCol;
    int pct = card->pct;
    if (pct < 0) pct = 0; if (pct > 100) pct = 100;
    if (badge_kind == 0) {
        brBgBad = BADGE_MEM_BG; fgBad = BADGE_MEM_FG;
        if (pct >= 92)      progCol = ALERT_RED;
        else if (pct >= 85) progCol = ALERT_ORANGE;
        else                progCol = UI_ACCENT;
    } else if (badge_kind == 1) {
        brBgBad = BADGE_PAGE_BG; fgBad = BADGE_PAGE_FG;
        progCol  = ALERT_ORANGE;
    } else {
        brBgBad = BADGE_KERN_BG; fgBad = BADGE_KERN_FG;
        progCol  = BADGE_KERN_FG;
    }

    /* 3) 顶部：label 左 + badge 右
       —— 卡片由 68→90，padding 加大（x=22, top=18），不挤压 */
    int pad_x = 22;
    int top_y = rc->top + 18;
    RECT rcLabel = { rc->left + pad_x, top_y, rc->right - 110, top_y + 20 };
    SelectObject(hdc, g_font_ui);     /* label 用 UI 字体(13px)，比 small 更清晰 */
    SetTextColor(hdc, COL_TEXT_DIM);
    DrawTextW(hdc, card->label, -1, &rcLabel,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    SIZE sz;
    SelectObject(hdc, g_font_ui);
    GetTextExtentPoint32W(hdc, card->badge, (int)wcslen(card->badge), &sz);
    int bw = sz.cx + 24, bh = 24;   /* 徽章扩大 20→24 高，x-padding 9→12 */
    int bx = rc->right - pad_x - bw;
    int by = top_y - 2;
    HBRUSH brB = CreateSolidBrush(brBgBad);
    HGDIOBJ oB = SelectObject(hdc, brB);
    RoundRect(hdc, bx, by, bx + bw, by + bh, 12, 12);
    SelectObject(hdc, oB);
    DeleteObject(brB);
    SetTextColor(hdc, fgBad);
    RECT rcBadge = { bx, by, bx + bw, by + bh };
    DrawTextW(hdc, card->badge, -1, &rcBadge,
              DT_CENTER | DT_SINGLELINE | DT_VCENTER);

    /* 4) value 大字：用 g_font_mid(13px semibold) 但高度更高 */
    RECT rcValue = { rc->left + pad_x, top_y + 26, rc->right - pad_x, top_y + 54 };
    SelectObject(hdc, g_font_mid);
    SetTextColor(hdc, UI_FG);
    DrawTextW(hdc, card->value, -1, &rcValue,
              DT_LEFT | DT_SINGLELINE | DT_VCENTER);

    /* 5) 底部进度条：4→8px（加粗，让"条"不再"窄"），圆角 4 */
    int bar_x = rc->left + pad_x;
    int bar_y = rc->bottom - 16;
    int bar_w = rc->right - rc->left - pad_x * 2;
    int bar_h = 8;
    HBRUSH brTrack = CreateSolidBrush(CARD_DIVIDER);
    HGDIOBJ oT = SelectObject(hdc, brTrack);
    RoundRect(hdc, bar_x, bar_y, bar_x + bar_w, bar_y + bar_h, 4, 4);
    SelectObject(hdc, oT);
    DeleteObject(brTrack);
    int fill_w = (int)((double)bar_w * pct / 100.0);
    if (fill_w > 0) {
        HBRUSH brFill = CreateSolidBrush(progCol);
        HGDIOBJ oF = SelectObject(hdc, brFill);
        RoundRect(hdc, bar_x, bar_y, bar_x + fill_w, bar_y + bar_h, 4, 4);
        SelectObject(hdc, oF);
        DeleteObject(brFill);
    }
    return TRUE;
}

/* 触发一次后台自动清理：仅在超过阈值且距上次清理足够久时才执行。
   走独立线程，避免 8 步 × 150ms 延迟阻塞 UI 主线程(原实现同步调用 do_clean
   会导致窗口卡顿 1+ 秒)。

   BUGFIX(超阈值不触发)：
   旧实现判断条件
     m.dwMemoryLoad >= threshold  AND  (now - last_clean_tick) >= interval
   与 start_clean_ex 内部对 g_last_clean_tick 赋值在【锁前】，有两个严重坑：
   1) GUI 模式下用户刚手动清理完，last_clean_tick 会被设为 now，但
      auto_clean_if_needed 还要求 ≥ interval 的时间跨度（默认 10 分钟），
      即便瞬间又跳到超阈值状态也不会立刻清。
   2) 最关键：auto_clean_if_needed 自己也对 g_last_clean_tick 赋值 now
      后才进入 start_clean_ex，但 start_clean_ex 又再次写 g_last_clean_tick。
      这导致清理线程的互斥锁 g_gui_clean_running 被持有时间可能很长
      （8 步 × 150ms ≈ 1.2 秒），下一次 timer 的 auto_clean_if_needed
      与 clean 结束的 PostMessage(WM_CLEAN_DONE) 会在时序上错位：
      若 now 卡在 worker 清理中，会让 "last_clean_tick 已设置但状态显示
      还是清理中" 的状态对不上，以及 g_auto_enabled 默认 0 +
      is_elevated() 之外的双重限制，使许多情况永远不会进入清理路径。

   修复策略（更符合用户直觉，也与 memreduct 的 TimerCleanup 一致）：
   拆成两个独立条件，只要满足其一就清理：
     A) 超阈值 AND 距离上次清理 ≥ 间隔
         (常规：保证"每 N 分钟最多清一次"避免持续轰炸)
     OR
     B) 超阈值 AND 上次成功清理至今从未发生 (last_clean_tick == 0)
         AND 程序已启动 ≥ 启动防抖窗口 (默认 60 秒，让系统稳定后再介入)
         (启动后首次达到阈值立刻清，避免一直等 10 分钟窗口才清)
*/
static void auto_clean_if_needed(void) {
    MEMORYSTATUSEX m;
    m.dwLength = sizeof(m);
    GlobalMemoryStatusEx(&m);

    ULONG64 now = GetTickCount64();
    ULONG64 interval = (ULONG64)g_auto_interval;

    /* 启动防抖窗口：避免开机后系统正忙着读盘/自启时立刻抢资源。
       g_app_start_tick 在 WinMain 创建完窗口后写入一次。 */
    extern ULONG64 g_app_start_tick;   /* 前置声明：WinMain 里定义 */
    const ULONG64 STARTUP_GRACE_MS = 60 * 1000ULL; /* 60 秒 */

    int pct = (int)m.dwMemoryLoad;
    int hit_threshold = (pct >= g_auto_threshold);

    int cond_A = hit_threshold &&
                 g_last_clean_tick &&
                 (now - g_last_clean_tick) >= interval;

    int cond_B = hit_threshold &&
                 (g_last_clean_tick == 0) &&
                 (now >= g_app_start_tick) &&
                 (now - g_app_start_tick) >= STARTUP_GRACE_MS;

    if (!(cond_A || cond_B)) return;

    /* 进入清理：先锁互斥，成功再写 last_clean_tick（与 start_clean_ex
       内部顺序一致，避免锁竞争时双写错位） */
    if (InterlockedCompareExchange(&g_gui_clean_running, 1, 0) != 0)
        return;   /* 已有清理在进行 */

    g_last_clean_tick = now;

    int aggro = g_auto_aggressive;
    ULONG region = aggro ? R_ALL_OLD : R_DEFAULT;
    int source = aggro ? CLEAN_SRC_AUTO_AGGRO : CLEAN_SRC_AUTO_CONSERV;

    /* 与 start_clean_ex 体一致，自己再写一份避免重复函数内部
       g_last_clean_tick 赋值的时序问题 */
    CleanJob *job = (CleanJob *)malloc(sizeof(CleanJob));
    if (!job) {
        InterlockedExchange(&g_gui_clean_running, 0);
        g_last_clean_tick = 0; /* 申请失败不占用 tick */
        return;
    }
    job->region = region;
    job->allow_risky = aggro;
    job->source = source;

    HANDLE h = CreateThread(NULL, 0, clean_worker, job, 0, NULL);
    if (!h) {
        free(job);
        InterlockedExchange(&g_gui_clean_running, 0);
        g_last_clean_tick = 0;
        return;
    }
    CloseHandle(h);

    /* 状态先提示"清理中"，实际释放量在 WM_CLEAN_DONE 后更新 */
    wchar_t buf[192];
    const wchar_t *why = cond_A ? L"间隔" : L"首次触发";
    swprintf(buf, _countof(buf),
        L"[自动-%ls] %ls: 内存 %.0f%% ≥ %d%% 阈值，开始清理...",
        aggro ? L"强力" : L"保守", why,
        (double)pct, g_auto_threshold);
    log_msg(L"%ls", buf);
    if (g_hStatus) {
        SetWindowTextW(g_hStatus, buf);
        InvalidateRect(g_hStatus, NULL, TRUE);
    }
}

/* 刷新主窗口所有内存指标的显示 */
static void gui_refresh_status(void) {
    MEMORYSTATUSEX m;
    m.dwLength = sizeof(m);
    GlobalMemoryStatusEx(&m);

    PERFORMANCE_INFORMATION pi;
    pi.cb = sizeof(pi);
    GetPerformanceInfo(&pi, sizeof(pi));

    int pct = (int)m.dwMemoryLoad;
    if (pct > 100) pct = 100;

    double total_gb = m.ullTotalPhys / (1024.0 * 1024 * 1024);
    double used_gb  = m.ullTotalPhys ? (m.ullTotalPhys - m.ullAvailPhys)
                                     / (1024.0 * 1024 * 1024) : 0;
    double used_pct = m.ullTotalPhys ? (used_gb / total_gb) * 100.0 : 0;

    /* 总内存卡片：used_gb / total_gb GB 已用。
       badge 固定为 "内存"（分类标签，非百分比） */
    swprintf(g_card_total.value,  _countof(g_card_total.value),
             L"%.1f GB / %.1f GB", used_gb, total_gb);
    wcscpy_s(g_card_total.badge,  _countof(g_card_total.badge), L"内存");
    g_card_total.pct = (int)used_pct;
    if (g_hTotalMem) InvalidateRect(g_hTotalMem, NULL, TRUE);

    /* 页面使用卡片：commit_used / commit_limit GB。
       badge 固定为 "页面"（分类标签，非百分比）。 */
    {
        double commit_used  = (double)(m.ullTotalPageFile - m.ullAvailPageFile)
                              / (1024.0 * 1024 * 1024);
        double commit_limit = (double)m.ullTotalPageFile
                              / (1024.0 * 1024 * 1024);
        double page_pct     = commit_limit ? (commit_used / commit_limit) * 100.0 : 0;
        swprintf(g_card_page.value, _countof(g_card_page.value),
                 L"%.1f GB / %.1f GB", commit_used, commit_limit);
        wcscpy_s(g_card_page.badge, _countof(g_card_page.badge), L"页面");
        g_card_page.pct = (int)page_pct;
        if (g_hPageMem) InvalidateRect(g_hPageMem, NULL, TRUE);
    }

    /* 系统工作集卡片：KernelPaged+KernelNonpaged (GB) + "内核" 徽章。
       内核内存没有百分比概念，固定显示约 60% 的填充表示状态。 */
    {
        double sys_ws = (double)(pi.KernelPaged + pi.KernelNonpaged)
                        * (double)pi.PageSize / (1024.0 * 1024.0 * 1024.0);
        swprintf(g_card_sysws.value, _countof(g_card_sysws.value),
                 L"%.2f GB · 内核内存", sys_ws);
        wcscpy_s(g_card_sysws.badge, _countof(g_card_sysws.badge), L"内核");
        /* 用 sys_ws 对比 4 GB 做粗略参考填充值，避免一眼看上去为空 */
        g_card_sysws.pct = (int)((sys_ws / 4.0) * 100.0);
        if (g_card_sysws.pct > 100) g_card_sysws.pct = 100;
        if (g_card_sysws.pct < 0)   g_card_sysws.pct = 0;
        if (g_hSysWS) InvalidateRect(g_hSysWS, NULL, TRUE);
    }

    /* 顶部大号百分比 */
    if (g_hPct) {
        wchar_t t[80];
        swprintf(t, _countof(t), L"%d%%", pct);
        SetWindowTextW(g_hPct, t);
    }

    /* Hero 区 — 内存已使用信息 */
    if (g_hMemInfo) {
        wchar_t info[128];
        swprintf(info, _countof(info),
                 L"\u5185\u5B58\u5DF2\u4F7F\u7528 %.1f GB / %.1f GB",
                 used_gb, total_gb);
        SetWindowTextW(g_hMemInfo, info);
    }

    /* 进度条（自绘，存储百分比触发重绘） */
    g_progress_pct = pct;
    InvalidateRect(g_hwnd, NULL, FALSE);

    /* 状态卡片：上次清理信息。
       状态条改为 WM_DRAWITEM 自绘（带绿点指示器，设计稿风格）。
       这里只需存储显示数据，真正画绿点+文字在 WM_DRAWITEM / draw_status_bar 里。 */
    if (g_hStatus) {
        ULONG64 now = GetTickCount64();
        ULONG64 elapsed_ms = (g_last_clean_tick && now > g_last_clean_tick)
                            ? (now - g_last_clean_tick) : 0;
        if (!g_last_clean_tick) elapsed_ms = 0;

        wchar_t last[96];
        if (g_last_clean_tick) {
            swprintf(last, _countof(last), L"上次清理: %ls  释放 %.1f MB",
                     g_last_clean_tag, g_last_freed / (1024.0 * 1024.0));
        } else {
            wcscpy_s(last, _countof(last), L"上次清理: 暂无");
        }

        /* 两行显示（状态条 72px 高）：
           行1（与绿点水平对齐）：后台清理已(启用|停用) · 每 X 分钟 · 阈值 Y%
           行2（缩进对齐）：上次清理: xxx  释放 xxx MB（完整不截断）
           存储格式："\x25CF/X line1 \n line2" —— WM_DRAWITEM 按 \n 拆成两行画。 */
        wchar_t line1[128];
        if (g_auto_enabled) {
            swprintf(line1, _countof(line1),
                L"后台清理已启用 · 每 %d 分钟 · 阈值 %d%%",
                g_auto_interval / 60000, g_auto_threshold);
        } else {
            wcscpy_s(line1, _countof(line1), L"后台清理已关闭");
        }
        wchar_t buf[512];
        swprintf(buf, _countof(buf),
            L"%ls\t%ls\n%ls",
            g_auto_enabled ? L"\x25CF" : L"\x25CB", line1, last);
        SetWindowTextW(g_hStatus, buf);
        InvalidateRect(g_hStatus, NULL, TRUE);
    }
}

static void gui_update_tray(void) {
    MEMORYSTATUSEX m;
    m.dwLength = sizeof(m);
    GlobalMemoryStatusEx(&m);
    int pct = (int)m.dwMemoryLoad;
    if (pct > 100) pct = 100;

    wchar_t tip[128];
    swprintf(tip, _countof(tip), L"MemOpt  %d%%", pct);
    wcscpy_s(g_nid.szTip, _countof(g_nid.szTip), tip);

    /* 动态托盘图标：蓝底白字显示当前内存占用百分比 */
    HICON hNew = create_memory_icon(pct);
    if (hNew) {
        HICON hOld = g_nid.hIcon;
        g_nid.hIcon = hNew;
        Shell_NotifyIconW(NIM_MODIFY, &g_nid);
        if (hOld) DestroyIcon(hOld);
    }
}

static void gui_report(ULONG64 freed) {
    wchar_t msg[256];
    swprintf(msg, _countof(msg), L"清理完成。释放约 %.1f MB",
             freed / (1024.0 * 1024.0));
    log_msg(L"[手动] %ls", msg);
    MessageBoxW(g_hwnd, msg, L"MemOpt", MB_OK | MB_ICONINFORMATION);
}

/* 清理工作线程：后台执行 do_clean，完成后向主窗口投递 WM_CLEAN_DONE。
   job 由本线程释放（malloc 分配），主线程不再持有其指针。 */
static DWORD WINAPI clean_worker(LPVOID param) {
    CleanJob *job = (CleanJob *)param;
    do_clean(job->region, job->allow_risky);
    PostMessageW(g_hwnd, WM_CLEAN_DONE, (WPARAM)job->source, 0);
    free(job);
    InterlockedExchange(&g_gui_clean_running, 0);
    return 0;
}

/* 启动一次清理（手动/自动共用）。g_gui_clean_running 防止并发清理，
   避免 0xF7 根因——内核内存列表清除 API 重叠调用。
   source 决定结果提示方式：CLEAN_SRC_MANUAL 弹 MessageBox，其余静默。 */
static void start_clean_ex(ULONG region, int allow_risky, int source) {
    if (!is_elevated()) {
        if (source == CLEAN_SRC_MANUAL)
            MessageBoxW(g_hwnd, L"请以管理员身份运行以执行内存清理。",
                        L"MemOpt", MB_OK | MB_ICONSTOP);
        return;
    }
    if (InterlockedCompareExchange(&g_gui_clean_running, 1, 0) != 0)
        return;  /* 已有清理在进行 */

    g_last_clean_tick = GetTickCount64();
    CleanJob *job = (CleanJob *)malloc(sizeof(CleanJob));
    if (!job) { InterlockedExchange(&g_gui_clean_running, 0); return; }
    job->region = region;
    job->allow_risky = allow_risky;
    job->source = source;

    HANDLE h = CreateThread(NULL, 0, clean_worker, job, 0, NULL);
    if (!h) {
        free(job);
        InterlockedExchange(&g_gui_clean_running, 0);
        return;
    }
    CloseHandle(h);  /* 不持有句柄；靠 g_gui_clean_running 跟踪生命周期 */
}

/* 手动清理：全区域，允许高风险，完成后弹结果框 */
static void start_clean(void) {
    start_clean_ex(R_ALL_OLD, 1, CLEAN_SRC_MANUAL);
}

static void gui_clean(void) {
    start_clean();
}

/* 显示/隐藏主窗口 */
static void gui_toggle_window(void) {
    if (IsWindowVisible(g_hwnd)) {
        ShowWindow(g_hwnd, SW_HIDE);
    } else {
        ShowWindow(g_hwnd, SW_SHOW);
        SetForegroundWindow(g_hwnd);
    }
}

/* ====== 设置弹窗实现 ====== */

/* （旧 sync_settings_to_ui 已废弃删除 — 现在在 WM_CREATE 中直接初始化 g_s_* 状态） */
/* 设置窗口 WM_CTLCOLORSTATIC：白底卡片与浅灰窗口 */
static HBRUSH g_brush_settings_bg;
static HBRUSH g_brush_hint;
static COLORREF g_fg_blue = RGB(29, 78, 216);

static LRESULT CALLBACK SettingsProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        /* 初始化状态（从主配置同步） */
        g_s_auto.checked     = g_auto_enabled;
        g_s_autostart.checked = autostart_enabled();
        g_s_thresh.value     = g_auto_threshold;
        g_s_interval.value   = g_auto_interval / 60000;
        if (g_s_interval.value < 1) g_s_interval.value = 1;
        g_s_aggro.checked    = g_auto_aggressive;

        /* ========== 清晰的两列栅格：左列 PAD_X~RIGHT_X，右列 RIGHT_X 开始 ========== */
        #define SY          TITLE_BAR_H
        #define PAD_X       24
        #define RIGHT_X     250   /* 右列控件起始X */
        #define CW          116   /* 右列控件宽度 */
        #define ROWH        36    /* 行高 */

        /* Row 1 (Y=28): 左=后台自动清理 | 右=开机自启动 */
        CreateWindowW(L"STATIC", L"后台自动清理",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW | SS_NOTIFY,
            PAD_X, 28+SY, RIGHT_X - PAD_X, ROWH, dlg, (HMENU)S_ID_CHK_AUTO, NULL, NULL);
        CreateWindowW(L"STATIC", L"开机自启动",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW | SS_NOTIFY,
            RIGHT_X, 28+SY, CW, ROWH, dlg, (HMENU)S_ID_CHK_AUTOSTART, NULL, NULL);

        /* Row 2 (Y=90): 左=清理阈值 | 右=数字调节器 + % */
        CreateWindowW(L"STATIC", L"清理阈值",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            PAD_X, 90+SY, RIGHT_X - PAD_X, ROWH, dlg, (HMENU)S_ID_LBL_THRESH, NULL, NULL);
        CreateWindowW(L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW | SS_NOTIFY,
            RIGHT_X, 90+SY, CW - 24, ROWH, dlg, (HMENU)S_ID_SPIN_THRESH, NULL, NULL);
        CreateWindowW(L"STATIC", L"%",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            RIGHT_X + CW - 16, 90+SY, 18, ROWH, dlg, NULL, NULL, NULL);

        /* Row 3 (Y=146): 左=强力模式 | 右=释放更多 按钮 */
        CreateWindowW(L"STATIC", L"强力模式",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW | SS_NOTIFY,
            PAD_X, 146+SY, RIGHT_X - PAD_X, ROWH, dlg, (HMENU)S_ID_CHK_AGGRO, NULL, NULL);
        CreateWindowW(L"BUTTON", L"释放更多",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            RIGHT_X, 150+SY, 88, 28, dlg, (HMENU)S_ID_BTN_MORE, NULL, NULL);

        /* Row 4 (Y=202): 左=清理间隔 | 右=数字调节器 + 分钟 */
        CreateWindowW(L"STATIC", L"清理间隔",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            PAD_X, 202+SY, RIGHT_X - PAD_X, ROWH, dlg, (HMENU)S_ID_LBL_INTERVAL, NULL, NULL);
        CreateWindowW(L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW | SS_NOTIFY,
            RIGHT_X, 202+SY, CW - 24, ROWH, dlg, (HMENU)S_ID_SPIN_INTERVAL, NULL, NULL);
        CreateWindowW(L"STATIC", L"分钟",
            WS_VISIBLE | WS_CHILD | SS_LEFT,
            RIGHT_X + CW - 16, 202+SY, 34, ROWH, dlg, NULL, NULL, NULL);

        /* 底部按钮：右对齐 */
        int btn_w = 104, btn_h = 36;
        int btn_y = 278; /* 360 - 36 - 46 (底部留白) */
        CreateWindowW(L"BUTTON", L"取消",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            400 - btn_w * 2 - 24 - 16, btn_y, btn_w, btn_h, dlg, (HMENU)S_ID_BTN_CANCEL, NULL, NULL);
        CreateWindowW(L"BUTTON", L"保存设置",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            400 - btn_w - 24, btn_y, btn_w, btn_h, dlg, (HMENU)S_ID_BTN_OK, NULL, NULL);

        #undef SY
        #undef PAD_X
        #undef RIGHT_X
        #undef CW
        #undef ROWH

        /* 文本类子控件统一字体（自定义绘制的 STATIC 不变字号） */
        SendMessageW(GetDlgItem(dlg, S_ID_LBL_THRESH),   WM_SETFONT, (WPARAM)g_font_ui, TRUE);
        SendMessageW(GetDlgItem(dlg, S_ID_LBL_INTERVAL), WM_SETFONT, (WPARAM)g_font_ui, TRUE);
        SendMessageW(GetDlgItem(dlg, S_ID_BTN_OK),      WM_SETFONT, (WPARAM)g_font_ui, TRUE);
        SendMessageW(GetDlgItem(dlg, S_ID_BTN_CANCEL),  WM_SETFONT, (WPARAM)g_font_ui, TRUE);
        SendMessageW(GetDlgItem(dlg, S_ID_BTN_MORE),    WM_SETFONT, (WPARAM)g_font_mid, TRUE);

        /* 子类化自定义绘制控件 */
        subclass_custom_controls(dlg);

        /* 给两个 spinner 内嵌可键盘键入的 EDIT 控件（数字支持手动输入） */
        create_spinner_edits(dlg);

        /* 文本标签用纯 SS_LEFT (非自绘)，WM_CTLCOLORSTATIC 已经处理好字体颜色 */
        return 0;
    }
    case WM_COMMAND: {
        switch (LOWORD(wp)) {
        case S_ID_BTN_MORE:
            MessageBoxW(dlg,
                L"强力模式会清理 Standby 列表（含 R_STANDBY_LIST / R_STANDBY_LOW）\r\n"
                L"可释放更多内存，但风险略高，已通过 150ms 步间延迟保证稳定。\r\n"
                L"自动清理默认 10 分钟一次，到达你设置的内存占用阈值即触发。",
                L"释放更多", MB_OK | MB_ICONINFORMATION);
            return 0;
        case S_ID_BTN_OK: {
            /* 点保存前，强制把两个 EDIT 当前输入写回 g_s_*（即使用户
               还没失焦/没按回车，避免在 EDIT 里刚输入的数字不被保存） */
            spin_apply_edit_text(g_hSpinEditThresh,   &g_s_thresh);
            spin_apply_edit_text(g_hSpinEditInterval, &g_s_interval);

            /* 保存到全局状态 */
            g_auto_enabled    = g_s_auto.checked;
            g_auto_aggressive = g_s_aggro.checked;
            g_auto_threshold  = g_s_thresh.value;
            g_auto_interval   = g_s_interval.value * 60000;
            set_autostart(g_s_autostart.checked);
            save_config();        /* 持久化到 INI */
            gui_refresh_status();
            DestroyWindow(dlg);
            return 0;
        }
        case S_ID_BTN_CANCEL:
            DestroyWindow(dlg);
            return 0;
        }
        return 0;
    }
    case WM_LBUTTONDOWN: {
        /* 标题栏关闭按钮 —— 必须用 DestroyWindow 才能让设置窗口能再次打开
           （SW_HIDE 会把窗口留在内存里，下次 open_settings 以为存在无法重建） */
        POINT pt = { (int)(short)LOWORD(lp), (int)(short)HIWORD(lp) };
        RECT rcS; GetClientRect(dlg, &rcS);
        if (pt.y >= 2 && pt.y < TITLE_BAR_H &&
            pt.x >= rcS.right - WIN_BTN_W - 2) {
            DestroyWindow(dlg);
            return 0;
        }
        /* 点击自定义控件的事件已由 SettingsSubclassProc 直接处理
           （子类化控件自己接收 WM_LBUTTONDOWN），父窗口收不到该消息，
           旧的 ChildWindowFromPoint 分支是永远不执行的死代码，已删除。 */
    }
    case WM_LBUTTONUP:
        KillTimer(dlg, 1); KillTimer(dlg, 2);
        g_s_thresh.pressing   = 0;
        g_s_interval.pressing = 0;
        InvalidateRect(GetDlgItem(dlg, S_ID_SPIN_THRESH),   NULL, TRUE);
        InvalidateRect(GetDlgItem(dlg, S_ID_SPIN_INTERVAL), NULL, TRUE);
        return 0;
    case WM_TIMER: {
        /* 长按 spiner 时连续递增/递减，同时把新值同步给内嵌 EDIT */
        POINT pt; GetCursorPos(&pt);
        S_State *st = (wp == 1) ? &g_s_thresh : &g_s_interval;
        HWND hSpin = GetDlgItem(dlg, (wp == 1) ? S_ID_SPIN_THRESH
                                               : S_ID_SPIN_INTERVAL);
        if (st->pressing ==  1 && st->value < st->value_max) st->value++;
        if (st->pressing == -1 && st->value > st->value_min) st->value--;
        sync_spinner_edit(hSpin);
        InvalidateRect(hSpin, NULL, TRUE);
        UNREFERENCED_PARAMETER(pt);
        return 0;
    }
    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp;
        RECT rc; GetClientRect(dlg, &rc);
        HBRUSH br = CreateSolidBrush(COL_BG);
        FillRect(hdc, &rc, br);
        DeleteObject(br);
        return 1;
    }
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(dlg, &ps);
        RECT rc; GetClientRect(dlg, &rc);
        /* 白色标题栏 */
        HBRUSH brTB = CreateSolidBrush(TB_BG);
        RECT rcTB = { 0, 0, rc.right, TITLE_BAR_H };
        FillRect(hdc, &rcTB, brTB);
        DeleteObject(brTB);
        /* 标题栏底部分隔线 */
        HPEN pnDiv = CreatePen(PS_SOLID, 1, TB_BORDER);
        HGDIOBJ opDv = SelectObject(hdc, pnDiv);
        MoveToEx(hdc, 0, TITLE_BAR_H, NULL);
        LineTo(hdc, rc.right, TITLE_BAR_H);
        SelectObject(hdc, opDv); DeleteObject(pnDiv);
        /* 标题文字 */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, TB_FG);
        HFONT fTB = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ ofTB = SelectObject(hdc, fTB);
        RECT rcTxt = { 12, 0, 180, TITLE_BAR_H };
        DrawTextW(hdc, L"MemOpt \u00B7 \u8BBE\u7F6E", -1, &rcTxt,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, ofTB); DeleteObject(fTB);
        /* 关闭按钮 */
        draw_win_button(hdc, rc.right - WIN_BTN_W - 2, 2, -1, g_s_btn_hover == -1);
        /* 1px 边框 */
        HPEN pnB = CreatePen(PS_SOLID, 1, RGB(200, 204, 210));
        HGDIOBJ opB = SelectObject(hdc, pnB);
        HGDIOBJ obB = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, 0, 0, rc.right, rc.bottom);
        SelectObject(hdc, obB); SelectObject(hdc, opB);
        DeleteObject(pnB);
        EndPaint(dlg, &ps);
        return 0;
    }
    /* 设置窗口标题栏拖动支持 */
    case WM_NCHITTEST: {
        POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(dlg, &pt);
        RECT rc; GetClientRect(dlg, &rc);
        /* ×按钮区域必须返回 HTCLIENT，否则系统当成 HTCAPTION 拖动标题栏，
           WM_LBUTTONDOWN 永远不会触发，×按钮点不动 */
        if (pt.y >= 0 && pt.y < TITLE_BAR_H) {
            if (pt.x >= rc.right - WIN_BTN_W - 2)
                return HTCLIENT;   /* ×按钮区域 → 让 WM_LBUTTONDOWN 处理 */
            return HTCAPTION;      /* 其余标题栏区域 → 可拖动 */
        }
        return HTCLIENT;
    }
    case WM_MOUSEMOVE: {
        int mx = GET_X_LPARAM(lp), my = GET_Y_LPARAM(lp);
        int prev = g_s_btn_hover;
        RECT rc; GetClientRect(dlg, &rc);
        if (my >= 2 && my < TITLE_BAR_H && mx >= rc.right - WIN_BTN_W - 2)
            g_s_btn_hover = -1;
        else
            g_s_btn_hover = 0;
        if (prev != g_s_btn_hover) InvalidateRect(dlg, NULL, FALSE);
        return 0;
    }
    case WM_MOUSELEAVE:
        g_s_btn_hover = 0;
        InvalidateRect(dlg, NULL, FALSE);
        return 0;
    case WM_CTLCOLORSTATIC: {
        /* 标签类（百分比/分钟/标题）背景与窗口一致 */
        HDC hdc = (HDC)wp;
        SetTextColor(hdc, COL_TEXT_DIM);
        SetBkColor(hdc, COL_BG);
        static HBRUSH br = NULL;
        if (!br) br = CreateSolidBrush(COL_BG);
        return (LRESULT)br;
    }
    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)lp;
        int cid = di->CtlID;
        if (cid == S_ID_BTN_OK) {
            BOOL pressed = (di->itemState & ODS_SELECTED) != 0;
            COLORREF bg = pressed ? RGB(0, 94, 172) : COL_BLUE_DARK;
            HBRUSH br = CreateSolidBrush(bg);
            HPEN   pn = CreatePen(PS_SOLID, 1, bg);
            HGDIOBJ ob = SelectObject(di->hDC, br);
            HGDIOBJ op = SelectObject(di->hDC, pn);
            RoundRect(di->hDC, di->rcItem.left, di->rcItem.top,
                      di->rcItem.right, di->rcItem.bottom, 8, 8);
            SelectObject(di->hDC, ob);
            SelectObject(di->hDC, op);
            DeleteObject(br); DeleteObject(pn);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, RGB(255, 255, 255));
            SelectObject(di->hDC, g_font_ui);
            wchar_t txt[32]; GetWindowTextW(di->hwndItem, txt, 32);
            DrawTextW(di->hDC, txt, -1, &di->rcItem,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        if (cid == S_ID_BTN_MORE) {
            BOOL hover = (di->itemState & ODS_SELECTED) != 0
                      || (di->itemState & ODS_HOTLIGHT) != 0;
            draw_pill_button(di->hDC, &di->rcItem, L"释放更多", hover);
            return TRUE;
        }
        if (cid == S_ID_BTN_CANCEL) {
            RECT rc = di->rcItem;
            HBRUSH br = CreateSolidBrush(COL_BG_CARD);
            FillRect(di->hDC, &rc, br);
            DeleteObject(br);
            HPEN pn = CreatePen(PS_SOLID, 1, COL_BORDER);
            HGDIOBJ op = SelectObject(di->hDC, pn);
            RoundRect(di->hDC, rc.left, rc.top, rc.right, rc.bottom, 8, 8);
            SelectObject(di->hDC, op);
            DeleteObject(pn);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, RGB(75, 85, 99));
            SelectObject(di->hDC, g_font_ui);
            wchar_t txt[32]; GetWindowTextW(di->hwndItem, txt, 32);
            DrawTextW(di->hDC, txt, -1, &rc,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        break;
    }
    /* 自定义绘制 STATIC 控件（复选框 / 数字调节器）的 WM_PAINT */
    case WM_CTLCOLORSTATIC + 1 /* placeholder */ : break;
    case WM_DESTROY:
        release_spinner_edits();
        g_hSettingsDlg = NULL;
        return 0;
    }
    return DefWindowProcW(dlg, msg, wp, lp);
}

/* 打开设置弹窗 */
static void open_settings(void) {
    if (g_hSettingsDlg && IsWindow(g_hSettingsDlg)) {
        SetForegroundWindow(g_hSettingsDlg);
        return;
    }

    static int reg = 0;
    if (!reg) {
        WNDCLASSEXW wc = {0};
        wc.cbSize = sizeof(wc);
        wc.lpfnWndProc = SettingsProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hbrBackground = CreateSolidBrush(COL_BG);
        wc.lpszClassName = L"MemOptSettingsClass";
        wc.hIcon = LoadIconW(wc.hInstance, (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT));
        wc.hIconSm = (HICON)LoadImageW(wc.hInstance, (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT),
                                        IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR);
        RegisterClassExW(&wc);
        reg = 1;
    }

    /* 居中位于主窗口 —— 尺寸放大到 400x360，两列栅格更宽敞 */
    RECT rc; GetWindowRect(g_hwnd, &rc);
    int cx = 400, cy = 360;
    int x = rc.left + ((rc.right - rc.left) - cx) / 2;
    int y = rc.top  + ((rc.bottom - rc.top) - cy) / 2;
    if (x < 0) x = 0; if (y < 0) y = 0;

    g_hSettingsDlg = CreateWindowExW(WS_EX_TOPMOST,
        L"MemOptSettingsClass", L"MemOpt \u00B7 \u8BBE\u7F6E",
        WS_POPUP,
        x, y, cx, cy, g_hwnd, NULL, GetModuleHandleW(NULL), NULL);
    SendMessageW(g_hSettingsDlg, WM_SETICON, ICON_BIG,
        (LPARAM)LoadIconW(GetModuleHandleW(NULL), (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT)));
    SendMessageW(g_hSettingsDlg, WM_SETICON, ICON_SMALL,
        (LPARAM)(HICON)LoadImageW(GetModuleHandleW(NULL), (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT),
                                   IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));
    ShowWindow(g_hSettingsDlg, SW_SHOW);
    UpdateWindow(g_hSettingsDlg);
}

/* ====== 主窗口 ====== */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        init_ui_res();

        /* Y 偏移（为自绘标题栏预留 32px）*/
        #define Y_OFF TITLE_BAR_H
        #define WIN_W 480
        #define PAD 20

        /* Hero 区 — 大号百分比 + 环形进度条视觉中心 */
        g_hPct = CreateWindowW(L"STATIC", L"--",
            WS_VISIBLE | WS_CHILD | SS_CENTER,
            PAD, 32 + Y_OFF, WIN_W - PAD * 2, 60, hwnd, NULL, NULL, NULL);

        /* Hero 区 — "内存已使用 X.X GB / XX.X GB" 信息文字 */
        g_hMemInfo = CreateWindowW(L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_CENTER,
            PAD, 96 + Y_OFF, WIN_W - PAD * 2, 22, hwnd, NULL, NULL, NULL);
        SendMessageW(g_hMemInfo, WM_SETFONT, (WPARAM)g_font_small, TRUE);

        /* 进度条改为 WM_PAINT 自绘，不再创建 PROGRESS_CLASS */
        g_hBar = NULL;

        /* 三张内存卡片（竖排）—— hero 底部 136, 卡片加高到 90px, 间距 12px
           （用户反馈"条太窄"，加高后进度条也能加粗到 8px） */
        int card_y  = 136 + Y_OFF;
        int card_h  = 90;
        int card_gap = 12;
        int card_w  = WIN_W - PAD * 2;
        
        g_hTotalMem = CreateWindowExW(0, L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW,
            PAD, card_y, card_w, card_h,
            hwnd, (HMENU)ID_CARD_TOTAL, NULL, NULL);
        g_hPageMem = CreateWindowExW(0, L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW,
            PAD, card_y + 1 * (card_h + card_gap), card_w, card_h,
            hwnd, (HMENU)ID_CARD_PAGE, NULL, NULL);
        g_hSysWS = CreateWindowExW(0, L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW,
            PAD, card_y + 2 * (card_h + card_gap), card_w, card_h,
            hwnd, (HMENU)ID_CARD_SYSWS, NULL, NULL);

        /* 底部按钮行：[立即清理] [设置] —— 统一高 44px，间距调整 */
        int btn_y = card_y + 3 * card_h + 2 * card_gap + 20;
        int btn_h = 44;
        CreateWindowW(L"BUTTON", L"立即清理",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            PAD, btn_y, WIN_W - PAD * 2 - 136, btn_h,
            hwnd, (HMENU)ID_BTN_CLEAN, NULL, NULL);
        CreateWindowW(L"BUTTON", L"设置",
            WS_VISIBLE | WS_CHILD | BS_OWNERDRAW,
            WIN_W - PAD - 120, btn_y, 120, btn_h,
            hwnd, (HMENU)ID_BTN_SETTINGS, NULL, NULL);

        /* 底部状态条 —— 设计稿风格：白底 1px 描边 + 左侧绿点（自绘）。
           高度改为 72px 支持两行：
           行1：[绿点] 后台清理已启用 · 每 X 分钟 · 阈值 Y%
           行2：     上次清理: xxx  释放 xxx MB（完整显示不截断） */
        int status_y = btn_y + btn_h + 20;
        g_hStatus = CreateWindowExW(0, L"STATIC", L"",
            WS_VISIBLE | WS_CHILD | SS_OWNERDRAW,
            PAD, status_y, WIN_W - PAD * 2, 72,
            hwnd, (HMENU)ID_TXT_STATUS, NULL, NULL);

        EnumChildWindows(hwnd, set_child_font, (LPARAM)g_font_ui);
        SendMessageW(g_hPct,   WM_SETFONT, (WPARAM)g_font_big,   TRUE);
        SendMessageW(g_hStatus, WM_SETFONT, (WPARAM)g_font_small, TRUE);

        #undef Y_OFF
        #undef WIN_W
        #undef PAD

        SetTimer(hwnd, ID_TIMER_TRAY, 3000, NULL);
        SetTimer(hwnd, ID_TIMER_AUTO, 30000, NULL);
        gui_refresh_status();
        return 0;
    }

    case WM_ERASEBKGND: {
        HDC hdc = (HDC)wp;
        RECT rc; GetClientRect(hwnd, &rc);
        FillRect(hdc, &rc, g_brush_bg);
        return 1;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wp;
        DWORD cid = GetDlgCtrlID((HWND)lp);
        if (cid == ID_TXT_STATUS || cid == ID_CARD_TOTAL ||
            cid == ID_CARD_PAGE  || cid == ID_CARD_SYSWS) {
            SetTextColor(hdc, RGB(77, 82, 89));
            SetBkColor(hdc, RGB(255, 255, 255));
            return (LRESULT)g_brush_card;
        }
        /* Hero 区 STATIC：白底 + 蓝色文字 */
        if ((HWND)lp == g_hPct) {
            SetTextColor(hdc, UI_ACCENT);
            SetBkColor(hdc, RGB(255, 255, 255));
            return (LRESULT)g_brush_card;
        }
        if ((HWND)lp == g_hMemInfo) {
            SetTextColor(hdc, RGB(94, 103, 118));
            SetBkColor(hdc, RGB(255, 255, 255));
            return (LRESULT)g_brush_card;
        }
        SetTextColor(hdc, UI_FG);
        SetBkColor(hdc, UI_BG);
        return (LRESULT)g_brush_bg;
    }

    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        RECT rc; GetClientRect(hwnd, &rc);

        /* 1) 自绘白色标题栏 */
        RECT rcTB = { 0, 0, rc.right, TITLE_BAR_H };
        HBRUSH brTB = CreateSolidBrush(TB_BG);
        FillRect(hdc, &rcTB, brTB);
        DeleteObject(brTB);

        /* 1b) 标题栏底部分隔线（弱化） */
        HPEN pnDiv = CreatePen(PS_SOLID, 1, TB_BORDER);
        HGDIOBJ opDv = SelectObject(hdc, pnDiv);
        MoveToEx(hdc, 0, TITLE_BAR_H, NULL);
        LineTo(hdc, rc.right, TITLE_BAR_H);
        SelectObject(hdc, opDv); DeleteObject(pnDiv);

        /* 2) M logo */
        draw_m_logo(hdc, 14, 5);

        /* 3) 标题文字 "MemOpt 内存优化" */
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, TB_FG);
        HFONT fTB = CreateFontW(-13, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
            DEFAULT_PITCH | FF_DONTCARE, L"Segoe UI");
        HGDIOBJ ofTB = SelectObject(hdc, fTB);
        RECT rcTitle = { 44, 0, 200, TITLE_BAR_H };
        DrawTextW(hdc, L"MemOpt \u5185\u5B58\u4F18\u5316", -1, &rcTitle,
                  DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        SelectObject(hdc, ofTB); DeleteObject(fTB);

        /* 4) 窗口按钮（最小化 / 关闭） */
        draw_win_button(hdc, rc.right - WIN_BTN_W*2 - 2, 2, 1,
            g_win_btn_hover == 1);
        draw_win_button(hdc, rc.right - WIN_BTN_W - 2, 2, -1,
            g_win_btn_hover == -1);

        /* 5) Hero 白色背景区（视觉主体，高度增加到 140） */
        int hero_bottom = TITLE_BAR_H + 150;
        RECT rcHero = { 0, TITLE_BAR_H, rc.right, hero_bottom };
        HBRUSH brHero = CreateSolidBrush(RGB(255, 255, 255));
        FillRect(hdc, &rcHero, brHero);
        DeleteObject(brHero);
        
        /* 6) Hero 底部柔和分隔线（替代生硬的 1px 线） */
        RECT rcDivider = { 0, hero_bottom, rc.right, hero_bottom + 1 };
        HBRUSH brDiv = CreateSolidBrush(RGB(240, 242, 246));
        FillRect(hdc, &rcDivider, brDiv);
        DeleteObject(brDiv);

        /* 7) 自绘进度条（居中加宽，视觉更扎实） */
        int bar_ht = 10;
        RECT rcBar = { 40, 106 + TITLE_BAR_H, rc.right - 40, 106 + TITLE_BAR_H + bar_ht };
        COLORREF bar_col = UI_ACCENT;
        /* 降低焦虑感：仅在 >85% 时变橙，>92% 变红 */
        if (g_progress_pct >= 92) bar_col = ALERT_RED;
        else if (g_progress_pct >= 85) bar_col = ALERT_ORANGE;
        
        /* 自定义更现代的进度条绘制（双层圆角+阴影感）*/
        {
            /* 背景轨道（更浅的灰） */
            HBRUSH brTk = CreateSolidBrush(RGB(235, 238, 244));
            HPEN pnTk = CreatePen(PS_SOLID, 1, RGB(235, 238, 244));
            HGDIOBJ ot = SelectObject(hdc, brTk);
            HGDIOBJ opT = SelectObject(hdc, pnTk);
            RoundRect(hdc, rcBar.left, rcBar.top, rcBar.right, rcBar.bottom, 5, 5);
            SelectObject(hdc, ot); SelectObject(hdc, opT);
            DeleteObject(brTk); DeleteObject(pnTk);
            
            /* 填充 */
            if (g_progress_pct > 0) {
                int fill_w = (int)((double)(rcBar.right - rcBar.left) * g_progress_pct / 100.0);
                if (fill_w > bar_ht) { /* 至少超过圆角半径 */
                    HBRUSH brF = CreateSolidBrush(bar_col);
                    HPEN pnF = CreatePen(PS_SOLID, 1, bar_col);
                    HGDIOBJ of = SelectObject(hdc, brF);
                    HGDIOBJ opF = SelectObject(hdc, pnF);
                    RoundRect(hdc, rcBar.left, rcBar.top, rcBar.left + fill_w, rcBar.bottom, 5, 5);
                    SelectObject(hdc, of); SelectObject(hdc, opF);
                    DeleteObject(brF); DeleteObject(pnF);
                }
            }
        }

        /* 8) 1px 边框（弱化：RGB(228, 230, 234)） */
        HPEN pnBorder = CreatePen(PS_SOLID, 1, RGB(226, 228, 234));
        HGDIOBJ opB = SelectObject(hdc, pnBorder);
        HGDIOBJ obB = SelectObject(hdc, GetStockObject(NULL_BRUSH));
        Rectangle(hdc, 0, 0, rc.right, rc.bottom);
        SelectObject(hdc, obB); SelectObject(hdc, opB);
        DeleteObject(pnBorder);

        EndPaint(hwnd, &ps);
        return 0;
    }

    /* 允许从标题栏区域拖动窗口 */
    case WM_NCHITTEST: {
        POINT pt = { GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
        ScreenToClient(hwnd, &pt);
        RECT rc; GetClientRect(hwnd, &rc);
        if (pt.y >= 0 && pt.y < TITLE_BAR_H) {
            /* 如果点到关闭/最小化按钮不拦截 */
            int btn = hit_win_button(hwnd, pt.x, pt.y);
            if (btn == 0) return HTCAPTION;
        }
        /* 窗口四边可调整大小 */
        if (pt.x < 4) return HTLEFT;
        if (pt.x > rc.right - 4) return HTRIGHT;
        if (pt.y < 4) return HTTOP;
        if (pt.y > rc.bottom - 4) return HTBOTTOM;
        if (pt.x < 4 && pt.y < 4) return HTTOPLEFT;
        if (pt.x > rc.right - 4 && pt.y < 4) return HTTOPRIGHT;
        if (pt.x < 4 && pt.y > rc.bottom - 4) return HTBOTTOMLEFT;
        if (pt.x > rc.right - 4 && pt.y > rc.bottom - 4) return HTBOTTOMRIGHT;
        return HTCLIENT;
    }

    /* 追踪窗口按钮 hover 状态 */
    case WM_MOUSEMOVE: {
        int mx = GET_X_LPARAM(lp), my = GET_Y_LPARAM(lp);
        int prev = g_win_btn_hover;
        g_win_btn_hover = hit_win_button(hwnd, mx, my);
        if (prev != g_win_btn_hover) InvalidateRect(hwnd, NULL, FALSE);
        return 0;
    }

    /* 窗口按钮点击：遵循托盘应用标准交互
       - X (Close) 按钮：隐藏窗口到系统托盘（而非退出程序）
       - Minimize 按钮：同样隐藏到托盘，避免任务栏残留
       真正的"退出"应通过托盘右键菜单实现 */
    case WM_LBUTTONDOWN: {
        int mx = GET_X_LPARAM(lp), my = GET_Y_LPARAM(lp);
        int btn = hit_win_button(hwnd, mx, my);
        if (btn == -1 || btn == 1) {
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        }
        break;
    }

    /* 鼠标离开窗口时清除 hover */
    case WM_MOUSELEAVE:
        g_win_btn_hover = 0;
        InvalidateRect(hwnd, NULL, FALSE);
        return 0;

    case WM_DRAWITEM: {
        DRAWITEMSTRUCT *di = (DRAWITEMSTRUCT *)lp;

        /* 三张内存卡片自绘：圆角白底 + label/value/badge + 底部进度条 */
        if (di->CtlID == ID_CARD_TOTAL || di->CtlID == ID_CARD_PAGE ||
            di->CtlID == ID_CARD_SYSWS) {
            const CardData *card;
            if      (di->CtlID == ID_CARD_TOTAL) card = &g_card_total;
            else if (di->CtlID == ID_CARD_PAGE)  card = &g_card_page;
            else                                  card = &g_card_sysws;
            return draw_memory_card(di->hDC, &di->rcItem, card);
        }

        /* 底部状态条：白底 1px 描边 + 绿点指示器 + 两行文字
           72px 高：
           行1（y = top + 20）：[绿点] 后台清理已启用 · 每 X 分钟 · 阈值 Y%
           行2（y = top + 44）：       上次清理: xxx  释放 xxx MB（完整显示不截断） */
        if (di->CtlID == ID_TXT_STATUS) {
            RECT *rc = &di->rcItem;
            HBRUSH brBg = CreateSolidBrush(RGB(255, 255, 255));
            HPEN   pnBd = CreatePen(PS_SOLID, 1, RGB(235, 236, 239));
            HGDIOBJ ob = SelectObject(di->hDC, brBg);
            HGDIOBJ op = SelectObject(di->hDC, pnBd);
            RoundRect(di->hDC, rc->left, rc->top, rc->right, rc->bottom, 10, 10);
            SelectObject(di->hDC, ob);
            SelectObject(di->hDC, op);
            DeleteObject(brBg);
            DeleteObject(pnBd);

            /* 绿点 3D 指示器（对准第一行中心 y = top + 24） */
            int cxDot = rc->left + 22;
            int cyDot = rc->top + 24;
            HBRUSH brHalo1 = CreateSolidBrush(RGB(215, 246, 228));
            HBRUSH brHalo2 = CreateSolidBrush(RGB(170, 230, 196));
            HBRUSH brHalo3 = CreateSolidBrush(ALERT_GREEN);
            SetBkMode(di->hDC, TRANSPARENT);
            HPEN pnN = (HPEN)GetStockObject(NULL_PEN);
            {   /* 外圈 12px 淡 */
                HGDIOBJ oh = SelectObject(di->hDC, brHalo1);
                HGDIOBJ op2 = SelectObject(di->hDC, pnN);
                Ellipse(di->hDC, cxDot - 6, cyDot - 6, cxDot + 6, cyDot + 6);
                SelectObject(di->hDC, op2);
                SelectObject(di->hDC, oh);
            }
            {   /* 中圈 9px 中 */
                HGDIOBJ oh = SelectObject(di->hDC, brHalo2);
                HGDIOBJ op2 = SelectObject(di->hDC, pnN);
                Ellipse(di->hDC, cxDot - 4, cyDot - 4, cxDot + 5, cyDot + 5);
                SelectObject(di->hDC, op2);
                SelectObject(di->hDC, oh);
            }
            {   /* 核心 6px 实绿 */
                HGDIOBJ oh = SelectObject(di->hDC, brHalo3);
                HGDIOBJ op2 = SelectObject(di->hDC, pnN);
                Ellipse(di->hDC, cxDot - 3, cyDot - 3, cxDot + 4, cyDot + 4);
                SelectObject(di->hDC, op2);
                SelectObject(di->hDC, oh);
            }
            DeleteObject(brHalo1);
            DeleteObject(brHalo2);
            DeleteObject(brHalo3);

            /* 文字：buf 格式 = "●\tline1\nline2"（○ 表示关闭）。
               按 \n 拆出两行：
               - 先把 \n 替换成 \0，让 line1 真正只到第一行结尾
                 （否则 DrawTextW 的 -1 长度会把 line2 也当成 line1 的尾巴，
                  导致第一行末尾出现"上次清理..."文字）
               - line1 前的 ●/○ + \t 前缀用 wcschr 跳掉。 */
            wchar_t buf[512];
            GetWindowTextW(di->hwndItem, buf, _countof(buf));
            wchar_t *nl = wcschr(buf, L'\n');   /* 找行分隔 */
            if (nl) { *nl = L'\0'; }            /* ★ 截断第一行！关键 */
            wchar_t *line1 = buf;
            wchar_t *line2 = nl ? (nl + 1) : L"";
            /* 跳过 line1 前缀：●/○ + \t（"●\t后台清理..." 里第一个 tab 前是前缀） */
            wchar_t *tab = wcschr(line1, L'\t');
            if (tab) line1 = tab + 1;
            /* 空保护：第一行前缀格式异常时就显示空串，不渲染垃圾 */
            if (!line1) line1 = L"";

            SetBkMode(di->hDC, TRANSPARENT);
            int textX = cxDot + 16;

            /* 行1：略深、略主字体 g_font_ui，y = top + 14 → top+34 (高 20) */
            SelectObject(di->hDC, g_font_ui);
            SetTextColor(di->hDC, RGB(60, 66, 78));
            RECT rcL1 = { textX, rc->top + 14, rc->right - 16, rc->top + 36 };
            DrawTextW(di->hDC, line1, -1, &rcL1,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);

            /* 行2：上次清理信息 — 小一号字体，颜色更淡，缩进保持与 line1 对齐 */
            SelectObject(di->hDC, g_font_small);
            SetTextColor(di->hDC, RGB(124, 133, 148));
            RECT rcL2 = { textX, rc->top + 42, rc->right - 16, rc->top + 64 };
            DrawTextW(di->hDC, line2, -1, &rcL2,
                      DT_LEFT | DT_SINGLELINE | DT_VCENTER | DT_END_ELLIPSIS);
            return TRUE;
        }

        if (di->CtlID == ID_BTN_CLEAN || di->CtlID == ID_BTN_SETTINGS) {
            BOOL pressed = (di->itemState & ODS_SELECTED) != 0;
            COLORREF bg, fg;
            BOOL is_primary = (di->CtlID == ID_BTN_CLEAN);
            if (is_primary) {
                bg = pressed ? RGB(0, 94, 172) : UI_ACCENT;
                fg = RGB(255, 255, 255);
            } else {
                bg = pressed ? RGB(230, 233, 238) : RGB(255, 255, 255);
                fg = RGB(75, 85, 99);
            }
            HBRUSH br = CreateSolidBrush(bg);
            HPEN pn = CreatePen(PS_SOLID, 1,
                                is_primary ? bg : RGB(216, 221, 230));
            HGDIOBJ ob = SelectObject(di->hDC, br);
            HGDIOBJ op = SelectObject(di->hDC, pn);
            RoundRect(di->hDC, di->rcItem.left, di->rcItem.top,
                      di->rcItem.right, di->rcItem.bottom, 8, 8);
            SelectObject(di->hDC, ob);
            SelectObject(di->hDC, op);
            DeleteObject(br);
            DeleteObject(pn);
            SetBkMode(di->hDC, TRANSPARENT);
            SetTextColor(di->hDC, fg);
            SelectObject(di->hDC, g_font_ui);
            wchar_t txt[64]; GetWindowTextW(di->hwndItem, txt, 64);
            DrawTextW(di->hDC, txt, -1, &di->rcItem,
                      DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            return TRUE;
        }
        break;
    }

    case WM_HSCROLL:
        return 0; /* 兼容占位 */

    case WM_COMMAND:
        if (LOWORD(wp) == ID_BTN_CLEAN) {
            gui_clean();
        } else if (LOWORD(wp) == ID_BTN_SETTINGS) {
            open_settings();
        }
        return 0;

    case WM_TIMER:
        if (wp == ID_TIMER_TRAY) {
            gui_update_tray();
            gui_refresh_status();
        } else if (wp == ID_TIMER_AUTO) {
            if (g_auto_enabled && is_elevated())
                auto_clean_if_needed();
        }
        return 0;

    case WM_CLEAN_DONE: {
        ULONG64 freed = bytes_freed();
        g_last_freed = freed;
        int source = (int)wp;
        if (source == CLEAN_SRC_AUTO_AGGRO)
            wcscpy_s(g_last_clean_tag, _countof(g_last_clean_tag), L"自动-强力");
        else if (source == CLEAN_SRC_AUTO_CONSERV)
            wcscpy_s(g_last_clean_tag, _countof(g_last_clean_tag), L"自动-保守");
        else
            wcscpy_s(g_last_clean_tag, _countof(g_last_clean_tag), L"手动");

        if (source == CLEAN_SRC_MANUAL) {
            gui_report(freed);  /* 仅手动模式弹 MessageBox */
        } else {
            wchar_t buf[128];
            swprintf(buf, _countof(buf), L"[%ls] 清理完成，释放 %.1f MB",
                     g_last_clean_tag, freed / (1024.0 * 1024.0));
            log_msg(L"%ls", buf);
        }
        gui_update_tray();
        gui_refresh_status();
        return 0;
    }

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        if (g_hSettingsDlg) DestroyWindow(g_hSettingsDlg);
        KillTimer(hwnd, ID_TIMER_TRAY);
        KillTimer(hwnd, ID_TIMER_AUTO);
        Shell_NotifyIconW(NIM_DELETE, &g_nid);
        if (g_hTrayIcon) { DestroyIcon(g_hTrayIcon); g_hTrayIcon = NULL; }
        if (g_font_ui)    DeleteObject(g_font_ui);
        if (g_font_big)   DeleteObject(g_font_big);
        if (g_font_small) DeleteObject(g_font_small);
        if (g_font_mid)   DeleteObject(g_font_mid);
        if (g_brush_bg)   DeleteObject(g_brush_bg);
        if (g_brush_card) DeleteObject(g_brush_card);
        if (g_brush_settings_bg) DeleteObject(g_brush_settings_bg);
        if (g_brush_hint) DeleteObject(g_brush_hint);
        PostQuitMessage(0);
        return 0;

    case WM_USER + 1: {
        UINT u = LOWORD(lp);
        if (u == WM_LBUTTONUP) {
            gui_toggle_window();
        } else if (u == WM_RBUTTONUP) {
            POINT pt; GetCursorPos(&pt);
            HMENU menu = CreatePopupMenu();
            AppendMenuW(menu, MF_STRING, ID_TRAY_SHOW, IsWindowVisible(hwnd) ? L"隐藏主窗口" : L"显示主窗口");
            AppendMenuW(menu, MF_STRING, ID_BTN_CLEAN, L"清理内存");
            AppendMenuW(menu, MF_STRING, ID_BTN_SETTINGS, L"设置");
            AppendMenuW(menu, MF_SEPARATOR, 0, NULL);
            AppendMenuW(menu, MF_STRING, ID_TRAY_EXIT, L"退出");
            SetForegroundWindow(hwnd);
            UINT id = TrackPopupMenu(menu, TPM_RETURNCMD | TPM_NONOTIFY, pt.x, pt.y, 0, hwnd, NULL);
            DestroyMenu(menu);
            if (id == ID_TRAY_SHOW) gui_toggle_window();
            else if (id == ID_BTN_CLEAN) gui_clean();
            else if (id == ID_BTN_SETTINGS) open_settings();
            else if (id == ID_TRAY_EXIT) {
                /* 真退出：清理托盘图标，再发退出消息 */
                Shell_NotifyIconW(NIM_DELETE, &g_nid);
                PostQuitMessage(0);
            }
        }
        return 0;
    }

    default:
        if (msg == g_taskbar_created) {
            Shell_NotifyIconW(NIM_ADD, &g_nid);
        }
        break;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

static void run_gui(void) {
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    WNDCLASSW wc = {0};
    wc.style         = CS_DBLCLKS;
    wc.lpfnWndProc   = WndProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.hCursor       = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = CreateSolidBrush(UI_BG);
    wc.lpszClassName = L"MemOptClass";
    RegisterClassW(&wc);

    /* 主窗口：WS_POPUP 自绘标题栏 —— 480x620：更宽松面板比例，
       让三张卡片、底部状态条(两行)不挤压 */
    g_hwnd = CreateWindowExW(0, L"MemOptClass", L"MemOpt",
        WS_POPUP | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 480, 620,
        NULL, NULL, GetModuleHandleW(NULL), NULL);
    /* 强制使用图标资源（覆盖系统默认） */
    SendMessageW(g_hwnd, WM_SETICON, ICON_BIG,
        (LPARAM)LoadIconW(wc.hInstance, (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT)));
    SendMessageW(g_hwnd, WM_SETICON, ICON_SMALL,
        (LPARAM)(HICON)LoadImageW(wc.hInstance, (LPCWSTR)MAKEINTRESOURCE(IDI_MEMOPT),
                                   IMAGE_ICON, 16, 16, LR_DEFAULTCOLOR));

    /* 应用启动时刻：auto_clean_if_needed 首次触发时做启动防抖，
       避免开机后系统正忙时立刻抢 I/O */
    extern ULONG64 g_app_start_tick;
    g_app_start_tick = GetTickCount64();

    /* 托盘图标 */
    g_taskbar_created = RegisterWindowMessageW(L"TaskbarCreated");
    memset(&g_nid, 0, sizeof(g_nid));
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = g_hwnd;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_USER + 1;
    {
        MEMORYSTATUSEX m2;
        m2.dwLength = sizeof(m2);
        GlobalMemoryStatusEx(&m2);
        int pct2 = (int)m2.dwMemoryLoad;
        if (pct2 > 100) pct2 = 100;
        g_nid.hIcon = create_memory_icon(pct2);
    }
    wcscpy_s(g_nid.szTip, _countof(g_nid.szTip), L"MemOpt");
    Shell_NotifyIconW(NIM_ADD, &g_nid);

    ShowWindow(g_hwnd, SW_HIDE);
    gui_update_tray();

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

/* ---------- 入口 ---------- */

/* 前向声明 */
int wmain(int argc, wchar_t **argv);

/* GUI 子系统入口：将 WinMain 参数转为 wmain 的 argc/argv */
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {
    (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    int ret = wmain(argc, argv);
    LocalFree(argv);
    return ret;
}

/* 动态启用 DPI 感知（Win10 1703+ PerMonitorV2 → SystemAware，旧系统回退
   SetProcessDPIAware）。必须在创建任何窗口之前调用，否则自绘界面会被
   系统按位图拉伸导致模糊（4K/125% 缩放下尤其明显）。 */
static void setup_dpi_awareness(void) {
    HMODULE hUser = GetModuleHandleW(L"user32.dll");
    if (!hUser) return;
    /* SetProcessDpiAwarenessContext: Win10 1703+ */
    typedef BOOL (WINAPI *PSetProcessDpiAwarenessContext)(HANDLE value);
    void *fn = (void *)GetProcAddress(hUser, "SetProcessDpiAwarenessContext");
    if (fn) {
        PSetProcessDpiAwarenessContext pSet = (PSetProcessDpiAwarenessContext)fn;
        if (pSet((HANDLE)-4)) return;  /* DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 */
        if (pSet((HANDLE)-2)) return;  /* DPI_AWARENESS_CONTEXT_SYSTEM_AWARE      */
    }
    /* 旧系统回退 */
    typedef BOOL (WINAPI *PSetProcessDPIAware)(void);
    void *fn2 = (void *)GetProcAddress(hUser, "SetProcessDPIAware");
    if (fn2) ((PSetProcessDPIAware)fn2)();
}

int wmain(int argc, wchar_t **argv) {
    setup_dpi_awareness();   /* 创建窗口前启用 DPI 感知 */

    /* 单实例互斥：防止双开后两个实例的清理线程并发调用内核内存 API
       （并发清理正是 0xF7 蓝屏风险来源之一）。已有实例时：
       GUI 模式弹提示并退出，命令行模式静默退出。 */
    {
        HANDLE hMutex = CreateMutexW(NULL, TRUE, L"Local\\MemOpt_SingleInstance");
        if (hMutex && GetLastError() == ERROR_ALREADY_EXISTS) {
            if (argc < 2)
                MessageBoxW(NULL,
                    L"MemOpt 已在运行。\n如需立即清理，请使用托盘菜单或主窗口按钮。",
                    L"MemOpt", MB_OK | MB_ICONINFORMATION);
            CloseHandle(hMutex);
            return 0;
        }
        /* 首次实例：持有句柄直到进程退出（进程终止时系统自动释放互斥锁） */
    }

    init_os_version();
    resolve_nt();
    load_config();   /* 从 INI 文件加载持久化设置 */

    /* 启动横幅：方便在日志中定位每次启动的配置与权限状态 */
    {
        MEMORYSTATUSEX m;
        m.dwLength = sizeof(m);
        GlobalMemoryStatusEx(&m);
        log_msg(L"== MemOpt 启动 == 内存占用 %u%% | 阈值 %d%% | 间隔 %d 分钟 | "
                L"强力 %ls | 后台自动 %ls | 管理员 %ls",
                (unsigned)m.dwMemoryLoad,
                g_auto_threshold, g_auto_interval / 60000,
                g_auto_aggressive ? L"开" : L"关",
                g_auto_enabled ? L"开" : L"关",
                is_elevated() ? L"是" : L"否");
    }

    if (!is_elevated()) {
        /* 启动时自动调起 UAC 获取管理员权限；用户拒绝则以当前权限继续 */
        if (relaunch_elevated(argc, argv))
            return 0;
        /* 命令行模式必须提权；GUI 模式可继续(清理时另行提示) */
        if (argc >= 2 && !_wcsicmp(argv[1], L"clean")) {
            wprintf(L"Error: memory cleaning requires administrator privileges. Right-click and 'Run as administrator'.\n");
            return 1;
        }
    } else {
        enable_privilege(L"SeIncreaseQuotaPrivilege");
        if (!enable_privilege(L"SeProfileSingleProcessPrivilege"))
            enable_privilege(L"SeProfSingleProcessPrivilege");
    }

    ULONG mask = parse_args(argc, argv);

    if (mask == (ULONG)-1) {
        run_gui();
        return 0;
    }
    if (mask == (ULONG)-2) {
        return 0;
    }

    log_msg(L"== Command-line clean started ==");
    do_clean(mask, 1);
    ULONG64 freed = bytes_freed();
    log_msg(L"== Done. Freed about %.2f MB ==", freed / (1024.0 * 1024.0));
    return 0;
}
