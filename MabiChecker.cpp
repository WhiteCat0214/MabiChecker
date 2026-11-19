// MabiChecker.cpp
// 瑪奇 Mabinogi (台服) 遊戲檔案完整性檢查 / 修復工具
//
// 編譯：請在「x64 Native Tools Command Prompt for VS 2022」執行 build.bat
// 使用：放在遊戲目錄(與 Client.exe、version.dat 同一層)執行
//
// 流程摘要
//   檢查：讀 version.dat -> 抓 patch_live.txt(版本/下載位置) -> 抓 version.txt
//         -> 逐檔比對大小與 MD5 -> 列出結果與 summary
//   更新：只重新下載異常檔案到暫存資料夾，驗證 MD5 後才取代原檔
//   下載網址規則(由官方啟動器封包確認)： http://<host>/Mabinogi/live/Mabinogi/<檔案路徑>

#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <tlhelp32.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

typedef unsigned long long u64;

// ---------------------------------------------------------------- 常數
static const wchar_t* kCdnHost        = L"tw.cdnpatch.mabinogi.beanfun.com";
static const wchar_t* kPatchLivePath  = L"/mabinogi/patch_live.txt";
static const wchar_t* kDefaultBase    = L"/Mabinogi/live";      // patch_live 讀不到時的備用值
static const INTERNET_PORT kDefaultPort = 80;
static const wchar_t* kTmpDirName     = L"_MabiChecker_tmp";
static const wchar_t* kLogFileName    = L"MabiChecker_log.txt";   // 儲存報告時的預設檔名

enum { IDC_EDIT = 101, IDC_CHECK, IDC_UPDATE, IDC_CLOSE, IDC_PROGRESS, IDC_STATUS, IDC_COPY, IDC_SAVE };
enum { WM_APP_LOG = WM_APP + 1, WM_APP_DONE = WM_APP + 2 };
enum { TIMER_PROGRESS = 1 };

// ---------------------------------------------------------------- 資料結構
struct Entry {
    std::wstring rel;      // 相對路徑(正斜線，與 version.txt 相同)
    u64          size = 0;
    std::string  md5;      // 小寫 32 字元
    int          ver = 0;
    bool         placeholder = false;   // size=0 且 md5 全 0：廢棄/佔位項目
};

struct PatchLive {
    bool         ok = false;
    int          accept = 1;
    int          version = -1;
    bool         ftpUnsupported = false;
    std::wstring host = kCdnHost;
    INTERNET_PORT port = kDefaultPort;
    std::wstring base = kDefaultBase;
};

// ---------------------------------------------------------------- 全域狀態
static HWND g_hwnd, g_hEdit, g_hCheck, g_hUpdate, g_hClose, g_hProgress, g_hStatus, g_hCopy, g_hSave;
static HFONT g_fontUi, g_fontMono;
static int g_dpi = 96;

static std::wstring g_gameDir;
static std::atomic<int>  g_busy{0};          // 0 閒置 / 1 檢查中 / 2 更新中
static std::atomic<bool> g_cancel{false};
static std::atomic<u64>  g_done{0}, g_total{0};

static std::mutex   g_logMtx;
static std::wstring g_report;                // 完整報告(存檔用)

static std::vector<Entry> g_bad;             // 需要修復的檔案(僅在 busy==0 或由工作執行緒存取)
static bool         g_checkComplete = false;
static int          g_checkedVer = -1;       // 檢查當下 本機=線上 的版本
static std::wstring g_host = kCdnHost;
static INTERNET_PORT g_port = kDefaultPort;
static std::wstring g_base = kDefaultBase;

static BCRYPT_ALG_HANDLE g_hAlg = nullptr;
static DWORD g_hashObjLen = 0;

// ---------------------------------------------------------------- 工具函式
static int S(int v) { return MulDiv(v, g_dpi, 96); }

static std::wstring Fmt(const wchar_t* f, ...) {
    va_list ap;
    va_start(ap, f);
    int n = _vscwprintf(f, ap);
    va_end(ap);
    std::wstring s(n > 0 ? n : 0, L'\0');
    if (n > 0) {
        va_start(ap, f);
        vswprintf_s(&s[0], (size_t)n + 1, f, ap);
        va_end(ap);
    }
    return s;
}

static std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), &w[0], n);
    return w;
}

static std::string Narrow(const std::wstring& w) {
    if (w.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.data(), (int)w.size(), &s[0], n, nullptr, nullptr);
    return s;
}

static std::string LowerA(std::string s) {
    for (auto& c : s) if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return s;
}

static std::wstring FmtBytes(u64 b) {
    static const wchar_t* unit[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double v = (double)b;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    if (i == 0) return Fmt(L"%llu B", b);
    return Fmt(L"%.2f %ls", v, unit[i]);
}

static std::wstring FmtDuration(u64 sec) {
    u64 h = sec / 3600, m = (sec / 60) % 60, s = sec % 60;
    if (h) return Fmt(L"%llu:%02llu:%02llu", h, m, s);
    return Fmt(L"%llu:%02llu", m, s);
}

static std::wstring Backslash(std::wstring s) {
    std::replace(s.begin(), s.end(), L'/', L'\\');
    return s;
}

// 加上 \\?\ 前綴以支援長路徑(UNC 路徑不處理)
static std::wstring Lp(const std::wstring& p) {
    if (p.size() >= 3 && p[1] == L':' && p[2] == L'\\') return L"\\\\?\\" + p;
    return p;
}

static u64 FileSizeOrZero(const std::wstring& path) {
    WIN32_FILE_ATTRIBUTE_DATA d;
    if (!GetFileAttributesExW(Lp(path).c_str(), GetFileExInfoStandard, &d)) return 0;
    return ((u64)d.nFileSizeHigh << 32) | d.nFileSizeLow;
}

static void EnsureParentDirs(const std::wstring& filePath) {
    // 逐層建立父資料夾(filePath 為完整路徑)
    size_t start = 3;  // 跳過 "X:\"
    for (size_t i = start; i < filePath.size(); ++i) {
        if (filePath[i] == L'\\') {
            std::wstring dir = filePath.substr(0, i);
            CreateDirectoryW(Lp(dir).c_str(), nullptr);   // 已存在時失敗，忽略
        }
    }
}

static void RemoveEmptyDirs(const std::wstring& dir) {
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(Lp(dir + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) {
                RemoveEmptyDirs(dir + L"\\" + fd.cFileName);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    RemoveDirectoryW(Lp(dir).c_str());   // 非空時自然失敗
}

// version.txt 路徑安全檢查：不允許絕對路徑、.. 與非法字元
static bool SafeRel(const std::wstring& r) {
    if (r.empty()) return false;
    if (r[0] == L'/' || r[0] == L'\\') return false;
    if (r.find_first_of(L":*?\"<>|\\") != std::wstring::npos) return false;
    size_t pos = 0;
    while (pos <= r.size()) {
        size_t e = r.find(L'/', pos);
        if (e == std::wstring::npos) e = r.size();
        std::wstring part = r.substr(pos, e - pos);
        if (part.empty() || part == L"." || part == L"..") return false;
        pos = e + 1;
    }
    return true;
}

static std::wstring UrlEncodePath(const std::wstring& rel) {
    std::string u = Narrow(rel);
    std::wstring out;
    for (unsigned char c : u) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~' || c == '/') {
            out += (wchar_t)c;
        } else {
            out += Fmt(L"%%%02X", (unsigned)c);
        }
    }
    return out;
}

// ---------------------------------------------------------------- 記錄(工作執行緒 -> UI)
static void Log(const std::wstring& line) {
    {
        std::lock_guard<std::mutex> lk(g_logMtx);
        g_report += line;
        g_report += L"\r\n";
    }
    auto* p = new std::wstring(line + L"\r\n");
    if (!g_hwnd || !PostMessageW(g_hwnd, WM_APP_LOG, 0, (LPARAM)p)) delete p;
}

// ---------------------------------------------------------------- MD5 (Windows CNG)
static bool InitHash() {
    if (BCryptOpenAlgorithmProvider(&g_hAlg, BCRYPT_MD5_ALGORITHM, nullptr, 0) < 0) return false;
    DWORD cb = 0;
    if (BCryptGetProperty(g_hAlg, BCRYPT_OBJECT_LENGTH, (PUCHAR)&g_hashObjLen, sizeof(DWORD), &cb, 0) < 0) return false;
    return true;
}

enum Md5Result { MD5_OK, MD5_OPENFAIL, MD5_READFAIL, MD5_CANCEL, MD5_INTERNAL };

static Md5Result Md5File(const std::wstring& path, std::string& hex, DWORD& err, bool countProgress) {
    err = 0;
    HANDLE hf = CreateFileW(Lp(path).c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (hf == INVALID_HANDLE_VALUE) { err = GetLastError(); return MD5_OPENFAIL; }

    std::vector<UCHAR> obj(g_hashObjLen);
    BCRYPT_HASH_HANDLE hh = nullptr;
    if (BCryptCreateHash(g_hAlg, &hh, obj.data(), (ULONG)obj.size(), nullptr, 0, 0) < 0) {
        CloseHandle(hf);
        return MD5_INTERNAL;
    }

    std::vector<UCHAR> buf(1 << 20);
    Md5Result res = MD5_OK;
    for (;;) {
        if (g_cancel) { res = MD5_CANCEL; break; }
        DWORD n = 0;
        if (!ReadFile(hf, buf.data(), (DWORD)buf.size(), &n, nullptr)) { err = GetLastError(); res = MD5_READFAIL; break; }
        if (n == 0) break;
        if (BCryptHashData(hh, buf.data(), n, 0) < 0) { res = MD5_INTERNAL; break; }
        if (countProgress) g_done += n;
    }

    UCHAR dig[16] = {};
    if (res == MD5_OK && BCryptFinishHash(hh, dig, 16, 0) < 0) res = MD5_INTERNAL;
    BCryptDestroyHash(hh);
    CloseHandle(hf);

    if (res == MD5_OK) {
        static const char* hx = "0123456789abcdef";
        hex.assign(32, '0');
        for (int i = 0; i < 16; ++i) { hex[i * 2] = hx[dig[i] >> 4]; hex[i * 2 + 1] = hx[dig[i] & 15]; }
    }
    return res;
}

// ---------------------------------------------------------------- HTTP (WinHTTP)
struct HReq {
    HINTERNET h;
    explicit HReq(HINTERNET x) : h(x) {}
    ~HReq() { if (h) WinHttpCloseHandle(h); }
};

class Http {
public:
    HINTERNET ses = nullptr, con = nullptr;
    ~Http() { Close(); }
    void Close() {
        if (con) { WinHttpCloseHandle(con); con = nullptr; }
        if (ses) { WinHttpCloseHandle(ses); ses = nullptr; }
    }
    bool Open(const std::wstring& host, INTERNET_PORT port) {
        Close();
        ses = WinHttpOpen(L"MabiChecker/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                          WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!ses) ses = WinHttpOpen(L"MabiChecker/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!ses) return false;
        WinHttpSetTimeouts(ses, 10000, 10000, 15000, 30000);
        con = WinHttpConnect(ses, host.c_str(), port, 0);
        return con != nullptr;
    }

    // 送出 GET 並收到回應標頭。傳輸失敗回傳 nullptr；否則回傳 request 並填入狀態碼與 Content-Length
    HINTERNET Begin(const std::wstring& path, const std::wstring& extraHeaders,
                    int& status, u64& contentLen, std::wstring& err) {
        status = 0;
        contentLen = (u64)-1;
        HINTERNET req = WinHttpOpenRequest(con, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
                                           WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        if (!req) { err = Fmt(L"WinHttpOpenRequest 失敗 (%lu)", GetLastError()); return nullptr; }
        std::wstring hdr = L"Cache-Control: no-cache\r\n" + extraHeaders;
        if (!WinHttpSendRequest(req, hdr.c_str(), (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(req, nullptr)) {
            err = Fmt(L"連線失敗 (錯誤碼 %lu)", GetLastError());
            WinHttpCloseHandle(req);
            return nullptr;
        }
        DWORD sc = 0, sz = sizeof(sc);
        WinHttpQueryHeaders(req, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                            WINHTTP_HEADER_NAME_BY_INDEX, &sc, &sz, WINHTTP_NO_HEADER_INDEX);
        status = (int)sc;
        wchar_t cl[64] = {};
        DWORD cb = sizeof(cl);
        if (WinHttpQueryHeaders(req, WINHTTP_QUERY_CONTENT_LENGTH, WINHTTP_HEADER_NAME_BY_INDEX, cl, &cb,
                                WINHTTP_NO_HEADER_INDEX)) {
            contentLen = _wcstoui64(cl, nullptr, 10);
        }
        return req;
    }

    bool GetSmall(const std::wstring& path, std::string& out, int& status, std::wstring& err) {
        u64 cl;
        HReq r(Begin(path, L"", status, cl, err));
        if (!r.h) return false;
        if (status != 200) { err = Fmt(L"HTTP %d", status); return false; }
        out.clear();
        std::vector<char> buf(65536);
        for (;;) {
            if (g_cancel) { err = L"已中止"; return false; }
            DWORD n = 0;
            if (!WinHttpReadData(r.h, buf.data(), (DWORD)buf.size(), &n)) {
                err = Fmt(L"讀取失敗 (錯誤碼 %lu)", GetLastError());
                return false;
            }
            if (n == 0) break;
            out.append(buf.data(), n);
            if (out.size() > (64u << 20)) { err = L"回應過大"; return false; }
        }
        return true;
    }
};

enum DlResult { DL_OK, DL_FAIL_RETRY, DL_FAIL_FATAL, DL_CANCEL };

// 下載到 part 檔(支援續傳)。成功只代表「收到完整位元組數」，MD5 由呼叫端驗證
static DlResult Download(Http& http, const std::wstring& urlPath, const std::wstring& part,
                         u64 expected, std::wstring& err) {
    u64 have = FileSizeOrZero(part);
    if (have > expected) { DeleteFileW(Lp(part).c_str()); have = 0; }
    if (have == expected && expected > 0) { g_done += have; return DL_OK; }   // 之前已下載完整

    std::wstring extra;
    if (have > 0) extra = Fmt(L"Range: bytes=%llu-\r\n", have);

    int st = 0;
    u64 cl = (u64)-1;
    HReq r(http.Begin(urlPath, extra, st, cl, err));
    if (!r.h) return DL_FAIL_RETRY;

    if (st == 404 || st == 403 || st == 410) {
        err = Fmt(L"伺服器回應 HTTP %d（檔案不存在或無權限）", st);
        return DL_FAIL_FATAL;
    }
    if (st == 416) {
        DeleteFileW(Lp(part).c_str());
        err = L"續傳位置無效，改為重新下載";
        return DL_FAIL_RETRY;
    }
    if (st != 200 && st != 206) { err = Fmt(L"HTTP %d", st); return DL_FAIL_RETRY; }

    bool append = (st == 206);
    if (append) g_done += have; else have = 0;     // 回 200 表示伺服器不支援續傳，從頭來
    u64 want = expected - have;
    if (cl != (u64)-1 && cl != want) {
        err = Fmt(L"伺服器回報大小 %llu 與清單不符（預期 %llu）", cl, want);
        return DL_FAIL_FATAL;
    }

    HANDLE hf = CreateFileW(Lp(part).c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                            append ? OPEN_EXISTING : CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        err = Fmt(L"無法寫入暫存檔 (錯誤碼 %lu)", GetLastError());
        return DL_FAIL_FATAL;
    }
    if (append) { LARGE_INTEGER z; z.QuadPart = 0; SetFilePointerEx(hf, z, nullptr, FILE_END); }

    std::vector<char> buf(256 * 1024);
    u64 got = 0;
    for (;;) {
        if (g_cancel) { CloseHandle(hf); return DL_CANCEL; }
        DWORD n = 0;
        if (!WinHttpReadData(r.h, buf.data(), (DWORD)buf.size(), &n)) {
            err = Fmt(L"下載中斷 (錯誤碼 %lu)", GetLastError());
            CloseHandle(hf);
            return DL_FAIL_RETRY;
        }
        if (n == 0) break;
        DWORD w = 0;
        if (!WriteFile(hf, buf.data(), n, &w, nullptr) || w != n) {
            err = Fmt(L"寫入暫存檔失敗 (錯誤碼 %lu)", GetLastError());
            CloseHandle(hf);
            return DL_FAIL_FATAL;
        }
        got += n;
        g_done += n;
    }
    CloseHandle(hf);
    if (got != want) {
        err = Fmt(L"下載中斷（收到 %llu / %llu bytes）", got, want);
        return DL_FAIL_RETRY;
    }
    return DL_OK;
}

// ---------------------------------------------------------------- 版本與清單
static int ReadLocalVersion() {
    HANDLE hf = CreateFileW(Lp(g_gameDir + L"\\version.dat").c_str(), GENERIC_READ,
                            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) return -1;
    DWORD v = 0, n = 0;
    BOOL ok = ReadFile(hf, &v, 4, &n, nullptr);
    CloseHandle(hf);
    if (!ok || n != 4) return -1;
    return (int)v;      // little-endian DWORD
}

static std::string Trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && (s[a] == ' ' || s[a] == '\t' || s[a] == '\r' || s[a] == '\n')) ++a;
    while (b > a && (s[b - 1] == ' ' || s[b - 1] == '\t' || s[b - 1] == '\r' || s[b - 1] == '\n')) --b;
    return s.substr(a, b - a);
}

// 解析 patch_live.txt 的 ftp 欄位： host[:port]/path
static void ParseFtpField(const std::string& v, PatchLive& pl) {
    std::string s = Trim(v);
    std::string low = LowerA(s);
    if (low.rfind("http://", 0) == 0) s = s.substr(7);
    else if (low.rfind("ftp:", 0) == 0 || low.rfind("devftp:", 0) == 0 || low.rfind("ftp://", 0) == 0) {
        pl.ftpUnsupported = true;
        return;
    }
    size_t slash = s.find('/');
    std::string hostport = (slash == std::string::npos) ? s : s.substr(0, slash);
    std::string path = (slash == std::string::npos) ? "" : s.substr(slash);
    while (!path.empty() && path.back() == '/') path.pop_back();
    size_t colon = hostport.find(':');
    std::string host = (colon == std::string::npos) ? hostport : hostport.substr(0, colon);
    int port = (colon == std::string::npos) ? 80 : atoi(hostport.substr(colon + 1).c_str());
    if (host.empty() || port <= 0 || port > 65535) return;
    pl.host = Widen(host);
    pl.port = (INTERNET_PORT)port;
    if (!path.empty()) pl.base = Widen(path);
}

static bool FetchPatchLive(PatchLive& pl, std::wstring& err) {
    Http h;
    if (!h.Open(kCdnHost, kDefaultPort)) { err = L"無法初始化網路連線"; return false; }
    std::string body;
    int st = 0;
    if (!h.GetSmall(kPatchLivePath, body, st, err)) return false;

    std::map<std::string, std::string> kv;
    size_t pos = 0;
    while (pos < body.size()) {
        size_t eol = body.find('\n', pos);
        if (eol == std::string::npos) eol = body.size();
        std::string line = Trim(body.substr(pos, eol - pos));
        pos = eol + 1;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        kv[Trim(line.substr(0, eq))] = Trim(line.substr(eq + 1));
    }
    if (kv.count("patch_version")) pl.version = atoi(kv["patch_version"].c_str());
    if (kv.count("patch_accept")) pl.accept = atoi(kv["patch_accept"].c_str());
    if (kv.count("ftp")) ParseFtpField(kv["ftp"], pl);
    pl.ok = (pl.version >= 0);
    if (!pl.ok) err = L"patch_live.txt 內容無法解析";
    return pl.ok;
}

static void ParseVersionTxt(const std::string& data, std::vector<Entry>& out, int& badLines, int& maxVer) {
    size_t pos = 0;
    if (data.size() >= 3 && (unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF) pos = 3;
    while (pos < data.size()) {
        size_t eol = data.find('\n', pos);
        if (eol == std::string::npos) eol = data.size();
        std::string line = data.substr(pos, eol - pos);
        pos = eol + 1;
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ')) line.pop_back();
        if (line.empty()) continue;

        std::vector<std::string> f;
        size_t s = 0;
        for (;;) {
            size_t t = line.find('\t', s);
            if (t == std::string::npos) { f.push_back(line.substr(s)); break; }
            f.push_back(line.substr(s, t - s));
            s = t + 1;
        }
        bool ok = f.size() >= 4 && !f[0].empty() && f[2].size() == 32;
        if (ok) for (char c : f[2]) if (!isxdigit((unsigned char)c)) { ok = false; break; }
        if (!ok) { ++badLines; continue; }

        Entry e;
        e.rel = Widen(f[0]);
        e.size = _strtoui64(f[1].c_str(), nullptr, 10);
        e.md5 = LowerA(f[2]);
        e.ver = atoi(f[3].c_str());
        e.placeholder = (e.size == 0 && e.md5 == std::string(32, '0'));
        maxVer = std::max(maxVer, e.ver);
        out.push_back(std::move(e));
    }
}

// ---------------------------------------------------------------- 遊戲是否執行中
static bool GameRunningHere(std::wstring& whichExe) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    bool found = false;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"Client.exe") && _wcsicmp(pe.szExeFile, L"clientd.exe") &&
                _wcsicmp(pe.szExeFile, L"Mabinogi.exe")) continue;
            HANDLE hp = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hp) continue;
            wchar_t buf[2048];
            DWORD n = 2048;
            if (QueryFullProcessImageNameW(hp, 0, buf, &n)) {
                std::wstring full(buf, n);
                size_t bs = full.find_last_of(L'\\');
                if (bs != std::wstring::npos && _wcsicmp(full.substr(0, bs).c_str(), g_gameDir.c_str()) == 0) {
                    found = true;
                    whichExe = pe.szExeFile;
                }
            }
            CloseHandle(hp);
        } while (!found && Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

// ---------------------------------------------------------------- 檢查工作
static void RunCheck() {
    g_bad.clear();
    g_checkComplete = false;
    g_checkedVer = -1;
    const u64 t0 = GetTickCount64();

    Log(L"=== 檔案完整性檢查 ===");
    Log(Fmt(L"目前目錄：%ls", g_gameDir.c_str()));

    // 1. 本機版本
    int localVer = ReadLocalVersion();
    if (localVer < 0) {
        Log(L"[錯誤] 讀不到 version.dat。請確認本程式放在遊戲目錄下。");
        return;
    }
    Log(Fmt(L"本機版本 (version.dat)：%d", localVer));

    // 2. patch_live.txt：線上版本與下載位置
    PatchLive pl;
    std::wstring err;
    if (FetchPatchLive(pl, err)) {
        Log(Fmt(L"線上版本 (patch_live.txt)：%d", pl.version));
        if (pl.accept == 0) Log(L"[警告] patch_live 標示 patch_accept=0，官方可能正在維護或暫停更新。");
        if (pl.ftpUnsupported) {
            Log(L"[警告] ftp 欄位是 FTP 位置，本程式不支援，改用預設下載位置。");
            pl.host = kCdnHost; pl.port = kDefaultPort; pl.base = kDefaultBase;
        }
    } else {
        Log(Fmt(L"[警告] 無法取得 patch_live.txt（%ls），改用預設下載位置，略過線上版本預檢。", err.c_str()));
        pl = PatchLive();
    }
    if (g_cancel) { Log(L"已中止。"); return; }

    if (pl.ok && pl.version != localVer) {
        if (localVer < pl.version)
            Log(Fmt(L"[停止] 本機版本 (%d) 低於線上版本 (%d)。請先使用官方啟動器 (Mabinogi.exe) 更新到最新版後，再執行檢查。", localVer, pl.version));
        else
            Log(Fmt(L"[停止] 本機版本 (%d) 高於線上版本 (%d)，無法比對。請稍後再試或確認官方狀態。", localVer, pl.version));
        return;
    }

    g_host = pl.host; g_port = pl.port; g_base = pl.base;

    // 3. version.txt
    Http http;
    if (!http.Open(g_host, g_port)) { Log(L"[錯誤] 無法初始化網路連線。"); return; }
    Log(Fmt(L"下載檔案清單：http://%ls:%u%ls/version.txt", g_host.c_str(), (unsigned)g_port, g_base.c_str()));
    std::string data;
    int st = 0;
    if (!http.GetSmall(g_base + L"/version.txt", data, st, err)) {
        Log(Fmt(L"[錯誤] 下載 version.txt 失敗：%ls", err.c_str()));
        return;
    }
    std::vector<Entry> entries;
    int badLines = 0, maxVer = 0;
    ParseVersionTxt(data, entries, badLines, maxVer);
    if (entries.empty()) { Log(L"[錯誤] version.txt 內容無法解析。"); return; }
    Log(Fmt(L"清單共 %d 筆（最高版本 %d）%ls", (int)entries.size(), maxVer,
            badLines ? Fmt(L"，另有 %d 行格式錯誤已忽略", badLines).c_str() : L""));

    if (!pl.ok) {
        if (maxVer != localVer) {
            Log(Fmt(L"[停止] 本機版本 (%d) 與清單最高版本 (%d) 不一致。請先使用官方啟動器更新後再檢查。", localVer, maxVer));
            return;
        }
    } else if (maxVer != pl.version) {
        Log(Fmt(L"[警告] 清單最高版本 (%d) 與 patch_live 版本 (%d) 不同，結果僅供參考。", maxVer, pl.version));
    }

    // 4. 逐檔比對
    u64 total = 0;
    for (auto& e : entries) if (!e.placeholder) total += e.size;
    g_total = total;
    g_done = 0;
    Log(Fmt(L"開始檢查（%ls）...", FmtBytes(total).c_str()));
    Log(L"");

    int cOk = 0, cMissing = 0, cSize = 0, cMd5 = 0, cUnread = 0, cSkip = 0;
    std::vector<std::wstring> unreadable;
    bool cancelled = false;

    for (const Entry& e : entries) {
        if (g_cancel) { cancelled = true; break; }
        const u64 base = g_done.load();

        if (e.placeholder) {
            Log(Fmt(L"[略過]     %ls（佔位項目）", e.rel.c_str()));
            ++cSkip;
            continue;
        }
        if (!SafeRel(e.rel)) {
            Log(Fmt(L"[略過]     %ls（清單中的路徑不合法）", e.rel.c_str()));
            ++cSkip;
            g_done = base + e.size;
            continue;
        }

        const std::wstring full = g_gameDir + L"\\" + Backslash(e.rel);
        WIN32_FILE_ATTRIBUTE_DATA fad;
        if (!GetFileAttributesExW(Lp(full).c_str(), GetFileExInfoStandard, &fad)) {
            Log(Fmt(L"[缺少]     %ls", e.rel.c_str()));
            ++cMissing;
            g_bad.push_back(e);
            g_done = base + e.size;
            continue;
        }
        if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            Log(Fmt(L"[無法讀取] %ls（該路徑是資料夾）", e.rel.c_str()));
            ++cUnread;
            unreadable.push_back(e.rel);
            g_done = base + e.size;
            continue;
        }
        const u64 sz = ((u64)fad.nFileSizeHigh << 32) | fad.nFileSizeLow;
        if (sz != e.size) {
            Log(Fmt(L"[大小不符] %ls（本機 %llu / 預期 %llu）", e.rel.c_str(), sz, e.size));
            ++cSize;
            g_bad.push_back(e);
            g_done = base + e.size;
            continue;
        }

        std::string hex;
        DWORD ec = 0;
        Md5Result mr = Md5File(full, hex, ec, true);
        if (mr == MD5_CANCEL) { cancelled = true; break; }
        if (mr == MD5_OK) {
            if (hex == e.md5) {
                Log(Fmt(L"[OK]       %ls", e.rel.c_str()));
                ++cOk;
            } else {
                Log(Fmt(L"[MD5不符]  %ls", e.rel.c_str()));
                ++cMd5;
                g_bad.push_back(e);
            }
        } else {
            Log(Fmt(L"[無法讀取] %ls（錯誤碼 %lu）", e.rel.c_str(), ec));
            ++cUnread;
            unreadable.push_back(e.rel);
        }
        g_done = base + e.size;
    }

    // 5. Summary
    const u64 sec = (GetTickCount64() - t0) / 1000;
    Log(L"");
    Log(L"==================== 統計報告 ====================");
    if (cancelled) Log(L"*** 檢查已被中止，以下統計不完整 ***");
    Log(Fmt(L"清單項目：%d　正常：%d　缺少：%d　大小不符：%d　MD5 不符：%d　無法讀取：%d　略過：%d",
            (int)entries.size(), cOk, cMissing, cSize, cMd5, cUnread, cSkip));
    Log(Fmt(L"耗時：%ls", FmtDuration(sec).c_str()));

    if (!g_bad.empty()) {
        u64 need = 0;
        for (auto& e : g_bad) need += e.size;
        Log(L"");
        Log(Fmt(L"異常檔案 %d 個（需下載約 %ls）：", (int)g_bad.size(), FmtBytes(need).c_str()));
        for (auto& e : g_bad) Log(Fmt(L"  %ls", e.rel.c_str()));
    }
    if (!unreadable.empty()) {
        Log(L"");
        Log(L"無法讀取的檔案（可能是權限或被其他程式鎖定，本程式無法修復）：");
        for (auto& r : unreadable) Log(Fmt(L"  %ls", r.c_str()));
    }
    Log(L"");
    if (cancelled) {
        g_bad.clear();
        Log(L"檢查未完成，請重新檢查。");
    } else if (g_bad.empty() && cUnread == 0) {
        Log(L"所有檔案皆正確。");
        g_checkComplete = true;
        g_checkedVer = localVer;
    } else {
        g_checkComplete = true;
        g_checkedVer = localVer;
        if (!g_bad.empty()) Log(L"可按「更新」重新下載異常檔案。");
    }
}

// ---------------------------------------------------------------- 更新工作
static void RunUpdate() {
    const u64 t0 = GetTickCount64();
    std::vector<Entry> todo = g_bad;

    Log(L"=== 更新（修復異常檔案）===");
    Log(Fmt(L"待修復：%d 個檔案", (int)todo.size()));

    std::wstring which;
    if (GameRunningHere(which)) {
        Log(Fmt(L"[停止] 偵測到 %ls 正在執行。請先關閉遊戲與官方啟動器後再更新。", which.c_str()));
        return;
    }

    // 版本須與檢查當下一致
    int localVer = ReadLocalVersion();
    std::wstring err;
    PatchLive pl;
    if (FetchPatchLive(pl, err)) {
        if (pl.version != g_checkedVer || localVer != g_checkedVer) {
            Log(Fmt(L"[停止] 版本已變動（檢查時 %d，現在本機 %d / 線上 %d）。請重新按「檢查」。", g_checkedVer, localVer, pl.version));
            g_bad.clear();
            g_checkComplete = false;
            return;
        }
    } else {
        Log(Fmt(L"[警告] 無法確認線上版本（%ls），仍使用先前的下載位置。", err.c_str()));
        if (localVer != g_checkedVer) {
            Log(L"[停止] 本機版本已變動，請重新按「檢查」。");
            g_bad.clear();
            g_checkComplete = false;
            return;
        }
    }

    // 磁碟空間
    u64 total = 0, largest = 0;
    for (auto& e : todo) { total += e.size; largest = std::max(largest, e.size); }
    ULARGE_INTEGER freeB;
    if (GetDiskFreeSpaceExW(g_gameDir.c_str(), &freeB, nullptr, nullptr)) {
        if (freeB.QuadPart < largest + (100ull << 20)) {
            Log(Fmt(L"[停止] 磁碟剩餘空間不足（剩 %ls，最大檔案需 %ls 另加 100 MB 餘裕）。",
                    FmtBytes(freeB.QuadPart).c_str(), FmtBytes(largest).c_str()));
            return;
        }
    }

    Http http;
    if (!http.Open(g_host, g_port)) { Log(L"[錯誤] 無法初始化網路連線。"); return; }

    const std::wstring tmpDir = g_gameDir + L"\\" + kTmpDirName;
    CreateDirectoryW(Lp(tmpDir).c_str(), nullptr);

    g_total = total;
    g_done = 0;
    Log(Fmt(L"開始下載（共 %ls）...", FmtBytes(total).c_str()));
    Log(L"");

    std::vector<Entry> failed;
    int cOk = 0;
    size_t idx = 0;
    bool cancelled = false;

    for (; idx < todo.size(); ++idx) {
        if (g_cancel) { cancelled = true; break; }
        const Entry& e = todo[idx];
        const u64 base = g_done.load();
        const std::wstring rel = Backslash(e.rel);
        const std::wstring target = g_gameDir + L"\\" + rel;
        const std::wstring part = tmpDir + L"\\" + rel + L".part";
        EnsureParentDirs(part);

        Log(Fmt(L"[下載]     %ls（%ls）", e.rel.c_str(), FmtBytes(e.size).c_str()));

        bool done = false, fatal = false, canceledHere = false;
        std::wstring lastErr = L"未知錯誤";
        const std::wstring url = g_base + L"/Mabinogi/" + UrlEncodePath(e.rel);

        for (int attempt = 1; attempt <= 3 && !done && !fatal; ++attempt) {
            g_done = base;
            if (attempt > 1) Log(Fmt(L"           重試 (%d/3)：%ls", attempt, lastErr.c_str()));
            DlResult r = Download(http, url, part, e.size, lastErr);
            if (r == DL_CANCEL) { canceledHere = true; break; }
            if (r == DL_FAIL_FATAL) { fatal = true; break; }
            if (r == DL_FAIL_RETRY) {
                for (int k = 0; k < attempt * 10 && !g_cancel; ++k) Sleep(100);
                continue;
            }
            // 驗證
            std::string hex;
            DWORD ec = 0;
            Md5Result mr = Md5File(part, hex, ec, false);
            if (mr == MD5_CANCEL) { canceledHere = true; break; }
            if (mr == MD5_OK && hex == e.md5 && FileSizeOrZero(part) == e.size) { done = true; break; }
            lastErr = L"下載完成但 MD5 驗證失敗";
            DeleteFileW(Lp(part).c_str());
        }

        if (canceledHere || g_cancel) { cancelled = true; break; }

        if (done) {
            EnsureParentDirs(target);
            SetFileAttributesW(Lp(target).c_str(), FILE_ATTRIBUTE_NORMAL);   // 取消唯讀(檔案不存在時忽略)
            if (!MoveFileExW(Lp(part).c_str(), Lp(target).c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
                DWORD ec = GetLastError();
                lastErr = Fmt(L"無法取代原檔（錯誤碼 %lu）。檔案可能被佔用，或需要以系統管理員身分執行", ec);
                done = false;
            }
        }

        g_done = base + e.size;
        if (done) {
            Log(Fmt(L"[已修復]   %ls", e.rel.c_str()));
            ++cOk;
        } else {
            Log(Fmt(L"[失敗]     %ls：%ls", e.rel.c_str(), lastErr.c_str()));
            failed.push_back(e);
        }
    }

    // 未處理(被中止)的項目保留
    if (cancelled) for (; idx < todo.size(); ++idx) failed.push_back(todo[idx]);

    RemoveEmptyDirs(tmpDir);

    const u64 sec = (GetTickCount64() - t0) / 1000;
    Log(L"");
    Log(L"==================== 統計報告 ====================");
    if (cancelled) Log(L"*** 更新已被中止 ***");
    Log(Fmt(L"成功：%d　失敗/未處理：%d　耗時：%ls", cOk, (int)failed.size(), FmtDuration(sec).c_str()));
    if (!failed.empty() && !cancelled) {
        Log(L"失敗的檔案：");
        for (auto& e : failed) Log(Fmt(L"  %ls", e.rel.c_str()));
    }
    Log(L"");
    if (failed.empty()) Log(L"全部修復完成。建議再按一次「檢查」確認。");
    else Log(L"仍有檔案未修復，可再按「更新」重試（已下載的暫存內容會續用）。");
    g_bad = failed;
}

// ---------------------------------------------------------------- UI
static void AppendText(const std::wstring& s) {
    SendMessageW(g_hEdit, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
    SendMessageW(g_hEdit, EM_REPLACESEL, FALSE, (LPARAM)s.c_str());
}

static void Layout() {
    RECT rc;
    GetClientRect(g_hwnd, &rc);
    const int W = rc.right, H = rc.bottom;
    const int m = S(10), bw = S(90), bh = S(30), ph = S(18);
    const int yBtn = H - m - bh;
    const int yProg = yBtn - m - ph;
    int x = W - m - bw;
    MoveWindow(g_hClose, x, yBtn, bw, bh, TRUE);
    x -= m + bw;
    MoveWindow(g_hUpdate, x, yBtn, bw, bh, TRUE);
    x -= m + bw;
    MoveWindow(g_hCheck, x, yBtn, bw, bh, TRUE);
    MoveWindow(g_hCopy, m, yBtn, bw, bh, TRUE);
    MoveWindow(g_hSave, m + bw + m, yBtn, bw, bh, TRUE);
    const int sx = m + 2 * (bw + m);
    MoveWindow(g_hStatus, sx, yBtn, std::max(S(50), x - m - sx), bh, TRUE);
    MoveWindow(g_hProgress, m, yProg, W - 2 * m, ph, TRUE);
    MoveWindow(g_hEdit, m, m, W - 2 * m, std::max(S(50), yProg - 2 * m), TRUE);
}

static void SetIdleUi() {
    SetWindowTextW(g_hCheck, L"檢查");
    SetWindowTextW(g_hUpdate, L"更新");
    EnableWindow(g_hCheck, TRUE);
    EnableWindow(g_hUpdate, (!g_bad.empty() && g_checkComplete) ? TRUE : FALSE);
    bool hasReport;
    {
        std::lock_guard<std::mutex> lk(g_logMtx);
        hasReport = !g_report.empty();
    }
    EnableWindow(g_hCopy, hasReport);
    EnableWindow(g_hSave, hasReport);
}

static void StartJob(int mode) {
    g_busy = mode;
    g_cancel = false;
    g_done = 0;
    g_total = 0;
    {
        std::lock_guard<std::mutex> lk(g_logMtx);
        g_report.clear();
    }
    SetWindowTextW(g_hEdit, L"");
    SendMessageW(g_hProgress, PBM_SETPOS, 0, 0);
    SetWindowTextW(g_hStatus, L"");
    EnableWindow(g_hCopy, FALSE);
    EnableWindow(g_hSave, FALSE);
    if (mode == 1) {
        SetWindowTextW(g_hCheck, L"停止");
        EnableWindow(g_hCheck, TRUE);
        EnableWindow(g_hUpdate, FALSE);
    } else {
        SetWindowTextW(g_hUpdate, L"停止");
        EnableWindow(g_hUpdate, TRUE);
        EnableWindow(g_hCheck, FALSE);
    }
    std::thread([mode]() {
        try {
            if (mode == 1) RunCheck(); else RunUpdate();
        } catch (...) {
            Log(L"[錯誤] 發生未預期的例外狀況。");
        }
        PostMessageW(g_hwnd, WM_APP_DONE, (WPARAM)mode, 0);
    }).detach();
}

static std::wstring ReportCopy() {
    std::lock_guard<std::mutex> lk(g_logMtx);
    return g_report;
}

static void CopyReport() {
    std::wstring t = ReportCopy();
    if (t.empty()) return;
    if (!OpenClipboard(g_hwnd)) {
        MessageBoxW(g_hwnd, L"無法開啟剪貼簿。", L"複製報告", MB_ICONWARNING);
        return;
    }
    EmptyClipboard();
    size_t bytes = (t.size() + 1) * sizeof(wchar_t);
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (hg) {
        void* p = GlobalLock(hg);
        if (p) {
            memcpy(p, t.c_str(), bytes);
            GlobalUnlock(hg);
            if (!SetClipboardData(CF_UNICODETEXT, hg)) GlobalFree(hg);   // 成功時所有權交給剪貼簿
        } else {
            GlobalFree(hg);
        }
    }
    CloseClipboard();
    SetWindowTextW(g_hStatus, L"報告已複製到剪貼簿");
}

static void SaveReportDialog() {
    std::wstring t = ReportCopy();
    if (t.empty()) return;
    wchar_t file[MAX_PATH] = {};
    wcscpy_s(file, kLogFileName);
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"文字檔 (*.txt)\0*.txt\0所有檔案 (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrInitialDir = g_gameDir.c_str();
    ofn.lpstrDefExt = L"txt";
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn)) return;

    std::string u8 = Narrow(t);
    HANDLE hf = CreateFileW(Lp(file).c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hf == INVALID_HANDLE_VALUE) {
        MessageBoxW(g_hwnd, Fmt(L"無法寫入檔案（錯誤碼 %lu）。", GetLastError()).c_str(), L"儲存報告", MB_ICONWARNING);
        return;
    }
    const unsigned char bom[3] = { 0xEF, 0xBB, 0xBF };
    DWORD w = 0;
    WriteFile(hf, bom, 3, &w, nullptr);
    WriteFile(hf, u8.data(), (DWORD)u8.size(), &w, nullptr);
    CloseHandle(hf);
    SetWindowTextW(g_hStatus, L"報告已儲存");
}

static void OnTimer() {
    if (!g_busy) return;
    static u64 lastTick = 0, lastDone = 0;
    static double speed = 0;
    const u64 now = GetTickCount64();
    const u64 done = std::min(g_done.load(), g_total.load());
    const u64 total = g_total.load();
    if (lastTick == 0 || done < lastDone) { lastTick = now; lastDone = done; speed = 0; }
    if (now - lastTick >= 1000) {
        double inst = (double)(done - lastDone) * 1000.0 / (double)(now - lastTick);
        speed = (speed == 0) ? inst : speed * 0.7 + inst * 0.3;
        lastTick = now;
        lastDone = done;
    }
    if (total == 0) return;
    int pos = (int)(done * 1000 / total);
    SendMessageW(g_hProgress, PBM_SETPOS, pos, 0);
    std::wstring t = Fmt(L"%ls / %ls (%d%%)", FmtBytes(done).c_str(), FmtBytes(total).c_str(), pos / 10);
    if (speed > 1.0) {
        t += Fmt(L"　%ls/s　剩餘 %ls", FmtBytes((u64)speed).c_str(), FmtDuration((u64)((total - done) / speed)).c_str());
    }
    SetWindowTextW(g_hStatus, t.c_str());
}

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        g_hwnd = hwnd;
        HDC dc = GetDC(nullptr);
        g_dpi = GetDeviceCaps(dc, LOGPIXELSX);
        ReleaseDC(nullptr, dc);

        NONCLIENTMETRICSW ncm = {};
        ncm.cbSize = sizeof(ncm);
        SystemParametersInfoW(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);
        g_fontUi = CreateFontIndirectW(&ncm.lfMessageFont);
        g_fontMono = CreateFontW(-MulDiv(9, g_dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                                 OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                                 FIXED_PITCH | FF_MODERN, L"Consolas");

        g_hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
                                  ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
                                  0, 0, 10, 10, hwnd, (HMENU)IDC_EDIT, nullptr, nullptr);
        g_hProgress = CreateWindowExW(0, PROGRESS_CLASSW, L"", WS_CHILD | WS_VISIBLE, 0, 0, 10, 10, hwnd,
                                      (HMENU)IDC_PROGRESS, nullptr, nullptr);
        g_hStatus = CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE | SS_LEFT | SS_CENTERIMAGE | SS_ENDELLIPSIS,
                                    0, 0, 10, 10, hwnd, (HMENU)IDC_STATUS, nullptr, nullptr);
        g_hCopy = CreateWindowExW(0, L"BUTTON", L"複製報告", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED | BS_PUSHBUTTON,
                                  0, 0, 10, 10, hwnd, (HMENU)IDC_COPY, nullptr, nullptr);
        g_hSave = CreateWindowExW(0, L"BUTTON", L"儲存報告", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED | BS_PUSHBUTTON,
                                  0, 0, 10, 10, hwnd, (HMENU)IDC_SAVE, nullptr, nullptr);
        g_hCheck = CreateWindowExW(0, L"BUTTON", L"檢查", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 10, 10, hwnd, (HMENU)IDC_CHECK, nullptr, nullptr);
        g_hUpdate = CreateWindowExW(0, L"BUTTON", L"更新", WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_DISABLED | BS_PUSHBUTTON,
                                    0, 0, 10, 10, hwnd, (HMENU)IDC_UPDATE, nullptr, nullptr);
        g_hClose = CreateWindowExW(0, L"BUTTON", L"關閉", WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON,
                                   0, 0, 10, 10, hwnd, (HMENU)IDC_CLOSE, nullptr, nullptr);
        for (HWND c : { g_hProgress, g_hStatus, g_hCopy, g_hSave, g_hCheck, g_hUpdate, g_hClose })
            SendMessageW(c, WM_SETFONT, (WPARAM)g_fontUi, TRUE);
        SendMessageW(g_hEdit, WM_SETFONT, (WPARAM)g_fontMono, TRUE);
        SendMessageW(g_hEdit, EM_SETLIMITTEXT, 0, 0);                 // 取消預設字數上限
        SendMessageW(g_hProgress, PBM_SETRANGE32, 0, 1000);

        // 遊戲目錄 = 本程式所在目錄
        wchar_t path[MAX_PATH * 2];
        GetModuleFileNameW(nullptr, path, MAX_PATH * 2);
        g_gameDir = path;
        g_gameDir = g_gameDir.substr(0, g_gameDir.find_last_of(L'\\'));

        if (!InitHash()) MessageBoxW(hwnd, L"無法初始化 MD5 (Windows CNG)。", L"錯誤", MB_ICONERROR);

        AppendText(Fmt(L"目前目錄：%ls\r\n", g_gameDir.c_str()));
        int v = ReadLocalVersion();
        if (v < 0) AppendText(L"[警告] 找不到 version.dat，這裡看起來不是遊戲目錄。\r\n");
        else AppendText(Fmt(L"本機版本：%d\r\n", v));
        AppendText(L"按「檢查」開始比對檔案。\r\n");

        SetTimer(hwnd, TIMER_PROGRESS, 250, nullptr);
        Layout();
        return 0;
    }
    case WM_SIZE:
        if (g_hEdit) Layout();
        return 0;
    case WM_GETMINMAXINFO: {
        auto* mm = (MINMAXINFO*)lp;
        mm->ptMinTrackSize.x = S(740);
        mm->ptMinTrackSize.y = S(360);
        return 0;
    }
    case WM_CTLCOLORSTATIC:
        if ((HWND)lp == g_hEdit) {
            SetTextColor((HDC)wp, GetSysColor(COLOR_WINDOWTEXT));
            SetBkColor((HDC)wp, GetSysColor(COLOR_WINDOW));
            return (LRESULT)GetSysColorBrush(COLOR_WINDOW);
        }
        break;
    case WM_COMMAND:
        if (HIWORD(wp) != BN_CLICKED) break;
        switch (LOWORD(wp)) {
        case IDC_CHECK:
            if (g_busy == 1) { g_cancel = true; EnableWindow(g_hCheck, FALSE); }
            else if (g_busy == 0) StartJob(1);
            break;
        case IDC_UPDATE:
            if (g_busy == 2) { g_cancel = true; EnableWindow(g_hUpdate, FALSE); }
            else if (g_busy == 0) {
                u64 need = 0;
                for (auto& e : g_bad) need += e.size;
                std::wstring q = Fmt(L"將重新下載並覆蓋 %d 個異常檔案（約 %ls）。\r\n請確認遊戲與官方啟動器都已關閉。\r\n\r\n是否繼續？",
                                     (int)g_bad.size(), FmtBytes(need).c_str());
                if (MessageBoxW(hwnd, q.c_str(), L"確認更新", MB_YESNO | MB_ICONQUESTION) == IDYES) StartJob(2);
            }
            break;
        case IDC_COPY:
            if (!g_busy) CopyReport();
            break;
        case IDC_SAVE:
            if (!g_busy) SaveReportDialog();
            break;
        case IDC_CLOSE:
            SendMessageW(hwnd, WM_CLOSE, 0, 0);
            break;
        }
        return 0;
    case WM_APP_LOG: {
        auto* p = (std::wstring*)lp;
        AppendText(*p);
        delete p;
        return 0;
    }
    case WM_APP_DONE: {
        const int mode = (int)wp;
        g_busy = 0;
        g_cancel = false;
        SetIdleUi();
        if (g_total.load() > 0) {
            SendMessageW(g_hProgress, PBM_SETPOS, (int)(std::min(g_done.load(), g_total.load()) * 1000 / g_total.load()), 0);
        }
        std::wstring s = (mode == 1) ? L"檢查結束" : L"更新結束";
        if (g_checkComplete && !g_bad.empty()) s += Fmt(L"：有 %d 個異常檔案", (int)g_bad.size());
        SetWindowTextW(g_hStatus, s.c_str());
        return 0;
    }
    case WM_TIMER:
        if (wp == TIMER_PROGRESS) OnTimer();
        return 0;
    case WM_CLOSE:
        if (g_busy) {
            if (MessageBoxW(hwnd, L"作業進行中，確定要結束嗎？\r\n（下載到一半的內容會保留，下次可續傳）", L"確認",
                            MB_YESNO | MB_ICONQUESTION) != IDYES) return 0;
            g_cancel = true;
            TerminateProcess(GetCurrentProcess(), 0);     // 工作執行緒仍在跑，直接結束行程
        }
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        KillTimer(hwnd, TIMER_PROGRESS);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    SetProcessDPIAware();
    INITCOMMONCONTROLSEX icc = { sizeof(icc), ICC_PROGRESS_CLASS };
    InitCommonControlsEx(&icc);

    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"MabiCheckerWnd";
    wc.hIcon = LoadIconW(nullptr, IDI_APPLICATION);
    RegisterClassExW(&wc);

    HDC dc = GetDC(nullptr);
    int dpi = GetDeviceCaps(dc, LOGPIXELSX);
    ReleaseDC(nullptr, dc);

    RECT r = { 0, 0, MulDiv(820, dpi, 96), MulDiv(560, dpi, 96) };
    AdjustWindowRect(&r, WS_OVERLAPPEDWINDOW, FALSE);
    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"瑪奇 Mabinogi 遊戲檔案完整性檢查 / 修復工具", WS_OVERLAPPEDWINDOW,
                                CW_USEDEFAULT, CW_USEDEFAULT, r.right - r.left, r.bottom - r.top,
                                nullptr, nullptr, hInst, nullptr);
    if (!hwnd) return 1;
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG m;
    while (GetMessageW(&m, nullptr, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &m)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
    return (int)m.wParam;
}
