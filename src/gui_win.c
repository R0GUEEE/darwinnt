/* darwinnt GUI — native Win32.
 *
 * A real window, not a console wrapper. Layout:
 *
 *   [ menu: File / Run / Help ]
 *   +--------------------------------------------------------------+
 *   | toolbar: [Open binary...] [Root: C:\DarwinRoot]  [Run] [Stop] |
 *   +--------------------------------------------------------------+
 *   | output (read-only edit control, monospace, scrolls)          |
 *   |                                                              |
 *   +--------------------------------------------------------------+
 *   | status bar: state | exit code | bound imports | imports miss |
 *   +--------------------------------------------------------------+
 *
 * The guest runs on a worker thread so the UI keeps painting; its writes to
 * fd 1/2 arrive through the port output sink and are appended to the output
 * control from that thread by posting a window message (never touching a
 * control from a non-UI thread directly).
 */
#ifdef _WIN32

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

#include "dnt_abi.h"
#include "dnt_exec.h"
#include "dnt_port.h"
#include "dnt_vfs.h"
#include "dnt_win.h"
#include "dnt_syscall.h"
#include "dnt_ipa.h"

#define IDC_OUTPUT   1001
#define IDC_OPEN     1002
#define IDC_RUN      1003
#define IDC_STOP     1004
#define IDC_ROOT     1005
#define IDC_IPA      1006
#define IDM_IPA      2003
#define IDM_ABOUT    2001
#define IDM_EXIT     2002
#define WM_APPEND    (WM_APP + 1)   /* lParam = heap char*, wParam = len */

static HWND g_main, g_output, g_root, g_run, g_stop, g_status, g_ipa;
static HFONT g_mono;
static HANDLE g_thread;
static volatile LONG g_running;
static int g_ui_scale = 100;

/* Text queued by the guest thread, drained on the UI thread. */
typedef struct { char *text; uint64_t len; } append_msg;

/* Append a literal; the length is computed, never hand-counted. */
#define ui_puts(lit) ui_append((lit), sizeof(lit) - 1)

static void ui_append(const char *buf, uint64_t len)
{
    append_msg *m = malloc(sizeof(*m));
    if (!m)
        return;
    m->text = malloc((size_t)len + 1);
    if (!m->text) { free(m); return; }
    memcpy(m->text, buf, (size_t)len);
    m->text[len] = 0;
    m->len = len;
    PostMessage(g_main, WM_APPEND, (WPARAM)len, (LPARAM)m);
}

static void out_sink(int stream, const char *buf, uint64_t len, void *user)
{
    (void)stream; (void)user;
    ui_append(buf, len);
}

/* ---- layout ---- */
static void layout(HWND hwnd)
{
    RECT rc;
    GetClientRect(hwnd, &rc);
    int pad = 10 * g_ui_scale / 100;
    int bar = 34 * g_ui_scale / 100;
    int status = 24 * g_ui_scale / 100;
    /* Button widths are set from the text they must hold: "Run binary..." is
     * wider than "Stop", and splitting a fixed budget between them clipped the
     * label. */
    int run_w = 110 * g_ui_scale / 100;
    int stop_w = 60 * g_ui_scale / 100;
    int root_w = 320 * g_ui_scale / 100;
    int x = pad, y = pad, h = 26 * g_ui_scale / 100;

    MoveWindow(g_root, x, y, root_w, h, TRUE);
    MoveWindow(g_run, x + root_w + pad, y, run_w, h, TRUE);
    MoveWindow(g_stop, x + root_w + pad + run_w + 6, y, stop_w, h, TRUE);
    MoveWindow(g_ipa, x + root_w + pad + run_w + stop_w + 12, y,
               110 * g_ui_scale / 100, h, TRUE);
    MoveWindow(g_output, pad, pad + bar,
               rc.right - pad * 2,
               rc.bottom - (pad + bar) - status - pad, TRUE);
    MoveWindow(g_status, 0, rc.bottom - status, rc.right, status, TRUE);
}

static void set_status(const wchar_t *text)
{
    SetWindowTextW(g_status, text);
}

static void enable_controls(BOOL run)
{
    EnableWindow(g_run, run);
    EnableWindow(g_stop, !run);
}

/* ---- guest thread ---- */
typedef struct {
    char *path;
    char *root;
} job_t;

static DWORD WINAPI guest_thread(LPVOID param)
{
    job_t *job = param;

    FILE *f = fopen(job->path, "rb");
    if (!f) {
        ui_puts("\r\n[darwinnt] cannot open binary\r\n");
        PostMessage(g_main, WM_APP + 2, 0, 0);
        return 1;
    }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = n > 0 ? malloc((size_t)n) : NULL;
    if (data && fread(data, 1, (size_t)n, f) != (size_t)n) {
        free(data);
        data = NULL;
    }
    fclose(f);

    if (!data) {
        ui_puts("[darwinnt] cannot read binary\r\n");
        PostMessage(g_main, WM_APP + 2, 0, 0);
        return 1;
    }

    dnt_win_set_interpreter_mode(1);
    dnt_exec_result r;
    int rc = dnt_exec_image(data, (size_t)n, job->root, 0, &r);
    dnt_win_set_interpreter_mode(0);
    free(data);

    char line[512];
    if (rc != 0) {
        int len = snprintf(line, sizeof(line), "\r\n[darwinnt] %s\r\n", r.detail);
        ui_append(line, (uint64_t)len);
        for (int i = 0; i < r.nmissing; i++) {
            len = snprintf(line, sizeof(line), "[darwinnt] unresolved import: %s\r\n",
                           r.missing[i]);
            ui_append(line, (uint64_t)len);
        }
    } else {
        int len = snprintf(line, sizeof(line), "\r\n[darwinnt] exit %d\r\n", r.exit_code);
        ui_append(line, (uint64_t)len);
    }

    InterlockedExchange(&g_running, 0);
    /* Wake the UI so it can update the status bar and re-enable Run. */
    PostMessage(g_main, WM_APP + 2, (WPARAM)(rc == 0 ? r.exit_code : -1),
                (LPARAM)r.nbound);
    return 0;
}

static void start_run(HWND hwnd)
{
    if (InterlockedCompareExchange(&g_running, 1, 0) != 0)
        return;

    wchar_t wpath[MAX_PATH] = {0};
    GetWindowTextW(g_root, wpath, MAX_PATH);
    char root[MAX_PATH * 4];
    WideCharToMultiByte(CP_UTF8, 0, wpath, -1, root, sizeof(root), NULL, NULL);

    wchar_t wbin[MAX_PATH] = {0};
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"Darwin binaries (*.macho;*.bin;*.*)\0*.macho;*.bin;*.*\0All files\0*.*\0";
    ofn.lpstrFile = wbin;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

    if (!GetOpenFileNameW(&ofn)) {
        InterlockedExchange(&g_running, 0);
        return;
    }

    char path[MAX_PATH * 4];
    WideCharToMultiByte(CP_UTF8, 0, wbin, -1, path, sizeof(path), NULL, NULL);

    SendMessageW(g_output, WM_SETTEXT, 0, (LPARAM)L"");
    ui_puts("[darwinnt] loading ");
    ui_append(path, (uint64_t)strlen(path));
    ui_puts("\r\n");

    enable_controls(FALSE);
    set_status(L"running...");

    job_t *job = malloc(sizeof(*job));
    job->path = _strdup(path);
    job->root = _strdup(root);
    g_thread = CreateThread(NULL, 0, guest_thread, job, 0, NULL);
}


/* Read a file whole. Returns NULL on failure. */
static uint8_t *read_whole_file(const char *path, size_t *out_len, char *err, size_t errcap)
{
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(err, errcap, "cannot open file"); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (n <= 0) { fclose(f); snprintf(err, errcap, "empty file"); return NULL; }
    uint8_t *d = malloc((size_t)n);
    if (!d) { fclose(f); snprintf(err, errcap, "out of memory (%ld bytes)", n); return NULL; }
    if (fread(d, 1, (size_t)n, f) != (size_t)n) {
        free(d); fclose(f);
        snprintf(err, errcap, "short read");
        return NULL;
    }
    fclose(f);
    *out_len = (size_t)n;
    return d;
}

/* Open an IPA and report what it actually is. This is deliberately blunt: an
 * app that links 66 private frameworks is not something this engine can run,
 * and the report says so rather than implying a workaround exists. */
static void inspect_ipa(HWND hwnd)
{
    wchar_t wfile[MAX_PATH] = {0};
    OPENFILENAMEW ofn;
    memset(&ofn, 0, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hwnd;
    ofn.lpstrFilter = L"iOS apps (*.ipa)\0*.ipa\0All files\0*.*\0";
    ofn.lpstrFile = wfile;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    if (!GetOpenFileNameW(&ofn))
        return;

    char path[MAX_PATH * 4];
    WideCharToMultiByte(CP_UTF8, 0, wfile, -1, path, sizeof(path), NULL, NULL);

    SendMessageW(g_output, WM_SETTEXT, 0, (LPARAM)L"");
    char line[512];
    int len = snprintf(line, sizeof(line), "[ipa] opening %s\r\n", path);
    ui_append(line, (uint64_t)len);
    set_status(L"inspecting...");
    UpdateWindow(g_main);

    size_t n = 0;
    char err[256] = {0};
    uint8_t *data = read_whole_file(path, &n, err, sizeof(err));
    if (!data) {
        len = snprintf(line, sizeof(line), "[ipa] failed: %s\r\n", err);
        ui_append(line, (uint64_t)len);
        set_status(L"inspection failed");
        return;
    }

    dnt_ipa ipa;
    if (dnt_ipa_open(&ipa, data, n) != 0) {
        len = snprintf(line, sizeof(line), "[ipa] %s\r\n", ipa.error);
        ui_append(line, (uint64_t)len);
        free(data);
        set_status(L"not an iOS app bundle");
        return;
    }

    len = snprintf(line, sizeof(line),
                   "\r\n  bundle        %s\r\n"
                   "  name          %s\r\n"
                   "  version       %s   (minimum iOS %s)\r\n"
                   "  executable    %s  %.1f MB\r\n"
                   "  architecture  arm64\r\n"
                   "  encryption    %s\r\n"
                   "  entries       %u files, %.1f MB archive\r\n"
                   "  frameworks    %d linked, %d bundled\r\n",
                   ipa.bundle_id, ipa.display_name, ipa.version, ipa.min_os,
                   ipa.executable, ipa.exec_size / 1e6,
                   (ipa.has_encryption_info && ipa.crypt_id)
                       ? "FairPlay-encrypted (App Store)" : "none",
                   ipa.n_entries, n / 1e6,
                   ipa.n_dylibs, ipa.n_frameworks);
    ui_append(line, (uint64_t)len);

    if (ipa.n_dylibs > 0) {
        ui_puts("\r\n  required frameworks (first 12):\r\n");
        for (int i = 0; i < ipa.n_dylibs && i < 12; i++) {
            len = snprintf(line, sizeof(line), "    %s\r\n", ipa.dylibs[i]);
            ui_append(line, (uint64_t)len);
        }
        if (ipa.n_dylibs > 12) {
            len = snprintf(line, sizeof(line), "    ... and %d more\r\n",
                           ipa.n_dylibs - 12);
            ui_append(line, (uint64_t)len);
        }
    }

    char verdict[512];
    dnt_ipa_verdict(&ipa, verdict, sizeof(verdict));
    len = snprintf(line, sizeof(line), "\r\n  VERDICT: %s\r\n\r\n", verdict);
    ui_append(line, (uint64_t)len);
    ui_puts("  An IPA is an application bundle: a GUI process built on UIKit and\r\n"
            "  dozens of private frameworks. darwinnt executes command-line\r\n"
            "  Darwin binaries. Running an IPA needs SpringBoard, the window\r\n"
            "  server and those frameworks, not a better loader.\r\n");

    free(data);
    set_status(ipa.n_dylibs ? L"app bundle - not runnable here" : L"candidate");
}

/* ---- window procedure ---- */
static LRESULT CALLBACK wndproc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_CREATE: {
        HDC dc = GetDC(hwnd);
        int dpi = GetDeviceCaps(dc, LOGPIXELSY);
        ReleaseDC(hwnd, dc);
        g_ui_scale = dpi * 100 / 96;
        if (g_ui_scale < 100) g_ui_scale = 100;

        g_mono = CreateFontW(-MulDiv(10, dpi, 72), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                             CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, L"Consolas");

        g_root = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"C:\\DarwinRoot",
                                 WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL,
                                 0, 0, 0, 0, hwnd, (HMENU)IDC_ROOT, NULL, NULL);
        g_run = CreateWindowW(L"BUTTON", L"Run binary...",
                              WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                              (HMENU)IDC_RUN, NULL, NULL);
        g_stop = CreateWindowW(L"BUTTON", L"Stop",
                               WS_CHILD | WS_VISIBLE | WS_DISABLED, 0, 0, 0, 0, hwnd,
                               (HMENU)IDC_STOP, NULL, NULL);
        g_ipa = CreateWindowW(L"BUTTON", L"Inspect IPA...",
                              WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, hwnd,
                              (HMENU)IDC_IPA, NULL, NULL);
        g_output = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                   WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
                                   ES_READONLY | ES_AUTOVSCROLL,
                                   0, 0, 0, 0, hwnd, (HMENU)IDC_OUTPUT, NULL, NULL);
        g_status = CreateWindowW(L"STATIC", L"ready",
                                 WS_CHILD | WS_VISIBLE | SS_LEFT,
                                 0, 0, 0, 0, hwnd, NULL, NULL, NULL);

        SendMessageW(g_output, WM_SETFONT, (WPARAM)g_mono, TRUE);
        SendMessageW(g_status, WM_SETFONT, (WPARAM)GetStockObject(DEFAULT_GUI_FONT), TRUE);

        /* The guest's stdout flows here, not to a console. */
        dnt_port_set_output(out_sink, NULL);
        layout(hwnd);
        return 0;
    }

    case WM_SIZE:
        layout(hwnd);
        return 0;

    case WM_APPEND: {
        append_msg *m = (append_msg *)lp;
        int len = GetWindowTextLengthW(g_output);
        SendMessageW(g_output, EM_SETSEL, (WPARAM)len, (LPARAM)len);

        /* Guest bytes are UTF-8; convert for the wide edit control. Invalid
         * sequences are replaced rather than dropped. */
        int need = MultiByteToWideChar(CP_UTF8, 0, m->text, (int)m->len, NULL, 0);
        if (need > 0) {
            wchar_t *w = malloc((size_t)(need + 1) * sizeof(wchar_t));
            if (w) {
                MultiByteToWideChar(CP_UTF8, 0, m->text, (int)m->len, w, need);
                w[need] = 0;
                SendMessageW(g_output, EM_REPLACESEL, FALSE, (LPARAM)w);
                free(w);
            }
        }
        SendMessageW(g_output, EM_SCROLLCARET, 0, 0);
        free(m->text);
        free(m);
        return 0;
    }

    case WM_APP + 2: {   /* guest finished */
        enable_controls(TRUE);
        wchar_t buf[256];
        if ((int)wp >= 0)
            _snwprintf(buf, 256, L"finished - exit %d - %llu imports bound",
                      (int)wp, (unsigned long long)lp);
        else
            _snwprintf(buf, 256, L"stopped with an error");
        set_status(buf);
        return 0;
    }

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDC_RUN:
            start_run(hwnd);
            return 0;
        case IDC_STOP:
            /* The interpreter has no interruption point yet, so the only
             * truthful action is to terminate the thread running it -- and to
             * say so, because that skips freeing the image and stack. */
            if (InterlockedCompareExchange(&g_running, 0, 1) == 1 && g_thread) {
                TerminateThread(g_thread, 1);
                CloseHandle(g_thread);
                g_thread = NULL;
                ui_puts("\r\n[darwinnt] terminated by user (guest resources not released)\r\n");
                enable_controls(TRUE);
                set_status(L"terminated by user");
            }
            return 0;
        case IDC_IPA:
        case IDM_IPA:
            inspect_ipa(hwnd);
            return 0;
        case IDM_EXIT:
            DestroyWindow(hwnd);
            return 0;
        case IDM_ABOUT:
            MessageBoxW(hwnd,
                L"darwinnt\n\n"
                L"Runs Darwin (Mach-O, arm64) userland binaries on Windows.\n\n"
                L"Loads the image, traps SVC, and provides a libSystem symbol\n"
                L"table backed by Darwin syscalls. Dynamically linked binaries\n"
                L"stop at dyld_stub_binder until lazy binding lands.\n\n"
                L"Not an iOS emulator: it cannot boot iOS or run App Store apps.",
                L"About darwinnt", MB_OK | MB_ICONINFORMATION);
            return 0;
        }
        return 0;

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE inst, HINSTANCE prev, PWSTR cmdline, int show)
{
    (void)prev; (void)cmdline;
    SetProcessDPIAware();

    /* Engine host services must be live before any guest runs. */
    dnt_syscall_init(dnt_win_host_ops());

    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = wndproc;
    wc.hInstance = inst;
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = L"darwinnt_window";
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    if (!RegisterClassExW(&wc))
        return 1;

    g_main = CreateWindowExW(0, L"darwinnt_window", L"darwinnt",
                             WS_OVERLAPPEDWINDOW | WS_CLIPCHILDREN,
                             CW_USEDEFAULT, CW_USEDEFAULT, 900, 600,
                             NULL, NULL, inst, NULL);
    if (!g_main)
        return 1;

    HMENU menu = CreateMenu();
    HMENU file = CreatePopupMenu();
    AppendMenuW(file, MF_STRING, IDM_IPA, L"Inspect &IPA...\tCtrl+I");
    AppendMenuW(file, MF_STRING, IDM_ABOUT, L"&About");
    AppendMenuW(file, MF_SEPARATOR, 0, NULL);
    AppendMenuW(file, MF_STRING, IDM_EXIT, L"E&xit");
    AppendMenuW(menu, MF_POPUP, (UINT_PTR)file, L"&File");
    SetMenu(g_main, menu);

    ShowWindow(g_main, show);
    UpdateWindow(g_main);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(g_main, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return (int)msg.wParam;
}

#endif /* _WIN32 */
