//***********************************************************************************************
// Library: mact.dll mact.cpp
//
// Description: This dll is injected into a process and used to intercept specific Windows API 
//              calls.
//
// Functionality: 
//                  Communicates with a server application.
//                  Saves logs regarding APIs called, parameters, and return values.
//                  Allows the programmer to override return values.
//                  Saves artifacts such as registry, file, memory and communication.
//
//***********************************************************************************************
//***********************************************************************************************
//
// Define the required libraries.
//
//***********************************************************************************************
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "Iphlpapi.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "Ole32.lib")
#pragma comment(lib, "samsrv.lib")
#pragma comment(lib, "Secur32.lib")
#pragma comment(lib, "Urlmon.lib")
#pragma comment(lib, "Wininet.lib")

//***********************************************************************************************
// 
// Identify the include members.
//
//***********************************************************************************************
#include <stdio.h>
#include <winsock2.h>
#include <windows.h>
#include <winreg.h>
#include <C:\\detours\\include\\detours.h>
#include <algorithm>
#include <stdlib.h>
#include <iostream>
#include <tchar.h>
#include <atlconv.h>
#include <ctime>
#include <chrono>
#include <future>
#include <psapi.h>
#include <strsafe.h>
#include <fcntl.h> 
#include <fstream>
#include <Iphlpapi.h>
#include <sys/stat.h>
#include <io.h>  
#include <locale> 
#include <codecvt>
#include <ntsecapi.h>
#include <Objbase.h>
#include <Shlobj.h>
#include <subauth.h>
#include <ws2tcpip.h> 
#include <TlHelp32.h>
#include <Urlmon.h>
#include <vector>
#include <Wincrypt.h>
#include <Wininet.h>
#include <winsock2.h>
#include <mscoree.h>
#include "verify.cpp"

//***********************************************************************************************
//
// Define global variables that need to exist between API calls.
//
//***********************************************************************************************

// Default lengths for socket communication.
#define BUFSIZE 512

// Create Socket variable.
SOCKET ConnectSocket = INVALID_SOCKET;

// Variables containing paths for artifacts.
static std::string MACTdir;
static std::string MACTdirFilesClosed;
static std::string MACTdirFilesDeleted;
static std::string MACTdirFilesMapped;
static std::string MACTdirFilesCreated;
static std::string MACTdirMem;

// Define variables that keep track of specific states between API calls.
static BOOL  fBroke          = FALSE;
static BOOL  fLog            = FALSE;
static LONG  dwSlept         = 0;
static BOOL  MACTFINISH      = FALSE;
static BOOL  MACTDEBUG       = FALSE;
static BOOL  MACTDEBUG2      = FALSE;
static BOOL  MACTSTARTED     = FALSE;
static BOOL  MACTVERBOSE     = TRUE;
static BOOL  MACTBP          = FALSE;
static BOOL  MACTSEND        = FALSE;
static int   MACTMSGS        = 0;
static int   MACTWRITE       = TRUE;
static BOOL  MACTWIN7        = TRUE;
static int   MACTTICKCOUNT   = 0;
static int   MACTTICKNUM     = 0;
static int   MACTTICKCOUNT64 = 0;
static int   MACTTICKNUM64   = 0;
static int   MACTQPCCOUNT = 0;
static int   MACTQPCNUM      = 0;
static DWORD MACTTICKADJ     = 0;

static std::vector<int> vTicks;
static std::vector<int> vTicks64;
static std::vector<LARGE_INTEGER> vQPC;


// Memory allocation definition.
typedef struct Mem {
    LPVOID            Mem_address;
    size_t            Mem_size;
    int               Mem_type;
    int               Mem_interval;
    std::future<void> Mem_futureObj;
} MEMDATA, *PMEMDATA;
PMEMDATA pDataArray[8096];
DWORD    dwThreadIdArray[8096];
HANDLE   hThreadArray[8096];

// Thread information.  Threads are spawned to tracked changes in memory allocations.
int      THREADCOUNT = 0;
std::promise<void> exitSignal; 

// Global variables used for return value substitution.
static HANDLE      SR_HANDLE;
static BOOL        SR_BOOL;
static LPVOID      SR_LPVOID;
static UINT        SR_UINT;
static HINSTANCE   SR_HINSTANCE;
static LONG        SR_LONG;
static HCERTSTORE  SR_HCERTSTORE;
static SC_HANDLE   SR_SC_HANDLE;
static HRSRC       SR_HRSRC;
static HWND        SR_HWND;
static ULONG       SR_ULONG;
static SHORT       SR_SHORT;
static HDC         SR_HDC;
static hostent     SR_HOSTENT;
static INT         SR_INT;
static DWORD       SR_DWORD;
static HMODULE     SR_HMODULE;
static FARPROC     SR_FARPROC;
static LANGID      SR_LANGID;
static HINTERNET   SR_HINTERNET;
static NTSTATUS    SR_NTSTATUS;
static HGLOBAL     SR_HGLOBAL;
static LSTATUS     SR_LSTATUS;
static HHOOK       SR_HHOOK;
static HRESULT     SR_HRESULT;
static SOCKET      SR_SOCKET;
static ULONGLONG   SR_ULONGLONG;
//26


// Memory construct definition.
struct MACTVA {
    LPVOID       MACTVAAddress;
    SIZE_T       MACTVASize;
    CHAR         MACTVAType;
    std::string  MACTVAStatus;
    DWORD        MACTVAProtect;
};

static const INT MAXMEMCON = 8192;
MACTVA aMemory[MAXMEMCON];
int aMemoryCount = 0;

// Storage to track breakpoint information.
std::string MACTBreakpoints[50];
int MACTBreakpointCount = 0;

// Substitute MACTSTARTUPINFO structure.
typedef struct _MACTSTARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} MACTSTARTUPINFOA, *LPMACTSTARTUPINFOA;

// Function signatures for calls before defined.
BOOL MACTSocketPrint2(CHAR* a1);
BOOL MACTPrint(const CHAR *psz, ...);
static INT MACTReceive(CHAR* sType);
VOID MACTlog(const CHAR *psz, ...);
void MACTCreateThread(LPVOID buffer, size_t msize, int interval, int imemtype);
HANDLE WINAPI MyCreateFileA(LPCSTR a0,
                            DWORD a1,
                            DWORD a2,
                            LPSECURITY_ATTRIBUTES a3,
                            DWORD a4,
                            DWORD a5,
                            HANDLE a6);
HANDLE WINAPI MyCreateFileW(LPCWSTR a0,
                            DWORD a1,
                            DWORD a2,
                            LPSECURITY_ATTRIBUTES a3,
                            DWORD a4,
                            DWORD a5,
                            HANDLE a6);
BOOL WINAPI MyWriteFileEx(HANDLE a0,
                          LPCVOID a1,
                          DWORD a2,
                          LPOVERLAPPED a3,
                          LPOVERLAPPED_COMPLETION_ROUTINE a4);
BOOL WINAPI MyFlushFileBuffers(HANDLE a0);
BOOL WINAPI MyCloseHandle(HANDLE a0);

//
//***********************************************************************************************
//
// Function   : TrueSleep
// Description: This function suspends the execution of the current thread for a specified 
//              interval. 
// Relavance  : Used by Malware to appear inactive.
//
//***********************************************************************************************
static VOID (WINAPI * TrueSleep)(DWORD a0) = Sleep;
//***********************************************************************************************
//
// Function   : TrueSleepEx
// Description: This function suspends the execution of the current thread for a specified 
//              interval. 
// Relavance  : Used by Malware to appear inactive.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueSleepEx)(DWORD a0, 
                                    BOOL  a1) = SleepEx;
//***********************************************************************************************
//
// Function   : TrueGetTickCount
// Description: Retrieves the number of milliseconds that have elapsed since the system was  
//              started, up to 49.7 days.
// Relavance  : Used by Malware to try and detect being analyzed.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetTickCount)(void) = GetTickCount;
//***********************************************************************************************
//
// Function   : TrueGetTickCount64
// Description: Retrieves the number of milliseconds that have elapsed since the system was 
//              started.
// Relavance  : Used by Malware to try and detect being analyzed.
//
//***********************************************************************************************
static ULONGLONG (WINAPI * TrueGetTickCount64)(void) = GetTickCount64;
//***********************************************************************************************
//
// Function   : TrueQueryPerformanceCounter
// Description: Retrieves the current value of the performance counter, which is a high  
//              resolution (<1us) time stamp that can be used for time-interval measurements.
// Relavance  : Used by Malware to try and detect being analyzed.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueQueryPerformanceCounter)(_Out_ LARGE_INTEGER *a0) = QueryPerformanceCounter;
//***********************************************************************************************
//
// Function   : lstrcmpiA
// Description: Compares two character strings. 
// Relavance  : 
//
//***********************************************************************************************
static INT (WINAPI * TruelstrcmpiA)(LPCSTR a0,
                                    LPCSTR a1) = lstrcmpiA;
//***********************************************************************************************
//
// Function   : lstrcmpiW
// Description: Compares two character strings. 
// Relavance  : 
//
//***********************************************************************************************
static INT (WINAPI * TruelstrcmpiW)(LPCWSTR a0,
                                    LPCWSTR a1) = lstrcmpiW;
//***********************************************************************************************
//
// Function   : lstrcmpW
// Description: Compares two character strings. 
// Relavance  : 
//
//***********************************************************************************************
static INT (WINAPI * TruelstrcmpW)(LPCWSTR a0,
                                   LPCWSTR a1) = lstrcmpW;
//***********************************************************************************************
//
// Function   : CompareStringEx
// Description: Compares two Unicode (wide character) strings, for a locale specified by name. 
// Relavance  : 
//
//***********************************************************************************************
static INT (WINAPI * TrueCompareStringEx)(LPCWSTR                          a0,
                                          DWORD                            a1,
                                          _In_NLS_string_(cchCount1)LPCWCH a2,
                                          int                              a3,
                                          _In_NLS_string_(cchCount2)LPCWCH a4,
                                          int                              a5,
                                          LPNLSVERSIONINFO                 a6,
                                          LPVOID                           a7,
                                          LPARAM                           a8) = CompareStringEx;
//***********************************************************************************************
//
// Function   : TrueCreateFileA
// Description: Creates or opens a file or I/O device.
// Relavance  :
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateFileA)(LPCSTR a0,
                                         DWORD a1,
                                         DWORD a2,
                                         LPSECURITY_ATTRIBUTES a3,
                                         DWORD a4,
                                         DWORD a5,
                                         HANDLE a6) = CreateFileA;
//***********************************************************************************************
//
// Function   : TrueGetFileSize
// Description: Retrieves the size of the specified file, in bytes.
// Relavance  :
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetFileSize)(HANDLE  a0,
                                        LPDWORD a1) = GetFileSize;
//***********************************************************************************************
//
// Function   : TrueCreateFileW
// Description: Creates or opens a file or I/O device.
// Relavance  :
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateFileW)(LPCWSTR a0,
                                         DWORD a1,
                                         DWORD a2,
                                         LPSECURITY_ATTRIBUTES a3,
                                         DWORD a4,
                                         DWORD a5,
                                         HANDLE a6) = CreateFileW;
//***********************************************************************************************
//
// Function   : TrueWriteFile
// Description: Writes data to the specified file or input/output (I/O) device. 
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueWriteFile)(HANDLE       a0,
                                     LPCVOID      a1,
                                     DWORD        a2,
                                     LPDWORD      a3,
                                     LPOVERLAPPED a4) = WriteFile;
//***********************************************************************************************
//
// Function   : TrueWriteFileEx
// Description: Writes data to the specified file or input/output (I/O) device.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueWriteFileEx)(HANDLE a0,
                                       LPCVOID a1,
                                       DWORD a2,
                                       LPOVERLAPPED a3,
                                       LPOVERLAPPED_COMPLETION_ROUTINE a4) = WriteFileEx;
//***********************************************************************************************
//
// Function   : TrueFlushFileBuffers
// Description: Flushes the buffers of a specified file and causes all buffered data to be 
//              written to a file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueFlushFileBuffers)(HANDLE a0) = FlushFileBuffers;
//***********************************************************************************************
//
// Function   : TrueCloseHandle
// Description: Closes an open object handle.
// Relavance  :
//
//***********************************************************************************************

static BOOL (WINAPI * TrueCloseHandle)(HANDLE a0) = CloseHandle;
//***********************************************************************************************
//
// Function   : TrueCopyFileA
// Description: Copies an existing file to a new file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCopyFileA)(LPCSTR a0,
                                     LPCSTR a1,
                                     BOOL a2) = CopyFileA;
//***********************************************************************************************
//
// Function   : TrueCopyFileExA
// Description: Copies an existing file to a new file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCopyFileExA)(LPCSTR a0,
                                       LPCSTR a1,
                                       LPPROGRESS_ROUTINE a2,
                                       LPVOID a3,
                                       LPBOOL a4,
                                       DWORD a5) = CopyFileExA;
//***********************************************************************************************
//
// Function   : TrueCopyFileExW
// Description: Copies an existing file to a new file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCopyFileExW)(LPCWSTR            a0,
                                       LPCWSTR            a1,
                                       LPPROGRESS_ROUTINE a2,
                                       LPVOID             a3,
                                       LPBOOL             a4,
                                       DWORD              a5) = CopyFileExW;
//***********************************************************************************************
//
// Function   : TrueCopyFileW
// Description: Copies an existing file to a new file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCopyFileW)(LPCWSTR a0,
                                     LPCWSTR a1,
                                     BOOL    a2) = CopyFileW;
//***********************************************************************************************
//
// Function   : TrueDeleteFileA
// Description: Deletes the specified file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueDeleteFileA)(LPCSTR a0) = DeleteFileA;
//***********************************************************************************************
//
// Function   : TrueDeleteFileW
// Description: Deletes the specified file.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueDeleteFileW)(LPCWSTR a0) = DeleteFileW;
//***********************************************************************************************
//
// Function   : TrueVirtualAlloc
// Description: This function is a memory-allocation routine that can allocate memory in a remote 
//              process.
// Relavance  : Malware sometimes uses VirtualAllocEx as part of process injection.
//
//***********************************************************************************************
static LPVOID (WINAPI * TrueVirtualAlloc)(LPVOID a0,
                                          SIZE_T a1,
                                          DWORD a2,
                                          DWORD a3) = VirtualAlloc;
//***********************************************************************************************
//
// Function   : TrueVirtualAllocEx
// Description: This function is a memory-allocation routine that can allocate memory in a remote 
//              process.
// Relavance  : Malware sometimes uses VirtualAllocEx as part of process injection.
//
//***********************************************************************************************
static LPVOID (WINAPI * TrueVirtualAllocEx)(HANDLE a0,
                                            LPVOID a1,
                                            SIZE_T a2,
                                            DWORD  a3,
                                            DWORD  a4) = VirtualAllocEx;
//***********************************************************************************************
//
// Function   : TrueVirtualFree
// Description: Releases, decommits, or releases and decommits a region of pages within the  
//              virtual address space of the calling process.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueVirtualFree)(LPVOID a0,
                                       SIZE_T a1,
                                       DWORD  a2) = VirtualFree;
//***********************************************************************************************
//
// Function   : TrueVirtualFreeEx
// Description: Releases, decommits, or releases and decommits a region of memory within the
//              virtual address space of a specified process.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueVirtualFreeEx)(HANDLE a0,
                                         LPVOID a1,
                                         SIZE_T a2,
                                         DWORD a3) = VirtualFreeEx;
//***********************************************************************************************
//
// Function   : TrueCoTaskMemAlloc
// Description: Allocates a block of task memory in the same way that IMalloc::Alloc does.
// Relavance  :
//
//***********************************************************************************************
static __drv_allocatesMem(Mem)LPVOID (WINAPI * TrueCoTaskMemAlloc)(SIZE_T a0) = CoTaskMemAlloc;
//***********************************************************************************************
//
// Function   : TrueCoTaskMemFree
// Description: Frees a block of task memory previously allocated through a call to the  
//              CoTaskMemAlloc or CoTaskMemRealloc function.
// Relavance  :
//
//***********************************************************************************************
static VOID (WINAPI * TrueCoTaskMemFree)(LPVOID a0) = CoTaskMemFree;
//***********************************************************************************************
//
// Function   : TrueVirtualProtect
// Description: This function is used to change the protection on a region of memory.
// Relavance  : Malware may use this function to change a read-only section of memory to an 
//              executable.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueVirtualProtect)(LPVOID a0,
                                          SIZE_T a1,
                                          DWORD a2,
                                          PDWORD a3) = VirtualProtect;
//***********************************************************************************************
//
// Function   : TrueVirtualProtectEx
// Description: Changes the protection on a region of committed pages in the virtual address 
//              space of a specified process.
// Relavance  : Malware may use this function to change a read-only section of memory to an 
//              executable.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueVirtualProtectEx)(HANDLE a0,
                                            LPVOID a1,
                                            SIZE_T a2,
                                            DWORD a3,
                                            PDWORD a4) = VirtualProtectEx;
//***********************************************************************************************
//
// Function   : TrueWinExec
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************
static UINT (WINAPI * TrueWinExec)(LPCSTR a0,
                                   UINT a1) = WinExec;
//***********************************************************************************************
//
// Function   : TrueShellExecuteW
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************
static HINSTANCE (WINAPI * TrueShellExecuteW)(HWND a0,
                                              LPCWSTR a1,
                                              LPCWSTR a2,
                                              LPCWSTR a3,
                                              LPCWSTR a4,
                                              INT     a5) = ShellExecuteW;
//***********************************************************************************************
//
// Function   : TrueShellExecuteExA
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueShellExecuteExA)(SHELLEXECUTEINFOA *a0) = ShellExecuteExA;
//***********************************************************************************************
//
// Function   : TrueShellExecuteExW
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueShellExecuteExW)(SHELLEXECUTEINFOW *a0) = ShellExecuteExW;
//***********************************************************************************************
//
// Function   : TrueRegGetValueA
// Description: Retrieves the type and data for the specified registry value.
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegGetValueA)(HKEY    a0,
                                        LPCSTR  a1,
                                        LPCSTR  a2,
                                        DWORD   a3,
                                        LPDWORD a4,
                                        PVOID   a5,
                                        PDWORD  a6) = RegGetValueA;
//***********************************************************************************************
//
// Function   : TrueRegGetValueW
// Description: Retrieves the type and data for the specified registry value.
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegGetValueW)(HKEY    a0,
                                        LPCWSTR a1,
                                        LPCWSTR a2,
                                        DWORD   a3,
                                        LPDWORD a4,
                                        PVOID   a5,
                                        PDWORD  a6) = RegGetValueW;
//***********************************************************************************************
//
// Function   : TrueRegQueryValueEx
// Description: Retrieves the data associated with the default or unnamed value of a specified 
//              registry key.
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegQueryValueEx)(HKEY    a0,
                                           LPCTSTR a1,
                                           LPDWORD a2,
                                           LPDWORD a3,
                                           LPBYTE  a4,
                                           LPDWORD a5) = RegQueryValueEx;
//***********************************************************************************************
//
// Function   : TrueRegOpenKeyEx
// Description: Opens the specified registry key. 
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegOpenKeyEx)(HKEY    a0,
                                        LPCTSTR a1,
                                        DWORD   a2,
                                        REGSAM  a3,
                                        PHKEY   a4) = RegOpenKeyEx;
//***********************************************************************************************
//
// Function   : TrueRegSetValueA
// Description: Sets the data and type of a specified value under a registry key.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegSetValueA)(HKEY   a0,
                                           LPCSTR a1,
                                           DWORD  a2,
                                           LPCSTR a3,
                                           DWORD  a4) = RegSetValueA;
//***********************************************************************************************
//
// Function   : TrueRegSetValueEx
// Description: Sets the data and type of a specified value under a registry key.
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegSetValueEx)(HKEY         a0,
                                         LPCTSTR      a1,
                                         DWORD        a2,
                                         DWORD        a3,
                                         const BYTE * a4,
                                         DWORD        a5) = RegSetValueEx;
//***********************************************************************************************
//
// Function   : TrueRegSetValueExW
// Description: Sets the data and type of a specified value under a registry key.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegSetValueExW)(HKEY         a0,
                                             LPCWSTR      a1,
                                             DWORD        a2,
                                             DWORD        a3,
                                             const BYTE * a4,
                                             DWORD        a5) = RegSetValueExW;
//***********************************************************************************************
//
// Function   : TrueRegEnumKeyExA
// Description: Enumerates the subkeys of the specified open registry key. The function retrieves 
//              information about one subkey each time it is called.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegEnumKeyExA)(HKEY      a0,
                                            DWORD     a1,
                                            LPSTR     a2,
                                            LPDWORD   a3,
                                            LPDWORD   a4,
                                            LPSTR     a5,
                                            LPDWORD   a6,
                                            PFILETIME a7) = RegEnumKeyExA;
//***********************************************************************************************
//
// Function   : TrueRegEnumKeyExW
// Description: Enumerates the subkeys of the specified open registry key. The function retrieves 
//              information about one subkey each time it is called.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegEnumKeyExW)(HKEY      a0,
                                            DWORD     a1,
                                            LPWSTR    a2,
                                            LPDWORD   a3,
                                            LPDWORD   a4,
                                            LPWSTR    a5,
                                            LPDWORD   a6,
                                            PFILETIME a7) = RegEnumKeyExW;
//***********************************************************************************************
//
// Function   : TrueRegCreateKeyEx
// Description: Creates the specified registry key. If the key already exists, the function opens it.
// Relavance  :
//
//***********************************************************************************************
static LONG (WINAPI * TrueRegCreateKeyEx)(HKEY                  a0,
                                          LPCTSTR               a1,
                                          DWORD                 a2,
                                          LPTSTR                a3,
                                          DWORD                 a4,
                                          REGSAM                a5,
                                          LPSECURITY_ATTRIBUTES a6,
                                          PHKEY                 a7,
                                          LPDWORD               a8) = RegCreateKeyEx;
//***********************************************************************************************
//
// Function   : TrueAdjustTokenPrivileges
// Description: This function is used to enable or disable specific access privileges. 
// Relavance  : In a process injection attack, this function is used by malware to gain additional 
//              permissions.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueAdjustTokenPrivileges)(HANDLE            a0,
                                                 BOOL              a1,
                                                 PTOKEN_PRIVILEGES a2,
                                                 DWORD             a3,
                                                 PTOKEN_PRIVILEGES a4,
                                                 PDWORD            a5) = AdjustTokenPrivileges;
//***********************************************************************************************
//
// Function   : TrueAttachThreadInput
// Description: This function attaches the input processing from one thread to another so that 
//              the second thread receives input events such as keyboard and mouse events. 
// Relavance  : Keyloggers and other spyware use this function.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueAttachThreadInput)(DWORD a0,
                                             DWORD a1,
                                             BOOL  a2) = AttachThreadInput;
//***********************************************************************************************
//
// Function   : TrueBitBlt
// Description: This function is used to copy graphic data from one device to another.
// Relavance  : Spyware sometimes uses this function to capture screenshots.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueBitBlt)(HDC   a0, 
                                  int   a1,
                                  int   a2,
                                  int   a3,
                                  int   a4,
                                  HDC   a5,
                                  int   a6,
                                  int   a7,
                                  DWORD a8) = BitBlt;
//***********************************************************************************************
//
// Function   : TrueCertOpenSystemStore
// Description: This function is used to access the certificates stored on the local system.
// Relavance  :
//
//***********************************************************************************************
static HCERTSTORE (WINAPI * TrueCertOpenSystemStore)(HCRYPTPROV_LEGACY a0,
                                                     LPCTSTR           a1) = CertOpenSystemStore;
//***********************************************************************************************
//
// Function   : TrueControlService
// Description: This function is used to start, stop, modify, or send a signal to a running 
//              service.
// Relavance  : If malware is using its own malicious service, code needs to be analyzed that 
//              implements the service in order to determine the purpose of the call.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueControlService)(SC_HANDLE        a0,
                                          DWORD            a1,
                                          LPSERVICE_STATUS a2) = ControlService;
//***********************************************************************************************
//
// Function   : TrueCreateMutex
// Description: This function creates a mutual exclusion object
// Relavance  : Can be used by malware to ensure that only a single instance of the malware is 
//              running on a system at any given time.  Malware often uses fixed names for 
//              mutexes, which can be good host-based indicators to detect additional 
//              installations of the malware.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateMutex)(LPSECURITY_ATTRIBUTES a0,
                                         BOOL                  a1,
                                         LPCTSTR               a2) = CreateMutex;
//***********************************************************************************************
//
// Function   : TrueCreateMutexEx
// Description: This function creates a mutual exclusion object
// Relavance  : Can be used by malware to ensure that only a single instance of the malware is 
//              running on a system at any given time.  Malware often uses fixed names for 
//              mutexes, which can be good host-based indicators to detect additional 
//              installations of the malware.
//
//***********************************************************************************************
static HANDLE (WINAPI  * TrueCreateMutexEx)(LPSECURITY_ATTRIBUTES a0,
                                            LPCTSTR               a1,
                                            DWORD                 a2,
                                            DWORD                 a3) = CreateMutexEx;
//***********************************************************************************************
//
// Function   : TrueCreateProcess
// Description: This function creates and launches a new process.
// Relavance  : If malware creates a new process, new process needs to be analyzed as well.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCreateProcess)(LPCTSTR               a0,
                                         LPTSTR                a1,
                                         LPSECURITY_ATTRIBUTES a2,
                                         LPSECURITY_ATTRIBUTES a3,
                                         BOOL                  a4,
                                         DWORD                 a5,
                                         LPVOID                a6,
                                         LPCTSTR               a7,
                                         LPSTARTUPINFO         a8,
                                         LPPROCESS_INFORMATION a9) = CreateProcess;
//***********************************************************************************************
//
// Function   : TrueCreateProcessW
// Description: This function creates and launches a new process.
// Relavance  : If malware creates a new process, new process needs to be analyzed as well.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCreateProcessW)(LPCWSTR               a0,
                                          LPWSTR                a1,
                                          LPSECURITY_ATTRIBUTES a2,
                                          LPSECURITY_ATTRIBUTES a3,
                                          BOOL                  a4,
                                          DWORD                 a5,
                                          LPVOID                a6,
                                          LPCWSTR               a7,
                                          LPSTARTUPINFOW        a8,
                                          LPPROCESS_INFORMATION a9) = CreateProcessW;
//***********************************************************************************************
//
// Function   : TrueTerminateProcess
// Description: Terminates the specified process and all of its threads.
// Relavance  : 
//
//***********************************************************************************************
static BOOL (WINAPI * TrueTerminateProcess)(HANDLE a0,
                                            UINT   a1) = TerminateProcess;
//***********************************************************************************************
//
// Function   : TrueCreateRemoteThread
// Description: This function is used to start a thread in a remote process.
// Relavance  : Launchers and stealth malware use CreateRemoteThread to inject code into a 
//              different process.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateRemoteThread)(HANDLE                 a0,
                                                LPSECURITY_ATTRIBUTES  a1,
                                                SIZE_T                 a2,
                                                LPTHREAD_START_ROUTINE a3,
                                                LPVOID                 a4,
                                                DWORD                  a5,
                                                LPDWORD                a6) = CreateRemoteThread;
//***********************************************************************************************
//
// Function   : TrueCreateRemoteThread
// Description: This function is used to start a thread in a remote process.
// Relavance  : Launchers and stealth malware use CreateRemoteThread to inject code into a 
//              different process.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateRemoteThreadEx)(HANDLE                       a0,
                                                  LPSECURITY_ATTRIBUTES        a1,
                                                  SIZE_T                       a2,
                                                  LPTHREAD_START_ROUTINE       a3,
                                                  LPVOID                       a4,
                                                  DWORD                        a5,
                                                  LPPROC_THREAD_ATTRIBUTE_LIST a6,
                                                  LPDWORD                      a7) = CreateRemoteThreadEx;
//***********************************************************************************************
//
// Function   : TrueCreateService
// Description: This function is used to create a service that can be started at boot time.
// Relavance  : Malware uses CreateService for persistence, stealth, or to load kernel drivers.
//
//***********************************************************************************************
static SC_HANDLE (WINAPI * TrueCreateService)(SC_HANDLE a0,
                                              LPCTSTR   a1,
                                              LPCTSTR   a2,
                                              DWORD     a3,
                                              DWORD     a4,
                                              DWORD     a5,
                                              DWORD     a6,
                                              LPCTSTR   a7,
                                              LPCTSTR   a8,
                                              LPDWORD   a9,
                                              LPCTSTR   a10,
                                              LPCTSTR   a11,
                                              LPCTSTR   a12) = CreateService;
//***********************************************************************************************
//
// Function   : TrueCreateToolhelp32Snapshot
// Description: This function is used to create a snapshot of processes, heaps, threads, and 
//              modules.
// Relavance  : Malware often uses this function as part of code that iterates through processes 
//              or threads.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateToolhelp32Snapshot)(DWORD a0,
                                                      DWORD a1) = CreateToolhelp32Snapshot;
//***********************************************************************************************
//
// Function   : TrueCryptAcquireContextA
// Description: The CryptAcquireContext function is used to acquire a handle to a particular key 
//              container within a particular cryptographic service provider (CSP).
// Relavance  : This function is often the first function used by malware to initialize the use 
//              of Windows encryption.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCryptAcquireContextA)(HCRYPTPROV *a0,
                                                LPCTSTR    a1,
                                                LPCTSTR    a2,
                                                DWORD      a3,
                                                DWORD      a4) = CryptAcquireContext;
//***********************************************************************************************
//
// Function   : TrueCryptAcquireContextW
// Description: The CryptAcquireContext function is used to acquire a handle to a particular key 
//              container within a particular cryptographic service provider (CSP).
// Relavance  : This function is often the first function used by malware to initialize the use 
//              of Windows encryption.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueCryptAcquireContextW)(HCRYPTPROV *a0,
                                                LPCWSTR    a1,
                                                LPCWSTR    a2,
                                                DWORD      a3,
                                                DWORD      a4) = CryptAcquireContextW;
//***********************************************************************************************
//
// Function   : TrueDeviceIoControl
// Description: This function sends a control message from user space to a device driver.
// Relavance  : Kernel malware that needs to pass information between user space and kernel space 
//              often use this function.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueDeviceIoControl)(HANDLE       a0,
                                           DWORD        a1,
                                           LPVOID       a2,
                                           DWORD        a3,
                                           LPVOID       a4,
                                           DWORD        a5,
                                           LPDWORD      a6,
                                           LPOVERLAPPED a7) = DeviceIoControl;
//***********************************************************************************************
//
// Function   : TrueEnumProcesses
// Description: This function is used to enumerate through running processes on the system.
// Relavance  : Malware often enumerates through processes to find a process into which to 
//              inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueEnumProcesses)(DWORD *a0,
                                         DWORD a1,
                                         DWORD *a2) = EnumProcesses;
//***********************************************************************************************
//
// Function   : TrueEnumProcessModules

// Relavance  : Malware enumerates through modules when doing an injection.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueEnumProcessModules)(HANDLE  a0,
                                              HMODULE *a1,
                                              DWORD   a2,
                                              LPDWORD a3) = EnumProcessModules;
//***********************************************************************************************
//
// Function   : TrueEnumProcessModulesEx
// Description: This function is used to enumerate the loaded modules (executables and DLLs) for 
//              a given process.
// Relavance  : Malware enumerates through modules when doing an injection.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueEnumProcessModulesEx)(HANDLE  a0,
                                                HMODULE *a1,
                                                DWORD   a2,
                                                LPDWORD a3,
                                                DWORD   a4) = EnumProcessModulesEx;
//***********************************************************************************************
//
// Function   : TrueFindFirstFile
// Description: This function is used to search through a directory and enumerate the file 
//              system.
// Relavance  :
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueFindFirstFile)(LPCTSTR           a0,
                                           LPWIN32_FIND_DATA a1) = FindFirstFile;
//***********************************************************************************************
//
// Function   : TrueFindFirstFileEx
// Description: This function is used to search through a directory and enumerate the file 
//              system.
// Relavance  :
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueFindFirstFileEx)(LPCTSTR            a0,
                                             FINDEX_INFO_LEVELS a1,
                                             LPVOID             a2,
                                             FINDEX_SEARCH_OPS  a3,
                                             LPVOID             a4,
                                             DWORD              a5) = FindFirstFileEx;
//***********************************************************************************************
//
// Function   : TrueFindNextFile
// Description: This function is used to search through a directory and enumerate the file 
//              system.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueFindNextFile)(HANDLE             a0,
                                        LPWIN32_FIND_DATAA a1) = FindNextFile;
//***********************************************************************************************
//
// Function   : TrueNextNextFileEx
// Description: This function is used to search through a directory and enumerate the file 
//              system.
// Relavance  :
//
//***********************************************************************************************
static HRSRC (WINAPI * TrueFindResourceA)(HMODULE a0,
                                          LPCSTR  a1,
                                          LPCSTR  a2) = FindResourceA;
//***********************************************************************************************
//
// Function   : TrueNextNextFileEx
// Description: This function is used to search through a directory and enumerate the file 
//              system.
// Relavance  :
//
//***********************************************************************************************
static HRSRC (WINAPI * TrueFindResourceExA)(HMODULE a0,
                                            LPCSTR  a1,
                                            LPCSTR  a2,
                                            WORD    a3) = FindResourceExA;
//***********************************************************************************************
//
// Function   : TrueFindWindow
// Description: This function is used to search for an open window on the desktop.
// Relavance  : Sometimes this function is used as an anti-debugging technique to search for 
//              OllyDbg windows.
//
//***********************************************************************************************
static HWND (WINAPI * TrueFindWindow)(LPCTSTR a0,
                                      LPCTSTR a1) = FindWindow;
//***********************************************************************************************
//
// Function   : TrueFindWindow
// Description: This function is used to search for an open window on the desktop.
// Relavance  : Sometimes this function is used as an anti-debugging technique to search for 
//              OllyDbg windows.
//
//***********************************************************************************************
static HWND (WINAPI * TrueFindWindowEx)(HWND    a0,
                                        HWND    a1,
                                        LPCTSTR a2,
                                        LPCTSTR a3) = FindWindowExA;
//***********************************************************************************************
//
// Function   : TrueFtpOpenFileW
// Description: Initiates access to a remote file on an FTP server for reading or writing.
// Relavance  :
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueFtpOpenFileW)(HINTERNET a0,
                                             LPCWSTR   a1,
                                             DWORD     a2,
                                             DWORD     a3,
                                             DWORD_PTR a4) = FtpOpenFileW;
//***********************************************************************************************
//
// Function   : TrueFtpPutFile
// Description: This function is used to upload a file to remote FTP server.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueFtpPutFile)(HINTERNET a0, 
                                      LPCTSTR a1, 
                                      LPCTSTR a2, 
                                      DWORD a3, 
                                      DWORD a4) = FtpPutFile; 
//***********************************************************************************************
//
// Function   : TrueGetAdaptersInfo
// Description: This function is used to obtain information about the network adapters on the 
//              system.
// Relavance  : Backdoors sometimes call GetAdaptersInfo in the information-gathering phase to 
//              gather information about infected machines. In some cases, it’s used to gather 
//              MAC addresses to check for VMware as part of anti-virtual machine techniques.
//
//***********************************************************************************************
static ULONG (WINAPI * TrueGetAdaptersInfo)(PIP_ADAPTER_INFO a0,
                                            PULONG           a1) = GetAdaptersInfo;
//***********************************************************************************************
//
// Function   : TrueGetAsyncKeyState
// Description: This function is used to determine whether a particular key is being pressed.
// Relavance  : Malware sometimes uses this function to implement a keylogger.
//
//***********************************************************************************************
static SHORT (WINAPI * TrueGetAsyncKeyState)(int a0) = GetAsyncKeyState;
//***********************************************************************************************
//
// Function   : TrueGetDC
// Description: This function returns a handle to a device context for a window or the whole 
//              screen.
// Relavance  : Spyware that takes screen captures often uses this function.
//
//***********************************************************************************************
static HDC (WINAPI * TrueGetDC)(HWND a0) = GetDC;
//***********************************************************************************************
//
// Function   : TrueGetForegroundWindow
// Description: This function returns a handle to the window currently in the foreground of the 
//              desktop.
// Relavance  : Keyloggers commonly use this function to determine in which window the user is 
//              entering his keystrokes.
//
//***********************************************************************************************
static HWND (WINAPI * TrueGetForegroundWindow)(void) = GetForegroundWindow;
//***********************************************************************************************
//
// Function   : TrueGetWindowText
// Description: Copies the text of the specified window's title bar (if it has one) into a 
//              buffer. If the specified window is a control, the text of the control is copied. 
// Relavance  : Can be used to get text from forms.
//
//***********************************************************************************************
static INT (WINAPI * TrueGetWindowText)(HWND   a0,
                                        LPTSTR a1,
                                        int    a2) = GetWindowText;
//***********************************************************************************************
//
// Function   : Truegethostbyname
// Description: This function is used to perform a DNS lookup on a particular hostname prior to 
//              making an IP connection to a remote host.
// Relavance  : Hostnames that serve as command and-control servers often make good 
//              network-based signatures.
//
//***********************************************************************************************
static hostent *(WINAPI * Truegethostbyname)(const char *a0) = gethostbyname;
//***********************************************************************************************
//
// Function   : Truegethostname
// Description: This function is used to retrieve the hostname of the computer.
// Relavance  : Backdoors sometimes use gethostname in information gathering phase of the 
//              victim machine.
//
//***********************************************************************************************
static int (WINAPI * Truegethostname)(char *a0,
                                      int  a1) = gethostname;
//***********************************************************************************************
//
// Function   : Truegetaddrinfo
// Description: This function translates from an ANSI host name to an address.
// Relavance  : 
//
//***********************************************************************************************
static INT (WINAPI * Truegetaddrinfo)(PCSTR            a0,
                                      PCSTR            a1,
                                      const ADDRINFOA *a2,
                                      PADDRINFOA      *a3) = getaddrinfo;
//***********************************************************************************************
//
// Function   : TrueGetKeyState
// Description: Obtain the status of a particular key on the keyboard.
// Relavance  : This function is used by keyloggers to obtain the status of a particular key.
//
//***********************************************************************************************
static SHORT (WINAPI * TrueGetKeyState)(int a0) = GetKeyState;
//***********************************************************************************************
//
// Function   : GetModuleFileName
// Description: This function returns the filename of a module that is loaded in the current 
//              process.
// Relavance  : Malware can use this function to modify or copy files in the currently running 
//              process.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetModuleFileName)(HMODULE a0,
                                              LPTSTR  a1,
                                              DWORD   a2) = GetModuleFileName;
//***********************************************************************************************
//
// Function   : GetModuleFileNameExA
// Description: This function returns the filename of a module that is loaded in the current 
//              process.
// Relavance  : Malware can use this function to modify or copy files in the currently running 
//              process.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetModuleFileNameExA)(HANDLE  a0,
                                                 HMODULE a1,
                                                 LPSTR   a2,
                                                 DWORD   a3) = GetModuleFileNameExA;
//***********************************************************************************************
//
// Function   : GetModuleFileNameExW
// Description: This function returns the filename of a module that is loaded in the current 
//              process.
// Relavance  : Malware can use this function to modify or copy files in the currently running 
//              process.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetModuleFileNameExW)(HANDLE  a0,
                                                 HMODULE a1,
                                                 LPWSTR  a2,
                                                 DWORD   a3) = GetModuleFileNameExW;
//***********************************************************************************************
//
// Function   : TrueGetModuleHandle
// Description: This function is used to obtain a handle to an already loaded module.

//
//***********************************************************************************************
static HMODULE (WINAPI * TrueGetModuleHandle)(LPCTSTR a0) = GetModuleHandle;
//***********************************************************************************************
//
// Function   : TrueGetModuleHandleEx
// Description: This function is used to obtain a handle to an already loaded module.
// Relavance  : Malware may use GetModuleHandle to locate and modify code in a loaded module or 
//              to search for a good location to inject code.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueGetModuleHandleEx)(DWORD    a0,
                                             LPCTSTR  a1,
                                             HMODULE *a2) = GetModuleHandleEx;
//***********************************************************************************************
//
// Function   : TrueGetProcAddress
// Description: This function is used to retrieve the address of a function in a DLL loaded into 
//              memory.
// Relavance  : This is used to import functions from other DLLs in addition to the functions 
//              imported in the PE file header.
//
//***********************************************************************************************
static FARPROC (WINAPI * TrueGetProcAddress)(HMODULE a0,
                                             LPCSTR  a1) = GetProcAddress;
//***********************************************************************************************
//
// Function   : TrueGetStartupInfoA
// Description: This function is used to retrieve a structure containing details about how the  
//              current process was configured to run, such as where the standard handles are 
//              directed.
// Relavance  :
//
//***********************************************************************************************
static VOID (WINAPI * TrueGetStartupInfoA)(LPSTARTUPINFOA a0) = GetStartupInfoA;
//***********************************************************************************************
//
// Function   : TrueGetSystemDefaultLangID
// Description: This function returns the default language settings for the system.
// Relavance  : These are used by malwares by specifically designed for region-based attacks.
//
//***********************************************************************************************
static LANGID (WINAPI * TrueGetSystemDefaultLangID)(void) = GetSystemDefaultLangID;
//***********************************************************************************************
//
// Function   : TrueGetTempPathA
// Description: This function returns the temporary file path.
// Relavance  : If malware call this function, check whether it reads or writes any files in the 
//              temporary file path.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueGetTempPathA)(DWORD a0,
                                         LPSTR a1) = GetTempPathA;
//***********************************************************************************************
//
// Function   : TrueGetThreadContext
// Description: This function returns the context structure of a given thread.
// Relavance  : The context for a thread stores all the thread information, such as the register 
//              values and current state.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueGetThreadContext)(HANDLE    a0,
                                            LPCONTEXT a1) = GetThreadContext;
//***********************************************************************************************
//
// Function   : TrueGetVersionEx
// Description: This function returns information about which version of Windows is currently 
//              running.
// Relavance  : This can be used as part of a victim survey, or to select between different 
//              offsets for undocumented structures that have changed between different versions
//              of Windows.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueGetVersionEx)(LPOSVERSIONINFO a0) = GetVersionEx;
//***********************************************************************************************
//
// Function   : TrueGetWindowsDirectory
// Description: This function returns the file path to the Windows directory (usually C:\Windows)
// Relavance  : Malware sometimes uses this call to determine into which directory to install 
//              additional malicious programs.
//
//***********************************************************************************************
static UINT (WINAPI * TrueGetWindowsDirectory)(LPTSTR a0,
                                               UINT   a1) = GetWindowsDirectory;
//***********************************************************************************************
//
// Function   : Trueinet_addr
// Description: This function converts an IP address string like 127.0.0.1 so that it can be used 
//              by functions such as connect. The string specified can sometimes be used as a 
//              network-based signature.
// Relavance  :
//
//***********************************************************************************************
static ULONG (WINAPI * Trueinet_addr)(const char * a0) = inet_addr;
//***********************************************************************************************
//
// Function   : TrueInternetOpen
// Description: This function initializes the high-level Internet access functions from WinINet, 
//              such as InternetOpenUrl and InternetReadFile. Searching for InternetOpen is a 
//              good way to find the start of Internet access functionality. One of the 
//              parameters to InternetOpen is the User-Agent, which can sometimes make a good 
//              network-based signature.
// Relavance  :
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueInternetOpen)(LPCTSTR a0, 
                                             DWORD   a1, 
                                             LPCTSTR a2, 
                                             LPCTSTR a3, 
                                             DWORD   a4) = InternetOpen;
//***********************************************************************************************
//
// Function   : TrueInternetOpenW
// Description: This function initializes the high-level Internet access functions from WinINet, 
//              such as InternetOpenUrl and InternetReadFile. Searching for InternetOpen is a 
//              good way to find the start of Internet access functionality. One of the 
//              parameters to InternetOpen is the User-Agent, which can sometimes make a good 
//              network-based signature.
// Relavance  :
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueInternetOpenW)(LPCWSTR a0, 
                                              DWORD   a1, 
                                              LPCWSTR a2, 
                                              LPCWSTR a3, 
                                              DWORD   a4) = InternetOpenW;
//***********************************************************************************************
//
// Function   : TrueInternetOpenUrl
// Description: This function opens a specific URL for a connection using FTP, HTTP, or HTTPS. 
//              URLs, if fixed, can often be good network-based signatures.
// Relavance  :
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueInternetOpenUrl)(HINTERNET a0, 
                                                LPCTSTR   a1, 
                                                LPCTSTR   a2, 
                                                DWORD     a3, 
                                                DWORD     a4, 
                                                DWORD_PTR a5) = InternetOpenUrl;
//***********************************************************************************************
//
// Function   : TrueInternetOpenUrlA
// Description: This function opens a specific URL for a connection using FTP, HTTP, or HTTPS. 
//              URLs, if fixed, can often be good network-based signatures.
// Relavance  :
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueInternetOpenUrlA)(HINTERNET a0, 
                                                 LPCSTR    a1, 
                                                 LPCSTR    a2, 
                                                 DWORD     a3, 
                                                 DWORD     a4, 
                                                 DWORD_PTR a5) = InternetOpenUrlA;
//***********************************************************************************************
//
// Function   : TrueInternetConnectW
// Description: This function opens an FTP or HTTP session for a specified site.
// Relavance  : C&C Communication and downloading payloads.
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueInternetConnectW)(HINTERNET     a0, 
                                                 LPCWSTR       a1, 
                                                 INTERNET_PORT a2, 
                                                 LPCWSTR       a3, 
                                                 LPCWSTR       a4, 
                                                 DWORD         a5, 
                                                 DWORD         a6, 
                                                 DWORD         a7) = InternetConnectW;
//***********************************************************************************************
//
// Function   : TrueHttpOpenRequestW
// Description: Creates an HTTP request handle.
// Relavance  : Communication
//
//***********************************************************************************************
static HINTERNET (WINAPI * TrueHttpOpenRequestW)(HINTERNET  a0,
                                                 LPCWSTR    a1,
                                                 LPCWSTR    a2,
                                                 LPCWSTR    a3,
                                                 LPCWSTR    a4,
                                                 LPCWSTR   *a5,
                                                 DWORD      a6,
                                                 DWORD_PTR  a7) = HttpOpenRequestW;
//***********************************************************************************************
//
// Function   : TrueHttpSendRequestW
// Description: Creates an HTTP request handle.
// Relavance  : Communication
//
//***********************************************************************************************
static BOOL (WINAPI * TrueHttpSendRequestW)(HINTERNET a0,
                                            LPCWSTR   a1,
                                            DWORD     a2,
                                            LPVOID    a3,
                                            DWORD     a4) = HttpSendRequestW;
//***********************************************************************************************
//
// Function   : TrueHttpSendRequestExW
// Description: Creates an HTTP request handle.
// Relavance  : Communication
//
//***********************************************************************************************
static BOOL (WINAPI * TrueHttpSendRequestExW)(HINTERNET           a0,
                                              LPINTERNET_BUFFERSW a1,
                                              LPINTERNET_BUFFERSW a2,
                                              DWORD               a3,
                                              DWORD_PTR           a4) = HttpSendRequestExW;
//***********************************************************************************************
//
// Function   : TrueInternetReadFile
// Description: This function reads data from a previously opened URL.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueInternetReadFile)(HINTERNET a0, 
                                            LPVOID    a1, 
                                            DWORD     a2, 
                                            LPDWORD   a3) = InternetReadFile;
//***********************************************************************************************
//
// Function   : TrueInternetWriteFile
// Description: This function reads data from a previously opened URL.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueInternetWriteFile)(HINTERNET a0, 
                                             LPCVOID   a1, 
                                             DWORD     a2, 
                                             LPDWORD   a3) = InternetWriteFile;
//***********************************************************************************************
//
// Function   : TrueIsWow64Process
// Description: This function is used by a 32-bit process to determine if it is running on a 
//              64-bit operating system.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueIsWow64Process)(HANDLE a0,
                                          PBOOL a1) = IsWow64Process;
//***********************************************************************************************
//
// Function   : LdrLoadDll
// Description: This is a low-level function to load a DLL into a process, just like LoadLibrary.
// Relavance  : Normal programs use LoadLibrary, and the presence of this import may indicate a 
//              program that is attempting to be stealthy.
//
//***********************************************************************************************
typedef NTSTATUS (WINAPI *fLdrLoadDll) 
(
    IN PWCHAR PathToFile OPTIONAL,
    IN ULONG Flags OPTIONAL, 
    IN PUNICODE_STRING ModuleFileName, 
    OUT PHANDLE ModuleHandle 
); 
// Not part of export table of ntdll.dll, have to access this way.
HMODULE hmodule = GetModuleHandleA("ntdll.dll");
fLdrLoadDll   _LdrLoadDll = (fLdrLoadDll) TrueGetProcAddress ( hmodule, "LdrLoadDll" );
static NTSTATUS (WINAPI * TrueLdrLoadDll)(PWCHAR           a0,
                                          ULONG            a1,
                                          PUNICODE_STRING  a2,
                                          PHANDLE          a3) = _LdrLoadDll;
//***********************************************************************************************
//
// Function   : RtlCreateRegistryKey
// Description: This function is used to create a registry from kernel-mode code.
// Relavance  : 
//
//***********************************************************************************************
typedef NTSTATUS (WINAPI *fRtlCreateRegistryKey) 
(
    IN ULONG RelativeTo,
    IN PWSTR Path
); 
// Not part of export table of ntdll.dll, have to access this way.
HMODULE hmodule2 = GetModuleHandleA("ntdll.dll");
fRtlCreateRegistryKey _RtlCreateRegistryKey = (fRtlCreateRegistryKey) TrueGetProcAddress(hmodule2, "RtlCreateRegistryKey");
static NTSTATUS (WINAPI * TrueRtlCreateRegistryKey)(ULONG a0,
                                                    PWSTR a1) = _RtlCreateRegistryKey;
//***********************************************************************************************
//
// Function   : RtlWriteRegistryValue
// Description: This function is used to write a value to the registry from kernel-mode code.
// Relavance  : 
//
//***********************************************************************************************
typedef NTSTATUS (WINAPI *fRtlWriteRegistryValue) 
(
    IN ULONG  RelativeTo,
    IN PCWSTR Path,
    IN PCWSTR ValueName,
    IN ULONG  ValueType,
    IN PVOID  ValueData,
    IN ULONG  ValueLength
); 
// Not part of export table of ntdll.dll, have to access this way.
HMODULE hmodule3 = GetModuleHandleA("ntdll.dll");
fRtlWriteRegistryValue _RtlWriteRegistryValue = (fRtlWriteRegistryValue) TrueGetProcAddress(hmodule3, "RtlWriteRegistryValue");
static NTSTATUS (WINAPI * TrueRtlWriteRegistryValue)(ULONG  a0,
                                                     PCWSTR a1,
                                                     PCWSTR a2,
                                                     ULONG  a3,
                                                     PVOID  a4,
                                                     ULONG  a5) = _RtlWriteRegistryValue;
//***********************************************************************************************
//
// Function   : TrueLoadResource
// Description: This function loads a resource from a PE file into memory.
// Relavance  : Malware sometimes uses resources to store strings, configuration information, or 
//              other malicious files.
//
//***********************************************************************************************
static HGLOBAL (WINAPI * TrueLoadResource)(HMODULE a0,
                                           HRSRC   a1) = LoadResource;
//***********************************************************************************************
//
// Function   : TrueLsaEnumerateLogonSessions
// Description: This function is used to enumerate through logon sessions on the current system. 
// Relavance  : Can be used as part of a credential stealer.
//
//***********************************************************************************************
static NTSTATUS (WINAPI * TrueLsaEnumerateLogonSessions)(PULONG a0,
                                                         PLUID  *a1) = LsaEnumerateLogonSessions;
//***********************************************************************************************
//
// Function   : TrueMapViewOfFile
// Description: This function is used to map a file into memory and makes the contents of the 
//              file accessible via memory addresses.
// Relavance  : Launchers, loaders, and injectors use this function to read and modify PE files.
//              By using MapViewOfFile, the malware can avoid using WriteFile to modify the 
//              contents of a file.
//
//*********************************************************************************************** 
static LPVOID (WINAPI * TrueMapViewOfFile)(HANDLE a0,
                                           DWORD  a1,
                                           DWORD  a2,
                                           DWORD  a3,
                                           SIZE_T a4) = MapViewOfFile;
//***********************************************************************************************
//
// Function   : TrueMapViewOfFileEx
// Description: This function is used to map a file into memory and makes the contents of the 
//              file accessible via memory addresses.
// Relavance  : Launchers, loaders, and injectors use this function to read and modify PE files.
//              By using MapViewOfFile, the malware can avoid using WriteFile to modify the 
//              contents of a file.
//
//***********************************************************************************************
static LPVOID (WINAPI * TrueMapViewOfFileEx)(HANDLE a0,
                                             DWORD a1,
                                             DWORD a2,
                                             DWORD a3,
                                             SIZE_T a4,
                                             LPVOID a5) = MapViewOfFileEx;
//***********************************************************************************************
//
// Function   : TrueMapVirtualKeyA
// Description: This function is used to translate a virtual-key code into a character value.
// Relavance  : It is often used by keylogging malware.
//
//***********************************************************************************************
static UINT (WINAPI * TrueMapVirtualKeyA)(UINT a0,
                                          UINT a1) = MapVirtualKeyA;
//***********************************************************************************************
//
// Function   : TrueMapVirtualKeyExA
// Description: This function is used to translate a virtual-key code into a character value.
// Relavance  : It is often used by keylogging malware
//
//***********************************************************************************************
static UINT (WINAPI * TrueMapVirtualKeyExA)(UINT a0,
                                            UINT a1,
                                            HKL  a2) = MapVirtualKeyExA;
//***********************************************************************************************
//
// Function   : TrueMapVirtualKeyW
// Description: This function is used to translate a virtual-key code into a character value.
// Relavance  : It is often used by keylogging malware
//
//***********************************************************************************************
static UINT (WINAPI * TrueMapVirtualKeyW)(UINT a0,
                                          UINT a1) = MapVirtualKeyW;
//***********************************************************************************************
//
// Function   : TrueMapVirtualKeyExW
// Description: This function is used to translate a virtual-key code into a character value.
// Relavance  : It is often used by keylogging malware
//
//***********************************************************************************************
static UINT (WINAPI * TrueMapVirtualKeyExW)(UINT a0,
                                            UINT a1,
                                            HKL  a2) = MapVirtualKeyExW;
//***********************************************************************************************
//
// Function   : TrueModule32First
// Description: This function is used to enumerate through modules loaded into a process.
// Relavance  : Injectors use this function to determine where to inject code.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueModule32First)(HANDLE          a0, 
                                         LPMODULEENTRY32 a1) = Module32First;
//***********************************************************************************************
//
// Function   : TrueModule32Next
// Description: This function is used to enumerate through modules loaded into a process.
// Relavance  : Injectors use this function to determine where to inject code.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueModule32Next)(HANDLE          a0, 
                                        LPMODULEENTRY32 a1) = Module32Next;
//***********************************************************************************************
//
// Function   : TrueOpenMutexA
// Description: This function opens a handle to a mutual exclusion object that can be used by 
//              malware to ensure that only a single instance of malware is running on a system 
//              at any given time.
// Relavance  : Malware often uses fixed names for mutexes, which can be good host-based 
//              indicators.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueOpenMutexA)(DWORD  a0,
                                        BOOL   a1,
                                        LPCSTR a2) = OpenMutexA;
//***********************************************************************************************
//
// Function   : TrueOpenProcess
// Description: This function is used to open a handle to another process running on the system.
// Relavance  : This handle can be used to read and write to the other process memory or to 
//              inject code into the other process.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueOpenProcess)(DWORD a0,
                                         BOOL  a1,
                                         DWORD a2) = OpenProcess;
//***********************************************************************************************
//
// Function   : TrueOutputDebugString
// Description: This function is used to output a string to a debugger if one is attached.
// Relavance  : This can be used as an anti-debugging technique.
//
//***********************************************************************************************
static VOID (WINAPI * TrueOutputDebugString)(LPCTSTR a0) = OutputDebugString;
//***********************************************************************************************
//
// Function   : TrueOutputDebugStringA
// Description: This function is used to output a string to a debugger if one is attached.
// Relavance  : This can be used as an anti-debugging technique.
//
//***********************************************************************************************
static VOID (WINAPI * TrueOutputDebugStringA)(LPCSTR a0) = OutputDebugStringA;
//***********************************************************************************************
//
// Function   : TruePeekNamedPipe
// Description: This function is used to output a string to a debugger if one is attached.
// Relavance  : This can be used as an anti-debugging technique.
//
//***********************************************************************************************
static VOID (WINAPI * TrueOutputDebugStringW)(LPCWSTR a0) = OutputDebugStringW;
//***********************************************************************************************
//
// Function   : TruePeekNamedPipe
// Description: This function is used to copy data from a named pipe without removing data from 
//              the pipe.
// Relavance  : This function is popular with reverse shells.
//
//***********************************************************************************************
static BOOL (WINAPI * TruePeekNamedPipe)(HANDLE  a0,
                                         LPVOID  a1,
                                         DWORD   a2,
                                         LPDWORD a3,
                                         LPDWORD a4,
                                         LPDWORD a5) = PeekNamedPipe;
//***********************************************************************************************
//
// Function   : TrueProcess32First
// Description: This function is used to begin enumerating processes from a previous call to 
//              CreateToolhelp32Snapshot.
// Relavance  : Malware often enumerates through processes to find a process into which to 
//              inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueProcess32First)(HANDLE           a0,
                                          LPPROCESSENTRY32 a1) = Process32First;
//***********************************************************************************************
//
// Function   : TrueProcess32FirstW
// Description: This function is used to begin enumerating processes from a previous call to 
//              CreateToolhelp32Snapshot.
// Relavance  : Malware often enumerates through processes to find a process into which to 
//              inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueProcess32FirstW)(HANDLE            a0,
                                           LPPROCESSENTRY32W a1) = Process32FirstW;
//***********************************************************************************************
//
// Function   : TrueProcess32Next
// Description: This function is used to begin enumerating processes from a previous call to 
//              CreateToolhelp32Snapshot.
// Relavance  : Malware often enumerates through processes to find a process into which to 
//              inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueProcess32Next)(HANDLE           a0,
                                         LPPROCESSENTRY32 a1) = Process32Next;
//***********************************************************************************************
//
// Function   : TrueProcess32NextW
// Description: This function is used to begin enumerating processes from a previous call to 
//              CreateToolhelp32Snapshot..
// Relavance  : Malware often enumerates through processes to find a process into which to 
//              inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueProcess32NextW)(HANDLE            a0,
                                          LPPROCESSENTRY32W a1) = Process32NextW;
//***********************************************************************************************
//
// Function   : TrueQueueUserAPC
// Description: This function is used to execute code for a different thread.
// Relavance  : Malware sometimes uses QueueUserAPC to inject code into another process.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueQueueUserAPC)(PAPCFUNC  a0,
                                         HANDLE    a1,
                                         ULONG_PTR a2) = QueueUserAPC;
//***********************************************************************************************
//
// Function   : TrueReadProcessMemory
// Description: This function is used to read the memory of a remote process.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueReadProcessMemory)(HANDLE  a0,
                                             LPCVOID a1,
                                             LPVOID  a2,
                                             SIZE_T  a3,
                                             SIZE_T  *a4) = ReadProcessMemory;
//***********************************************************************************************
//
// Function   : TrueRegisterHotKey
// Description: This function is used to register a handler to be notified anytime a user enters 
//              a particular key combination (like CTRL-ALT-J), regardless of which window is
//              active when the user presses the key combination.
// Relavance  : This function is sometimes used by spyware that remains hidden from the user 
//              until the key combination is pressed.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueRegisterHotKey)(HWND a0,
                                          int  a1,
                                          UINT a2,
                                          UINT a3) = RegisterHotKey;
//***********************************************************************************************
//
// Function   : TrueRegOpenKeyA
// Description: This function is used to open a handle to a registry key for reading and editing. 
//              Registry keys are sometimes written as a way for software to achieve persistence 
//              on a host. The registry also contains a whole host of operating system and 
//              application setting information.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegOpenKeyA)(HKEY   a0,
                                          LPCSTR a1,
                                          PHKEY  a2) = RegOpenKeyA;
//***********************************************************************************************
//
// Function   : TrueRegOpenKeyExA
// Description: This function is used to open a handle to a registry key for reading and editing. 
//              Registry keys are sometimes written as a way for software to achieve persistence 
//              on a host. The registry also contains a whole host of operating system and 
//              application setting information.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegOpenKeyExA)(HKEY   a0,
                                            LPCSTR a1,
                                            DWORD  a2,
                                            REGSAM a3,
                                            PHKEY  a4) = RegOpenKeyExA;
//***********************************************************************************************
//
// Function   : TrueRegOpenKeyExW
// Description: This function is used to open a handle to a registry key for reading and editing. 
//              Registry keys are sometimes written as a way for software to achieve persistence 
//              on a host. The registry also contains a whole host of operating system and 
//              application setting information.
// Relavance  :
//
//***********************************************************************************************
static LSTATUS (WINAPI * TrueRegOpenKeyExW)(HKEY    a0,
                                            LPCWSTR a1,
                                            DWORD   a2,
                                            REGSAM  a3,
                                            PHKEY   a4) = RegOpenKeyExW;
//***********************************************************************************************
//
// Function   : TrueResumeThread
// Description: This function is used to resume a previously suspended thread.
// Relavance  : ResumeThread is used as part of several injection techniques.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueResumeThread)(HANDLE a0) = ResumeThread;
//***********************************************************************************************
//
// Function   : TrueSamIConnect
// Description: This function is used to connect to the Security Account Manager (SAM) in order 
//              to make future calls that access credential information.
// Relavance  : Hash-dumping programs access the SAM database in order to retrieve the hash of 
//              users’ login passwords.
//
//***********************************************************************************************
typedef LPVOID (WINAPI *SAMICONNECT) 
    (
         IN PDWORD a0,
         IN PDWORD a1, 
         IN PDWORD a2
    );

// Needs to be reached via ordinal.
SAMICONNECT Dallas0()
{
    USES_CONVERSION;
    TCHAR szSystemDir[MAX_PATH+1];
    int nSize = GetSystemDirectory(szSystemDir,MAX_PATH);
    szSystemDir[nSize] = '\0';
    TCHAR szSFCOS[MAX_PATH+1];
    _tcscpy(szSFCOS,szSystemDir);
    _tcscat(szSFCOS,_T("\\samsrv.dll"));
    HMODULE hSFSModule=::LoadLibrary(szSFCOS);
           
    SAMICONNECT pFnSamIConnect;
    pFnSamIConnect = (SAMICONNECT) TrueGetProcAddress(hSFSModule, (LPCSTR)5);

    return (pFnSamIConnect);
}
static LPVOID (WINAPI * TrueSamIConnect)(PDWORD a0,
                                         PDWORD a1,
                                         PDWORD a2) = Dallas0(); 

//***********************************************************************************************
//
// Function   : TrueSetFileTime
// Description: This function is used to modify the creation, access, or last modified time of a 
//              file.
// Relavance  : Malware often uses this function to conceal malicious activity.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueSetFileTime)(HANDLE         a0,
                                       CONST FILETIME *a1,
                                       CONST FILETIME *a2,
                                       CONST FILETIME *a3) = SetFileTime;
//***********************************************************************************************
//
// Function   : TrueSetThreadContext
// Description: This function is used to modify the context of a given thread.
// Relavance  : Some injection techniques use SetThreadContext.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueSetThreadContext)(HANDLE  a0,
                                            const CONTEXT *a1) = SetThreadContext;
//***********************************************************************************************
//
// Function   : TrueSetWindowsHookEx
// Description: This function is used to set a hook function to be called whenever a certain 
//              event is called.
// Relavance  : Commonly used with keyloggers and spyware, this function also provides an easy 
//              way to load  a DLL into all GUI processes on the system. This function is 
//              sometimes added by the compiler.
//
//***********************************************************************************************
static HHOOK (WINAPI * TrueSetWindowsHookEx)(int       a0,
                                             HOOKPROC  a1,
                                             HINSTANCE a2,
                                             DWORD     a3) = SetWindowsHookEx;
//***********************************************************************************************
//
// Function   : TrueSfcTerminateWatcherThread
// Description: This function is used to disable Windows file protection and modify files that 
//              otherwise would be protected.
// Relavance  :
//
//***********************************************************************************************

typedef BOOL (WINAPI *SFCTERMINATEWATCHERTHREAD) (void);
// Needs to be reached via ordinal.
SFCTERMINATEWATCHERTHREAD Dallas()
{
    USES_CONVERSION;
    TCHAR szSystemDir[MAX_PATH+1];
    int nSize = GetSystemDirectory(szSystemDir,MAX_PATH);
    szSystemDir[nSize] = '\0';
    TCHAR szSFCOS[MAX_PATH+1];
    _tcscpy(szSFCOS,szSystemDir);
    _tcscat(szSFCOS,_T("\\sfc_os.dll"));
    HMODULE hSFSModule=::LoadLibrary(szSFCOS);
           
    SFCTERMINATEWATCHERTHREAD pFnSfcTerminateWatcherThread;
    pFnSfcTerminateWatcherThread = (SFCTERMINATEWATCHERTHREAD) TrueGetProcAddress(hSFSModule, (LPCSTR)5);

    return (pFnSfcTerminateWatcherThread);
}

static BOOL (WINAPI * TrueSfcTerminateWatcherThread)(void) = Dallas();  

//***********************************************************************************************
//
// Function   : TrueStartServiceCtrlDispatcherA
// Description: This function is used by a service to connect the main thread of the process to 
//              the service control manager. Any process that runs as a service must call this 
//              function within 30 seconds of startup.
// Relavance  : Locating this function in malware will tell that the function should be run as a 
//              service.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueStartServiceCtrlDispatcherA)(CONST SERVICE_TABLE_ENTRYA *a0) = StartServiceCtrlDispatcherA;
//***********************************************************************************************
//
// Function   : TrueSuspendThread
// Description: This function is used to suspend a thread so that it stops running.
// Relavance  : Malware will sometimes suspend a thread in order to modify it by performing code 
//              injection.
//
//***********************************************************************************************
static DWORD (WINAPI * TrueSuspendThread)(HANDLE a0) = SuspendThread;
//***********************************************************************************************
//
// Function   : Truesystem
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************
static INT (__cdecl * Truesystem)(const char *a0) = system;
//***********************************************************************************************
//
// Function   : True_wsystem
// Description: This function is used to execute another program.
// Relavance  :
//
//***********************************************************************************************  
static INT (__cdecl * True_wsystem)(const wchar_t *a0) = _wsystem;
//***********************************************************************************************
//
// Function   : TrueThread32First
// Description: This function is used to iterate through the threads of a process.
// Relavance  : Injectors use these functions to find an appropriate thread into which to inject.
//
//***********************************************************************************************   
static BOOL (WINAPI * TrueThread32First)(HANDLE          a0,
                                         LPTHREADENTRY32 a1) = Thread32First;
//***********************************************************************************************
//
// Function   : TrueThread32Next
// Description: This function is used to iterate through the threads of a process.
// Relavance  : Injectors use these functions to find an appropriate thread into which to inject.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueThread32Next)(HANDLE          a0,
                                        LPTHREADENTRY32 a1) = Thread32Next;
//***********************************************************************************************
//
// Function   : TrueToolhelp32ReadProcessMemory
// Description: This function is used to read the memory of a remote process.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueToolhelp32ReadProcessMemory)(DWORD   a0,
                                                       LPCVOID a1,
                                                       LPVOID  a2,
                                                       SIZE_T  a3,
                                                       SIZE_T  *a4) = Toolhelp32ReadProcessMemory;
//***********************************************************************************************
//
// Function   : TrueURLDownloadToFile
// Description: This function is used to download a file from a web server and save it to disk.
// Relavance  : This function is popular with downloaders because it implements all the 
//              functionality of a downloader in one function call.
//
//***********************************************************************************************
static HRESULT (WINAPI * TrueURLDownloadToFile)(LPUNKNOWN            a0,
                                                LPCTSTR              a1,
                                                LPCTSTR              a2,
                                                DWORD                a3,
                                                LPBINDSTATUSCALLBACK a4) = URLDownloadToFile;
//***********************************************************************************************
//
// Function   : URLDownloadToFileA
// Description: Downloads bits from the Internet and saves them to a file.
// Relavance  :
//
//***********************************************************************************************
static HRESULT (WINAPI * TrueURLDownloadToFileA)(LPUNKNOWN            a0,
                                                 LPCTSTR              a1,
                                                 LPCTSTR              a2,
                                                 _Reserved_ DWORD     a3,
                                                 LPBINDSTATUSCALLBACK a4) = URLDownloadToFileA;
//***********************************************************************************************
//
// Function   : TrueWideCharToMultiByte
// Description: This function is used to convert a Unicode string into an ASCII string.
// Relavance  :
//
//***********************************************************************************************
static INT (WINAPI * TrueWideCharToMultiByte)(UINT                               a0,
                                              DWORD                              a1,
                                              _In_NLS_string_(cchWideChar)LPCWCH a2,
                                              int                                a3,
                                              LPSTR                              a4,
                                              int                                a5,
                                              LPCCH                              a6,
                                              LPBOOL                             a7) = WideCharToMultiByte;
//***********************************************************************************************
//
// Function   : TrueWriteProcessMemory
// Description: This function is used to write data to a remote process.
// Relavance  : Malware uses WriteProcessMemory as part of process injection.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueWriteProcessMemory)(HANDLE   a0,
                                              LPVOID   a1,
                                              LPCVOID  a2,
                                              SIZE_T   a3,
                                              SIZE_T  *a4) = WriteProcessMemory;
//***********************************************************************************************
//
// Function   : accept
// Description: This function is used to listen for incoming connections.
// Relavance  : This function indicates that the program will listen for incoming connections on 
//              a socket. 
//              It is mostly used by malware to communicate with their Command and Communication 
//              server.
//
//***********************************************************************************************
static SOCKET (WINAPI * Trueaccept)(SOCKET           a0,
                                    struct sockaddr *a1,
                                    int             *a2) = accept;
//***********************************************************************************************
//
// Function   : Truebind
// Description: This function is used to associate a local address to a socket in order to listen
//              for incoming connections.
// Relavance  :
//
//***********************************************************************************************
static INT (WINAPI * Truebind)(SOCKET                 a0,
                               const struct sockaddr *a1,
                               int                    a2) = bind;
//***********************************************************************************************
//
// Function   : Trueconnect
// Description: This function is used to connect to a remote socket.
// Relavance  : Malware often uses low-level functionality to connect to a command-and-control 
//              server. It is mostly used by malware to communicate with their Command and 
//              Communication server.
//
//***********************************************************************************************
static INT (WINAPI * Trueconnect)(SOCKET                 a0,
                                  const struct sockaddr *a1,
                                  int                    a2) = connect;
//***********************************************************************************************
//
// Function   : TrueConnectNamedPipe
// Description: This function is used to create a server pipe for interprocess communication 
//              that will wait for a client pipe to connect.
// Relavance  : Backdoors and reverse shells sometimes use ConnectNamedPipe to simplify 
//              connectivity to a command-and-control server.
//
//***********************************************************************************************
static BOOL (WINAPI * TrueConnectNamedPipe)(HANDLE       a0,
                                            LPOVERLAPPED a1) = ConnectNamedPipe;
//***********************************************************************************************
//
// Function   : Truerecv
// Description: This function is used to receive data from a remote machine.
// Relavance  : Malware often uses this function to receive data from a remote 
//              command-and-control server.
//
//***********************************************************************************************
static INT (WINAPI * Truerecv)(SOCKET   a0,
                               char    *a1,
                               int      a2,
                               int      a3) = recv;
//***********************************************************************************************
//
// Function   : Truesend
// Description: This function is used to send data to a remote machine.
// Relavance  : It is often used by malwares to send data to a remote command-and-control server.
//
//***********************************************************************************************
static INT (WINAPI * Truesend)(SOCKET         a0,
                               const char    *a1,
                               int            a2,
                               int            a3) = send;
//***********************************************************************************************
//
// Function   : TrueWSAStartup
// Description: This function is used to initialize low-level network functionality.
// Relavance  : Finding calls to WSAStartup can often be an easy way to locate the start of
//              network related functionality.
//
//***********************************************************************************************
static INT (WINAPI * TrueWSAStartup)(WORD      a0,
                                     LPWSADATA a1) = WSAStartup;
//***********************************************************************************************
//
// Function   : TrueCreateFileMappingA
// Description: This function is used to create a handle to a file mapping that loads a file into 
//              memory and makes it accessible via memory addresses.
// Relavance  : Launchers, loaders, and injectors use this function to read and modify PE files.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueCreateFileMappingA)(HANDLE                a0,
                                                LPSECURITY_ATTRIBUTES a1,
                                                DWORD                 a2,
                                                DWORD                 a3,
                                                DWORD                 a4,
                                                LPCSTR                a5) = CreateFileMappingA;
//***********************************************************************************************
//
// Function   : TrueIsNTAdmin
// Description: Check if the program is being ran as and Administrator.
// Relavance  :
//
//***********************************************************************************************
//extern BOOL WINAPI IsNTAdmin(DWORD a0, LPDWORD a1);
//static BOOL (WINAPI * TrueIsNTAdmin)(DWORD a0,
//                                     LPDWORD a1) = IsNTAdmin;

typedef BOOL (WINAPI *fIsNTAdmin) 
(
    IN DWORD  a0,
    IN DWORD *a1 
); 
//HMODULE hmodule1 = GetModuleHandleA("advpack.dll");
fIsNTAdmin Dallas2()
{
    USES_CONVERSION;
    TCHAR szSystemDir[MAX_PATH+1];
    int nSize = GetSystemDirectory(szSystemDir,MAX_PATH);
    szSystemDir[nSize] = '\0';
    TCHAR szSFCOS[MAX_PATH+1];
    _tcscpy(szSFCOS,szSystemDir);
    _tcscat(szSFCOS,_T("\\advpack.dll"));
    HMODULE hSFSModule=::LoadLibrary(szSFCOS);
           
    fIsNTAdmin pfIsNTAdmin;
    pfIsNTAdmin = (fIsNTAdmin) TrueGetProcAddress(hSFSModule, (LPCSTR)43);

    return (pfIsNTAdmin);
}
//fIsNTAdmin _IsNTAdmin = (fIsNTAdmin) GetProcAddress ( hmodule1, "IsNTAdmin" );
static BOOL (WINAPI * TrueIsNTAdmin)(DWORD  a0,
                                     DWORD *a1) = Dallas2();

//***********************************************************************************************
//
// Function   : IsUserAnAdmin
// Description: Tests whether the current user is a member of the Administrator's group.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueIsUserAnAdmin)(void) = IsUserAnAdmin;
//***********************************************************************************************
//
// Function   : TrueLoadLibrary
// Description: Loads the specified module into the address space of the calling process. The
//              specified module may cause other modules to be loaded.
// Relavance  :
//
//***********************************************************************************************
static HMODULE (WINAPI * TrueLoadLibrary)(LPCTSTR a0) = LoadLibrary;
//***********************************************************************************************
//
// Function   : TrueLoadLibraryExA
// Description: Loads the specified module into the address space of the calling process. The
//              specified module may cause other modules to be loaded.
// Relavance  :
//
//***********************************************************************************************
static HMODULE (WINAPI * TrueLoadLibraryExA)(LPCSTR a0,
                                             HANDLE a1,
                                             DWORD  a2) = LoadLibraryExA;
//***********************************************************************************************
//
// Function   : TrueGetConsoleWindow
// Description: Retrieves the window handle used by the console associated with the calling 
//              process.
// Relavance  :
//
//***********************************************************************************************
static HWND (WINAPI * TrueGetConsoleWindow)(void) = GetConsoleWindow;
//***********************************************************************************************
//
// Function   : TrueSetProcessDEPPolicy
// Description: Changes data execution prevention (DEP) and DEP-ATL thunk emulation settings for
//              a 32-bit process.
// Relavance  :
//
//***********************************************************************************************
static BOOL (WINAPI * TrueSetProcessDEPPolicy)(DWORD a0) = SetProcessDEPPolicy;
//***********************************************************************************************
//
// Function   : TrueWSASend
// Description: The WSASend function sends data on a connected socket.
// Relavance  :
//
//***********************************************************************************************
static INT (WINAPI * TrueWSASend)(SOCKET                             a0,
                                  LPWSABUF                           a1,
                                  DWORD                              a2,
                                  LPDWORD                            a3,
                                  DWORD                              a4,
                                  LPWSAOVERLAPPED                    a5,
                                  LPWSAOVERLAPPED_COMPLETION_ROUTINE a6) = WSASend;
//***********************************************************************************************
//
// Function   : TrueHeapCreate
// Description: Creates a private heap object that can be used by the calling process.
// Relavance  : Used after loading a resource and before writing to a file.
//
//***********************************************************************************************
static HANDLE (WINAPI * TrueHeapCreate)(DWORD  a0,
                                        SIZE_T a1,
                                        SIZE_T a2) = HeapCreate;
//***********************************************************************************************
//
// Function   : GetTimeStamp
// Description: Returns a time stamp for file name purposes.
//
//***********************************************************************************************
std::string GetTimeStamp() {

    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();

    typedef std::chrono::duration<int, std::ratio_multiply<std::chrono::hours::period, std::ratio<8>
    >::type> Days; /* UTC: +8:00 */

    Days days = std::chrono::duration_cast<Days>(duration);
        duration -= days;
    auto hours = std::chrono::duration_cast<std::chrono::hours>(duration);
        duration -= hours;
    auto minutes = std::chrono::duration_cast<std::chrono::minutes>(duration);
        duration -= minutes;
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
        duration -= seconds;
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(duration);
        duration -= milliseconds;
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(duration);
        duration -= microseconds;
    auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(duration);

    DWORD dTicks;
    char  cTicks[16];
    std::string sTimestamp;

    dTicks = hours.count();
    sprintf(cTicks, "%d", hours.count());
    sTimestamp = cTicks;
    sprintf(cTicks, "%d", minutes.count());
    sTimestamp += cTicks;
    sprintf(cTicks, "%lld", seconds.count());
    sTimestamp += cTicks;
    sprintf(cTicks, "%lld", milliseconds.count());
    sTimestamp += cTicks;
    sprintf(cTicks, "%lld", microseconds.count());
    sTimestamp += cTicks;
    sprintf(cTicks, "%lld", nanoseconds.count());
    sTimestamp += cTicks;

    return(sTimestamp);
}

//***********************************************************************************************
//
// Function   : MACTGetFileName
// Description: Returns the file name from a fully qualified path.
//
//***********************************************************************************************
std::string MACTGetFileName(const std::string& filepath)
{
    auto pos = filepath.rfind("\\");
    if(pos == std::string::npos)
        pos = -1;
    return std::string(filepath.begin() + pos + 1, filepath.end());
}

//***********************************************************************************************
//
// Function   : IsIni
// Description: Determines if the file extension is ini.
//
//***********************************************************************************************
BOOL IsIni(std::string fn)
{
  return(fn.substr(fn.find_last_of(".") + 1) == "ini");
}

//***********************************************************************************************
//
// Function   : IsLnk
// Description: Determines if the file extension is lnk.
//
//***********************************************************************************************
BOOL IsLnk(std::string fn)
{
  return(fn.substr(fn.find_last_of(".") + 1) == "lnk");
}

//***********************************************************************************************
//
// Function   : FileEsists
// Description: Determines if the file exists.
//
//***********************************************************************************************
BOOL FileExists(std::string filename) 
{
    struct stat fileInfo;
    return stat(filename.c_str(), &fileInfo) == 0;
}

//***********************************************************************************************
//
// Function   : CopyFileFromHandle
// Description: Given a file handle this function determines the file name and saves it.
//
//***********************************************************************************************
BOOL CopyFileFromHandle(HANDLE hFile, std::string sDir) 
{
    BOOL bSuccess = FALSE;
    TCHAR pszFilename[MAX_PATH+1];
    HANDLE hFileMap;

// Get the file size.
    DWORD dwFileSizeHi = 0;
    DWORD dwFileSizeLo = TrueGetFileSize(hFile, &dwFileSizeHi); 

    if( dwFileSizeLo == 0 && dwFileSizeHi == 0 )
        return FALSE;

// Create a file mapping object.
    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL); ;

    if (hFileMap == NULL || hFileMap == INVALID_HANDLE_VALUE)
        return FALSE;

//    MACTPrint(">CopyFileFromHandle Point C\n");

    if (hFileMap) 
    {
    // Create a file mapping to get the file name.
        void* pMem = TrueMapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);

        if (pMem) 
        {
            if (GetMappedFileName(GetCurrentProcess(), pMem, pszFilename, MAX_PATH))
            {

        // Translate path with device name to drive letters.
                TCHAR szTemp[BUFSIZE];
                szTemp[0] = '\0';

                if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) 
                {
                    TCHAR szName[MAX_PATH];
                    TCHAR szDrive[3] = TEXT(" :");
                    BOOL bFound = FALSE;
                    TCHAR* p = szTemp;

                    do 
                    {
            // Copy the drive letter to the template string
                        *szDrive = *p;

            // Look up each device name
                        if (QueryDosDevice(szDrive, szName, MAX_PATH))
                        {
                            size_t uNameLen = _tcslen(szName);

                            if (uNameLen < MAX_PATH) 
                            {
                                bFound = _tcsnicmp(pszFilename, szName, uNameLen) == 0 && *(pszFilename + uNameLen) == _T('\\');
                                if (bFound) 
                                {
                  // Reconstruct pszFilename using szTempFile
                  // Replace device path with DOS path
                                    TCHAR szTempFile[MAX_PATH];
                                    StringCchPrintf(szTempFile, MAX_PATH, TEXT("%s%s"), szDrive, pszFilename+uNameLen);
                                    StringCchCopyN(pszFilename, MAX_PATH+1, szTempFile, _tcslen(szTempFile));
                                }
                            }
                        } 
                        while (*p++);
                    } while (!bFound && *p); // end of string
                }
            }
            bSuccess = TRUE;
            UnmapViewOfFile(pMem);
        } 

        TrueCloseHandle(hFileMap);
    }

    if (bSuccess && !IsIni(pszFilename) && !IsLnk(pszFilename) && FileExists(pszFilename)) {
//        MACTPrint(">Target file name %s\n", MACTGetFileName(pszFilename).c_str());
        std::string sFilename = sDir + "\\" + GetTimeStamp() + " " + MACTGetFileName(pszFilename);
        TrueCopyFileA((LPCSTR)pszFilename, sFilename.c_str(), 0);
    }
    else
        return(FALSE);


    return(bSuccess);
}

//***********************************************************************************************
//
// Function   : MACTAddToMemoryConstruct
// Description: Add a memory allocation to the structure used for tracking.
//
//***********************************************************************************************
void MACTAddToMemoryConstruct(LPVOID lAddress, SIZE_T tSize, DWORD dProtect, int imemtype)
{
    BOOL bReallocated = FALSE;
    int  iCurrent = 0;

    for(int x = 0; x < aMemoryCount; ++x) {
        if((aMemory[x].MACTVAAddress != NULL) && (aMemory[x].MACTVAAddress == lAddress)){
            bReallocated = TRUE;
            aMemory[x].MACTVASize    = tSize;
            aMemory[x].MACTVAType    = imemtype;
            aMemory[x].MACTVAStatus  = "Allocated";
            aMemory[x].MACTVAProtect = dProtect;
            iCurrent = x;
            if(MACTDEBUG)
                MACTPrint(">DEBUG: MACTAddToMemoryConstruct found = %x\n", (int)aMemory[x].MACTVAAddress);
            break;              
        }
    }


    if(!bReallocated && (aMemoryCount < MAXMEMCON))
    {
        aMemory[aMemoryCount].MACTVAAddress = lAddress;
        aMemory[aMemoryCount].MACTVASize    = tSize;
        aMemory[aMemoryCount].MACTVAStatus  = "Allocated";
        aMemory[aMemoryCount].MACTVAType    = imemtype;
        aMemory[aMemoryCount].MACTVAProtect = dProtect;
        
        if(MACTDEBUG) {
            printf("DEBUG: address in aMemory = %x\n", (int)aMemory[aMemoryCount].MACTVAAddress);
            printf("DEBUG: size in aMemory    = %zu\n", aMemory[aMemoryCount].MACTVASize);
        }
        iCurrent = aMemoryCount;
        ++aMemoryCount;
    }
    else {
        if(aMemoryCount >= MAXMEMCON)
            MACTPrint(">MACT error : memory constructs exceed maximum.\n");
    }


    if(aMemory[iCurrent].MACTVAProtect == PAGE_NOACCESS)
        void(0);
    else {
        MACTCreateThread(aMemory[iCurrent].MACTVAAddress, aMemory[iCurrent].MACTVASize, 50, imemtype);
    }

}

//***********************************************************************************************
//
// Function   : MACTSafeOpenFile
// Description: Open a file in a safe way.
//
//***********************************************************************************************
FILE * MACTSafeOpenFile(char *sFilename, char *sMode)
{
    FILE *pFile = NULL;

    __try {
        pFile = fopen(sFilename, sMode);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return NULL;
    }

    return pFile;
}

//***********************************************************************************************
//
// Function   : MACTMemOpen
// Description: Create a memory artifact file.
//
//***********************************************************************************************
FILE * MACTMemOpen(char *sFilename, int iFileName, int imemtype)
{
    FILE *pFile;

    std::string stype[9] = {"Unknown", "VirtualFree", "VirtualFreeEx", "CoTaskMemFree", "WriteProcessMemory", 
                            "ManualSave", "VirtualAlloc", "VirutalAllocEx", "CoTaskMemAlloc"};

    sprintf(sFilename, "%s\\%x %s %s.bin", MACTdirMem.c_str(), iFileName, stype[imemtype].c_str(), GetTimeStamp().c_str());


    pFile = MACTSafeOpenFile(sFilename, "wb");


    return(pFile);
}

//***********************************************************************************************
//
// Function   : MACTSaveFromAddress
// Description: Save a memory artifact.
//
//***********************************************************************************************
void MACTSaveFromAddress(LPVOID lpAddress, SIZE_T dwSize, int imemtype)
{
    char *sFilename = new char[MAX_PATH];
    DWORD sBinaryType = 0;

    FILE *pFile = MACTMemOpen(sFilename, (int)lpAddress, imemtype);
    if(pFile == NULL)
        return;
    __try {
        fwrite(lpAddress, 1, dwSize, pFile);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        fclose(pFile);
        if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
            MACTPrint(">Executable File: %s\n", sFilename);
    }

    fclose(pFile);
    if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
        MACTPrint(">Executable File: %s\n", sFilename);

    delete[] sFilename;
}

//***********************************************************************************************
//
// Function   : MACTSaveMemLoc
// Description: Save an existing memory allocation.
//
//***********************************************************************************************
void MACTSaveMemLoc(LPVOID lpAddress, SIZE_T dwSize, int imemtype)
{
    int iElement = 0;
    if(dwSize == 0) 
        for(iElement = 0; iElement < aMemoryCount; ++iElement) 
            if(aMemory[iElement].MACTVAAddress == lpAddress) {
                dwSize = aMemory[iElement].MACTVASize;
                break;            
            }

    if(iElement != aMemoryCount) {
        MACTSaveFromAddress(lpAddress, dwSize, imemtype);
    } 

}

//***********************************************************************************************
//
// Function   : MACTMemThread
// Description: Start a thread to monitor memory for changes and creating an artifact.
//
//***********************************************************************************************
DWORD WINAPI MACTMemThread(LPVOID lpParam) 
{ 
    PMEMDATA ptDataArray;

    ptDataArray = (PMEMDATA)lpParam;   

    char *MemoryChunk = new char[ptDataArray->Mem_size];
    char *sFilename = new char[MAX_PATH];
    DWORD sBinaryType = 0;
    FILE *pFile = MACTMemOpen(sFilename, (int)ptDataArray->Mem_address, ptDataArray->Mem_type);
    if(pFile == NULL) {
        delete[] MemoryChunk;
        delete[] sFilename;
        return 0;
    }
    __try {
        fwrite(ptDataArray->Mem_address, 1, ptDataArray->Mem_size, pFile);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        fclose(pFile);
        if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
            MACTPrint(">Executable File: %s\n", sFilename);
        delete[] MemoryChunk;
        delete[] sFilename;
        return 0;
    }
    fclose(pFile);
    if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
            MACTPrint(">Executable File: %s\n", sFilename);

    __try {
        CopyMemory(MemoryChunk, ptDataArray->Mem_address, ptDataArray->Mem_size);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        delete[] MemoryChunk;
        delete[] sFilename;
        return 0;
    }

    // when memory contents change create an artifacct, check an after a cetain period for changes
    for(;;) {
        __try {
            TrueSleep(100);
            if(memcmp(MemoryChunk, ptDataArray->Mem_address, ptDataArray->Mem_size) != 0) {
                pFile = MACTMemOpen(sFilename, (int)ptDataArray->Mem_address, ptDataArray->Mem_type);
                if(pFile == NULL) {
                    delete[] MemoryChunk;
                    delete[] sFilename;
                    return 0;
                }
                __try {
                    fwrite(ptDataArray->Mem_address, 1, ptDataArray->Mem_size, pFile);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    fclose(pFile);
                    if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
                        MACTPrint(">Executable File: %s\n", sFilename);
                    delete[] MemoryChunk;
                    delete[] sFilename;
                    return 0;
                };
                fclose(pFile);
                if(GetBinaryTypeA((LPCSTR)sFilename, &sBinaryType))
                        MACTPrint(">Executable File: %s\n", sFilename);
                __try {
                    CopyMemory(MemoryChunk, ptDataArray->Mem_address, ptDataArray->Mem_size);
                } __except(EXCEPTION_EXECUTE_HANDLER) {
                    delete[] MemoryChunk;
                    delete[] sFilename;
                    return 0;
                }
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            break;
        } 
    }

//    printf(">>>>>>>>>>>>>>>>>>>>>>>>Exiting thread.\n");
    delete[] MemoryChunk;
    delete[] sFilename;
    return 0; 
} 

//***********************************************************************************************
//
// Function   : MACTDeleteFromMemoryConstruct
// Description: Delete does not actually occur, rather it is marked as "freed"
//
//***********************************************************************************************
void MACTDeleteFromMemoryConstruct(LPVOID lAddress, int imemtype)
{

    for(int x = 0; x < aMemoryCount; ++x) {
        if(aMemory[x].MACTVAAddress == lAddress) {
            MACTSaveMemLoc(lAddress, aMemory[x].MACTVASize, imemtype);
            aMemory[x].MACTVAStatus  = "Freed";  
            break;              
        }
    }
       
    if(MACTDEBUG) 
        printf("DEBUG: MACTDeleteFromMemoryConstruct parm  = %x\n", (int)lAddress);

}

//***********************************************************************************************
//
// Function   : MACTDisplayMemory
// Description: Display a defined area of process accessable memory.
//
//***********************************************************************************************
void MACTDisplayMemory(LPVOID lAddress, int iLength)
{
    // Determine the number of full rows to display.
    int iRows = (iLength / 16);
    // Determine the bytes left over after all complete rows are displayed.
    int iRem = (iLength % 16);

    // Display all complete rows.
    int iCols = 0;
    for(int z = 1; z <= iRows; ++z) {
        MACTPrint("=%x: ", ((int)lAddress + iCols));
        // Display in hex.
        for(int x = iCols; x < (iCols + 16); ++x)
            MACTPrint("=%02x ", ((uint8_t*) lAddress)[x]);
        MACTPrint("=  ");
        // Display printable characters.
        for(int x = iCols; x < (iCols + 16); ++x)
            if((((uint8_t*) lAddress)[x] > 31) && (((uint8_t*) lAddress)[x] < 128))
                MACTPrint("=%c", ((char*) lAddress)[x]);
            else
                MACTPrint("=.");
        MACTPrint("=\n");
        iCols += 16;
    }

    // Display remaining bytes in incomplete row.
    if(iRem > 0) {
        iRem += iCols;
        MACTPrint("=%x: ", ((int)lAddress + iCols));
        // Display in hex.
        for(int x = iCols; x < iRem; ++x)
            MACTPrint("=%02x ", ((uint8_t*) lAddress)[x]);
        // Add splaces to allign printable characters past the incomplete row.
        MACTPrint("=  ");
        int iSpace = 16 - (iRem - iCols);
        for(int x = 0; x < iSpace; ++x) 
            MACTPrint("=   ");
        // Display printable characters.
        for(int x = iCols; x < iRem; ++x)
            if((((uint8_t*) lAddress)[x] > 31) && (((uint8_t*) lAddress)[x] < 128))
                MACTPrint("=%c", ((char*) lAddress)[x]);
            else
                MACTPrint("=.");       
        MACTPrint("=\n");
    }
}

//***********************************************************************************************
//
// Function   : MACTDisplayMemoryConstruct
// Description: Display the contents of the memory construct.
//
//***********************************************************************************************
void MACTDisplayMemoryConstruct()
{

    if(aMemoryCount > 0) {
        for(int x = 0;x < aMemoryCount; ++x) {
            if((aMemory[x].MACTVAType == 6) || (aMemory[x].MACTVAType == 7)) {
                MACTPrint("=Memory construct %d: \n", x);
                MACTPrint("=\tAddress : %x\n", (int)aMemory[x].MACTVAAddress);
                MACTPrint("=\tSize    : %zu\n", aMemory[x].MACTVASize);
                MACTPrint("=\tType    : %d\n", aMemory[x].MACTVAType);
                MACTPrint("=\tStatus  : %s\n", aMemory[x].MACTVAStatus.c_str());
                MACTPrint("=\tProtect : %02x\n", aMemory[x].MACTVAProtect);

                if(MACTDEBUG)
                    MACTPrint(">DEBUG: MACTDisplayMemoryConstruct Displaying..\n");
            }
        }
    }
    else {
        MACTPrint(">No memory constructs to display.\n");
    }

}

//***********************************************************************************************
//
// Function   : MACTAddBreakpoint
// Description: Add a breakpoint to the breakpoint list.
//
//***********************************************************************************************
void MACTAddBreakpoint(std::string sBreakpoint)
{
    for(int i = 0; i < MACTBreakpointCount; ++i) 
        if(MACTBreakpoints[i] == sBreakpoint) {
            MACTPrint(">Breakpoint already exists.\n");
            return;
        }

    MACTBreakpoints[MACTBreakpointCount] = sBreakpoint;
    ++MACTBreakpointCount;
    MACTPrint(">Breakpoint added for %s\n", sBreakpoint.c_str());
}

//***********************************************************************************************
//
// Function   : MACTDeleteBreakpoint
// Description: Remove a breakpoint from the breakpoint list.
//
//***********************************************************************************************
void MACTDeleteBreakpoint(std::string sBreakpoint)
{

    int i;

    for(i = 0; i < MACTBreakpointCount; ++i) 
        if(MACTBreakpoints[i] == sBreakpoint) 
            break;

    if(i < MACTBreakpointCount) {
        MACTPrint(">Breakpoint %s deleted.\n", sBreakpoint.c_str());
        --MACTBreakpointCount;
        for(int j = i; j < MACTBreakpointCount; ++j) 
            MACTBreakpoints[j] = MACTBreakpoints[++i];
    }
    else
        MACTPrint(">Did not find breakpoint.\n");
}

//***********************************************************************************************
//
// Function   : MACTListBreakpoint
// Description: Display all breakpoints.
//
//***********************************************************************************************
void MACTListBreakpoint()
{
    MACTPrint(">Breakpoints:\n");

    if(MACTBreakpointCount == 0) {
        MACTPrint(">No breakpoints defined.\n");
        return;
    }

    for(int i = 0; i < MACTBreakpointCount; ++i) 
        MACTPrint(">%s\n", MACTBreakpoints[i].c_str());
}

//***********************************************************************************************
//
// Function   : MACTSClearBreakpoint
// Description: Clear all breakpoints.
//
//***********************************************************************************************
void MACTClearBreakpoint()
{
    MACTBreakpointCount = 0;
    MACTPrint(">Breakpoints cleared.\n");
}

//***********************************************************************************************
//
// Function   : MACTSubRetVal
// Description: Perform return value substitution.
//
//***********************************************************************************************
INT MACTSubRetVal(char* sType, int iHex) {
    int iRet = 100;

    if(strncmp(sType, "HANDLE", strlen(sType)) == 0) {
//        return 0;
    }

    if(strncmp(sType, "BOOL", strlen(sType)) == 0) {
        SR_BOOL = iHex;
        return 1;
    }
    
    if(strncmp(sType, "LPVOID", strlen(sType)) == 0) {
//        return 2;
    }

    if(strncmp(sType, "LPVOID", strlen(sType)) == 0) {
        SR_UINT = iHex;
        return 3;
    }

    if(strncmp(sType, "HINSTANCE", strlen(sType)) == 0) {
//        return 4;
    }

    if(strncmp(sType, "LONG", strlen(sType)) == 0) {
        SR_UINT = iHex;
        return 5;
    }

    if(strncmp(sType, "HCERTSTORE", strlen(sType)) == 0) {
//        return 6;
    }

    if(strncmp(sType, "SC_HANDLE", strlen(sType)) == 0) {
//        return 7;
    }

    if(strncmp(sType, "HRSRC", strlen(sType)) == 0) {
//        return 8;
    }

    if(strncmp(sType, "HWND", strlen(sType)) == 0) {
//        return 9;
    }
   
    if(strncmp(sType, "ULONG", strlen(sType)) == 0) {
        SR_UINT = iHex;
        return 10;
    }
    
    if(strncmp(sType, "SHORT", strlen(sType)) == 0) {
        SR_UINT = iHex;
        return 11;
    }

    if(strncmp(sType, "HDC", strlen(sType)) == 0) {
//        return 12;
    }

    if(strncmp(sType, "HOSTENT", strlen(sType)) == 0) {
//        return 13;
    }
    
    if(strncmp(sType, "INT", strlen(sType)) == 0) {
        SR_UINT = iHex;
        return 14;
    }
    
    if(strncmp(sType, "DWORD", strlen(sType)) == 0) {
        SR_DWORD = iHex;
        return 15;
    }
       
    if(strncmp(sType, "HMODULE", strlen(sType)) == 0) {
//        return 16;
    }
    
    if(strncmp(sType, "FARPROC", strlen(sType)) == 0) {
//        return 17;
    }
    
    if(strncmp(sType, "LANGID", strlen(sType)) == 0) {
//        return 18;
    }
    
    if(strncmp(sType, "HINTERNET", strlen(sType)) == 0) {
//        return 19;
    }
    
    if(strncmp(sType, "NTSTATUS", strlen(sType)) == 0) {
//        return 20;
    }
    
    if(strncmp(sType, "HGLOBAL", strlen(sType)) == 0) {
//        return 21;
    }
    
    if(strncmp(sType, "LSTATUS", strlen(sType)) == 0) {
//        return 22;
    }
    
    if(strncmp(sType, "HHOOK", strlen(sType)) == 0) {
//        return 23;
    }
    
    if(strncmp(sType, "HRESULT", strlen(sType)) == 0) {
//        return 24;
    }
    
    if(strncmp(sType, "SOCKET", strlen(sType)) == 0) {
//        return 25;
    }
    
    if(strncmp(sType, "ULONGLONG", strlen(sType)) == 0) {
//        return 26;
    }

    MACTPrint(">%s cannot currently be overridden.\n", sType);
    return iRet;
}


//***********************************************************************************************
//
// Function   : MACTlog
// Description: Write to the MACT log and send to server.
//
//***********************************************************************************************
VOID MACTlog(const CHAR *psz, ...)
{
    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog entry.\n");

    MACTSTARTED = FALSE;

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog point A.\n");

    FILE * pFile;
    std::string sFilename = MACTdir + "\\log.txt";
    pFile = fopen(sFilename.c_str(), "a");

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog point B.\n");

    va_list args;
    va_start(args, psz);
    vfprintf(pFile, psz, args);

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog point C.\n");
    int len;  

    char* buffer;    
    len = _vscprintf(psz, args) + 1;   
    buffer = (char*)malloc( len * sizeof(char) );  
    vsprintf(buffer, psz, args); 

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog point D.\n");

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTlog point E.\n");
 
    va_end(args);


    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);    
    DetourTransactionCommit();

    fclose(pFile);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);  
    DetourTransactionCommit();
    MACTSTARTED = TRUE;

    MACTPrint(buffer);

    free(buffer);
}

//***********************************************************************************************
//
// Function   : MACTreg
// Description: Write to the registry artifact file.
//
//***********************************************************************************************
VOID MACTreg(const CHAR *psz, ...)
{
    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg entry.\n");

    MACTSTARTED = FALSE;

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg point A.\n");

    FILE * pFile;
    std::string sFilename = MACTdir + "\\reg.txt";
    pFile = fopen(sFilename.c_str(), "a");

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg point B.\n");

    va_list args;
    va_start(args, psz);
    vfprintf(pFile, psz, args);

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg point C.\n");

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg point E.\n");
 
    va_end(args);


    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);    
    DetourTransactionCommit();

    fclose(pFile);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);  
    DetourTransactionCommit();
    MACTSTARTED = TRUE;
}

//***********************************************************************************************
//
// Function   : MACTcomm
// Description: Write to the communication artifact file.
//
//***********************************************************************************************
VOID MACTcomm(const CHAR *psz, ...)
{
    MACTSTARTED = FALSE;

    FILE * pFile;
    std::string sFilename = MACTdir + "\\comm.txt";
    pFile = fopen(sFilename.c_str(), "a");

    if(MACTDEBUG)
        MACTPrint(">DEBUG: MACTreg point B.\n");

    va_list args;
    va_start(args, psz);
    vfprintf(pFile, psz, args);

    va_end(args);

    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);    
    DetourTransactionCommit();

    fclose(pFile);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle); 
    DetourTransactionCommit();

    MACTSTARTED = TRUE;
}

//***********************************************************************************************
//
// Function   : MACTCreateLogDir
// Description: Create the log directory structure for this execution.
//
//***********************************************************************************************
VOID CreateLogDir()
{
    time_t now = time(0);
    std::string dt = ctime(&now);
    MACTdir = dt;
    MACTdir.erase(std::remove(MACTdir.begin(), MACTdir.end(), ':'), MACTdir.end());
    MACTdir = "C:\\MACT\\" + MACTdir;
    MACTdir.erase(std::remove(MACTdir.begin(), MACTdir.end(), '\n'), MACTdir.end());

    CreateDirectory("C:\\MACT\\", NULL);

    if(!CreateDirectory(MACTdir.c_str(), NULL)) {
        exit(-1);
    }

    std::string sDir = MACTdir + "\\Files";    
    if(!CreateDirectory(sDir.c_str(), NULL)) {
        exit(-1);
    }

    MACTdirFilesClosed = MACTdir + "\\Files\\Closed";    
    if(!CreateDirectory(MACTdirFilesClosed.c_str(), NULL)) {
        exit(-1);
    }

    MACTdirFilesDeleted = MACTdir + "\\Files\\Deleted";    
    if(!CreateDirectory(MACTdirFilesDeleted.c_str(), NULL)) {
        exit(-1);
    }

    MACTdirFilesMapped = MACTdir + "\\Files\\Mapped";    
    if(!CreateDirectory(MACTdirFilesMapped.c_str(), NULL)) {
        exit(-1);
    }

    MACTdirFilesCreated = MACTdir + "\\Files\\Created";    
    if(!CreateDirectory(MACTdirFilesCreated.c_str(), NULL)) {
        exit(-1);
    }

    MACTdirMem = MACTdir + "\\Mem";    
    if(!CreateDirectory(MACTdirMem.c_str(), NULL)) {
        printf("Error creating log directory.\n");
    }

    fLog = TRUE;

    return;
}


//***********************************************************************************************
//
// Function   : MACTmain
// Description: Begin the interactive functionality.
//
//***********************************************************************************************
static int MACTmain(char* sType)
{
    return MACTReceive(sType);
}

VOID WINAPI MySleep(DWORD a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSleep(a0);

    MACTlog(":Sleep(%x)\n", a0);
        
    MACTlog("-Sleep will return void.\n");
    MACTlog("*Sleep(%x),(void,void,void)", a0);

//    MACTTICK += a0;

    TrueSleep(a0);

    return;
}

DWORD WINAPI MySleepEx(DWORD a0, 
                       BOOL  a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSleepEx(a0, a1);

    MACTlog(":SleepEx(%x,%x)\n", a0, a1);

    DWORD bReturnValue = TrueSleepEx(a0, a1);

    MACTlog("*SleepEx(%x,%x),(void,void,%x)", a0, a1, bReturnValue);

    return bReturnValue;
}

DWORD WINAPI MyGetTickCount(void)
{
//    DWORD retx = TrueGetTickCount();
//    MACTPrint(">%x\n", retx);
//    return retx;

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":GetTickCount(void)\n");

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    if(MACTTICKCOUNT > 0) {
        iOption = 15;
        bReturnValue = vTicks.at(MACTTICKNUM);
        if(MACTTICKNUM < (MACTTICKCOUNT - 1)) 
            ++MACTTICKNUM;
        else     
            MACTPrint(">GetTickCount too many ticks.\n");           
    }

    DWORD ret;
    __try {
        ret = TrueGetTickCount();
    } __finally {
        MACTlog("-GetTickCount will return %x\n", ret);
        MACTlog("*GetTickCount(void),(%x,%x,%x)", ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+GetTickCount modified to return %x\n", ret);
        }
    }

    return ret;
}

ULONGLONG WINAPI MyGetTickCount64(void)
{
//    DWORD retx = TrueGetTickCount64();
//    MACTPrint(">Tick64 %x\n", retx);
//    return retx;

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":GetTickCount64(void)\n");

    ULONGLONG iOption = MACTmain("ULONGLONG");
    ULONGLONG bReturnValue = 0;
    if(iOption == 26) {
        bReturnValue = SR_ULONGLONG;
    }

    if(MACTTICKCOUNT64 > 0) {
        iOption = 24;
        bReturnValue = vTicks64.at(MACTTICKNUM64);
        if(MACTTICKNUM64 < (MACTTICKCOUNT64 - 1)) 
            ++MACTTICKNUM64;
        else     
            MACTPrint(">GetTickCount64 too many ticks.\n");           
    }

    ULONGLONG ret;
    __try {
        ret = TrueGetTickCount64();
    } __finally {
        MACTlog("-GetTickCount64 will return %x\n", ret);
        MACTlog("*GetTickCount64(void),(%x,%x,%x)", ret, iOption, bReturnValue);
        if(iOption == 26) {
            ret = bReturnValue;
            MACTlog("+GetTickCount64 modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyQueryPerformanceCounter(_Out_ LARGE_INTEGER *a0) 
{
//    BOOL retx = TrueQueryPerformanceCounter(a0);
//    MACTPrint(">QueryPerformanceCounter %x\n", a0);
//    return retx;

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":QueryPerformanceCounter(%x)\n", a0);
    MACTmain("BOOL");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    if(MACTQPCCOUNT > 0) {
        iOption = 1;
        bReturnValue = TRUE;
        *a0 = vQPC.at(MACTQPCNUM);
        if(MACTQPCNUM < (MACTQPCCOUNT - 1)) 
            ++MACTQPCNUM;
        else     
            MACTPrint(">QueryPerformanceCounter too many values.\n");           
    }

    BOOL ret = 0;
    __try {
        if(iOption != 1)
            ret = TrueQueryPerformanceCounter(a0);
    } __finally {
        MACTlog("*QueryPerformanceCounter(%x),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        MACTlog("+QueryPerformanceCounter will return %x\n", ret);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTPrint("+QueryPerformanceCounter modified to return %x\n", a0);
        }
    };

    return ret;

}

INT WINAPI MylstrcmpiA(LPCSTR a0,
                       LPCSTR a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TruelstrcmpiA(a0, a1);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":lstrcmpiA(%s,%s)\n", buffer0, buffer1);

    int iOption = MACTmain("HOSTENT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = TruelstrcmpiA(a0, a1);
    } __finally {
        MACTlog("-lstrcmpiA will return %x\n", ret);
        MACTlog("*lstrcmpiA(%s,%s),(%x,%x,%x)", buffer0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+lstrcmpiA modified to return %x\n", ret);
        }
    }

    delete[] buffer0;
    delete[] buffer1;
    //chgsleep
    TrueSleep(50);

    return ret;
}

INT WINAPI MylstrcmpiW(LPCWSTR a0,
                       LPCWSTR a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TruelstrcmpiW(a0, a1);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 

    origsize = wcslen(a1) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer1 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer1, newsize2, a1, _TRUNCATE); 

    MACTlog(":lstrcmpiW(%s,%s)\n", buffer0, buffer1);

    int iOption = MACTmain("HOSTENT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = TruelstrcmpiW(a0, a1);
    } __finally {
        MACTlog("-lstrcmpiW will return %x\n", ret);
        MACTlog("*lstrcmpiW(%s,%s),(%x,%x,%x)", buffer0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+lstrcmpiW modified to return %x\n", ret);
        }
    }

    delete[] buffer0;
    delete[] buffer1;
    //chgsleep
    TrueSleep(50);

    return ret;
}


INT WINAPI MylstrcmpW(LPCWSTR a0,
                      LPCWSTR a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TruelstrcmpW(a0, a1);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 

    origsize = wcslen(a1) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer1 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer1, newsize2, a1, _TRUNCATE); 

    MACTlog(":lstrcmpW(%s,%s)\n", buffer0, buffer1);

    INT iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = TruelstrcmpW(a0, a1);
    } __finally {
        MACTlog("-lstrcmpW will return %x\n", ret);
        MACTlog("*lstrcmpW(%s,%s),(%x,%x,%x)", buffer0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+lstrcmpW modified to return %x\n", ret);
        }
    }

    delete[] buffer0;
    delete[] buffer1;
//chgsleep
    TrueSleep(50);
    return ret;
}

INT WINAPI MyCompareStringEx(LPCWSTR                          a0,
                             DWORD                            a1,
                             _In_NLS_string_(cchCount1)LPCWCH a2,
                             int                              a3,
                             _In_NLS_string_(cchCount2)LPCWCH a4,
                             int                              a5,
                             LPNLSVERSIONINFO                 a6,
                             LPVOID                           a7,
                             LPARAM                           a8)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":CompareStringEx(%p,%p,%p,%d,%p,%d,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7, a8);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = CompareStringEx(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    } __finally {
        MACTlog("-CompareStringEx will return %x\n", ret);
        MACTlog("*CompareStringEx(%p,%p,%p,%d,%p,%d,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, a6, a7, a8, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+CompareStringEx modified to return %x\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyCreateFileA(LPCSTR a0,
                            DWORD a1,
                            DWORD a2,
                            LPSECURITY_ATTRIBUTES a3,
                            DWORD a4,
                            DWORD a5,
                            HANDLE a6)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTPrint(":CreateFileA(%s,%p,%p,%p,%p,%p,%p)\n", buffer0, a1, a2, a3, a4, a5, a6);
    
    int iOption = MACTmain("HANDLE");
    HANDLE hReturnValue;
    if(iOption == 1) {
        hReturnValue = SR_HANDLE;
    }

    HANDLE ret = 0;
    __try {
        ret = TrueCreateFileA(a0, a1, a2, a3, a4, a5, a6);
    } __finally {
        MACTPrint("-CreateFileA will return %p\n", ret);
        MACTPrint("*CreateFileA(%s,%p,%p,%p,%p,%p,%p),(%p,%d,%p)", buffer0, a1, a2, a3, a4, a5, a6, ret, iOption, hReturnValue);
        if(iOption == 1) {
            ret = hReturnValue;
            MACTPrint("+CreateFileA modified to return %p\n", ret);
        }
        delete[] buffer0;
    };
    return ret;
}

HANDLE WINAPI MyCreateFileW(LPCWSTR a0,
                            DWORD a1,
                            DWORD a2,
                            LPSECURITY_ATTRIBUTES a3,
                            DWORD a4,
                            DWORD a5,
                            HANDLE a6)
{
    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 

    if(strncmp(buffer0, "C:\\MACT", 7) == 0) {
        HANDLE ret  = NULL;

        ret = TrueCreateFileW(a0, a1, a2, a3, a4, a5, a6);

        delete[] buffer0;
// chgsleep
        TrueSleep(100);
        return(ret);
    } 

    if(MACTDEBUG2)
        MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTPrint(":CreateFileW(%s,%p,%p,%p,%p,%p,%p)\n", buffer0, a1, a2, a3, a4, a5, a6);

    std::string pszSource = buffer0;

    std::string pszFilename = MACTdirFilesCreated + "\\" + GetTimeStamp() + " " + MACTGetFileName(pszSource);

    MACTPrint(">CreateFileW pszFilename = %s\n", pszFilename.c_str());

    int iOption = MACTmain("HANDLE");
    HANDLE hReturnValue;
    if(iOption == 1) {
        hReturnValue = SR_HANDLE;
    }
    
    HANDLE ret = 0;
    ret = TrueCreateFileW(a0, a1, a2, a3, a4, a5, a6);
    TrueCopyFileA(pszSource.c_str(), pszFilename.c_str(), FALSE);
    MACTPrint("-CreateFileW will return %p\n", ret);
    MACTPrint("*CreateFileW(%s,%p,%p,%p,%p,%p,%p),(%p,%d,%p)", buffer0, a1, a2, a3, a4, a5, a6, ret, iOption, hReturnValue);
    if(iOption == 1) {
        ret = hReturnValue;
        MACTPrint("+CreateFileW modified to return %p\n", ret);
    }
    delete[] buffer0;

// chgsleep
    TrueSleep(200);
    return ret;
}

DWORD WINAPI MyGetFileSize(HANDLE  a0,
                           LPDWORD a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":GetFileSize(%p,%p)\n", a0, a1);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;

    }

    DWORD ret;
    __try {
        ret = TrueGetFileSize(a0,a1);
    } __finally {
        MACTlog("-GetFileSize will return %x\n", ret);
        MACTlog("*GetFileSize(void),(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+GetFileSize modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyWriteFile(HANDLE       a0,
                        LPCVOID      a1,
                        DWORD        a2,
                        LPDWORD      a3,
                        LPOVERLAPPED a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        TrueWriteFile(a0, a1, a2, a3, a4);

    MACTPrint(":WriteFile(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    DetourTransactionCommit();

    BOOL ret = 0;
    __try {
        ret = TrueWriteFile(a0, a1, a2, a3, a4);
        MACTPrint(">Write File %p", (LPVOID)a1);
    } __finally {
        MACTPrint("*WriteFile(%p,%p,%p,%p,%p),(%p,0,0)", a0, a1, a2, a3, a4, ret);
        MACTPrint("+WriteFile will return %x\n", ret);
    };

    return ret;
}

BOOL WINAPI MyWriteFileEx(HANDLE                          a0,
                          LPCVOID                         a1,
                          DWORD                           a2,
                          LPOVERLAPPED                    a3,
                          LPOVERLAPPED_COMPLETION_ROUTINE a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":WriteFileEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
    MACTmain("BOOL");


    BOOL ret = 0;
    __try {
        ret = TrueWriteFileEx(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("*WriteFile(%p,%p,%p,%p,%p),(%p,0,0)", a0, a1, a2, a3, a4, ret);
        MACTlog("+WriteFileEx will return %x\n", ret);
    };

    return ret;
}

BOOL WINAPI MyFlushFileBuffers(HANDLE a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":FlushFileBuffers(%p)\n", a0);
    MACTmain("BOOL");

    MACTSTARTED = FALSE;
    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();

    BOOL ret = 0;
    __try {
        ret = TrueFlushFileBuffers(a0);
    } __finally {
        MACTlog("*FlushFileBuffers(%p),(%p,0,0)", a0, ret);
        MACTlog("+FlushFileBuffers will return %x\n", ret);
    };


    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();
    MACTSTARTED = TRUE;
    

    return ret;
}

BOOL WINAPI MyCloseHandle(HANDLE a0)
{

    MACTSTARTED = FALSE;
    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();

    CopyFileFromHandle(a0, MACTdirFilesClosed);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();
    MACTSTARTED = TRUE;

    BOOL ret = 0;

    ret = TrueCloseHandle(a0);

    return ret;
}

BOOL WINAPI MyCopyFileA(LPCSTR a0,
                        LPCSTR a1,
                        BOOL a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":CopyFileA(%s,%s,%p)\n", buffer0, buffer1, a2);
    if(MACTDEBUG)
        printf("Debug: In CopyFileA return from MACTlog\n");
    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }
    if(MACTDEBUG)
        printf("Debug: In CopyFileA return from MACTmain\n");

    BOOL ret = FALSE;
    __try {
        if(MACTDEBUG) {
            printf("Debug: In CopyFileA before call to TrueCopyFilaA\n");
            printf("Debug: a0 = %s\n", a0);
            printf("Debug: a1 = %s\n", a1);
        }
        ret = TrueCopyFileA(a0, a1, a2);

        if(MACTDEBUG)
            printf("Debug: In CopyFileA after call to TrueCopyFilaA\n");
    } __finally {
        MACTlog("-CopyFileA will return %x\n", ret);
        MACTlog("*CopyFileA(%s,%s,%p),(%x,%x,%x)", buffer0, buffer1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CopyFileA modified to return %x\n", ret);
        }
        delete[] buffer0;
        delete[] buffer1;
    }

    if(MACTDEBUG)
        printf("Debug: In CopyFileA before return.\n");
    return ret;
}

BOOL WINAPI MyCopyFileW(LPCWSTR a0,
                        LPCWSTR a1,
                        BOOL a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 


    origsize = wcslen(a1) + 1;  
    convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a1, _TRUNCATE); 

    MACTlog(":CopyFileW(%s,%s,%p)\n", buffer0, buffer1, a2);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        ret = TrueCopyFileW(a0, a1, a2);
    } __finally {
        MACTlog("-CopyFileW will return %x\n", ret);
        MACTlog("*CopyFileW(%s,%s,%p),(%x,%x,%x)", buffer0, buffer1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CopyFileW modified to return %x\n", ret);           
        }
        delete[] buffer0;
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyCopyFileExA(LPCSTR a0,
                          LPCSTR a1,
                          LPPROGRESS_ROUTINE a2,
                          LPVOID a3,
                          LPBOOL a4,
                          DWORD a5)
{

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":CopyFileExA(%s,%s,%p,%p,%p,%p)\n", buffer0, buffer1, a2, a3, a4, a5);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        ret = TrueCopyFileExA(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-CopyFileExA will return %x\n", ret);
        MACTlog("*CopyFileExA(%s,%s,%p,%p,%p,%p),(%x,%x,%x)", buffer0, buffer1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CopyFileExA modified to return %x\n", ret);           
        }
        delete[] buffer0;
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyCopyFileExW(LPCWSTR a0,
                          LPCWSTR a1,
                          LPPROGRESS_ROUTINE a2,
                          LPVOID a3,
                          LPBOOL a4,
                          DWORD a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCopyFileExW(a0, a1, a2, a3, a4, a5);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer1 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer1, newsize, a0, _TRUNCATE); 

    origsize = wcslen(a1) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer2, newsize2, a1, _TRUNCATE); 

    MACTlog(":CopyFileExW(%s,%s,%p,%p,%p,%p)\n", buffer1, buffer2, a2, a3, a4, a5);


    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        if(MACTDEBUG)
            MACTPrint(">DEBUG: MyCopyFileExW Before TrueCopyFileExW\n");
        ret = TrueCopyFileExW(a0, a1, a2, a3, a4, a5);
    } __finally {
        if(MACTDEBUG)
            MACTPrint(">DEBUG: MyCopyFileExW After TrueCopyFileExW\n");
        MACTlog("-CopyFileExW will return %x\n", ret);
        MACTlog("*CopyFileExW(%ls,%ls,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CopyFileExW modified to return %x\n", ret);           
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

BOOL WINAPI MyDeleteFileA(LPCSTR a0)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":DeleteFileA(%s)\n", buffer0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    MACTSTARTED = FALSE;
    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();

    std::string sTargetFile = MACTdirFilesDeleted + "\\" + GetTimeStamp() + " " + MACTGetFileName(a0);
    TrueCopyFileA(a0, (LPCSTR)sTargetFile.c_str(), 0);

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();
    MACTSTARTED = TRUE;

    BOOL ret = 0;
    ret = TrueDeleteFileA(a0);

    MACTlog("-DeleteFileA will return %x\n", ret);
    MACTlog("*DeleteFileA(%s),(%x,%x,%x)", buffer0, ret, iOption, bReturnValue);
    if(iOption == 1) {
        ret = bReturnValue;
        MACTlog("+DeleteFileA modified to return %x\n", ret);   
    }

    delete[] buffer0;

    return ret;
}

BOOL WINAPI MyDeleteFileW(LPCWSTR a0)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE);

    MACTlog(":DeleteFileW(%s)\n", buffer0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    DetourTransactionBegin();
    DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();


    using convert_type = std::codecvt_utf8<wchar_t>;
    std::wstring_convert<convert_type, wchar_t> converter;
    std::string converted_str = converter.to_bytes(a0);


    std::string sTargetFile = MACTdirFilesDeleted + "\\" + GetTimeStamp() + " " + MACTGetFileName(converted_str);

    std::wstring To(sTargetFile.begin(), sTargetFile.end());
    LPCWSTR dcopy = To.c_str();
    if(MACTDEBUG)
        MACTPrint(">DEBUG: MyDeleteFileW dcopy = %ls\n", dcopy);
    

    if(TrueCopyFileW(a0, dcopy, FALSE) == 0)
        MACTPrint(">DeleteFileW copy failed.\n");

    DetourTransactionBegin();
    DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
    DetourTransactionCommit();

    BOOL ret = 0;
    ret = TrueDeleteFileW(a0);

    MACTlog("-DeleteFileW will return %x\n", ret);
    MACTlog("*DeleteFileW(%s),(%x,%x,%x)", buffer0, ret, iOption, bReturnValue);
    if(iOption == 1) {
        ret = bReturnValue;
        MACTlog("+DeleteFileW modified to return %x\n", ret);        
    }

    delete[] buffer0;

    return ret;
}

LPVOID WINAPI MyVirtualAlloc(LPVOID a0,
                             SIZE_T a1,
                             DWORD a2,
                             DWORD a3)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":VirtualAlloc(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    int iOption = MACTmain("LPVOID");
    LPVOID bReturnValue = NULL;
    if(iOption == 2) {
        bReturnValue = SR_LPVOID;
    }

    LPVOID ret = 0;
    __try {
        if(MACTDEBUG)
            MACTPrint(">DEBUG: VirtualAlloc about to call TrueVirtualAlloc\n");
        ret = TrueVirtualAlloc(a0, a1, a2, a3);
        if(MACTDEBUG)
            MACTPrint(">DEBUG: VirtualAlloc called TrueVirtualAlloc\n");
    } __finally {
        MACTlog("-VirtualAlloc will return %p\n", ret);
        MACTlog("*VirtualAlloc(%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        MACTAddToMemoryConstruct(ret, a1, a3, 6);
        if(iOption == 2) {
            ret = bReturnValue;
            MACTlog("+VirtualAlloc modified to return %p\n", (int)&ret);            
        }
    }

    return ret;
}

LPVOID WINAPI MyVirtualAllocEx(HANDLE a0,
                               LPVOID a1,
                               SIZE_T a2,
                               DWORD  a3,
                               DWORD  a4)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":VirtualAllocEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("LPVOID");
    LPVOID bReturnValue = NULL;
    if(iOption == 2) {
        bReturnValue = SR_LPVOID;
    }

    LPVOID ret = 0;
    __try {
        ret = TrueVirtualAllocEx(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-VirtualAllocEx will return %p\n", ret);
        MACTlog("*VirtualAllocEx(%p,%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        MACTAddToMemoryConstruct(ret, a2, a4, 7);
        if(iOption == 2) {
            ret = bReturnValue;
            MACTlog("+VirtualAllocEx modified to return %p\n", ret);           
        }
    }

    return ret;
}

BOOL WINAPI MyVirtualProtect(LPVOID a0,
                             SIZE_T a1,
                             DWORD a2,
                             PDWORD a3)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

// A lot of virtual protects.  Turn on if you wish.
//    if((a2 == PAGE_EXECUTE_READ) || (a2 == PAGE_EXECUTE_READWRITE) || (a2 == PAGE_EXECUTE_WRITECOPY))    
//        (void)0;
//    else
//        return(TrueVirtualProtect(a0, a1, a2, a3));
    if(!MACTSTARTED)
        return(TrueVirtualProtect(a0, a1, a2, a3));

    if(MACTDEBUG)
        printf(">DEBUG: MyVirtualProtect A\n");

    MACTPrint(":VirtualProtect(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    if(MACTDEBUG)//
        printf(">DEBUG: MyVirtualProtect B\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        ret = TrueVirtualProtect(a0, a1, a2, a3);
    } __finally {
        MACTPrint("-VirtualProtect will return %x\n", ret);
        MACTPrint("*VirtualProtect(%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTPrint("+VirtualProtect modified to return %x\n", (int)&ret);          
        }
    }

    return ret;
}

BOOL WINAPI MyVirtualProtectEx(HANDLE a0,
                               LPVOID a1,
                               SIZE_T a2,
                               DWORD a3,
                               PDWORD a4)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        MACTlog(":VirtualProtectEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        ret = TrueVirtualProtectEx(a0, a1, a2, a3, a4);
        MACTlog("*VirtualProtect(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
    } __finally {
        MACTlog("-VirtualProtectEx will return %x\n", (int)&ret);
        if(iOption == 2) {
            ret = bReturnValue;
            MACTlog("+VirtualProtectEx modified to return %x\n", (int)&ret);           
        }
    }

    return ret;
}

BOOL WINAPI  MyVirtualFree(LPVOID a0,
                           SIZE_T a1,
                           DWORD  a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":VirtualFree(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        MACTDeleteFromMemoryConstruct(a0, 1);
        ret = TrueVirtualFree(a0, a1, a2);
    } __finally {
        MACTlog("-VirtualFree will return %x\n", ret);
        MACTlog("*VirtualFree(%p,%p,%p),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+VirtualFree modified to return %x\n", ret);            
        }
    }

    return ret;
}

BOOL WINAPI MyVirtualFreeEx(HANDLE a0,
                            LPVOID a1,
                            SIZE_T a2,
                            DWORD a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog(":VirtualFreeEx(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = 0;
    __try {
        MACTDeleteFromMemoryConstruct(a1, 2);
        ret = TrueVirtualFreeEx(a0, a1, a2, a3);
    } __finally {
        MACTlog("-VirtualFreeEx will return %x\n", ret);
        MACTlog("*VirtualFreeEx(%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+VirtualFreeEx modified to return %x\n", ret);            
        }
    }

    return ret;
}

__drv_allocatesMem(Mem)LPVOID WINAPI MyCoTaskMemAlloc(SIZE_T a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTPrint(":CoTaskMemAlloc(%x)\n", a0);

    __drv_allocatesMem(Mem)LPVOID ret = 0;
    __try {
        ret = TrueCoTaskMemAlloc(a0);
    } __finally {
        MACTPrint("-CoTaskMemAlloc will return %x\n", ret);
        MACTPrint("*CoTaskMemAlloc(%x),(%p,%x,%p)", a0, ret, 0, 0);
        MACTAddToMemoryConstruct((LPVOID)ret, a0, 0, 8);
    }
//chgsleep
    TrueSleep(50);
    return ret;
}

VOID WINAPI MyCoTaskMemFree(LPVOID a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);


    MACTPrint(":CoTaskMemFree(%p)\n", a0);

    __try {
        MACTDeleteFromMemoryConstruct(a0, 3);
        TrueCoTaskMemFree(a0);
    } __finally {
        MACTPrint("-CoTaskMemFree will return VOID\n");
        MACTPrint("*CoTaskMemFree(%p),(%x,%x,%x)", a0, 0, 0, 0);
    }
//chgsleep
    TrueSleep(50);
    return;
}

UINT WINAPI MyWinExec(LPCSTR a0,
                      UINT a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":WinExec(%s,%u)\n", buffer0, a1);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_UINT;
    }
/*
    if(strncmp(a0, "C:\\Users\\MACT\\AppData\\Local\\Temp\\LhIgoE.exe", sizeof(a0)) == 0) { 
        a0 = "C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\Desktop\\MACT\\LhIgoE.exe";
        MACTPrint(">WinExec override to C:\\Users\\MACT\\AppData\\Local\\Temp\\LhIgoE.exe");
    }

    if(strncmp(a0, "C:\\Users\\MACT\\AppData\\Local\\Temp\\BUSeJQv.exe", sizeof(a0)) == 0) { 
        a0 = "C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\Desktop\\MACT\\BUSeJQv.exe";
        MACTPrint(">WinExec override to C:\\Users\\MACT\\AppData\\Local\\Temp\\BUSeJQv.exe");
    }

    if(strncmp(a0, "C:\\Users\\MACT\\AppData\\Local\\Temp\\ivXSsb.exe", sizeof(a0)) == 0) { 
        a0 = "C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\AppData\\Local\\Temp\\ivXSsb.exe";
        MACTPrint(">WinExec override to C:\\Users\\MACT\\AppData\\Local\\Temp\\ivXSsb.exe");
    }
*/    
    UINT ret = 0;
    __try {
        ret = TrueWinExec(a0, a1);
    } __finally {
        MACTlog("-WinExec will return %x\n", (int)&ret);
        MACTlog("*WinExec(%s,%u),(%u,%x,%u)", buffer0, a1, ret, iOption, bReturnValue);
        if(iOption == 3) {
            ret = bReturnValue;
            MACTlog("+WinExec modified to return %x\n", ret);            
        }
        delete[] buffer0;
    }

    return ret;
}

HINSTANCE WINAPI MyShellExecuteW(HWND a0,
                                 LPCWSTR a1,
                                 LPCWSTR a2,
                                 LPCWSTR a3,
                                 LPCWSTR a4,
                                 INT a5)
{
//    MACTPrint(">>SEONLY ShellExecuteW");
//    HINSTANCE retx = TrueShellExecuteW(a0, a1, a2, a3, a4, a5);
//    return retx;

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a1, _TRUNCATE);
    
    origsize = wcslen(a2) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer2, newsize2, a2, _TRUNCATE);

    origsize = wcslen(a3) + 1;  
    convertedChars = 0;      
    const size_t newsize3 = origsize * 2;  
    char *buffer3 = new char[newsize3];  
    wcstombs_s(&convertedChars, buffer3, newsize3, a3, _TRUNCATE);

    origsize = wcslen(a4) + 1;  
    convertedChars = 0;      
    const size_t newsize4 = origsize * 2;  
    char *buffer4 = new char[newsize4];  
    wcstombs_s(&convertedChars, buffer4, newsize4, a4, _TRUNCATE);

    MACTlog(":ShellExecuteW(%p,%s,%s,%s,%s,%d)\n", a0, buffer1, buffer2, buffer3, buffer4, a5);

    int iOption = MACTmain("HINSTANCE");
    HINSTANCE bReturnValue = NULL;
    if(iOption == 4) {
        bReturnValue = SR_HINSTANCE;
    }

    HINSTANCE ret = 0;
    __try {
        ret = TrueShellExecuteW(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-ShellExecuteW will return %x\n", (int)ret);
        MACTlog("*ShellExecuteW(%p,%s,%s,%s,%s,%d),(%x,%x,%x)", a0, buffer1, buffer2, buffer3, buffer4, a5, ret, iOption, bReturnValue);
        if(iOption == 4) {
            ret = bReturnValue;
            MACTlog("+ShellExecuteW modified to return %x\n", ret);        
        }
        delete[] buffer1;
        delete[] buffer2;
        delete[] buffer3;
        delete[] buffer4;
    }

    return ret;
}

BOOL WINAPI MyShellExecuteExA(SHELLEXECUTEINFOA *a0)
{

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueShellExecuteExA(a0);

    typedef struct _MACTSHELLEXECUTEINFOA {
      DWORD     cbSize;
      ULONG     fMask;
      HWND      hwnd;
      LPCSTR    lpVerb;
      LPCSTR    lpFile;
      LPCSTR    lpParameters;
      LPCSTR    lpDirectory;
      int       nShow;
      HINSTANCE hInstApp;
      void      *lpIDList;
      LPCSTR    lpClass;
      HKEY      hkeyClass;
      DWORD     dwHotKey;
      union {
        HANDLE hIcon;
        HANDLE hMonitor;
      } DUMMYUNIONNAME;
      HANDLE    hProcess;
    } MACTSHELLEXECUTEINFOA, *LPMACTSHELLEXECUTEINFOA;

    int la = 0;

    BOOL wcsfail = FALSE;
    __try {
        la = lstrlenA(a0->lpVerb); 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        la = 5;
    } 
    char *buffer0 = new char[la+1];
    if(wcsfail) {
        strncpy(buffer0, "NULL\0", 5); 
    }
    else {
        strncpy(buffer0, a0->lpVerb, la); 
        buffer0[la] = '\0';
    }

    la = lstrlenA(a0->lpFile);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a0->lpFile, la);
    buffer1[la] = '\0';

     wcsfail = FALSE;
    __try {
        la = lstrlenA(a0->lpParameters); 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        la = 5;
    } 
    char *buffer2 = new char[la+1];
    if(wcsfail) {
        strncpy(buffer2, "NULL\0", 5); 
    }
    else {
        strncpy(buffer2, a0->lpParameters, la); 
        buffer2[la] = '\0';
    }

    wcsfail = FALSE;
    __try {
        la = lstrlenA(a0->lpDirectory); 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        la = 5;
    } 
    char *buffer3 = new char[la+1];
    if(wcsfail) {
        strncpy(buffer3, "NULL\0", 5); 
    }
    else {
        strncpy(buffer3, a0->lpDirectory, la); 
        buffer3[la] = '\0';
    }

    MACTPrint(">ShellExecuteExA lpVerb       = [%s]\n", buffer0);
    MACTPrint(">ShellExecuteExA lpFile       = [%s]\n", buffer1);
    MACTPrint(">ShellExecuteExA lpParameters = [%s]\n", buffer2);
    MACTPrint(">ShellExecuteExA lpDirectory  = [%s]\n", buffer3);

    LPMACTSHELLEXECUTEINFOA MACTShellExecuteExA = (LPMACTSHELLEXECUTEINFOA)a0;
//    MACTShellExecuteExW->lpFile = L"cmd.exe";
//    MACTShellExecuteExW->lpParameters = L"C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\AppData\\Local\\Temp/MBSSCR.exe";
//    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start withdll.exe -d:mact32.dll sample.exe\" ";
//    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\wdll.exe -d:C:\\mac.dll c:\\sam.exe\" ";
//ok    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\sample.exe\"";
//ok    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\serverc.exe\"";
    // C:\Users\MACT\Desktop\MACT\withdll.exe -d:C:\Users\MACT\Desktop\MACT\mact32.dll C:\Users\MACT\Desktop\MACT\sample.exe
//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\Desktop\\MACT\\serverc.exe\"";
//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start withdll.exe -d:mact32.dll sample.exe\"";
// process call create "cmd /c start withdll.exe -d:mact32.dll sample.exe"  "

//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mactsc32.dll C:\\Users\\MACT\\Desktop\\MACT\\sample.exe\"";
//    MACTShellExecuteExA->lpFile = L"C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe";
//    MACTShellExecuteExA->lpParameters = L"-d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\AppData\\Local\\Temp/MBSSCR.exe";

    a0 = (LPSHELLEXECUTEINFOA)MACTShellExecuteExA;

    MACTlog(":ShellExecuteExA(%p)\n", a0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueShellExecuteExA(a0);
    } __finally {
        MACTlog("-ShellExecuteExA will return %x\n", ret);
        MACTlog("*ShellExecuteExA(%p),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+ShellExecuteExA modified to return %x\n", ret);
        }
    }

    delete[] buffer0;
    delete[] buffer1;
    delete[] buffer2;
    delete[] buffer3;

    return ret;
}

BOOL WINAPI MyShellExecuteExW(SHELLEXECUTEINFOW *a0)
{

    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueShellExecuteExW(a0);

    typedef struct _MACTSHELLEXECUTEINFOW {
      DWORD     cbSize;
      ULONG     fMask;
      HWND      hwnd;
      LPCWSTR   lpVerb;
      LPCWSTR   lpFile;
      LPCWSTR   lpParameters;
      LPCWSTR   lpDirectory;
      int       nShow;
      HINSTANCE hInstApp;
      void      *lpIDList;
      LPCWSTR   lpClass;
      HKEY      hkeyClass;
      DWORD     dwHotKey;
      union {
        HANDLE hIcon;
        HANDLE hMonitor;
      } DUMMYUNIONNAME;
      HANDLE    hProcess;
    } MACTSHELLEXECUTEINFOW, *LPMACTSHELLEXECUTEINFOW;


    size_t origsize = 0;

    BOOL wcsfail = FALSE;
    __try {
        origsize = wcslen(a0->lpVerb) + 1; 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        origsize = 5;
    } 
    size_t convertedChars = 0;      
    const size_t newsize0 = origsize * 2; 
    char *buffer0 = new char[newsize0];
    if(wcsfail) {
        strncpy(buffer0, "NULL\0", 5); 
    }
    else
        wcstombs_s(&convertedChars, buffer0, newsize0, a0->lpVerb, _TRUNCATE); 

    origsize = wcslen(a0->lpFile) + 1;  
    convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a0->lpFile, _TRUNCATE);

    wcsfail = FALSE;
    __try {
        origsize = wcslen(a0->lpParameters) + 1; 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        origsize = 5;
    } 
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2; 
    char *buffer2 = new char[newsize2];
    if(wcsfail) {
        strncpy(buffer2, "NULL\0", 5); 
    }
    else
        wcstombs_s(&convertedChars, buffer2, newsize2, a0->lpParameters, _TRUNCATE); 

    wcsfail = FALSE;
    __try {
        origsize = wcslen(a0->lpDirectory) + 1; 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        origsize = 5;
    } 
    convertedChars = 0;      
    const size_t newsize3 = origsize * 2; 
    char *buffer3 = new char[newsize3];
    if(wcsfail) {
        strncpy(buffer3, "NULL\0", 5); 
    }
    else
        wcstombs_s(&convertedChars, buffer3, newsize3, a0->lpDirectory, _TRUNCATE); 

    MACTPrint(">ShellExecuteExW lpVerb       = [%s]\n", buffer0);
    MACTPrint(">ShellExecuteExW lpFile       = [%s]\n", buffer1);
    MACTPrint(">ShellExecuteExW lpParameters = [%s]\n", buffer2);
    MACTPrint(">ShellExecuteExW lpDirectory  = [%s]\n", buffer3);

    LPMACTSHELLEXECUTEINFOW MACTShellExecuteExW = (LPMACTSHELLEXECUTEINFOW)a0;
//    MACTShellExecuteExW->lpFile = L"cmd.exe";
//    MACTShellExecuteExW->lpParameters = L"C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\AppData\\Local\\Temp/MBSSCR.exe";
//    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start withdll.exe -d:mact32.dll sample.exe\" ";
//    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\wdll.exe -d:C:\\mac.dll c:\\sam.exe\" ";
//ok    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\sample.exe\"";
//ok    MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\serverc.exe\"";
    // C:\Users\MACT\Desktop\MACT\withdll.exe -d:C:\Users\MACT\Desktop\MACT\mact32.dll C:\Users\MACT\Desktop\MACT\sample.exe
//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\Desktop\\MACT\\serverc.exe\"";
//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start withdll.exe -d:mact32.dll sample.exe\"";
// process call create "cmd /c start withdll.exe -d:mact32.dll sample.exe"  "

//      MACTShellExecuteExW->lpParameters = L"process call create \"cmd /c start C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe -d:C:\\Users\\MACT\\Desktop\\MACT\\mactsc32.dll C:\\Users\\MACT\\Desktop\\MACT\\sample.exe\"";
//    MACTShellExecuteExW->lpFile = L"C:\\Users\\MACT\\Desktop\\MACT\\withdll.exe";
//    MACTShellExecuteExW->lpParameters = L"-d:C:\\Users\\MACT\\Desktop\\MACT\\mact32.dll C:\\Users\\MACT\\AppData\\Local\\Temp/MBSSCR.exe";

    a0 = (LPSHELLEXECUTEINFOW)MACTShellExecuteExW;

    MACTlog(":ShellExecuteExW(%p)\n", a0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        MACTPrint(">ShellExecuteW before.\n");
        ret = TrueShellExecuteExW(a0);
        MACTPrint(">ShellExecuteW after.\n");
    } __finally {
        MACTlog("-ShellExecuteExW will return %x\n", ret);
        MACTlog("*ShellExecuteExW(%p),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+ShellExecuteExW modified to return %x\n", ret);
        }
    }

    delete[] buffer0;
    delete[] buffer1;
    delete[] buffer2;
    delete[] buffer3;

    return ret;
}

LONG WINAPI MyRegGetValueA(HKEY    a0,
                           LPCSTR  a1,
                           LPTSTR  a2,
                           DWORD   a3,
                           LPDWORD a4,
                           PVOID   a5,
                           PDWORD  a6) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la;
    if(a1 == NULL)
        la = 4;
    else
        la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    if(a1 == NULL)
        strncpy(buffer1, "NULL", la);
    else
        strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    if(a2 == NULL)
        la = 4;
    else
        la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    if(a2 == NULL)
        strncpy(buffer2, "NULL", la);
    else
        strncpy(buffer2, a2, la);

    MACTlog(":RegGetValueA(%p,%s,%s,%p,%p,%p,%p)\n", a0, buffer1, buffer2, a3, a4, a5, a6);

    MACTreg(">RegGetValueA SubKey = [%s]\n", buffer1);

    MACTreg(">RegGetValueA Value  = [%s]\n", buffer2);

    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = 0;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;
    __try {
        ret = TrueRegGetValueA(a0, a1, a2, a3, a4, a5, a6);
    } __finally {
        MACTlog("-RegGetValueA will return %x\n", (int)ret); 
        MACTlog("*RegGetValueA(%p,%s,%s,%p,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, buffer2, a3, a4, a5, a6, 
            ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+RegGetValueA modified to return %x\n", ret);        
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

LONG WINAPI MyRegGetValueW(HKEY    a0,
                           LPCWSTR a1,
                           LPCWSTR a2,
                           DWORD   a3,
                           LPDWORD a4,
                           PVOID   a5,
                           PDWORD  a6) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize;
    if(a1 == NULL)
        origsize = 4;
    else
        origsize = wcslen(a1) + 1;

    size_t convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1]; 

    if(a1 == NULL) {
        strncpy(buffer1, "NULL", origsize);
        buffer1[origsize] = '\0'; 
    }
    else
        wcstombs_s(&convertedChars, buffer1, newsize1, a1, _TRUNCATE); 


    if(a2 == NULL)
        origsize = 4;
    else
        origsize = wcslen(a2) + 1;

    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2]; 

    if(a2 == NULL) {
        strncpy(buffer2, "NULL", origsize);
        buffer2[origsize] = '\0'; 
    }
    else
        wcstombs_s(&convertedChars, buffer2, newsize2, a2, _TRUNCATE); 

    MACTlog(":RegGetValueW(%p,%s,%s,%p,%p,%p,%p)\n", a0, buffer1, buffer2, a3, a4, a5, a6);

    MACTreg(">RegGetValueW SubKey = [%s]\n", buffer1);

    MACTreg(">RegGetValueW Value  = [%s]\n", buffer2);

    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = 0;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;
    __try {
        ret = TrueRegGetValueW(a0, a1, a2, a3, a4, a5, a6);
    } __finally {
        MACTlog("-RegGetValueW will return %x\n", (int)ret); 
        MACTlog("*RegGetValueW(%p,%s,%s,%p,%p,%p,%p),(%x,%x,%x)", a0, buffer1, buffer2, a3, a4, a5, a6, 
            ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+RegGetValueW modified to return %x\n", ret);        
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

LONG WINAPI MyRegQueryValueEx(HKEY    a0,
                              LPCTSTR a1,
                              LPDWORD a2,
                              LPDWORD a3,
                              LPBYTE  a4,
                              LPDWORD a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":RegQueryValueEx(%p,%s,%p,%p,%p,%p)\n", a0, buffer1, a2, a3, a4, a5);
  
    MACTreg(">RegQueryValueEx Key = [%s]\n", buffer1);

    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = 0;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;

    ret = TrueRegQueryValueEx(a0, a1, a2, a3, a4, a5);

    MACTlog("-RegQueryValueEx will return %x\n", ret);
    MACTlog("*RegQueryValueEx(%p,%s,%p,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, a3, a4, a5, ret, iOption, bReturnValue);
    if(iOption == 6) {
        ret = bReturnValue;
        MACTlog("+RegQueryValueEx modified to return %x\n", ret);
    }

// chgsleep
    TrueSleep(100);
    delete[] buffer1;
    return ret;
}

LONG WINAPI MyRegOpenKeyEx(HKEY    a0,
                           LPCTSTR a1,
                           DWORD   a2,
                           REGSAM  a3,
                           PHKEY   a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":RegOpenKeyEx(%p,%s,%p,%p,%p)\n", a0, buffer1, a2, a3, a4);

    MACTreg(">RegOpenKeyEx Key = [%s]\n", buffer1);


    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = FALSE;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;
    __try {
        ret = TrueRegOpenKeyEx(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-RegOpenKeyEx will return %x\n", (int)ret);
        MACTlog("*GetOpenKeyEx(%p,%s,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+RegOpenKeyEx modified to return %x\n", ret);
        }
    }
// chgsleep
    TrueSleep(100);
    delete[] buffer1;
    return ret;
}

LSTATUS WINAPI MyRegSetValueA(HKEY   a0,
                              LPCSTR a1,
                              DWORD  a2,
                              LPCSTR a3,
                              DWORD  a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la;
    if(a1 == NULL)
        la = 4;
    else
        la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    if(a1 == NULL)
        strncpy(buffer1, "NULL", la);
    else
        strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a3);
    char *buffer3 = new char[la+1];
    strncpy(buffer3, a3, la);
    buffer3[la] = '\0';

    MACTlog(":RegSetValueA(%p,%s,%p,%s,%p)\n", a0, buffer1, a2, buffer3, a4);

    MACTreg(">RegSetValueA SubKey = [%s]\n", buffer1);
    MACTreg(">RegSetValueA Data   = [%s]\n", buffer3);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = 0;
    __try {
        ret = TrueRegSetValueA(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-RegSetValueA will return %x\n", ret);
        MACTlog("*RegSetValueA(%p,%s,%p,%s,%p),(%x,%x,%x)", a0, buffer1, a2, buffer3, a4, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegSetValueA modified to return %x\n", ret);
        }
        delete[] buffer1;
        delete[] buffer3;
    }

    return ret;
}

LONG WINAPI MyRegSetValueEx(HKEY        a0,
                            LPCTSTR     a1,
                            DWORD       a2,
                            DWORD       a3,
                            const BYTE* a4,
                            DWORD       a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":RegSetValueEx(%p,%s,%p,%p,%p,%p)\n", a0, buffer1, a2, a3, a4, a5);

    MACTreg(">RegSetValueEx Key = [%s]\n", buffer1);


    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = FALSE;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;
    __try {
        ret = TrueRegSetValueEx(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-RegSetValueEx will return %x\n", (int)ret);
        MACTlog("*RegSetValueEx(%p,%s,%p,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+RegSetValueEx modified to return %x\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

LSTATUS WINAPI MyRegSetValueExW(HKEY        a0,
                                LPCWSTR     a1,
                                DWORD       a2,
                                DWORD       a3,
                                const BYTE* a4,
                                DWORD       a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer1 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer1, newsize, a1, _TRUNCATE);

    MACTlog(":RegSetValueExW(%p,%s,%p,%p,%p,%p)\n", a0, buffer1, a2, a3, a4, a5);

    MACTreg(">RegSetValueExW Key = [%s]\n", buffer1);


    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = 0;
    __try {
        ret = TrueRegSetValueExW(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-RegSetValueExW will return %x\n", (int)ret);
        MACTlog("*RegSetValueExW(%p,%s,%p,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegSetValueExW modified to return %x\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

LSTATUS WINAPI MyRegEnumKeyExA(HKEY      a0,
                               DWORD     a1,
                               LPSTR     a2,
                               LPDWORD   a3,
                               LPDWORD   a4,
                               LPSTR     a5,
                               LPDWORD   a6,
                               PFILETIME a7)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegEnumKeyExA(a0, a1, a2, a3, a4, a5, a6, a7);

    int la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0'; 

    MACTreg(">RegEnumKeyExA Subkey = [%s]\n", buffer2);

    MACTlog(":RegEnumKeyExA(%p,%p,%s,%p,%p,%p,%p,%p)\n", a0, a1, buffer2, a3, a4, a5, a6, a7);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = NULL;
    __try {
        ret = TrueRegEnumKeyExA(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-RegEnumKeyExA will return %p\n", ret);
        MACTlog("*RegEnumKeyExA(%p,%p,%s,%p,%p,%p,%p,%p)(%p,%x,%p)", a0, a1, buffer2, a3, a4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegEnumKeyExA modified to return %p\n", ret);
        }
        delete[] buffer2;
    }

//    TrueSleep(50);
    return ret;
}

LSTATUS WINAPI MyRegEnumKeyExW(HKEY      a0,
                               DWORD     a1,
                               LPWSTR    a2,
                               LPDWORD   a3,
                               LPDWORD   a4,
                               LPWSTR    a5,
                               LPDWORD   a6,
                               PFILETIME a7)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegEnumKeyExW(a0, a1, a2, a3, a4, a5, a6, a7);

    size_t origsize = wcslen(a2) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer2 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer2, newsize, a2, _TRUNCATE);

    MACTreg(">RegEnumKeyExW Subkey = [%s]\n", buffer2);

    MACTlog(":RegEnumKeyExW(%p,%p,%s,%p,%p,%p,%p,%p)\n", a0, a1, buffer2, a3, a4, a5, a6, a7);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = NULL;
    __try {
        ret = TrueRegEnumKeyExW(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-RegEnumKeyExW will return %p\n", ret);
        MACTlog("*RegEnumKeyExW(%p,%p,%s,%p,%p,%p,%p,%p)(%p,%x,%p)", a0, a1, buffer2, a3, a4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegEnumKeyExW modified to return %p\n", ret);
        }
        delete[] buffer2;
    }

//    TrueSleep(50);
    return ret;
}

LONG WINAPI  MyRegCreateKeyEx(HKEY                  a0,
                              LPCTSTR               a1,
                              DWORD                 a2,
                              LPTSTR                a3,
                              DWORD                 a4,
                              REGSAM                a5,
                              LPSECURITY_ATTRIBUTES a6,
                              PHKEY                 a7,
                              LPDWORD               a8) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":RegCreateKeyEx(%p,%s,%p,%p,%p,%p,%p,%p,%p)\n", a0, buffer1, a2, a3, a4, a5, a6, a7, a8);

    MACTreg(">RegCreateKeyEx Key = [%s]\n", buffer1);


    int iOption = MACTmain("HINSTANCE");
    LONG bReturnValue = FALSE;
    if(iOption == 6) {
        bReturnValue = SR_LONG;
    }

    LONG ret = 0;
    __try {
        ret = TrueRegCreateKeyEx(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    } __finally {
        MACTlog("-RegCreateKeyEx will return %x\n", (int)ret);
        MACTlog("*RegCreateKeyEx(%p,%s,%p,%p,%p,%p,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, a3, a4, 
            a5, a6, a7, a8, ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+RegCreateKeyEx modified to return %x\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyAdjustTokenPrivileges(HANDLE            a0,
                                    BOOL              a1,
                                    PTOKEN_PRIVILEGES a2,
                                    DWORD             a3,
                                    PTOKEN_PRIVILEGES a4,
                                    PDWORD            a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueAdjustTokenPrivileges(a0, a1, a2, a3, a4, a5);

    MACTlog(":AdjustTokenPrivileges(%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueAdjustTokenPrivileges(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-AdjustTokenPrivileges will return %x\n", (int)ret);
        MACTlog("*AdjustTokenPrivileges(%p,%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+AdjustTokenPrivileges modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyAttachThreadInput(DWORD a0,
                                DWORD a1,
                                BOOL  a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueAttachThreadInput(a0, a1, a2);

    MACTPrint(":AttachThreadInput(%p,%p,%x)\n", a0, a1, (int)a2);
    return TrueAttachThreadInput(a0, a1, a2);

    MACTlog(":AttachThreadInput(%p,%p,%x)\n", a0, a1, (int)a2);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueAttachThreadInput(a0, a1, a2);
    } __finally {
        MACTlog("-AttachThreadInput will return %x\n", (int)ret);
        MACTlog("*AttachThreadInput(%p,%p,%x),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+AttachThreadInput modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyBitBlt(HDC   a0, 
                     int    a1,
                     int    a2,
                     int    a3,
                     int    a4,
                     HDC    a5,
                     int    a6,
                     int    a7,
                     DWORD  a8)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

// This is called a lot and causes a lot of noise so it is shut off.
// The TrueSleep is necessary as the program dies before everything is processed.
//    return TrueBitBlt(a0, a1, a2, a3, a4, a5, a6, a7, a8);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueBitBlt(a0, a1, a2, a3, a4, a5, a6, a7, a8);

    if(MACTVERBOSE)
        MACTPrint(":BitBlt(%p,%x,%x,%x,%x,%p,%x,%x,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7, a8);

    MACTPrint("*BitBlt(%p,%x,%x,%x,%x,%p,%x,%x,%p),(%ld,%d,%ld)", a0, a1, a2, a4, a5, a6, a7, a8, 
                0, 0, 0);
    TrueSleep(50);
    return TrueBitBlt(a0, a1, a2, a3, a4, a5, a6, a7, a8);

    MACTlog(":BitBlt(%p,%x,%x,%x,%x,%p,%x,%x,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7, a8);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueBitBlt(a0, a1, a2, a3, a4, a5, a6, a7, a8);
    } __finally {
        MACTlog("-BitBlt will return %x\n", (int)ret);
        MACTlog("*BitBlt(%p,%x,%x,%x,%x,%p,%x,%x,%p),(%x,%x,%x)", a0, a1, a2, a4, a5, a6, a7, a8, 
                ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+BitBlt modified to return %x\n", ret);
        }
    }

    return ret;
}

HCERTSTORE WINAPI MyCertOpenSystemStore(HCRYPTPROV_LEGACY a0,
                                        LPCTSTR           a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCertOpenSystemStore(a0, a1);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":CertOpenSystemStore(%p,%s)\n", a0, buffer1);

    int iOption = MACTmain("HCERTSTORE");
    HCERTSTORE bReturnValue = NULL;
    if(iOption == 6) {
        bReturnValue = SR_HCERTSTORE;
    }

    HCERTSTORE ret;
    __try {
        ret = TrueCertOpenSystemStore(a0, a1);
    } __finally {
        MACTlog("-CertOpenSystemStore will return %p\n", ret);
        MACTlog("*CertOpenSystemStore(%p,%s),(%p,%x,%p)", a0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 6) {
            ret = bReturnValue;
            MACTlog("+CertOpenSystemStore modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyControlService(SC_HANDLE        a0,
                             DWORD            a1,
                             LPSERVICE_STATUS a2)

{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueControlService(a0, a1, a2);

    MACTlog(":ControlService(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueControlService(a0, a1, a2);
    } __finally {
        MACTlog("-ControlService will return %xx", (int)ret);
        MACTlog("*ControlService(%p,%p,%p),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+ControlService modified to return %x\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyCreateMutex(LPSECURITY_ATTRIBUTES a0,
                            BOOL                  a1,
                            LPCTSTR               a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateMutex(a0, a1, a2);

    int la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":CreateMutex(%p,%p,%s)\n", a0, a1, buffer2);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = FALSE;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = FALSE;
    __try {
        ret = TrueCreateMutex(a0, a1, a2);
    } __finally {
        MACTlog("-CreateMutex will return %p\n", ret);
        MACTlog("*CreateMutex(%p,%p,%s),(%p,%x,%p)", a0, a1, buffer2, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateMutex modified to return %x\n", ret);
        }
        delete[] buffer2;
    }

    return ret;
}

HANDLE WINAPI MyCreateMutexEx(LPSECURITY_ATTRIBUTES a0,
                              LPCTSTR               a1,
                              DWORD                 a2,
                              DWORD                 a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateMutexEx(a0, a1, a2, a3);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":CreateMutexEx(%p,%s,%p,%p)\n", a0, buffer1, a2, a3);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = FALSE;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = FALSE;
    __try {
        ret = TrueCreateMutexEx(a0, a1, a2, a3);
    } __finally {
        MACTlog("-CreateMutexEx will return %p\n", ret);
        MACTlog("*CreateMutexEx(%p,%s,%p,%p),(%p,%x,%p)", a0, buffer1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateMutexEx modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyCreateProcess(LPCTSTR               a0,
                            LPTSTR                a1,
                            LPSECURITY_ATTRIBUTES a2,
                            LPSECURITY_ATTRIBUTES a3,
                            BOOL                  a4,
                            DWORD                 a5,
                            LPVOID                a6,
                            LPCTSTR               a7,
                            LPSTARTUPINFO         a8,
                            LPPROCESS_INFORMATION a9) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateProcess(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a7);
    char *buffer7 = new char[la+1];
    strncpy(buffer7, a7, la);
    buffer7[la] = '\0';

    MACTlog(":CreateProcess(%s,%s,%p,%p,%x,%p,%p,%s,%p,%p)\n", buffer0, (char *) a1, a2, a3, a4, a5, a6, buffer7, a8, a9);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueCreateProcess(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    } __finally {
        MACTlog("-CreateProcess will return %x\n", (int)ret);
        MACTlog("*CreateProcess(%s,%s,%p,%p,%x,%p,%p,%s,%p,%p),(%p,%x,%p)", buffer0, (char *) a1, a2, a4, a5, a6, buffer7, a8, a9,
                ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CreateProcess modified to return %x\n", ret);
        }
        delete[] buffer0;
        delete[] buffer7;
    }

    return ret;
}


BOOL WINAPI MyCreateProcessW(LPCWSTR               a0,
                             LPWSTR                a1,
                             LPSECURITY_ATTRIBUTES a2,
                             LPSECURITY_ATTRIBUTES a3,
                             BOOL                  a4,
                             DWORD                 a5,
                             LPVOID                a6,
                             LPCWSTR               a7,
                             LPSTARTUPINFOW        a8,
                             LPPROCESS_INFORMATION a9) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateProcessW(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE);

    origsize = wcslen(a7) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer7 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer7, newsize2, a7, _TRUNCATE);

    MACTlog(":CreateProcessW(%s,%p,%p,%p,%x,%p,%p,%s,%p,%p)\n", buffer0, a1, a2, a3, a4, a5, a6, buffer7, a8, a9);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueCreateProcessW(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9);
    } __finally {
        MACTlog("-CreateProcessW will return %x\n", (int)ret);
        MACTlog("*CreateProcessW(%s,%p,%p,%p,%x,%p,%p,%s,%p,%p),(%p,%x,%p)", buffer0, a1, a2, a4, a5, a6, buffer7, a8, a9,
                ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CreateProcessW modified to return %x\n", ret);
        }
        delete[] buffer0;
        delete[] buffer7;
    }

    return ret;
}

BOOL WINAPI MyTerminateProcess(HANDLE a0,
                               UINT   a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueTerminateProcess(a0, a1);

    MACTlog(":TerminateProcess(%p,%p,)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueTerminateProcess(a0, a1);
    } __finally {
        MACTlog("-TerminateProcess will return %x\n", (int)ret);
        MACTlog("*TerminateProcess(%p,%p),(%p,%x,%p)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+TerminateProcess modified to return %x\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyCreateRemoteThread(HANDLE                 a0,
                                   LPSECURITY_ATTRIBUTES  a1,
                                   SIZE_T                 a2,
                                   LPTHREAD_START_ROUTINE a3,
                                   LPVOID                 a4,
                                   DWORD                  a5,
                                   LPDWORD                a6) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateRemoteThread(a0, a1, a2, a3, a4, a5, a6);

    MACTPrint(":CreateRemoteThread(%p,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = 0;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = 0;
    __try {
        ret = TrueCreateRemoteThread(a0, a1, a2, a3, a4, a5, a6);
    } __finally {
        MACTPrint("-CreateRemoteThread will return %p\n", ret);
        MACTPrint("*CreateRemoteThread(%p,%p,%p,%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, a4, a5, a6, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTPrint("+CreateRemoteThread modified to return %p\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyCreateRemoteThreadEx(HANDLE                       a0,
                                     LPSECURITY_ATTRIBUTES        a1,
                                     SIZE_T                       a2,
                                     LPTHREAD_START_ROUTINE       a3,
                                     LPVOID                       a4,
                                     DWORD                        a5,
                                     LPPROC_THREAD_ATTRIBUTE_LIST a6,
                                     LPDWORD                      a7)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateRemoteThreadEx(a0, a1, a2, a3, a4, a5, a6, a7);

    MACTlog(":CreateRemoteThreadEx(%p,%p,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = 0;
    __try {
        ret = TrueCreateRemoteThreadEx(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-CreateRemoteThreadEx will return %p\n", ret);
        MACTlog("*CreateRemoteThreadEx(%p,%p,%p,%p,%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, a4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateRemoteThreadEx modified to return %p\n", ret);
        }
    }

    return ret;
}

SC_HANDLE WINAPI MyCreateService(SC_HANDLE a0,
                                 LPCTSTR   a1,
                                 LPCTSTR   a2,
                                 DWORD     a3,
                                 DWORD     a4,
                                 DWORD     a5,
                                 DWORD     a6,
                                 LPCTSTR   a7,
                                 LPCTSTR   a8,
                                 LPDWORD   a9,
                                 LPCTSTR   a10,
                                 LPCTSTR   a11,
                                 LPCTSTR   a12) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateService(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    la = lstrlenA(a7);
    char *buffer7 = new char[la+1];
    strncpy(buffer7, a7, la);
    buffer7[la] = '\0';

    la = lstrlenA(a8);
    char *buffer8 = new char[la+1];
    strncpy(buffer8, a8, la);
    buffer8[la] = '\0';

    la = lstrlenA(a10);
    char *buffer10 = new char[la+1];
    strncpy(buffer10, a10, la);
    buffer10[la] = '\0';

    la = lstrlenA(a11);
    char *buffer11 = new char[la+1];
    strncpy(buffer11, a11, la);
    buffer11[la] = '\0';

    la = lstrlenA(a12);
    char *buffer12 = new char[la+1];
    strncpy(buffer12, a12, la);
    buffer12[la] = '\0';

    MACTlog(":CreateService(%p,%s,%s,%x,%x,%x,%x,%s,%s,%p,%s,%s,%s)\n", 
        a0, buffer1, buffer2, a3, a4, a5, a6, buffer7, buffer8, a9, buffer10, buffer11, buffer12);

    int iOption = MACTmain("SC_HANDLE");
    SC_HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_SC_HANDLE;
    }

    SC_HANDLE ret = FALSE;
    __try {
        ret = TrueCreateService(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12);
    } __finally {
        MACTlog("-CreateService will return %p\n", ret);
        MACTlog("*CreateService(%p,%s,%s,%x,%x,%x,%x,%s,%s,%p,%s,%s,%s),(%p,%x,%p)", 
            a0, buffer1, buffer2, a3, a4, a5, a6, buffer7, buffer8, a9, buffer10, buffer11, buffer12, 
            ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateService modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
        delete[] buffer7;
        delete[] buffer8;
        delete[] buffer10;
        delete[] buffer11;
        delete[] buffer12;
    }

    return ret;
}

HANDLE WINAPI MyCreateToolhelp32Snapshot(DWORD a0,
                                         DWORD a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCreateToolhelp32Snapshot(a0, a1);

    MACTlog(":CreateToolhelp32Snapshot(%x,%x)\n", a0, a1);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = FALSE;
    __try {
        ret = TrueCreateToolhelp32Snapshot(a0, a1);
    } __finally {
        MACTlog("-CreateToolhelp32Snapshot will return %p\n", ret);
        MACTlog("*CreateToolhelp32Snapshot(%x,%x),(%p,%x,%p)", a0, a1,ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateToolhelp32Snapshot modified to return %p\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyCryptAcquireContextA(HCRYPTPROV *a0,
                                   LPCTSTR    a1,
                                   LPCTSTR    a2,
                                   DWORD      a3,
                                   DWORD      a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCryptAcquireContextA(a0, a1, a2, a3, a4);

    MACTlog(":CryptAcquireContextA(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueCryptAcquireContextA(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-CryptAcquireContextA will return %x\n", (int)ret);
        MACTlog("*CryptAcquireContextA(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CryptAcquireContextA modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyCryptAcquireContextW(HCRYPTPROV *a0,
                                   LPCWSTR     a1,
                                   LPCWSTR     a2,
                                   DWORD       a3,
                                   DWORD       a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueCryptAcquireContextW(a0, a1, a2, a3, a4);

    MACTlog(":CryptAcquireContextW(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueCryptAcquireContextW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-CryptAcquireContextW will return %x\n", (int)ret);
        MACTlog("*CryptAcquireContextW(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+CryptAcquireContextW modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyDeviceIoControl(HANDLE       a0,
                              DWORD        a1,
                              LPVOID       a2,
                              DWORD        a3,
                              LPVOID       a4,
                              DWORD        a5,
                              LPDWORD      a6,
                              LPOVERLAPPED a7) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueDeviceIoControl(a0, a1, a2, a3, a4, a5, a6, a7);

    MACTPrint(":DeviceIoControl(%p,%p,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);
    MACTPrint("*DeviceIoControl(%p,%p,%p,%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, a6, a7, 
            0, 0, 0);

    return TrueDeviceIoControl(a0, a1, a2, a3, a4, a5, a6, a7);

    MACTlog(":DeviceIoControl(%p,%p,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueDeviceIoControl(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-DeviceIoControl will return %x\n", (int)ret);
        MACTlog("*DeviceIoControl(%p,%p,%p,%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, a6, a7, 
            ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+DeviceIoControl modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyEnumProcesses(DWORD *a0,
                            DWORD a1,
                            DWORD *a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueEnumProcesses(a0, a1, a2);

    MACTlog(":EnumProcesses(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueEnumProcesses(a0, a1, a2);
    } __finally {
        MACTlog("-EnumProcesses will return %x\n", (int)ret);
        MACTlog("*EnumProcesses(%p,%p,%p),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+EnumProcesses modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyEnumProcessModules(HANDLE  a0,
                                 HMODULE *a1,
                                 DWORD   a2,
                                 LPDWORD a3) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueEnumProcessModules(a0, a1, a2, a3);

    MACTlog(":EnumProcessModules(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueEnumProcessModules(a0, a1, a2, a3);
    } __finally {
        MACTlog("-EnumProcessModules will return %x\n", (int)ret);
        MACTlog("*EnumProcessModules(%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+EnumProcessModules modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyEnumProcessModulesEx(HANDLE  a0,
                                   HMODULE *a1,
                                   DWORD   a2,
                                   LPDWORD a3,
                                   DWORD   a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueEnumProcessModulesEx(a0, a1, a2, a3, a4);

    MACTlog(":EnumProcessModulesEx(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret;
    __try {
        ret = TrueEnumProcessModulesEx(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-EnumProcessModulesEx will return %x\n", (int)ret);
        MACTlog("*EnumProcessModulesEx(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+EnumProcessModulesEx modified to return %x\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyFindFirstFile(LPCTSTR           a0,
                              LPWIN32_FIND_DATA a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindFirstFile(a0, a1);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":FindFirstFile(%s,%p)\n", buffer0, a1);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret;
    __try {
        ret = TrueFindFirstFile(a0, a1);
    } __finally {
        MACTlog("-FindFirstFile will return %p\n", ret);
        MACTlog("*FindFirstFile(%s,%p),(%p,%x,%p)", buffer0, a1, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+FindFirstFile modified to return %p\n", ret);
        }
        delete[] buffer0;
    }

    return ret;
}

HANDLE WINAPI MyFindFirstFileEx(LPCTSTR            a0,
                                FINDEX_INFO_LEVELS a1,
                                LPVOID             a2,
                                FINDEX_SEARCH_OPS  a3,
                                LPVOID             a4,
                                DWORD              a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindFirstFileEx(a0, a1, a2, a3, a4, a5);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":FindFirstFileEx(%s,%d,%p,%d,%p,%p)\n", buffer0, (int)a1, a2, (int)a3, a4, a5);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret;
    __try {
        ret = TrueFindFirstFileEx(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-FindFirstFileEx will return %p\n", ret);
        MACTlog("*FindFirstFileEx(%s,%d,%p,%d,%p,%p),(%p,%x,%p)", buffer0, (int)a1, a2, (int)a3, a4, a5, 
            ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+FindFirstFileEx modified to return %p\n", ret);
        }
        delete[] buffer0;
    }

    return ret;
}

BOOL WINAPI MyFindNextFile(HANDLE             a0,
                           LPWIN32_FIND_DATAA a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindNextFile(a0, a1);

    MACTlog(":FindNextFile(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueFindNextFile(a0, a1);
    } __finally {
        MACTlog("-FindNextFile will return %p\n", ret);
        MACTlog("*FindNextFile(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+FindNextFile modified to return %p\n", ret);
        }
    }

    return ret;
}

HRSRC WINAPI MyFindResourceA(HMODULE a0,
                             LPCSTR  a1,
                             LPCSTR  a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindResourceA(a0, a1, a2);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":FindResourceA(%p,%s,%s)\n", a0, buffer1, buffer2);

    int iOption = MACTmain("HRSRC");
    HRSRC bReturnValue = NULL;
    if(iOption == 8) {
        bReturnValue = SR_HRSRC;
    }

    HRSRC ret;
    __try {
        ret = TrueFindResourceA(a0, a1, a2);
    } __finally {
        MACTlog("-FindResourceA will return %p\n", ret);
        MACTlog("*FindResourceA(%p,%s,%s),(%p,%x,%p)", a0, buffer1, buffer2, ret, iOption, bReturnValue);
        if(iOption == 8) {
            ret = bReturnValue;
            MACTlog("+FindResourceA modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

HRSRC WINAPI MyFindResourceExA(HMODULE a0,
                               LPCSTR  a1,
                               LPCSTR  a2,
                               WORD    a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindResourceExA(a0, a1, a2, a3);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';


    MACTlog(":FindResourceExA(%p,%s,%s,%p)\n", a0, buffer1, buffer2, a3);

    int iOption = MACTmain("HRSRC");
    HRSRC bReturnValue = NULL;
    if(iOption == 8) {
        bReturnValue = SR_HRSRC;
    }

    HRSRC ret;
    __try {
        ret = TrueFindResourceExA(a0, a1, a2, a3);
    } __finally {
        MACTlog("-FindResourceExA will return %p\n", ret);
        MACTlog("*FindResourceExA(%p,%s,%s,%p),(%p,%x,%p)", a0, buffer1, buffer2, a3, ret, iOption, bReturnValue);
        if(iOption == 8) {
            ret = bReturnValue;
            MACTlog("+FindResourceExA modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

HWND WINAPI MyFindWindow(LPCTSTR a0,
                         LPCTSTR a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindWindow(a0, a1);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTlog(":FindWindow(%s,%s)\n", buffer0, buffer1);

    int iOption = MACTmain("HRWND");
    HWND bReturnValue = NULL;
    if(iOption == 9) {
        bReturnValue = SR_HWND;
    }

    HWND ret;
    __try {
        ret = TrueFindWindow(a0, a1);
    } __finally {
        MACTlog("-FindWindow will return %p\n", ret);
        MACTlog("*FindWindow(%s,%s),(%p,%x,%p)", buffer0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 9) {
            ret = bReturnValue;
            MACTlog("+FindWindow modified to return %p\n", ret);
        }
        delete[] buffer0;
        delete[] buffer1;
    }

    return ret;
}

HWND WINAPI MyFindWindowEx(HWND    a0,
                           HWND    a1,
                           LPCTSTR a2,
                           LPCTSTR a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFindWindowEx(a0, a1, a2, a3);

    int la = lstrlenA(a3);
    char *buffer3 = new char[la+1];
    strncpy(buffer3, a3, la);
    buffer3[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';


    MACTlog(":FindWindowEx(%p,%p,%s,%s)\n", a0, a1, buffer2, buffer3);

    int iOption = MACTmain("HWND");
    HWND bReturnValue = NULL;
    if(iOption == 9) {
        bReturnValue = SR_HWND;
    }

    HWND ret;
    __try {
        ret = TrueFindWindowEx(a0, a1, a2, a3);
    } __finally {
        MACTlog("-FindWindowEx will return %p\n", ret);
        MACTlog("*FindWindowEx(%p,%p,%s,%s),(%p,%x,%p)", a0, a1, buffer2, buffer3, ret, iOption, bReturnValue);
        if(iOption == 9) {
            ret = bReturnValue;
            MACTlog("+FindWindowEx modified to return %p\n", ret);
        }
        delete[] buffer2;
        delete[] buffer3;
    }

    return ret;
}

HINTERNET WINAPI MyFtpOpenFileW(HINTERNET a0,
                                LPCWSTR   a1,
                                DWORD     a2,
                                DWORD     a3,
                                DWORD_PTR a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueFtpOpenFileW(a0, a1, a2, a3, a4);
    }

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a1, _TRUNCATE);

    MACTlog(":FtpOpenFileW(%s,%p,%s,%s,%p)\n", a0, buffer1, a2, a3, a4);
    MACTcomm(">FtpOpenFileW- File Name = [%s]\n", buffer1);

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueFtpOpenFileW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-FtpOpenFileW will return (void)\n");
        MACTlog("*FtpOpenFileW(%s,%p,%s,%s,%p),(%llu,%x,%llu)", a0, buffer1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+FtpOpenFileW modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

BOOL WINAPI MyFtpPutFile(HINTERNET a0, 
                         LPCTSTR a1, 
                         LPCTSTR a2, 
                         DWORD a3, 
                         DWORD a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueFtpPutFile(a0, a1, a2, a3, a4);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":FtpPutFile(%p,%s,%s,%p,%p)\n", a0, buffer1, buffer2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueFtpPutFile(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-FtpPutFile will return %p\n", ret);
        MACTlog("*FtpPutFile(%p,%s,%s,%p,%p),(%x,%x,%x)", a0, buffer1, buffer2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+FtpPutFile modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

ULONG WINAPI MyGetAdaptersInfo(PIP_ADAPTER_INFO a0,
                               PULONG           a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetAdaptersInfo(a0, a1);

    MACTlog(":GetAdaptersInfo(%p,%x)\n", a0, a1);

    int iOption = MACTmain("ULONG");
    ULONG bReturnValue = 0;
    if(iOption == 10) {
        bReturnValue = SR_ULONG;
    }

    ULONG ret;
    __try {
        ret = TrueGetAdaptersInfo(a0, a1);
    } __finally {
        MACTlog("-GetAdaptersInfo will return %p\n", ret);
        MACTlog("*GetAdaptersInfo(%p,%x),(%ld,%x,%ld)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 10) {
            ret = bReturnValue;
            MACTlog("+GetAdaptersInfo modified to return %p\n", ret);
        }
    }

    return ret;
}

SHORT WINAPI MyGetAsyncKeyState(int a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetAsyncKeyState(a0);

    MACTlog(":GetAsyncKeyState(%x)\n", a0);

    int iOption = MACTmain("SHORT");
    SHORT bReturnValue = 0;
    if(iOption == 11) {
        bReturnValue = SR_SHORT;
    }

    SHORT ret;
    __try {
        ret = TrueGetAsyncKeyState(a0);
    } __finally {
        MACTlog("-GetAsyncKeyState will return %x\n", ret);
        MACTlog("*GetAsyncKeyState(%x),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 11) {
            ret = bReturnValue;
            MACTlog("+GetAsyncKeyState modified to return %x\n", ret);
        }
    }

    return ret;
}

HDC WINAPI MyGetDC(HWND a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueGetDC(a0);

    MACTlog(":GetDC(%p)\n", a0);

    HDC ret = TrueGetDC(a0);
    MACTlog("*GetDC(%p),(%ld,%d,%ld)", a0, 0, ret, 0);
    TrueSleep(50);
    return ret;

    MACTlog(":GetDC(%p)\n", a0);

    int iOption = MACTmain("HDC");
    HDC bReturnValue = NULL;
    if(iOption == 12) {
        bReturnValue = SR_HDC;
    }

    ret;
    __try {
        ret = TrueGetDC(a0);
    } __finally {
        MACTlog("-GetDC will return %p\n", ret);
        MACTlog("*GetDC(%p),(%p,%x,%p)", a0, ret, iOption, bReturnValue);
        if(iOption == 12) {
            ret = bReturnValue;
            MACTlog("+GetDC modified to return %p\n", ret);
        }
    }

    TrueSleep(100);
    return ret;
}

HWND WINAPI MyGetForegroundWindow(void)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueGetForegroundWindow();

    MACTlog(":GetForegroundWindow()\n");

    int iOption = MACTmain("HWND");
    HWND bReturnValue = NULL;
    if(iOption == 12) {
        bReturnValue = SR_HWND;
    }

    HWND ret;
    __try {
        ret = TrueGetForegroundWindow();
    } __finally {
        MACTlog("-GetForegroundWindow will return %p\n", ret);
        MACTlog("*GetForegroundWindow(),(%p,%x,%p)", ret, iOption, bReturnValue);
        if(iOption == 12) {
            ret = bReturnValue;
            MACTlog("+GetForegroundWindow modified to return %p\n", ret);
        }
    }

    return ret;
}

INT WINAPI MyGetWindowText(HWND   a0,
                           LPTSTR a1,
                           int    a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueGetWindowText(a0, a1, a2);

    MACTlog(":GetWindowText(%p,%p,%x)\n", a0, a1, a2);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret = 0;

    ret = TrueGetWindowText(a0, a1, a2);
          
    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0'; 
    
    MACTlog("-GetWindowText will return %x\n", ret);
    MACTlog("*GetWindowText(%p,%s,%x),(%x,%x,%x)", a0, buffer1, a2, ret, iOption, bReturnValue);
    if(iOption == 14) {
        ret = bReturnValue;
        MACTlog("+GetWindowText modified to return %x\n", ret);            
    }
    delete[] buffer1;

    TrueSleep(100);
    return ret;
}


HOSTENT * WINAPI Mygethostbyname(const char *a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return Truegethostbyname(a0);

    MACTlog(":gethostbyname(%s)\n", a0);

    MACTcomm(">gethostbyname: %s\n\n", a0);

    int iOption = MACTmain("HOSTENT");
    hostent bReturnValue;
    if(iOption == 13) {
        bReturnValue = SR_HOSTENT;
    }

    hostent *ret;
    __try {
        ret = Truegethostbyname(a0);
    } __finally {
        MACTlog("-gethostbyname will return %p\n", ret);
        MACTlog("*gethostbyname(%s),(%p,%x,%p)", a0, ret, iOption, bReturnValue);
        if(iOption == 13) {
            ret = &bReturnValue;
            MACTlog("+gethostbyname modified to return %p\n", ret);
        }
    }

    return ret;
}

int WINAPI Mygethostname(const char *a0,
                         int         a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return Truegethostname((char *)a0, a1);

    MACTlog(":gethostname(%s,%x)\n", a0, a1);
    MACTcomm(">gethostname: %s\n\n", a0);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = Truegethostname((char *)a0, a1);
    } __finally {
        MACTlog("-gethostname will return %x\n", ret);
        MACTlog("*gethostname(%s,%x),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+gethostname modified to return %x\n", ret);
        }
    }

    return ret;
}

static INT WINAPI Mygetaddrinfo(PCSTR            a0,
                                PCSTR            a1,
                                const ADDRINFOA *a2,
                                PADDRINFOA      *a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return Truegetaddrinfo(a0, a1, a2, a3);

    MACTlog(":getaddrinfo(%s,%s,%p,%p)\n", a0, a1, a2, a3);
    MACTcomm(">getaddrinfo: Node:%s Service:%s\n\n", a0, a1);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret;
    __try {
        ret = Truegetaddrinfo(a0, a1, a2, a3);
    } __finally {
        MACTlog("-getaddrinfo will return %x\n", ret);
        MACTlog("*ggetaddrinfo(%s,%s,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+getaddrinfo modified to return %x\n", ret);
        }
    }

    return ret;
}

SHORT WINAPI MyGetKeyState(int a0) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueGetKeyState(a0);

    MACTlog(":GetKeyState(%x)\n", a0);

    int iOption = MACTmain("SHORT");
    SHORT bReturnValue = 0;
    if(iOption == 11) {
        bReturnValue = SR_SHORT;
    }

    SHORT ret;
    __try {
        ret = TrueGetKeyState(a0);
    } __finally {
        MACTlog("-GetKeyState will return %x\n", ret);
        MACTlog("*GetKeyState(%x),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 11) {
            ret = bReturnValue;
            MACTlog("+GetKeyState modified to return %x\n", ret);
        }
    }

    TrueSleep(100);
    return ret;
}

DWORD WINAPI MyGetModuleFileName(HMODULE a0,
                                 LPTSTR  a1,
                                 DWORD   a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetModuleFileName(a0, a1, a2);

    MACTlog(":GetModuleFileName(%p,%p,%x)\n", a0, a1, a2);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;

    ret = TrueGetModuleFileName(a0, a1, a2);

    size_t la1 = strlen(a1);
    char *buffer = new char[la1+1];
    strncpy(buffer, a1, la1);
    buffer[la1] = '\0';

    MACTlog("-GetModuleFileName will return %ld with %s\n", ret, buffer);
    MACTlog("*GetModuleFileName(%p,%s,%x),(%ld,%ld,%ld)", a0, buffer, a2, ret, iOption, bReturnValue);
    if(iOption == 15) {
        ret = bReturnValue;
        MACTlog("+GetModuleFileName modified to return %ld\n", ret);
    }
    delete[] buffer;

    return ret;
}

DWORD WINAPI MyGetModuleFileNameExA(HANDLE  a0,
                                    HMODULE a1,
                                    LPSTR   a2,
                                    DWORD   a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetModuleFileNameExA(a0, a1, a2, a3);

    int la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0'; 

    MACTlog(":GetModuleFileNameExA(%p,%p,%s,%x)\n", a0, a1, buffer2, a3);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;
    __try {
        ret = TrueGetModuleFileNameExA(a0, a1, a2, a3);
    } __finally {
        MACTlog("-GetModuleFileNameExA will return %ld with %s\n", ret, buffer2);
        MACTlog("*GetModuleFileNameExA(%p,%p,%s,%x),(%x,%x,%x)", a0, a1, buffer2, a3, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+GetModuleFileNameExA modified to return %x\n", ret);
        }
        delete[] buffer2;
    }

    return ret;
}

DWORD WINAPI MyGetModuleFileNameExW(HANDLE  a0,
                                    HMODULE a1,
                                    LPWSTR  a2,
                                    DWORD   a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetModuleFileNameExW(a0, a1, a2, a3);
   
    size_t origsize = wcslen(a2) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer2 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer2, newsize, a2, _TRUNCATE);

    MACTlog(":GetModuleFileNameExW(%p,%p,%s,%x)\n", a0, a1, a2, a3);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;
    __try {
        ret = TrueGetModuleFileNameExW(a0, a1, a2, a3);
    } __finally {
        MACTlog("-GetModuleFileNameExW will return %ld with %s\n", ret, buffer2);
        MACTlog("*GetModuleFileNameExW(%p,%p,%s,%x),(%x,%x,%x)", a0, a1, buffer2, a3, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+GetModuleFileNameExW modified to return %x\n", ret);
        }
        delete[] buffer2;
    }

    return ret;
}

HMODULE WINAPI MyGetModuleHandle(LPCTSTR a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetModuleHandle(a0);


    int la;
    if(a0 == NULL)
        la = 4;
    else
        la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    if(a0 == NULL)
        strncpy(buffer0, "NULL", la);
    else
        strncpy(buffer0, a0, la);
    buffer0[la] = '\0';


    MACTlog(":GetModuleHandle(%s)\n", buffer0);

    int iOption = MACTmain("HMODULE");
    HMODULE bReturnValue = NULL;
    if(iOption == 16) {
        bReturnValue = SR_HMODULE;
        MACTPrint(">Returning from MACTmain %x\n", bReturnValue);
    }

    HMODULE ret;
    __try {
        ret = TrueGetModuleHandle(a0);
    } __finally {
        MACTlog("-GetModuleHandle will return %p\n", ret);
        MACTlog("*GetModuleHandle(%s),(%p,%x,%p)", buffer0, ret, iOption, bReturnValue);
        if(iOption == 16) {
            ret = bReturnValue;
            MACTPrint(">Returning from MACTmain %x\n", bReturnValue);
            MACTPrint(">Returning from MACTmain %x\n", ret);
            MACTlog("+GetModuleHandle modified to return %p\n", ret);
        }
        delete[] buffer0;
    }

    return ret;
}

BOOL WINAPI MyGetModuleHandleEx(DWORD    a0,
                                LPCTSTR  a1,
                                HMODULE *a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetModuleHandleEx(a0, a1, a2);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    if(a0 == GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
        MACTlog(":GetModuleHandleEx(%p,%x,%p)\n", a0, a1, a2);
    else {
        MACTlog(":GetModuleHandleEx(%p,%s,%p)\n", a0, buffer1, a2);
    }
        

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueGetModuleHandleEx(a0, a1, a2);
    } __finally {
        MACTlog("-GetModuleHandleEx will return %p\n", ret);
        if(a0 == GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS)
            MACTlog("*GetModuleHandleEx(%p,%x,%p),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        else
            MACTlog("*GetModuleHandleEx(%p,%s,%p),(%x,%x,%x)", a0, buffer1, a2, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+GetModuleHandleEx modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

    return ret;
}

int GetBufferLength(LPCSTR a1)
{
    int ia1 = (int)a1;

    int la;
    if(ia1 <= 65535)
        la = std::to_string(ia1).length();
    else
        la = lstrlenA(a1);

    return(la);
}

void GetBuffer(LPCSTR a1, char *buffer1, int la)
{
    int ia1 = (int)a1;

    if(ia1 <= 65535) {
        strncpy(buffer1, std::to_string(ia1).c_str(), la);
    }
    else {
        strncpy(buffer1, a1, la);
    }

    buffer1[la] = '\0';
}

FARPROC WINAPI MyGetProcAddress(HMODULE a0,
                                LPCSTR  a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueGetProcAddress(a0, a1);

    int la = GetBufferLength(a1);
    char *buffer1 = new char[la+1];

    GetBuffer(a1, buffer1, la);

    MACTPrint(":GetProcAddress(%p,%s)\n", a0, buffer1);

    int iOption = MACTmain("FARPROC");
    FARPROC bReturnValue = NULL;
    if(iOption == 17) {
        bReturnValue = SR_FARPROC;
    }

    FARPROC ret = NULL;
    __try {
        ret = TrueGetProcAddress(a0, a1);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        MACTPrint(">>>>>>>>>>GetProcAddress E\n");
        MACTPrint("-GetProcAddress failed.\n");
        MACTPrint("*GetProcAddress(%p,%s),(%s,%x,%p)", a0, buffer1, "FAIL", iOption, bReturnValue);
//        TrueSleep(200);
        delete[] buffer1;
        return ret;
    } 

    MACTPrint("-GetProcAddress will return %p\n", ret);
    MACTPrint("*GetProcAddress(%p,%s),(%p,%x,%p)", a0, buffer1, ret, iOption, bReturnValue);
    if(iOption == 17) {
        ret = bReturnValue;
        MACTPrint("+GetProcAddress modified to return %p\n", ret);
    }

// chgsleep
    TrueSleep(200);
    delete[] buffer1;
    return ret;
}

VOID WINAPI MyGetStartupInfoA(LPSTARTUPINFOA a0) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        TrueGetStartupInfoA(a0);
        return;
    }

    TrueGetStartupInfoA(a0);

    LPMACTSTARTUPINFOA MACTstartup = (LPMACTSTARTUPINFOA) a0;
    MACTPrint(">-------------lpTitle = %s\n", a0->lpTitle);

    a0 = (LPSTARTUPINFOA)MACTstartup;

    MACTlog(":GetStartupInfoA(%p)\n", a0);

    __try {
        TrueGetStartupInfoA(a0);
    } __finally {
        MACTlog("-GetStartupInfoA will return (void)\n");
        MACTlog("*GetStartupInfoA(%p),(void,void,void)", a0);
    }

    return;
}

LANGID WINAPI MyGetSystemDefaultLangID(void)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetSystemDefaultLangID();

    MACTlog(":GetSystemDefaultLangID()\n");

    int iOption = MACTmain("LANGID");
    LANGID bReturnValue = NULL;
    if(iOption == 18) {
        bReturnValue = SR_LANGID;
    }

    LANGID ret;
//    __try {
        ret = TrueGetSystemDefaultLangID();
//    } __finally {
        MACTlog("-GetSystemDefaultLangID will return %p\n", ret);
        MACTlog("*GetSystemDefaultLangID(),(%p,%x,%p)", ret, iOption, bReturnValue);
        if(iOption == 18) {
            ret = bReturnValue;
            MACTlog("+GetSystemDefaultLangID modified to return %p\n", ret);
        }
//    }

    return ret;
}

DWORD WINAPI MyGetTempPathA(DWORD a0,
                            LPSTR a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetTempPathA(a0, a1);

    MACTlog(":GetTempPathA(%p,%p)\n", a0, a1);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret = 0;

    ret = TrueGetTempPathA(a0, a1);

    size_t la1 = strlen(a1);
    char *buffer = new char[la1+1];
    strncpy(buffer, a1, la1);
    buffer[la1] = '\0';

    MACTlog("-GetTempPathA will return %ld with %s\n", ret, buffer);
    MACTlog("*GetTempPathA(%p,%s),(%ld,%ld,%ld)", a0, buffer, ret, iOption, bReturnValue);
    if(iOption == 15) {
        ret = bReturnValue;
        MACTlog("+GetTempPathA modified to return %ld\n", ret);
    }
    delete[] buffer;

    return ret;
}

BOOL WINAPI MyGetThreadContext(HANDLE    a0,
                               LPCONTEXT a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetThreadContext(a0, a1);

    MACTlog(":GetThreadContext(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueGetThreadContext(a0, a1);
    } __finally {
        MACTlog("-GetThreadContext will return %p\n", ret);
        MACTlog("*GetThreadContext(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+GetThreadContext modified to return %p\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyGetVersionEx(LPOSVERSIONINFO a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetVersionEx(a0);

    MACTlog(":GetVersionEx(%x)\n", a0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueGetVersionEx(a0);
    } __finally {
        MACTlog("-GetVersionEx will return %p\n", ret);
        MACTlog("*GetVersionEx(%x),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+GetVersionEx modified to return %x\n", ret);
        }
    }

    return ret;
}

UINT WINAPI MyGetWindowsDirectory(LPTSTR a0,
                                  UINT   a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueGetWindowsDirectory(a0, a1);

    MACTlog(":GetWindowsDirectory(%p,%p,%x)\n", a0, a1);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_DWORD;
    }

    UINT ret;

    ret = TrueGetWindowsDirectory(a0, a1);

    size_t la0 = strlen(a0);
    char *buffer = new char[la0+1];
    strncpy(buffer, a0, la0);
    buffer[la0] = '\0';

    MACTlog("-GetWindowsDirectory will return %x with %s\n", ret, buffer);
    MACTlog("*GetWindowsDirectory(%s,%p),(%x,%x,%x)", a0, buffer, ret, iOption, bReturnValue);
    if(iOption == 3) {
        ret = bReturnValue;
        MACTlog("+GetWindowsDirectory modified to return %x\n", ret);
    }
    delete[] buffer;

    return ret;
}

ULONG WINAPI Myinet_addr(const char * a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return Trueinet_addr(a0);
    }

    MACTlog(":inet_addr(%p)\n", a0);
    MACTcomm(">inet_addr %s\n", a0);

    int iOption = MACTmain("ULONG");
    ULONG bReturnValue = 0;
    if(iOption == 10) {
        bReturnValue = SR_ULONG;
    }

    ULONG ret;
    __try {
        ret = Trueinet_addr(a0);
    } __finally {
        MACTlog("-inet_addr will return (void)\n");
        MACTlog("*inet_addr(%p),(%ld,%x,%ld)", a0, ret, iOption, bReturnValue);
        if(iOption == 10) {
            ret = bReturnValue;
            MACTlog("+inet_addr modified to return %p\n", ret);
        }
    }

    return ret;
}

HINTERNET WINAPI MyInternetOpen(LPCTSTR a0, 
                                DWORD   a1, 
                                LPCTSTR a2, 
                                LPCTSTR a3, 
                                DWORD   a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueInternetOpen(a0, a1, a2, a3, a4);
    }

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    la = lstrlenA(a3);
    char *buffer3 = new char[la+1];
    strncpy(buffer3, a3, la);
    buffer3[la] = '\0';


    MACTlog(":InternetOpen(%s,%p,%s,%s,%p)\n", buffer0, a1, buffer2, buffer3, a4);
    MACTcomm(">InternetOpen\n");

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueInternetOpen(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-InternetOpen will return (void)\n");
        MACTlog("*InternetOpen(%s,%p,%s,%s,%p),(%llu,%x,%llu)", buffer0, a1, buffer2, buffer3, a4, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+InternetOpen modified to return %p\n", ret);
        }
        delete[] buffer0;
        delete[] buffer2;
        delete[] buffer3;
    }

    return ret;
}


HINTERNET WINAPI MyInternetOpenW(LPCWSTR a0, 
                                 DWORD   a1, 
                                 LPCWSTR a2, 
                                 LPCWSTR a3, 
                                 DWORD   a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueInternetOpenW(a0, a1, a2, a3, a4);
    }

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize0 = origsize * 2;  
    char *buffer0 = new char[newsize0];  
    wcstombs_s(&convertedChars, buffer0, newsize0, a0, _TRUNCATE);

    origsize = wcslen(a2) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer2, newsize2, a2, _TRUNCATE); 

    origsize = wcslen(a3) + 1;  
    convertedChars = 0;      
    const size_t newsize3 = origsize * 2;  
    char *buffer3 = new char[newsize3];  
    wcstombs_s(&convertedChars, buffer3, newsize3, a3, _TRUNCATE);

    MACTlog(":InternetOpenW(%s,%p,%s,%s,%p)\n", buffer0, a1, buffer2, buffer3, a4);
    MACTcomm(">InternetOpenW\n");

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueInternetOpenW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-InternetOpenW will return (void)\n");
        MACTlog("*InternetOpenW(%s,%p,%s,%s,%p),(%llu,%x,%llu)", buffer0, a1, buffer2, buffer3, a4, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+InternetOpenW modified to return %p\n", ret);
        }
        delete[] buffer0;
        delete[] buffer2;
        delete[] buffer3;
    }

    return ret;
}

HINTERNET WINAPI MyInternetOpenUrl(HINTERNET a0, 
                                   LPCTSTR   a1, 
                                   LPCTSTR   a2, 
                                   DWORD     a3, 
                                   DWORD     a4, 
                                   DWORD_PTR a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueInternetOpenUrl(a0, a1, a2, a3, a4, a5);
    }

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":InternetOpenUrl(%p,%s,%s,%p,%p,%p)\n", a0, buffer1, buffer2, a3, a4, a5);
    MACTcomm(">InternetOpenUrl\n\tURL =[%s]\n\tHeaders = [%s]\n", buffer1, buffer2);

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueInternetOpenUrl(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-InternetOpenUrl will return (void)\n");
        MACTlog("*InternetOpenUrl(%p,%s,%s,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, buffer2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+InternetOpenUrl modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

HINTERNET WINAPI MyInternetOpenUrlA(HINTERNET a0, 
                                    LPCSTR    a1, 
                                    LPCSTR    a2, 
                                    DWORD     a3, 
                                    DWORD     a4, 
                                    DWORD_PTR a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueInternetOpenUrlA(a0, a1, a2, a3, a4, a5);
    }

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":InternetOpenUrlA(%p,%s,%s,%p,%p,%p)\n", a0, buffer1, buffer2, a3, a4, a5);
    MACTcomm(">InternetOpenUrlA\n\tURL =[%s]\n\tHeaders = [%s]\n", buffer1, buffer2);

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueInternetOpenUrlA(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-InternetOpenUrlA will return (void)\n");
        MACTlog("*InternetOpenUrlA(%p,%s,%s,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, buffer2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+InternetOpenUrlA modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

HINTERNET WINAPI MyInternetConnectW(HINTERNET     a0, 
                                    LPCWSTR       a1, 
                                    INTERNET_PORT a2, 
                                    LPCWSTR       a3, 
                                    LPCWSTR       a4, 
                                    DWORD         a5, 
                                    DWORD         a6, 
                                    DWORD         a7) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueInternetConnectW(a0, a1, a2, a3, a4, a5, a6, a7);
    }

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a1, _TRUNCATE); 

    origsize = wcslen(a3) + 1;  
    convertedChars = 0;      
    const size_t newsize3 = origsize * 2;  
    char *buffer3 = new char[newsize3];  
    wcstombs_s(&convertedChars, buffer3, newsize3, a3, _TRUNCATE);

    origsize = wcslen(a4) + 1;  
    convertedChars = 0;      
    const size_t newsize4 = origsize * 2;  
    char *buffer4 = new char[newsize4];  
    wcstombs_s(&convertedChars, buffer4, newsize4, a4, _TRUNCATE);

    MACTlog(":InternetConnectW(%p,%s,%p,%s,%s,%p,%p,%p)\n", a0, buffer1, a2, buffer3, buffer4, a5, a6, a7);
    MACTcomm(">InternetConnectW\n\tServer =[%s]\n\tUser = [%s]\n\tPassword = [%s]\n", buffer1, buffer3, buffer4);

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueInternetConnectW(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-InternetConnectW will return (void)\n");
        MACTlog("*InternetConnectW(%p,%s,%p,%s,%s,%p,%p,%p),(%ld,%x,%ld)", a0, buffer1, a2, buffer3, buffer4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+InternetConnectW modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer3;
        delete[] buffer4;
    }

    return ret;
}

HINTERNET WINAPI MyHttpOpenRequestW(HINTERNET  a0,
                                    LPCWSTR    a1,
                                    LPCWSTR    a2,
                                    LPCWSTR    a3,
                                    LPCWSTR    a4,
                                    LPCWSTR   *a5,
                                    DWORD      a6,
                                    DWORD_PTR  a7)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) {
        return TrueHttpOpenRequestW(a0, a1, a2, a3, a4, a5, a6, a7);
    }
    
    LPCWSTR a1n = a1;
    if(a1 == NULL) {
        a1n = L"GET\0";
    }
    size_t origsize = wcslen(a1n) + 1;
    size_t convertedChars = 0;       
    const size_t newsize1 = origsize * 2;  
    char *buffer1 = new char[newsize1];  
    wcstombs_s(&convertedChars, buffer1, newsize1, a1n, _TRUNCATE); 

    origsize = wcslen(a2) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer2, newsize2, a2, _TRUNCATE);

    origsize = wcslen(a3) + 1;  
    convertedChars = 0;      
    const size_t newsize3 = origsize * 2;  
    char *buffer3 = new char[newsize3];  
    wcstombs_s(&convertedChars, buffer3, newsize3, a3, _TRUNCATE);

    MACTlog(":HttpOpenRequestW(%p,%s,%s,%s,%p,%p,%p,%p)\n", a0, buffer1, buffer2, buffer3, a4, a5, a6, a7);
    MACTcomm(">HttpOpenRequestW\n\tVerb =[%s]\n\tName = [%s]\n\tVersion = [%s]\n", buffer1, buffer2, buffer3);

    int iOption = MACTmain("HINTERNET");
    HINTERNET bReturnValue = NULL;
    if(iOption == 19) {
        bReturnValue = SR_HINTERNET;
    }

    HINTERNET ret;
    __try {
        ret = TrueHttpOpenRequestW(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-HttpOpenRequestW will return (void)\n");
        MACTlog("*HttpOpenRequestW(%p,%s,%s,%s,%p,%p,%p,%p)\n", a0, buffer1, buffer2, buffer3, a4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 19) {
            ret = bReturnValue;
            MACTlog("+HttpOpenRequestW modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
        delete[] buffer3;
    }

    return ret;
}

BOOL WINAPI MyHttpSendRequestW(HINTERNET a0,
                               LPCWSTR   a1,
                               DWORD     a2,
                               LPVOID    a3,
                               DWORD     a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueHttpSendRequestW(a0, a1, a2, a3, a4);

    MACTlog(":HttpSendRequestW(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
    MACTcomm(">HttpSendRequestW\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueHttpSendRequestW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-HttpSendRequestW will return %p\n", ret);
        MACTlog("*HttpSendRequestW(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+HttpSendRequestW modified to return %p\n", ret);
        }
    }

//    TrueSleep(50);
    return ret;
}


BOOL WINAPI MyHttpSendRequestExW(HINTERNET           a0,
                                 LPINTERNET_BUFFERSW a1,
                                 LPINTERNET_BUFFERSW a2,
                                 DWORD               a3,
                                 DWORD_PTR           a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueHttpSendRequestExW(a0, a1, a2, a3, a4);

    MACTlog(":HttpSendRequestExW(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);
    MACTcomm(">HttpSendRequestExW\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueHttpSendRequestExW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-HttpSendRequestExW will return %p\n", ret);
        MACTlog("*HttpSendRequestExW(%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+HttpSendRequestExW modified to return %p\n", ret);
        }
    }

//    TrueSleep(50);
    return ret;
}

BOOL WINAPI MyInternetReadFile(HINTERNET a0, 
                               LPVOID    a1, 
                               DWORD     a2, 
                               LPDWORD   a3) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueInternetReadFile(a0, a1, a2, a3);

    MACTlog(":InternetReadFile(%p,%p,%p,%p)\n", a0, a1, a2, a3);
    MACTcomm(">InternetReadFile\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueInternetReadFile(a0, a1, a2, a3);
    } __finally {
        MACTlog("-InternetReadFile will return %p\n", ret);
        MACTlog("*InternetReadFile(%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+InternetReadFile modified to return %p\n", ret);
        }
    }

//    TrueSleep(50);
    return ret;
}

BOOL WINAPI MyInternetWriteFile(HINTERNET a0, 
                                LPCVOID   a1, 
                                DWORD     a2, 
                                LPDWORD   a3) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueInternetWriteFile(a0, a1, a2, a3);

    MACTlog(":InternetWriteFile(%p,%p,%p,%p)\n", a0, a1, a2, a3);
    MACTcomm(">InternetWriteFile\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueInternetWriteFile(a0, a1, a2, a3);
    } __finally {
        MACTlog("-InternetWriteFile will return %p\n", ret);
        MACTlog("*InternetWriteFile(%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+InternetWriteFile modified to return %p\n", ret);
        }
    }

    return ret;
}

//Doesnt matter, as this is only running on a 32 bit machine
BOOL WINAPI MyIsWow64Process(HANDLE a0,
                             PBOOL  a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueIsWow64Process(a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueIsWow64Process(a0, a1);
    } __finally {
        if(iOption == 1) {
            ret = bReturnValue;
        }
    }

    return ret;
}

NTSTATUS WINAPI MyLdrLoadDll(PWCHAR            a0,
                             ULONG             a1,
                             PUNICODE_STRING   a2,
                             PHANDLE           a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueLdrLoadDll(a0, a1, a2, a3);

// #include <codecvt>
    std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>,wchar_t> convert;
    std::string sStr = convert.to_bytes((wchar_t*)a2->Buffer);

    size_t origsize;
    if(a0 == NULL)
        origsize = 4;
    else
        origsize = wcslen(a0) + 1;

    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize]; 

    if(a0 == NULL) {
        strncpy(buffer0, "NULL", origsize);
        buffer0[origsize] = '\0'; 
    }
    else
        wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 

    MACTlog(":LdrLoadDll(%s,%p,%s,%p)\n", buffer0, a1, sStr.c_str(), a3);
 
    int iOption = MACTmain("NTSTATUS");
    NTSTATUS bReturnValue = NULL;
    if(iOption == 20) {
        bReturnValue = SR_NTSTATUS;
    }
   
    NTSTATUS ret;

    ret = TrueLdrLoadDll(a0, a1, a2, a3);

    MACTlog("-LdrLoadDll will return (void)\n");
    MACTlog("*LdrLoadDll(%s,%p,%s,%p),(%p,%x,%p)", buffer0, a1, sStr.c_str(), a3, ret, iOption, bReturnValue);
    if(iOption == 20) {
        ret = bReturnValue;
        MACTlog("+LdrLoadDll modified to return %p\n", ret);

    }
    delete[] buffer0;

//    TrueSleep(250);
    return ret;
}

NTSTATUS WINAPI MyRtlCreateRegistryKey(ULONG a0,
                                       PWSTR a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueRtlCreateRegistryKey(a0, a1); 

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer1 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer1, newsize, a1, _TRUNCATE);

    MACTlog(":RtlCreateRegistryKey(%p,%s)\n", a0, buffer1);

    MACTreg(">RtlCreateRegistryKey = [%s]\n", buffer1);
 
    int iOption = MACTmain("NTSTATUS");
    NTSTATUS bReturnValue = NULL;
    if(iOption == 20) {
        bReturnValue = SR_NTSTATUS;
    }
   
    NTSTATUS ret;
    __try {
        ret = TrueRtlCreateRegistryKey(a0, a1);
    } __finally {
        MACTlog("-RtlCreateRegistryKey will return (void)\n");
        MACTlog("*RtlCreateRegistryKey(%p,%s),(%p,%x,%p)", a0, buffer1, ret, iOption, bReturnValue);
        if(iOption == 20) {
            ret = bReturnValue;
            MACTlog("+RtlCreateRegistryKey modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

//    TrueSleep(50);
    return ret;
}

NTSTATUS WINAPI MyRtlWriteRegistryValue(ULONG  a0,
                                        PCWSTR a1,
                                        PCWSTR a2,
                                        ULONG  a3,
                                        PVOID  a4,
                                        ULONG  a5) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueRtlWriteRegistryValue(a0, a1, a2, a3, a4, a5); 

    size_t origsize = wcslen(a1) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer1 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer1, newsize, a1, _TRUNCATE);

    origsize = wcslen(a2) + 1;  
    convertedChars = 0;      
    const size_t newsize2 = origsize * 2;  
    char *buffer2 = new char[newsize2];  
    wcstombs_s(&convertedChars, buffer2, newsize2, a2, _TRUNCATE);

    MACTlog(":RtlWriteRegistryValue(%p,%s,%s,%p,%p,%p)\n", a0, buffer1, buffer2, a3, a4, a5);

    MACTreg(">RtlWriteRegistryValue Path = [%s] Name = [%s]\n", buffer1, buffer2);
 
    int iOption = MACTmain("NTSTATUS");
    NTSTATUS bReturnValue = NULL;
    if(iOption == 20) {
        bReturnValue = SR_NTSTATUS;
    }
   
    NTSTATUS ret;
    __try {
        ret = TrueRtlWriteRegistryValue(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-RtlWriteRegistryValue will return (void)\n");
        MACTlog("*RtlWriteRegistryValue(%p,%s,%s,%p,%p,%p),(%p,%x,%p)", a0, buffer1, buffer2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 20) {
            ret = bReturnValue;
            MACTlog("+RtlWriteRegistryValue modified to return %p\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

//    TrueSleep(50);
    return ret;
}

HGLOBAL WINAPI MyLoadResource(HMODULE a0,
                              HRSRC   a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueLoadResource(a0, a1);

    MACTlog(":LoadResource(%p,%p)\n", a0, a1);
 
    int iOption = MACTmain("HGLOBAL");
    HGLOBAL bReturnValue = NULL;
    if(iOption == 21) {
        bReturnValue = SR_HGLOBAL;
    }
   
    HGLOBAL ret = 0;
    __try {
        ret = TrueLoadResource(a0, a1);
    } __finally {
        MACTlog("-LoadResource will return (void)\n");
        MACTlog("*LoadResource(%p,%p),(%p,%x,%p)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 21) {
            ret = bReturnValue;
            MACTlog("+LoadResource modified to return %p\n", ret);
        }
    }

//    TrueSleep(250);
    return ret;
}

NTSTATUS WINAPI MyLsaEnumerateLogonSessions(PULONG a0,
                                            PLUID  *a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueLsaEnumerateLogonSessions(a0, a1);

    MACTlog(":LsaEnumerateLogonSessions(%p,%p)\n", a0, a1);
 
    int iOption = MACTmain("NTSTATUS");
    NTSTATUS bReturnValue = NULL;
    if(iOption == 20) {
        bReturnValue = SR_NTSTATUS;
    }
   
    NTSTATUS ret;
    __try {
        ret = TrueLsaEnumerateLogonSessions(a0, a1);
    } __finally {
        MACTlog("-LsaEnumerateLogonSessions will return (void)\n");
        MACTlog("*LsaEnumerateLogonSessions(%p,%p),(%p,%x,%p)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 20) {
            ret = bReturnValue;
            MACTlog("+LsaEnumerateLogonSessions modified to return %p\n", ret);
        }
    }

//    TrueSleep(250);
    return ret;
}

LPVOID WINAPI MyMapViewOfFile(HANDLE a0,
                              DWORD  a1,
                              DWORD  a2,
                              DWORD  a3,
                              SIZE_T a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueMapViewOfFile(a0, a1, a2, a3, a4);

    CopyFileFromHandle(a0, MACTdirFilesClosed);

    MACTlog(":MapViewOfFile(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("LPVOID");
    LPVOID bReturnValue = NULL;
    if(iOption == 2) {
        bReturnValue = SR_LPVOID;
    }

    LPVOID ret = 0;
    ret = TrueMapViewOfFile(a0, a1, a2, a3, a4);
    MACTlog("-MapViewOfFile will return %x\n", ret);
    MACTlog("*MapViewOfFile(%p,%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
    if(iOption == 2) {
        ret = bReturnValue;
        MACTlog("+MapViewOfFile modified to return %x\n", ret);           
    }

//    TrueSleep(250);
    return ret;
}

LPVOID WINAPI MyMapViewOfFileEx(HANDLE a0,
                                DWORD  a1,
                                DWORD  a2,
                                DWORD  a3,
                                SIZE_T a4,
                                LPVOID a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueMapViewOfFileEx(a0, a1, a2, a3, a4, a5);

    CopyFileFromHandle(a0, MACTdirFilesMapped);

    MACTlog(":MapViewOfFileEx(%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5);

    int iOption = MACTmain("LPVOID");
    LPVOID bReturnValue = NULL;
    if(iOption == 2) {
        bReturnValue = SR_LPVOID;
    }

    LPVOID ret = 0;
    ret = TrueMapViewOfFileEx(a0, a1, a2, a3, a4, a5);
    MACTlog("-MapViewOfFileEx will return %p\n", ret);
    MACTlog("*MapViewOfFileEx(%p,%p,%p,%p,%p,%p),(%p,%x,%p)", a0, a1, a2, a3, a4, a5, ret, iOption, bReturnValue);
    if(iOption == 2) {
        ret = bReturnValue;
        MACTlog("+MapViewOfFileEx modified to return %p\n", ret);           
    }

    return ret;
}

UINT WINAPI MyMapVirtualKeyA(UINT a0,
                             UINT a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueMapVirtualKeyA(a0, a1);

    MACTlog(":MapVirtualKeyA(%p,%p)\n", a0, a1);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_UINT;
    }

    UINT ret = 0;
    __try {
        ret = TrueMapVirtualKeyA(a0, a1);
    } __finally {
        MACTlog("-MapVirtualKeyA will return %x\n", (int)&ret);
        MACTlog("*MapVirtualKeyA(%p,%p),(%u,%x,%u)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 3) {
            ret = bReturnValue;
            MACTlog("+MapVirtualKeyA modified to return %x\n", ret);            
        }
    }

    return ret;
}

UINT WINAPI MyMapVirtualKeyExA(UINT a0,
                               UINT a1,
                               HKL  a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueMapVirtualKeyExA(a0, a1, a2);

    MACTlog(":MapVirtualKeyExA(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_UINT;
    }

    UINT ret = 0;
    __try {
        ret = TrueMapVirtualKeyExA(a0, a1, a2);
    } __finally {
        MACTlog("-MapVirtualKeyExA will return %x\n", (int)&ret);
        MACTlog("*MapVirtualKeyExA(%p,%p,%p),(%u,%x,%u)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 3) {
            ret = bReturnValue;
            MACTlog("+MapVirtualKeyExA modified to return %x\n", ret);            
        }
    }

    return ret;
}

UINT WINAPI MyMapVirtualKeyW(UINT a0,
                             UINT a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueMapVirtualKeyW(a0, a1);

    MACTlog(":MapVirtualKeyW(%p,%p)\n", a0, a1);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_UINT;
    }

    UINT ret = 0;
    __try {
        ret = TrueMapVirtualKeyW(a0, a1);
    } __finally {
        MACTlog("-MapVirtualKeyW will return %x\n", (int)&ret);
        MACTlog("*MapVirtualKeyW(%p,%p),(%u,%x,%u)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 3) {
            ret = bReturnValue;
            MACTlog("+MapVirtualKeyW modified to return %x\n", ret);            
        }
    }

    return ret;
}

UINT WINAPI MyMapVirtualKeyExW(UINT a0,
                               UINT a1,
                               HKL  a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return TrueMapVirtualKeyExW(a0, a1, a2);

    MACTlog(":MapVirtualKeyExW(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("UINT");
    UINT bReturnValue = 0;
    if(iOption == 3) {
        bReturnValue = SR_UINT;
    }

    UINT ret = 0;
    __try {
        ret = TrueMapVirtualKeyExW(a0, a1, a2);
    } __finally {
        MACTlog("-MapVirtualKeyExW will return %x\n", (int) &ret);
        MACTlog("*MapVirtualKeyExW(%p,%p,%p),(%u,%x,%u)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 3) {
            ret = bReturnValue;
            MACTlog("+MapVirtualKeyExW modified to return %x\n", (int) &ret);            
        }
    }

    return ret;
}

BOOL WINAPI MyModule32First(HANDLE          a0, 
                            LPMODULEENTRY32 a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueModule32First(a0, a1);

    MACTlog(":Module32First(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueModule32First(a0, a1);
    } __finally {
        MACTlog("-Module32First will return %x\n", ret);
        MACTlog("*Module32First(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Module32First modified to return %x\n", ret);
        }
    }

    return ret;
}


BOOL WINAPI MyModule32Next(HANDLE          a0, 
                           LPMODULEENTRY32 a1) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueModule32Next(a0, a1);

    MACTlog(":Module32Next(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueModule32Next(a0, a1);
    } __finally {
        MACTlog("-Module32Next will return %x\n", ret);
        MACTlog("*Module32Next(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Module32Next modified to return %x\n", ret);
        }
    }

    return ret;
}

HANDLE WINAPI MyOpenMutexA(DWORD  a0,
                           BOOL   a1,
                           LPCSTR a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueOpenMutexA(a0, a1, a2);

    int la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":OpenMutexA(%p,%x,%s)\n", a0, a1, buffer2);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = NULL;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    MACTlog("-OpenMutexA will return. Returned before override.");
    MACTlog("*OpenMutexA(%p,%x,%s),(0,0,0)", a0, a1, buffer2);
    delete[] buffer2;
    return TrueOpenMutexA(a0, a1, a2);

    HANDLE ret = NULL;
    __try {
        ret = TrueOpenMutexA(a0, a1, a2);
    } __finally {
        MACTlog("-OpenMutexA will return %p\n", ret);
        MACTlog("*OpenMutexA(%p,%x,%s),(0,0,0)", a0, a1, buffer2);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+OpenMutexA modified to return %p\n", ret);
        }
    }

//    TrueSleep(100);
    return ret;
}

HANDLE WINAPI MyOpenProcess(DWORD a0,
                            BOOL  a1,
                            DWORD a2) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueOpenProcess(a0, a1, a2);

    MACTlog(":OpenProcess(%p,%p,%d)\n", a0, a1, a2);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = FALSE;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = 0;
    __try {
        ret = TrueOpenProcess(a0, a1, a2);
    } __finally {
        MACTlog("-OpenProcess will return %p\n", ret);
        MACTlog("*OpenProcess(%p,%p,%d),(%p,%x,%p)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+OpenProcess modified to return %p\n", ret);
        }
    }

//    TrueSleep(100);
    return ret;
}

VOID WINAPI MyOutputDebugString(LPCTSTR a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    MACTlog("*OutputDebugString(%p),(void,void,void)", a0);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":OutputDebugString(%s)\n", buffer0);

    MACTlog("-OutputDebugString will return (void)\n");
    MACTlog("*OutputDebugString(%s),(void,void,void)", buffer0);
    delete[] buffer0;

    return TrueOutputDebugString(a0);
}

VOID WINAPI MyOutputDebugStringA(LPCSTR a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    int la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":OutputDebugStringA(%s)\n", buffer0);

    MACTlog("-OutputDebugStringA will return (void)\n");
    MACTlog("*OutputDebugStringA(%s),(void,void,void)", buffer0);

    delete[] buffer0;
    return TrueOutputDebugStringA(a0);;
}

VOID WINAPI MyOutputDebugStringW(LPCWSTR a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    size_t origsize = wcslen(a0) + 1;  
    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2;  
    char *buffer0 = new char[newsize];  
    wcstombs_s(&convertedChars, buffer0, newsize, a0, _TRUNCATE); 

    MACTlog(":OutputDebugStringW(%s)\n", buffer0);

    MACTlog("-OutputDebugStringW will return (void)\n");
    MACTlog("*OutputDebugStringW(%s),(void,void,void)", buffer0);

    delete[] buffer0;
    return TrueOutputDebugStringW(a0);;
}

BOOL WINAPI MyPeekNamedPipe(HANDLE  a0,
                            LPVOID  a1,
                            DWORD   a2,
                            LPDWORD a3,
                            LPDWORD a4,
                            LPDWORD a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TruePeekNamedPipe(a0, a1, a2, a3, a4, a5);

    MACTlog(":PeekNamedPipe(%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TruePeekNamedPipe(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-PeekNamedPipe will return %x\n", ret);
        MACTlog("*PeekNamedPipe(%p,%p,%p,%p,%p,%p,(%x,%x,%x)", a0, a1, a2, a3, a4, a5, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+PeekNamedPipe modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyProcess32First(HANDLE           a0,
                             LPPROCESSENTRY32 a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueProcess32First(a0, a1);

    MACTlog(":Process32First(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueProcess32First(a0, a1);
    } __finally {
        MACTlog("-Process32First will return %x\n", ret);
        MACTlog("*Process32First(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Process32First modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyProcess32FirstW(HANDLE           a0,
                             LPPROCESSENTRY32W a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueProcess32FirstW(a0, a1);

    MACTlog(":Process32FirstW(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueProcess32FirstW(a0, a1);
    } __finally {
        MACTlog("-Process32FirstW will return %x\n", ret);
        MACTlog("*Process32FirstW(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Process32FirstW modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyProcess32Next(HANDLE           a0,
                            LPPROCESSENTRY32 a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueProcess32Next(a0, a1);

    MACTlog(":Process32Next(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueProcess32Next(a0, a1);
    } __finally {
        MACTlog("-Process32Next will return %x\n", ret);
        MACTlog("*Process32Next(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Process32Next modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyProcess32NextW(HANDLE           a0,
                             LPPROCESSENTRY32W a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueProcess32NextW(a0, a1);

    MACTlog(":Process32NextW(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueProcess32NextW(a0, a1);
    } __finally {
        MACTlog("-Process32NextW will return %x\n", ret);
        MACTlog("*Process32NextW(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Process32NextW modified to return %x\n", ret);
        }
    }

    return ret;
}

DWORD WINAPI MyQueueUserAPC(PAPCFUNC  a0,
                            HANDLE    a1,
                            ULONG_PTR a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueQueueUserAPC(a0, a1, a2);

    MACTlog(":QueueUserAPC(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;

    __try {
    ret = TrueQueueUserAPC(a0, a1, a2);
    } __finally {
        MACTlog("-QueueUserAPC will return %ld\n", ret);   
        MACTlog("*QueueUserAPC(%p,%p %p),(%ld,%ld,%ld)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+QueueUserAPC modified to return %ld\n", ret);
        }
    }

    return ret;
} 

BOOL WINAPI MyReadProcessMemory(HANDLE  a0,
                                LPCVOID a1,
                                LPVOID  a2,
                                SIZE_T  a3,
                                SIZE_T  *a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueReadProcessMemory(a0, a1, a2, a3, a4);

    MACTlog(":ReadProcessMemory(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueReadProcessMemory(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-ReadProcessMemory will return %x\n", ret);
        MACTlog("*ReadProcessMemory(%p,%p,%p,%p,%p)(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+ReadProcessMemory modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyRegisterHotKey(HWND a0,
                             int  a1,
                             UINT a2,
                             UINT a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegisterHotKey(a0, a1, a2, a3);

    MACTlog(":RegisterHotKey(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueRegisterHotKey(a0, a1, a2, a3);
    } __finally {
        MACTlog("-RegisterHotKey will return %x\n", ret);
        MACTlog("*RegisterHotKey(%p,%p,%p,%p)(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+RegisterHotKey modified to return %x\n", ret);
        }
    }

    return ret;
}

LSTATUS WINAPI MyRegOpenKeyA(HKEY   a0,
                             LPCSTR a1,
                             PHKEY  a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegOpenKeyA(a0, a1, a2);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTreg(">RegOpenKeyA Key = [%s]\n", buffer1);

    MACTlog(":RegOpenKeyA(%p,%s,%p)\n", a0, buffer1, a2);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = NULL;
    __try {
        ret = TrueRegOpenKeyA(a0, a1, a2);
    } __finally {
        MACTlog("-RegOpenKeyA will return %p\n", ret);
        MACTlog("*RegOpenKeyA(%p,%s,%p)(%p,%x,%p)", a0, buffer1, a2, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegOpenKeyA modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

//    TrueSleep(50);
    return ret;
}

LSTATUS WINAPI MyRegOpenKeyExA(HKEY   a0,
                               LPCSTR a1,
                               DWORD  a2,
                               REGSAM a3,
                               PHKEY  a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegOpenKeyExA(a0, a1, a2, a3, a4);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    MACTreg(">RegOpenKeyExA Key = [%s]\n", buffer1);

    MACTlog(":RegOpenKeyExA(%p,%s,%p)\n", a0, buffer1, a2, a3, a4);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = NULL;
    __try {
        ret = TrueRegOpenKeyExA(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-RegOpenKeyExA will return %p\n", ret);
        MACTlog("*RegOpenKeyExA(%p,%s,%p)(%p,%x,%p)", a0, buffer1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegOpenKeyExA modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

//    TrueSleep(50);
    return ret;
}

LSTATUS WINAPI MyRegOpenKeyExW(HKEY    a0,
                               LPCWSTR a1,
                               DWORD   a2,
                               REGSAM  a3,
                               PHKEY   a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueRegOpenKeyExW(a0, a1, a2, a3, a4);

    size_t origsize;
    BOOL wcsfail = FALSE;
    __try {
        origsize = wcslen(a1) + 1; 
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        wcsfail = TRUE;
        origsize = 5;
    } 

    size_t convertedChars = 0;      
    const size_t newsize = origsize * 2; 
    char *buffer1 = new char[newsize];
    if(wcsfail) {
        strncpy(buffer1, "NULL\0", 5); 
    }
    else
        wcstombs_s(&convertedChars, buffer1, newsize, a1, _TRUNCATE); 

    MACTreg(">RegOpenKeyExW Key = [%s]\n", buffer1);

    MACTlog(":RegOpenKeyExW(%p,%s,%p,%p,%p)\n", a0, buffer1, a2, a3, a4);

    int iOption = MACTmain("LSTATUS");
    LSTATUS bReturnValue = FALSE;
    if(iOption == 22) {
        bReturnValue = SR_LSTATUS;
    }

    LSTATUS ret = NULL;
    __try {
        ret = TrueRegOpenKeyExW(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-RegOpenKeyExW will return %p\n", ret);
        MACTlog("*RegOpenKeyExW(%p,%s,%p,%p,%p)(%p,%x,%p)", a0, buffer1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 22) {
            ret = bReturnValue;
            MACTlog("+RegOpenKeyExW modified to return %p\n", ret);
        }
        delete[] buffer1;
    }

//    TrueSleep(50);
    return ret;
}

DWORD WINAPI MyResumeThread(HANDLE a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueResumeThread(a0);

    MACTlog(":ResumeThread(%p)\n", a0);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;
    __try {
        ret = TrueResumeThread(a0);
    } __finally {
        MACTlog("-ResumeThread will return %ld\n", ret);
        MACTlog("*ResumeThread(%p),(%ld,%ld,%ld)", a0, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+ResumeThread modified to return %ld\n", ret);
        }
    }

    return ret;
} 

LPVOID WINAPI MySamIConnect(PDWORD a0,
                            PDWORD a1,
                            PDWORD a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSamIConnect(a0, a1, a2);

    MACTlog(":SamIConnect(%p,%p,%p)\n", a0, a1, a2);

    int iOption = MACTmain("LPVOID");
    LPVOID bReturnValue = NULL;
    if(iOption == 2) {
        bReturnValue = SR_LPVOID;
    }

    LPVOID ret;
    __try {
        ret = TrueSamIConnect(a0, a1, a2);
    } __finally {
        MACTlog("-SamIConnect will return %p\n", ret);
        MACTlog("*SamIConnect(%p,%p,%p),(%p,%x,%p)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 2) {
            ret = bReturnValue;
            MACTlog("+SamIConnect modified to return %p\n", ret);
        }
    }

    return ret;
} 


BOOL WINAPI MySetFileTime(HANDLE         a0,
                          CONST FILETIME *a1,
                          CONST FILETIME *a2,
                          CONST FILETIME *a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSetFileTime(a0, a1, a2, a3);

    char Buffer1[20];
    char Buffer2[20];
    char Buffer3[20];

    if(a1 != NULL) {
        SYSTEMTIME sta1;
        FileTimeToSystemTime(a1, &sta1);
        sprintf(Buffer1, "%02d/%02d/%d %02d:%02d:%02d", sta1.wMonth, sta1.wDay, sta1.wYear, sta1.wHour, sta1.wMinute, sta1.wSecond);
    }
    else 
        sprintf(Buffer1, "NULL");

    if(a2 != NULL) {
        SYSTEMTIME sta1;
        FileTimeToSystemTime(a2, &sta1);
        sprintf(Buffer2, "%02d/%02d/%d %02d:%02d:%02d", sta1.wMonth, sta1.wDay, sta1.wYear, sta1.wHour, sta1.wMinute, sta1.wSecond);
    }
    else 
        sprintf(Buffer2, "NULL");

    if(a3 != NULL) {
        SYSTEMTIME sta1;
        FileTimeToSystemTime(a3, &sta1);
        sprintf(Buffer3, "%02d/%02d/%d %02d:%02d:%02d", sta1.wMonth, sta1.wDay, sta1.wYear, sta1.wHour, sta1.wMinute, sta1.wSecond);
    }
    else 
        sprintf(Buffer3, "NULL");

    MACTlog(":SetFileTime(%p,%s,%s,%s)\n", a0, Buffer1, Buffer2, Buffer3);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueSetFileTime(a0, a1, a2, a3);
    } __finally {
        MACTlog("-SetFileTime will return %x\n", ret);

        MACTlog("*SetFileTime(%p,%s,%s,%s)(%x,%x,%x)", a0, Buffer1, Buffer2, Buffer3, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+SetFileTime modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MySetThreadContext(HANDLE         a0,
                               const CONTEXT *a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSetThreadContext(a0, a1);

    MACTlog(":SetThreadContext(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueSetThreadContext(a0, a1);
    } __finally {
        MACTlog("-SetThreadContext will return %x\n", ret);
        MACTlog("*SetThreadContext(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+SetThreadContext modified to return %x\n", ret);
        }
    }

    return ret;
}

HHOOK WINAPI MySetWindowsHookEx(int       a0,
                                HOOKPROC  a1,
                                HINSTANCE a2,
                                DWORD     a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSetWindowsHookEx(a0, a1, a2, a3);

    MACTlog(":SetWindowsHookEx(%p,%p,%p,%p)\n", a0, a1, a2, a3);

    int iOption = MACTmain("HHOOK");
    HHOOK bReturnValue = NULL;
    if(iOption == 23) {
        bReturnValue = SR_HHOOK;
    }

    HHOOK ret = FALSE;
    __try {
        ret = TrueSetWindowsHookEx(a0, a1, a2, a3);
    } __finally {
        MACTlog("-SetWindowsHookEx will return %p\n", ret);
        MACTlog("*SetWindowsHookEx(%p,%p,%p,%p)(%p,%x,%p)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 23) {
            ret = bReturnValue;
            MACTlog("+SetWindowsHookEx modified to return %p\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MySfcTerminateWatcherThread(void)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSfcTerminateWatcherThread();

    MACTlog(":SfcTerminateWatcherThread(void)\n");

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueSfcTerminateWatcherThread();
    } __finally {
        MACTlog("-SfcTerminateWatcherThread will return %x\n", ret);
        MACTlog("*SfcTerminateWatcherThread(void)(%x,%x,%x)", ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+SfcTerminateWatcherThread modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyStartServiceCtrlDispatcherA(CONST SERVICE_TABLE_ENTRYA *a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueStartServiceCtrlDispatcherA(a0);

    MACTlog(":StartServiceCtrlDispatcherA(%p)\n", a0);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueStartServiceCtrlDispatcherA(a0);
    } __finally {
        MACTlog("-StartServiceCtrlDispatcherA will return %x\n", ret);
        MACTlog("*StartServiceCtrlDispatcherA(%p)(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+StartServiceCtrlDispatcherA modified to return %x\n", ret);
        }
    }

    return ret;
}

DWORD WINAPI MySuspendThread(HANDLE a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSuspendThread(a0);

    MACTlog(":SuspendThread(%p)\n", a0);

    int iOption = MACTmain("DWORD");
    DWORD bReturnValue = 0;
    if(iOption == 15) {
        bReturnValue = SR_DWORD;
    }

    DWORD ret;
    __try {
        ret = TrueSuspendThread(a0);
    } __finally {
        MACTlog("-SuspendThread will return %ld\n", ret);
        MACTlog("*SuspendThread(%p),(%ld,%ld,%ld)", a0, ret, iOption, bReturnValue);
        if(iOption == 15) {
            ret = bReturnValue;
            MACTlog("+SuspendThread modified to return %ld\n", ret);
        }
    }

    return ret;
}

INT __cdecl Mysystem(const char *a0) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return Truesystem(a0);

    MACTlog(":system(%s)\n", a0);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_UINT;
    }

    INT ret = 0;
    __try {
        ret = Truesystem(a0);
    } __finally {
        MACTlog("-system will return %x\n", ret);
        MACTlog("*system(%s),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+system modified to return %x\n", ret);            
        }
    }

    return ret;
} 

INT __cdecl My_wsystem(const wchar_t *a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED) 
        return True_wsystem(a0);

    MACTlog(":_wsystem(%s)\n", a0);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_UINT;
    }

    INT ret = 0;
    __try {
        ret = True_wsystem(a0);
    } __finally {
        MACTlog("-_wsystem will return %x\n", ret);
        MACTlog("*_wsystem(%s,%p,%p),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+_wsystem modified to return %x\n", ret);            
        }
    }

    return ret;
}   

BOOL (WINAPI MyThread32First)(HANDLE          a0,
                              LPTHREADENTRY32 a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueThread32First(a0, a1);

    MACTlog(":Thread32First(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueThread32First(a0, a1);
    } __finally {
        MACTlog("-Thread32First will return %x\n", ret);
        MACTlog("*Thread32First(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Thread32First modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL (WINAPI MyThread32Next)(HANDLE          a0,
                             LPTHREADENTRY32 a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueThread32Next(a0, a1);

    MACTlog(":Thread32Next(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueThread32Next(a0, a1);
    } __finally {
        MACTlog("-Thread32Next will return %x\n", ret);
        MACTlog("*Thread32Next(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Thread32Next modified to return %x\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyToolhelp32ReadProcessMemory(DWORD   a0,
                                          LPCVOID a1,
                                          LPVOID  a2,
                                          SIZE_T  a3,
                                          SIZE_T  *a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueToolhelp32ReadProcessMemory(a0, a1, a2, a3, a4);

    MACTlog(":Toolhelp32ReadProcessMemory(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueToolhelp32ReadProcessMemory(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-Toolhelp32ReadProcessMemory will return %x\n", ret);
        MACTlog("*Toolhelp32ReadProcessMemory(%p,%p,%p,%p,%p)(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+Toolhelp32ReadProcessMemory modified to return %x\n", ret);
        }
    }

    return ret;
}

HRESULT WINAPI MyURLDownloadToFile(LPUNKNOWN            a0,
                                   LPCTSTR              a1,
                                   LPCTSTR              a2,
                                   DWORD                a3,
                                   LPBINDSTATUSCALLBACK a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueURLDownloadToFile(a0, a1, a2, a3, a4);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":URLDownloadToFile(%p,%s,%s,%p,%p)\n", a0, buffer1, buffer2, a3, a4);
    MACTcomm(">URLDownloadToFile :[%s] [%s]\n", buffer1, buffer2);

    int iOption = MACTmain("HRESULT");
    HRESULT bReturnValue = NULL;
    if(iOption == 24) {
        bReturnValue = SR_HRESULT;
    }

    HRESULT ret = FALSE;
    __try {
        ret = TrueURLDownloadToFile(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-URLDownloadToFile will return %x\n", ret);
        MACTlog("*URLDownloadToFile(%p,%s,%s,%p,%p)(%x,%x,%x)", a0, buffer1, buffer2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 24) {
            ret = bReturnValue;
            MACTlog("+URLDownloadToFile modified to return %x\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

HRESULT WINAPI MyURLDownloadToFileA(LPUNKNOWN            a0,
                                    LPCTSTR              a1,
                                    LPCTSTR              a2,
                                    _Reserved_ DWORD     a3,
                                    LPBINDSTATUSCALLBACK a4)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueURLDownloadToFileA(a0, a1, a2, a3, a4);

    int la = lstrlenA(a1);
    char *buffer1 = new char[la+1];
    strncpy(buffer1, a1, la);
    buffer1[la] = '\0';

    la = lstrlenA(a2);
    char *buffer2 = new char[la+1];
    strncpy(buffer2, a2, la);
    buffer2[la] = '\0';

    MACTlog(":URLDownloadToFileA(%p,%s,%s,%p,%p)\n", a0, buffer1, buffer2, a3, a4);
    MACTcomm(">URLDownloadToFileA :[%s] [%s]\n", buffer1, buffer2);

    int iOption = MACTmain("HRESULT");
    HRESULT bReturnValue = NULL;
    if(iOption == 24) {
        bReturnValue = SR_HRESULT;
    }

    HRESULT ret = FALSE;
    __try {
        ret = TrueURLDownloadToFileA(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-URLDownloadToFileA will return %x\n", ret);
        MACTlog("*URLDownloadToFileA(%p,%s,%s,%p,%p)(%x,%x,%x)", a0, buffer1, buffer2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 24) {
            ret = bReturnValue;
            MACTlog("+URLDownloadToFileA modified to return %x\n", ret);
        }
        delete[] buffer1;
        delete[] buffer2;
    }

    return ret;
}

INT WINAPI MyWideCharToMultiByte(UINT                               a0,
                                 DWORD                              a1,
                                 _In_NLS_string_(cchWideChar)LPCWCH a2,
                                 int                                a3,
                                 LPSTR                              a4,
                                 int                                a5,
                                 LPCCH                              a6,
                                 LPBOOL                             a7)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueWideCharToMultiByte(a0, a1, a2, a3, a4, a5, a6, a7);

    MACTlog(":WideCharToMultiByte(%p,%p,%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6, a7);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    INT ret = 0;
    __try {
        ret = TrueWideCharToMultiByte(a0, a1, a2, a3, a4, a5, a6, a7);
    } __finally {
        MACTlog("-WideCharToMultiByte will return %x\n", ret);
        MACTlog("*WideCharToMultiByte(%p,%p,%p,%p,%p,%p,%p,%p),(%x,%x,%x)", a0, a1, a2, a3, a4, a5, a6, a7, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+WideCharToMultiByte modified to return %x\n", ret);            
        }
    }

    TrueSleep(200);
    return ret;
}

BOOL WINAPI MyWriteProcessMemory(HANDLE  a0,
                                 LPVOID  a1,
                                 LPCVOID a2,
                                 SIZE_T  a3,
                                 SIZE_T  *a4) 
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueWriteProcessMemory(a0, a1, a2, a3, a4);

    MACTlog(":WriteProcessMemory(%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        MACTSaveFromAddress((LPVOID)a2, a3, 4);
        ret = TrueWriteProcessMemory(a0, a1, a2, a3, a4);
    } __finally {
        MACTlog("-WriteProcessMemory will return %x\n", ret);
        MACTlog("*WriteProcessMemory(%p,%p,%p,%p,%p)(%x,%x,%x)", a0, a1, a2, a3, a4, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+WriteProcessMemory modified to return %x\n", ret);
        }
    }

    return ret;
}

SOCKET WINAPI Myaccept(SOCKET           a0,
                       struct sockaddr *a1,
                       int             *a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return Trueaccept(a0, a1, a2);

    MACTlog(":accept(%p,%p,%x)\n", a0, a1, a2);

    MACTcomm(">accept\n");
    int iOption = MACTmain("SOCKET");
    SOCKET bReturnValue = NULL;
    if(iOption == 25) {
        bReturnValue = SR_SOCKET;
    }

    SOCKET ret = NULL;
    __try {
        MACTPrint(">accept before\n");
        ret = Trueaccept(a0, a1, a2);
        MACTPrint(">accept after\n");
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        MACTlog("-accept failed\n");
        MACTlog("*accept(%p,%p,%x)(NULL,%x,NULL)", a0, a1, a2, iOption);
        return NULL;
    } 

    MACTlog("-accept will return %p\n", ret);
    MACTlog("*accept(%p,%p,%x)(%p,%x,%p)", a0, a1, a2, ret, iOption, bReturnValue);
    if(iOption == 25) {
        ret = bReturnValue;
        MACTlog("+accept modified to return %p\n", ret);
    }

    return ret;
}

INT WINAPI Mybind(SOCKET                 a0,
                  const struct sockaddr *a1,
                  int                    a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return Truebind(a0, a1, a2);

    MACTlog(":bind(%p,%p,%x)\n", a0, a1, a2);

    char *strPort = new char[6];
    SOCKADDR_IN *sa1 = (SOCKADDR_IN *)a1;
    char *ip = inet_ntoa(sa1->sin_addr);
    MACTPrint(">bind IP: %s Port: %d\n", ip, sa1->sin_port);
    MACTcomm(">bind IP: %s Port: %d\n\n", ip, sa1->sin_port);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    UINT ret = 0;
    __try {
        ret = Truebind(a0, a1, a2);
    } __finally {
        MACTlog("-bind will return %x\n", ret);
        MACTlog("*bind(%p,%p,%x),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+bind modified to return %x\n", ret);            
        }
    }

    return ret;
}

INT WINAPI Myconnect(SOCKET                 a0,
                     const struct sockaddr *a1,
                     int                    a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return Trueconnect(a0, a1, a2);

    MACTlog(":connect(%p,%p,%x)\n", a0, a1, a2);

    SOCKADDR_IN *sa1 = (SOCKADDR_IN *)a1;
    char *ip = inet_ntoa(sa1->sin_addr);

    MACTPrint(">connect IP: %s Port: %hu\n", ip, sa1->sin_port);
    MACTcomm(">connect IP: %s Port: %hu\n\n", ip, sa1->sin_port);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    UINT ret = 0;
    __try {
        ret = Trueconnect(a0, a1, a2);
    } __finally {
        MACTlog("-connect will return %x\n", ret);
        MACTlog("*connect(%p,%p,%x),(%x,%x,%x)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+connect modified to return %x\n", ret);            
        }
    }

    return ret;
}

BOOL WINAPI MyConnectNamedPipe(HANDLE       a0,
                               LPOVERLAPPED a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueConnectNamedPipe(a0, a1);

    MACTlog(":ConnectNamedPipe(%p,%p)\n", a0, a1);

    int iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_BOOL;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueConnectNamedPipe(a0, a1);
    } __finally {
        MACTlog("-ConnectNamedPipe will return %x\n", ret);
        MACTlog("*ConnectNamedPipe(%p,%p)(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+ConnectNamedPipe modified to return %x\n", ret);
        }
    }

    return ret;
}

INT WINAPI Myrecv(SOCKET   a0,
                  char    *a1,
                  int      a2,
                  int      a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return Truerecv(a0, a1, a2, a3);

    MACTlog(":recv(%p,%p,%x,%x)\n", a0, a1, a2, a3);

    MACTcomm(">recv:\n%s\n", a1);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    UINT ret = 0;
    __try {
        ret = Truerecv(a0, a1, a2, a3);
    } __finally {
        MACTlog("-recv will return %x\n", ret);
        MACTlog("*recv(%p,%p,%x,%x),(%x,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+recv modified to return %x\n", ret);            
        }
    }

    return ret;
}

INT WINAPI Mysend(SOCKET         a0,
                  const char    *a1,
                  int            a2,
                  int            a3)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return Truesend(a0, a1, a2, a3);

    MACTlog(":send(%p,%p,%x,%x)\n", a0, a1, a2, a3);

    MACTcomm(">send:\n%s\n", a1);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    UINT ret = 0;
    __try {
        ret = Truesend(a0, a1, a2, a3);
    } __finally {
        MACTlog("-send will return %x\n", ret);
        MACTlog("*send(%p,%p,%x,%x)", a0, a1, a2, a3, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+send modified to return %x\n", ret);            
        }
    }

    return ret;
}

INT WINAPI MyWSAStartup(WORD      a0,
                      LPWSADATA a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueWSAStartup(a0, a1);

    MACTlog(":WSAStartup(%x,%p)\n", a0, a1);

    int iOption = MACTmain("INT");
    INT bReturnValue = 0;
    if(iOption == 14) {
        bReturnValue = SR_INT;
    }

    UINT ret = 0;
    __try {
        ret = TrueWSAStartup(a0, a1);
    } __finally {
        MACTlog("-WSAStartup will return %x\n", ret);
        MACTlog("*WSAStartup(%x,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 14) {
            ret = bReturnValue;
            MACTlog("+WSAStartup modified to return %x\n", ret);            
        }
    }

    return ret;
}

HANDLE WINAPI MyCreateFileMappingA(HANDLE                a0,
                                   LPSECURITY_ATTRIBUTES a1,
                                   DWORD                 a2,
                                   DWORD                 a3,
                                   DWORD                 a4,
                                   LPCSTR                a5)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE)
        return TrueCreateFileMappingA(a0, a1, a2, a3, a4, a5);

    MACTlog(":CreateFileMappingA(%p,%p,%p,%p,%p,%p)\n", a0, a1, a2, a3, a4, a5);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = FALSE;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = 0;
    __try {
        ret = TrueCreateFileMappingA(a0, a1, a2, a3, a4, a5);
    } __finally {
        MACTlog("-CreateFileMappingA will return %p\n", ret);
        MACTlog("*CreateFileMappingA(%p,%p,%p,%p,%p,%p)(%p,%x,%p)", a0, a1, a2, a3, a4, a5, ret, iOption, bReturnValue);

        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+CreateFileMappingA modified to return %p\n", ret);
        }
    }

    return ret;
}

BOOL WINAPI MyIsNTAdmin(DWORD  a0, 
                        DWORD *a1)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueIsNTAdmin(a0, a1);

    MACTlog(":IsNTAdmin(%p,%p)\n", a0, a1);

    BOOL iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_LONG;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueIsNTAdmin(a0, a1);
    } __finally {
        MACTlog("-IsNTAdmin will return %x\n", ret);
        MACTlog("*IsNTAdmin(%p,%p),(%x,%x,%x)", a0, a1, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+IsNTAdmin modified to return %x\n", ret);
        }
    }

    return ret;
}


BOOL WINAPI MyIsUserAnAdmin(void)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueIsUserAnAdmin();

    MACTlog(":IsUserAnAdmin(void)\n");

    BOOL iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_LONG;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueIsUserAnAdmin();
    } __finally {
        MACTlog("-IsUserAnAdmin will return %x\n", ret);
        MACTlog("*IsUserAnAdmin(void),(%x,%x,%x)", ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+IsUserAnAdmin modified to return %x\n", ret);
        }
    }

    return ret;
}

HMODULE WINAPI MyLoadLibrary(LPCTSTR a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueLoadLibrary(a0);

    int la;
    if(a0 == NULL)
        la = 4;
    else
        la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    if(a0 == NULL)
        strncpy(buffer0, "NULL", la);
    else
        strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":LoadLibrary(%s)\n", buffer0);
 
    int iOption = MACTmain("HMODULE");
    HMODULE bReturnValue = NULL;
    if(iOption == 16) {
        bReturnValue = SR_HMODULE;
    }
   
    HMODULE ret;
    __try {
        ret = TrueLoadLibrary(a0);
    } __finally {
        MACTlog("-LoadLibrary will return (void)\n");
        MACTlog("*LoadLibrary(%s),(%p,%x,%p)", buffer0, ret, iOption, bReturnValue);
        if(iOption == 16) {
            ret = bReturnValue;
            MACTlog("+LoadLibrary modified to return %p\n", ret);
        }
        delete[] buffer0;
    }

    return ret;
}

HMODULE WINAPI MyLoadLibraryExA(LPCSTR a0,
                                HANDLE a1,
                                DWORD  a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return TrueLoadLibraryExA(a0, a1, a2);

    int la;
    if(a0 == NULL)
        la = 4;
    else
        la = lstrlenA(a0);
    char *buffer0 = new char[la+1];
    if(a0 == NULL)
        strncpy(buffer0, "NULL", la);
    else
        strncpy(buffer0, a0, la);
    buffer0[la] = '\0';

    MACTlog(":LoadLibraryExA(%s,%p,%p)\n", buffer0, a1, a2);
 
    int iOption = MACTmain("HMODULE");
    HMODULE bReturnValue = NULL;
    if(iOption == 16) {
        bReturnValue = SR_HMODULE;
    }
   
    HMODULE ret;
    __try {
        ret = TrueLoadLibraryExA(a0, a1, a2);
    } __finally {
        MACTlog("-LoadLibraryExA will return (void)\n");
        MACTlog("*LoadLibraryExA(%s,%p,%p),(%p,%x,%p)", buffer0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 16) {
            ret = bReturnValue;
            MACTlog("+LoadLibraryExA modified to return %p\n", ret);
        }
        delete[] buffer0;
    }

    return ret;
}

HWND WINAPI MyGetConsoleWindow(void)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED || !MACTVERBOSE) 
        return NULL;

    MACTlog(":GetConsoleWindow(void)\n");
 

    MACTlog("-GetConsoleWindow will return NULL\n");
    MACTlog("*GetConsoleWindow(void),(0,0,NULL)");
    MACTlog("+GetConsoleWindow modified to return NULL\n");

    return NULL;
}

BOOL WINAPI MySetProcessDEPPolicy(DWORD a0)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueSetProcessDEPPolicy(a0);

    MACTlog(":SetProcessDEPPolicy(%x)\n", a0);

    BOOL iOption = MACTmain("BOOL");
    BOOL bReturnValue = FALSE;
    if(iOption == 1) {
        bReturnValue = SR_LONG;
    }

    BOOL ret = FALSE;
    __try {
        ret = TrueSetProcessDEPPolicy(a0);
    } __finally {
        MACTlog("-SetProcessDEPPolicy will return %x\n", ret);
        MACTlog("*SetProcessDEPPolicy(%x),(%x,%x,%x)", a0, ret, iOption, bReturnValue);
        if(iOption == 1) {
            ret = bReturnValue;
            MACTlog("+SetProcessDEPPolicy modified to return %x\n", ret);
        }
    }

    return ret;
}

INT WINAPI MyWSASend(SOCKET                             a0,
                     LPWSABUF                           a1,
                     DWORD                              a2,
                     LPDWORD                            a3,
                     DWORD                              a4,
                     LPWSAOVERLAPPED                    a5,
                     LPWSAOVERLAPPED_COMPLETION_ROUTINE a6)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueWSASend(a0, a1, a2, a3, a4, a5, a6);

    MACTlog(":WSASend(%p,%p,%lu,%p,%lu,%p,%p)\n", a0, a1, a2, a3, a4, a5, a6);

    u_long imaxbuf = 0;
    for(int x = 0; x < a2; ++x)
        imaxbuf = max(imaxbuf, a1[x].len);

    char *buffer = new char[imaxbuf+1];
    for(int x = 0; x < a2; ++x) {
        snprintf(buffer, a1[x].len, "%s", a1[x].buf);
        MACTcomm(">WSASend:\n%s\n", buffer);
    }

    INT ret = FALSE;
    __try {
        ret = TrueWSASend(a0, a1, a2, a3, a4, a5, a6);
    } __finally {
        MACTlog("-WSASend will return %x\n", ret);
        MACTlog("*WSASend(%p,%p,%lu,%p,%lu,%p,%p),(%p,0,0)", a0, a1, a2, a3, a4, a5, a6, ret);
        delete[] buffer;
    }

    return ret;
}

HANDLE WINAPI MyHeapCreate(DWORD  a0,
                           SIZE_T a1,
                           SIZE_T a2)
{
    if(MACTDEBUG2)
       MACTPrint(">>DEBUG Function: %s\n", __FUNCTION__);

    if(!MACTSTARTED)
        return TrueHeapCreate(a0, a1, a2);

    MACTlog(":HeapCreate(%x,%d,%d)\n", a0, a1, a2);

    int iOption = MACTmain("HANDLE");
    HANDLE bReturnValue = FALSE;
    if(iOption == 0) {
        bReturnValue = SR_HANDLE;
    }

    HANDLE ret = FALSE;
    __try {
        ret = TrueHeapCreate(a0, a1, a2);
    } __finally {
        MACTlog("-HeapCreate will return %p\n", ret);
        MACTlog("*HeapCreate(%x,%d,%d),(%p,%x,%p)", a0, a1, a2, ret, iOption, bReturnValue);
        if(iOption == 0) {
            ret = bReturnValue;
            MACTlog("+HeapCreate modified to return %x\n", ret);
        }
    }

    return ret;
}

//***********************************************************************************************
//
// Function   : MACTGetSocket
// Description: Establishes the connection to the socket for server communications
//
//***********************************************************************************************
BOOL MACTGetSocket(u_short uPort)
{
    WSADATA WsaDat;
    if(TrueWSAStartup(MAKEWORD(2,2),&WsaDat)!=0) {
        printf("Winsock error - Winsock initialization failed\r\n");
        WSACleanup();
        return FALSE;
    }
    
    // Create our socket
    ConnectSocket=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(ConnectSocket==INVALID_SOCKET)
    {
        printf("Winsock error - Socket creation Failed!\r\n");
        WSACleanup();
        return FALSE;
    }
    
    // Resolve IP address for hostname
    struct hostent *host;
//    if((host=gethostbyname("localhost"))==NULL)
    if((host=Truegethostbyname("localhost"))==NULL)
    {
        printf("Failed to resolve hostname.\r\n");
        WSACleanup();
        return FALSE;
    }
    
    // Setup our socket address structure
    SOCKADDR_IN SockAddr;
    SockAddr.sin_port=htons(uPort);
    SockAddr.sin_family=AF_INET;
    SockAddr.sin_addr.s_addr=*((unsigned long*)host->h_addr);
    
    // Attempt to connect to server
    if(Trueconnect(ConnectSocket,(SOCKADDR*)(&SockAddr),sizeof(SockAddr))!=0)
    {
        printf("Failed to establish connection with server\r\n");
        WSACleanup();
//        system("PAUSE");
        return FALSE;
    }
    else
        printf("Connected to server.\n");
    
    // If iMode!=0, non-blocking mode is enabled.
    u_long iMode=1;
    ioctlsocket(ConnectSocket, FIONBIO, &iMode);
 
    return TRUE;
}

//***********************************************************************************************
//
// Function   : MACTSocketPrint
// Description: Send data through the socket connection to the server.
//
//***********************************************************************************************
BOOL MACTSocketPrint(char *szMessage)
{

        ++MACTMSGS;

        MACTSEND = TRUE;

        fd_set WriteFDs;
        FD_ZERO(&WriteFDs);
        FD_SET(ConnectSocket, &WriteFDs);

        char buffer[512];
        memset(buffer, 0, 512);
        strncpy(buffer, szMessage, strlen(szMessage));
        buffer[511] = '\0';

        if(select(0, NULL, &WriteFDs, NULL, 0) > 0) {
            if (FD_ISSET(ConnectSocket, &WriteFDs)) {
                int iBytesSent = Truesend(ConnectSocket, buffer, 512, 0);
                if(iBytesSent < 0) {
                    int nError=WSAGetLastError();
                    printf("Winsock error code: %d\r\n", nError);
                    printf("Server disconnected!\r\n");
                    shutdown(ConnectSocket,SD_SEND);
                    closesocket(ConnectSocket);
                    exit(0);
                }
            }
            else {
                printf("Error Write FD_ISSET\n");
            }
        } 
        else {           
            printf("Error on select write.\n");
            int nError=WSAGetLastError();
            printf("Winsock error code: %d\r\n", nError);
            printf("Server disconnected!\r\n");
            shutdown(ConnectSocket,SD_SEND);
            closesocket(ConnectSocket);
            exit(0);
        }

        MACTSEND = FALSE;
        --MACTMSGS;

        return TRUE;
}

//***********************************************************************************************
//
// Function   : MACTExecuteCommand
// Description: Execute the users command sent from the server.
//
//***********************************************************************************************
INT MACTExecuteCommand(char* buffer, char* sType)
{
    int iRet = 100;

    if(strncmp(buffer, "CE", 2) == 0) {
        MACTFINISH = TRUE;
    } else if(strncmp(buffer, "C\0", 2) == 0 ) {
        (void)0;
    } else if(strncmp(buffer, "DC", 2) == 0) {
        MACTPrint(">Displaying Commands mact.cpp.\n");
    } else if(strncmp(buffer, "DM", 2) == 0) {
        std::string sAddress = buffer;
        sAddress = sAddress.substr(2, 8);
        std::string sLength = buffer;
        sLength  = sLength.substr(10, 8);
        MACTDisplayMemory((LPVOID)std::stoi(sAddress, NULL, 16), std::stoi(sLength, NULL, 16));
    } else if(strncmp(buffer, "DS", 2) == 0) {
        MACTDisplayMemoryConstruct();
    } else if(strncmp(buffer, "BA", 2) == 0) {
        std::string sBreakpoint;
        sBreakpoint = buffer;
        MACTAddBreakpoint(sBreakpoint.substr(2, sBreakpoint.length() - 2));
    } else if(strncmp(buffer, "BC", 2) == 0) {
        MACTClearBreakpoint();
    } else if(strncmp(buffer, "BD", 2) == 0) {
        std::string sBreakpoint;
        sBreakpoint = buffer;
        MACTDeleteBreakpoint(sBreakpoint.substr(2, sBreakpoint.length() - 2));
    } else if(strncmp(buffer, "BL", 2) == 0) {
        MACTListBreakpoint();
    } else if(strncmp(buffer, "MA", 2) == 0) {
        std::string sAddress = buffer;
        sAddress = sAddress.substr(2, 8);
        std::string sLength = buffer;
        sLength  = sLength.substr(10, 8);
        MACTSaveFromAddress((LPVOID)std::stoi(sAddress, NULL, 16), std::stoi(sLength, NULL, 16), 5);
    } else if(strncmp(buffer, "SR", 2) == 0) {
        std::string sHex;
        sHex = buffer;
        sHex = sHex.substr(2, sHex.length() - 2);
        iRet = MACTSubRetVal(sType, std::stoi(sHex, NULL, 16));
    }
    else
        MACTPrint(">Invalid command.\n");

    return iRet;

}

//***********************************************************************************************
//
// Function   : MACTReceive
// Description: Receive data from the server.
//
//***********************************************************************************************
static INT MACTReceive(char * sType)
{

    int iRet = 100;

    if(MACTFINISH) {
        return iRet;
    }

    char buffer[80];
    memset(buffer, 0, 80);


    MACTBP = TRUE;

    while(buffer[0] != 'C') {
        MACTPrint("MACTSTART\n");

        fd_set ReadFDs;
        FD_ZERO(&ReadFDs);
        FD_SET(ConnectSocket, &ReadFDs);

        memset(buffer, 0, 80);

        if(select(0, &ReadFDs, NULL, NULL, 0) > 0) {
            if (FD_ISSET(ConnectSocket, &ReadFDs)) {
                memset(buffer, 0, 80);
                int inDataLength = Truerecv(ConnectSocket, buffer, 80, 0);
                if(inDataLength > 0) {
                    buffer[79] = '\0';
                    if(MACTDEBUG) {
                        printf("Debug: Received %d bytes.\n", inDataLength);
                        printf("Debug: Received from server: <%s>\n", buffer);
                    }
                    iRet = MACTExecuteCommand(buffer, sType);
                }
            }
            else {
                MACTPrint(">Error FD_ISSET\n");
            }
        } 
        else {
            MACTPrint(">Error on select.\n");
        }

        switch(buffer[0]) {
            case 'S' :
                MACTBP = FALSE;
                return iRet;
                break;
            case 'Q' :
                exit(0);
                break;
        }
    }


    MACTBP = FALSE;
    return iRet;
}

//***********************************************************************************************
//
// Function   : MACTPrint
// Description: Send a message to the server.
//
//***********************************************************************************************
BOOL MACTPrint(const CHAR *psz, ...)
{

    if(MACTDEBUG)
        printf(">DEBUG: MACTPrint\n");

    va_list args;
    va_start(args, psz);

    int     len;  
    char    *buffer;  
  
    len = _vscprintf(psz, args) + 1; 
  
    buffer = (char*)malloc( len * sizeof(char) );  
    vsprintf(buffer, psz, args);
 
    MACTSocketPrint(buffer);

    if(MACTFINISH && (buffer[0] == ':')) {
        std::string sbuffer = buffer;
        sbuffer = sbuffer.substr(1, sbuffer.length() - 1);
        sbuffer = sbuffer.substr(0, sbuffer.find('(', 0));
        std::transform(sbuffer.begin(), sbuffer.end(), sbuffer.begin(), toupper);
        for(int i = 0; i < MACTBreakpointCount; ++i) 
            if(sbuffer == MACTBreakpoints[i]) {
                MACTFINISH = FALSE;
                break;
            }
    }
    
    vprintf(psz, args);
    va_end(args);

    free(buffer);

    return TRUE;

}

//***********************************************************************************************
//
// Function   : MACTCreateThread
// Description: Create a thread for monitoring memory allocations.
//
//***********************************************************************************************
void MACTCreateThread(LPVOID buffer, size_t msize, int interval, int imemtype)
{
    pDataArray[THREADCOUNT] = (PMEMDATA) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(MEMDATA));

    if( pDataArray[THREADCOUNT] == NULL )
        ExitProcess(2);

    pDataArray[THREADCOUNT]->Mem_address   = buffer;
    pDataArray[THREADCOUNT]->Mem_size      = msize;
    pDataArray[THREADCOUNT]->Mem_interval  = interval;
    pDataArray[THREADCOUNT]->Mem_type      = imemtype;

    hThreadArray[THREADCOUNT] = CreateThread(NULL, 0, MACTMemThread, pDataArray[THREADCOUNT], 0, &dwThreadIdArray[THREADCOUNT]);   

    if (hThreadArray[THREADCOUNT] == NULL) 
           ExitProcess(3);

    ++THREADCOUNT;
}

//***********************************************************************************************
//
// Function   : MACTLoadTicks
// Description: Load GetTickCount substitution values from file.
//
//***********************************************************************************************
int MACTLoadTicks()
{
    using namespace std;

    string line;
    ifstream myfile ("getticks.txt");

    if(myfile.is_open()) {
        while(getline(myfile, line))
          vTicks.push_back(stoi(line, NULL, 16));
        myfile.close();
    } else
        return 0;

    int iGetTickCount = 0;
    for(vector<int>::iterator it = vTicks.begin(); it != vTicks.end(); ++it) {
        cout << *it << endl;
        ++iGetTickCount;
    }

    return iGetTickCount;
}

//***********************************************************************************************
//
// Function   : MACTLoadTicks64
// Description: Load GetTickCount64 substitution values from file.
//
//***********************************************************************************************
int MACTLoadTicks64()
{
    using namespace std;

    string line;
    ifstream myfile ("getticks64.txt");

    if(myfile.is_open()) {
        while(getline(myfile, line))
          vTicks64.push_back(stoi(line, NULL, 16));
        myfile.close();
    } else
        return 0;

    int iGetTickCount = 0;
    for(vector<int>::iterator it = vTicks64.begin(); it != vTicks64.end(); ++it) {
        cout << *it << endl;
        ++iGetTickCount;
    }

    return iGetTickCount;
}


//***********************************************************************************************
//
// Function   : MACTLoadQPC
// Description: Load QueryPerformanceCounter substitution values from file.
//
//***********************************************************************************************
int MACTLoadQPC()
{
    using namespace std;

    string line;
    ifstream myfile ("qpc.txt");

    if(myfile.is_open()) {
        printf("File is open.");
        LARGE_INTEGER liTemp;
        while(getline(myfile, line)) {
            liTemp.QuadPart = stoi(line, NULL, 16); 
            vQPC.push_back(liTemp);
        }
        myfile.close();
    } else
        return 0;

    int iQPCCount = 0;
    for(vector<LARGE_INTEGER>::iterator it = vQPC.begin(); it != vQPC.end(); ++it) {
        ++iQPCCount;
    }

    return iQPCCount;
}

//***********************************************************************************************
//
// Function   : DllMain
// Description: Verify, Attach and Detach functions.
//
//***********************************************************************************************
BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {

        if (!fLog) {
            CreateLogDir();
        }

        DetourRestoreAfterWith();


        if(!MACTGetSocket(27015)) 
            if(!MACTGetSocket(27014))
                MACTGetSocket(27013);

        std::string sStart = "MACTINIT " + MACTdir;
        MACTPrint(sStart.c_str());

        MACTPrint(">Starting...\n");

        MACTTICKCOUNT = MACTLoadTicks();
        MACTPrint(">MACTTICKCOUNT   = %d\n", MACTTICKCOUNT);
        MACTTICKCOUNT64 = MACTLoadTicks64();
        MACTPrint(">MACTTICKCOUNT64 = %d\n", MACTTICKCOUNT64);
        MACTQPCCOUNT = MACTLoadQPC();
        MACTPrint(">MACTQPCCOUNT = %d\n", MACTQPCCOUNT);

        MACTPrint(">mact" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " Starting.\n");
        PVOID pbExeEntry = DetourGetEntryPoint(NULL);
        PVOID pbDllEntry = DetourGetEntryPoint(hinst);
        MACTPrint(">mact" DETOURS_STRINGIFY(DETOURS_BITS) ".dll: "
               " ExeEntry=%p, DllEntry=%p\n", pbExeEntry, pbDllEntry);

        Verify("GetTickCount", (PVOID)GetTickCount);
        Verify("GetTickCount64", (PVOID)GetTickCount64);
        Verify("QueryPerformanceCounter", (PVOID)QueryPerformanceCounter);
        Verify("Sleep", (PVOID)Sleep);
        Verify("SleepEx", (PVOID)SleepEx);
        Verify("lstrcmpiA", (PVOID)lstrcmpiA);
        Verify("lstrcmpiW", (PVOID)lstrcmpiW);
        Verify("lstrcmpW", (PVOID)lstrcmpW);
        Verify("CompareStringEx", (PVOID)CompareStringEx);
        Verify("CreateFileW", (HANDLE)CreateFileW);
        Verify("CreateFileA", (HANDLE)CreateFileA);
        Verify("GetFileSize", (PVOID)GetFileSize);
        Verify("WriteFile", (PVOID)WriteFile);
        Verify("WriteFileEx", (PVOID)WriteFileEx);
        Verify("FlushFileBuffers", (PVOID)FlushFileBuffers);
        Verify("CloseHandle", (PVOID)CloseHandle);
        Verify("CopyFileA", (PVOID)CopyFileA);
        Verify("CopyFileW", (PVOID)CopyFileW);
        Verify("CopyFileExA", (PVOID)CopyFileExA);
        Verify("CopyFileExW", (PVOID)CopyFileExW);
        Verify("DeleteFileA", (PVOID)DeleteFileA);
        Verify("DeleteFileW", (PVOID)DeleteFileW);
        Verify("VirtualAlloc", (LPVOID)VirtualAlloc);
        Verify("VirtualAllocEx", (LPVOID)VirtualAllocEx);
        Verify("VirtualProtect", (PVOID)VirtualProtect);
        Verify("VirtualProtectEx", (PVOID)VirtualProtectEx);
        Verify("VirtualFree", (PVOID)VirtualFree);
        Verify("VirtualFreeEx", (PVOID)VirtualFreeEx);
        Verify("WinExec", (PVOID)WinExec);
        Verify("ShellExecuteW", (PVOID)ShellExecuteW);
        Verify("ShellExecuteExA", (PVOID)ShellExecuteExA);
        Verify("ShellExecuteExW", (PVOID)ShellExecuteExW);
        Verify("RegGetValueA", (PVOID)RegGetValueA);
        Verify("RegGetValueW", (PVOID)RegGetValueW);
        Verify("RegQueryValueEx", (PVOID)RegQueryValueEx);        
        Verify("RegOpenKeyEx", (PVOID)RegOpenKeyEx);
        Verify("RegSetValueA", (PVOID)RegSetValueA);
        Verify("RegSetValueEx", (PVOID)RegSetValueEx);
        Verify("RegSetValueExW", (PVOID)RegSetValueExW);
        Verify("RegEnumKeyExA", (PVOID)RegEnumKeyExA);
        Verify("RegEnumKeyExW", (PVOID)RegEnumKeyExW);
        Verify("RegCreateKeyEx", (PVOID)RegCreateKeyEx);
        Verify("AdjustTokenPrivileges", (PVOID)AdjustTokenPrivileges); 
        Verify("AttachThreadInput", (PVOID)AttachThreadInput);
        Verify("BitBlt", (PVOID)BitBlt);
        Verify("CertOpenSystemStore", (LPVOID)CertOpenSystemStore);
        Verify("ControlService", (PVOID)ControlService);
        Verify("CreateMutex", (HANDLE)CreateMutex);
        Verify("CreateMuteEx", (HANDLE)CreateMutexEx);
        Verify("CreateProcess", (PVOID)CreateProcess);
        Verify("CreateProcessW", (PVOID)CreateProcessW);
        Verify("TerminateProcess", (PVOID)TerminateProcess);
        Verify("CreateRemoteThread", (HANDLE)CreateRemoteThread);
        Verify("CreateRemoteThreadEx", (HANDLE)CreateRemoteThreadEx);
        Verify("CreateService", (HANDLE)CreateService);        
        Verify("CreateToolhelp32Snapshot", (HANDLE)CreateToolhelp32Snapshot);
        Verify("CryptAcquireContextA", (PVOID)CryptAcquireContextA);
        Verify("CryptAcquireContextW", (PVOID)CryptAcquireContextW);
        Verify("DeviceIoControl", (PVOID)DeviceIoControl);
        Verify("EnumProcesses", (PVOID)EnumProcesses);
        Verify("EnumProcessModules", (PVOID)EnumProcessModules);
        Verify("EnumProcessModulesEx", (PVOID)EnumProcessModulesEx);
        Verify("FindFirstFile", (HANDLE)FindFirstFile);
        Verify("FindFirstFileEx", (HANDLE)FindFirstFileEx);
        Verify("FindNextFile", (PVOID)FindNextFile);
        Verify("FindResourceA", (HANDLE)FindResourceA);
        Verify("FindResourceExA", (HANDLE)FindResourceExA);
        Verify("FindWindow", (HANDLE)FindWindow);
        Verify("FindWindowEx", (HANDLE)FindWindowEx);
        Verify("FtpOpenFileW", (HANDLE)FtpOpenFileW);
        Verify("FtpPutFile", (PVOID)FtpPutFile);
        Verify("GetAdaptersInfo", (PVOID)GetAdaptersInfo);
        Verify("GetAsyncKeyState", (PVOID)GetAsyncKeyState);
        Verify("GetDC", (PVOID)GetDC);
        Verify("GetForegroundWindow", (PVOID)GetForegroundWindow);
        Verify("GetWindowText", (PVOID)GetWindowText);
        Verify("gethostbyname", (PVOID)gethostbyname);
        Verify("getaddrinfo", (PVOID)getaddrinfo);
        Verify("gethostname", (PVOID)gethostname);
        Verify("GetKeyState", (PVOID)GetKeyState);
        Verify("GetModuleFileName", (PVOID)GetModuleFileName);
        Verify("GetModuleFileNameExA", (PVOID)GetModuleFileNameExA);
        Verify("GetModuleFileNameExW", (PVOID)GetModuleFileNameExW);
        Verify("GetModuleHandle", (HANDLE)GetModuleHandle);
        Verify("GetModuleHandle", (PVOID)GetModuleHandleEx);
        Verify("GetProcAddress", (PVOID)GetProcAddress);
        Verify("GetStartupInfoA", (PVOID)GetStartupInfoA);
        Verify("GetSystemDefaultLangID", (PVOID)GetSystemDefaultLangID);
        Verify("GetTempPathA", (PVOID)GetTempPathA);
        Verify("GetThreadContext", (PVOID)GetThreadContext);
        Verify("GetVersionEx", (PVOID)GetVersionEx);
        Verify("GetWindowsDirectory", (PVOID)GetWindowsDirectory);
        Verify("inet_addr", (PVOID)inet_addr);
        Verify("InternetOpen", (HANDLE)InternetOpen);
        Verify("InternetOpenW", (HANDLE)InternetOpenW);
        Verify("InternetConnectW", (HANDLE)InternetConnectW);
        Verify("HttpOpenRequestW", (HANDLE)HttpOpenRequestW);
        Verify("HttpSendRequestW", (HANDLE)HttpSendRequestW);
        Verify("HttpSendRequestExW", (HANDLE)HttpSendRequestExW);
        Verify("InternetOpenUrl", (HANDLE)InternetOpenUrl);
        Verify("InternetOpenUrlA", (HANDLE)InternetOpenUrlA);
        Verify("InternetReadFile", (PVOID)InternetReadFile);
        Verify("InternetWriteFile", (PVOID)InternetWriteFile);
        Verify("IsWow64Process", (PVOID)IsWow64Process);
//        Verify("LdrLoadDll", (PVOID)LdrLoadDll);
        Verify("LoadResource", (HANDLE)LoadResource);
        Verify("LsaEnumerateLogonSessions", (PVOID)LsaEnumerateLogonSessions);
        Verify("MapViewOfFile", (PVOID)MapViewOfFile);
        Verify("MapViewOfFileEx", (PVOID)MapViewOfFileEx);
        Verify("MapVirtualKeyA", (PVOID)MapVirtualKeyA);
        Verify("MapVirtualKeyExA", (PVOID)MapVirtualKeyExA);
        Verify("MapVirtualKeyW", (PVOID)MapVirtualKeyW);
        Verify("MapVirtualKeyExW", (PVOID)MapVirtualKeyExW);
        Verify("Module32First", (PVOID)Module32First);
        Verify("Module32Next", (PVOID)Module32Next);
        Verify("OpenMutexA", (HANDLE)OpenMutexA);
        Verify("OpenProcess", (HANDLE)OpenProcess);
        Verify("OutputDebugString", (PVOID)OutputDebugString);
        Verify("OutputDebugStringA", (PVOID)OutputDebugStringA);
        Verify("OutputDebugStringW", (PVOID)OutputDebugStringW);
        Verify("PeekNamedPipe", (PVOID)PeekNamedPipe);
        Verify("Process32First", (PVOID)Process32First);
        Verify("Process32FirstW", (PVOID)Process32FirstW);
        Verify("Process32Next", (PVOID)Process32Next);
        Verify("Process32NextW", (PVOID)Process32NextW);
        Verify("QueueUserAPC", (PVOID)QueueUserAPC);
        Verify("ReadProcessMemory", (PVOID)ReadProcessMemory);
        Verify("RegisterHotKey", (PVOID)RegisterHotKey);
        Verify("RegOpenKeyA", (PVOID)RegOpenKeyA);
        Verify("RegOpenKeyExA", (PVOID)RegOpenKeyExA);
        Verify("RegOpenKeyExW", (PVOID)RegOpenKeyExW);
        Verify("ResumeThread", (PVOID)ResumeThread);
//        Verify("TrueSamIConnect", (LPVOID)TrueSamIConnect);
        Verify("TrueLdrLoadDll", (PVOID)TrueLdrLoadDll);
        Verify("TrueRtlCreateRegistryKey", (PVOID)TrueRtlCreateRegistryKey);
        Verify("TrueRtlWriteRegistryValue", (PVOID)TrueRtlWriteRegistryValue);
        Verify("SetFileTime", (PVOID)SetFileTime);
        Verify("SetThreadContext", (PVOID)SetThreadContext);
        Verify("SetWindowsHookEx", (PVOID)SetWindowsHookEx);

        Verify("TrueSfcTerminateWatcherThread", (PVOID)TrueSfcTerminateWatcherThread);

        Verify("StartServiceCtrlDispatcherA", (PVOID)StartServiceCtrlDispatcherA);
        Verify("SuspendThread", (PVOID)SuspendThread);
        Verify("system", (PVOID)system);
        Verify("_wsystem", (PVOID)_wsystem);
        Verify("Thread32First", (PVOID)Thread32First);
        Verify("Thread32Next", (PVOID)Thread32Next);
        Verify("Toolhelp32ReadProcessMemory", (PVOID)Toolhelp32ReadProcessMemory);
        Verify("URLDownloadToFile", (PVOID)URLDownloadToFile);
        Verify("URLDownloadToFileA", (PVOID)URLDownloadToFileA);
        Verify("WideCharToMultiByte", (PVOID)WideCharToMultiByte);
        Verify("WriteProcessMemory", (PVOID)WriteProcessMemory);
        Verify("accept", (PVOID)accept);
        Verify("bind", (PVOID)bind);
        Verify("connect", (PVOID)connect);
        Verify("ConnectNamedPipe", (PVOID)ConnectNamedPipe);
        Verify("recv", (PVOID)recv);
        Verify("send", (PVOID)send);
        Verify("WSAStartup", (PVOID)WSAStartup);
        Verify("CreateFileMappingA", (HANDLE)CreateFileMappingA);

        Verify("TrueIsNTAdmin", (PVOID)TrueIsNTAdmin);   

        Verify("IsUserAnAdmin", (PVOID)IsUserAnAdmin);
        Verify("LoadLibrary", (PVOID)LoadLibrary);
        Verify("LoadLibraryExA", (PVOID)LoadLibraryExA);
        Verify("GetConsoleWindow", (PVOID)GetConsoleWindow);
        Verify("SetProcessDEPPolicy", (PVOID)SetProcessDEPPolicy);
        Verify("CoTaskMemAlloc", (PVOID)CoTaskMemAlloc);
        Verify("CoTaskMemFree", (PVOID)CoTaskMemFree);
        Verify("WSASend", (PVOID)WSASend);
        Verify("HeapCreate", (HANDLE)HeapCreate);

        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());


        DetourAttach(&(PVOID&)TrueGetTickCount, MyGetTickCount);
        DetourAttach(&(PVOID&)TrueGetTickCount64, MyGetTickCount64);
        DetourAttach(&(PVOID&)TrueQueryPerformanceCounter, MyQueryPerformanceCounter);

        DetourAttach(&(PVOID&)TrueShellExecuteW, MyShellExecuteW);
        DetourAttach(&(PVOID&)TrueShellExecuteExA, MyShellExecuteExA);
        DetourAttach(&(PVOID&)TrueShellExecuteExW, MyShellExecuteExW);


        DetourAttach(&(PVOID&)TrueSleep, MySleep);
        DetourAttach(&(PVOID&)TrueSleepEx, MySleepEx);
        DetourAttach(&(PVOID&)TruelstrcmpiA, MylstrcmpiA);
        DetourAttach(&(PVOID&)TruelstrcmpiW, MylstrcmpiW);
        DetourAttach(&(PVOID&)TruelstrcmpW, MylstrcmpW);
        DetourAttach(&(PVOID&)TrueCompareStringEx, MyCompareStringEx);        
//        DetourAttach(&(PVOID&)TrueVirtualProtect, MyVirtualProtect);
//        DetourAttach(&(PVOID&)TrueWriteFile, MyWriteFile);
        DetourAttach(&(HANDLE&)TrueCreateFileW, MyCreateFileW);
        DetourAttach(&(HANDLE&)TrueCreateFileA, MyCreateFileA);
        DetourAttach(&(PVOID&)TrueGetFileSize, MyGetFileSize);
 //       DetourAttach(&(LPVOID&)TrueWriteFileEx, MyWriteFileEx);
        DetourAttach(&(PVOID&)TrueFlushFileBuffers, MyFlushFileBuffers);
        DetourAttach(&(PVOID&)TrueCloseHandle, MyCloseHandle);        
        DetourAttach(&(PVOID&)TrueCopyFileA, MyCopyFileA);
        DetourAttach(&(PVOID&)TrueCopyFileW, MyCopyFileW);
        DetourAttach(&(PVOID&)TrueCopyFileExA, MyCopyFileExA);
        DetourAttach(&(PVOID&)TrueCopyFileExW, MyCopyFileExW);
        DetourAttach(&(PVOID&)TrueDeleteFileA, MyDeleteFileA);
        DetourAttach(&(PVOID&)TrueDeleteFileW, MyDeleteFileW);
        DetourAttach(&(LPVOID&)TrueVirtualAlloc, MyVirtualAlloc);
        DetourAttach(&(LPVOID&)TrueVirtualAllocEx, MyVirtualAllocEx);
        DetourAttach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
        DetourAttach(&(PVOID&)TrueVirtualFree, MyVirtualFree);
        DetourAttach(&(PVOID&)TrueVirtualFreeEx, MyVirtualFreeEx);
        DetourAttach(&(PVOID&)TrueCoTaskMemAlloc, MyCoTaskMemAlloc);
        DetourAttach(&(PVOID&)TrueCoTaskMemFree, MyCoTaskMemFree);        
        DetourAttach(&(PVOID&)TrueWinExec, MyWinExec);
        DetourAttach(&(PVOID&)TrueRegGetValueA, MyRegGetValueA);
        DetourAttach(&(PVOID&)TrueRegGetValueW, MyRegGetValueW);
        DetourAttach(&(PVOID&)TrueRegQueryValueEx, MyRegQueryValueEx);
        DetourAttach(&(PVOID&)TrueRegSetValueA, MyRegSetValueA);
        DetourAttach(&(PVOID&)TrueRegSetValueEx, MyRegSetValueEx);
        DetourAttach(&(PVOID&)TrueRegSetValueExW, MyRegSetValueExW);  
        DetourAttach(&(PVOID&)TrueRegEnumKeyExA, MyRegEnumKeyExA);
        DetourAttach(&(PVOID&)TrueRegEnumKeyExW, MyRegEnumKeyExW);         
        DetourAttach(&(PVOID&)TrueRegOpenKeyEx, MyRegOpenKeyEx);
        DetourAttach(&(PVOID&)TrueRegCreateKeyEx, MyRegCreateKeyEx);
        DetourAttach(&(PVOID&)TrueAdjustTokenPrivileges, MyAdjustTokenPrivileges);
        DetourAttach(&(PVOID&)TrueAttachThreadInput, MyAttachThreadInput);
        DetourAttach(&(PVOID&)TrueBitBlt, MyBitBlt);
        DetourAttach(&(LPVOID&)TrueCertOpenSystemStore, MyCertOpenSystemStore);        
        DetourAttach(&(PVOID&)TrueControlService, MyControlService);
        DetourAttach(&(HANDLE&)TrueCreateMutex, MyCreateMutex);
        DetourAttach(&(HANDLE&)TrueCreateMutexEx, MyCreateMutexEx);
        DetourAttach(&(PVOID&)TrueCreateProcess, MyCreateProcess);
        DetourAttach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
        DetourAttach(&(PVOID&)TrueTerminateProcess, MyTerminateProcess);
        DetourAttach(&(HANDLE&)TrueCreateRemoteThread, MyCreateRemoteThread);
        DetourAttach(&(HANDLE&)TrueCreateRemoteThreadEx, MyCreateRemoteThreadEx);
        DetourAttach(&(HANDLE&)TrueCreateService, MyCreateService);       
        DetourAttach(&(HANDLE&)TrueCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot);
        DetourAttach(&(PVOID&)TrueCryptAcquireContextA, MyCryptAcquireContextA);
        DetourAttach(&(PVOID&)TrueCryptAcquireContextW, MyCryptAcquireContextW);
        DetourAttach(&(PVOID&)TrueDeviceIoControl, MyDeviceIoControl);
        DetourAttach(&(PVOID&)TrueEnumProcesses, MyEnumProcesses);
        DetourAttach(&(PVOID&)TrueEnumProcessModules, MyEnumProcessModules);
        DetourAttach(&(PVOID&)TrueEnumProcessModulesEx, MyEnumProcessModulesEx);
        DetourAttach(&(HANDLE&)TrueFindFirstFile, MyFindFirstFile);
        DetourAttach(&(HANDLE&)TrueFindFirstFileEx, MyFindFirstFileEx);
        DetourAttach(&(PVOID&)TrueFindNextFile, MyFindNextFile);
        DetourAttach(&(HANDLE&)TrueFindResourceA, MyFindResourceA);
        DetourAttach(&(HANDLE&)TrueFindResourceExA, MyFindResourceExA);
        DetourAttach(&(HANDLE&)TrueFindWindow, MyFindWindow);
        DetourAttach(&(HANDLE&)TrueFindWindowEx, MyFindWindowEx);
        DetourAttach(&(HANDLE&)TrueFtpOpenFileW, MyFtpOpenFileW);
        DetourAttach(&(PVOID&)TrueFtpPutFile, MyFtpPutFile);
        DetourAttach(&(PVOID&)TrueGetAdaptersInfo, MyGetAdaptersInfo);
        DetourAttach(&(PVOID&)TrueGetAsyncKeyState, MyGetAsyncKeyState);
        DetourAttach(&(PVOID&)TrueGetDC, MyGetDC);       
        DetourAttach(&(PVOID&)TrueGetForegroundWindow, MyGetForegroundWindow);
        DetourAttach(&(PVOID&)TrueGetWindowText, MyGetWindowText);
        DetourAttach(&(PVOID&)Truegethostbyname, Mygethostbyname);
        DetourAttach(&(PVOID&)Truegetaddrinfo, Mygetaddrinfo);
        DetourAttach(&(PVOID&)Truegethostname, Mygethostname);          
        DetourAttach(&(PVOID&)TrueGetModuleFileName, MyGetModuleFileName);
        DetourAttach(&(PVOID&)TrueGetModuleFileNameExA, MyGetModuleFileNameExA);
        DetourAttach(&(PVOID&)TrueGetModuleFileNameExW, MyGetModuleFileNameExW);
        DetourAttach(&(HANDLE&)TrueGetModuleHandle, MyGetModuleHandle);
        DetourAttach(&(PVOID&)TrueGetModuleHandleEx, MyGetModuleHandleEx);
        DetourAttach(&(PVOID&)TrueGetProcAddress, MyGetProcAddress);
        DetourAttach(&(PVOID&)TrueGetStartupInfoA, MyGetStartupInfoA);
        DetourAttach(&(PVOID&)TrueGetSystemDefaultLangID, MyGetSystemDefaultLangID);
        DetourAttach(&(PVOID&)TrueGetTempPathA, MyGetTempPathA);
        DetourAttach(&(PVOID&)TrueGetThreadContext, MyGetThreadContext);
        DetourAttach(&(PVOID&)TrueGetVersionEx, MyGetVersionEx);
        DetourAttach(&(PVOID&)TrueGetWindowsDirectory, MyGetWindowsDirectory);
        DetourAttach(&(PVOID&)Trueinet_addr, Myinet_addr);
        DetourAttach(&(HANDLE&)TrueInternetOpen, MyInternetOpen);
        DetourAttach(&(HANDLE&)TrueInternetOpenW, MyInternetOpenW);
        DetourAttach(&(HANDLE&)TrueInternetConnectW, MyInternetConnectW);
        DetourAttach(&(HANDLE&)TrueHttpOpenRequestW, MyHttpOpenRequestW);
        DetourAttach(&(HANDLE&)TrueHttpSendRequestW, MyHttpSendRequestW);
        DetourAttach(&(HANDLE&)TrueHttpSendRequestExW, MyHttpSendRequestExW);
        DetourAttach(&(HANDLE&)TrueInternetOpenUrl, MyInternetOpenUrl);
        DetourAttach(&(HANDLE&)TrueInternetOpenUrlA, MyInternetOpenUrlA);
        DetourAttach(&(PVOID&)TrueInternetReadFile, MyInternetReadFile);
        DetourAttach(&(PVOID&)TrueInternetWriteFile, MyInternetWriteFile);
        DetourAttach(&(PVOID&)TrueIsWow64Process, MyIsWow64Process);
        DetourAttach(&(PVOID&)TrueLdrLoadDll, MyLdrLoadDll);
        DetourAttach(&(HANDLE&)TrueLoadResource, MyLoadResource);
        DetourAttach(&(PVOID&)TrueRtlCreateRegistryKey, MyRtlCreateRegistryKey);
        DetourAttach(&(PVOID&)TrueRtlWriteRegistryValue, MyRtlWriteRegistryValue);
        DetourAttach(&(PVOID&)TrueLsaEnumerateLogonSessions, MyLsaEnumerateLogonSessions);
        DetourAttach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
        DetourAttach(&(PVOID&)TrueMapViewOfFileEx, MyMapViewOfFileEx);
        DetourAttach(&(PVOID&)TrueMapVirtualKeyA, MyMapVirtualKeyA);
        DetourAttach(&(PVOID&)TrueMapVirtualKeyExA, MyMapVirtualKeyExA);
        DetourAttach(&(PVOID&)TrueMapVirtualKeyW, MyMapVirtualKeyW);
        DetourAttach(&(PVOID&)TrueMapVirtualKeyExW, MyMapVirtualKeyExW);
        DetourAttach(&(PVOID&)TrueModule32First, MyModule32First);
        DetourAttach(&(PVOID&)TrueModule32Next, MyModule32Next);
        DetourAttach(&(HANDLE&)TrueOpenMutexA, MyOpenMutexA);
        DetourAttach(&(HANDLE&)TrueOpenProcess, MyOpenProcess);
        DetourAttach(&(PVOID&)TrueOutputDebugString, MyOutputDebugString);
        DetourAttach(&(PVOID&)TrueOutputDebugStringA, MyOutputDebugStringA);
        DetourAttach(&(PVOID&)TrueOutputDebugStringW, MyOutputDebugStringW);
        DetourAttach(&(PVOID&)TruePeekNamedPipe, MyPeekNamedPipe);
        DetourAttach(&(PVOID&)TrueProcess32First, MyProcess32First);
        DetourAttach(&(PVOID&)TrueProcess32FirstW, MyProcess32FirstW);
        DetourAttach(&(PVOID&)TrueProcess32Next, MyProcess32Next);
        DetourAttach(&(PVOID&)TrueProcess32NextW, MyProcess32NextW);
        DetourAttach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
        DetourAttach(&(PVOID&)TrueReadProcessMemory, MyReadProcessMemory);
        DetourAttach(&(PVOID&)TrueRegisterHotKey, MyRegisterHotKey);
        DetourAttach(&(PVOID&)TrueRegOpenKeyA, MyRegOpenKeyA);
        DetourAttach(&(PVOID&)TrueRegOpenKeyExA, MyRegOpenKeyExA);
        DetourAttach(&(PVOID&)TrueRegOpenKeyExW, MyRegOpenKeyExW);
        DetourAttach(&(PVOID&)TrueResumeThread, MyResumeThread);
        DetourAttach(&(PVOID&)TrueSetFileTime, MySetFileTime);
        DetourAttach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
        DetourAttach(&(PVOID&)TrueSetWindowsHookEx, MySetWindowsHookEx);
        DetourAttach(&(PVOID&)TrueSfcTerminateWatcherThread, MySfcTerminateWatcherThread);
        DetourAttach(&(PVOID&)TrueStartServiceCtrlDispatcherA, MyStartServiceCtrlDispatcherA);
        DetourAttach(&(PVOID&)TrueSuspendThread, MySuspendThread);
        DetourAttach(&(PVOID&)Truesystem, Mysystem);
        DetourAttach(&(PVOID&)True_wsystem, My_wsystem);
        DetourAttach(&(PVOID&)TrueThread32First, MyThread32First);
        DetourAttach(&(PVOID&)TrueThread32Next, MyThread32Next);
        DetourAttach(&(PVOID&)TrueToolhelp32ReadProcessMemory, MyToolhelp32ReadProcessMemory);
        DetourAttach(&(PVOID&)TrueURLDownloadToFile, MyURLDownloadToFile);
        DetourAttach(&(PVOID&)TrueURLDownloadToFileA, MyURLDownloadToFileA);
// Too much noise
//        DetourAttach(&(PVOID&)TrueGetKeyState, MyGetKeyState);  
//        DetourAttach(&(PVOID&)TrueWideCharToMultiByte, MyWideCharToMultiByte);
        DetourAttach(&(PVOID&)TrueWriteProcessMemory, MyWriteProcessMemory);
        DetourAttach(&(PVOID&)Trueaccept, Myaccept);
        DetourAttach(&(PVOID&)Truebind, Mybind);
        DetourAttach(&(PVOID&)Trueconnect, Myconnect);
        DetourAttach(&(PVOID&)TrueConnectNamedPipe, MyConnectNamedPipe);
        DetourAttach(&(PVOID&)Truerecv, Myrecv);
        DetourAttach(&(PVOID&)Truesend, Mysend);
        DetourAttach(&(PVOID&)TrueWSAStartup, MyWSAStartup);
//        DetourAttach(&(HANDLE&)TrueCreateFileMappingA, MyCreateFileMappingA);
        DetourAttach(&(HANDLE&)TrueLoadLibrary, MyLoadLibrary);
        DetourAttach(&(HANDLE&)TrueLoadLibraryExA, MyLoadLibraryExA);
        DetourAttach(&(HANDLE&)TrueGetConsoleWindow, MyGetConsoleWindow);
        DetourAttach(&(HANDLE&)TrueSetProcessDEPPolicy, MySetProcessDEPPolicy);
        DetourAttach(&(PVOID&)TrueIsUserAnAdmin, MyIsUserAnAdmin);
        DetourAttach(&(PVOID&)TrueWSASend, MyWSASend);
        DetourAttach(&(HANDLE&)TrueHeapCreate, MyHeapCreate);
//       DetourAttach(&(LPVOID&)TrueSamIConnect, MySamIConnect);
        
       DetourAttach(&(PVOID&)TrueIsNTAdmin, MyIsNTAdmin);


        MACTPrint(">All attached!\n");
        error = DetourTransactionCommit();
        MACTSTARTED = TRUE;

        MACTReceive("START");

    }
    else if (dwReason == DLL_PROCESS_DETACH) {
//        MACTSocketPrint();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueGetTickCount, MyGetTickCount);
        DetourDetach(&(PVOID&)TrueGetTickCount64, MyGetTickCount64);
        DetourDetach(&(PVOID&)TrueQueryPerformanceCounter, MyQueryPerformanceCounter);
        DetourDetach(&(PVOID&)TrueSleep, MySleep);
        DetourDetach(&(PVOID&)TrueSleepEx, MySleepEx);
        DetourDetach(&(PVOID&)TruelstrcmpiA, MylstrcmpiA);
        DetourDetach(&(PVOID&)TruelstrcmpiW, MylstrcmpiW);
        DetourDetach(&(PVOID&)TruelstrcmpW, MylstrcmpW);
        DetourDetach(&(PVOID&)TrueCompareStringEx, MyCompareStringEx);
        DetourDetach(&(HANDLE&)TrueCreateFileW, MyCreateFileW);
        DetourDetach(&(HANDLE&)TrueCreateFileA, MyCreateFileA);
        DetourDetach(&(PVOID&)TrueGetFileSize, MyGetFileSize);
        DetourDetach(&(PVOID&)TrueWriteFile, MyWriteFile);
        DetourDetach(&(PVOID&)TrueWriteFileEx, MyWriteFileEx);
        DetourDetach(&(PVOID&)TrueFlushFileBuffers, MyFlushFileBuffers);
        DetourDetach(&(PVOID&)TrueCloseHandle, MyCloseHandle);
        DetourDetach(&(PVOID&)TrueCopyFileA, MyCopyFileA);
        DetourDetach(&(PVOID&)TrueCopyFileW, MyCopyFileW);
        DetourDetach(&(PVOID&)TrueCopyFileExA, MyCopyFileExA);
        DetourDetach(&(PVOID&)TrueCopyFileExW, MyCopyFileExW);
        DetourDetach(&(PVOID&)TrueDeleteFileA, MyDeleteFileA);
        DetourDetach(&(PVOID&)TrueDeleteFileW, MyDeleteFileW);
        DetourDetach(&(LPVOID&)TrueVirtualAlloc, MyVirtualAlloc);
        DetourDetach(&(LPVOID&)TrueVirtualAllocEx, MyVirtualAllocEx);
        DetourDetach(&(PVOID&)TrueVirtualProtect, MyVirtualProtect);
        DetourDetach(&(PVOID&)TrueVirtualProtectEx, MyVirtualProtectEx);
        DetourDetach(&(PVOID&)TrueVirtualFree, MyVirtualFree);
        DetourDetach(&(PVOID&)TrueVirtualFreeEx, MyVirtualFreeEx);
        DetourDetach(&(PVOID&)TrueWinExec, MyWinExec);
        DetourDetach(&(PVOID&)TrueShellExecuteW, MyShellExecuteW);
        DetourDetach(&(PVOID&)TrueShellExecuteExA, MyShellExecuteExA);
        DetourDetach(&(PVOID&)TrueShellExecuteExW, MyShellExecuteExW);
        DetourDetach(&(PVOID&)TrueRegGetValueA, MyRegGetValueA);
        DetourDetach(&(PVOID&)TrueRegGetValueW, MyRegGetValueW);
        DetourDetach(&(PVOID&)TrueRegQueryValueEx, MyRegQueryValueEx);
        DetourDetach(&(PVOID&)TrueRegSetValueA, MyRegSetValueA);
        DetourDetach(&(PVOID&)TrueRegSetValueEx, MyRegSetValueEx);
        DetourDetach(&(PVOID&)TrueRegSetValueExW, MyRegSetValueExW);  
        DetourDetach(&(PVOID&)TrueRegEnumKeyExA, MyRegEnumKeyExA);
        DetourDetach(&(PVOID&)TrueRegEnumKeyExW, MyRegEnumKeyExW);
        DetourDetach(&(PVOID&)TrueRegOpenKeyEx, MyRegOpenKeyEx);
        DetourDetach(&(PVOID&)TrueRegCreateKeyEx, MyRegCreateKeyEx);
        DetourDetach(&(PVOID&)TrueAdjustTokenPrivileges, MyAdjustTokenPrivileges);
        DetourDetach(&(PVOID&)TrueAttachThreadInput, MyAttachThreadInput);
        DetourDetach(&(PVOID&)TrueBitBlt, MyBitBlt);
        DetourDetach(&(LPVOID&)TrueCertOpenSystemStore, MyCertOpenSystemStore);
        DetourDetach(&(PVOID&)TrueControlService, MyControlService);
        DetourDetach(&(HANDLE&)TrueCreateMutex, MyCreateMutex);
        DetourDetach(&(HANDLE&)TrueCreateMutexEx, MyCreateMutexEx);
        DetourDetach(&(PVOID&)TrueCreateProcess, MyCreateProcess);
        DetourDetach(&(PVOID&)TrueCreateProcessW, MyCreateProcessW);
        DetourDetach(&(PVOID&)TrueTerminateProcess, MyTerminateProcess);
        DetourDetach(&(HANDLE&)TrueCreateRemoteThread, MyCreateRemoteThread);
        DetourDetach(&(HANDLE&)TrueCreateRemoteThreadEx, MyCreateRemoteThreadEx);
        DetourDetach(&(HANDLE&)TrueCreateService, MyCreateService);
        DetourDetach(&(HANDLE&)TrueCreateToolhelp32Snapshot, MyCreateToolhelp32Snapshot);
        DetourDetach(&(PVOID&)TrueCryptAcquireContextA, MyCryptAcquireContextA);
        DetourDetach(&(PVOID&)TrueCryptAcquireContextW, MyCryptAcquireContextW);;
        DetourDetach(&(PVOID&)TrueDeviceIoControl, MyDeviceIoControl);
        DetourDetach(&(PVOID&)TrueEnumProcesses, MyEnumProcesses);
        DetourDetach(&(PVOID&)TrueEnumProcessModules, MyEnumProcessModules);
        DetourDetach(&(PVOID&)TrueEnumProcessModulesEx, MyEnumProcessModulesEx);
        DetourDetach(&(HANDLE&)TrueFindFirstFile, MyFindFirstFile);
        DetourDetach(&(HANDLE&)TrueFindFirstFileEx, MyFindFirstFileEx);
        DetourDetach(&(PVOID&)TrueFindNextFile, MyFindNextFile);
        DetourDetach(&(HANDLE&)TrueFindResourceA, MyFindResourceA);
        DetourDetach(&(HANDLE&)TrueFindResourceExA, MyFindResourceExA);
        DetourDetach(&(HANDLE&)TrueFindWindow, MyFindWindow);
        DetourDetach(&(HANDLE&)TrueFindWindowEx, MyFindWindowEx);
        DetourDetach(&(HANDLE&)TrueFtpOpenFileW, MyFtpOpenFileW);
        DetourDetach(&(PVOID&)TrueFtpPutFile, MyFtpPutFile);
        DetourDetach(&(PVOID&)TrueGetAdaptersInfo, MyGetAdaptersInfo);
        DetourDetach(&(PVOID&)TrueGetAsyncKeyState, MyGetAsyncKeyState);
        DetourDetach(&(PVOID&)TrueGetDC, MyGetDC);
        DetourDetach(&(PVOID&)TrueGetForegroundWindow, MyGetForegroundWindow);
        DetourDetach(&(PVOID&)TrueGetWindowText, MyGetWindowText);
        DetourDetach(&(PVOID&)Truegethostbyname, Mygethostbyname);
        DetourDetach(&(PVOID&)Truegetaddrinfo, Mygetaddrinfo);
        DetourDetach(&(PVOID&)Truegethostname, Mygethostname);
        DetourDetach(&(PVOID&)TrueGetKeyState, MyGetKeyState);
        DetourDetach(&(PVOID&)TrueGetModuleFileName, MyGetModuleFileName);
        DetourDetach(&(PVOID&)TrueGetModuleFileNameExA, MyGetModuleFileNameExA);
        DetourDetach(&(PVOID&)TrueGetModuleFileNameExW, MyGetModuleFileNameExW);
        DetourDetach(&(PVOID&)TrueGetModuleHandle, MyGetModuleHandle);
        DetourDetach(&(PVOID&)TrueGetModuleHandleEx, MyGetModuleHandleEx);
        DetourDetach(&(PVOID&)TrueGetProcAddress, MyGetProcAddress);
        DetourDetach(&(PVOID&)TrueGetStartupInfoA, MyGetStartupInfoA);
        DetourDetach(&(PVOID&)TrueGetSystemDefaultLangID, MyGetSystemDefaultLangID);
        DetourDetach(&(PVOID&)TrueGetTempPathA, MyGetTempPathA);
        DetourDetach(&(PVOID&)TrueGetThreadContext, MyGetThreadContext);
        DetourDetach(&(PVOID&)TrueGetVersionEx, MyGetVersionEx);
        DetourDetach(&(PVOID&)TrueGetWindowsDirectory, MyGetWindowsDirectory);
        DetourDetach(&(PVOID&)Trueinet_addr, Myinet_addr);
        DetourDetach(&(HANDLE&)TrueInternetOpen, MyInternetOpen);
        DetourDetach(&(HANDLE&)TrueInternetOpenW, MyInternetOpenW);
        DetourDetach(&(HANDLE&)TrueInternetConnectW, MyInternetConnectW);
        DetourDetach(&(HANDLE&)TrueHttpOpenRequestW, MyHttpOpenRequestW);
        DetourDetach(&(HANDLE&)TrueHttpSendRequestW, MyHttpSendRequestW);
        DetourDetach(&(HANDLE&)TrueHttpSendRequestExW, MyHttpSendRequestExW);
        DetourDetach(&(HANDLE&)TrueInternetOpenUrlA, MyInternetOpenUrlA);
        DetourDetach(&(HANDLE&)TrueInternetOpenUrl, MyInternetOpenUrl);
        DetourDetach(&(PVOID&)TrueInternetReadFile, MyInternetReadFile);
        DetourDetach(&(PVOID&)TrueInternetWriteFile, MyInternetWriteFile);
        DetourDetach(&(PVOID&)TrueIsWow64Process, MyIsWow64Process);
        DetourDetach(&(PVOID&)TrueLdrLoadDll, MyLdrLoadDll);
        DetourDetach(&(PVOID&)TrueRtlCreateRegistryKey, MyRtlCreateRegistryKey);
        DetourDetach(&(PVOID&)TrueRtlWriteRegistryValue, MyRtlWriteRegistryValue);
        DetourDetach(&(HANDLE&)LoadResource, LoadResource);
        DetourDetach(&(PVOID&)TrueLsaEnumerateLogonSessions, MyLsaEnumerateLogonSessions);
        DetourDetach(&(PVOID&)TrueMapViewOfFile, MyMapViewOfFile);
        DetourDetach(&(PVOID&)TrueMapVirtualKeyA, MyMapVirtualKeyA);
        DetourDetach(&(PVOID&)TrueMapVirtualKeyExA, MyMapVirtualKeyExA);
        DetourDetach(&(PVOID&)TrueMapVirtualKeyW, MyMapVirtualKeyW);
        DetourDetach(&(PVOID&)TrueMapVirtualKeyExW, MyMapVirtualKeyExW);
        DetourDetach(&(PVOID&)TrueModule32First, MyModule32First);
        DetourDetach(&(PVOID&)TrueModule32Next, MyModule32Next);
        DetourDetach(&(HANDLE&)TrueOpenMutexA, MyOpenMutexA);
        DetourDetach(&(HANDLE&)TrueOpenProcess, MyOpenProcess);
        DetourDetach(&(PVOID&)TrueOutputDebugString, MyOutputDebugString);
        DetourDetach(&(PVOID&)TrueOutputDebugStringA, MyOutputDebugStringA);
        DetourDetach(&(PVOID&)TrueOutputDebugStringW, MyOutputDebugStringW);
        DetourDetach(&(PVOID&)TruePeekNamedPipe, MyPeekNamedPipe);
        DetourDetach(&(PVOID&)TrueProcess32First, MyProcess32First);
        DetourDetach(&(PVOID&)TrueProcess32FirstW, MyProcess32FirstW);
        DetourDetach(&(PVOID&)TrueProcess32Next, MyProcess32Next);
        DetourDetach(&(PVOID&)TrueProcess32NextW, MyProcess32NextW);
        DetourDetach(&(PVOID&)TrueQueueUserAPC, MyQueueUserAPC);
        DetourDetach(&(PVOID&)TrueReadProcessMemory, MyReadProcessMemory);
        DetourDetach(&(PVOID&)TrueRegisterHotKey, MyRegisterHotKey);
        DetourDetach(&(PVOID&)TrueRegOpenKeyA, MyRegOpenKeyA);
        DetourDetach(&(PVOID&)TrueRegOpenKeyExA, MyRegOpenKeyExA);
        DetourDetach(&(PVOID&)TrueRegOpenKeyExW, MyRegOpenKeyExW);
        DetourDetach(&(PVOID&)TrueResumeThread, MyResumeThread);
//        DetourDetach(&(PVOID&)TrueSamIConnect, MySamIConnect);
        DetourDetach(&(PVOID&)TrueSetFileTime, MySetFileTime);
        DetourDetach(&(PVOID&)TrueSetThreadContext, MySetThreadContext);
        DetourDetach(&(PVOID&)TrueSetWindowsHookEx, MySetWindowsHookEx);
        DetourDetach(&(PVOID&)TrueSfcTerminateWatcherThread, MySfcTerminateWatcherThread);
        DetourDetach(&(PVOID&)TrueStartServiceCtrlDispatcherA, MyStartServiceCtrlDispatcherA);
        DetourDetach(&(PVOID&)TrueSuspendThread, MySuspendThread);
        DetourDetach(&(PVOID&)True_wsystem, My_wsystem);
        DetourDetach(&(PVOID&)TrueThread32First, MyThread32First);
        DetourDetach(&(PVOID&)TrueThread32Next, MyThread32Next);
        DetourDetach(&(PVOID&)TrueToolhelp32ReadProcessMemory, MyToolhelp32ReadProcessMemory);
        DetourDetach(&(PVOID&)TrueURLDownloadToFile, MyURLDownloadToFile);
        DetourDetach(&(PVOID&)TrueURLDownloadToFileA, MyURLDownloadToFileA);
        DetourDetach(&(PVOID&)TrueWideCharToMultiByte, MyWideCharToMultiByte);
        DetourDetach(&(PVOID&)TrueWriteProcessMemory, MyWriteProcessMemory);
        DetourDetach(&(PVOID&)Trueaccept, Myaccept);
        DetourDetach(&(PVOID&)Truebind, Mybind);
        DetourDetach(&(PVOID&)Trueconnect, Myconnect);
        DetourDetach(&(PVOID&)TrueConnectNamedPipe, MyConnectNamedPipe);
        DetourDetach(&(PVOID&)Truerecv, Myrecv);
        DetourDetach(&(PVOID&)Truesend, Mysend);
        DetourDetach(&(PVOID&)TrueWSAStartup, MyWSAStartup);
        DetourDetach(&(HANDLE&)TrueCreateFileMappingA, MyCreateFileMappingA);
        DetourDetach(&(PVOID&)TrueIsNTAdmin, MyIsNTAdmin);
        DetourDetach(&(PVOID&)TrueIsUserAnAdmin, MyIsUserAnAdmin);
        DetourDetach(&(HANDLE&)TrueLoadLibrary, MyLoadLibrary);
        DetourDetach(&(HANDLE&)TrueLoadLibraryExA, MyLoadLibraryExA);
        DetourDetach(&(HANDLE&)TrueGetConsoleWindow, MyGetConsoleWindow);
        DetourDetach(&(HANDLE&)TrueSetProcessDEPPolicy, MySetProcessDEPPolicy);
        DetourDetach(&(PVOID&)TrueWSASend, MyWSASend);
        DetourDetach(&(HANDLE&)TrueHeapCreate, MyHeapCreate);
        DetourDetach(&(PVOID&)TrueCoTaskMemAlloc, MyCoTaskMemAlloc);
        DetourDetach(&(PVOID&)TrueCoTaskMemFree, MyCoTaskMemFree);

        printf("All detached!\n");
        error = DetourTransactionCommit();
        fflush(stdout);
        printf("Flushed.\n");

    }
    return TRUE;
}
