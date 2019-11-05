#include <Windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define CALLBACKOBJ_SERVICE_NAMEW       L"ExCallbackObjectsSvc"
#define CALLBACKOBJ_SERVICE_INSTALL     0
#define CALLBACKOBJ_SERVICE_UNINSTALL   1


typedef struct _EX_CALLBACK_OBJ_TUPLE {
    PCWSTR  DriverName;
    DWORD   StartType;
} EX_CALLBACK_OBJ_TUPLE;

EX_CALLBACK_OBJ_TUPLE g_ExCallbackObjectDrivers[] = {
    { L"WdProcessNotificationCallback.sys", SERVICE_DEMAND_START },
    { L"Phase1InitComplete.sys", SERVICE_BOOT_START },
    { L"EnlightenmentState.sys", SERVICE_BOOT_START },
    { L"TcpConnectionCallbackTemp.sys", SERVICE_DEMAND_START }
};
DWORD g_NumCallbackObjectDrivers = sizeof(g_ExCallbackObjectDrivers) / sizeof(g_ExCallbackObjectDrivers[0]);

_Success_(return == TRUE)
BOOLEAN
InstallDriver(
    _In_    SC_HANDLE   hSCManager,
    _In_    LPCTSTR     ServiceName,
    _In_    LPCTSTR     DriverPath,
    _In_    DWORD       StartType
)
{
    SC_HANDLE   schService;
    DWORD       errCode;

    schService = CreateService(hSCManager,
                               ServiceName,
                               ServiceName,
                               SERVICE_ALL_ACCESS,
                               SERVICE_KERNEL_DRIVER,
                               StartType,
                               SERVICE_ERROR_NORMAL,
                               DriverPath,
                               NULL,
                               NULL,
                               NULL,
                               NULL,
                               NULL);
    if (NULL == schService) {
        errCode = GetLastError();

        if (ERROR_SERVICE_EXISTS == errCode) {
            fprintf(stderr, __FUNCTION__ " Service already exists\n");

            return TRUE;
        } else {
            fprintf(stderr, __FUNCTION__ " Failed creating service: %#x\n", errCode);

            return FALSE;
        }
    } else {
        CloseServiceHandle(schService);

        fprintf(stdout, __FUNCTION__ " Service %S was successfully created\n", ServiceName);

        return TRUE;
    }
}

_Success_(return == TRUE)
BOOLEAN
UninstallDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE   schService;
    BOOLEAN     bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, __FUNCTION__ " Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (DeleteService(schService)) {
        bRetStatus = TRUE;

        fprintf(stdout, __FUNCTION__ " Service %S was successfully deleted\n", ServiceName);
    } else {
        fprintf(stderr, __FUNCTION__ " Failed deleting the service: %#X\n", GetLastError());
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
StartDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE   schService;
    DWORD       errCode;
    BOOLEAN     bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, __FUNCTION__ " Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (!StartService(schService,
                      0,
                      NULL)) {
        errCode = GetLastError();

        if (ERROR_SERVICE_ALREADY_RUNNING == errCode) {
            bRetStatus = TRUE;

            fprintf(stdout, __FUNCTION__ " Service %S already running\n", ServiceName);
        } else {
            fprintf(stderr, __FUNCTION__ " Failed starting the service: %#X\n", errCode);
        }
    } else {
        bRetStatus = TRUE;

        fprintf(stdout, __FUNCTION__ " Service %S was successfully started\n", ServiceName);
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
StopDriver(
    _In_	SC_HANDLE	hSCManager,
    _In_	LPCTSTR		ServiceName
)
{
    SC_HANDLE       schService;
    SERVICE_STATUS  serviceStatus;
    BOOLEAN         bRetStatus = FALSE;

    schService = OpenService(hSCManager,
                             ServiceName,
                             SERVICE_ALL_ACCESS);
    if (NULL == schService) {
        fprintf(stderr, __FUNCTION__ " Failed opening the service: %#X\n", GetLastError());

        return bRetStatus;
    }

    if (ControlService(schService,
                       SERVICE_CONTROL_STOP,
                       &serviceStatus)) {
        bRetStatus = TRUE;

        fprintf(stdout, __FUNCTION__ " Service %S was successfully stopped\n", ServiceName);
    } else {
        fprintf(stderr, __FUNCTION__ " Failed stopping the service: %#X\n", GetLastError());
    }

    CloseServiceHandle(schService);

    return bRetStatus;
}

_Success_(return == TRUE)
BOOLEAN
ManageDriver(
    _In_    LPCTSTR DriverPath,
    _In_    LPCTSTR ServiceName,
    _In_    SIZE_T  Action,
    _In_    DWORD   StartType
)
{
    SC_HANDLE	schSCManager;
    BOOLEAN		bRetVal = TRUE;

    if (NULL == DriverPath || NULL == ServiceName) {
        fprintf(stderr, __FUNCTION__ " Invalid driver name or service name\n");

        return FALSE;
    }

    schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schSCManager) {
        fprintf(stderr, __FUNCTION__ " Failed opening a connection to SCM: %#X\n", GetLastError());

        return FALSE;
    }

    switch (Action) {
    case CALLBACKOBJ_SERVICE_INSTALL:
        if (InstallDriver(schSCManager, ServiceName, DriverPath, StartType)) {
            if (StartType == SERVICE_DEMAND_START) {
                bRetVal = StartDriver(schSCManager, ServiceName);
            } else {
                fprintf(stderr, __FUNCTION__ " StartType isn't DEMAND_START, the service isn't started\n");

                bRetVal = TRUE;
            }
        } else {
            bRetVal = FALSE;
        }

        break;
    case CALLBACKOBJ_SERVICE_UNINSTALL:
        if (StopDriver(schSCManager, ServiceName)) {
            bRetVal = UninstallDriver(schSCManager, ServiceName);
        } else {
            bRetVal = FALSE;
        }

        break;
    default:
        fprintf(stderr, __FUNCTION__ " Unknown action: %zu\n", Action);

        bRetVal = FALSE;

        break;
    }

    if (CloseServiceHandle(schSCManager) == 0) {
        fprintf(stderr, __FUNCTION__ " Failed closing SCM: %#X\n", GetLastError());
    }

    return bRetVal;
}

DWORD chk_strtoul(PCSTR pStr, PBOOL bFail) {
    PCHAR pEndPtr;
    DWORD dwNum;

    *bFail = strchr(pStr, '-') != NULL;
    
    errno = 0;
    dwNum = strtoul(pStr, &pEndPtr, 10);
    if (errno || pEndPtr == pStr || *pEndPtr) {
        *bFail = 1;
    }

    return dwNum;
}

int __cdecl main(int argc, char* argv[])
{
    DWORD   retCode = EXIT_SUCCESS;
    DWORD   dwBufferLength = 0;
    DWORD   dwCallbackId = 0;
    BOOL    bFail = FALSE;
    LPWSTR  lpBuffer = NULL;
    LPCWSTR lpDriverName = NULL;

    if (argc > 2) {
        dwCallbackId = chk_strtoul(argv[2], &bFail);
        if (bFail) {
            fwprintf(stderr, L"Failed to parse callback id\n");

            return EXIT_FAILURE;;
        }
        if (dwCallbackId >= g_NumCallbackObjectDrivers) {
            fwprintf(stderr, L"Maximum id number is %lu\n", g_NumCallbackObjectDrivers - 1);

            retCode = EXIT_FAILURE;

            goto usage;
        }

        fprintf(stdout, "Selected callback object: %ls\n", g_ExCallbackObjectDrivers[dwCallbackId].DriverName);

        if (_strnicmp(argv[1], "load", strlen("load")) == 0) {
            lpDriverName = g_ExCallbackObjectDrivers[dwCallbackId].DriverName;

            if (g_ExCallbackObjectDrivers[dwCallbackId].StartType == SERVICE_BOOT_START) {
                // FIXME: User env variable expansion or read system drive letter instead of hardcoding.
                LPCWSTR lpSystem32W = L"C:\\Windows\\System32\\";
                lpBuffer = calloc(wcslen(lpSystem32W) + wcslen(lpDriverName) + 1, sizeof(WCHAR));
                if (NULL == lpBuffer) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed allocating a buffer for System32: %08X\n", retCode);

                    goto free_buff;
                }
                if (wcsncpy_s(lpBuffer,
                              wcslen(lpSystem32W) + wcslen(lpDriverName) + 1,
                              lpSystem32W,
                              wcslen(lpSystem32W)) != 0) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"wcsncpy_s failed: %08X\n", retCode);

                    free(lpBuffer);
                    lpBuffer = NULL;

                    goto free_buff;
                }
                if (wcsncat_s(lpBuffer,
                              wcslen(lpSystem32W) + wcslen(lpDriverName) + 1,
                              lpDriverName,
                              wcslen(lpDriverName)) != 0) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"wcsncat_s failed: %08X\n", retCode);

                    free(lpBuffer);
                    lpBuffer = NULL;

                    goto free_buff;
                }

                if (!CopyFile(lpDriverName, lpBuffer, TRUE)) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"CopyFile failed: %08X\n", retCode);
                } else {
                    fwprintf(stdout, L"%lS was successfully copied\n", lpBuffer);
                }
            } else if (g_ExCallbackObjectDrivers[dwCallbackId].StartType == SERVICE_DEMAND_START) {
                dwBufferLength = GetCurrentDirectory(dwBufferLength, lpBuffer);
                if (!dwBufferLength) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"Failed to query current directory length: %08X\n", retCode);

                    return retCode;
                } else {
                    lpBuffer = calloc(dwBufferLength + wcslen(lpDriverName) + 2, sizeof(WCHAR)); // + 2: 1 for \ and 1 for NULL
                    if (NULL == lpBuffer) {
                        retCode = GetLastError();
                        fwprintf(stderr, L"Failed allocating a buffer for current directory: %08X\n", retCode);

                        return retCode;
                    }

                    if (!GetCurrentDirectory(dwBufferLength, lpBuffer)) {
                        retCode = GetLastError();
                        fwprintf(stderr, L"Failed to query current directory length: %08X\n", retCode);

                        goto free_buff;
                    }
                }

                if (wcsncat_s(lpBuffer,
                              dwBufferLength + wcslen(lpDriverName) + 1,
                              L"\\",
                              wcslen(L"\\")) != 0) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"wcsncat_s failed: %08X\n", retCode);

                    goto free_buff;
                }
                if (wcsncat_s(lpBuffer,
                              dwBufferLength + wcslen(lpDriverName) + 1,
                              lpDriverName,
                              wcslen(lpDriverName)) != 0) {
                    retCode = GetLastError();
                    fwprintf(stderr, L"wcsncat_s failed: %08X\n", retCode);

                    goto free_buff;
                }
            } else {
                fwprintf(stderr, L"Unknown service start option: %08X\n", g_ExCallbackObjectDrivers[dwCallbackId].StartType);

                return EXIT_FAILURE;
            }

            fwprintf(stdout, L"Absolute path of the driver to load: %lS\n", lpBuffer);

            ManageDriver(lpBuffer, CALLBACKOBJ_SERVICE_NAMEW, CALLBACKOBJ_SERVICE_INSTALL, g_ExCallbackObjectDrivers[dwCallbackId].StartType);

        free_buff:
            free(lpBuffer);
            lpBuffer = NULL;
        } else {
            goto usage;
        }
    } else if (argc > 1) {
        if (_strnicmp(argv[1], "unload", strlen("unload")) == 0) {
            ManageDriver(L"", CALLBACKOBJ_SERVICE_NAMEW, CALLBACKOBJ_SERVICE_UNINSTALL, ULONG_MAX);
        } else {
            goto usage;
        }
    } else {
usage:
        fwprintf(stdout, L"[*] Usage: %hs [ load <callback_id> | unload ]\n", argv[0]);
        fwprintf(stdout, L"[*] Available callback object drivers:\n");
        for (size_t i = 0; i < g_NumCallbackObjectDrivers; i++) {
            fwprintf(stdout, L"[+] %zu: %ls\n", i, g_ExCallbackObjectDrivers[i].DriverName);
        }
    }

    return retCode;
}