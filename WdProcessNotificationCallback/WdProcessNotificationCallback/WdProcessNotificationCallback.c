#include <fltKernel.h>

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

PVOID g_WdRegisteredCallback;

#pragma warning(disable:4214 4201)
typedef struct _PS_PROTECTION {
    union {
        UCHAR Level;
        struct {
            UCHAR Type : 3;
            UCHAR Audit : 1;                  // Reserved
            UCHAR Signer : 4;
        };
    };
} PS_PROTECTION, *PPS_PROTECTION;

//
// 1 Creation of a process, 2 process deleted, 3 set trusted/untrusted process
//
typedef enum _WD_PROC_CB_TYPE { WD_PROC_CREATE = 1, WD_PROC_TERMINATE, WD_PROC_SET_TRUSTED_UNTRUSTED_REFRESH } WD_PROC_CB_TYPE;

//
// Magic values for each structure, to help keeping track when they change
//
typedef enum _MP_MAGICS { MP_MAGIC_PROC_CTX = 0xC0DA0F, MP_MAGIC_DOC_RULE = 0x228DA15 } MP_MAGICS;

//
// Expected size of each structure
//
typedef enum _MP_STRUCT_SIZE { MP_STSZ_PROC_CTX = 0xC0, MP_STSZ_DOC_RULE = 0x228 } MP_STRUCT_SIZE;


typedef struct _MP_DOC_OPEN_RULE
{
    DWORD32       Magic; // 0x228DA15
    INT32         Addend;
    PLIST_ENTRY   ListEntryHead;
    WCHAR         pBuffer[261];
    PVOID         PagedPoolBuffer;
} MP_DOC_OPEN_RULE, *PMP_DOC_OPEN_RULE;

typedef struct _MP_PROCESS_CONTEXT
{
    DWORD64                           Magic; // 0xC0DA0F; previous version of WdFilter used 0xC8DA0F
    LIST_ENTRY                        ListEntry;
    HANDLE                            Pid;
    LONGLONG                          ProcessCreationTime;
    PUNICODE_STRING                   ProcessCommandLine;
    INT32                             Addend;
    DWORD32                           ProcessFlags;
    DWORD32                           Reserved1;
    DWORD32                           Reserved2;
    INT64                             Reserved3;
    INT64                             Reserved4;
    PMP_DOC_OPEN_RULE                 MpDocOpenRule;
    PFLT_COMPLETED_ASYNC_IO_CALLBACK  PfltCompletedAsyncIoCallback;
    INT32                             Addend2;
    INT32                             Addend3;
    INT64                             Addend4;
    INT64                             Reserved5;
    SUBSYSTEM_INFORMATION_TYPE        ProcessSubsystemInfo;
    PUNICODE_STRING                   ProcessName;
    UCHAR                             Reserved6[48];
    PS_PROTECTION                     ProcessProtectionInfo;
    INT32                             Reserved9; // initialized to 0
    // PFLT_FILE_NAME_INFORMATION        FileNameInformation; // was available in a previous version of the structure
} MP_PROCESS_CONTEXT, *PMP_PROCESS_CONTEXT;

typedef struct _WD_PS_NOTIFY_INFO
{
    HANDLE            Pid;
    PHANDLE           pPPid;
    PUNICODE_STRING   ImageFileName;
    DWORD32           OperationType;
    BOOLEAN           IsTrustedProcess;
} WD_PS_NOTIFY_INFO, *PWD_PS_NOTIFY_INFO;

typedef struct _WD_PS_NOTIFY_INFO_EX
{
    PMP_PROCESS_CONTEXT pMpProcessContext;
    HANDLE              PPid;
    WD_PS_NOTIFY_INFO   WdPsNotifyInfo;
} WD_PS_NOTIFY_INFO_EX, *PWD_PS_NOTIFY_INFO_EX;

CALLBACK_FUNCTION WdProcCallback;

static_assert(sizeof(WD_PS_NOTIFY_INFO) == 0x20, "Incorrect WD_PS_NOTIFY_INFO structure size");
static_assert(sizeof(WD_PS_NOTIFY_INFO_EX) == 0x30, "Incorrect WD_PS_NOTIFY_INFO_EX structure size");
static_assert(sizeof(MP_PROCESS_CONTEXT) == MP_STSZ_PROC_CTX, "Incorrect MP_PROCESS_CONTEXT structure size");
static_assert(sizeof(MP_DOC_OPEN_RULE) == MP_STSZ_DOC_RULE, "Incorrect MP_DOC_OPEN_RULE structure size");

VOID
WdProcCallback(
    _In_opt_    PVOID   CallbackContext,
    _In_opt_    PVOID   Argument1,
    _In_opt_    PVOID   Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument2);

    if (NULL == Argument1) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": Argument1 NULL !?");

        return;
    }

    PWD_PS_NOTIFY_INFO pWdProcNotifInfo = (PWD_PS_NOTIFY_INFO)Argument1;
    switch (pWdProcNotifInfo->OperationType)
    {
    case WD_PROC_CREATE:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": [+] New process with PID: %08x ImageFileName: %wZ\n",
                   HandleToULong(pWdProcNotifInfo->Pid),
                   pWdProcNotifInfo->ImageFileName
        );

        if (pWdProcNotifInfo->pPPid != NULL) {
            PWD_PS_NOTIFY_INFO_EX pWdProcNotifInfoEx = CONTAINING_RECORD(pWdProcNotifInfo->pPPid, WD_PS_NOTIFY_INFO_EX, PPid);
            if (NULL == pWdProcNotifInfoEx) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_ERROR_LEVEL,
                           __FUNCTION__ ": [!] Extended info isn't available!\n"
                );

                return;
            }
            if (pWdProcNotifInfoEx->pMpProcessContext->Magic != MP_MAGIC_PROC_CTX) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_ERROR_LEVEL,
                           __FUNCTION__ ": [!] MP_PROC_CONTEXT.Magic isn't matching: %08llX\n",
                           pWdProcNotifInfoEx->pMpProcessContext->Magic
                );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [+] ProcessCreationTime: %lld ProcessCmdLine: %wZ PPID: %08x\n",
                           pWdProcNotifInfoEx->pMpProcessContext->ProcessCreationTime,
                           pWdProcNotifInfoEx->pMpProcessContext->ProcessCommandLine,
                           HandleToULong(pWdProcNotifInfoEx->PPid)
                );

                if (pWdProcNotifInfoEx->pMpProcessContext->MpDocOpenRule != NULL) {
                    if (pWdProcNotifInfoEx->pMpProcessContext->MpDocOpenRule->Magic != MP_MAGIC_DOC_RULE) {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                                   DPFLTR_ERROR_LEVEL,
                                   __FUNCTION__ ": [!] MP_DOC_OPEN_RULE.Magic isn't matching: %04X\n",
                                   pWdProcNotifInfoEx->pMpProcessContext->MpDocOpenRule->Magic
                        );
                    } else {
                        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                                   DPFLTR_INFO_LEVEL,
                                   __FUNCTION__ ": [+] Doc Rule buffer: %lS\n",
                                   pWdProcNotifInfoEx->pMpProcessContext->MpDocOpenRule->pBuffer
                        );
                    }
                }
            }
            //
            // An earlier version of WdFilter(on Windows 10 Insiders Preview 19008) MP_PROCESS_CONTEXT had a PFLT_FILE_NAME_INFORMATION
            // pointer as its last field, so the size of the structure was 0xC8DA0F. Later that field was removed and the size of the
            // structure became 0xC0DA0F. Leaving this piece of code as a reference or maybe they'll rethink and add it back ;)
            //
#if 0
            if ((pWdProcNotifInfoEx->pMpProcessContext->Magic == 0xC8DA0F) && 
                (pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation != NULL)) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           "File name: %wZ",
                           &pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->Name
                );

                if ((pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->NamesParsed & FLTFL_FILE_NAME_PARSED_EXTENSION) &&
                    (pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->Extension.Length != 0)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                               DPFLTR_INFO_LEVEL,
                               "File extension: %wZ",
                               pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->Extension
                    );
                }
                if ((pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->NamesParsed & FLTFL_FILE_NAME_PARSED_PARENT_DIR) &&
                    (pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->ParentDir.Length != 0)) {
                    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                               DPFLTR_INFO_LEVEL,
                               "File parent dir: %wZ",
                               &pWdProcNotifInfoEx->pMpProcessContext->FileNameInformation->ParentDir
                    );
                }
            }
#endif
        }

        break;

    case WD_PROC_TERMINATE:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": [-] Process terminated PID %08x\n", HandleToULong(pWdProcNotifInfo->Pid));

        break;
    case WD_PROC_SET_TRUSTED_UNTRUSTED_REFRESH:
        if (pWdProcNotifInfo->IsTrustedProcess) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": [*] Set trusted process PID %08x\n", HandleToULong(pWdProcNotifInfo->Pid));
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": [*] Set untrusted process PID %08x\n", HandleToULong(pWdProcNotifInfo->Pid));
        }

        break;
    default:
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": [!] Why are you not treating me equally: %08x!?\n", pWdProcNotifInfo->OperationType);
        break;
    }
}

VOID DriverUnload(
    _In_    PDRIVER_OBJECT  DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    //
    // The check is needed as ExUnregisterCallback doesn't check for a NULL pointer
    //
    if (g_WdRegisteredCallback != NULL) {
        ExUnregisterCallback(g_WdRegisteredCallback);
    }
}

NTSTATUS
DriverEntry(
    _In_    PDRIVER_OBJECT  DriverObject,
    _In_    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = DriverUnload;

    PCALLBACK_OBJECT    pWdProcessNotifCb = NULL;
    UNICODE_STRING      WdObjName = RTL_CONSTANT_STRING(L"\\Callback\\WdProcessNotificationCallback");
    OBJECT_ATTRIBUTES   WdProcNotifObjAttr; // InitializeObjectAttributes would be recommended to use, but...
    RtlSecureZeroMemory(&WdProcNotifObjAttr, sizeof(OBJECT_ATTRIBUTES));
    WdProcNotifObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    WdProcNotifObjAttr.ObjectName = &WdObjName;
    WdProcNotifObjAttr.Attributes = 0x210;

    if (!NT_SUCCESS(ExCreateCallback(&pWdProcessNotifCb, &WdProcNotifObjAttr, FALSE, FALSE))) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ ": Failed to obtain callback object!\n");

        return STATUS_NOT_FOUND;
    }

    g_WdRegisteredCallback = ExRegisterCallback(pWdProcessNotifCb, WdProcCallback, NULL);
    if (g_WdRegisteredCallback != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": Callback was successfully registered!\n");

    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": Hmmm, something wrong!\n");

    }

    return STATUS_SUCCESS;
}