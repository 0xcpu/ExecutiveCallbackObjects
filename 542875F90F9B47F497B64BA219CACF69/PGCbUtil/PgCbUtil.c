#include <ntifs.h>
#include <ntstrsafe.h>


#define PG_CTX_PTAG         'xcgP'
#define PG_CTX_SZ           0x3f024
#define PG_CTX_RVA          0xCFC388  // Adapt RVAs
#define PG_CB_RVA           0x38BDE0
#define NT_DDI_WIN10_20H1   0xA000008 // Adapt DDI version


DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

typedef struct _SEC_PROCESSOR_INFO
{
    KAFFINITY   ActiveLogicalProcessor;
    USHORT      GroupCounter;
} SEC_PROCESSOR_INFO, *PSEC_PROCESSOR_INFO;

typedef struct _SEC_USERPROBE_INFO
{
    ULONG64 UserProbeAddress;
    __int64 PtrSize;
} SEC_USERPROBE_INFO, *PSEC_USERPROBE_INFO;

typedef union _SEC_PG_INFO
{
    SEC_PROCESSOR_INFO    SecProcessorInfo;
    SEC_USERPROBE_INFO    SecUserProbeInfo;
} SEC_PG_INFO, *PSEC_PG_INFO;

typedef struct _MSSEC_PG_CB_ARG1
{
    DWORD64         SizeOfStruct;
    DWORD64         NtDdiVersion;
    DWORD           Reserved80000h;
    int             UsePgCtxSize;
    __int64         field_18;
    int             field_20;
    int             field_24;
    int             field_28;
    int             Unknown1;
    DWORD           Option;
    DWORD           Reserved10h;
    PSEC_PG_INFO    SecPgInfo;
} MSSEC_PG_CB_ARG1, *PMSSEC_PG_CB_ARG1;

typedef struct _MSSEC_PG_CB_ARG2
{
    int     field_0;
    int     field_4;
    __int64 field_8;
    __int64 field_10;
    __int64 field_18;
    __int64 field_20;
    __int64 field_28;
} MSSEC_PG_CB_ARG2, *PMSSEC_PG_CB_ARG2;

typedef NTSTATUS(*PGCALLBACK)(PMSSEC_PG_CB_ARG1, PMSSEC_PG_CB_ARG2);

NTKERNELAPI
PVOID
NTAPI
RtlPcToFileHeader(
    _In_    PVOID  PcValue,
    _Out_   PVOID *BaseOfImage
);


PVOID GetNtoskrnlBaseAddress(VOID)
{
    PVOID NtoskrnlBaseAddress;
    
    return RtlPcToFileHeader((PVOID)RtlPcToFileHeader, &NtoskrnlBaseAddress);
}

BOOLEAN DumpPgCtx(
    _In_    ULONG_PTR   NtosKrnlBaseAddress
)
{
    UNICODE_STRING      DumpFileName;
    LARGE_INTEGER       Delay = { .QuadPart = 1 << 20 };
    LARGE_INTEGER       Offset = { .QuadPart = 0 };
    PULONG_PTR          pPgCtxAddr = NULL;
    PUCHAR              PgCtx;
    IO_STATUS_BLOCK     IoStatusBlock = { 0 };
    OBJECT_ATTRIBUTES   ObjAttrib = { 0 };
    HANDLE              hPgCtxDump;
    NTSTATUS            ntStatus;
    BOOLEAN             bRet = FALSE;

    PgCtx = (PUCHAR)ExAllocatePoolWithTag(NonPagedPoolNx, PG_CTX_SZ, PG_CTX_PTAG);
    if (NULL == PgCtx) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ "[PgCtxDump] Failed to allocate PgCtx pool.\n");

        return FALSE;
    }

    pPgCtxAddr = (PULONG_PTR)(NtosKrnlBaseAddress + PG_CTX_RVA);

    for (size_t i = 0; i < (1 << 10); i++) {
        if ((PVOID)*pPgCtxAddr != NULL) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ "[PgCtxDump] PgCtx address: %08llx\n",
                       *pPgCtxAddr);

            RtlCopyMemory(PgCtx, (PVOID)*pPgCtxAddr, PG_CTX_SZ);

            bRet = TRUE;

            break;
        } else {
            KeDelayExecutionThread(KernelMode, TRUE, &Delay);
        }
    }
    
    if (!bRet) {
        goto epilogue;
    }

    //
    // Adapt the path to dump file, if needed
    //
    if (RtlUnicodeStringInit(&DumpFileName, L"\\Device\\HarddiskVolume4\\PgCtx.dmp") != STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ "[PgCtxDump] Failed to initialize file name\n");

        bRet = FALSE;

        goto epilogue;
    }

    ObjAttrib.Length = sizeof(OBJECT_ATTRIBUTES);
    ObjAttrib.RootDirectory = NULL;
    ObjAttrib.ObjectName = &DumpFileName;
    ObjAttrib.Attributes = OBJ_CASE_INSENSITIVE;
    ObjAttrib.SecurityDescriptor = NULL;
    ObjAttrib.SecurityQualityOfService = NULL;
    ntStatus = ZwCreateFile(&hPgCtxDump,
                            GENERIC_WRITE,
                            &ObjAttrib,
                            &IoStatusBlock,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            FILE_SHARE_WRITE,
                            FILE_OVERWRITE_IF,
                            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                            NULL,
                            0);
    if (ntStatus != STATUS_SUCCESS) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ "[PgCtxDump] Failed to create dump file %08lX\n",
                   ntStatus);

        bRet = FALSE;
    } else {
        RtlSecureZeroMemory(&IoStatusBlock, sizeof(IO_STATUS_BLOCK));
        ntStatus = ZwWriteFile(hPgCtxDump,
                               NULL,
                               NULL,
                               NULL,
                               &IoStatusBlock,
                               PgCtx,
                               PG_CTX_SZ,
                               &Offset,
                               NULL);

        if (ntStatus != STATUS_SUCCESS || IoStatusBlock.Status != STATUS_SUCCESS) {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ "[PgCtxDump] ntStatus: %08lX IO_STATUS_BLOCK.Status: %08lX\n",
                       ntStatus,
                       IoStatusBlock.Status);

            bRet = FALSE;
        } else {
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ "[PgCtxDump] PgCtx was successfully writen to %wZ\n",
                       DumpFileName);
        }

        NtClose(hPgCtxDump);
    }

epilogue:

    ExFreePoolWithTag(PgCtx, PG_CTX_PTAG);
    PgCtx = NULL;

    return bRet;
}

NTSTATUS ExecutePgCallback(
    _In_    ULONG_PTR   NtosKrnlBaseAddress
)
{
    INT                 Trials = 5;
    SEC_PG_INFO         SecPgInfo = { 0 };
    MSSEC_PG_CB_ARG1    MsSecPgArg1 = { 0 };
    MSSEC_PG_CB_ARG2    MsSecPgArg2 = { 0 };
    NTSTATUS            ntStatus = STATUS_UNSUCCESSFUL;
    PGCALLBACK          PgCb = NULL;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               __FUNCTION__ "[PgCtxDump] KdDebuggerNotPresent: %hhu\n", *KdDebuggerNotPresent);

    PgCb = (PGCALLBACK)(NtosKrnlBaseAddress + PG_CB_RVA);

    MsSecPgArg1.SizeOfStruct = 0x40;
    MsSecPgArg1.NtDdiVersion = NT_DDI_WIN10_20H1;
    MsSecPgArg1.Reserved80000h = 0x80000;
    MsSecPgArg1.Reserved10h = 0x10;
    MsSecPgArg1.Option = 0;
    if (0 == MsSecPgArg1.Option) {
        SecPgInfo.SecUserProbeInfo.UserProbeAddress = MmUserProbeAddress;
        SecPgInfo.SecUserProbeInfo.PtrSize = 8;
    } else {
        SecPgInfo.SecProcessorInfo.GroupCounter = 0;
        SecPgInfo.SecProcessorInfo.ActiveLogicalProcessor = KeQueryGroupAffinity(0);
    }
    MsSecPgArg1.SecPgInfo = &SecPgInfo;    

    while (Trials--) {
        ntStatus = PgCb(&MsSecPgArg1, &MsSecPgArg2);
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ "[PgCtxDump] NtStatus: %08lx\n", ntStatus);
        if (STATUS_SUCCESS == ntStatus) {
            break;
        }
    }

    return ntStatus;
}

VOID DriverUnload(
    _In_    PDRIVER_OBJECT  DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);
}

NTSTATUS
DriverEntry(
    _In_    PDRIVER_OBJECT  DriverObject,
    _In_    PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    ULONG_PTR   NtosKrnlBaseAddress = 0;

    DriverObject->DriverUnload = DriverUnload;

    NtosKrnlBaseAddress = (ULONG_PTR)GetNtoskrnlBaseAddress();
    if (0 == NtosKrnlBaseAddress) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ "[PgCtxDump] Failed to get Ntoskrnl base address\n");
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ "[PgCtxDump] Ntoskrnl base address: %08llx\n",
                   NtosKrnlBaseAddress);

        DumpPgCtx(NtosKrnlBaseAddress);
        ExecutePgCallback(NtosKrnlBaseAddress);   
    }

    return STATUS_SUCCESS;
}