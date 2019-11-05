#include <ntifs.h>

#define IPByte1(x) ((int)((x) & 0xff))
#define IPByte2(x) ((int)(((x) >> 8) & 0xff))
#define IPByte3(x) ((int)(((x) >> 16) & 0xff))
#define IPByte4(x) ((int)(((x) >> 24) & 0xff))

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;

PVOID               g_TcpConnRegisteredCallback;
CALLBACK_FUNCTION   TcpConnCallback;

typedef struct _TCP_CB
{
    UINT16  Magic;
    UINT16  Reserved;
    DWORD32 Unknown0; // observed values: 1, 3, 5, 6, 7, 10, 11
    DWORD64 NotificationType; // observed values: 1, 3, 4, 5
    PVOID   pSrcIpAddr;
    PVOID   pDstIpAddr;
    UINT16  pSrcPort;
    UINT16  pDstPort;
    DWORD32 Unknown1; // observed values: 0xe0000001
    DWORD32 Unknown2; // observed values: 0xe0000001
    DWORD32 Unknown3; // 0x21, 0x1
} TCP_CB, *PTCP_CB;

VOID
TcpConnCallback(
    _In_opt_    PVOID   CallbackContext,
    _In_opt_    PVOID   Argument1,
    _In_opt_    PVOID   Argument2
)
{
    UNREFERENCED_PARAMETER(CallbackContext);
    
    PTCP_CB pTcpCb = (PTCP_CB)Argument2;
    ULONG   IPv4Addr;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
               DPFLTR_INFO_LEVEL,
               __FUNCTION__ ": [+] Argument1: %#08llX\n", (DWORD64)Argument1);

    if (pTcpCb != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": [*] Magic: %#06x Reserved: %#06x\n",
                   pTcpCb->Magic,
                   pTcpCb->Reserved
        );

        switch (pTcpCb->NotificationType) {
        case 1:
            if (pTcpCb->Unknown0 == 11) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~1] Called from TcpShutdownTimeWaitTcb\n"
                );
            } else if (pTcpCb->Unknown0 == 10) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~1] Called from TcpTcbCarefulDatagram\n"
                );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~1] Called from TcpShutdownTcb or TcpInvokeCcb. Unknown0: %#10lx\n",
                           pTcpCb->Unknown0
                );
            }

            break;
        case 3:
            if (pTcpCb->Unknown0 == 1) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~2] Called from TcpCreateAndConnectTcbRateLimitComplete\n"
                );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~2] Called from ?\n"
                );
            }

            break;
        case 4:
            if (pTcpCb->Unknown0 == 1) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~3] Called from TcpCreateAndAcceptTcb\n"
                );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~3] Called from ?\n"
                );
            }

            break;
        case 5:
            if (pTcpCb->Unknown0 == 3) {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~4] Called from TcpCreateAndConnectTcbComplete\n"
                );
            } else {
                DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                           DPFLTR_INFO_LEVEL,
                           __FUNCTION__ ": [~4] Called from ?\n"
                );
            }

            break;
        default:
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": [~5] Called from InvokeCcb. NotificationType: %#10llx Unknown0: %#10lx\n",
                       pTcpCb->NotificationType,
                       pTcpCb->Unknown0
            );

            break;
        }


        if (pTcpCb->pSrcIpAddr && pTcpCb->pDstIpAddr) {
            IPv4Addr = *(PULONG)pTcpCb->pSrcIpAddr;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": [<] Source IP: %d.%d.%d.%d Port: %u\n",
                       IPByte1(IPv4Addr),
                       IPByte2(IPv4Addr),
                       IPByte3(IPv4Addr),
                       IPByte4(IPv4Addr),
                       pTcpCb->pSrcPort
            );
            IPv4Addr = *(PULONG)pTcpCb->pDstIpAddr;
            DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                       DPFLTR_INFO_LEVEL,
                       __FUNCTION__ ": [>] Destination IP: %d.%d.%d.%d Port: %u\n",
                       IPByte1(IPv4Addr),
                       IPByte2(IPv4Addr),
                       IPByte3(IPv4Addr),
                       IPByte4(IPv4Addr),
                       pTcpCb->pDstPort
            );
        }

        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": [-] Unknown1: %#10x Unknown2: %#10x Unknown3: %#10x\n",
                   pTcpCb->Unknown1,
                   pTcpCb->Unknown1,
                   pTcpCb->Unknown3
        );
    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ ": [!] Argument2 isn't available\n");
    }
}

VOID DriverUnload(
    _In_    PDRIVER_OBJECT  DriverObject
)
{
    UNREFERENCED_PARAMETER(DriverObject);

    if (g_TcpConnRegisteredCallback != NULL) {
        ExUnregisterCallback(g_TcpConnRegisteredCallback);
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

    PCALLBACK_OBJECT    pTcpConnCb = NULL;
    UNICODE_STRING      TcpConnObjName = RTL_CONSTANT_STRING(L"\\Callback\\TcpConnectionCallbackTemp");
    OBJECT_ATTRIBUTES   TcpConnObjAttr;
    RtlSecureZeroMemory(&TcpConnObjAttr, sizeof(OBJECT_ATTRIBUTES));
    TcpConnObjAttr.Length = sizeof(OBJECT_ATTRIBUTES);
    TcpConnObjAttr.ObjectName = &TcpConnObjName;
    TcpConnObjAttr.Attributes = 0x50;

    if (!NT_SUCCESS(ExCreateCallback(&pTcpConnCb, &TcpConnObjAttr, TRUE, TRUE))) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ ": Failed to obtain callback object!\n");

        return STATUS_NOT_FOUND;
    }

    g_TcpConnRegisteredCallback = ExRegisterCallback(pTcpConnCb, TcpConnCallback, NULL);
    if (g_TcpConnRegisteredCallback != NULL) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_INFO_LEVEL,
                   __FUNCTION__ ": Callback was successfully registered!\n");

    } else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
                   DPFLTR_ERROR_LEVEL,
                   __FUNCTION__ ": Hmmm, something wrong!\n");

    }

    return STATUS_SUCCESS;
}