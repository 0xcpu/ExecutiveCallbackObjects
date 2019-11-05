#include <ntddk.h>

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;
CALLBACK_FUNCTION   EnlightenmentStateCallback;

PVOID g_EnlightenmentStateCb;

VOID
EnlightenmentStateCallback(
    _In_opt_    PVOID   CallbackContext,
    _In_opt_    PVOID   Argument1,
    _In_opt_    PVOID   Argument2
)
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER(CallbackContext);
    UNREFERENCED_PARAMETER(Argument1);
    UNREFERENCED_PARAMETER(Argument2);

}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
)
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_EnlightenmentStateCb != NULL) {
        ExUnregisterCallback(g_EnlightenmentStateCb);
    }

}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{

    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING      EnlightenmentStateObjName;
    OBJECT_ATTRIBUTES   EnlightenmentStateAttr;
    PCALLBACK_OBJECT    pEnlightenmentState = NULL;

    DriverObject->DriverUnload = DriverUnload;

    RtlInitUnicodeString(&EnlightenmentStateObjName, L"\\Callback\\EnlightenmentState");

    InitializeObjectAttributes(&EnlightenmentStateAttr, &EnlightenmentStateObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (!NT_SUCCESS(ExCreateCallback(&pEnlightenmentState, &EnlightenmentStateAttr, FALSE, FALSE))) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__ ": Failed to obtain callback object!\n");

        return STATUS_NOT_FOUND;
    }

    g_EnlightenmentStateCb = ExRegisterCallback(pEnlightenmentState, EnlightenmentStateCallback, NULL);

    if (g_EnlightenmentStateCb != NULL) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __FUNCTION__ ": Seems ok!\n");

    }
    else {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __FUNCTION__ ": Hmmm, something wrong!\n");

        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;

}