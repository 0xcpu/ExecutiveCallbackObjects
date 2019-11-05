#include <ntddk.h>
#include <intrin.h>

DRIVER_INITIALIZE   DriverEntry;
DRIVER_UNLOAD       DriverUnload;
CALLBACK_FUNCTION   Phase1Callback;

PVOID g_Phase1Callback;

VOID
Phase1Callback(
    _In_opt_    PVOID   CallbackContext,
    _In_opt_    PVOID   Argument1,
    _In_opt_    PVOID   Argument2
)
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER(CallbackContext);

    PVOID pvAddressOfReturnAddress;
    PVOID pLoaderParamBlock;

    // Make sure we are getting notified by the kernel
    if (Argument1 != NULL && Argument2 != NULL) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__ ": Wrong Arguments!!");

        return;
    }


    pvAddressOfReturnAddress = _AddressOfReturnAddress();
    
    /* In Windows 10 ver 1903 (OS Build 19002.1002) adding 0x68 to the return addres of this callback we get a pointer to the LOADER_PARAMETER_BLOCK. This is of course not reliable, just throwing out some ideas :)
    */
    pLoaderParamBlock = (PVOID)((char *)pvAddressOfReturnAddress + 0x68);

}

VOID
DriverUnload(
    _In_ PDRIVER_OBJECT DriverObject
) 
{

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);

    if (g_Phase1Callback != NULL) {
        ExUnregisterCallback(g_Phase1Callback);
    }

}

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{

    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING      Phase1ObjName;
    OBJECT_ATTRIBUTES   Phase1ObjAttr;
    PCALLBACK_OBJECT    pPhase1InitComplete = NULL;

    DriverObject->DriverUnload = DriverUnload;

    RtlInitUnicodeString(&Phase1ObjName, L"\\Callback\\Phase1InitComplete");

    InitializeObjectAttributes(&Phase1ObjAttr, &Phase1ObjName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (!NT_SUCCESS(ExCreateCallback(&pPhase1InitComplete, &Phase1ObjAttr, FALSE, FALSE))) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, __FUNCTION__ ": Failed to obtain callback object!\n");

        return STATUS_NOT_FOUND;
    }
     
    g_Phase1Callback = ExRegisterCallback(pPhase1InitComplete, Phase1Callback, NULL);

    if (g_Phase1Callback != NULL) {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __FUNCTION__ ": Seems ok!\n");

    } else {

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, __FUNCTION__ ": Hmmm, something wrong!\n");

        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;

}