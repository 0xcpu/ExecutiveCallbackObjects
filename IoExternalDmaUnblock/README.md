## IoExternalDmaUnblock

### Description

The callback object is created inside `ntoskrnl.exe`. The root of function tree that frames actions on this callback object is `PiCslInitialize` function, where `PipCslConsoleLockState` is initialized to 0 and `PipCslCreateCallback` is called in order to create the callback object (symbol `PipCslCallbackObject`). After the object is successfully created, the callback function `PipCslStateChangeCallback` is registered. The goal of this callback is to check if `PipCslInitialized` was initialized (not 0), otherwise the system bugchecks (code _0xCA_), then call `PipCslUpdateState` with argument value _1_ or _2_. The latter call compares the value of `PipCslConsoleLockState` with the argument value and if the values are different and the argument value is _1_ - `PipCslUnlockCallback` is called. An outline of what was mentioned:
```C
NTSTATUS __stdcall PiCslInitialize()
{
  NTSTATUS v0;

  PipCslConsoleLockState = 0;
  v0 = PipCslCreateCallback();
  if ( v0 >= 0 )
  {
    ExRegisterCallback((PCALLBACK_OBJECT)PipCslCallbackObject, (PCALLBACK_FUNCTION)PipCslStateChangeCallback, 0i64);
    PipCslInitialized = 1;
  }
  return v0;
}
```

What is `PipCslUnlockCallback` doing? Skimming the references we observe that the only write to this global function pointer is inside `PipDmgInitPhaseOne` function and the written value is the address of `PipDmgConsoleUnlockCallback` function. It is important to mention that the initialization happens only when `PipDmaGuardPolicy` is not _0_. As described on [Policy CSP - DmaGuard](https://docs.microsoft.com/en-us/windows/client-management/mdm/policy-csp-dmaguard), the value _0_ stands for _most restrictive_ policy, so the callback is going to be initialized in other cases, like when the policy is _1_ or _2_ (there are other undocumented values, like _3_). These primitives seem to be related to [Kernel DMA Protection](https://docs.microsoft.com/en-us/windows/security/information-protection/kernel-dma-protection-for-thunderbolt). In the end, `PipDmgConsoleUnlockCallback` is responsible for calling `PipDmgFlushQueueAndRestartDevices` function when `PipDmaGuardPolicy` is equal to _2_.

Callback object notifications are sent from `ntoskrnl`'s [NtPowerInformation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntpowerinformation), when `InformationLevel` argument has value _0x5F_, through calling `PnpWinlogonExternalDmaNotification` function. `Argument1` parameter of `ExNotifyCallback` is `NtPowerInformation`'s second parameter named `InputBuffer` and `Argument2` is always set to _0_.

There's another callback function registered inside `pci.sys` by function `PciCreateConsoleLockCallback`. The callback function name is `PciConsoleLockCallback` which is a wrapper for `PciSetConsoleState`. Inside the wrapper, first argument value (parameter `Argument1`) is checked if _0_ / _NULL_ and if not then the argument to later call is value _1_ otherwise _2_. `PciSetConsoleState` goal is to iterate over every _bus_ in every _PCI segment_ and verify if the _bus_ is affected by console lock (a - `PciBusAffectedByConsoleLock` is called) and should be disabled (b - `PciBusShouldBeDisabledByConsoleLock` is called). If only (a) is satisfied then `IoInvalidateDeviceRelations` is called. It is important to note that all of the above actions are done only when `PciConsoleState` global variable value is different than the value of the argument passed to the function.

We were curios about any executables, libraries or drivers that make use of `NtPowerInformation` and call it with first argument being _0x5F_. For that we searched recursively inside `%SystemRoot%\System32` looking for files containing the string _NtPowerInformation_ (in different code pages like ANSI, UTF-8, UTF-16). Then using _HexRays decompiler plugin_ and [two scripts](ida_run.py) (watch out, unpolished code!) allowing to run _IDA Pro_ in batch mode we found 91 files calling `NtPowerInformation` at least once. And from those, the only one using _0x5F_ as an argument is inside a function (`NotifyUserPresenceOnDesktopForDMAProtection`) hosted by `winlogon.exe`. Here's the pseudocode:
```C
//
// When symbols are loaded the function prototype is:
// void __fastcall NotifyUserPresenceOnDesktopForDMAProtection(int, struct _WLSM_GLOBAL_CONTEXT *)
//
void **__fastcall sub_1400391B8(int a1, __int64 a2)
{
  __int64 v2; // rcx
  void **result; // rax
  NTSTATUS v4; // eax
  __int64 v5; // rdx
  __int64 v6; // r8
  __int64 v7; // r9
  const wchar_t *v8; // r9
  int v9; // [rsp+40h] [rbp+8h]
  char InputBuffer; // [rsp+48h] [rbp+10h]

  v9 = a1;
  v2 = *(_QWORD *)(a2 + 16);
  InputBuffer = 0;
  if ( (unsigned int)sub_140027BB8(v2) ) // CSession::IsBoundToConsole
  {
    InputBuffer = v9;
    //
    // TraceApplicationPowerMessageEnd - 0x1F
    //
    v4 = NtPowerInformation(TraceApplicationPowerMessageEnd|0x40, &InputBuffer, 1u, 0i64, 0);
    v7 = (unsigned int)v4;
    ...
```

EOF
