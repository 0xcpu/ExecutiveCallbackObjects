## AfdTdxCallback

### Description

`Afd.sys` - `Ancillary Function Driver for WinSock`.

`Tdx.sys` - [TDI](https://en.wikipedia.org/wiki/Transport_Driver_Interface) `Translation Driver`.

---

Another _producer_ (`Tdx.sys`) - _consumer_ (`Afd.sys`) pattern (as in [TcpConnectionCallbackTemp](../TcpConnectionCallbackTemp)). Inside `Tdx.sys` callback object creation is governed by `TdxInitializeTransportAddressModule` function and all notifications (4 call references) on this object are triggered from `TdxActivateTransportAddress` function. `Afd.sys` registers a callback named `AfdTdxCallbackRoutine` inside `AfdTdxInitCallback` function. What is the consumer receiving as `Argument1` and `Argument2`(see [CallbackFunction](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exregistercallback)) when the callback object is notified?
- `Argument1` is of type `struct _ECP_LIST *`.
- `Argument2` is used as an output argument (communication channel), through which `Afd.sys` passes back data to `Tdx.sys`. Here we can see that the authors are abusing the definition of the [CallbackFunction](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exregistercallback) which in the documentation has `IN` SAL annotation, but here is used as an `OUT` parameter.

`Argument1` can be useful in a call to [FsRtlFindExtraCreateParameter](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfindextracreateparameter) (that's the use case in `afd.sys`), where the ECP context structure is obtained through using an appropriate `GUID` (like ones listed in [System-Defined ECPs](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/system-defined-ecps)). Last note, `afd.sys` uses the following `GUID`: `d37479c1-4502-a067-0e35-2e8cd59134f5`.
