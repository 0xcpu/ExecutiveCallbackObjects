## TcpConnectionCallbackTemp

### Description

**This is still work in progress!**

This callback object can be created in `tcpip.sys` or `rasacd.sys`. In both drivers the symbol for the object is `TcpCcbObject`.
A strong friendship relationship is observed in `tcpip.sys`, where _9_ references lead to `ExNotifyCallback`, while `rasacd.sys` has _1_ reference leading to `ExRegisterCallback`. So our understanding comes to a conclusion that we have a _producer_ - _consumer_ pattern between these _2_ drivers.

There seem to be 3 possible values for the `Argument1`, they are the following:
- 1: Default case
- 2: Seems to be related to `TCP_SYN_ATTACK_ENTRY`
- 3: Seems to be related to `TCP_SYN_ATTACK_EXIT`

For `Argument2`, only when `Argument1` is equal to `1`, we get a pointer to a structure:
```C
typedef struct _TCP_CB
{
    UINT16  Magic; // 2
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
```

### POC

[TcpConnectionCallbackTemp](TcpConnectionCallbackTemp)
