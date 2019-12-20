```C
__int64 __fastcall EncryptDecryptEntries(PPgCtx PgCtx)
{
  int SomeFlags; // er11
  __int64 i; // r10
  int ChecksStatusFlags; // er9
  __int64 OffsetPgEntries; // rcx
  __int64 LoopInitValue_Xor; // rbp
  unsigned __int64 SizeIterations; // rdi
  char *pData; // rbx
  unsigned __int64 pDataEnd; // r14
  __int64 XoredRAXRDX_1; // r11
  __int64 i2; // rsi
  __int64 v13; // rdx
  _DWORD *pFaultRegion; // rax
  int v15; // ecx
  unsigned __int64 TimestampCtr; // rax
  __int64 XoredRAXRDX; // r11
  __int64 a1[2];

  SomeFlags = PgCtx->SomeFlags;
  if ( !_bittest(&SomeFlags, 30u) )
  {
    i = 0i64;
    while ( 1 )
    {
      ChecksStatusFlags = PgCtx->ChecksStatusFlags;
      a1[1] = (a1[0] & 0xffffffff) != 0;
      if ( a1 == ((PgCtx->ChecksStatusFlags >> 21) & 1) || !(SomeFlags & 2) )
        break;
      OffsetPgEntries = PgCtx->OffsetStartPgEntries;
      LoopInitValue_Xor = PgCtx->LoopInitValue;
      SizeIterations = (PgCtx->SizeofAllPgEntries - OffsetPgEntries) >> 3;
      pData = &PgCtx->CmpAppendDllSection[OffsetPgEntries];
      pDataEnd = PgCtx + 8 * SizeIterations + OffsetPgEntries;
      if ( a1[0] & 0xffffffff )
      {
        TimestampCtr = __rdtsc();
        a1 = (__ROR8__(TimestampCtr, 3) ^ TimestampCtr) * 0x7010008004002001ui64;
        XoredRAXRDX = a1[0] ^ a1[1];
        PgCtx->XoredRAXRDX = XoredRAXRDX;
        if ( pData > pDataEnd )
          SizeIterations = 0i64;
        if ( SizeIterations )
        {
          do
          {
            ++i;
            a1[0] = XoredRAXRDX ^ *pData;
            a1[1] = LoopInitValue_Xor ^ *pData;
            *pData = a1;
            XoredRAXRDX = (a[1] + __ROR8__(XoredRAXRDX, XoredRAXRDX & 0x3F)) ^ 0xEFFi64;
            pData += 8;
          }
          while ( i != SizeIterations );
          ChecksStatusFlags = PgCtx->ChecksStatusFlags;
        }
        PgCtx->XoredRAXRDX2 = XoredRAXRDX;
        PgCtx->ChecksStatusFlags = ChecksStatusFlags | 0x200000;
        return a1;
      }
      XoredRAXRDX_1 = PgCtx->XoredRAXRDX;
      i2 = 0i64;
      if ( pData > pDataEnd )
        SizeIterations = 0i64;
      if ( SizeIterations )
      {
        do
        {
          *pData ^= XoredRAXRDX_1;
          ++i2;
          v13 = *pData;
          pData += 8;
          XoredRAXRDX_1 = ((LoopInitValue_Xor ^ v13) + __ROR8__(XoredRAXRDX_1, XoredRAXRDX_1 & 0x3F)) ^ 0xEFF;
        }
        while ( i2 != SizeIterations );
        ChecksStatusFlags = PgCtx->ChecksStatusFlags;
      }
      PgCtx->ChecksStatusFlags = ChecksStatusFlags & 0xFFDFFFFF;
      if ( XoredRAXRDX_1 != PgCtx->XoredRAXRDX2 )
      {
        pPgFault = PgCtx->pPgFault;
        v15 = PgCtx->SizeofAllPgEntries;
        pPgFault->Ptr1 = PgCtx;
        pPgFault->Id1 = v15;
        if (!PgCtx->SomethingWentWrong;)
        {
          PgCtx->pPgFault->XoredChecksum = XoredRAXRDX_1 ^ PgCtx->XoredRAXRDX2;
          if (!PgCtx->SomethingWentWrong;)
          {
            PgCtx->EncodedPointerPgCtxEntry = 0i64;
            PgCtx->PgEntryType = 0x100i64;
            PgCtx->EncodedPointerPgCtxLocal = &PgCtx + 0A3A03F5891C8B4E8h;
            a1[0] = 0;
            PgCtx->PgEntryData = XoredRAXRDX_1;
            PgCtx->SomethingWentWrong = 1;
            SomeFlags = PgCtx->SomeFlags;
            if ( !_bittest(&SomeFlags, 0x1Eu) )
              continue;
          }
        }
      }
      return a1;
    }
  }
  return a1;
}
```