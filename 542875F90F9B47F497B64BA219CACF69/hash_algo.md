```C
void __fastcall ComputeHash(PPgCtx PgCtx, PVOID Data, SIZE_T Size, PVOID OutBuffer)
{
  INT64 i;
  BYTE v6;
  char j;
  int TempBuffer[8];

  KeGuardDispatchICall(PgCtx->KeComputeSha256, Data, Size, OutBuffer);
  for ( i = 0i64; i < 4; ++i )
    OutBuffer[i] = TempBuffer[i] ^ TempBuffer[i + 4];
  v6 = *(OutBuffer + 15);
  for ( j = *(OutBuffer + 15); ; j ^= v6 )
  {
    v6 >>= 7;
    if ( !v6 )
      break;
  }
  *(OutBuffer + 15) = j & 0x7F;
}
```