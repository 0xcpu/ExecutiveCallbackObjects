```C
PgEntryData = PgEntry->Data;
PgEntry_DataSize = PgEntry->DataSize;
PgEntryData_1 = PgEntryData;
PgCtx->MsSecRes80000_SumPgDataSizes += PgEntry_DataSize;
_RAX = PgEntryData;
NumRot = PgCtx->RotNum;
for (i = PgCtx->LoopInitValue; _RAX < PgEntryData + PgEntry_DataSize; _RAX += 64)
    __asm { prefetchnta byte ptr [rax]}
    LoopInitValue = PgCtx->LoopInitValue;
Iterations = PgEntry_DataSize >> 7;
if (PgEntry_DataSize >> 7)
{
    do
    {
        Iterations_1 = 8;
        do
        {
            Temp = PgEntryData_1[1] ^ __ROL8__(*PgEntryData_1 ^ LoopInitValue, NumRot);
            PgEntryData_1 += 2;
            LoopInitValue = __ROL8__(Temp, NumRot);
            --Iterations_1;
        } while (Iterations_1);
        *Temp = (__ROL8__(i ^ (PgEntryData_1 - PgEntryData_11), 17) ^ i ^ (PgEntryData_1 - PgEntryData)) * 0x7010008004002001;
        Temp2 = LOBYTE(Temp1[0]) ^ LOBYTE(Temp1[1]) ^ NumRot;
        LODWORD(Temp1[1]) = 1;
        NumRot = Temp2 & 0x3F;
        if (!NumRot)
            LOBYTE(NumRot) = 1;
        --Iterations;
    } while (Iterations);
}
j = PgEntry_DataSize & 0x7F;
if (j >= 8)
{
    Iterations_2 = j >> 3;
    do
    {
        LoopInitValue = __ROL8__(*PgEntryData_1 ^ LoopInitValue, NumRot);
        ++PgEntryData_1;
        j = j - 8;
        --Iterations_2;
    } while (Iterations_2);
}
for (; j; j = (j - 1))
{
    PgEntryData_Byte = *PgEntryData_1;
    PgEntryData_1 = (PgEntryData_1 + 1);
    LoopInitValue = __ROL8__(PgEntryData_Byte ^ LoopInitValue, NumRot);
}
for (k = LoopInitValue;; LODWORD(LoopInitValue) = k ^ LoopInitValue)
{
    k >>= 31;
    if (!k)
        break;
}
ComputedChecksum = LoopInitValue & 0x7FFFFFFF;
if (ComputedChecksum == PgEntry->CheckSum)
    goto checksum_match;
```