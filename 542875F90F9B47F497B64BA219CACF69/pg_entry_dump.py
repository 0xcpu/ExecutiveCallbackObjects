import ctypes
import struct
import sys
import traceback
import abc


class PgEntry(abc.ABC):
    def __init__(self,
                 pg_type,
                 data_ptr,
                 data_size,
                 checksum,
                 const1,
                 const2,
                 const3,
                 const4,
                 const5,
                 const6):
        self._pg_type   = pg_type
        self._data_ptr  = ctypes.c_uint64(data_ptr) 
        self._data_size = ctypes.c_uint32(data_size)
        self._checksum  = ctypes.c_uint32(checksum)
        self._const1    = ctypes.c_uint32(const1)
        self._const2    = ctypes.c_uint32(const2)
        self._const3    = ctypes.c_uint32(const3)
        self._const4    = ctypes.c_uint32(const4)
        self._const5    = ctypes.c_uint32(const5)
        self._const6    = ctypes.c_uint32(const6)

        self.next_entry_off = ctypes.c_int64()

        super().__init__()


    def __str__(self):
        return "{0:<10s}: {1:08x}\n" \
            "{2:<10s}: {3:08x}\n"    \
            "{4:<10s}: {5:08x}\n"    \
            "{6:<10s}: {7:08x}\n"    \
            "{8:<10s}: {9:08x}\n"    \
            "{10:<10s}: {11:08x}\n"  \
            "{12:<10s}: {13:08x}\n"  \
            "{14:<10s}: {15:08x}\n"  \
            "{16:<10s}: {17:08x}\n"  \
            "{18:<10s}: {19:08x}\n".format(
                        "Type",     self.pg_type,
                        "DataPtr",  self.data_ptr.value,
                        "DataSize", self.data_size.value,
                        "Checksum", self.checksum.value,
                        "Const1",   self.const1.value,
                        "Const2",   self.const2.value,
                        "Const3",   self.const3.value,
                        "Const4",   self.const4.value,
                        "Const5",   self.const5.value,
                        "Const6",   self.const6.value)

    def __eq__(self, entry2) -> bool:
        if not isinstance(entry2, PgEntry):
            return False

        return \
            self.pg_type         == entry2.pg_type          and \
            self.data_ptr.value  == entry2.data_ptr.value   and \
            self.data_size.value == entry2.data_size.value  and \
            self.checksum.value  == entry2.checksum.value   and \
            self.const1.value    == entry2.const1.value     and \
            self.const2.value    == entry2.const2.value     and \
            self.const3.value    == entry2.const3.value     and \
            self.const4.value    == entry2.const4.value     and \
            self.const5.value    == entry2.const5.value     and \
            self.const6.value    == entry2.const6.value

    @property
    def pg_type(self) -> int:
        return self._pg_type
    
    @pg_type.setter
    def pg_type(self, pg_type: int) -> None:
        self._pg_type = pg_type

    @property
    def data_ptr(self) -> ctypes.POINTER:
        return self._data_ptr

    @data_ptr.setter
    def data_ptr(self, data_ptr: ctypes.POINTER) -> None:
        self._data_ptr = data_ptr

    @property
    def data_size(self) -> ctypes.c_uint32:
        return self._data_size

    @data_size.setter
    def data_size(self, value: ctypes.c_uint32) -> None:
        self._data_size = value

    @property
    def checksum(self) -> ctypes.c_uint32:
        return self._checksum

    @checksum.setter
    def checksum(self, checksum: ctypes.c_uint32) -> None:
        self._checksum = checksum

    @property
    def const1(self) -> ctypes.c_uint32:
        return self._const1

    @const1.setter
    def const1(self, value: ctypes.c_uint32) -> None:
        self._const1 = value

    @property
    def const2(self) -> ctypes.c_uint32:
        return self._const2

    @const2.setter
    def constw(self, value: ctypes.c_uint32) -> None:
        self._const2 = value

    @property
    def const3(self) -> ctypes.c_uint32:
        return self._const3

    @const3.setter
    def const3(self, value: ctypes.c_uint32) -> None:
        self._const3 = value

    @property
    def const4(self) -> ctypes.c_uint32:
        return self._const4

    @const4.setter
    def const4(self, value: ctypes.c_uint32) -> None:
        self._const4 = value

    @property
    def const5(self) -> ctypes.c_uint32:
        return self._const5

    @const5.setter
    def const5(self, value: ctypes.c_uint32) -> None:
        self._const5 = value

    @property
    def const6(self) -> ctypes.c_uint32:
        return self._const6

    @const6.setter
    def const6(self, value: ctypes.c_uint32) -> None:
        self._const6 = value

    @abc.abstractmethod
    def get_next_entry(self):
        pass


class PgEntryFunctionOrPdata(PgEntry):
    """Handles types FunctionOrPdata, SessionFunctionOrPdata and FunctionOrPdata1"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = 4 * (self.data_size.value // 0xc) + 0x30

        return self.next_entry_off


class PgEntryProcessorProc(PgEntry):
    """Handles types FFFFFFFF ProcessorIDT, ProcessorGDT, Type1ProcessList, Type2ProcessList, DebugRoutine, CriticalMSR"""

    def get_next_entry(self) -> ctypes.c_int64:
        if self.pg_type == 0x2:
            self.next_entry_off.value = 0x30
        else:
            self.next_entry_off.value = 0x18 * (self.const1.value + 2) #(2 * (self.const1.value + 2) + self.const1.value) << 3

        return self.next_entry_off


class PgEntryObjectType(PgEntry):
    """Handles type ObjectType"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = (self.const3.value & 0xffff) + 0x37 & 0xfffffff8

        return self.next_entry_off


class PgEntrySystemServiceFunction(PgEntry):
    """Handles type SystemServiceFunction"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = (self.const2.value + 3) * 0x10

        return self.next_entry_off


class PgEntryDriverObject(PgEntry):
    """Handles type DriverObject"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = (self.const5.value & 0xffff) + 0x37 & 0xfffffff8

        return self.next_entry_off


class PgEntryModulePadding(PgEntry):
    """Handles type ModulePadding"""

    def get_next_entry(self) -> ctypes.c_int64:
        temp = self.const4.value - 1 if self.const4.value > 0 else 0
        self.next_entry_off.value = ((temp // 0xc + 7) & 0xfffffff8) + 0x18 * ((self.const5.value & 0xffff) + 2)

        return self.next_entry_off


class PgEntryHashMismatch(PgEntry):
    """Handles types PageHashMismatch, SessionPageHashMismatch"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = 0x14 * (((self.const3.value & 0xfff) + self.const5.value + 0xfff) >> 12) + 0x30

        return self.next_entry_off


class PgEntryGenericType(PgEntry):
    """Handles other types not covered by other classes"""

    def get_next_entry(self) -> ctypes.c_int64:
        self.next_entry_off.value = 0x30

        return self.next_entry_off


class PgEntryFactory(object):
    def __init__(self):
        pass

    @classmethod
    def create(cls, entry):
        if entry[0] == 0x1 or entry[0] == 0xc or entry[0] == 0x2b:
            return PgEntryFunctionOrPdata(*entry)
        elif 2 <= entry[0] <= 7:
            return PgEntryProcessorProc(*entry)
        elif entry[0] == 0x8:
            return PgEntryObjectType(*entry)
        elif entry[0] == 0xa:
            return PgEntrySystemServiceFunction(*entry)
        elif entry[0] == 0x1c:
            return PgEntryDriverObject(*entry)
        elif entry[0] == 0x1e:
            return PgEntryModulePadding(*entry)
        elif 0x21 <= entry[0] <= 0x22:
            return PgEntryHashMismatch(*entry)
        else:
            return PgEntryGenericType(*entry)

    @classmethod
    def create_null(cls):
        return PgEntryGenericType(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)


assert(len(sys.argv) > 1)

struct_fmt = "=QQLLLLLLLL"
struct_sz = struct.calcsize(struct_fmt)
struct_unpack = struct.Struct(struct_fmt).unpack_from

PgEntriesOff = 0xaa0
with open(sys.argv[1], "rb") as f:
    null_entry = PgEntryFactory.create_null()
    while True:
        f.seek(PgEntriesOff)
        try:
            s = struct_unpack(f.read(struct_sz))
        except struct.error:
            traceback.print_exc()

            break

        pg_entry = PgEntryFactory.create(s)
        if pg_entry == null_entry:
            break
        
        print(pg_entry)

        PgEntriesOff += pg_entry.get_next_entry().value
