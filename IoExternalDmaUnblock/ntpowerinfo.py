import ida_ida
import ida_auto
import ida_loader
import ida_hexrays
import ida_idp
import ida_entry
import idautils
import ida_nalt
import ida_pro

from os.path import basename

def imp_cb(ea, name, ord):
    if "NtPowerInformation" in name:
        global nt_power_information
        nt_power_information = ea
        # False stops iteration over imports
        return False
    # Continue to iterate over imports
    return True


nimps = idaapi.get_import_module_qty()

nt_power_information = None
for i in range(0, nimps):
    name = idaapi.get_import_module_name(i)
    if not name:
        continue
    
    if "ntdll" in name:
        idaapi.enum_import_names(i, imp_cb)
        if nt_power_information is not None:
            break

output_filename = basename(ida_nalt.get_input_file_path()) \
                     + ida_nalt.get_root_filename() + ".dec"
if nt_power_information:
    ida_auto.auto_wait()

    if ida_loader.load_plugin("hexx64") and ida_hexrays.init_hexrays_plugin():
        code_xrefs = idautils.CodeRefsTo(nt_power_information, 1)
        for cx in code_xrefs:
            cf = ida_hexrays.decompile(cx)
            if cf:
                with open(output_filename, "a") as fd:
                    fd.write(str(cf) + '\n')
            else:
                with open(output_filename, "a") as fd:
                    fd.write("[!] Decompilation failed\n")
    else:
        with open(output_filename, "a") as fd:
            fd.write("[!] Decompiler loading failed\n")
else:
    with open(output_filename, "a") as fd:
        fd.write("[+] NtPowerInformation import was not found\n")

ida_pro.qexit(0)
