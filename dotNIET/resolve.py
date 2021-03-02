# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay@synacktiv.com> wrote this file. As long as you 
# retain this notice you can do whatever you want with this stuff. 
# If we meet some day, and you think this stuff is worth it, you can buy me a
# beer in return
# ----------------------------------------------------------------------------

import idaapi, ida_pro, idautils, idc


def get_symbols(ordinals):
    symbols = []

    sharedlibrary_base_addr = idaapi.get_imagebase()
    customexport_section_addr = [x[2] for x in list(idautils.Entries()) if x[3] == '$NEAT$'][0]

    # we then get EETableSection address, still don't know what it is though...
    eetablesection_addr = 0
    for names in idautils.Names():
        if names[1] == "EETableSection":
            eetablesection_addr = names[0]
            break

    for i in range(len(ordinals)):
        offset = idaapi.get_dword(customexport_section_addr + ordinals[i])
        symbol_addr = sharedlibrary_base_addr + offset
        name_symbol = idc.get_name(symbol_addr)

        # dirty hacks because no auto-analysis
        if name_symbol == "":
            # we first try to convert to code to see if this is a jmp
            idc.create_insn(symbol_addr)
            if idc.print_insn_mnem(symbol_addr) == 'jmp':
                name_symbol = 'jmp_' + idc.get_name(get_operand_value(symbol_addr,0))
            else:
                # assume off_xxx   dq offset MYSYMBOL
                sym = symbol_addr
                # 3 derefs should be enough...
                for i in range(3):
                    sym = idaapi.get_qword(sym)
                    if idc.get_name(sym) != "":
                        name_symbol = idc.get_name(sym)+ '_deref_' + str(i + 1)
                        break
                if name_symbol == "":
                # assume we are in EETableSection or at an xref, but because 
                # auto-analysis is disabled we have no way to know it easily
                # (eg: could be an offset of a vtable)
                    eetablesection_off = symbol_addr - eetablesection_addr
                    symbols.append("EETableSection" + ["_0x%x" % eetablesection_off \
                                                       if eetablesection_off else ""][0])
                    continue
        # some symbols are just jmpstubs, we fix this to have something
        # more readable
        elif '__jmpstub' in name_symbol:
            # as auto-analysis is disabled, we must create code here first
            idc.create_insn(symbol_addr)
            if idc.print_insn_mnem(symbol_addr) == 'jmp':
                name_symbol = 'jmp_' + idc.get_name(get_operand_value(symbol_addr,0))

        symbols.append(name_symbol)
    return symbols

if __name__ =='__main__':
    # we first disable auto-analysis for performances
    idc.set_inf_attr(INF_AF, idc.get_inf_attr(INF_AF) & (~AF_USED));

    ordinals = []
    with open(idc.ARGV[1], 'r') as f:
        ordinals_array = f.read()
        ordinals = [int(x) for x in ordinals_array.split(',')]
    symbols = get_symbols(ordinals)

    # we write them back to the file
    if len(symbols) != 0:
        with open(idc.ARGV[1], 'w') as f:
            f.write(",".join([str(x) for x in symbols]))
        ida_pro.qexit(0)
    else:
        ida_pro.qexit(1)
