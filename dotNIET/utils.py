# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay@synacktiv.com> wrote this file. As long as you 
# retain this notice you can do whatever you want with this stuff. 
# If we meet some day, and you think this stuff is worth it, you can buy me a
# beer in return
# ----------------------------------------------------------------------------

import os, re
import pefile
import idaapi, idc, ida_diskio, ida_kernwin
from dotNIET import pdbguid as pdbg


def _parse_symbol_path(value):
    symbol_paths = []
    if value != "":
        for entry in value.split(";"):
            for x in entry.split('*'):
                if x.lower() != "srv" and "http" not in x.lower():
                    symbol_paths.append(x)
    return symbol_paths

def _parse_cfg_file(path):
    with open(path, 'r') as f:
        for line in f.readlines():
            if line.startswith("_NT_SYMBOL_PATH"):
                return _parse_symbol_path(line.split('"')[1])

def find_pdb(dll_path):
    # we first check if the pdb is available
    symbol_paths = []
    cfg_known_locations= [ida_diskio.get_user_idadir() + "/cfg/pdb.cfg", 
                          idc.idadir() + "/cfg/pdb.cfg"]

    for cfg in cfg_known_locations:
        if os.path.exists(cfg):
            symbol_paths = _parse_cfg_file(cfg)
            # ida first check IDAUSR dir and if ok ignore IDADIR cfg
            if symbol_paths is not None and len(symbol_paths):
                break

    nt_symbol_path_env = os.getenv("_NT_SYMBOL_PATH")
    # assume Windows + it overrides values of ida cfg file
    if nt_symbol_path_env is not None and nt_symbol_path_env != "":
        symbol_paths = _parse_symbol_path(os.getenv("_NT_SYMBOL_PATH"))

    if symbol_paths is None or not len(symbol_paths):
        idaapi.msg("Error: \'_NT_SYMBOL_PATH\' could not be found. One must" +\
                    " set for .NIET to work.\n")
        return False
    else:
        # we then compute pdb guid of SharedLibrary.dll
        pdbguid = pdbg.get_guid(dll_path)
        if pdbguid is None:
            return False
        # we can have multiple paths, we check all of them
        for paths in symbol_paths:
            pdb_path = paths.replace('\\','/') + "/SharedLibrary.pdb/" + \
                       pdbguid + "/SharedLibrary.pdb"
            if not os.path.exists(pdb_path):
                idaapi.msg("Error: %s could not be found\n" % pdb_path)
                return False
            else:
                return True

def get_NET_native_version(filepath):
    pe = pefile.PE(filepath, fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return "unknown"

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if str(entry.name) == "NETNATIVEBUILDINFO":
            break
    else:
        return "unknown"

    rsrc_data = entry.directory.entries[0].directory.entries[0].data
    data = pe.get_data(rsrc_data.struct.OffsetToData, rsrc_data.struct.Size)
    res = re.findall(b"ilc.exe *: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", data)

    if res:
        NET_version = res[0]
        return NET_version.decode()

    return "unknown"

def is_x64(dll):
    pe = pefile.PE(dll)
    if hex(pe.FILE_HEADER.Machine) == '0x14c':
        return False
    else:
        return True