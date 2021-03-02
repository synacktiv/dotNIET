# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay@synacktiv.com> wrote this file. As long as you 
# retain this notice you can do whatever you want with this stuff. 
# If we meet some day, and you think this stuff is worth it, you can buy me a
# beer in return
# ----------------------------------------------------------------------------

import binascii, struct
import idaapi

try:
    import pefile
except ImportError:
    idaapi.msg("\"pefile\" python module is required")


def byte_swap(value, struct_pack_format):
    if struct_pack_format.startswith("<") or struct_pack_format.startswith("="):
        bswapped_format = ">%s" % struct_pack_format[1:]
    elif struct_pack_format.startswith(">"):
        bswapped_format = "<%s" % struct_pack_format[1:]
    else:
        bswapped_format = ">%s" % struct_pack_format

    return struct.unpack(bswapped_format,struct.pack("%s" % struct_pack_format, value))[0]

def _get_guid(debug_entry):
    if not hasattr(debug_entry, "Signature_Data5"):
        hex_guid = "%08x%04x%04x%s%x" % ( 
            debug_entry.Signature_Data1, 
            debug_entry.Signature_Data2, 
            debug_entry.Signature_Data3, 
            binascii.hexlify(debug_entry.Signature_Data4).decode('ascii'),
            debug_entry.Age
        )
    else:
        hex_guid = "%08x%04x%04x%04x%04x%08x%x" % ( 
            debug_entry.Signature_Data1, 
            debug_entry.Signature_Data2, 
            debug_entry.Signature_Data3, 
            byte_swap(debug_entry.Signature_Data4, "H"),
            byte_swap(debug_entry.Signature_Data5, "H"),
            byte_swap(debug_entry.Signature_Data6, "I"),
            debug_entry.Age
        )

    return hex_guid.upper()

def _get_debug_entry(pe):

    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_DEBUG']])

    if not hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
        raise ValueError("no debug directory present in the binary file.")

    is_debug_entry = lambda x: x.entry is not None and x.entry.name == 'CV_INFO_PDB70'
    debug_entries = list(filter(is_debug_entry, pe.DIRECTORY_ENTRY_DEBUG))

    if not len(debug_entries):
        raise ValueError("no debug entries present in the binary file.")

    return debug_entries[0].entry

def get_guid(filepath):
    try:
        pe = pefile.PE(filepath, fast_load=True)
    except pefile.PEFormatError as pefe:
        idaapi.msg("Binary file %s is not a valid PE file \n" % filepath)
        idaapi.msg(pefe)
        return

    try:
        debug_entry = _get_debug_entry(pe)
    except AttributeError as ae:
        idaapi.msg("[!]  Binary file %s has no debug entry. Skipping \n" % filepath)
        return
    except ValueError as ve:
        idaapi.msg("[!]  Binary file %s has no debug entry. Skipping \n" % filepath)
        return

    return _get_guid(debug_entry)