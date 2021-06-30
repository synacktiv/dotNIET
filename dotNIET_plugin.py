# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay@synacktiv.com> wrote this file. As long as you 
# retain this notice you can do whatever you want with this stuff. 
# If we meet some day, and you think this stuff is worth it, you can buy me a
# beer in return
# ----------------------------------------------------------------------------

import os, shutil, tempfile, subprocess
from collections import defaultdict

import idaapi, idc, idautils, ida_kernwin, ida_pro
from idaapi import PluginForm
from ida_name import SN_NOCHECK, SN_FORCE, SN_NODUMMY

from PyQt5 import QtCore, QtWidgets
from dotNIET import utils


dotnet_versions_offsets = defaultdict(dict)
dotnet_versions_offsets["1.3"] = {"nbCustomModules" : 0x124, "ImportDescriptors" : 0x120}
dotnet_versions_offsets["1.6"] = {"nbCustomModules" : 0x124, "ImportDescriptors" : 0x120}
dotnet_versions_offsets["1.7"] = {"nbCustomModules" : 0x124, "ImportDescriptors" : 0x120}
dotnet_versions_offsets["2.2"] = {"nbCustomModules" : 0x10C, "ImportDescriptors" : 0x108}

class CustomImportDescriptor:
    def __init__(self, **kwds):
        self.__dict__.update(kwds)


class dotNIET():
    def __init__(self, dotnet_version):
        self.dotnet_version = dotnet_version
        self.imagebase = idaapi.get_imagebase()
        self.module_header_struct = idaapi.get_segm_by_name(".rdata").start_ea
        self.nb_custom_modules = idaapi.get_dword(self.module_header_struct + \
                                 dotnet_versions_offsets[self.dotnet_version]\
                                 ["nbCustomModules"])

    def get_modules_info(self):
        if self.nb_custom_modules == 1:
            idaapi.msg("This binary does not have any custom imports\n")

        import_descriptors_offset = self.module_header_struct + \
                                    idaapi.get_dword(self.module_header_struct 
                                    + dotnet_versions_offsets[self.dotnet_version]\
                                    ["ImportDescriptors"])
        # this array contains structs describing, EAT, IAT and CountIAT of the 
        # modules to be treated for import
        import_descriptors = []
        for i in range(self.nb_custom_modules):
            import_descriptors.append(CustomImportDescriptor(\
            RvaEAT=idaapi.get_dword(import_descriptors_offset + i * 12),
            RvaIAT=idaapi.get_dword(import_descriptors_offset + i * 12 + 4),
            CountIAT=idaapi.get_dword(import_descriptors_offset + i * 12 + 8)))

        # only get SharedLibrary.dll imports. Could there be some more?
        # first entry is the app itself
        assert import_descriptors[0].RvaEAT == import_descriptors[0].RvaIAT \
               and import_descriptors[0].CountIAT == 0

        # First module should not be checked. Now we check that this belongs 
        # to SharedLibrary.dll
        self.eat_addr = self.imagebase + import_descriptors[1].RvaEAT
        # This is the first symbol from the CustomExportSection of SharedLibrary.dll
        assert idc.get_name(self.eat_addr) == "$NEAT$"

        self.ordinals = self.imagebase + import_descriptors[1].RvaIAT
        self.nb_symbols = import_descriptors[1].CountIAT

    def resolve_symbols(self, dll):
        tmpdir  = tempfile.gettempdir().replace('\\','/') + '/'
        # File who will first contain ordinals then symbols
        tmpfile = tmpdir + "dotNIETsymbols.txt"
        tmplog = tmpdir + "dotNIETlogs.txt"
        # Destination path for a copy of SharedLibrary.dll
        tmpdll = tmpdir + os.path.basename(dll)
        # Path to the idat binary, needed to parse a remote idb
        idat = idc.idadir().replace('\\','/') + '/' + 'idat' + \
               ['64' if utils.is_x64(dll) else ''][0]

        if os.getenv("windir") is not None:
            idat += '.exe'
        # script called along with idat in order to parse SharedLibrary.idb
        parsing_script_path = '"' + os.path.dirname(os.path.realpath(__file__)).replace('\\','/')\
                              + '/dotNIET/resolve.py"'

        # we first copy SharedLibrary.dll to tmp to be sure we are in a 
        # writable location
        shutil.copyfile(dll, tmpdll)

        # we have to use temporary files because of the ida headless stuff...
        # pretty dirty
        ordinals = []
        with open(tmpfile, 'w') as f:
            for i in range(self.nb_symbols):
                ordinals.append((idaapi.get_qword(self.ordinals + i * 8) & ~0x8000000000000000)*4)
            f.write(",".join([str(x) for x in ordinals]))

        # be prepared to wait as this will load the binary + pdb
        idaapi.msg("Starting parsing of %d symbols...\n" % self.nb_symbols)
        subprocess.run([idat, "-L" + tmplog, "-c", "-A", "-S" + \
                        parsing_script_path + " " + tmpfile, tmpdll], 
                        creationflags=subprocess.CREATE_NO_WINDOW,
                        check=True)

        # we read back tmpfile which now contains symbols
        symbols = []
        with open(tmpfile, 'r') as f:
            symbolsArray = f.read()
            symbols = symbolsArray.split(',')

        # we first have to undef structure as it is an array and ida will 
        # refuse to set names within it
        idc.del_items(self.ordinals)
        idc.set_cmt(self.ordinals - 8, "Custom imports from SharedLibrary.dll", 0)
        # we then apply the symbols at this very same location (start of .idata)
        for i in range(self.nb_symbols):
            idc.set_name(self.ordinals + i*8, symbols[i], SN_NOCHECK|SN_FORCE|SN_NODUMMY)

        # finally we remove our temp files
        os.remove(tmpfile)
        os.remove(tmpdll)
        # ida generate a db
        os.remove(tmpdll + '.i64')
        # if everything went smoothly, we should not need this anymore
        os.remove(tmplog)


class dotNIETForm_t(PluginForm):
    def cb_btn_run(self):
        if self.dotnet_version_full == "unknown":
            ida_kernwin.warning(".NET Native framework could not be identified.\n"\
                                ".NIET needs it to work properly.")
            return
        # self.dotnet_version_full[:3] is "major.minor"
        if not self.dotnet_version_full[:3] in dotnet_versions_offsets:
            ida_kernwin.warning(".NIET currently does not support %s, please "\
                                "create an issue.")
            return

        instance = dotNIET(self.dotnet_version_full[:3])
        instance.get_modules_info()

        # if "restore" is checked, everything else is greyed out
        if self.cb_restore.checkState() == QtCore.Qt.Checked:
            ida_kernwin.show_wait_box("HIDECANCEL\nClearing symbol names...")
            for i in range(instance.nb_symbols):
                # unset name of imports
                idc.set_name(instance.ordinals + i*8, "")
            idaapi.msg("%d symbols removed!\n" % instance.nb_symbols)
        else :
            if self.dll_input_path.text() == "":
                idaapi.msg("Error: \"SharedLibrary.dll\" path must be selected\n")
                del instance
                return
            # target SharedLibrary.dll .NET framework version is asked to be checked
            if self.cb_verify.checkState() == QtCore.Qt.Checked:
                ida_kernwin.show_wait_box("HIDECANCEL\nVerifying target dll "\
                                          ".NET Native framework version...")
                dll_dotnet_version_full = utils.get_NET_Native_version(self.dll_input_path.text())
                ida_kernwin.hide_wait_box()
                if dll_dotnet_version_full == "unknown" \
                   or dll_dotnet_version_full != self.dotnet_version_full:
                    answer = ida_kernwin.ask_buttons("", "","", 1, "HIDECANCEL\n"\
                                                    "Target dll .NET Native "\
                                                    "framework version is '%s' "\
                                                    "whereas current binary one "\
                                                    "is '%s'.\nProceed anyway?" \
                                                    % (dll_dotnet_version_full,\
                                                    self.dotnet_version_full))
                    # "No" or "cancel/escape"
                    if not answer:
                        return
            # getting target SharedLibrary.dll GUID to verify that the pdb does 
            # exist and is the right one
            ida_kernwin.show_wait_box("HIDECANCEL\nGetting pdb information...")
            if not utils.find_pdb(self.dll_input_path.text()):
                ida_kernwin.hide_wait_box()
                del instance
                return

            # everything is okay, ready to import
            ida_kernwin.replace_wait_box("HIDECANCEL\nImporting symbols...")
            instance.resolve_symbols(self.dll_input_path.text())
            idaapi.msg("%d symbols imported at 0x%x\n" % (instance.nb_symbols, 
                       instance.ordinals))
        ida_kernwin.hide_wait_box()
        del instance

    def cb_btn_browse(self):
        dll = QtWidgets.QFileDialog.getOpenFileName(None, "Select a file...", './',
                                                    filter="*.dll;;All Files (*)")
        if isinstance(dll, tuple):
            self.dll_input_path.setText(str(dll[0]))
        else:
            self.dll_input_path.setText(str(dll))

    def cb_restore_toggle(self, state):
        if state == QtCore.Qt.Checked:
            self.btn_browse.setEnabled(False)
            self.dll_input_path.setEnabled(False)
            self.cb_verify.setEnabled(False)
        else :
            self.btn_browse.setEnabled(True)
            self.dll_input_path.setEnabled(True)
            self.cb_verify.setEnabled(True)

    def OnCreate(self, form):
        # get parent widget
        parent = self.FormToPyQtWidget(form)

        # checkboxes
        self.cb_restore = QtWidgets.QCheckBox('Restore .idata section')
        self.cb_restore.move(20, 20)
        self.cb_restore.stateChanged.connect(self.cb_restore_toggle)

        self.cb_verify = QtWidgets.QCheckBox("Verify target dll .NET Native "\
                                             "framework version")
        self.cb_verify.move(20, 20)
        # default is checked
        self.cb_verify.toggle()

        label_sharedlibrary = QtWidgets.QLabel("Path to target dll "\
                                               "(SharedLibrary.dll):")
        # create input field for SharedLibrary.dll
        self.dll_input_path = QtWidgets.QLineEdit(parent)
        self.dll_input_path.setMaxLength = 256
        self.dll_input_path.setFixedWidth(300)

        # create buttons
        self.btn_run = QtWidgets.QPushButton("Run", parent)
        self.btn_run.setToolTip("Proceed to import or restore.")
        self.btn_run.clicked.connect(self.cb_btn_run)

        self.btn_browse = QtWidgets.QPushButton("Browse", parent)
        self.btn_browse.setToolTip('Browse to "SharedLibrary.dll" location.')
        self.btn_browse.clicked.connect(self.cb_btn_browse)

        # we try to guess .NET Native framework version
        ida_kernwin.show_wait_box("HIDECANCEL\nIdentifying .NET "\
                                  "Native framework version...")
        dotnet_version_full_text = ".NET Native framework version: "
        dotnet_version_full = "unknown"
        if not os.path.exists(idc.get_input_file_path()):
            ida_kernwin.warning("%s could not be found.\n.NIET must identify .NET"\
                                " Native framework version of the original binary "\
                                "in order to work properly."\
                                % idc.get_input_file_path())
        else:
            dotnet_version_full = utils.get_NET_Native_version(idc.get_input_file_path())
            if dotnet_version_full == "unknown":
                ida_kernwin.warning(".NET Native framework could not be identified.\n"\
                                    ".NIET needs it to work properly.")

            self.dotnet_version_full = dotnet_version_full
            dotnet_version_full_text += dotnet_version_full
        ida_kernwin.hide_wait_box()
        label_dotnet_version_full = QtWidgets.QLabel(dotnet_version_full_text)

        # then we check if SharedLibrary.dll is an import
        imported_modules = [idaapi.get_import_module_name(i) for i in range(idaapi.get_import_module_qty())]
        if not "SharedLibrary" in imported_modules:
            ida_kernwin.warning("This binary does not import symbols from "
                                "'SharedLibrary.dll' at runtime.\n.NIET is not"\
                                " required")

        # create layout
        spacerItem = QtWidgets.QSpacerItem(5, 16)
        layout = QtWidgets.QGridLayout()
        layout.addWidget(label_dotnet_version_full, 0, 0)
        layout.addItem(spacerItem)
        layout.addWidget(label_sharedlibrary, 1, 0)
        layout.addWidget(self.dll_input_path, 2, 0)
        layout.addWidget(self.btn_browse, 2, 1)
        spacerItem = QtWidgets.QSpacerItem(5, 16)
        layout.addItem(spacerItem)
        layout.addWidget(self.cb_restore, 4, 0)
        layout.addWidget(self.btn_run, 5, 0)
        layout.addWidget(self.cb_verify, 5, 1, 1, 2)
        layout.setColumnStretch(4, 1)
        layout.setRowStretch(6, 1)
        parent.setLayout(layout)

    def OnClose(self, form):
        global dotNIETForm
        del dotNIETForm

    def Show(self):
        return PluginForm.Show(self, ".NIET", options=PluginForm.WOPN_PERSIST)


class dotNIETplugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = ""
    help = ""
    wanted_name = ".NIET"
    wanted_hotkey = "Alt-Shift-N"

    def init(self):
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        global dotNIETForm
        dotNIETForm = dotNIETForm_t()
        dotNIETForm.Show()

    def term(self):
        pass

def PLUGIN_ENTRY():
    return dotNIETplugin()
