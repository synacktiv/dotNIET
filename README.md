<img align="left" width="100" height="115" src="./img/vladimir.png" alt="vladimir">  
&nbsp;
&nbsp;

# .NIET

![Alt text](./img/dotNIET_before_after.png?raw=true "Before After")

*.NIET* is an IDA Pro plugin. Its purpose is to import missing symbols (usually few thousands) which are resolved at runtime by [.NET native](https://docs.microsoft.com/en-us/dotnet/framework/net-native/) compiled binaries. These symbols lie in ```SharedLibrary.dll``` and are not exported by this one.

*.NIET* has been tested on IDA Pro 7.5 using python 3.8 on the following platforms:

* Windows
* Linux

This plugin currently supports the following .NET native framework versions:

* 1.3
* 1.6
* 1.7
* 2.2

**Please create an issue if you encounter another version.**

## Installation

Copy these elements to your IDA Pro plugin directory:

```
dotNIET_plugin.py
dotNIET\
```

## Dependencies

*.NIET* relies on [pefile](https://pypi.org/project/pefile/) in order to parse resources directories.

*pefile* can be installed as follows:

```
pip install pefile
```

## Requirements

Because symbols are imported from ```SharedLibrary.dll```, this one must be provided to *.NIET* **along with its pdb** (its location is searched by the plugin within ```_NT_SYMBOL_PATH```).

Helpers are implemented to identify .NET native framework versions and verifying that ```SharedLibrary.dll``` ```pdb``` exists within the configured symbols path.

## Usage

![Alt text](./img/dotNIET_display.png?raw=true "Display")

*.NIET* can be launch using shortcut ```Alt-Shift-N``` or through the ```Edit/Plugins``` menu.

Upon launch, the plugin tries to identify current binary .NET native framework version. All you have to do is to select ```SharedLibrary.dll``` in the right version then click ```Run```.

*.NIET* will identify target dll .NET native framework version and prompt a message if versions are not the same. **Major and Minor version numbers are usually the only ones that matter.**

## Functioning

*.NIET* looks for .NET native custom import descriptors table within the ```.rdata``` section. To proceed so, it reads at specific offsets of a ```Custom Header``` structure then parses an ordinals array.

This ordinals array points to various locations within a ```SharedLibrary.dll```'s custom table entries.

Symbol resolution is achieved by launching an IDA Pro headless instance through its binary ```idat``` in order to parse to ```SharedLibrary.dll``` ```pdb```

## Imported symbols naming convention

Symbols are imported as is if possible but some corner cases may be encountered:

* sometimes imported addresses are solely ```jmpstubs``` symbols to offsets or single ```jmp``` instructions to symbols. Their symbol name is replaced by *.NIET* to the target function's name prepended with ```jmp_```
* some addresses resolved by the .NET native runtime point to symbols after multiple derefences. If *.NIET* cannot find a symbol at an imported address it tries to dereference until it finds one. ```deref_X``` is appended to this symbol name, if found, with ```X``` being the number of derefs.
* some addresses points to offsets within an ```EETableSection``` table. Being new to .NET native, I have no idea what this is (yet?) so these addresses are labeled ```EETableSection_XXX```, ```XXX``` being offsets from ```EETableSection``` within ```SharedLibrary.dll```

## Known limitations

* Does not work (yet) on macOS IDA Pro version
* *.NIET* is pretty slow as it requires to parse ```pdb``` of fairly huge binaries
* "restore .idata" option (kind of "undo" option) solely unsets imported symbols. Because IDA automagically propagates names during import, you will likely need to run auto-analysis again if you want to remove all traces of imported symbols. A workaround could be to create a database snapshot before running the plugin.
* *.NIET* parses symbols solely from ```SharedLibrary.dll``` module although the original routine in charge of symbols resolution likely offers the possibility to parse other modules (I don't know if this really occurs apart from ```SharedLibrary.dll``` module)

## Troubleshooting

```idat``` *logfile* is defined to ```%tmpdir%/dotNIETlogs.txt```

## Why such a name

Because reversing .NET native is a nightmare