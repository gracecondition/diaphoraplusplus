# δiaphora++

<p align='center'>
<img src="https://raw.githubusercontent.com/gracecondition/diaphoraplusplus/refs/heads/master/images/logo.png" width="40%">
</p>

Diaphora++ is a fork of Diaphora, the best IDA plugin for diffing binaries.
Since 2024 Diaphora has not recieved any updates, and I found that it was lacking some featuers, so I took it upon myself
to fork the project and add more stuff.
## Unique Features

Diaphora has many of the most common program diffing (bindiffing) features you might expect, like:

 * Diffing assembler.
 * Diffing control flow graphs.
 * Porting symbol names and comments.
 * Adding manual matches.
 * Similarity ratio calculation.
 * Batch automation.
 * Call graph matching calculation.
 * Dozens of heuristics based on graph theory, assembler, bytes, functions' features, etc...

However, Diaphora has also many features that are unique, not available in any other public tool. The following is a non extensive list of unique features:

 * Ability to port structs, enums, unions and typedefs.
 * Potentially fixed vulnerabilities detection for patch diffing sessions.
 * Support for compilation units (finding and diffing compilation units).
 * Microcode support.
 * Parallel diffing.
 * Pseudo-code based heuristics.
 * Pseudo-code patches generation.
 * Diffing pseudo-codes (with syntax highlighting!).
 * Scripting support (for both the exporting and diffing processes).
 * ...

## Diaphora++ improvements
- Significant diffing speed improvements (5x speed)
- Heap size increases to alleviate SQLite reading bottleneck
- SQLite query modifications to increase speed
- orjson for faster json handling
- .diff export of function
- Better UI colors for dark mode
- Search within diff in IDA.

## Installation

Diaphora requires no installation: just download the code and run the script `diaphora.py` from within IDA or on the command line (only for diffing already exported databases). However, it can be integrated as a [plugin](https://github.com/joxeankoret/diaphora/tree/master/plugin) into IDA by doing the following:

 * Copy `plugins/diaphora_plugin.py` and `plugins/diaphora_plugin.cfg` to the IDA's plugins directory.
 * Edit `diaphora_plugin.cfg` and set the path value to the Diaphora's directory.

## Donations

You can help (or thank) the author of Diaphora by making a donation. If you feel like doing so you can use one of the following links:

 * [![Liberapay](https://img.shields.io/liberapay/receives/diaphora.svg?logo=liberapay)](https://liberapay.com/Diaphora/donate)
 * [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=68Z4H8SE7N64L)

## Wiki

If you are looking to how to automate the export or diffing process, or you want to speed operations, etc... You might want to take a look to the [wiki](https://github.com/joxeankoret/diaphora/wiki) where such questions are answered.

## Screenshots

Diaphora++ finding the exact function where a vulnerability was patched in CVE-2025-43200:

![CVE-2025-43200](https://raw.githubusercontent.com/gracecondition/diaphoraplusplus/refs/heads/master/images/screenshot1.png)

Diaphora++, diffing the pseudocode part of the patch:

![CVE-2025-43200](https://raw.githubusercontent.com/gracecondition/diaphoraplusplus/refs/heads/master/images/screenshot2.png)

Diaphora++, diffing another part of the patch:

![CVE-2025-43200](https://raw.githubusercontent.com/gracecondition/diaphoraplusplus/refs/heads/master/images/screenshot4.png)

Diaphora++, assembly diffing view

![CVE-2025-43200](https://raw.githubusercontent.com/gracecondition/diaphoraplusplus/refs/heads/master/images/screenshot3.png)
