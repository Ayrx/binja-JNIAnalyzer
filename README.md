# JNIAnalyzer

This is a Binary Ninja extension contains various scripts that assists in
analyzing Android NDK applications.

This is a port of my [JNIAnalyzer][ghidra-jnianalyzer] Ghidra extension. The
APK parsing is done with [Androguard][androguard] instead of JADX.

## Installation

1. Install Androguard by cloning the git repository and running the `setup.py`
script. The version of Androguard available on PyPI is currently too old to
work.
2. Install [binja-typemanager][binja-typemanager]
and [binja-typelibs-collection][binja-typelibs-collection]. Alternatively, make
the types from the JNI header available to Binary Ninja in another manner.
3. Install the plugin the typical Binary Ninja way. `install_linux.sh` does
the correct things if you are on Linux.

## Usage

### Import APK

Run the "JNIAnalyzer: Import APK" command and select the APK file associated
with the native library being analyzed.

### Import trace_registernatives

Run the "JNIAnalyzer: Import trace_registernatives JSON" command and select
the JSON output from [trace_registernatives][trace_registernatives].

### Binary Ninja Tags

JNI related functions or data structures detected by this extension will be
tagged with "JNIAnalyzer" using Binary Ninja's Tag API which can be viewed
using Binary Ninja's tag browser.

[ghidra-jnianalyzer]: https://github.com/Ayrx/JNIAnalyzer
[androguard]: https://github.com/androguard/androguard
[binja-typemanager]: https://github.com/Ayrx/binja-typemanager
[binja-typelibs-collection]: https://github.com/Ayrx/binja-typelibs-collection
[trace_registernatives]: https://github.com/Ayrx/trace_registernatives
