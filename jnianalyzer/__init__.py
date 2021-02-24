from binaryninja.plugin import PluginCommand
from binaryninja.log import log_info, log_error
from binaryninja.typelibrary import TypeLibrary

from jnianalyzer.apkimporter import APKImporter
from jnianalyzer.registernatives import (
    TraceRegisterNativesImporter,
    RegisterNativesAnalysis,
)


def init_binja(bv):
    log_info("Importing JNI type library")
    typelib = TypeLibrary.from_name(bv.arch, "JNI")
    if typelib == None:
        log_error("JNI type library not found")
        return

    bv.add_type_library(typelib)

    return bv.create_tag_type("JNIAnalyzer", "JNI")


def import_apk(bv):
    jnianalyzer_tagtype = init_binja(bv)
    i = APKImporter(bv, jnianalyzer_tagtype)
    i.start()


def import_trace_registernatives(bv):
    jnianalyzer_tagtype = init_binja(bv)
    i = TraceRegisterNativesImporter(bv, jnianalyzer_tagtype)
    i.start()


def registernatives_analysis(bv, func):
    jnianalyzer_tagtype = init_binja(bv)
    i = RegisterNativesAnalysis(bv, func, jnianalyzer_tagtype)
    i.start()


PluginCommand.register(
    "JNIAnalyzer\Import APK",
    "Analyze APK for native method signatures.",
    import_apk,
)

PluginCommand.register(
    "JNIAnalyzer\Import trace_registernatives JSON",
    "Import results from trace_registernatives output.",
    import_trace_registernatives,
)

PluginCommand.register_for_function(
    "JNIAnalyzer\Analyze RegisterNatives calls in current function",
    "Propagate type information from RegisterNatives calls within the current function.",
    registernatives_analysis,
)
