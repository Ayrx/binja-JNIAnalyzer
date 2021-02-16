from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.interaction import get_open_filename_input
from binaryninja.log import log_info, log_error
from binaryninja.typelibrary import TypeLibrary
from binaryninja.highlevelil import HighLevelILOperation

import json

from jnianalyzer.apkimporter import APKImporter
from jnianalyzer.registernatives import (
    TraceRegisterNativesImporter,
    HLILRegisterNativesAnalysis,
)
from jnianalyzer.binja_utils import (
    Method,
    apply_function_tag,
    apply_comment,
    apply_data_tag,
    build_binja_type_signature,
)
from jnianalyzer.jniparser import (
    parse_jni_method_name,
    parse_jni_method_name_full,
    parse_return_type,
    parse_parameter_types,
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


def locate_registernatives(bv):
    jnianalyzer_tagtype = init_binja(bv)
    i = HLILRegisterNativesAnalysis(bv, jnianalyzer_tagtype)
    i.start()


def test(bv):
    func = bv.get_function_at(0x475f08)

    # Save a mapping of identifiers for each parameter
    params = {}
    for p in func.parameter_vars:
        if p.type == "JavaVM*":
            params[p.identifier] = p

    q = []

    hlil = func.hlil
    for ins in hlil.instructions:
        if ins.operation == HighLevelILOperation.HLIL_CALL:
            # Skip processing if the HLIL_CALL is to a runtime function
            if not ins.dest.operation == HighLevelILOperation.HLIL_CONST_PTR:
                continue

            target_func = bv.get_function_at(ins.dest.value.value)

            for index, p in enumerate(ins.params):
                try:
                    param = params[p.var.identifier]
                    q.append((target_func, index, param.type))
                except KeyError:
                    continue


def process_javavm_queue(q):
    for target_func, index, param in q:
        # If the target function only has one caller, it is safe to apply the
        # type information as there can be no conflicts.
        if len(target_func.callers) == 1:
            pass


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

PluginCommand.register(
    "JNIAnalyzer\Locate RegisterNatives calls",
    "Find RegisterNatives calls through HLIL analysis.",
    locate_registernatives,
)

PluginCommand.register(
    "JNIAnalyzer: Experiment",
    "Test.",
    test,
)
