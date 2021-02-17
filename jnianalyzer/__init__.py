from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.interaction import get_open_filename_input
from binaryninja.log import log_info, log_error
from binaryninja.typelibrary import TypeLibrary
from binaryninja.enums import MediumLevelILOperation
from binaryninja.types import FunctionParameter, Type

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
from jnianalyzer.visitor import MLILVisitor


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


class CallVisitor(MLILVisitor):

    def __init__(self, bv, mlil params):
        super().__init__(raise_unimplemented=False)

        self.bv = bv
        self.mlil = mlil
        self.params = params
        self.callsites = []

    def MLIL_CALL(self, ins):
        if ins.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
            return None

        target_func = self.bv.get_function_at(ins.dest.value.value)
        for index, p in enumerate(ins.params):
            t = self.visit(p)
            if t:
                self.callsites.append((target_func, index, t))

    def MLIL_VAR(self, ins):
        try:
            return self.params[ins.src.identifier].type
        except KeyError:
            return None

    def MLIL_CONST(self, ins):
        pass


def test(bv):
    func = bv.get_function_at(0x460384)

    # Save a mapping of identifiers for each parameter
    params = {}
    for p in func.parameter_vars:
        if str(p.type) == "JavaVM*":
            params[p.identifier] = p

    visitor = CallVisitor(bv, func.mlil, params)
    for ins in func.mlil.instructions:
        visitor.visit(ins)

    process_javavm_queue(visitor.callsites)


def process_javavm_queue(q):
    log_info(str(q))
    for target_func, index, param_type in q:
        # If the target function only has one caller, it is safe to apply the
        # type information as there can be no conflicts.
        if len(target_func.callers) == 1:
            log_info("Setting type information for: {}".format(target_func.name))

            old = target_func.function_type
            new_params = []
            for var, params in zip(target_func.parameter_vars, old.parameters):
                new_params.append([var.type, params.name, params.location])

            p = new_params[index]
            p[0] = param_type
            p[1] = "vm"

            params = [FunctionParameter(p[0], p[1], p[2]) for p in new_params]
            target_func.function_type = Type.function(
                old.return_value,
                params,
                old.calling_convention,
                old.has_variable_arguments,
                old.stack_adjustment,
            )


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
