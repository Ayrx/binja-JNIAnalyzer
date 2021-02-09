from binaryninja.plugin import BackgroundTaskThread
from binaryninja.highlevelil import HighLevelILOperation
from binaryninja.binaryview import StructuredDataView
from binaryninja.interaction import get_open_filename_input
from binaryninja.types import Type, Symbol
from binaryninja.log import log_info

from androguard.misc import AnalyzeAPK
import json

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


def set_registernatives(
    bv, jnianalyzer_tagtype, class_name, methods_ptr, methods_count
):
    class_name_array = "{}_METHODS_ARRAY".format(class_name)

    # Set JNINativeMethod type
    t = bv.get_type_by_name("JNINativeMethod")
    t_size = t.width
    t = Type.array(t, methods_count)
    bv.define_user_data_var(methods_ptr, t)

    # Set function signature
    for i in range(0, methods_count):
        ptr = methods_ptr + (i * t_size)
        data = StructuredDataView(bv, "JNINativeMethod", ptr)

        method_name = str(bv.get_ascii_string_at(data.name.int, 1))
        fn_ptr = data.fnPtr.int
        signature = str(bv.get_ascii_string_at(data.signature.int, 1))

        method = Method(
            class_name,
            method_name,
            signature,
            False,
        )

        f = bv.get_function_at(fn_ptr)
        attr = str(f.function_type).split(")")[1]
        log_info("Setting type for: {}".format(f.name))
        f.function_type = build_binja_type_signature(f.name, method, attr)
        apply_function_tag(f, jnianalyzer_tagtype, f.name)
        apply_comment(f, method)

    # Set symbol for array
    sym = Symbol("DataSymbol", methods_ptr, class_name_array)
    bv.define_user_symbol(sym)

    # Set tag
    apply_data_tag(bv, methods_ptr, jnianalyzer_tagtype, class_name_array)


class TraceRegisterNativesImporter(BackgroundTaskThread):
    def __init__(self, bv, jnianalyzer_tagtype):
        BackgroundTaskThread.__init__(self, "Importing trace_registernatives...", True)
        self.bv = bv
        self.jnianalyzer_tagtype = jnianalyzer_tagtype

    def run(self):
        fname = get_open_filename_input("Select JSON")
        with open(fname, "rb") as f:
            data = json.load(f)

            for i in data:
                class_name = i["name"]
                methods_ptr = i["methods_ptr"]
                methods_count = i["nMethods"]

                log_info("Setting JNINativeMethod type at {}".format(methods_ptr))
                set_registernatives(
                    self.bv,
                    self.jnianalyzer_tagtype,
                    class_name,
                    int(methods_ptr, 16),
                    methods_count,
                )


class HLILRegisterNativesAnalysis(BackgroundTaskThread):
    def __init__(self, bv, jnianalyzer_tagtype):
        BackgroundTaskThread.__init__(self, "Running HLIL analysis...", True)
        self.bv = bv
        self.jnianalyzer_tagtype = jnianalyzer_tagtype

    def run(self):
        for func in self.bv.functions:
            hlil = func.hlil

            for ins in hlil.instructions:
                # 215 == RegisterNatives
                if self.hlil_check_jnienv_call(ins, 215):
                    log_info("Found RegisterNatives call in: {}".format(func.name))
                    callee_args = ins.params
                    class_name = self.process_findclass_call(callee_args[1])
                    methods_ptr = callee_args[2].value.value
                    methods_count = callee_args[3].value.value

                    log_info(
                        "Setting JNINativeMethod type at {}".format(hex(methods_ptr))
                    )
                    set_registernatives(
                        self.bv,
                        self.jnianalyzer_tagtype,
                        class_name,
                        methods_ptr,
                        methods_count,
                    )

    def hlil_check_jnienv_call(self, ins, offset):
        """Returns True if a HLIL instruction is a call to a JNIEnv* function."""
        if not ins.operation == HighLevelILOperation.HLIL_CALL:
            return False

        callee = ins.dest

        return (
            callee.operation == HighLevelILOperation.HLIL_DEREF_FIELD
            and str(callee.src.expr_type) == "struct JNINativeInterface_*"
            and callee.member_index == offset
        )

    def process_findclass_call(self, ins):
        """Process a FindClass JNI function call and returns the class name.

        This method only works if the class name is a constant within the binary
        and not determined during runtime.
        """
        # 6 == FindClass
        if self.hlil_check_jnienv_call(ins, 6):
            callee_args = ins.params

            if callee_args[1].operation == HighLevelILOperation.HLIL_CONST_PTR:
                return self.bv.get_ascii_string_at(callee_args[1].value.value, 1)
            else:
                print(callee_args[1])

        return None
