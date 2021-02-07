from binaryninja.binaryview import StructuredDataView
from binaryninja.plugin import PluginCommand
from binaryninja.interaction import get_open_filename_input
from binaryninja.log import log_info, log_error
from binaryninja.types import Type, Symbol
from binaryninja.typelibrary import TypeLibrary
from binaryninja.highlevelil import HighLevelILOperation
from androguard.misc import AnalyzeAPK
from collections import namedtuple
import json

from jnianalyzer.jniparser import (
    parse_jni_method_name,
    parse_jni_method_name_full,
    parse_return_type,
    parse_parameter_types,
)


Method = namedtuple(
    "Method", ["class_name", "method_name", "type_descriptor", "is_static"]
)


def run_analysis(apk):
    ret = []
    _, _, analysis = AnalyzeAPK(apk)

    for klass in analysis.get_classes():
        for method in klass.get_methods():
            if "native" in method.access:
                ret.append(
                    Method(
                        method.class_name,
                        method.name,
                        method.descriptor,
                        "static" in method.access,
                    )
                )
    return ret


def build_binja_type_signature(method_name, method, attr):
    t = ""
    t += parse_return_type(method)
    t += " {}".format(method_name)
    t += " (JNIEnv* env, "

    if method.is_static:
        t += "jclass thiz"
    else:
        t += "jobject thiz"

    for count, param in enumerate(parse_parameter_types(method)):
        t += ", {} p{}".format(param, count)

    t += ")"

    if attr:
        t += " {}".format(attr)

    return t


def init_binja(bv):
    log_info("Importing JNI type library")
    typelib = TypeLibrary.from_name(bv.arch, "JNI")
    if typelib == None:
        log_error("JNI type library not found")
        return

    bv.add_type_library(typelib)

    return bv.create_tag_type("JNIAnalyzer", "JNI")


def apply_data_tag(bv, address, tagtype, data):
    tags = bv.get_data_tags_at(address)
    for tag in tags:
        if tag.type.name == tagtype.name:
            break
    else:
        bv.create_user_data_tag(address, tagtype, data)


def apply_function_tag(func, tagtype, data):
    tags = func.function_tags
    for tag in tags:
        if tag.type.name == tagtype.name:
            break
    else:
        func.create_user_function_tag(tagtype, data)


def apply_comment(func, method):
    if "JNIAnalyzer" not in func.comment:
        func.comment = "{}\nJNIAnalyzer:\nClass: {}\nMethod: {}".format(
            func.comment, method.class_name, method.method_name
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


def hlil_check_jnienv_call(ins, offset):
    """Returns True if a HLIL instruction is a call to a JNIEnv* function."""
    if not ins.operation == HighLevelILOperation.HLIL_CALL:
        return False

    ops = ins.operands
    callee = ops[0]

    return (
        callee.operation == HighLevelILOperation.HLIL_DEREF_FIELD
        and str(callee.operands[0].expr_type) == "struct JNINativeInterface_*"
        and callee.operands[2] == offset
    )


def process_findclass_call(bv, ins):
    """Process a FindClass JNI function call and returns the class name.

    This method only works if the class name is a constant within the binary
    and not determined during runtime.
    """
    # 6 == FindClass
    if hlil_check_jnienv_call(ins, 6):
        ops = ins.operands
        callee_args = ops[1]

        if callee_args[1].operation == HighLevelILOperation.HLIL_CONST_PTR:
            return bv.get_ascii_string_at(callee_args[1].value.value, 1)
        else:
            print(callee_args[1])

    return None


def import_apk(bv):
    jnianalyzer_tagtype = init_binja(bv)

    fname = get_open_filename_input("Select APK")
    with open(fname, "rb") as f:
        log_info("Analyzing APK")
        analysis = run_analysis(f)
        log_info("Analysis complete")
        method_map = {}

        for method in analysis:
            method_map[parse_jni_method_name(method)] = method
            method_map[parse_jni_method_name_full(method)] = method

        for f in bv.functions:
            if f.name == "JNI_OnLoad":
                f.function_type = "jint JNI_OnLoad(JavaVM *vm, void *reserved);"
                apply_function_tag(f, jnianalyzer_tagtype, f.name)
                continue

            if f.name == "JNI_OnUnload":
                f.function_type = "void JNI_OnUnload(JavaVM *vm, void *reserved);"
                apply_function_tag(f, jnianalyzer_tagtype, f.name)
                continue

            try:
                method = method_map[f.name]
                log_info("Setting type for: {}".format(f.name))
                attr = str(f.function_type).split(")")[1]
                f.function_type = build_binja_type_signature(f.name, method, attr)
                apply_function_tag(f, jnianalyzer_tagtype, f.name)
                apply_comment(f, method)

            except KeyError:
                continue


def import_trace_registernatives(bv):
    jnianalyzer_tagtype = init_binja(bv)

    fname = get_open_filename_input("Select JSON")
    with open(fname, "rb") as f:
        data = json.load(f)

        for i in data:
            class_name = i["name"]
            methods_ptr = i["methods_ptr"]
            methods_count = i["nMethods"]

            log_info("Setting JNINativeMethod type at {}".format(methods_ptr))
            set_registernatives(
                bv, jnianalyzer_tagtype, class_name, int(methods_ptr, 16), methods_count
            )


def locate_registernatives(bv):
    jnianalyzer_tagtype = init_binja(bv)

    for func in bv.functions:
        hlil = func.hlil

        for ins in hlil.instructions:
            # 215 == RegisterNatives
            if hlil_check_jnienv_call(ins, 215):
                log_info("Found RegisterNatives call in: {}".format(func.name))
                ops = ins.operands
                callee_args = ops[1]
                # class_name = i["name"]
                class_name = process_findclass_call(bv, callee_args[1])
                methods_ptr = callee_args[2].value.value
                methods_count = callee_args[3].value.value

                log_info("Setting JNINativeMethod type at {}".format(hex(methods_ptr)))
                set_registernatives(
                    bv, jnianalyzer_tagtype, class_name, methods_ptr, methods_count
                )


PluginCommand.register(
    "JNIAnalyzer: Import APK",
    "Analyze APK for native method signatures.",
    import_apk,
)

PluginCommand.register(
    "JNIAnalyzer: Import trace_registernatives JSON",
    "Import results from trace_registernatives output.",
    import_trace_registernatives,
)

PluginCommand.register(
    "JNIAnalyzer: Locate RegisterNatives calls",
    "Find RegisterNatives calls through HLIL analysis.",
    locate_registernatives,
)
