from binaryninja.plugin import PluginCommand
from binaryninja.interaction import get_open_filename_input
from binaryninja.log import log_info, log_error
from binaryninja.types import Type, Symbol
from binaryninja.typelibrary import TypeLibrary
from androguard.misc import AnalyzeAPK
from collections import namedtuple
import re
import json

TYPE_REGEX = re.compile(r"\((|.+?)\)(.+?)")


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


def parse_jni_method_name(method):
    ret = "Java_"
    ret += mangle(str(method.class_name)[1:-1]).replace("/", "_")
    ret += "_"
    ret += mangle(str(method.method_name))
    return ret


def parse_jni_method_name_full(method):
    ret = parse_jni_method_name(method)
    ret += "__"
    ret += mangle(parse_parameter_signature(method)).replace("/", "_")
    return ret


def parse_return_type(method):
    sig = TYPE_REGEX.match(str(method.type_descriptor)).group(2)
    return parse_type_signature(sig)


def mangle(string):
    ret = ""
    for c in string:
        if c == "_":
            ret += "_1"
        elif c == ";":
            ret += "_2"
        elif c == "[":
            ret += "_3"
        elif c == "$":
            # "$" is an Androguard representation of a inner class. We can
            # just replace it with a "_".
            ret += "_"
        else:
            i = ord(c)

            if i < 128:
                # Ascii
                ret += c
            else:
                # Unicode
                ret += "_0{:04x}".format(i)

    return ret


def parse_parameter_signature(method):
    return TYPE_REGEX.match(str(method.type_descriptor)).group(1)


def parse_parameter_types(method):
    sig = parse_parameter_signature(method)
    sig = iter(sig)

    ret = []
    while True:
        try:
            cur = next(sig)

            # Handle class
            if cur == "L":
                ret.append(parse_type_signature(parse_class(sig)))

            # Handle arrays
            if cur == "[":
                param = "["
                cur = next(sig)
                if cur == "L":
                    param += parse_class(sig)
                    ret.append(parse_type_signature(param))
                else:
                    param += cur
                    ret.append(parse_type_signature(param))

            # Handle primitive types
            else:
                ret.append(parse_type_signature(cur))
        except StopIteration:
            break

    return ret


def parse_class(sig_iter):
    param = "L"
    while True:
        cur = next(sig_iter)
        param += cur
        if cur == ";":
            return param


def parse_type_signature(sig):
    if sig == "Z":
        return "jboolean"
    elif sig == "B":
        return "jbyte"
    elif sig == "C":
        return "jchar"
    elif sig == "S":
        return "jshort"
    elif sig == "I":
        return "jint"
    elif sig == "J":
        return "jlong"
    elif sig == "F":
        return "jfloat"
    elif sig == "D":
        return "jdouble"
    elif sig.startswith("L"):
        sig = sig[1:-1]
        if sig == "java/lang/String":
            return "jstring"
        elif sig == "java/lang/Class":
            return "jclass"
        else:
            return "jobject"
    elif sig.startswith("["):
        sig = sig[1]
        if sig == "Z":
            return "jbooleanArray"
        elif sig == "B":
            return "jbyteArray"
        elif sig == "C":
            return "jcharArray"
        elif sig == "S":
            return "jshortArray"
        elif sig == "I":
            return "jintArray"
        elif sig == "J":
            return "jlongArray"
        elif sig == "F":
            return "jfloatArray"
        elif sig == "D":
            return "jdoubleArray"
        else:
            return "jobjectArray"

    return "void"


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

    return bv.create_tag_type("JNIAnalyzer", u"🥃")


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
                f.create_user_function_tag(jnianalyzer_tagtype, f.name)
                continue

            if f.name == "JNI_OnUnload":
                f.function_type = "void JNI_OnUnload(JavaVM *vm, void *reserved);"
                f.create_user_function_tag(jnianalyzer_tagtype, f.name)
                continue

            try:
                method = method_map[f.name]
                log_info("Setting type for: {}".format(f.name))
                attr = str(f.function_type).split(")")[1]
                f.function_type = build_binja_type_signature(f.name, method, attr)
                f.create_user_function_tag( jnianalyzer_tagtype, f.name)

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

            methods_ptr_int = int(methods_ptr, 16)
            class_name_array = "{}_METHODS_ARRAY".format(class_name)

            log_info("Setting JNINativeMethod type at {}".format(methods_ptr))

            # Set JNINativeMethod type
            t = bv.get_type_by_name("JNINativeMethod")
            t = Type.array(t, methods_count)
            bv.define_user_data_var(methods_ptr_int, t)

            # Set symbol for array
            sym = Symbol("DataSymbol", methods_ptr_int, class_name_array)
            bv.define_user_symbol(sym)

            # Set tag
            bv.create_user_data_tag(methods_ptr_int, jnianalyzer_tagtype, class_name_array)


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
