from collections import namedtuple

from jnianalyzer.jniparser import (
    parse_return_type,
    parse_parameter_types,
)


Method = namedtuple(
    "Method", ["class_name", "method_name", "type_descriptor", "is_static"]
)


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
