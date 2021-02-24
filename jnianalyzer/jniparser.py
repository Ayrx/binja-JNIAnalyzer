import re

TYPE_REGEX = re.compile(r"\((|.+?)\)(.+)")


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


def parse_return_type(method):
    sig = TYPE_REGEX.match(str(method.type_descriptor)).group(2)
    return parse_type_signature(sig)


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

                # A class is always followed up with a space. Skip that.
                cur = next(sig)

            # Handle arrays
            elif cur == "[":
                param = "["
                cur = next(sig)
                if cur == "L":
                    param += parse_class(sig)
                    ret.append(parse_type_signature(param))
                else:
                    param += cur
                    ret.append(parse_type_signature(param))

                # An array is always followed up with a space. Skip that.
                cur = next(sig)

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
