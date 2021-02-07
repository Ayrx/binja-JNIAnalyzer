from binaryninja.plugin import BackgroundTaskThread
from binaryninja.interaction import get_open_filename_input
from binaryninja.log import log_info

from androguard.misc import AnalyzeAPK

from jnianalyzer.binja_utils import (
    Method,
    apply_function_tag,
    apply_comment,
    build_binja_type_signature,
)
from jnianalyzer.jniparser import (
    parse_jni_method_name,
    parse_jni_method_name_full,
    parse_return_type,
    parse_parameter_types,
)


class APKImporter(BackgroundTaskThread):
    def __init__(self, bv, jnianalyzer_tagtype):
        BackgroundTaskThread.__init__(self, "Importing APK...", True)
        self.bv = bv
        self.jnianalyzer_tagtype = jnianalyzer_tagtype

    def run(self):
        fname = get_open_filename_input("Select APK")
        with open(fname, "rb") as f:
            log_info("Analyzing APK")
            analysis = self.run_analysis(f)
            log_info("Analysis complete")
            method_map = {}

            for method in analysis:
                method_map[parse_jni_method_name(method)] = method
                method_map[parse_jni_method_name_full(method)] = method

            for f in self.bv.functions:
                if f.name == "JNI_OnLoad":
                    f.function_type = "jint JNI_OnLoad(JavaVM *vm, void *reserved);"
                    apply_function_tag(f, self.jnianalyzer_tagtype, f.name)
                    continue

                if f.name == "JNI_OnUnload":
                    f.function_type = "void JNI_OnUnload(JavaVM *vm, void *reserved);"
                    apply_function_tag(f, self.jnianalyzer_tagtype, f.name)
                    continue

                try:
                    method = method_map[f.name]
                    log_info("Setting type for: {}".format(f.name))
                    attr = str(f.function_type).split(")")[1]
                    f.function_type = build_binja_type_signature(f.name, method, attr)
                    apply_function_tag(f, self.jnianalyzer_tagtype, f.name)
                    apply_comment(f, method)

                except KeyError:
                    continue

    def run_analysis(self, apk):
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
