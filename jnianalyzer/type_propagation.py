from binaryninja.log import log_info
from binaryninja.enums import MediumLevelILOperation
from binaryninja.types import FunctionParameter, Type

from jnianalyzer.visitor import MLILVisitor


class VariableTracer(MLILVisitor):
    def __init__(self, bv, mlil):
        super().__init__(raise_unimplemented=False)
        self.mlil = mlil

    def MLIL_SET_VAR_SSA(self, ins):
        return self.visit(ins.src)

    def MLIL_VAR_SSA(self, ins):
        vardef = self.mlil.get_ssa_var_definition(ins.src)
        if vardef:
            return self.visit(vardef)

        return ins


class TypePropagationVisitor(MLILVisitor):
    def __init__(self, bv, mlil, params):
        super().__init__(raise_unimplemented=False)

        self.bv = bv
        self.mlil = mlil
        self.params = params
        self.callsites = []

    def MLIL_CALL_SSA(self, ins):
        if ins.dest.operation != MediumLevelILOperation.MLIL_CONST_PTR:
            return None

        target_func = self.bv.get_function_at(ins.dest.value.value)
        for index, p in enumerate(ins.params):
            t = self.visit(p)
            if t:
                self.callsites.append((target_func, index, t))

    def MLIL_VAR_SSA(self, ins):
        tracer = VariableTracer(self.bv, self.mlil)
        var = tracer.visit(ins)

        if var is None:
            return None

        try:
            return self.params[var.src.var.identifier].type
        except KeyError:
            return None

    def MLIL_CONST(self, ins):
        pass


def propagate_type(bv, func):
    # Save a mapping of identifiers for each parameter
    params = {}
    for p in func.parameter_vars:
        if str(p.type) == "JavaVM*" or str(p.type) == "JNIEnv*":
            params[p.identifier] = p

    visitor = TypePropagationVisitor(bv, func.mlil.ssa_form, params)
    for ins in func.mlil.ssa_form.instructions:
        visitor.visit(ins)

    process_javavm_queue(visitor.callsites)


def process_javavm_queue(q):
    for target_func, index, param_type in q:
        # If the target function only has one caller, it is safe to apply the
        # type information as there can be no conflicts.
        if len(target_func.callers) == 1:
            old = target_func.function_type
            new_params = []
            for var, params in zip(target_func.parameter_vars, old.parameters):
                new_params.append([var.type, params.name, params.location])

            p = new_params[index]
            p[0] = param_type

            if str(param_type) == "JavaVM*":
                p[1] = "vm"
            else:
                p[1] = "env"

            log_info(
                "Setting {} type for: {}".format(str(param_type), target_func.name)
            )

            params = [FunctionParameter(p[0], p[1], p[2]) for p in new_params]
            target_func.function_type = Type.function(
                old.return_value,
                params,
                old.calling_convention,
                old.has_variable_arguments,
                old.stack_adjustment,
            )

