from binaryninja.log import log_debug


class UnknownILOpException(Exception):
    def __init__(self, message):
        super().__init__(message)


class ILOpUnimplementedException(Exception):
    def __init__(self, message):
        super().__init__("{} is unimplemented".format(message))


class MLILVisitor(object):
    def __init__(self, raise_unimplemented=True):
        self.raise_unimplemented = raise_unimplemented

    def visit(self, ins):
        if hasattr(self, ins.operation.name):
            try:
                return getattr(self, ins.operation.name)(ins)
            except ILOpUnimplementedException as e:
                log_debug(str(e))
        else:
            raise UnknownILOpException("{} is an unknown operation")

    def MLIL_JUMP(self, ins):
        raise ILOpUnimplementedException("MLIL_JUMP")

    def MLIL_JUMP_TO(self, ins):
        raise ILOpUnimplementedException("MLIL_JUMP_TO")

    def MLIL_CALL(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL")

    def MLIL_CALL_UNTYPED(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_UNTYPED")

    def MLIL_CALL_OUTPUT(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_OUTPUT")

    def MLIL_CALL_PARAM(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_PARAM")

    def MLIL_RET(self, ins):
        raise ILOpUnimplementedException("MLIL_RET")

    def MLIL_RET_HINT(self, ins):
        raise ILOpUnimplementedException("MLIL_RET_HINT")

    def MLIL_NORET(self, ins):
        raise ILOpUnimplementedException("MLIL_NORET")

    def MLIL_IF(self, ins):
        raise ILOpUnimplementedException("MLIL_IF")

    def MLIL_GOTO(self, ins):
        raise ILOpUnimplementedException("MLIL_GOTO")

    def MLIL_TAILCALL(self, ins):
        raise ILOpUnimplementedException("MLIL_TAILCALL")

    def MLIL_SYSCALL(self, ins):
        raise ILOpUnimplementedException("MLIL_SYSCALL")

    def MLIL_SYSCALL_UNTYPED(self, ins):
        raise ILOpUnimplementedException("MLIL_SYSCALL_UNTYPED")

    def MLIL_SET_VAR(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR")

    def MLIL_SET_VAR_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_FIELD")

    def MLIL_SET_VAR_SPLIT(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_SPLIT")

    def MLIL_LOAD(self, ins):
        raise ILOpUnimplementedException("MLIL_LOAD")

    def MLIL_LOAD_STRUCT(self, ins):
        raise ILOpUnimplementedException("MLIL_LOAD_STRUCT")

    def MLIL_STORE(self, ins):
        raise ILOpUnimplementedException("MLIL_STORE")

    def MLIL_STORE_STRUCT(self, ins):
        raise ILOpUnimplementedException("MLIL_STORE_STRUCT")

    def MLIL_VAR(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR")

    def MLIL_VAR_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_FIELD")

    def MLIL_VAR_SPLIT(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_SPLIT")

    def MLIL_ADDRESS_OF(self, ins):
        raise ILOpUnimplementedException("MLIL_ADDRESS_OF")

    def MLIL_ADDRESS_OF_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_ADDRESS_OF_FIELD")

    def MLIL_CONST(self, ins):
        raise ILOpUnimplementedException("MLIL_CONST")

    def MLIL_CONST_PTR(self, ins):
        raise ILOpUnimplementedException("MLIL_CONST_PTR")

    def MLIL_EXTERN_PTR(self, ins):
        raise ILOpUnimplementedException("MLIL_EXTERN_PTR")

    def MLIL_FLOAT_CONST(self, ins):
        raise ILOpUnimplementedException("MLIL_FLOAT_CONST")

    def MLIL_IMPORT(self, ins):
        raise ILOpUnimplementedException("MLIL_IMPORT")

    def MLIL_LOW_PART(self, ins):
        raise ILOpUnimplementedException("MLIL_LOW_PART")

    def MLIL_ADD(self, ins):
        raise ILOpUnimplementedException("MLIL_ADD")

    def MLIL_ADC(self, ins):
        raise ILOpUnimplementedException("MLIL_ADC")

    def MLIL_SUB(self, ins):
        raise ILOpUnimplementedException("MLIL_SUB")

    def MLIL_SBB(self, ins):
        raise ILOpUnimplementedException("MLIL_SBB")

    def MLIL_AND(self, ins):
        raise ILOpUnimplementedException("MLIL_AND")

    def MLIL_OR(self, ins):
        raise ILOpUnimplementedException("MLIL_OR")

    def MLIL_XOR(self, ins):
        raise ILOpUnimplementedException("MLIL_XOR")

    def MLIL_LSL(self, ins):
        raise ILOpUnimplementedException("MLIL_LSL")

    def MLIL_LSR(self, ins):
        raise ILOpUnimplementedException("MLIL_LSR")

    def MLIL_ASR(self, ins):
        raise ILOpUnimplementedException("MLIL_ASR")

    def MLIL_ROL(self, ins):
        raise ILOpUnimplementedException("MLIL_ROL")

    def MLIL_RLC(self, ins):
        raise ILOpUnimplementedException("MLIL_RLC")

    def MLIL_ROR(self, ins):
        raise ILOpUnimplementedException("MLIL_ROR")

    def MLIL_RRC(self, ins):
        raise ILOpUnimplementedException("MLIL_RRC")

    def MLIL_MUL(self, ins):
        raise ILOpUnimplementedException("MLIL_MUL")

    def MLIL_MULU_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_MULU_DP")

    def MLIL_MULS_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_MULS_DP")

    def MLIL_DIVU(self, ins):
        raise ILOpUnimplementedException("MLIL_DIVU")

    def MLIL_DIVU_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_DIVU_DP")

    def MLIL_DIVS(self, ins):
        raise ILOpUnimplementedException("MLIL_DIVS")

    def MLIL_DIVS_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_DIVS_DP")

    def MLIL_MODU(self, ins):
        raise ILOpUnimplementedException("MLIL_MODU")

    def MLIL_MODU_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_MODU_DP")

    def MLIL_MODS(self, ins):
        raise ILOpUnimplementedException("MLIL_MODS")

    def MLIL_MODS_DP(self, ins):
        raise ILOpUnimplementedException("MLIL_MODS_DP")

    def MLIL_NEG(self, ins):
        raise ILOpUnimplementedException("MLIL_NEG")

    def MLIL_NOT(self, ins):
        raise ILOpUnimplementedException("MLIL_NOT")

    def MLIL_FADD(self, ins):
        raise ILOpUnimplementedException("MLIL_FADD")

    def MLIL_FSUB(self, ins):
        raise ILOpUnimplementedException("MLIL_FSUB")

    def MLIL_FMUL(self, ins):
        raise ILOpUnimplementedException("MLIL_FMUL")

    def MLIL_FDIV(self, ins):
        raise ILOpUnimplementedException("MLIL_FDIV")

    def MLIL_FSQRT(self, ins):
        raise ILOpUnimplementedException("MLIL_FSQRT")

    def MLIL_FNEG(self, ins):
        raise ILOpUnimplementedException("MLIL_FNEG")

    def MLIL_FABS(self, ins):
        raise ILOpUnimplementedException("MLIL_FABS")

    def MLIL_FLOAT_TO_INT(self, ins):
        raise ILOpUnimplementedException("MLIL_FLOAT_TO_INT")

    def MLIL_INT_TO_FLOAT(self, ins):
        raise ILOpUnimplementedException("MLIL_INT_TO_FLOAT")

    def MLIL_FLOAT_CONV(self, ins):
        raise ILOpUnimplementedException("MLIL_FLOAT_CONV")

    def MLIL_ROUND_TO_INT(self, ins):
        raise ILOpUnimplementedException("MLIL_ROUND_TO_INT")

    def MLIL_FLOOR(self, ins):
        raise ILOpUnimplementedException("MLIL_FLOOR")

    def MLIL_CEIL(self, ins):
        raise ILOpUnimplementedException("MLIL_CEIL")

    def MLIL_FTRUNC(self, ins):
        raise ILOpUnimplementedException("MLIL_FTRUNC")

    def MLIL_SX(self, ins):
        raise ILOpUnimplementedException("MLIL_SX")

    def MLIL_ZX(self, ins):
        raise ILOpUnimplementedException("MLIL_ZX")

    def MLIL_ADD_OVERFLOW(self, ins):
        raise ILOpUnimplementedException("MLIL_ADD_OVERFLOW")

    def MLIL_CMP_E(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_E")

    def MLIL_CMP_NE(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_NE")

    def MLIL_CMP_SLT(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_SLT")

    def MLIL_CMP_ULT(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_ULT")

    def MLIL_CMP_SLE(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_SLE")

    def MLIL_CMP_ULE(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_ULE")

    def MLIL_CMP_SGE(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_SGE")

    def MLIL_CMP_UGE(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_UGE")

    def MLIL_CMP_SGT(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_SGT")

    def MLIL_CMP_UGT(self, ins):
        raise ILOpUnimplementedException("MLIL_CMP_UGT")

    def MLIL_TEST_BIT(self, ins):
        raise ILOpUnimplementedException("MLIL_TEST_BIT")

    def MLIL_FCMP_E(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_E")

    def MLIL_FCMP_NE(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_NE")

    def MLIL_FCMP_LT(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_LT")

    def MLIL_FCMP_LE(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_LE")

    def MLIL_FCMP_GE(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_GE")

    def MLIL_FCMP_GT(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_GT")

    def MLIL_FCMP_O(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_O")

    def MLIL_FCMP_UO(self, ins):
        raise ILOpUnimplementedException("MLIL_FCMP_UO")

    def MLIL_BP(self, ins):
        raise ILOpUnimplementedException("MLIL_BP")

    def MLIL_TRAP(self, ins):
        raise ILOpUnimplementedException("MLIL_TRAP")

    def MLIL_INTRINSIC(self, ins):
        raise ILOpUnimplementedException("MLIL_INTRINSIC")

    def MLIL_FREE_VAR_SLOT(self, ins):
        raise ILOpUnimplementedException("MLIL_FREE_VAR_SLOT")

    def MLIL_UNDEF(self, ins):
        raise ILOpUnimplementedException("MLIL_UNDEF")

    def MLIL_UNIMPL(self, ins):
        raise ILOpUnimplementedException("MLIL_UNIMPL")

    def MLIL_UNIMPL_MEM(self, ins):
        raise ILOpUnimplementedException("MLIL_UNIMPL_MEM")

    def MLIL_BOOL_TO_INT(self, ins):
        raise ILOpUnimplementedException("MLIL_BOOL_TO_INT")


    def MLIL_CALL_OUTPUT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_OUTPUT_SSA")

    def MLIL_CALL_PARAM_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_PARAM_SSA")

    def MLIL_CALL_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_SSA")

    def MLIL_CALL_UNTYPED_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_CALL_UNTYPED_SSA")

    def MLIL_FREE_VAR_SLOT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_FREE_VAR_SLOT_SSA")

    def MLIL_INTRINSIC_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_INTRINSIC_SSA")

    def MLIL_LOAD_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_LOAD_SSA")

    def MLIL_LOAD_STRUCT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_LOAD_STRUCT_SSA")

    def MLIL_MEM_PHI(self, ins):
        raise ILOpUnimplementedException("MLIL_MEM_PHI")

    def MLIL_NOP(self, ins):
        raise ILOpUnimplementedException("MLIL_NOP")

    def MLIL_SET_VAR_ALIASED(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_ALIASED")

    def MLIL_SET_VAR_ALIASED_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_ALIASED_FIELD")

    def MLIL_SET_VAR_SPLIT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_SPLIT_SSA")

    def MLIL_SET_VAR_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_SSA")

    def MLIL_SET_VAR_SSA_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_SET_VAR_SSA_FIELD")

    def MLIL_STORE_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_STORE_SSA")

    def MLIL_STORE_STRUCT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_STORE_STRUCT_SSA")

    def MLIL_SYSCALL_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_SYSCALL_SSA")

    def MLIL_SYSCALL_UNTYPED_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_SYSCALL_UNTYPED_SSA")

    def MLIL_TAILCALL_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_TAILCALL_SSA")

    def MLIL_TAILCALL_UNTYPED(self, ins):
        raise ILOpUnimplementedException("MLIL_TAILCALL_UNTYPED")

    def MLIL_TAILCALL_UNTYPED_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_TAILCALL_UNTYPED_SSA")

    def MLIL_VAR_ALIASED(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_ALIASED")

    def MLIL_VAR_ALIASED_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_ALIASED_FIELD")

    def MLIL_VAR_PHI(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_PHI")

    def MLIL_VAR_SPLIT_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_SPLIT_SSA")

    def MLIL_VAR_SSA(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_SSA")

    def MLIL_VAR_SSA_FIELD(self, ins):
        raise ILOpUnimplementedException("MLIL_VAR_SSA_FIELD")
