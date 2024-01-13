// SPDX-FileCopyrightText: 2024 billow <billow.fun@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include "v850_il.h"

static const char *v850_registers[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"r30", // EP
	"r31", // LP
	/*PC*/
	"EIPC",
	"EIPSW",
	"FEPC",
	"FEPSW",
	"ECR",
	"PSW",
	NULL
};

RzAnalysisILConfig *v850_il_config(RzAnalysis *a) {
	rz_return_val_if_fail(a, NULL);

	RzAnalysisILConfig *cfg = rz_analysis_il_config_new(32, false, 32);
	cfg->reg_bindings = v850_registers;
	return cfg;
}

static const char *GR[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	"r13",
	"r14",
	"r15",
	"r16",
	"r17",
	"r18",
	"r19",
	"r20",
	"r21",
	"r22",
	"r23",
	"r24",
	"r25",
	"r26",
	"r27",
	"r28",
	"r29",
	"r30", // EP
	"r31", // LP
	/*PC*/
	NULL
};

typedef struct {
	const char *p;
	const char *x;
	unsigned i;
	unsigned b;
} V850_FLG;

static const char *SR[] = {
	"EIPC",
	"EIPSW",
	"FEPC",
	"FEPSW",
	"ECR",
	"PSW",
	NULL
};

static const V850_FLG flags[] = {
	{ "PSW", "RFU", 8, 24 },
	{ "PSW", "NP", 7, 1 },
	{ "PSW", "EP", 6, 1 },
	{ "PSW", "ID", 5, 1 },
	{ "PSW", "SAT", 4, 1 },
	{ "PSW", "CY", 3, 1 },
	{ "PSW", "OV", 2, 1 },
	{ "PSW", "S", 1, 1 },
	{ "PSW", "Z", 0, 1 },
};

static const V850_FLG *flag_find(const char *p, const char *x) {
	for (int i = 0; i < RZ_ARRAY_SIZE(flags); ++i) {
		const V850_FLG *f = flags + i;
		if (RZ_STR_NE(p, f->p)) {
			continue;
		}
		if (RZ_STR_NE(x, f->x)) {
			continue;
		}
		return f;
	}
	return NULL;
}

#include <rz_il/rz_il_opbuilder_begin.h>

static RzILOpEffect *SETGbs(const char *p, unsigned n, ...) {
	va_list args;
	va_start(args, n);

	RzILOpPure *expr = NULL;
	for (unsigned i = 0; i < n; ++i) {
		const char *x = va_arg(args, const char *);
		RzILOpPure *y = va_arg(args, RzILOpPure *);

		const V850_FLG *f = flag_find(p, x);
		if (!f) {
			rz_warn_if_reached();
			return NULL;
		}

		RzILOpPure *v = SHIFTL0(f->b == 1 ? BOOL_TO_BV(y, 32) : y, U32(f->i));
		expr = !expr ? v : LOGOR(expr, v);
	}
	return SETG(p, expr);
}
#define SETGb(p, ...) SETGbs(p, 1, __VA_ARGS__)

static RzILOpPure *nth_(RzILOpPure *x, RzILOpPure *n) {
	return NON_ZERO(LOGAND(SHIFTR0(x, n), U32(1)));
}
static RzILOpPure *nth(RzILOpPure *x, unsigned n) {
	return nth_(x, U32(n));
}

static RzILOpPure *set_nth(RzILOpPure *x, unsigned n, bool v) {
	if (v) {
		return LOGOR(x, U32((ut32)(v) << n));
	}
	return LOGAND(x, U32(~((ut32)(v) << n)));
}

static inline int32_t sext32(uint32_t X, unsigned B) {
	rz_warn_if_fail(B > 0 && B <= 32);
	return (int32_t)(X << (32 - B)) >> (32 - B);
}

#define LH(x) LOGAND(x, U32(0xffff))

#define PSW_NP  nth(VARG("PSW"), 7)
#define PSW_EP  nth(VARG("PSW"), 6)
#define PSW_ID  nth(VARG("PSW"), 5)
#define PSW_SAT nth(VARG("PSW"), 4)
#define PSW_CY  nth(VARG("PSW"), 3)
#define PSW_OV  nth(VARG("PSW"), 2)
#define PSW_S   nth(VARG("PSW"), 1)
#define PSW_Z   nth(VARG("PSW"), 0)

#define OPC     get_opcode(ctx->w1)
#define OPC_SUB get_subopcode(ctx->w1 | (ut32)ctx->w2 << 16)

#define R1_ get_reg1(ctx->w1)
#define R2_ get_reg2(ctx->w1)
#define R1  (GR[R1_])
#define R2  (GR[R2_])
#define R1V VARG(R1)
#define R2V VARG(R2)
#define R1F FLOATV32(VARG(R1))
#define R2F FLOATV32(VARG(R2))

#define I5    (ctx->w1 & 0x1f)
#define SEXT5 S32(sext32(I5, 5))
#define ZEXT5  U32(I5))

#define I16    (ctx->w2)
#define SEXT16 S32(sext32(16, 5))
#define ZEXT16  U32(I16))

#define BCOND_COND  (ctx->w1 & 0xf)
#define BCOND_DISP_ ((((ctx->w1 >> 4) & 0b111) | (((ctx->w1 >> 11) & 0b11111) << 3)) << 1)
#define BCOND_DISP  S32(sext32(BCOND_DISP_, 9))

#define JUMP_DISP_ sext32(ctx->w2 | (ctx->w1 & 0x3f), 22)
#define JUMP_DISP  S32(JUMP_DISP_)

#define BIT_SUB  ((ctx->w1 >> 14) & 0x3)
#define BIT_BIT  ((ctx->w1 >> 11) & 0x7)
#define BIT_DISP (ctx->w2)

#define EXT_SUB ((ctx->w2 > 5) & 0x3f)

#define EXT_SUB2 ((ctx->w1 >> 13) & 0x7)
#define EXT2_VEC I5

typedef RzILOpPure *(*F_OP1)(RzILOpPure *);
typedef RzILOpPure *(*F_OP2)(RzILOpPure *, RzILOpPure *);

static RzILOpPure *overflow(RzILOpPure *x) {
	return LET("_x", x,
		OR(
			SGT(VARLP("_x"), S32(+0x7fffffff)),
			SLT(VARLP("_x"), S32(-0x80000000))));
}

static RzAnalysisLiftedILOp flags_update(const V850AnalysisContext *ctx) {
	switch (OPC) {
	case V850_ADD:
	case V850_ADD_IMM5:
	case V850_ADDI:
		return SETGbs("PSW", 4,
			"CY", OR(SLT(VARL("result"), R2V), SLT(VARL("result"), R1V)),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_CMP:
	case V850_CMP_IMM5:
		return SETGbs("PSW", 4,
			"CY", SLT(R2V, R1V),
			"OV", overflow(VARL("result")),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	case V850_DIVH:
		return SETGbs("PSW", 3,
			"OV", IS_ZERO(LH(R1V)),
			"S", SLT(VARL("result"), S32(0)),
			"Z", IS_ZERO(VARL("result")));
	default:
		return NOP();
	}
}

static RzAnalysisLiftedILOp lift_op1(const V850AnalysisContext *ctx, RzILOpPure *x0, F_OP1 f) {
	return SEQ2(
		SETG(R2, f(x0)),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_op2(const V850AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ3(
		SETL("result", f(x0, x1)),
		flags_update(ctx),
		SETG(R2, VARL("result")));
}

static RzAnalysisLiftedILOp lift_bcond(const V850AnalysisContext *ctx, RzILOpPure *cond) {
	return BRANCH(cond, SEQ2(SETL("_pc", ADD(S32(ctx->pc), BCOND_DISP)), JMP(VARL("_pc"))), NOP());
}

static RzAnalysisLiftedILOp lift_bit(const V850AnalysisContext *ctx, RzILOpPure *adr) {
	return SEQ4(
		SETL("_adr", adr),
		SETL("_val", LOADW(8, VARL("adr"))),
		SETGb("PSW", "Z", INV(nth(VARL("_val"), BIT_BIT))),
		STOREW(VARL("_adr"), set_nth(VARL("_val"), BIT_BIT, 0)));
}

static RzAnalysisLiftedILOp lift_cmp(const V850AnalysisContext *ctx, RzILOpPure *x0, RzILOpPure *x1, F_OP2 f) {
	return SEQ2(
		SETL("result", f(x0, x1)),
		flags_update(ctx));
}

static RzAnalysisLiftedILOp lift_jarl(const V850AnalysisContext *ctx) {
	return SEQ3(
		SETG(R2, ADD(U32(ctx->pc), U32(4))),
		SETL("_pc", ADD(U32(ctx->pc), JUMP_DISP)),
		JMP(VARL("_pc")));
}

RzAnalysisLiftedILOp v850_il_op(const V850AnalysisContext *ctx) {
	switch (OPC) {
	case V850_MOV_IMM5:
	case V850_MOV:
	case V850_MOVEA:
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
		break;
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		break;
	case V850_NOT:
		break;
	case V850_DIVH: return lift_op2(ctx, R2V, LH(R1V), rz_il_op_new_div);
	case V850_JMP: return JMP(R1V);
	case V850_JARL: return lift_jarl(ctx);
	case V850_JR: return JMP(S32(ctx->pc + JUMP_DISP_));
	case V850_OR:
	case V850_ORI:
		break;
	case V850_MULH:
	case V850_MULH_IMM5:
		break;
	case V850_XOR:
	case V850_XORI:
		break;
	case V850_AND:
	case V850_ANDI:
		break;
	case V850_CMP: return lift_cmp(ctx, R2V, R1V, rz_il_op_new_sub);
	case V850_CMP_IMM5: return lift_cmp(ctx, R2V, SEXT5, rz_il_op_new_sub);
	case V850_TST:
		break;
	case V850_SUB:
	case V850_SUBR:
		break;
	case V850_ADD: return lift_op2(ctx, R2V, R1V, rz_il_op_new_add);
	case V850_ADD_IMM5: return lift_op2(ctx, R2V, SEXT5, rz_il_op_new_add);
	case V850_ADDI: return lift_op2(ctx, R2V, SEXT16, rz_il_op_new_add);
	case V850_SHR_IMM5:
		break;
	case V850_SAR_IMM5:
		break;
	case V850_SHL_IMM5:
		break;
	case V850_BCOND:
	case V850_BCOND2:
	case V850_BCOND3:
	case V850_BCOND4: {
		RzILOpPure *cnd = NULL;
		switch (BCOND_COND) {
		case C_BGT: cnd = INV(OR(XOR(PSW_S, PSW_OV), PSW_Z)); break;
		case C_BGE: cnd = INV(XOR(PSW_S, PSW_OV)); break;
		case C_BLT: cnd = XOR(PSW_S, PSW_OV); break;
		case C_BLE: cnd = OR(XOR(PSW_S, PSW_OV), PSW_Z); break;

		case C_BH: cnd = INV(OR(PSW_CY, PSW_Z)); break;
		case C_BNL: cnd = INV(PSW_CY); break;
		case C_BL: cnd = PSW_CY; break;
		case C_BNH: cnd = OR(PSW_CY, PSW_Z); break;

		case C_BE: cnd = PSW_Z; break;
		case C_BNE: cnd = INV(PSW_Z); break;

		case C_BV: cnd = PSW_OV; break;
		case C_BNV: cnd = INV(PSW_OV); break;
		case C_BN: cnd = PSW_S; break;
		case C_BP: cnd = INV(PSW_S); break;
		// case C_BC: break;
		// case C_BNC: break;
		// case C_BZ: break;
		// case C_BNZ: break;
		case C_BR: cnd = IL_TRUE; break;
		case C_NOP: cnd = IL_FALSE; break;
		default: break;
		}
		return lift_bcond(ctx, cnd);
	}
	case V850_BIT_MANIP: {
		switch (BIT_SUB) {
		case V850_BIT_CLR1: return lift_bit(ctx, ADD(R1V, SEXT16));
		}
	}
	case V850_EXT1:
		switch (EXT_SUB) {
		case V850_EXT_SHL:
			break;
		case V850_EXT_SHR:
			break;
		case V850_EXT_SAR:
			break;
		case V850_EXT_HALT: return NOP();
		case V850_EXT_EXT2: {
			switch (EXT_SUB2) {
			case V850_EXT_DI: return SETGb("PSW", "ID", IL_TRUE);
			case V850_EXT_EI: return SETGb("PSW", "ID", IL_FALSE);
			}
		}
		default: break;
		}
		break;
	default: break;
	}

	return NULL;
}
