// SPDX-FileCopyrightText: 2012-2020 pancake <pancake@nopcode.org>
// SPDX-FileCopyrightText: 2014 Fedor Sakharov <fedor.sakharov@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-only

#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_asm.h>
#include <rz_analysis.h>
#include <rz_util.h>
#include <rz_endian.h>

#include <v850_disas.h>
#include "../arch/v850/v850_il.h"

// Format I
#define F1_REG1(instr) ((instr) & 0x1F)
#define F1_REG2(instr) (((instr) & 0xF800) >> 11)

#define F1_RN1(instr) (V850_REG_NAMES[F1_REG1(instr)])
#define F1_RN2(instr) (V850_REG_NAMES[F1_REG2(instr)])

// Format II
#define F2_IMM(instr)  F1_REG1(instr)
#define F2_REG2(instr) F1_REG2(instr)

#define F2_RN2(instr) (V850_REG_NAMES[F2_REG2(instr)])

// Format III
#define F3_COND(instr) ((instr) & 0xF)
#define F3_DISP(instr) (((instr) & 0x70) >> 4) | (((instr) & 0xF800) >> 7)

// Format IV
#define F4_DISP(instr) ((instr) & 0x3F)
#define F4_REG2(instr) F1_REG2(instr)

#define F4_RN2(instr) (V850_REG_NAMES[F4_REG2(instr)])

// Format V
#define F5_REG2(instr) F1_REG2(instr)
#define F5_DISP(instr) ((((ut32)(instr) & 0xffff) << 31) | (((ut32)(instr) & 0xffff0000) << 1))
#define F5_RN2(instr)  (V850_REG_NAMES[F5_REG2(instr)])

// Format VI
#define F6_REG1(instr) F1_REG1(instr)
#define F6_REG2(instr) F1_REG2(instr)
#define F6_IMM(instr)  (((instr) & 0xFFFF0000) >> 16)

#define F6_RN1(instr) (V850_REG_NAMES[F6_REG1(instr)])
#define F6_RN2(instr) (V850_REG_NAMES[F6_REG2(instr)])

// Format VII
#define F7_REG1(instr) F1_REG1(instr)
#define F7_REG2(instr) F1_REG2(instr)
#define F7_DISP(instr) F6_IMM(instr)

#define F7_RN1(instr) (V850_REG_NAMES[F7_REG1(instr)])
#define F7_RN2(instr) (V850_REG_NAMES[F7_REG2(instr)])

// Format VIII
#define F8_REG1(instr) F1_REG1(instr)
#define F8_DISP(instr) F6_IMM(instr)
#define F8_BIT(instr)  (((instr) & 0x3800) >> 11)
#define F8_SUB(instr)  (((instr) & 0xC000) >> 14)

#define F8_RN1(instr) (V850_REG_NAMES[F8_REG1(instr)])
#define F8_RN2(instr) (V850_REG_NAMES[F8_REG2(instr)])

// Format IX
// Also regID/cond
#define F9_REG1(instr) F1_REG1(instr)
#define F9_REG2(instr) F1_REG2(instr)
#define F9_SUB(instr)  (((instr) & 0x7E00000) >> 21)

#define F9_RN1(instr) (V850_REG_NAMES[F9_REG1(instr)])
#define F9_RN2(instr) (V850_REG_NAMES[F9_REG2(instr)])
// TODO: Format X

// Format XI
#define F11_REG1(instr) F1_REG1(instr)
#define F11_REG2(instr) F1_REG2(instr)
#define F11_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F11_SUB(instr)  ((((instr) & 0x7E00000) >> 20) | (((instr) & 2) >> 1))

#define F11_RN1(instr) (V850_REG_NAMES[F11_REG1(instr)])
#define F11_RN2(instr) (V850_REG_NAMES[F11_REG2(instr)])
// Format XII
#define F12_IMM(instr)  (F1_REG1(instr) | (((instr) & 0x7C0000) >> 13))
#define F12_REG2(instr) F1_REG2(instr)
#define F12_REG3(instr) (((instr) & 0xF8000000) >> 27)
#define F12_SUB(instr)  ((((instr) & 0x7800001) >> 22) | (((instr) & 2) >> 1))

#define F12_RN2(instr) (V850_REG_NAMES[F12_REG2(instr)])
#define F12_RN3(instr) (V850_REG_NAMES[F12_REG3(instr)])

// Format XIII
#define F13_IMM(instr) (((instr) & 0x3E) >> 1)
// Also a subopcode
#define F13_REG2(instr) (((instr) & 0x1F0000) >> 16)
#define F13_LIST(instr) (((instr) && 0xFFE00000) >> 21)

#define F13_RN2(instr) (V850_REG_NAMES[F13_REG2(instr)])

static const char *V850_REG_NAMES[] = {
	"zero",
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
	"ep",
	"lp",
};

#include "../arch/v850/v850_esil.inc"

static int v850_op(RzAnalysis *analysis, RzAnalysisOp *op, ut64 addr, const ut8 *buf, int len, RzAnalysisOpMask mask) {
	int ret = 0;
	ut8 opcode = 0;
	ut16 destaddr = 0;
	st16 destaddrs = 0;
	ut16 word1 = 0, word2 = 0;
	struct v850_cmd cmd;

	if (len < 1 || (len > 0 && !memcmp(buf, "\xff\xff\xff\xff\xff\xff", RZ_MIN(len, 6)))) {
		return -1;
	}

	memset(&cmd, 0, sizeof(cmd));

	ret = op->size = v850_decode_command(buf, len, &cmd);

	if (ret < 1) {
		return ret;
	}

	op->addr = addr;

	word1 = rz_read_le16(buf);
	if (ret == 4) {
		word2 = rz_read_le16(buf + 2);
	}
	opcode = get_opcode(word1);

	switch (opcode) {
	case V850_MOV_IMM5:
	case V850_MOV:
	case V850_MOVEA:
		op->type = RZ_ANALYSIS_OP_TYPE_MOV;
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
		op->type = RZ_ANALYSIS_OP_TYPE_LOAD;
		if (F4_REG2(word1) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_GET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		op->type = RZ_ANALYSIS_OP_TYPE_STORE;
		if (F4_REG2(word1) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_SET;
			op->stackptr = 0;
			op->ptr = 0;
		}
		break;
	case V850_NOT:
		op->type = RZ_ANALYSIS_OP_TYPE_NOT;
		break;
	case V850_DIVH:
		op->type = RZ_ANALYSIS_OP_TYPE_DIV;
		break;
	case V850_JMP:
		if (F1_REG1(word1) == 31) {
			op->type = RZ_ANALYSIS_OP_TYPE_RET;
		} else {
			op->type = RZ_ANALYSIS_OP_TYPE_UJMP;
		}
		op->jump = word1; // UT64_MAX; // this is n RJMP instruction .. F1_RN1 (word1);
		op->fail = addr + 2;
		break;
	case V850_JARL:
		// TODO: fix displacement reading
		op->type = RZ_ANALYSIS_OP_TYPE_JMP;
		op->jump = addr + F5_DISP(((ut32)word2 << 16) | word1);
		op->fail = addr + 4;
		break;
	case V850_JR:
		// TODO: V850_JR
		break;
	case V850_OR:
	case V850_ORI:
		op->type = RZ_ANALYSIS_OP_TYPE_OR;
		break;
	case V850_MULH:
	case V850_MULH_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_MUL;
		break;
	case V850_XOR:
	case V850_XORI:
		op->type = RZ_ANALYSIS_OP_TYPE_XOR;
		break;
	case V850_AND:
	case V850_ANDI:
		op->type = RZ_ANALYSIS_OP_TYPE_AND;
		break;
	case V850_CMP:
	case V850_CMP_IMM5:
	case V850_TST:
		op->type = RZ_ANALYSIS_OP_TYPE_CMP;
		break;
	case V850_SUB:
	case V850_SUBR:
		op->type = RZ_ANALYSIS_OP_TYPE_SUB;
		break;
	case V850_ADD:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		break;
	case V850_ADD_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (F2_REG2(word1) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = F2_IMM(word1);
			op->val = op->stackptr;
		}
		break;
	case V850_ADDI:
		op->type = RZ_ANALYSIS_OP_TYPE_ADD;
		if (F6_REG2(word1) == V850_SP) {
			op->stackop = RZ_ANALYSIS_STACK_INC;
			op->stackptr = (st64)word2;
			op->val = op->stackptr;
		}
		break;
	case V850_SHR_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_SHR;
		break;
	case V850_SAR_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_SAR;
		break;
	case V850_SHL_IMM5:
		op->type = RZ_ANALYSIS_OP_TYPE_SHL;
		break;
	case V850_BCOND:
	case V850_BCOND2:
	case V850_BCOND3:
	case V850_BCOND4:
		destaddr = ((((word1 >> 4) & 0x7) |
				    ((word1 >> 11) << 3))
			<< 1);
		if (destaddr & 0x100) {
			destaddrs = destaddr | 0xFE00;
		} else {
			destaddrs = destaddr;
		}
		op->jump = addr + destaddrs;
		op->fail = addr + 2;
		op->type = RZ_ANALYSIS_OP_TYPE_CJMP;
		break;
	case V850_BIT_MANIP: break;
	case V850_EXT1:
		switch (get_subopcode(word1 | (ut32)word2 << 16)) {
		case V850_EXT_SHL:
			op->type = RZ_ANALYSIS_OP_TYPE_SHL;
			break;
		case V850_EXT_SHR:
			op->type = RZ_ANALYSIS_OP_TYPE_SHR;
			break;
		case V850_EXT_SAR:
			op->type = RZ_ANALYSIS_OP_TYPE_SAR;
			break;
		}
		break;
	}

	if (mask & RZ_ANALYSIS_OP_MASK_ESIL) {
		v850_esil(&op->esil, opcode, word1, word2);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_DISASM) {
		op->mnemonic = rz_str_newf("%s %s", cmd.instr, cmd.operands);
	}

	if (mask & RZ_ANALYSIS_OP_MASK_IL) {
		V850AnalysisContext ctx = { 0 };
		ctx.a = analysis;
		ctx.w1 = word1;
		ctx.w2 = word2;
		ctx.pc = addr;

		op->il_op = v850_il_op(&ctx);
	}

	return ret;
}

static char *get_reg_profile(RzAnalysis *analysis) {
	const char *p =
		"=PC	pc\n"
		"=SP	r3\n"
		"=ZF	z\n"
		"=A0	r1\n"
		"=A1	r5\n"
		"=A2	r6\n"
		"=A3	r7\n"
		"=A4	r8\n"
		"=SF	s\n"
		"=OF	ov\n"
		"=CF	cy\n"

		"gpr	zero	.32	?   0\n"
		"gpr	r0	.32	0   0\n"
		"gpr	r1	.32	4   0\n"
		"gpr	r2	.32	8   0\n"
		"gpr	r3	.32	12  0\n"
		"gpr	sp	.32	12  0\n"
		"gpr	r4	.32	16  0\n"
		"gpr	gp	.32	16  0\n"
		"gpr	r5	.32	20  0\n"
		"gpr	tp	.32	20  0\n"
		"gpr	r6	.32	24  0\n"
		"gpr	r7	.32	28  0\n"
		"gpr	r8	.32	32  0\n"
		"gpr	r9	.32	36  0\n"
		"gpr	r10	.32	40  0\n"
		"gpr	r11	.32	44  0\n"
		"gpr	r12	.32	48  0\n"
		"gpr	r13	.32	52  0\n"
		"gpr	r14	.32	56  0\n"
		"gpr	r15	.32	60  0\n"
		"gpr	r16	.32	64  0\n"
		"gpr	r17	.32	68  0\n"
		"gpr	r18	.32	72  0\n"
		"gpr	r19	.32	76  0\n"
		"gpr	r20	.32	80  0\n"
		"gpr	r21	.32	84  0\n"
		"gpr	r22	.32	88  0\n"
		"gpr	r23	.32	92  0\n"
		"gpr	r24	.32	96  0\n"
		"gpr	r25	.32	100 0\n"
		"gpr	r26	.32	104 0\n"
		"gpr	r27	.32	108 0\n"
		"gpr	r28	.32	112 0\n"
		"gpr	r29	.32	116 0\n"
		"gpr	r30	.32	120 0\n"
		"gpr	ep	.32	120 0\n"
		"gpr	r31	.32	124 0\n"
		"gpr	lp	.32	124 0\n"
		"gpr	pc	.32	128 0\n"

		// 32bit [   RFU   ][NP EP ID SAT CY OV S Z]
		"gpr	psw .32 132 0\n" // program status word
		"gpr	npi  .1 132.16 0\n" // non maskerable interrupt (NMI)
		"gpr	epi  .1 132.17 0\n" // exception processing interrupt
		"gpr	id   .1 132.18 0\n" // :? should be id
		"gpr	sat  .1 132.19 0\n" // saturation detection
		"flg	cy  .1 132.28 0\n" // carry or borrow
		"flg	ov  .1 132.29 0\n" // overflow
		"flg	s   .1 132.30 0\n" // signed result
		"flg	z   .1 132.31 0\n"; // zero result
	return strdup(p);
}

static RzList /*<RzSearchKeyword *>*/ *analysis_preludes(RzAnalysis *analysis) {
#define KW(d, ds, m, ms) rz_list_append(l, rz_search_keyword_new((const ut8 *)d, ds, (const ut8 *)m, ms, NULL))
	RzList *l = rz_list_newf((RzListFree)rz_search_keyword_free);
	KW("\x80\x07", 2, "\xf0\xff", 2);
	KW("\x50\x1a\x63\x0f", 4, "\xf0\xff\xff\x0f", 4);
	return l;
}

static int archinfo(RzAnalysis *a, RzAnalysisInfoType query) {
	switch (query) {
	case RZ_ANALYSIS_ARCHINFO_MIN_OP_SIZE:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_MAX_OP_SIZE:
		return 8;
	case RZ_ANALYSIS_ARCHINFO_TEXT_ALIGN:
		return 2;
	case RZ_ANALYSIS_ARCHINFO_DATA_ALIGN:
		return 0;
	case RZ_ANALYSIS_ARCHINFO_CAN_USE_POINTERS:
		return true;
	default:
		return -1;
	}
}

RzAnalysisPlugin rz_analysis_plugin_v850 = {
	.name = "v850",
	.desc = "V850 code analysis plugin",
	.license = "LGPL3",
	.preludes = analysis_preludes,
	.arch = "v850",
	.bits = 32,
	.op = v850_op,
	.esil = true,
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.il_config = v850_il_config
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ANALYSIS,
	.data = &rz_analysis_plugin_v850,
	.version = RZ_VERSION
};
#endif
