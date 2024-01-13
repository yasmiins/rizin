static void update_flags(RzStrBuf *out, int flags) {
	if (flags & V850_FLAG_CY) {
		rz_strbuf_append(out, "31,$c,cy,:=");
	}
	if (flags & V850_FLAG_OV) {
		rz_strbuf_append(out, ",31,$o,ov,:=");
	}
	if (flags & V850_FLAG_S) {
		rz_strbuf_append(out, ",31,$s,s,:=");
	}
	if (flags & V850_FLAG_Z) {
		rz_strbuf_append(out, ",$z,z,:=");
	}
}

static void clear_flags(RzStrBuf *out, int flags) {
	if (flags & V850_FLAG_CY) {
		rz_strbuf_append(out, ",0,cy,=");
	}
	if (flags & V850_FLAG_OV) {
		rz_strbuf_append(out, ",0,ov,=");
	}
	if (flags & V850_FLAG_S) {
		rz_strbuf_append(out, ",0,s,=");
	}
	if (flags & V850_FLAG_Z) {
		rz_strbuf_append(out, ",0,z,=");
	}
}

static void v850_esil(RzStrBuf *out, ut8 opcode, ut16 word1, ut16 word2) {
	const char *reg1 = NULL;
	const char *reg2 = NULL;
	ut32 bitmask = 0;
	ut16 destaddr = 0;
	st16 destaddrs = 0;
	switch (opcode) {
	case V850_MOV_IMM5:
	case V850_MOV:
		// 2 formats
		if (opcode != V850_MOV_IMM5) { // Format I
			rz_strbuf_appendf(out, "%s,%s,=", F1_RN1(word1), F1_RN2(word1));
		} else { // Format II
			rz_strbuf_appendf(out, "%" PFMT64d ",%s,=", (st64)(F2_IMM(word1)), F2_RN2(word1));
		}
		break;
	case V850_MOVEA:
		// FIXME: to decide about reading 16/32 bit and use only macros to access
		rz_strbuf_appendf(out, "%s,0xffff,&,%u,+,%s,=", F6_RN1(word1), word2, F6_RN2(word1));
		break;
	case V850_SLDB:
	case V850_SLDH:
	case V850_SLDW:
		if (F4_REG2(word1) == V850_SP) {
		}
		break;
	case V850_SSTB:
	case V850_SSTH:
	case V850_SSTW:
		if (F4_REG2(word1) == V850_SP) {
		}
		break;
	case V850_NOT:
		rz_strbuf_appendf(out, "%s,0xffffffff,^,%s,=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_DIVH:
		rz_strbuf_appendf(out, "%s,%s,0xffff,&,/,%s,=",
			F1_RN1(word1), F1_RN2(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_OV | V850_FLAG_S | V850_FLAG_Z);
		break;
	case V850_JMP:
		if (F1_REG1(word1) == 31) {
		} else {
		}
		rz_strbuf_appendf(out, "%s,pc,=", F1_RN1(word1));
		break;
	case V850_JARL2:
		// TODO: fix displacement reading
		rz_strbuf_appendf(out, "pc,%s,=,pc,%u,+=", F5_RN2(word1), F5_DISP(((ut32)word2 << 16) | word1));
		break;
#if 0 // same opcode as JARL?
	case V850_JR:
		jumpdisp = DISP26(word1, word2);
		rz_strbuf_appendf (out, "$$,%d,+,pc,=", jumpdisp);
		break;
#endif
	case V850_OR:
		rz_strbuf_appendf(out, "%s,%s,|=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_ORI:
		rz_strbuf_appendf(out, "%hu,%s,|,%s,=",
			word2, F6_RN1(word1), F6_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_MULH:
	case V850_MULH_IMM5:
		break;
	case V850_XOR:
		rz_strbuf_appendf(out, "%s,%s,^=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_XORI:
		rz_strbuf_appendf(out, "%hu,%s,^,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_AND:
		rz_strbuf_appendf(out, "%s,%s,&=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_ANDI:
		rz_strbuf_appendf(out, "%hu,%s,&,%s,=", word2, F6_RN1(word1), F6_RN2(word1));
		update_flags(out, V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV | V850_FLAG_S);
		break;
	case V850_CMP:
		rz_strbuf_appendf(out, "%s,%s,==", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_CMP_IMM5:
		rz_strbuf_appendf(out, "%d,%s,==", (st8)SIGN_EXT_T5(F2_IMM(word1)), F2_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_TST:
		rz_strbuf_appendf(out, "%s,%s,&", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_SUB:
		rz_strbuf_appendf(out, "%s,%s,-=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_SUBR:
		rz_strbuf_appendf(out, "%s,%s,-,%s=", F1_RN2(word1), F1_RN1(word1), F1_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_ADD:
		rz_strbuf_appendf(out, "%s,%s,+=", F1_RN1(word1), F1_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_ADD_IMM5:
		if (F2_REG2(word1) == V850_SP) {
		}
		rz_strbuf_appendf(out, "%d,%s,+=", (st8)SIGN_EXT_T5(F2_IMM(word1)), F2_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_ADDI:
		if (F6_REG2(word1) == V850_SP) {
		}
		rz_strbuf_appendf(out, "%d,%s,+,%s,=", (st32)word2, F6_RN1(word1), F6_RN2(word1));
		update_flags(out, -1);
		break;
	case V850_SHR_IMM5:
		rz_strbuf_appendf(out, "%u,%s,>>=", (ut8)F2_IMM(word1), F2_RN2(word1));
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	case V850_SAR_IMM5: {
		ut16 imm5 = F2_IMM(word1);
		reg2 = F2_RN2(word1);
		rz_strbuf_appendf(out, "31,%s,>>,?{,%u,32,-,%u,1,<<,--,<<,}{,0,},%u,%s,>>,|,%s,=", reg2, (ut8)imm5, (ut8)imm5, (ut8)imm5, reg2, reg2);
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
		break;
	}
	case V850_SHL_IMM5:
		rz_strbuf_appendf(out, "%u,%s,<<=", (ut8)F2_IMM(word1), F2_RN2(word1));
		update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
		clear_flags(out, V850_FLAG_OV);
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
		switch (F3_COND(word1)) {
		case V850_COND_V:
			rz_strbuf_appendf(out, "ov");
			break;
		case V850_COND_CL:
			rz_strbuf_appendf(out, "cy");
			break;
		case V850_COND_ZE:
			rz_strbuf_appendf(out, "z");
			break;
		case V850_COND_NH:
			rz_strbuf_appendf(out, "cy,z,|");
			break;
		case V850_COND_N:
			rz_strbuf_appendf(out, "s");
			break;
		case V850_COND_AL: // Always
			rz_strbuf_appendf(out, "1");
			break;
		case V850_COND_LT:
			rz_strbuf_appendf(out, "s,ov,^");
			break;
		case V850_COND_LE:
			rz_strbuf_appendf(out, "s,ov,^,z,|");
			break;
		case V850_COND_NV:
			rz_strbuf_appendf(out, "ov,!");
			break;
		case V850_COND_NL:
			rz_strbuf_appendf(out, "cy,!");
			break;
		case V850_COND_NE:
			rz_strbuf_appendf(out, "z,!");
			break;
		case V850_COND_H:
			rz_strbuf_appendf(out, "cy,z,|,!");
			break;
		case V850_COND_P:
			rz_strbuf_appendf(out, "s,!");
			break;
		case V850_COND_GE:
			rz_strbuf_appendf(out, "s,ov,^,!");
			break;
		case V850_COND_GT:
			rz_strbuf_appendf(out, "s,ov,^,z,|,!");
			break;
		}
		rz_strbuf_appendf(out, ",?{,$$,%d,+,pc,=,}", destaddrs);
		break;
	case V850_BIT_MANIP: {
		ut8 bitop = word1 >> 14;
		switch (bitop) {
		case V850_BIT_CLR1:
			bitmask = (1 << F8_BIT(word1));
			rz_strbuf_appendf(out, "%hu,%s,+,[1],%u,&,%hu,%s,+,=[1]", word2, F8_RN1(word1), bitmask, word2, F8_RN1(word1));
			// TODO: Read the value of the memory byte and set zero flag accordingly!
			break;
		case V850_BIT_NOT1:
			bitmask = (1 << F8_BIT(word1));
			rz_strbuf_appendf(out, "%hu,%s,+,[1],%u,^,%hu,%s,+,=[1]", word2, F8_RN1(word1), bitmask, word2, F8_RN1(word1));
			// TODO: Read the value of the memory byte and set zero flag accordingly!
			break;
		}
	} break;
	case V850_EXT1:
		switch (get_subopcode(word1 | (ut32)word2 << 16)) {
		case V850_EXT_SHL:
			rz_strbuf_appendf(out, "%s,%s,<<=", F9_RN1(word1), F9_RN2(word1));
			update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags(out, V850_FLAG_OV);
			break;
		case V850_EXT_SHR:
			rz_strbuf_appendf(out, "%s,%s,>>=", F9_RN1(word1), F9_RN2(word1));
			update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags(out, V850_FLAG_OV);
			break;
		case V850_EXT_SAR:
			reg1 = F9_RN1(word1);
			reg2 = F9_RN2(word1);
			rz_strbuf_appendf(out, "31,%s,>>,?{,%s,32,-,%s,1,<<,--,<<,}{,0,},%s,%s,>>,|,%s,=", reg2, reg1, reg1, reg1, reg2, reg2);
			update_flags(out, V850_FLAG_CY | V850_FLAG_S | V850_FLAG_Z);
			clear_flags(out, V850_FLAG_OV);
			break;
		}
		break;
	}
}