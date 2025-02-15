// SPDX-FileCopyrightText: 2012-2018 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <rz_types.h>
#include <rz_lib.h>
#include <rz_util.h>
#include <rz_asm.h>
#include "disas-asm.h"
#include <mybfd.h>

/* extern */
int decodeInstr(bfd_vma address, disassemble_info *info);
int ARCTangent_decodeInstr(bfd_vma address, disassemble_info *info);
int ARCompact_decodeInstr(bfd_vma address, disassemble_info *info);

/* ugly globals */
static ut32 Offset = 0;
static RzStrBuf *buf_global = NULL;
static int buf_len = 0;
static ut8 bytes[32] = { 0 };

static int arc_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - Offset);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > sizeof(bytes)) {
		return -1;
	}
	memcpy(myaddr, bytes + delta, RZ_MIN(buf_len - delta, length));
	return 0;
}

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC()
DECLARE_GENERIC_FPRINTF_FUNC()

typedef struct {
	struct disassemble_info disasm_obj;
} ArcContext;

static int disassemble(RzAsm *a, RzAsmOp *op, const ut8 *buf, int len) {
	ArcContext *ctx = (ArcContext *)a->plugin_data;
	if (len < 2) {
		return -1;
	}
	buf_global = &op->buf_asm;
	Offset = a->pc;
	if (len > sizeof(bytes)) {
		len = sizeof(bytes);
	}
	memcpy(bytes, buf, len); // TODO handle compact
	buf_len = len;
	/* prepare disassembler */
	memset(&ctx->disasm_obj, '\0', sizeof(struct disassemble_info));
	ctx->disasm_obj.buffer = bytes;
	ctx->disasm_obj.buffer_length = len;
	ctx->disasm_obj.read_memory_func = &arc_buffer_read_memory;
	ctx->disasm_obj.symbol_at_address_func = &symbol_at_address;
	ctx->disasm_obj.memory_error_func = &memory_error_func;
	ctx->disasm_obj.print_address_func = &generic_print_address_func;
	ctx->disasm_obj.endian = !a->big_endian;
	ctx->disasm_obj.fprintf_func = &generic_fprintf_func;
	ctx->disasm_obj.stream = stdout;
	ctx->disasm_obj.mach = 0;
	rz_strbuf_set(&op->buf_asm, "");
	if (a->bits == 16) {
		op->size = ARCompact_decodeInstr((bfd_vma)Offset, &ctx->disasm_obj);
	} else {
		op->size = ARCTangent_decodeInstr((bfd_vma)Offset, &ctx->disasm_obj);
	}
	if (op->size == -1) {
		rz_strbuf_set(&op->buf_asm, "(data)");
	}
	return op->size;
}

static bool init(void **user) {
	ArcContext *ctx = RZ_NEW0(ArcContext);
	rz_return_val_if_fail(ctx, false);
	*user = ctx;
	return true;
}

static bool the_end(void *p) {
	ArcContext *ctx = (ArcContext *)p;
	if (ctx) {
		RZ_FREE(ctx);
	}
	return true;
}

RzAsmPlugin rz_asm_plugin_arc = {
	.name = "arc",
	.arch = "arc",
	.bits = 16 | 32,
	.endian = RZ_SYS_ENDIAN_LITTLE | RZ_SYS_ENDIAN_BIG,
	.desc = "Argonaut RISC Core",
	.init = init,
	.fini = the_end,
	.disassemble = &disassemble,
	.license = "GPL3"
};

#ifndef RZ_PLUGIN_INCORE
RZ_API RzLibStruct rizin_plugin = {
	.type = RZ_LIB_TYPE_ASM,
	.data = &rz_asm_plugin_arc,
	.version = RZ_VERSION
};
#endif
