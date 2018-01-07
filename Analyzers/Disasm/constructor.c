#include "common.h"

#include <windows.h>

//#define DEBUG_MODRM

extern Z0_STATUS __stdcall write_result(PZ0_DISASM_CONTEXT context);

Z0_STATUS __stdcall process_ud(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	return status;
}

Z0_STATUS __stdcall process_error(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	if(1 == context->length)
	{
		switch(context->bytes[0])
		{
			case 0x26:
			case 0x2e:
			case 0x36:
			case 0x3e:
			case 0x64:
			case 0x65:
			case 0x66:
			case 0x67:
			case 0xf0:
			case 0xf2:
			case 0xf3: return status;
		}
	}

	printf("ERROR: invalid call:");
	for(i =0; i <context->length; i++) printf(" %02x", context->bytes[i]);
	printf("                              \r\n");

	return status;
}

void add_prefix(PZ0_DISASM_CONTEXT context, unsigned short prefix)
{
	int i;

	if(context->length < Z0_MAX_OPCODE_LENGTH)
	{
		for(i =(Z0_MAX_OPCODE_LENGTH -1); i; i--) context->bytes[i] =context->bytes[i-1];

		switch(prefix)
		{
			case Z0_PREFIX_ES: context->bytes[0] =0x26; context->prefix_segment =Z0_PREFIX_ES; break;
			case Z0_PREFIX_CS: context->bytes[0] =0x2e; context->prefix_segment =Z0_PREFIX_CS; break;
			case Z0_PREFIX_SS: context->bytes[0] =0x36; context->prefix_segment =Z0_PREFIX_SS; break;
			case Z0_PREFIX_DS: context->bytes[0] =0x3e; context->prefix_segment =Z0_PREFIX_DS; break;
			case Z0_PREFIX_FS: context->bytes[0] =0x64; context->prefix_segment =Z0_PREFIX_FS; break;
			case Z0_PREFIX_GS: context->bytes[0] =0x65; context->prefix_segment =Z0_PREFIX_GS; break;

			case Z0_PREFIX_OPERAND: context->bytes[0] =0x66; context->prefix_operand =Z0_PREFIX_OPERAND; break;
			case Z0_PREFIX_ADDRESS: context->bytes[0] =0x67; context->prefix_address =Z0_PREFIX_ADDRESS; break;

			case Z0_PREFIX_LOCK: context->bytes[0] =0xf0; context->prefix_lock =Z0_PREFIX_LOCK; break;

			case Z0_PREFIX_REPNE: context->bytes[0] =0xf2; context->prefix_repeat =Z0_PREFIX_REPNE; break;
			case Z0_PREFIX_REPE: context->bytes[0] =0xf3; context->prefix_repeat =Z0_PREFIX_REPE; break;
		}

		context->length++;
	}
}

char convert_to_16bit(PZ0_DISASM_CONTEXT context)
{
	int i;
	char result =0;

	if(context->flags & Z0_FLAG_PREFIX_REPNE)
	{
		if(Z0_PREFIX_REPNE == context->prefix_repeat)
		{
			return result;
		}
	}

	if(context->flags & Z0_FLAG_PREFIX_REPE)
	{
		if(Z0_PREFIX_REPE == context->prefix_repeat)
		{
			return result;
		}
	}

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->optype[i])
		{
			case Z0_OPTYPE_IMM32: result =1; context->optype[i] =Z0_OPTYPE_IMM16; break;

			case Z0_OPTYPE_RM32:
			{
				if(context->modrm)
				{
					if(3 == context->modrm->mod)
					{
						if(0 ==(context->flags &Z0_OVERRIDE_REG))
						{
							result =1;
						}
					}
				}

				context->optype[i] =Z0_OPTYPE_RM16;
			} break;

			case Z0_OPTYPE_RM32PTR:
			{
				if(context->modrm)
				{
					if(3 == context->modrm->mod)
					{
						if(0 ==(context->flags &Z0_OVERRIDE_REG))
						{
							result =1;
						}
					}
				}

				context->optype[i] =Z0_OPTYPE_RM16PTR;
			} break;

			case Z0_OPTYPE_RM48PTR: result =1; context->optype[i] =Z0_OPTYPE_RM32PTR; break;

			case Z0_OPTYPE_REG32: result =1; context->optype[i] =Z0_OPTYPE_REG16; break;

			case Z0_OPTYPE_PTR16_32:result =1; context->optype[i] =Z0_OPTYPE_PTR16_16; break;

			case Z0_OPTYPE_EAX: result =1; context->optype[i] =Z0_OPTYPE_AX; break;
			case Z0_OPTYPE_ECX: result =1; context->optype[i] =Z0_OPTYPE_CX; break;
			case Z0_OPTYPE_EDX: result =1; context->optype[i] =Z0_OPTYPE_DX; break;
			case Z0_OPTYPE_EBX: result =1; context->optype[i] =Z0_OPTYPE_BX; break;
			case Z0_OPTYPE_ESP: result =1; context->optype[i] =Z0_OPTYPE_SP; break;
			case Z0_OPTYPE_EBP: result =1; context->optype[i] =Z0_OPTYPE_BP; break;
			case Z0_OPTYPE_ESI: result =1; context->optype[i] =Z0_OPTYPE_SI; break;
			case Z0_OPTYPE_EDI: result =1; context->optype[i] =Z0_OPTYPE_DI; break;

			case Z0_OPTYPE_1: result =1; break;
			case Z0_OPTYPE_CL_1: result =1; break;
		}
	}

	if(!result)
	{
		switch(context->mnemonic)
		{
			case Z0_MNEMONIC_PUSHAD:
			case Z0_MNEMONIC_POPAD:
			case Z0_MNEMONIC_INSD:
			case Z0_MNEMONIC_OUTSD:
			case Z0_MNEMONIC_CWDE:
			case Z0_MNEMONIC_CDQ:
			case Z0_MNEMONIC_PUSHFD:
			case Z0_MNEMONIC_POPFD:
			case Z0_MNEMONIC_MOVSD:
			case Z0_MNEMONIC_CMPSD:
			case Z0_MNEMONIC_STOSD:
			case Z0_MNEMONIC_LODSD:
			case Z0_MNEMONIC_SCASD:

			case Z0_MNEMONIC_JECXZ:

			case Z0_MNEMONIC_NOT:
			case Z0_MNEMONIC_NEG:
			case Z0_MNEMONIC_MUL:
			case Z0_MNEMONIC_IMUL:
			case Z0_MNEMONIC_DIV:
			case Z0_MNEMONIC_IDIV:
			case Z0_MNEMONIC_INC:
			case Z0_MNEMONIC_DEC:
			case Z0_MNEMONIC_PUSH:
			case Z0_MNEMONIC_POP:

			case Z0_MNEMONIC_CVTPI2PS:
			case Z0_MNEMONIC_CVTTPS2PI:
			case Z0_MNEMONIC_CVTPS2PI:
			case Z0_MNEMONIC_CVTPS2PD:
			case Z0_MNEMONIC_CVTDQ2PS:

			case Z0_MNEMONIC_UCOMISS:
			case Z0_MNEMONIC_COMISS:

			case Z0_MNEMONIC_MOVMSKPS:
			case Z0_MNEMONIC_SQRTPS:

			case Z0_MNEMONIC_PSHUFB:
			case Z0_MNEMONIC_ANDPS:
			case Z0_MNEMONIC_ANDNPS:
			case Z0_MNEMONIC_ORPS:
			case Z0_MNEMONIC_XORPS:
			case Z0_MNEMONIC_ADDPS:
			case Z0_MNEMONIC_MULPS:
			case Z0_MNEMONIC_SUBPS:
			case Z0_MNEMONIC_MINPS:
			case Z0_MNEMONIC_DIVPS:
			case Z0_MNEMONIC_MAXPS:

			case Z0_MNEMONIC_PUNPCKLBW:
			case Z0_MNEMONIC_PUNPCKLWD:
			case Z0_MNEMONIC_PUNPCKLDQ:
			case Z0_MNEMONIC_PACKSSWB:
			case Z0_MNEMONIC_PCMPGTB:
			case Z0_MNEMONIC_PCMPGTW:
			case Z0_MNEMONIC_PCMPGTD:
			case Z0_MNEMONIC_PACKUSWB:

			case Z0_MNEMONIC_PUNPCKHBW:
			case Z0_MNEMONIC_PUNPCKHWD:
			case Z0_MNEMONIC_PUNPCKHDQ:
			case Z0_MNEMONIC_PACKSSDW:
			case Z0_MNEMONIC_PUNPCKLQDQ:
			case Z0_MNEMONIC_PUNPCKHQDQ:

			case Z0_MNEMONIC_MOVD_1:
			case Z0_MNEMONIC_MOVD_2:
			case Z0_MNEMONIC_MOVQ_1:
			case Z0_MNEMONIC_MOVQ_2:

			case Z0_MNEMONIC_PSHUFW:

			case Z0_MNEMONIC_PCMPEQB:
			case Z0_MNEMONIC_PCMPEQW:
			case Z0_MNEMONIC_PCMPEQD:

			case Z0_MNEMONIC_CMPPS:
			case Z0_MNEMONIC_ESC_0F_D0:
			case Z0_MNEMONIC_ESC_0F_D6:
			case Z0_MNEMONIC_ESC_0F_E6:

			case Z0_MNEMONIC_PINSRW:
			case Z0_MNEMONIC_PEXTRW:
			case Z0_MNEMONIC_SHUFPS:

			case Z0_MNEMONIC_PSRLW:
			case Z0_MNEMONIC_PSRLD:
			case Z0_MNEMONIC_PSRLQ:

			case Z0_MNEMONIC_PSLLW:
			case Z0_MNEMONIC_PSLLD:
			case Z0_MNEMONIC_PSLLQ:
			case Z0_MNEMONIC_PMULUDQ:
			case Z0_MNEMONIC_PMADDWD:
			case Z0_MNEMONIC_PSADBW:

			case Z0_MNEMONIC_PSUBUSB:
			case Z0_MNEMONIC_PSUBUSW:
			case Z0_MNEMONIC_PMINUB:
			case Z0_MNEMONIC_PAND:
			case Z0_MNEMONIC_PADDUSB:
			case Z0_MNEMONIC_PADDUSW:
			case Z0_MNEMONIC_PMAXUB:
			case Z0_MNEMONIC_PANDN:

			case Z0_MNEMONIC_PAVGB:
			case Z0_MNEMONIC_PSRAW:
			case Z0_MNEMONIC_PSRAD:
			case Z0_MNEMONIC_PAVGW:
			case Z0_MNEMONIC_PMULHUW:
			case Z0_MNEMONIC_PMULHW:

			case Z0_MNEMONIC_MOVNTQ:
			case Z0_MNEMONIC_MASKMOVQ:

			case Z0_MNEMONIC_PSUBSB:
			case Z0_MNEMONIC_PSUBSW:
			case Z0_MNEMONIC_PMINSW:
			case Z0_MNEMONIC_POR:
			case Z0_MNEMONIC_PADDSB:
			case Z0_MNEMONIC_PADDSW:
			case Z0_MNEMONIC_PMAXSW:
			case Z0_MNEMONIC_PXOR:

			case Z0_MNEMONIC_PSUBB:
			case Z0_MNEMONIC_PSUBW:
			case Z0_MNEMONIC_PSUBD:
			case Z0_MNEMONIC_PSUBQ:
			case Z0_MNEMONIC_PADDB:
			case Z0_MNEMONIC_PADDW:
			case Z0_MNEMONIC_PADDD:

			case Z0_MNEMONIC_MOVUPS:
			case Z0_MNEMONIC_MOVLPS:
			case Z0_MNEMONIC_MOVNTPS:
			case Z0_MNEMONIC_UNPCKLPS:
			case Z0_MNEMONIC_UNPCKHPS:
			case Z0_MNEMONIC_MOVHPS: result =1; break;

		//	case Z0_MNEMONIC_:
		}
	}

	if(context->flags & Z0_FLAG_MOD11_NO_PREFIX_OPERAND)
	{
		if(3 == context->modrm->mod)
		{
			result =0;
		}
	}

	return result;
}

char convert_to_16bitaddr(PZ0_DISASM_CONTEXT context)
{
	int i;
	char result =0;

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->optype[i])
		{
			case Z0_OPTYPE_PTR32:	result =1; context->optype[i] =Z0_OPTYPE_PTR16; break;
			case Z0_OPTYPE_EBX_PTR_1: result =1; break;

		}
	}

	return result;
}

char convert_to_repne(PZ0_DISASM_CONTEXT context)
{
	char result =0;

	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_ESC_0F_D6: 
		case Z0_MNEMONIC_ESC_0F_E6: context->flags |= Z0_FLAG_MOD11_FIXED;

		case Z0_MNEMONIC_CVTPI2PS:
		case Z0_MNEMONIC_CVTTPS2PI:
		case Z0_MNEMONIC_CVTPS2PI:
		case Z0_MNEMONIC_CVTPS2PD:

		case Z0_MNEMONIC_SQRTPS:
		case Z0_MNEMONIC_ADDPS:
		case Z0_MNEMONIC_MULPS:
		case Z0_MNEMONIC_SUBPS:
		case Z0_MNEMONIC_MINPS:
		case Z0_MNEMONIC_DIVPS:
		case Z0_MNEMONIC_MAXPS:

		case Z0_MNEMONIC_PSHUFW:

		case Z0_MNEMONIC_CMPPS:
		case Z0_MNEMONIC_ESC_0F_D0:

		case Z0_MNEMONIC_MOVNTPS:
		case Z0_MNEMONIC_MOVLPS:
		case Z0_MNEMONIC_MOVUPS: result =1; break;

		case Z0_MNEMONIC_ESC_0F_F0: context->mnemonic =Z0_MNEMONIC_LDDQU; result =1; break;
	}

	return result;
}

char convert_to_repe(PZ0_DISASM_CONTEXT context)
{
	char result =0;

	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_ESC_0F_D6: 
		case Z0_MNEMONIC_ESC_0F_E6: context->flags |= Z0_FLAG_MOD11_FIXED;

		case Z0_MNEMONIC_CVTPI2PS:
		case Z0_MNEMONIC_CVTTPS2PI:
		case Z0_MNEMONIC_CVTPS2PI:
		case Z0_MNEMONIC_CVTPS2PD:
		case Z0_MNEMONIC_CVTDQ2PS:

		case Z0_MNEMONIC_SQRTPS:
		case Z0_MNEMONIC_RSQRTPS:
		case Z0_MNEMONIC_RCPPS:
		case Z0_MNEMONIC_ADDPS:
		case Z0_MNEMONIC_MULPS:
		case Z0_MNEMONIC_SUBPS:
		case Z0_MNEMONIC_MINPS:
		case Z0_MNEMONIC_DIVPS:
		case Z0_MNEMONIC_MAXPS:

		case Z0_MNEMONIC_MOVQ_1:
		case Z0_MNEMONIC_MOVQ_2:
		case Z0_MNEMONIC_MOVD_2:

		case Z0_MNEMONIC_PSHUFW:

		case Z0_MNEMONIC_POPCNT:

		case Z0_MNEMONIC_CMPPS:

		case Z0_MNEMONIC_MOVNTPS:
		case Z0_MNEMONIC_MOVHPS:
		case Z0_MNEMONIC_MOVLPS:
		case Z0_MNEMONIC_MOVUPS: result =1; break;
	}

	return result;
}

Z0_STATUS __stdcall process_basic2(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_POPCNT:
		{
			if(Z0_PREFIX_REPE != context->prefix_repeat) return status;
		} break;

		case Z0_MNEMONIC_ESC_0F_F0: return status;
	}

	if(context->modrm)
	{
		switch(context->modrm->mod)
		{
			case 0:
			case 1:
			case 2: if(context->flags & Z0_FLAG_MOD11_FIXED) return status;
		}
	}

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->optype[i])
		{
			case Z0_OPTYPE_IMM8:
			case Z0_OPTYPE_IMM8SIGNED:
			case Z0_OPTYPE_REL8:
			{
				random_bytes(context->bytes + context->length, 1);
				context->length +=1;
			} break;

			case Z0_OPTYPE_IMM16:
			case Z0_OPTYPE_PTR16:
			case Z0_OPTYPE_REL16:
			{
				random_bytes(context->bytes + context->length, 2);
				context->length +=2;
			} break;

			case Z0_OPTYPE_IMM32:
			case Z0_OPTYPE_PTR32:
			case Z0_OPTYPE_REL32:
			{
				random_bytes(context->bytes + context->length, 4);
				context->length +=4;
			} break;

			case Z0_OPTYPE_PTR16_16:
			{
				random_bytes(context->bytes + context->length, 4);
				context->length +=4;
			} break;

			case Z0_OPTYPE_PTR16_32:
			{
				random_bytes(context->bytes + context->length, 6);
				context->length +=6;
			} break;
		}
	}

	context->finish(context);

	return status;
}

Z0_STATUS __stdcall process_ptr(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	if(context->flags & Z0_FLAG_PREFIX_ADDRESS)
	{
		my_context = *context;

		if(convert_to_16bitaddr(&my_context))
		{
			add_prefix(&my_context, Z0_PREFIX_ADDRESS);
			process_basic(&my_context);
		}
	}

	process_basic(context);

	return status;
}

Z0_STATUS __stdcall process_basic(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	if(context->flags & Z0_FLAG_PREFIX_REPNE)
	{
		my_context = *context;

		if(convert_to_repne(&my_context))
		{
			add_prefix(&my_context, Z0_PREFIX_REPNE);
			process_basic2(&my_context);

			if(context->flags & Z0_FLAG_PREFIX_OPERAND)
			{
				if(convert_to_16bit(&my_context))
				{
					add_prefix(&my_context, Z0_PREFIX_OPERAND);
					process_basic2(&my_context);
				}
			}
		}
	}

	if(context->flags & Z0_FLAG_PREFIX_REPE)
	{
		my_context = *context;

		if(convert_to_repe(&my_context))
		{
			add_prefix(&my_context, Z0_PREFIX_REPE);
			process_basic2(&my_context);

			if(context->flags & Z0_FLAG_PREFIX_OPERAND)
			{
				if(convert_to_16bit(&my_context))
				{
					add_prefix(&my_context, Z0_PREFIX_OPERAND);
					process_basic2(&my_context);
				}
			}
		}
	}

	if(context->flags & Z0_FLAG_PREFIX_OPERAND)
	{
		my_context = *context;

		if(convert_to_16bit(&my_context))
		{
			add_prefix(&my_context, Z0_PREFIX_OPERAND);
			process_basic2(&my_context);
		}
	}

	if(context->flags & Z0_FLAG_NOT_OPERAND_UD)
	{
		return process_ud(context);
	}

	process_basic2(context);

	return status;
}

Z0_STATUS __stdcall process_ext0f(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	for(i =0; i < 0x100; i++)
	{
		memset(&my_context, 0, sizeof(Z0_DISASM_CONTEXT));
		my_context.bytes[0] =0x0f;
		my_context.bytes[1] =i;
		my_context.length =2;
		my_context.finish =write_result;

		for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_ext0f[i].optype[j];
		my_context.flags = opcode_ext0f[i].flags;
		my_context.mnemonic = opcode_ext0f[i].mnemonic;

		status =opcode_ext0f[i].process_handler(&my_context);
		if(Z0_STATUS_OK != status)
		{
			printf("ERROR: constructor %s\r\n", translate_status(status));
			break;
		}
	}

	return status;
}

Z0_STATUS __stdcall process_ext38(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

//	for(i =0; i < 0x100; i++)
	for(i =0x00; i < 0x01; i++)
	{
		memset(&my_context, 0, sizeof(Z0_DISASM_CONTEXT));
		my_context.bytes[0] =0x0f;
		my_context.bytes[1] =0x38;
		my_context.bytes[2] =i;
		my_context.length =3;
		my_context.finish =write_result;

		for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_ext38[i].optype[j];
		my_context.flags = opcode_ext38[i].flags;
		my_context.mnemonic = opcode_ext38[i].mnemonic;

		status =opcode_ext38[i].process_handler(&my_context);
		if(Z0_STATUS_OK != status)
		{
			printf("ERROR: constructor %s\r\n", translate_status(status));
			break;
		}
	}

	return status;
}

Z0_STATUS __stdcall process_ext3a(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

//	for(i =0; i < 0x100; i++)
	for(i =0x00; i < 0x01; i++)
	{
		memset(&my_context, 0, sizeof(Z0_DISASM_CONTEXT));
		my_context.bytes[0] =0x0f;
		my_context.bytes[1] =0x3a;
		my_context.bytes[2] =i;
		my_context.length =3;
		my_context.finish =write_result;

		for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_ext3a[i].optype[j];
		my_context.flags = opcode_ext3a[i].flags;
		my_context.mnemonic = opcode_ext3a[i].mnemonic;

		status =opcode_ext3a[i].process_handler(&my_context);
		if(Z0_STATUS_OK != status)
		{
			printf("ERROR: constructor %s\r\n", translate_status(status));
			break;
		}
	}

	return status;
}

Z0_STATUS __stdcall process_sib(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	for(i =0; i < 0x100; i++)
	{
		my_context = *context;

		my_context.sib =(SIB*) (my_context.bytes + my_context.length);

		my_context.bytes[my_context.length++] =i;

		switch(my_context.modrm->mod)
		{
			case 0:
			{
				if((5 == my_context.sib->base) || (5 == my_context.modrm->rm))
				{
					random_bytes(my_context.bytes + my_context.length, 4);
					my_context.length +=4;
				}
			} break;

			case 1:
			{
				random_bytes(my_context.bytes + my_context.length, 1);
				my_context.length +=1;
			} break;

			case 2:
			{
				random_bytes(my_context.bytes + my_context.length, 4);
				my_context.length +=4;
			} break;
		}

		status = process_basic(&my_context);
	}

	return status;
}

Z0_STATUS __stdcall process_reg(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	for(i =0; i < 0x100; i++)
	{
		my_context = *context;

		if(NULL == my_context.modrm)
		{
			my_context.modrm =(MODRM*) (my_context.bytes + my_context.length);
			my_context.bytes[my_context.length++] =i;
		}

		if(my_context.modrm->mod < 3)
		{
			continue;
		}

		status = process_basic(&my_context);
	}

	return status;
}

Z0_STATUS __stdcall process_modrm(PZ0_DISASM_CONTEXT context)
{
	Z0_DISASM_CONTEXT my_context;
	Z0_DISASM_CONTEXT my_context2;
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	for(i =0; i < 0x100; i++)
	{
		my_context = *context;

		if(NULL == my_context.modrm)
		{
			my_context.modrm =(MODRM*) (my_context.bytes + my_context.length);
			my_context.length++;
		}

		*((unsigned char*)(my_context.modrm)) =i;

		for(j =0; j < Z0_MAX_OPERANDS; j++)
		{
			if(Z0_OPTYPE_REG_SEGMENT == my_context.optype[j])
			{
				if(Z0_OPTYPE_ERROR == reg_seg[my_context.modrm->reg]) goto next;

				if(0 == j) if(Z0_OPTYPE_CS == reg_seg[my_context.modrm->reg]) goto next; // mov cs,rm16/32
			}
		}

		switch(my_context.mnemonic)
		{
			case Z0_MNEMONIC_ESC_0F_AE:
			{
				if(3 == my_context.modrm->mod)
				{
					my_context.flags = opcode_0f_ae_11[my_context.modrm->reg].flags;

					for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_0f_ae_11[my_context.modrm->reg].optype[j];

					switch(my_context.modrm->reg)
					{
						case 0: case 1: case 2: case 3: case 4: goto next;
					}
				} else
				{
					my_context.flags = opcode_0f_ae[my_context.modrm->reg].flags;

					for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_0f_ae[my_context.modrm->reg].optype[j];

					switch(my_context.modrm->reg)
					{
						case 6: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_D9:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0: case 1: case 3: case 6: case 7: break;

						case 2:
						{
							switch(my_context.modrm->rm)
							{
								case 0: break;

								default: goto next;
							}
						} break;


						case 4:
						{
							switch(my_context.modrm->rm)
							{
								case 0: case 1: case 4: case 5: break;

								default: goto next;
							}
						} break;

						case 5:
						{
							switch(my_context.modrm->rm)
							{
								case 0: case 1: case 2: case 3: case 4: case 5: case 6: break;

								default: goto next;
							}
						} break;

						default: goto next;
					}
				} else
				{
					switch(my_context.modrm->reg)
					{
						case 0: case 2: case 3: case 4: case 5: case 6: case 7: break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_DA:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	break;

						case 5:
						{
							switch(my_context.modrm->rm)
							{
								case 1: break;

								default: goto next;
							}
						} break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_DB:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	case 5:	case 6: break;

						case 4:
						{
							switch(my_context.modrm->rm)
							{
								case 0: case 1: case 2: case 3: break;

								default: goto next;
							}
						} break;

						default: goto next;
					}
				} else
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	case 5:	case 7: break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_DD:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	case 4:	case 5: break;

						default: goto next;
					}
				} else
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	case 4:	case 6: case 7: break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_DE:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 4:	case 5:	case 6:	case 7:	break;

						case 3:
						{
							switch(my_context.modrm->rm)
							{
								case 1: break;

								default: goto next;
							}
						} break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_DF:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 0:	case 1:	case 2:	case 3:	case 5: case 6: break;

						case 4:
						{
							switch(my_context.modrm->rm)
							{
								case 0: break;

								default: goto next;
							}
						} break;

						default: goto next;
					}
				}
			} break;

			case Z0_MNEMONIC_ESC_F6:
			{
				my_context.mnemonic = opcode_f6[my_context.modrm->reg].mnemonic;

				switch(my_context.modrm->reg)
				{
					case 0:	case 1: my_context.optype[1] =Z0_OPTYPE_IMM8; break;
				}
			} break;

			case Z0_MNEMONIC_ESC_F7:
			{
				my_context.mnemonic = opcode_f7[my_context.modrm->reg].mnemonic;

				switch(my_context.modrm->reg)
				{
					case 0:	case 1: my_context.optype[1] =Z0_OPTYPE_IMM32; break;
				}
			} break;

			case Z0_MNEMONIC_ESC_FE:
			{
				my_context.mnemonic = opcode_fe[my_context.modrm->reg].mnemonic;
				my_context.flags = opcode_fe[my_context.modrm->reg].flags;

				for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_fe[my_context.modrm->reg].optype[j];

				switch(my_context.modrm->reg)
				{
					case 0:	case 1: break;

					default: goto next;
				}
			} break;

			case Z0_MNEMONIC_ESC_FF:
			{
				my_context.mnemonic = opcode_ff[my_context.modrm->reg].mnemonic;
				my_context.flags = opcode_ff[my_context.modrm->reg].flags;

				for(j =0; j < Z0_MAX_OPERANDS; j++) my_context.optype[j] = opcode_ff[my_context.modrm->reg].optype[j];

				switch(my_context.modrm->reg)
				{
					case 0:	case 1: case 2: case 3: case 4: case 5: case 6: break;

					default: goto next;
				}
			} break;

			case Z0_MNEMONIC_SET02:
			{
				switch(my_context.modrm->reg)
				{
					case 0: break;

					default: goto next;
				}
			} break;

			case Z0_MNEMONIC_SET04:
			{
				switch(my_context.modrm->reg)
				{
					case 0: break;

					default: goto next;
				}
			} break;

			case Z0_MNEMONIC_SET05:
			{
				switch(my_context.modrm->reg)
				{
					case 0:
					case 1:
					case 2:
					case 3:
					case 4:
					case 5: break;

					default: goto next;
				}
			} break;

			case Z0_MNEMONIC_SET06:
			{
				if(3 == my_context.modrm->mod)
				{
					switch(my_context.modrm->reg)
					{
						case 4:
						case 6: break;

						default:
						{
							switch(my_context.bytes[my_context.length -1])
							{
								case 0xc1:
								case 0xc2:
								case 0xc3:
								case 0xc4:
								case 0xc8:
								case 0xc9:
								case 0xd0:
								case 0xd1:
								case 0xd8:
								case 0xd9:
								case 0xda:
								case 0xdb:
								case 0xdc:
								case 0xdd:
								case 0xde:
								case 0xdf:
								case 0xf9:
								{
									for(j =0; j < Z0_MAX_OPERANDS; j++)
									{
										my_context.optype[j] =my_context.operand[j].type =Z0_OPTYPE_NULL;
									}

									status =process_basic(&my_context);
								}
							}
							goto next;
						}
					}
				} else
				{
					switch(my_context.modrm->reg)
					{
						case 0:
						case 1:
						case 2:
						case 3:
						case 4:
						case 6:
						case 7: break;

						default: goto next;
					}
				}
			} break;
		}

		if(my_context.modrm->mod < 3)
		{
			if(my_context.flags & Z0_FLAG_NOT_MOD11_UD) goto next;
			if(my_context.flags & Z0_FLAG_MOD11_FIXED) goto next;

			if(context->flags & Z0_FLAG_PREFIX_ADDRESS)
			{
				my_context2 = my_context;

				add_prefix(&my_context2, Z0_PREFIX_ADDRESS);

				switch(my_context2.modrm->mod)
				{
					case 0:
					{
						if(6 == my_context2.modrm->rm)
						{
							random_bytes(my_context2.bytes + my_context2.length, 2);
							my_context2.length +=2;
						}
					} break;

					case 1:
					{
						random_bytes(my_context2.bytes + my_context2.length, 1);
						my_context2.length +=1;
					} break;

					case 2:
					{
						random_bytes(my_context2.bytes + my_context2.length, 2);
						my_context2.length +=2;
					} break;
				}

				process_basic(&my_context2);
			}

			if(my_context.modrm->rm == 4)
			{
				status = process_sib(&my_context);
			} else
			{
				switch(my_context.modrm->mod)
				{
					case 0:
					{
						if(5 == my_context.modrm->rm)
						{
							random_bytes(my_context.bytes + my_context.length, 4);
							my_context.length +=4;
						}
					} break;

					case 1:
					{
						random_bytes(my_context.bytes + my_context.length, 1);
						my_context.length +=1;
					} break;

					case 2:
					{
						random_bytes(my_context.bytes + my_context.length, 4);
						my_context.length +=4;
					} break;
				}

				status = process_basic(&my_context);
			}
		} else
		{
			if(my_context.flags & Z0_FLAG_MOD11_UD) goto next;

			status = process_basic(&my_context);
		}

		next:
		;
	}

	return status;
}
