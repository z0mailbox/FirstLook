#include "common.h"

#include <windows.h>

Z0_STATUS __stdcall process_error(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;

	printf("ERROR: invalid call\r\n");

	return status;
}

Z0_STATUS __stdcall process_ud(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	context->mnemonic =Z0_MNEMONIC_UD;

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		context->operand[i].type =Z0_OPTYPE_NULL;
	}

	if(context->finish) context->finish(context);

	return status;
}

void prefix_repne(PZ0_DISASM_CONTEXT context)
{
	if(Z0_PREFIX_REPNE == context->prefix_repeat)
	{
		switch(context->mnemonic)
		{
			case Z0_MNEMONIC_MOVUPS:	context->mnemonic = Z0_MNEMONIC_MOVSD_; break;
			case Z0_MNEMONIC_MOVHLPS:
			case Z0_MNEMONIC_MOVLPS:	context->mnemonic = Z0_MNEMONIC_MOVDDUP; break;
			case Z0_MNEMONIC_MOVNTPS:	context->mnemonic = Z0_MNEMONIC_MOVNTSD; break;

			case Z0_MNEMONIC_CVTPI2PS:	context->mnemonic = Z0_MNEMONIC_CVTSI2SD; context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG32; break;
			case Z0_MNEMONIC_CVTTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTTSD2SI; context->optype[0] =Z0_OPTYPE_REG32; break;
			case Z0_MNEMONIC_CVTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTSD2SI; context->optype[0] =Z0_OPTYPE_REG32; break;
			case Z0_MNEMONIC_CVTPS2PD:	context->mnemonic = Z0_MNEMONIC_CVTSD2SS; break;

			case Z0_MNEMONIC_SQRTPS:	context->mnemonic = Z0_MNEMONIC_SQRTSD; break;
			case Z0_MNEMONIC_ADDPS:		context->mnemonic = Z0_MNEMONIC_ADDSD; break;
			case Z0_MNEMONIC_MULPS:		context->mnemonic = Z0_MNEMONIC_MULSD; break;
			case Z0_MNEMONIC_SUBPS:		context->mnemonic = Z0_MNEMONIC_SUBSD; break;
			case Z0_MNEMONIC_MINPS:		context->mnemonic = Z0_MNEMONIC_MINSD; break;
			case Z0_MNEMONIC_DIVPS:		context->mnemonic = Z0_MNEMONIC_DIVSD; break;
			case Z0_MNEMONIC_MAXPS:		context->mnemonic = Z0_MNEMONIC_MAXSD; break;

			case Z0_MNEMONIC_PSHUFW:
			{
				context->mnemonic = Z0_MNEMONIC_PSHUFLW;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_ESC_0F_D0:	context->mnemonic = Z0_MNEMONIC_ADDSUBPS; break;

			case Z0_MNEMONIC_ESC_0F_D6:
			{
				context->mnemonic = Z0_MNEMONIC_MOVDQ2Q;
				context->optype[0] =Z0_OPTYPE_REG_MM;
				context->optype[1] =Z0_OPTYPE_RM32;
				context->flags |= Z0_FLAG_MOD11_FIXED;
			} break;

			case Z0_MNEMONIC_ESC_0F_E6: context->mnemonic = Z0_MNEMONIC_CVTPD2DQ; break;

			case Z0_MNEMONIC_ESC_0F_F0: context->mnemonic =Z0_MNEMONIC_LDDQU; break;
		}
	}
}

void prefix_repe(PZ0_DISASM_CONTEXT context)
{
	if(Z0_PREFIX_REPE == context->prefix_repeat)
	{
		switch(context->mnemonic)
		{
			case Z0_MNEMONIC_MOVUPS:	context->mnemonic = Z0_MNEMONIC_MOVSS; break;
			case Z0_MNEMONIC_MOVHLPS:
			case Z0_MNEMONIC_MOVLPS:	context->mnemonic = Z0_MNEMONIC_MOVSLDUP; break;
			case Z0_MNEMONIC_MOVLHPS:
			case Z0_MNEMONIC_MOVHPS:	context->mnemonic = Z0_MNEMONIC_MOVSHDUP; break;
			case Z0_MNEMONIC_MOVNTPS:	context->mnemonic = Z0_MNEMONIC_MOVNTSS; break;

			case Z0_MNEMONIC_CVTPI2PS:	context->mnemonic = Z0_MNEMONIC_CVTSI2SS; context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG32; break;
			case Z0_MNEMONIC_CVTTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTTSS2SI; context->optype[0] =Z0_OPTYPE_REG32; break;
			case Z0_MNEMONIC_CVTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTSS2SI; context->optype[0] =Z0_OPTYPE_REG32; break;
			case Z0_MNEMONIC_CVTPS2PD:	context->mnemonic = Z0_MNEMONIC_CVTSS2SD; break;
			case Z0_MNEMONIC_CVTDQ2PS:	context->mnemonic = Z0_MNEMONIC_CVTTPS2DQ; break;

			case Z0_MNEMONIC_SQRTPS:	context->mnemonic = Z0_MNEMONIC_SQRTSS; break;
			case Z0_MNEMONIC_RSQRTPS:	context->mnemonic = Z0_MNEMONIC_RSQRTSS; break;
			case Z0_MNEMONIC_RCPPS:		context->mnemonic = Z0_MNEMONIC_RCPSS; break;
			case Z0_MNEMONIC_ADDPS:		context->mnemonic = Z0_MNEMONIC_ADDSS; break;
			case Z0_MNEMONIC_MULPS:		context->mnemonic = Z0_MNEMONIC_MULSS; break;
			case Z0_MNEMONIC_SUBPS:		context->mnemonic = Z0_MNEMONIC_SUBSS; break;
			case Z0_MNEMONIC_MINPS:		context->mnemonic = Z0_MNEMONIC_MINSS; break;
			case Z0_MNEMONIC_DIVPS:		context->mnemonic = Z0_MNEMONIC_DIVSS; break;
			case Z0_MNEMONIC_MAXPS:		context->mnemonic = Z0_MNEMONIC_MAXSS; break;

			case Z0_MNEMONIC_MOVQ_1:
			{
				context->mnemonic = Z0_MNEMONIC_MOVDQU;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MOVQ_2:
			{
				context->mnemonic = Z0_MNEMONIC_MOVDQU;
				context->optype[1] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_PSHUFW:
			{
				context->mnemonic = Z0_MNEMONIC_PSHUFHW;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MOVD_2:
			{
				context->mnemonic = Z0_MNEMONIC_MOVQ_3;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->optype[1] =Z0_OPTYPE_RM32;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_ESC_0F_D6:
			{
				context->mnemonic = Z0_MNEMONIC_MOVQ2DQ;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->optype[1] =Z0_OPTYPE_RM32;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_MM;
				context->flags |= Z0_FLAG_MOD11_FIXED;
			} break;

			case Z0_MNEMONIC_ESC_0F_E6:	context->mnemonic = Z0_MNEMONIC_CVTDQ2PD; break;
		}
	}
}

void prefix_operand(PZ0_DISASM_CONTEXT context)
{
	int i;

	if(Z0_PREFIX_OPERAND == context->prefix_operand)
	{
		if(context->flags & Z0_FLAG_PREFIX_REPNE)
		{
			if(Z0_PREFIX_REPNE == context->prefix_repeat)
			{
				return;
			}
		}

		if(context->flags & Z0_FLAG_PREFIX_REPE)
		{
			if(Z0_PREFIX_REPE == context->prefix_repeat)
			{
				return;
			}
		}

		if(!(context->flags & Z0_FLAG_NO_OPERAND_CONVERSION))
		{
			for(i =0; i < Z0_MAX_OPERANDS; i++)
			{
				switch(context->operand[i].type)
				{
					case Z0_OPTYPE_IMM32:	context->operand[i].type =Z0_OPTYPE_IMM16; break;
					case Z0_OPTYPE_REL32:	context->operand[i].type =Z0_OPTYPE_REL16; break;

					case Z0_OPTYPE_PTR16_32:context->operand[i].type =Z0_OPTYPE_PTR16_16; break;

					case Z0_OPTYPE_EAX:	context->operand[i].type =Z0_OPTYPE_AX; break;
					case Z0_OPTYPE_ECX:	context->operand[i].type =Z0_OPTYPE_CX; break;
					case Z0_OPTYPE_EDX:	context->operand[i].type =Z0_OPTYPE_DX; break;
					case Z0_OPTYPE_EBX:	context->operand[i].type =Z0_OPTYPE_BX; break;
					case Z0_OPTYPE_ESP:	context->operand[i].type =Z0_OPTYPE_SP; break;
					case Z0_OPTYPE_EBP:	context->operand[i].type =Z0_OPTYPE_BP; break;
					case Z0_OPTYPE_ESI:	context->operand[i].type =Z0_OPTYPE_SI; break;
					case Z0_OPTYPE_EDI:	context->operand[i].type =Z0_OPTYPE_DI; break;
				}
			}
		}

		switch(context->mnemonic)
		{
			case Z0_MNEMONIC_PUSHAD:	context->mnemonic = Z0_MNEMONIC_PUSHA; break;
			case Z0_MNEMONIC_POPAD:		context->mnemonic = Z0_MNEMONIC_POPA; break;

			case Z0_MNEMONIC_INSD:		context->mnemonic = Z0_MNEMONIC_INSW; break;
			case Z0_MNEMONIC_OUTSD:		context->mnemonic = Z0_MNEMONIC_OUTSW; break;

			case Z0_MNEMONIC_CWDE:		context->mnemonic = Z0_MNEMONIC_CBW; break;
			case Z0_MNEMONIC_CDQ:		context->mnemonic = Z0_MNEMONIC_CWD; break;

			case Z0_MNEMONIC_PUSHFD:	context->mnemonic = Z0_MNEMONIC_PUSHF; break;
			case Z0_MNEMONIC_POPFD:		context->mnemonic = Z0_MNEMONIC_POPF; break;

			case Z0_MNEMONIC_MOVSD:		context->mnemonic = Z0_MNEMONIC_MOVSW; break;
			case Z0_MNEMONIC_CMPSD:		context->mnemonic = Z0_MNEMONIC_CMPSW; break;
			case Z0_MNEMONIC_STOSD:		context->mnemonic = Z0_MNEMONIC_STOSW; break;
			case Z0_MNEMONIC_LODSD:		context->mnemonic = Z0_MNEMONIC_LODSW; break;
			case Z0_MNEMONIC_SCASD:		context->mnemonic = Z0_MNEMONIC_SCASW; break;

			case Z0_MNEMONIC_MOVAPS:	context->mnemonic = Z0_MNEMONIC_MOVAPD; break;
			case Z0_MNEMONIC_MOVUPS:	context->mnemonic = Z0_MNEMONIC_MOVUPD; break;
			case Z0_MNEMONIC_MOVLPS:	context->mnemonic = Z0_MNEMONIC_MOVLPD; break;
			case Z0_MNEMONIC_UNPCKLPS:	context->mnemonic = Z0_MNEMONIC_UNPCKLPD; break;
			case Z0_MNEMONIC_UNPCKHPS:	context->mnemonic = Z0_MNEMONIC_UNPCKHPD; break;
			case Z0_MNEMONIC_MOVHPS:	context->mnemonic = Z0_MNEMONIC_MOVHPD; break;
			case Z0_MNEMONIC_MOVNTPS:	context->mnemonic = Z0_MNEMONIC_MOVNTPD; break;

			case Z0_MNEMONIC_JECXZ:		context->mnemonic = Z0_MNEMONIC_JCXZ; break;

			case Z0_MNEMONIC_CVTPI2PS:	context->mnemonic = Z0_MNEMONIC_CVTPI2PD; break;
			case Z0_MNEMONIC_CVTTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTTPD2PI; break;
			case Z0_MNEMONIC_CVTPS2PI:	context->mnemonic = Z0_MNEMONIC_CVTPD2PI; break;
			case Z0_MNEMONIC_CVTPS2PD:	context->mnemonic = Z0_MNEMONIC_CVTPD2PS; break;
			case Z0_MNEMONIC_CVTDQ2PS:	context->mnemonic = Z0_MNEMONIC_CVTPS2DQ; break;

			case Z0_MNEMONIC_ESC_0F_D6:	context->mnemonic = Z0_MNEMONIC_MOVQ_3; break;

			case Z0_MNEMONIC_ESC_0F_E6:	context->mnemonic = Z0_MNEMONIC_CVTTPD2DQ; break;
			
			case Z0_MNEMONIC_UCOMISS:	context->mnemonic = Z0_MNEMONIC_UCOMISD; break;
			case Z0_MNEMONIC_COMISS:	context->mnemonic = Z0_MNEMONIC_COMISD; break;

			case Z0_MNEMONIC_SHUFPS:	context->mnemonic = Z0_MNEMONIC_SHUFPD; break;
			case Z0_MNEMONIC_ESC_0F_D0:	context->mnemonic = Z0_MNEMONIC_ADDSUBPD; break;

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

			case Z0_MNEMONIC_PSHUFB:
			case Z0_MNEMONIC_PCMPEQB:
			case Z0_MNEMONIC_PCMPEQW:
			case Z0_MNEMONIC_PCMPEQD:

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

			case Z0_MNEMONIC_PSUBSB:
			case Z0_MNEMONIC_PSUBSW:
			case Z0_MNEMONIC_PMINSW:
			case Z0_MNEMONIC_POR:
			case Z0_MNEMONIC_PADDSB:
			case Z0_MNEMONIC_PADDSW:
			case Z0_MNEMONIC_PMAXSW:
			case Z0_MNEMONIC_PXOR:
			{
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_PMOVMSKB:
			{
			//	context->optype[1] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MOVMSKPS:	context->mnemonic = Z0_MNEMONIC_MOVMSKPD; break;
			case Z0_MNEMONIC_SQRTPS:	context->mnemonic = Z0_MNEMONIC_SQRTPD; break;
			case Z0_MNEMONIC_ANDPS:		context->mnemonic = Z0_MNEMONIC_ANDPD; break;
			case Z0_MNEMONIC_ANDNPS:	context->mnemonic = Z0_MNEMONIC_ANDNPD; break;
			case Z0_MNEMONIC_ORPS:		context->mnemonic = Z0_MNEMONIC_ORPD; break;
			case Z0_MNEMONIC_XORPS:		context->mnemonic = Z0_MNEMONIC_XORPD; break;
			case Z0_MNEMONIC_ADDPS:		context->mnemonic = Z0_MNEMONIC_ADDPD; break;
			case Z0_MNEMONIC_MULPS:		context->mnemonic = Z0_MNEMONIC_MULPD; break;
			case Z0_MNEMONIC_SUBPS:		context->mnemonic = Z0_MNEMONIC_SUBPD; break;
			case Z0_MNEMONIC_MINPS:		context->mnemonic = Z0_MNEMONIC_MINPD; break;
			case Z0_MNEMONIC_DIVPS:		context->mnemonic = Z0_MNEMONIC_DIVPD; break;
			case Z0_MNEMONIC_MAXPS:		context->mnemonic = Z0_MNEMONIC_MAXPD; break;

			case Z0_MNEMONIC_MOVD_1: context->optype[0] =Z0_OPTYPE_REG_XMM; break;
			case Z0_MNEMONIC_MOVD_2: context->optype[1] =Z0_OPTYPE_REG_XMM; break;

			case Z0_MNEMONIC_MOVQ_1:
			{
				context->mnemonic = Z0_MNEMONIC_MOVDQA;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MOVQ_2:
			{
				context->mnemonic = Z0_MNEMONIC_MOVDQA;
				context->optype[1] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MOVNTQ:
			{
				context->mnemonic = Z0_MNEMONIC_MOVNTDQ;
				context->optype[1] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_PSHUFW:
			{
				context->mnemonic = Z0_MNEMONIC_PSHUFD;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_PINSRW: context->optype[0] =Z0_OPTYPE_REG_XMM; break;
			case Z0_MNEMONIC_PEXTRW:
			{
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_PSRLW:
			case Z0_MNEMONIC_PSRLD:
			case Z0_MNEMONIC_PSRLQ:
			case Z0_MNEMONIC_PSLLW:
			case Z0_MNEMONIC_PSLLD:
			case Z0_MNEMONIC_PSLLQ:
			case Z0_MNEMONIC_PMULUDQ:
			case Z0_MNEMONIC_PMADDWD:
			case Z0_MNEMONIC_PSADBW:
			case Z0_MNEMONIC_PSUBB:
			case Z0_MNEMONIC_PSUBW:
			case Z0_MNEMONIC_PSUBD:
			case Z0_MNEMONIC_PSUBQ:
			case Z0_MNEMONIC_PADDB:
			case Z0_MNEMONIC_PADDW:
			case Z0_MNEMONIC_PADDD:
			{
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;

			case Z0_MNEMONIC_MASKMOVQ:
			{
				context->mnemonic = Z0_MNEMONIC_MASKMOVDQU;
				context->optype[0] =Z0_OPTYPE_REG_XMM;
				context->flags &= ~Z0_OVERRIDE_REG;
				context->flags |= Z0_OVERRIDE_REG_XMM;
			} break;


		//	case Z0_MNEMONIC_VMREAD:
		//	{
		//		context->mnemonic = Z0_MNEMONIC_EXTRQ;
		//		context->optype[0] =Z0_OPTYPE_REG_XMM;
		//		context->optype[1] =Z0_OPTYPE_IMM8;
		//		context->optype[2] =Z0_OPTYPE_IMM8;
		//	} break;
		}
	}
}

void prefix_address(PZ0_DISASM_CONTEXT context)
{
	int i;

	if(Z0_PREFIX_ADDRESS == context->prefix_address)
	{
		for(i =0; i < Z0_MAX_OPERANDS; i++)
		{
			switch(context->operand[i].type)
			{
				case Z0_OPTYPE_PTR32:	context->operand[i].type =Z0_OPTYPE_PTR16; break;
				case Z0_OPTYPE_EBX_PTR_1: context->operand[i].type =Z0_OPTYPE_BX_PTR_1; break;
			}
		}

		switch(context->mnemonic)
		{
			case Z0_MNEMONIC_XLAT: context->mnemonic =Z0_MNEMONIC_XLATB; break;
		}
	}
}

Z0_STATUS __stdcall process_ptr(PZ0_DISASM_CONTEXT context)
{
	prefix_address(context);

	return process_basic(context);
}

Z0_STATUS __stdcall process_basic(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i;

	prefix_operand(context);
	prefix_repe(context);
	prefix_repne(context);

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->operand[i].type)
		{
			case Z0_OPTYPE_IMM8:
			{
				unsigned char* src;
				unsigned char* dst;

				src =context->addr_ptr +context->length;
				dst =context->bytes +context->length;

				context->operand[i].value.imm8 = *dst = *src;
				context->length++;
			} break;
		
			case Z0_OPTYPE_IMM8SIGNED:
			{
				char* src;
				char* dst;

				src =(char*) (context->addr_ptr +context->length);
				dst =(char*) (context->bytes +context->length);

				context->operand[i].value.imm8signed = *dst = *src;
				context->length++;
			} break;

			case Z0_OPTYPE_REL8:
			{
				char* src;
				char* dst;

				src =(char*) (context->addr_ptr +context->length);
				dst =(char*) (context->bytes +context->length);

				context->operand[i].value.rel32 = *dst = *src;
				context->length++;
				context->operand[i].value.rel32 += (unsigned int) (context->addr_ptr +context->length);
			} break;

			case Z0_OPTYPE_IMM16:
			{
				unsigned short* src;
				unsigned short* dst;

				src =(unsigned short*) (context->addr_ptr +context->length);
				dst =(unsigned short*) (context->bytes +context->length);

				context->operand[i].value.imm16 = *dst = *src;
				context->length +=2;
			} break;

			case Z0_OPTYPE_REL16:
			{
				unsigned short* src;
				unsigned short* dst;

				src =(unsigned short*) (context->addr_ptr +context->length);
				dst =(unsigned short*) (context->bytes +context->length);

				context->operand[i].value.rel32 = *dst = *src;
				context->length +=2;
				context->operand[i].value.rel32 += (unsigned int) (context->addr_ptr +context->length);
			} break;

			case Z0_OPTYPE_IMM32:
			{
				unsigned int* src;
				unsigned int* dst;

				src =(unsigned int*) (context->addr_ptr +context->length);
				dst =(unsigned int*) (context->bytes +context->length);

				context->operand[i].value.imm32 = *dst = *src;
				context->length +=4;
			} break;

			case Z0_OPTYPE_REL32:
			{
				unsigned int* src;
				unsigned int* dst;

				src =(unsigned int*) (context->addr_ptr +context->length);
				dst =(unsigned int*) (context->bytes +context->length);

				context->operand[i].value.rel32 = *dst = *src;
				context->length +=4;
				context->operand[i].value.rel32 += (unsigned int) (context->addr_ptr +context->length);
			} break;

			case Z0_OPTYPE_PTR16_16:
			{
				unsigned short* src_segment;
				unsigned short* dst_segment;
				unsigned short* src_offset;
				unsigned short* dst_offset;

				src_offset =(unsigned short*) (context->addr_ptr +context->length);
				dst_offset =(unsigned short*) (context->bytes +context->length);

				context->operand[i].value.imm16 = *dst_offset = *src_offset;
				context->length +=2;

				src_segment =(unsigned short*) (context->addr_ptr +context->length);
				dst_segment =(unsigned short*) (context->bytes +context->length);

				context->operand[i].segment = *dst_segment = *src_segment;
				context->length +=2;
			} break;

			case Z0_OPTYPE_PTR16_32:
			{
				unsigned short* src_segment;
				unsigned short* dst_segment;
				unsigned int* src_offset;
				unsigned int* dst_offset;

				src_offset =(unsigned int*) (context->addr_ptr +context->length);
				dst_offset =(unsigned int*) (context->bytes +context->length);

				context->operand[i].value.imm32 = *dst_offset = *src_offset;
				context->length +=4;

				src_segment =(unsigned short*) (context->addr_ptr +context->length);
				dst_segment =(unsigned short*) (context->bytes +context->length);

				context->operand[i].segment = *dst_segment = *src_segment;
				context->length +=2;
			} break;

			case Z0_OPTYPE_PTR16:
			{
				unsigned short* src_offset;
				unsigned short* dst_offset;

				src_offset =(unsigned short*) (context->addr_ptr +context->length);
				dst_offset =(unsigned short*) (context->bytes +context->length);

				context->operand[i].value.imm16 = *dst_offset = *src_offset;
				context->length +=2;
			} break;

			case Z0_OPTYPE_PTR32:
			{
				unsigned int* src_offset;
				unsigned int* dst_offset;

				src_offset =(unsigned int*) (context->addr_ptr +context->length);
				dst_offset =(unsigned int*) (context->bytes +context->length);

				context->operand[i].value.imm32 = *dst_offset = *src_offset;
				context->length +=4;
			} break;

		//	case Z0_OPTYPE_REG8:		context->operand[i].type =reg8[context->modrm->reg]; break;
		//	case Z0_OPTYPE_REG16:		context->operand[i].type =reg16[context->modrm->reg]; break;
			case Z0_OPTYPE_REG32:		context->operand[i].type =reg32[context->modrm->rm]; break;

			case Z0_OPTYPE_REG_ST:		context->operand[i].type =reg_st[context->modrm->rm]; break;

		//	case Z0_OPTYPE_REG_MM: context->operand[i].type =reg_mm[context->modrm->rm]; break;
		//	case Z0_OPTYPE_REG_XMM: context->operand[i].type =reg_xmm[context->modrm->rm]; break;

			case Z0_OPTYPE_REG_CONTROL:	context->operand[i].type =reg_control[context->modrm->reg]; break;
			case Z0_OPTYPE_REG_DEBUG:	context->operand[i].type =reg_debug[context->modrm->reg]; break;
			case Z0_OPTYPE_REG_TEST:	context->operand[i].type =reg_test[context->modrm->reg]; break;
		}
	}

	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_CMPPS:
		{
			context->operand[2].type =Z0_OPTYPE_NULL; // do not print IMM8 comparasion predicate

			switch(context->operand[2].value.imm8 &7)
			{
				case 0: context->mnemonic =Z0_MNEMONIC_CMPEQPS; break;
				case 1: context->mnemonic =Z0_MNEMONIC_CMPLTPS; break;
				case 2: context->mnemonic =Z0_MNEMONIC_CMPLEPS; break;
				case 3: context->mnemonic =Z0_MNEMONIC_CMPUNORDPS; break;
				case 4: context->mnemonic =Z0_MNEMONIC_CMPNEQPS; break;
				case 5: context->mnemonic =Z0_MNEMONIC_CMPNLTPS; break;
				case 6: context->mnemonic =Z0_MNEMONIC_CMPNLEPS; break;
				case 7: context->mnemonic =Z0_MNEMONIC_CMPORDPS; break;
			}

			if(Z0_PREFIX_REPNE == context->prefix_repeat)
			{
				switch(context->operand[2].value.imm8 &7)
				{
					case 0: context->mnemonic =Z0_MNEMONIC_CMPEQSD; break;
					case 1: context->mnemonic =Z0_MNEMONIC_CMPLTSD; break;
					case 2: context->mnemonic =Z0_MNEMONIC_CMPLESD; break;
					case 3: context->mnemonic =Z0_MNEMONIC_CMPUNORDSD; break;
					case 4: context->mnemonic =Z0_MNEMONIC_CMPNEQSD; break;
					case 5: context->mnemonic =Z0_MNEMONIC_CMPNLTSD; break;
					case 6: context->mnemonic =Z0_MNEMONIC_CMPNLESD; break;
					case 7: context->mnemonic =Z0_MNEMONIC_CMPORDSD; break;
				} break;
			}

			if(Z0_PREFIX_REPE == context->prefix_repeat)
			{
				switch(context->operand[2].value.imm8 &7)
				{
					case 0: context->mnemonic =Z0_MNEMONIC_CMPEQSS; break;
					case 1: context->mnemonic =Z0_MNEMONIC_CMPLTSS; break;
					case 2: context->mnemonic =Z0_MNEMONIC_CMPLESS; break;
					case 3: context->mnemonic =Z0_MNEMONIC_CMPUNORDSS; break;
					case 4: context->mnemonic =Z0_MNEMONIC_CMPNEQSS; break;
					case 5: context->mnemonic =Z0_MNEMONIC_CMPNLTSS; break;
					case 6: context->mnemonic =Z0_MNEMONIC_CMPNLESS; break;
					case 7: context->mnemonic =Z0_MNEMONIC_CMPORDSS; break;
				} break;
			}

			if(Z0_PREFIX_OPERAND == context->prefix_operand)
			{
				switch(context->operand[2].value.imm8 &7)
				{
					case 0: context->mnemonic =Z0_MNEMONIC_CMPEQPD; break;
					case 1: context->mnemonic =Z0_MNEMONIC_CMPLTPD; break;
					case 2: context->mnemonic =Z0_MNEMONIC_CMPLEPD; break;
					case 3: context->mnemonic =Z0_MNEMONIC_CMPUNORDPD; break;
					case 4: context->mnemonic =Z0_MNEMONIC_CMPNEQPD; break;
					case 5: context->mnemonic =Z0_MNEMONIC_CMPNLTPD; break;
					case 6: context->mnemonic =Z0_MNEMONIC_CMPNLEPD; break;
					case 7: context->mnemonic =Z0_MNEMONIC_CMPORDPD; break;
				} break;
			}
		} break;
	}

	if(context->finish) context->finish(context);

	return status;
}

Z0_STATUS __stdcall process_ext0f(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	i =context->bytes[context->length] =context->addr_ptr[context->length];
	context->length++;

	context->mnemonic = opcode_ext0f[i].mnemonic;
	context->flags = opcode_ext0f[i].flags;

	for(j =0; j < Z0_MAX_OPERANDS; j++)
	{
		context->optype[j] = context->operand[j].type = opcode_ext0f[i].optype[j];
	}

	return opcode_ext0f[i].process_handler(context);
}

Z0_STATUS __stdcall process_ext38(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	i =context->bytes[context->length] =context->addr_ptr[context->length];
	context->length++;

	context->mnemonic = opcode_ext38[i].mnemonic;
	context->flags = opcode_ext38[i].flags;

	for(j =0; j < Z0_MAX_OPERANDS; j++)
	{
		context->optype[j] = context->operand[j].type = opcode_ext38[i].optype[j];
	}

	return opcode_ext38[i].process_handler(context);
}

Z0_STATUS __stdcall process_ext3a(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	int i, j;

	i =context->bytes[context->length] =context->addr_ptr[context->length];
	context->length++;

	context->mnemonic = opcode_ext3a[i].mnemonic;
	context->flags = opcode_ext3a[i].flags;

	for(j =0; j < Z0_MAX_OPERANDS; j++)
	{
		context->optype[j] = context->operand[j].type = opcode_ext3a[i].optype[j];
	}

	return opcode_ext3a[i].process_handler(context);
}

Z0_STATUS __stdcall process_reg(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;

	if(!context->modrm)
	{
		context->modrm =(MODRM*) (context->addr_ptr +context->length);

		context->bytes[context->length] =context->addr_ptr[context->length];
		context->length++;
	}

	return process_basic(context);
}

Z0_STATUS __stdcall process_modrm(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	PZ0_OPCODE_TABLE table =NULL;
	int i, j;

	if(!context->modrm)
	{
		context->modrm =(MODRM*) (context->addr_ptr +context->length);

		context->bytes[context->length] =context->addr_ptr[context->length];
		context->length++;
	}

	prefix_repe(context);
	prefix_repne(context);
	prefix_operand(context);

	// escape corrector
	//
	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_ESC_0F_D0:
		case Z0_MNEMONIC_ESC_0F_D6:
		case Z0_MNEMONIC_ESC_0F_E6:
		{
			context->mnemonic =Z0_MNEMONIC_UD;
		} break;

		case Z0_MNEMONIC_ESC_D8:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_d8_11 +context->modrm->reg;

			} else context->mnemonic =Z0_MNEMONIC_SET_08;
		} break;

		case Z0_MNEMONIC_ESC_D9:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_d9_11 +context->modrm->reg;

				switch(context->modrm->reg)
				{
					case 2: table =opcode_d9_11_2 +context->modrm->rm; break;
					case 4: table =opcode_d9_11_4 +context->modrm->rm; break;
					case 5: table =opcode_d9_11_5 +context->modrm->rm; break;
					case 6: table =opcode_d9_11_6 +context->modrm->rm; break;
					case 7: table =opcode_d9_11_7 +context->modrm->rm; break;
				}

			} else table =opcode_d9 +context->modrm->reg;
		} break;

		case Z0_MNEMONIC_ESC_DA:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_da_11 +context->modrm->reg;

				switch(context->modrm->reg)
				{
					case 5: table =opcode_da_11_5 +context->modrm->rm; break;
				}

			} else context->mnemonic =Z0_MNEMONIC_SET_09;
		} break;

		case Z0_MNEMONIC_ESC_DB:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_db_11 +context->modrm->reg;

				switch(context->modrm->reg)
				{
					case 4: table =opcode_db_11_4 +context->modrm->rm; break;
				}

			} else table =opcode_db +context->modrm->reg;
		} break;

		case Z0_MNEMONIC_ESC_DC:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_dc_11 +context->modrm->reg;

			} else context->mnemonic =Z0_MNEMONIC_SET_08;
		} break;

		case Z0_MNEMONIC_ESC_DD:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_dd_11 +context->modrm->reg;

			} else table =opcode_dd +context->modrm->reg;
		} break;

		case Z0_MNEMONIC_ESC_DE:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_de_11 +context->modrm->reg;

				switch(context->modrm->reg)
				{
					case 3: table =opcode_de_11_3 +context->modrm->rm; break;
				}

			} else context->mnemonic =Z0_MNEMONIC_SET_09;
		} break;

		case Z0_MNEMONIC_ESC_DF:
		{
			if(3 == context->modrm->mod)
			{
				table =opcode_df_11 +context->modrm->reg;

				switch(context->modrm->reg)
				{
					case 4: table =opcode_df_11_4 +context->modrm->rm; break;
				}

			} else table =opcode_df +context->modrm->reg;
		} break;

		case Z0_MNEMONIC_ESC_F6: table =opcode_f6 +context->modrm->reg; break;
		case Z0_MNEMONIC_ESC_F7: table =opcode_f7 +context->modrm->reg; break;
		case Z0_MNEMONIC_ESC_FE: table =opcode_fe +context->modrm->reg; break;
		case Z0_MNEMONIC_ESC_FF: table =opcode_ff +context->modrm->reg; break;

		case Z0_MNEMONIC_ESC_0F_AE:
		{
			if(3 == context->modrm->mod) table =opcode_0f_ae_11 +context->modrm->reg;
			else table =opcode_0f_ae +context->modrm->reg;
		} break;
	}

	if(table)
	{
		context->mnemonic = table->mnemonic;
		context->flags = table->flags;

		for(i =0; i < Z0_MAX_OPERANDS; i++)
		{
			context->optype[i] = context->operand[i].type = table->optype[i];
		}

		return table->process_handler(context);
	}

	// mnemonic corrector
	//
	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_SET01:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_ADD; break;
				case 1: context->mnemonic = Z0_MNEMONIC_OR; break;
				case 2: context->mnemonic = Z0_MNEMONIC_ADC; break;
				case 3: context->mnemonic = Z0_MNEMONIC_SBB; break;
				case 4: context->mnemonic = Z0_MNEMONIC_AND; break;
				case 5: context->mnemonic = Z0_MNEMONIC_SUB; break;
				case 6: context->mnemonic = Z0_MNEMONIC_XOR; break;
				case 7: context->mnemonic = Z0_MNEMONIC_CMP; break;
			}
		} break;

		case Z0_MNEMONIC_SET02:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_POP; break;

				default: context->mnemonic = Z0_MNEMONIC_UD; break;
			}
		} break;

		case Z0_MNEMONIC_SET03:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_ROL; break;
				case 1: context->mnemonic = Z0_MNEMONIC_ROR; break;
				case 2: context->mnemonic = Z0_MNEMONIC_RCL; break;
				case 3: context->mnemonic = Z0_MNEMONIC_RCR; break;
				case 4: context->mnemonic = Z0_MNEMONIC_SHL; break;
				case 5: context->mnemonic = Z0_MNEMONIC_SHR; break;
				case 6: context->mnemonic = Z0_MNEMONIC_SAL; break;
				case 7: context->mnemonic = Z0_MNEMONIC_SAR; break;
			}
		} break;

		case Z0_MNEMONIC_SET04:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_MOV; break;

				default: context->mnemonic = Z0_MNEMONIC_UD; break;
			}
		} break;

		case Z0_MNEMONIC_SET05:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_SLDT; break;
				case 1: context->mnemonic = Z0_MNEMONIC_STR;  break;
				case 2: context->mnemonic = Z0_MNEMONIC_LLDT; context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG16; break;
				case 3: context->mnemonic = Z0_MNEMONIC_LTR;  context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG16; break;
				case 4: context->mnemonic = Z0_MNEMONIC_VERR; context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG16; break;
				case 5: context->mnemonic = Z0_MNEMONIC_VERW; context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG16; break;

				default: context->mnemonic = Z0_MNEMONIC_UD; break;
			}
		} break;

		case Z0_MNEMONIC_SET06:
		{
			if(3 == context->modrm->mod)
			{
				switch(context->modrm->reg)
				{
					case 4: context->mnemonic =Z0_MNEMONIC_SMSW; break;
					case 6: context->mnemonic =Z0_MNEMONIC_LMSW;  context->flags &= ~Z0_OVERRIDE_REG; context->flags |= Z0_OVERRIDE_REG16; break;

					default:
					{
						switch(context->bytes[context->length -1])
						{
							case 0xc1: context->mnemonic = Z0_MNEMONIC_VMCALL;	goto scratch_operands;
							case 0xc2: context->mnemonic = Z0_MNEMONIC_VMLAUNCH;	goto scratch_operands;
							case 0xc3: context->mnemonic = Z0_MNEMONIC_VMRESUME;	goto scratch_operands;
							case 0xc4: context->mnemonic = Z0_MNEMONIC_VMXOFF;	goto scratch_operands;
							case 0xc8: context->mnemonic = Z0_MNEMONIC_MONITOR;	goto scratch_operands;
							case 0xc9: context->mnemonic = Z0_MNEMONIC_MWAIT;	goto scratch_operands;
							case 0xd0: context->mnemonic = Z0_MNEMONIC_XGETBV;	goto scratch_operands;
							case 0xd1: context->mnemonic = Z0_MNEMONIC_XSETBV;	goto scratch_operands;
							case 0xd8: context->mnemonic = Z0_MNEMONIC_VMRUN;	goto scratch_operands;
							case 0xd9: context->mnemonic = Z0_MNEMONIC_VMMCALL;	goto scratch_operands;
							case 0xda: context->mnemonic = Z0_MNEMONIC_VMLOAD;	goto scratch_operands;
							case 0xdb: context->mnemonic = Z0_MNEMONIC_VMSAVE;	goto scratch_operands;
							case 0xdc: context->mnemonic = Z0_MNEMONIC_STGI;	goto scratch_operands;
							case 0xdd: context->mnemonic = Z0_MNEMONIC_CLGI;	goto scratch_operands;
							case 0xde: context->mnemonic = Z0_MNEMONIC_SKINIT;	goto scratch_operands;
							case 0xdf: context->mnemonic = Z0_MNEMONIC_INVLPGA;	goto scratch_operands;
							case 0xf9: context->mnemonic = Z0_MNEMONIC_RDTSCP;	goto scratch_operands;
						}
						context->mnemonic = Z0_MNEMONIC_UD;
					}
				}
			} else
			{
				switch(context->modrm->reg)
				{
					case 0: context->mnemonic = Z0_MNEMONIC_SGDT; break;
					case 1: context->mnemonic = Z0_MNEMONIC_SIDT; break;
					case 2: context->mnemonic = Z0_MNEMONIC_LGDT; break;
					case 3: context->mnemonic = Z0_MNEMONIC_LIDT; break;
					case 4: context->mnemonic = Z0_MNEMONIC_SMSW; break;
					case 6: context->mnemonic = Z0_MNEMONIC_LMSW; break;
					case 7: context->mnemonic = Z0_MNEMONIC_INVLPG; break;

					default: context->mnemonic = Z0_MNEMONIC_UD;
				}
			}
		} break;

		case Z0_MNEMONIC_SET07:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_PREFETCHNTA; break;
				case 1: context->mnemonic = Z0_MNEMONIC_PREFETCHT0; break;
				case 2: context->mnemonic = Z0_MNEMONIC_PREFETCHT1; break;
				case 3: context->mnemonic = Z0_MNEMONIC_PREFETCHT2; break;

				default: context->mnemonic = Z0_MNEMONIC_NOP; break;
			}
		} break;

		case Z0_MNEMONIC_SET_08:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_FADD; break;
				case 1: context->mnemonic = Z0_MNEMONIC_FMUL; break;
				case 2: context->mnemonic = Z0_MNEMONIC_FCOM; break;
				case 3: context->mnemonic = Z0_MNEMONIC_FCOMP; break;
				case 4: context->mnemonic = Z0_MNEMONIC_FSUB; break;
				case 5: context->mnemonic = Z0_MNEMONIC_FSUBR; break;
				case 6: context->mnemonic = Z0_MNEMONIC_FDIV; break;
				case 7: context->mnemonic = Z0_MNEMONIC_FDIVR; break;
			}
		} break;

		case Z0_MNEMONIC_SET_09:
		{
			switch(context->modrm->reg)
			{
				case 0: context->mnemonic = Z0_MNEMONIC_FIADD; break;
				case 1: context->mnemonic = Z0_MNEMONIC_FIMUL; break;
				case 2: context->mnemonic = Z0_MNEMONIC_FICOM; break;
				case 3: context->mnemonic = Z0_MNEMONIC_FICOMP; break;
				case 4: context->mnemonic = Z0_MNEMONIC_FISUB; break;
				case 5: context->mnemonic = Z0_MNEMONIC_FISUBR; break;
				case 6: context->mnemonic = Z0_MNEMONIC_FIDIV; break;
				case 7: context->mnemonic = Z0_MNEMONIC_FIDIVR; break;
			}
		} break;

		case Z0_MNEMONIC_POPCNT:
		{
			if(Z0_PREFIX_REPE != context->prefix_repeat) context->mnemonic =Z0_MNEMONIC_UD;
		} break;
	}

	if(Z0_MNEMONIC_UD == context->mnemonic)
	{
		return process_ud(context);
	}

	if(Z0_PREFIX_OPERAND == context->prefix_operand)
	{
		for(i =0; i < Z0_MAX_OPERANDS; i++)
		{
			switch(context->operand[i].type)
			{
				case Z0_OPTYPE_REG32:	context->operand[i].type =Z0_OPTYPE_REG16; break;
				case Z0_OPTYPE_RM32:	context->operand[i].type =Z0_OPTYPE_RM16; break;
				case Z0_OPTYPE_RM32PTR:	context->operand[i].type =Z0_OPTYPE_RM16PTR; break;
				case Z0_OPTYPE_RM48:	context->operand[i].type =Z0_OPTYPE_RM32; break;
				case Z0_OPTYPE_RM48PTR:	context->operand[i].type =Z0_OPTYPE_RM32PTR; break;
			}
		}
	}

	// operand resolver
	//
	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->optype[i])
		{
			case Z0_OPTYPE_REG8:		context->operand[i].type =reg8[context->modrm->reg]; break;
			case Z0_OPTYPE_REG16:		context->operand[i].type =reg16[context->modrm->reg]; break;
			case Z0_OPTYPE_REG32:		context->operand[i].type =reg32[context->modrm->reg]; break;

			case Z0_OPTYPE_REG_SEGMENT:	context->operand[i].type =reg_seg[context->modrm->reg]; break;
			case Z0_OPTYPE_REG_ST:		context->operand[i].type =reg_st[context->modrm->reg]; break;
			case Z0_OPTYPE_REG_MM:		context->operand[i].type =reg_mm[context->modrm->reg]; break;
			case Z0_OPTYPE_REG_XMM:		context->operand[i].type =reg_xmm[context->modrm->reg]; break;

			case Z0_OPTYPE_RM8:
			case Z0_OPTYPE_RM8PTR:

			case Z0_OPTYPE_RM16:
			case Z0_OPTYPE_RM16PTR:

			case Z0_OPTYPE_RM32:
			case Z0_OPTYPE_RM32PTR:

			case Z0_OPTYPE_RM48:
			case Z0_OPTYPE_RM48PTR:

			case Z0_OPTYPE_RM64:
			case Z0_OPTYPE_RM64PTR:

			case Z0_OPTYPE_RM80:
			case Z0_OPTYPE_RM80PTR:
			{
				if(context->modrm->mod <3)
				{
					if(context->flags & Z0_FLAG_NOT_MOD11_UD)
					{
						return process_ud(context);
					}

					if(context->flags & Z0_FLAG_MOD11_FIXED)
					{
						goto mod11;
					}

					// ptr adding
					//
					switch(context->operand[i].type)
					{
						case Z0_OPTYPE_RM8PTR: context->operand[i].ptr =Z0_OPTYPE_BYTE_PTR; break;
						case Z0_OPTYPE_RM16PTR: context->operand[i].ptr =Z0_OPTYPE_WORD_PTR; break;
						case Z0_OPTYPE_RM32PTR: context->operand[i].ptr =Z0_OPTYPE_DWORD_PTR; break;
						case Z0_OPTYPE_RM48PTR: context->operand[i].ptr =Z0_OPTYPE_FAR_PTR; break;
						case Z0_OPTYPE_RM64PTR: context->operand[i].ptr =Z0_OPTYPE_QWORD_PTR; break;
						case Z0_OPTYPE_RM80PTR: context->operand[i].ptr =Z0_OPTYPE_TBYTE_PTR; break;
					}

					if(Z0_PREFIX_ADDRESS == context->prefix_address)
					{
						switch(context->modrm->mod)
						{
							case 0:
							{
								if(6 == context->modrm->rm)
								{
									context->operand[i].type =Z0_OPTYPE_EMPTY;
									context->operand[i].base =Z0_OPTYPE_PTR16;
									goto add16;

								} else context->operand[i].type =reg16ptr[context->modrm->rm];
							} break;

							case 1:
							{
								context->operand[i].type =reg16ptr[context->modrm->rm];
								context->operand[i].base =Z0_OPTYPE_PTR8;
								goto add8signed;
							}

							case 2:
							{
								context->operand[i].type =reg16ptr[context->modrm->rm];
								context->operand[i].base =Z0_OPTYPE_PTR16;
								goto add16;
							}
						}
					} else
					{
						if(4 == context->modrm->rm) goto sib32;

						switch(context->modrm->mod)
						{
							case 0:
							{
								if(5 == context->modrm->rm)
								{
									context->operand[i].type =Z0_OPTYPE_EMPTY;
									context->operand[i].base =Z0_OPTYPE_PTR32;
									goto add32;

								} else context->operand[i].type =reg32ptr[context->modrm->rm];
							} break;

							case 1:
							{
								context->operand[i].type =reg32ptr[context->modrm->rm];
								context->operand[i].base =Z0_OPTYPE_PTR8;
								goto add8signed;
							}

							case 2:
							{
								context->operand[i].type =reg32ptr[context->modrm->rm];
								context->operand[i].base =Z0_OPTYPE_PTR32;
								goto add32;
							}
						}
					}
				} else
				{
					mod11:

					if(context->flags & Z0_FLAG_MOD11_UD)
					{
						return process_ud(context);
					}

					// mnemonic corrector
					//
					switch(context->mnemonic)
					{
						case Z0_MNEMONIC_MOVLPS: context->mnemonic =Z0_MNEMONIC_MOVHLPS; break;
						case Z0_MNEMONIC_MOVHPS: context->mnemonic =Z0_MNEMONIC_MOVLHPS; break;
					}

					switch(context->flags & Z0_OVERRIDE_REG)
					{
						case Z0_OVERRIDE_REG8:		context->operand[i].type =reg8[context->modrm->rm]; break;
						case Z0_OVERRIDE_REG16:		context->operand[i].type =reg16[context->modrm->rm]; break;
						case Z0_OVERRIDE_REG32:		context->operand[i].type =reg32[context->modrm->rm]; break;
						case Z0_OVERRIDE_REG_ST:	context->operand[i].type =reg_st[context->modrm->rm]; break;
						case Z0_OVERRIDE_REG_MM:	context->operand[i].type =reg_mm[context->modrm->rm]; break;
						case Z0_OVERRIDE_REG_XMM:	context->operand[i].type =reg_xmm[context->modrm->rm]; break;

						case 0:
						{
							switch(context->optype[i])
							{
								case Z0_OPTYPE_REG8:
								case Z0_OPTYPE_RM8PTR:
								case Z0_OPTYPE_RM8: context->operand[i].type =reg8[context->modrm->rm]; break;

								case Z0_OPTYPE_REG16:
								case Z0_OPTYPE_RM16PTR:
								case Z0_OPTYPE_RM16: context->operand[i].type =reg16[context->modrm->rm]; break;

								case Z0_OPTYPE_REG32:
								case Z0_OPTYPE_RM32PTR:
								case Z0_OPTYPE_RM32: context->operand[i].type =reg32[context->modrm->rm]; break;

								case Z0_OPTYPE_REG_XMM:
								case Z0_OPTYPE_RM64PTR:
								case Z0_OPTYPE_RM64: context->operand[i].type =reg_xmm[context->modrm->rm]; break;

								case Z0_OPTYPE_REG_ST: context->operand[i].type =reg_st[context->modrm->rm]; break;
								case Z0_OPTYPE_REG_MM: context->operand[i].type =reg_mm[context->modrm->rm]; break;
							}
						}
					}
				}
			} break;

			case Z0_OPTYPE_PTR8:
			add8signed:
			{
				char* src;
				char* dst;

				src =(char*) (context->addr_ptr +context->length);
				dst =(char*) (context->bytes +context->length);

				context->operand[i].value.imm8signed = *dst = *src;
				context->length++;
			} break;

			case Z0_OPTYPE_PTR16:
			add16:
			{
				unsigned short* src;
				unsigned short* dst;

				src =(unsigned short*) (context->addr_ptr +context->length);
				dst =(unsigned short*) (context->bytes +context->length);

				context->operand[i].value.imm16 = *dst = *src;
				context->length +=2;
			} break;

			case Z0_OPTYPE_PTR32:
			add32:
			{
				unsigned int* src;
				unsigned int* dst;

				src =(unsigned int*) (context->addr_ptr +context->length);
				dst =(unsigned int*) (context->bytes +context->length);

				context->operand[i].value.imm32 = *dst = *src;
				context->length +=4;
			} break;

			sib32:
			{
				context->sib =(SIB*) (context->addr_ptr + context->length);

				context->bytes[context->length] = context->addr_ptr[context->length];
				context->length++;

				if(4 != context->sib->index)
				{
					context->operand[i].index =reg32ptr[context->sib->index];
					context->operand[i].scale =reg_scale[context->sib->scale];
				}

				if(5 == context->sib->base)
				{
					if(0 == context->modrm->mod)
					{
						context->operand[i].type =Z0_OPTYPE_EMPTY;
						context->operand[i].base =Z0_OPTYPE_PTR32;
						goto add32;

					} else context->operand[i].type =Z0_OPTYPE_PTR_EBP;

				} else context->operand[i].type =reg32ptr[context->sib->base];

				switch(context->modrm->mod)
				{
					case 1:
					{
						context->operand[i].base =Z0_OPTYPE_PTR8;
						goto add8signed;
					}

					case 2:
					{
						context->operand[i].base =Z0_OPTYPE_PTR32;
						goto add32;
					}
				}
			} break;

			default: context->operand[i].type =context->optype[i];
		}

		if(Z0_OPTYPE_ERROR == context->operand[i].type)
		{
			return process_ud(context);
		}
	}

	return process_basic(context);

	scratch_operands:

	for(i =0; i <Z0_MAX_OPERANDS; i++)
	{
		context->optype[i] =context->operand[i].type =Z0_OPTYPE_NULL;
	}

	return process_basic(context);
}

Z0_STATUS disasm32(PZ0_DISASM_CONTEXT context)
{
	Z0_STATUS status =Z0_STATUS_OK;
	unsigned char i, j;

	context->addr_ptr += context->length;
	memset(context, 0, sizeof(Z0_DISASM_CONTEXT_VOLATILE));
		
	do
	{
		i = *(context->addr_ptr +context->length);

		context->bytes[context->length] = context->addr_ptr[context->length];
		context->length++;

		switch(i)
		{
			case 0x26: context->prefix_segment = Z0_PREFIX_ES; break;
			case 0x2e: context->prefix_segment = Z0_PREFIX_CS; break;
			case 0x36: context->prefix_segment = Z0_PREFIX_SS; break;
			case 0x3e: context->prefix_segment = Z0_PREFIX_DS; break;
			case 0x64: context->prefix_segment = Z0_PREFIX_FS; break;
			case 0x65: context->prefix_segment = Z0_PREFIX_GS; break;

			case 0x66: context->prefix_operand = Z0_PREFIX_OPERAND; break;
			case 0x67: context->prefix_address = Z0_PREFIX_ADDRESS; break;

			case 0xf0: context->prefix_lock = Z0_PREFIX_LOCK; break;

			case 0xf2: context->prefix_repeat = Z0_PREFIX_REPNE; break;
			case 0xf3: context->prefix_repeat = Z0_PREFIX_REPE; break;

			default:
			{
				context->mnemonic = opcode_base[i].mnemonic;
				context->flags = opcode_base[i].flags;

				for(j =0; j < Z0_MAX_OPERANDS; j++)
				{
					context->optype[j] = context->operand[j].type = opcode_base[i].optype[j];
				}

				return opcode_base[i].process_handler(context);
			}
		}

	} while(1);

	return status;
}


Z0_STATUS disasm(PZ0_DISASM_CONTEXT context)
{
	switch(context->mode)
	{
	//	case Z0_DISASM_MODE_16: return disasm16(context);
		case Z0_DISASM_MODE_32: return disasm32(context);
	//	case Z0_DISASM_MODE_64: return disasm64(context);
	}

	return Z0_STATUS_UNKNOWN_MODE;
}
