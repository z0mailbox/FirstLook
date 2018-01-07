#include "common.h"

#include <windows.h>

#define OPCODE_START 42
#define OPERAND_START 55

char string[0x200];
unsigned char* hiew_addr =NULL;

Z0_STATUS __stdcall print_disasm(PZ0_DISASM_CONTEXT context)
{
	int i;

	sprintf(string, " %p: ", hiew_addr);

	for(i =0; i < context->length; i++) sprintf(string, "%s%02X", string, context->bytes[i]);

	while(strlen(string) < OPCODE_START) sprintf(string, "%s ", string);

	// for hiew output compatibility
	//
	if(Z0_MNEMONIC_INT3 == context->mnemonic)
	{
		context->mnemonic =Z0_MNEMONIC_INT;

		context->operand[0].type =Z0_OPTYPE_IMM8;
		context->operand[0].value.imm8 =3;
	}

	sprintf(string, "%s%s", string, translate_mnemonic[context->mnemonic]);

	switch(context->operand[0].type)
	{
		case Z0_OPTYPE_NULL:
		case Z0_OPTYPE_EBX_PTR_1:
		case Z0_OPTYPE_BX_PTR_1: break;

		default: while(strlen(string) < OPERAND_START) sprintf(string, "%s ", string);
	}

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		if(context->operand[i].type)
		{
			if(i) sprintf(string, "%s,", string);

			if(context->operand[i].ptr) sprintf(string, "%s%s", string, translate_optype[context->operand[i].ptr]);

		//	if(context->operand[i].prefix_segment) sprintf(string, "%s%s", string, translate_opcode[context->operand[i].prefix_segment]);

			switch(context->operand[i].type)
			{
				case Z0_OPTYPE_NULL: break;

			//	case Z0_OPTYPE_1: sprintf(string, "%s1", string); break;
			//	case Z0_OPTYPE_CL_1: sprintf(string, "%scl", string); break;

				case Z0_OPTYPE_IMM8:
				case Z0_OPTYPE_IMM8SIGNED:
				{
					if(context->operand[i].value.imm8 < 0xa)
					{
						sprintf(string, "%s%X", string, context->operand[i].value.imm8);
						break;
					}
					
					if(context->operand[i].value.imm8 > 0xf6)
					{
						sprintf(string, "%s-%X", string, 0xff -context->operand[i].value.imm8 +1);
						break;
					}
					
					sprintf(string, "%s0%02X", string, context->operand[i].value.imm8);
				} break;

				case Z0_OPTYPE_IMM16:
				{
					if(context->operand[i].value.imm16 < 0xa)
					{
						sprintf(string, "%s%X", string, context->operand[i].value.imm16);
						break;
					}
					
					if(context->operand[i].value.imm16 > 0xfff6)
					{
						sprintf(string, "%s-%X", string, 0xffff -context->operand[i].value.imm16 +1);
						break;
					}
					
					sprintf(string, "%s0%04X", string, context->operand[i].value.imm16);
				} break;

				case Z0_OPTYPE_IMM32:
				{
					if(context->operand[i].value.imm32 < 0xa)
					{
						sprintf(string, "%s%X", string, context->operand[i].value.imm32);
						break;
					}
					
					if(context->operand[i].value.imm32 > 0xfffffff6)
					{
						sprintf(string, "%s-%X", string, 0xffffffff -context->operand[i].value.imm32 +1);
						break;
					}
					
					sprintf(string, "%s0%08X", string, context->operand[i].value.imm32);
				} break;

		//		case Z0_OPTYPE_IMM64: sprintf(string, "%s%lx", string, d->op[i].value._64); break;

				case Z0_OPTYPE_REL8:
				case Z0_OPTYPE_REL16:
				case Z0_OPTYPE_REL32: sprintf(string, "%s0%08X", string, context->operand[i].value.rel32 -(unsigned int) context->addr_ptr +(unsigned int) hiew_addr); break;

				case Z0_OPTYPE_PTR16_16: sprintf(string, "%s0%04X:0%04X", string, context->operand[i].segment, context->operand[i].value.imm16); break;
				case Z0_OPTYPE_PTR16_32: sprintf(string, "%s0%04X:0%04X", string, context->operand[i].segment, context->operand[i].value.imm32); break;

				case Z0_OPTYPE_PTR16: sprintf(string, "%s[0%04X]", string, context->operand[i].value.imm16); break;
				case Z0_OPTYPE_PTR32: sprintf(string, "%s[0%08X]", string, context->operand[i].value.imm32); break;

				default: sprintf(string, "%s%s", string, translate_optype[context->operand[i].type]);
			}
		
			if(context->operand[i].index) sprintf(string, "%s%s", string, translate_optype[context->operand[i].index]);
			if(context->operand[i].scale) sprintf(string, "%s%s", string, translate_optype[context->operand[i].scale]);

			switch(context->mnemonic)
			{
				case Z0_MNEMONIC_UNPCKHPD:
				case Z0_MNEMONIC_UNPCKHPS:

				case Z0_MNEMONIC_LEA:

				case Z0_MNEMONIC_ROL:
				case Z0_MNEMONIC_ROR:
				case Z0_MNEMONIC_RCL:
				case Z0_MNEMONIC_RCR:
				case Z0_MNEMONIC_SHL:
				case Z0_MNEMONIC_SHR:
				case Z0_MNEMONIC_SAL:
				case Z0_MNEMONIC_SAR:
				{
					switch(context->operand[i].base)
					{
						case Z0_OPTYPE_PTR8:
						{
							if(context->operand[i].value.imm8 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm8);
								break;
							}
					
							if(context->operand[i].value.imm8 > 0xf6)
							{
								sprintf(string, "%s[-%X]", string, 0xff -context->operand[i].value.imm8 +1);
								break;
							}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm8 < 0x80))
								sprintf(string, "%s[0%02X]", string, context->operand[i].value.imm8);
							else
								sprintf(string, "%s[-0%02X]", string, 0xff -context->operand[i].value.imm8 +1);
						} break;

						case Z0_OPTYPE_PTR16:
						{
							if(context->operand[i].value.imm16 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm16);
								break;
							}
					
						//	if(context->operand[i].value.imm16 > 0xfff6)
						//	{
						//		sprintf(string, "%s[-%X]", string, 0xffff -context->operand[i].value.imm16 +1);
						//		break;
						//	}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm16 < 0x8000))
								sprintf(string, "%s[0%04X]", string, context->operand[i].value.imm16);
							else
								sprintf(string, "%s[-0%04X]", string, 0xffff -context->operand[i].value.imm16 +1);
						} break;

						case Z0_OPTYPE_PTR32:
						{
							if(context->operand[i].value.imm32 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm32);
								break;
							}
					
							if(context->operand[i].value.imm32 > 0xfffffff6)
							{
								sprintf(string, "%s[-%X]", string, 0xffffffff -context->operand[i].value.imm32 +1);
								break;
							}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm32 < 0x80000000))
								sprintf(string, "%s[0%08X]", string, context->operand[i].value.imm32);
							else
								sprintf(string, "%s[-0%08X]", string, 0xffffffff -context->operand[i].value.imm32 +1);
						} break;
					}
				} break;

				default:
				{
					switch(context->operand[i].base)
					{
						case Z0_OPTYPE_PTR8:
						{
							if(context->operand[i].value.imm8 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm8);
								break;
							}
					
							if(context->operand[i].value.imm8 > 0xf6)
							{
								sprintf(string, "%s[-%X]", string, 0xff -context->operand[i].value.imm8 +1);
								break;
							}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm8 < 0x80))
								sprintf(string, "%s[0%02X]", string, context->operand[i].value.imm8);
							else
								sprintf(string, "%s[-0%02X]", string, 0xff -context->operand[i].value.imm8 +1);
						} break;

						case Z0_OPTYPE_PTR16:
						{
							if(context->operand[i].value.imm16 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm16);
								break;
							}
					
							if(context->operand[i].value.imm16 > 0xfff6)
							{
								sprintf(string, "%s[-%X]", string, 0xffff -context->operand[i].value.imm16 +1);
								break;
							}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm16 < 0x8000))
								sprintf(string, "%s[0%04X]", string, context->operand[i].value.imm16);
							else
								sprintf(string, "%s[-0%04X]", string, 0xffff -context->operand[i].value.imm16 +1);
						} break;

						case Z0_OPTYPE_PTR32:
						{
							if(context->operand[i].value.imm32 < 0xa)
							{
								sprintf(string, "%s[%X]", string, context->operand[i].value.imm32);
								break;
							}
					
							if(context->operand[i].value.imm32 > 0xfffffff6)
							{
								sprintf(string, "%s[-%X]", string, 0xffffffff -context->operand[i].value.imm32 +1);
								break;
							}
					
							if(((Z0_OPTYPE_EMPTY == context->operand[i].type) && (Z0_OPTYPE_NULL == context->operand[i].index)) || (context->operand[i].value.imm32 < 0x80000000))
								sprintf(string, "%s[0%08X]", string, context->operand[i].value.imm32);
							else
								sprintf(string, "%s[-0%08X]", string, 0xffffffff -context->operand[i].value.imm32 +1);
						} break;
					}
				}
			}
		}
	}

	for(i =0; i < Z0_MAX_OPERANDS; i++)
	{
		switch(context->operand[i].type)
		{
			case Z0_OPTYPE_IMM8:
			case Z0_OPTYPE_IMM8SIGNED:
			{
				unsigned char* ptr =(unsigned char*) &(context->operand[i].value.imm8);

				if(ptr[0] >= ' ')
					sprintf(string, "%s ;'%c'", string,
						(ptr[0] > ' ') ? ptr[0] : ' ');
			} goto check_mnemonic; // instead of brake for hiew output compatibility

			case Z0_OPTYPE_IMM16:
			{
				unsigned char* ptr =(unsigned char*) &(context->operand[i].value.imm16);

				if((ptr[0] >= ' ') || (ptr[1] >= ' '))
					sprintf(string, "%s ;'%c%c'", string,
						(ptr[1] > ' ') ? ptr[1] : ' ',
						(ptr[0] > ' ') ? ptr[0] : ' ');
			} goto check_mnemonic; // instead of brake for hiew output compatibility

			case Z0_OPTYPE_IMM32:
			{
				unsigned char* ptr =(unsigned char*) &(context->operand[i].value.imm32);

				if((ptr[0] >= ' ') || (ptr[1] >= ' ') || (ptr[2] >= ' ') || (ptr[3] >= ' '))
					sprintf(string, "%s ;'%c%c%c%c'", string,
						(ptr[3] > ' ') ? ptr[3] : ' ',
						(ptr[2] > ' ') ? ptr[2] : ' ',
						(ptr[1] > ' ') ? ptr[1] : ' ',
						(ptr[0] > ' ') ? ptr[0] : ' ');
			} goto check_mnemonic; // instead of brake for hiew output compatibility
		}
	}

	check_mnemonic:
	switch(context->mnemonic)
	{
		case Z0_MNEMONIC_RET:
		case Z0_MNEMONIC_RETF:
		case Z0_MNEMONIC_IRET: sprintf(string, "%s ; -^-^-^-^-^-^-^-^-^-^-^-^-^-^-^-", string); break;

		case Z0_MNEMONIC_CALLF:
		case Z0_MNEMONIC_JMPF:
		case Z0_MNEMONIC_CALL:
		case Z0_MNEMONIC_JMP:
		{
		//	sprintf(string, "%s --X", string);  // for hiew output compatibility
		} break;
	}

	printf("%s\n", string);

	hiew_addr += context->length;

	return Z0_STATUS_OK;
}
