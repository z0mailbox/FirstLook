char* translate_optype[] =
{
	"null",

//	Unresolved operand types
//
	"imm8",
	"imm8signed",
	"ptr8",
	"rel8",

	"imm16",
	"ptr16",
	"rel16",

	"imm32",
	"ptr32",
	"rel32",

	"rm8",
	"rm8ptr",
	"rm16",
	"rm16ptr",
	"rm32",
	"rm32ptr",
	"rm48",
	"rm48ptr",
	"rm64",
	"rm64ptr",
	"rm80",
	"rm80ptr",

	"ptr16_16",
	"ptr16_32",

	"reg8",
	"reg16",
	"reg32",
	"reg_segment",
	"reg_control",
	"reg_debug",
	"reg_test",
	"reg_st",
	"reg_mm",
	"reg_xmm",

//	Resolved operand types
//
	"",	// Z0_OPTYPE_EMPTY
	"",	// Z0_OPTYPE_ERROR

	"al",
	"cl",
	"dl",
	"bl",
	"ah",
	"ch",
	"dh",
	"bh",

	"ax",
	"cx",
	"dx",
	"bx",
	"sp",
	"bp",
	"si",
	"di",

	"eax",
	"ecx",
	"edx",
	"ebx",
	"esp",
	"ebp",
	"esi",
	"edi",

	"es",
	"cs",
	"ss",
	"ds",
	"fs",
	"gs",

	"[bx][si]",
	"[bx][di]",
	"[bp][si]",
	"[bp][di]",
	"[si]",
	"[di]",
	"[bp]",
	"[bx]",

	"[eax]",
	"[ecx]",
	"[edx]",
	"[ebx]",
	"[esp]",
	"[ebp]",
	"[esi]",
	"[edi]",

	"st(0)",
	"st(1)",
	"st(2)",
	"st(3)",
	"st(4)",
	"st(5)",
	"st(6)",
	"st(7)",

	"mm0",
	"mm1",
	"mm2",
	"mm3",
	"mm4",
	"mm5",
	"mm6",
	"mm7",

	"xmm0",
	"xmm1",
	"xmm2",
	"xmm3",
	"xmm4",
	"xmm5",
	"xmm6",
	"xmm7",

	"*2",
	"*4",
	"*8",

	"b,",
	"w,",
	"d,",
	"f,",
	"q,",
	"t,",
	"n,",
	"f,",

	"1",
	"cl",

	"",
	"",

	"cr0",
	"CR1",
	"cr2",
	"cr3",
	"cr4",
	"CR5",
	"CR6",
	"CR7",

	"dr0",
	"dr1",
	"dr2",
	"dr3",
	"DR4",
	"DR5",
	"DR6",
	"dr7",

	"TR0",
	"TR1",
	"TR2",
	"TR3",
	"TR4",
	"TR5",
	"tr6",
	"tr7",

	"?"

};
