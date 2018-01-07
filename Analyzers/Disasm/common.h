#include <flcommon.h>
#include <disasm.h>

#define Z0_OVERRIDE_REG		0xFF

#define Z0_OVERRIDE_REG8	0x01
#define Z0_OVERRIDE_REG16	0x02
#define Z0_OVERRIDE_REG32	0x04
#define Z0_OVERRIDE_REG64	0x08
#define Z0_OVERRIDE_REG_ST	0x10
#define Z0_OVERRIDE_REG_MM	0x20
#define Z0_OVERRIDE_REG_XMM	0x40
//#define Z0_OVERRIDE_REG_	0x80

#define Z0_FLAG_MOD11_UD		0x0100
#define Z0_FLAG_NOT_MOD11_UD		0x0200
#define Z0_FLAG_NOT_OPERAND_UD		0x0400
#define Z0_FLAG_MOD11_NO_PREFIX_OPERAND	0x0800
#define Z0_FLAG_NO_OPERAND_CONVERSION	0x1000
#define Z0_FLAG_MOD11_FIXED		0x2000

#define Z0_FLAG_PREFIX_OPERAND	0x010000
#define Z0_FLAG_PREFIX_ADDRESS	0x020000
#define Z0_FLAG_PREFIX_LOCK	0x040000
#define Z0_FLAG_PREFIX_REPNE	0x080000
#define Z0_FLAG_PREFIX_REPE	0x100000

Z0_STATUS __stdcall process_error(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_basic(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_ptr(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_modrm(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_ext0f(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_ext38(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_ext3a(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_ud(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_reg(PZ0_DISASM_CONTEXT context);
Z0_STATUS __stdcall process_cmpps(PZ0_DISASM_CONTEXT context);

extern Z0_OPCODE_TABLE opcode_base[];
extern Z0_OPCODE_TABLE opcode_ext0f[];
extern Z0_OPCODE_TABLE opcode_ext38[];
extern Z0_OPCODE_TABLE opcode_ext3a[];

extern Z0_OPCODE_TABLE opcode_d8_11[];

extern Z0_OPCODE_TABLE opcode_d9[];
extern Z0_OPCODE_TABLE opcode_d9_11[];
extern Z0_OPCODE_TABLE opcode_d9_11_2[];
extern Z0_OPCODE_TABLE opcode_d9_11_4[];
extern Z0_OPCODE_TABLE opcode_d9_11_5[];
extern Z0_OPCODE_TABLE opcode_d9_11_6[];
extern Z0_OPCODE_TABLE opcode_d9_11_7[];

extern Z0_OPCODE_TABLE opcode_da_11[];
extern Z0_OPCODE_TABLE opcode_da_11_5[];

extern Z0_OPCODE_TABLE opcode_db[];
extern Z0_OPCODE_TABLE opcode_db_11[];
extern Z0_OPCODE_TABLE opcode_db_11_4[];

extern Z0_OPCODE_TABLE opcode_dc_11[];

extern Z0_OPCODE_TABLE opcode_dd[];
extern Z0_OPCODE_TABLE opcode_dd_11[];

extern Z0_OPCODE_TABLE opcode_de_11[];
extern Z0_OPCODE_TABLE opcode_de_11_3[];

extern Z0_OPCODE_TABLE opcode_df[];
extern Z0_OPCODE_TABLE opcode_df_11[];
extern Z0_OPCODE_TABLE opcode_df_11_4[];

extern Z0_OPCODE_TABLE opcode_f6[];
extern Z0_OPCODE_TABLE opcode_f7[];
extern Z0_OPCODE_TABLE opcode_fe[];
extern Z0_OPCODE_TABLE opcode_ff[];

extern Z0_OPCODE_TABLE opcode_0f_ae[];
extern Z0_OPCODE_TABLE opcode_0f_ae_11[];

extern Z0_OPCODE_TABLE opcode_0f_d6[];

unsigned short reg_seg[];
unsigned short reg8[];
unsigned short reg16[];
unsigned short reg32[];
unsigned short reg16ptr[];
unsigned short reg32ptr[];
unsigned short reg_st[];
unsigned short reg_mm[];
unsigned short reg_xmm[];
unsigned short reg_scale[];
unsigned short reg_control[];
unsigned short reg_debug[];
unsigned short reg_test[];
