#include "common.h"

int mnemonic_selfcheck(void) { return ('?' == translate_mnemonic[Z0_MNEMONIC_LAST][0]) ?1 :0; }
int optype_selfcheck(void) { return ('?' == translate_optype[Z0_OPTYPE_LAST][0]) ?1 :0; }
