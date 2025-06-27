#include "bitcoin-script-internals.h"

const char *SCRIPT_GetStatusName(SCRIPT_STATUS status)
{
	return script_status_strings[status];
}

SCRIPT_OPCODE SCRIPT_GetOpcode(const char *opcode)
{
	for (U16 i = 0; script_opcode_strings[i] != 0; i++)
	{
		if (strcmp(opcode, script_opcode_strings[i]) == 0)
		{
			return (SCRIPT_OPCODE)i;
		}
	}
	return OP_INVALIDOPCODE;
}

const char *SCRIPT_GetOpcodeName(SCRIPT_OPCODE opcode)
{
	if (opcode <= OP_INVALIDOPCODE)
		return script_opcode_strings[opcode];
	else
		return "UNKNOW_OPCODE";
}

