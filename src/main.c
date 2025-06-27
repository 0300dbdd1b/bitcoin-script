#include "bitcoin-script-internals.h"
#include "bitcoin-script-interpreter.h"
#include <stdio.h>

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	ScriptInterpreter env;
	Script script;

	InitInterpreter(&env);
	InitScriptFromHRF(&script, argv[1]);

	SetInterpreterScript(&env, &script);
	PrintScript(&script);

	SCRIPT_STATUS status = ExecuteScript(&env);
	printf("Script finished with code : %s\n", SCRIPT_GetStatusName(status));

}
